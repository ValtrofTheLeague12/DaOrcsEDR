# Services

The Services page probes every endpoint in the lab and draws one card per
service. Three of those cards — **Analyzer API**, **MalAPI** and **ML scorer** —
also carry a **Start** / **Stop** row. This page is about that row: what it will
and will not do, and why.

Everything else on the page is still read-only. Containers are started from
**Containers**, the VM from **Fleet**, and the panel itself cannot restart
itself from inside a request it is serving.

A card that *is* a compose service says where its controls are: it names the
unit (`ia / cyberchef-api`, `kafka-agent / kafka`) and carries **Manage in
Containers →**. That join is the Containers page's own join — the same
`resolve()` that tells a container which endpoint it should open — so a card
can never point at a container that page would not recognise. The VM card has
no such pointer because it is not docker; Fleet owns it.

## The allowlist

Control exists only for the services the panel runs as Python processes. The
list is server-side (`launcher.UNIT_KEYS`), and the UI reads it from the same
payload it draws the cards from, so a card cannot offer a button the backend
would refuse:

| key | what is run | working directory | start waits |
| --- | --- | --- | --- |
| `analyzer` | `server.py` with the panel's own interpreter | repo root | 20 s |
| `malapi` | `python/api/server.py` with the panel's own interpreter | `python/` | 15 s |
| `ml` | `ml/serve.py` with `ml/_t/venv` | repo root | 30 s |

Two details in that table are not incidental:

- **MalAPI runs from `python/`**, not the repo root. `api/server.py` opens
  `yaml/malapi/*.yaml` relative to its working directory, so the wrong cwd turns
  every route into a 500.
- **The ML scorer uses its own venv.** It needs `lightgbm`, `sklearn`, `pefile`
  and `thrember`; the panel's venv has none of them. The other two only need
  Flask and PyYAML, which the panel itself requires, so `sys.executable` is the
  one interpreter guaranteed to have them.

The deadline is a ceiling on how long the request may take, not an expectation.
The ML scorer loads a 39 MB LightGBM model before it answers.

## Start

**Start** is synchronous. It returns success only once the endpoint the card
actually probes has answered — not when a process was forked. That is why the
button says **Starting…** for a few seconds and why "started" and "the card is
green" cannot disagree.

Before anything is spawned, these are checked and the start is refused **with
the reason** rather than launching a process that dies a second later:

| refusal | when |
| --- | --- |
| `python/.venv is missing` | the interpreter in the table does not exist |
| `static analyzer is not built` | `build-ucrt/static_analyzer.exe` (or `SA_ANALYZER`) is absent — build it from **Build** |
| `ml/model.txt is missing` | the scorer has no model to load |
| `ML_HOST is off-loopback and ML_SERVE_TOKEN is unset` | `ml/serve.py` refuses to bind a non-loopback address without a token |
| `port N is held by …` | something is listening but not answering the health check — a half-booted instance or another program |

The refusal is shown in the card and the note beside the disabled button. A
blocked card is not a bug to retry; it is a setup step.

If a process does start but never answers, the result carries the last three
lines of the child's log, so the common case — an import error, a bad token —
is one sentence and a traceback, not a timeout with no cause.

### Where the output goes

Children are spawned **detached** (`CREATE_NO_WINDOW |
CREATE_NEW_PROCESS_GROUP`), with stdout and stderr appended to:

```text
%APPDATA%/IAProject/logs/panel-services/<key>-<local timestamp>.log
```

A service that dies when the browser closes is not a service, so nothing holds
the child's handle past the request. The log file is the handle. The result's
`log` field is the exact path, and the card shows the tail on failure.

## Stop

**Stop** finds the process listening on the port the service is configured for
(`Get-NetTCPConnection` on Windows, `lsof` elsewhere) and kills that tree. Two
refusals matter more than the happy path:

- **Nothing listening** — reported as `not-running`, not as a success. If the
  probe answers anyway, the message says so: the service is running on another
  host, and there is nothing here to stop.
- **Not ours** — if the listener's command line does not look like that
  service, stop refuses and names the process it found. "Port 60025 is busy" and
  "our analyzer owns 60025" are different facts, and killing the wrong one is
  how an unrelated program disappears.

The two Python APIs are disambiguated deliberately: `server.py` by itself would
match both, so MalAPI is identified by `api\server.py` and the Analyzer API by
`server.py` *without* it. The ML scorer is `serve.py`.

Stop waits up to five seconds for the port to be released before reporting
success, so a green "stopped" means the socket really went away.

## Status codes

| code | HTTP | meaning |
| --- | --- | --- |
| `started` | 200 | the endpoint answered; `ms` is time from spawn |
| `already-running` | 200 | the probe was already green; nothing was spawned |
| `stopped` | 200 | the listener is gone and the port is free |
| `blocked` | 409 | a prerequisite is missing; see the refusal table |
| `port-held` | 409 | the port is occupied by something not answering the probe |
| `not-running` | 409 | no local listener, whether or not a remote one answers |
| `not-ours` | 409 | a listener exists but is not this service |
| `busy` | 409 | another start/stop for the same key is in flight |
| `timeout` | 502 | spawned, but nothing answered within the deadline |
| `exited` | 502 | the process died first; the log tail says why |
| `spawn-failed` | 502 | the OS refused to launch it |
| `stop-failed` | 502 | the port was still listening after the kill |

An unknown key is a **404** and an action other than `start` / `stop` is a
**400** — both are decided before any process is touched:

```powershell
# start, wait for the health check, return the log tail
Invoke-RestMethod -Method Post http://127.0.0.1:60100/api/services/analyzer/start

# a container key is not in this allowlist
Invoke-RestMethod -Method Post http://127.0.0.1:60100/api/services/kafka/start   # 404
```

## Relationship to the terminal

`admin-terminal` menu **2** (Activate) and **3** (Stop) do the same three
services, with the same rules: `core.bind_addr()` widens a non-loopback host to
`0.0.0.0`, and the analyzer's own clients dial `127.0.0.1`. This page is the
same logic behind a button. The terminal remains the bootstrap — it can start
the panel, which this page cannot.

Because the panel caches the overview for five seconds, every successful start
or stop invalidates that cache. Without it the click would succeed and the page
would immediately redraw the state from before it.
