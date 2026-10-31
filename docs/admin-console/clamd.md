# ClamAV

<!-- Source: README.md, split by topic. -->

#### ClamAV

ClamAV is a **guest on the analysis VM**, not a service on this host. `clamd`
answers on a unix socket inside the guest (`/var/run/clamav/clamd.ctl` by
default), and the two host-side drivers already in the repo are the whole
integration:

| file | what it owns |
| --- | --- |
| `python/clamd/scan_remote.py` | SSH into the VM, deploy the sample with SFTP, scan it there, bring the result JSON home |
| `python/clamd/clamd-python.py` | the in-VM scanner; speaks to `clamd` over the unix socket or TCP |
| `python/panel/utils/socket_validator.py` | the operator's TCP client, used as-is for the direct-socket transport |
| `python/clamd/results/*.json` | one document per scan, the only source of verdicts |

The panel reads those documents and, when asked, spawns the drivers. It does
not reimplement SSH, SFTP or the `clamd` protocol.

The page has three tabs, and they answer three different questions. Each tab
uses the same shape: a **rail** of facts and controls on the left, a wide
**console** of machine text on the right. The console is one component
(`admin-web/src/components/Console.tsx`), so the connection test, the scan log
and a result document scroll, number and copy identically.

## Service status

Read-only, and it checks **the transport that is actually selected** - not both,
and not a generic daemon probe. The selection lives in one place:

```json
// config/dynamic_analysis.json
{ "communication": "sftp" }
```

That is the same file, and the same key, the **Dynamic Analysis >
Configuration** page writes. The ClamAV page reads it back and never offers a
second choice, because a page that checks one path and scans down another is
how "the scan passed" stops meaning anything. Change it on the Dynamic Analysis
page; the service-status card has a shortcut there.

| selection | checks | network |
| --- | --- | --- |
| `sftp` | `scan_remote.py`, `clamd-python.py`, `vm_info.json` and `paramiko` - the driver files in `python/clamd/` | none: no SSH session is opened by a status poll |
| `tcp` | `socket_validator.py`, `ifaddr`, `colorama`, then the client opens the socket and clamd is asked for `PING` and `VERSION` | one connect, bounded by the client's own 3s timeout |

| field | meaning |
| --- | --- |
| `ready` | every hard check for the selected transport passed |
| `reachable` | a daemon answered (`true` only for TCP `PING`; SFTP is not probed here) |
| `communication.mode` / `.path` / `.error` | the choice, the file it came from, and why it could not be read |
| `version` | clamd's own `VERSION` reply (TCP only) |

A malformed config is an error the page shows and refuses to submit on: a typo
must not silently put the sample on a transport nobody selected. `ready: false`
with green rows is not possible - failed rows are named in the banner.

### Run check and output

The checks run on the 10-second poll and on demand: **Run check** in the
console header (or **Refresh** at the top of the page) re-runs them immediately
and stamps `checked_at`. The console beside the facts panel is the connection
test's own text, and it narrates itself the way a script does - each step is
announced, then its result is printed:

```text
$ clamd connection test - sftp (config/dynamic_analysis.json)
  endpoint ssh://qilin@192.168.56.105:22
  5 steps - every step passed

[1/5] locating the host-side SFTP driver
[ok  ] scan_remote.py: C:\...\python\clamd\scan_remote.py
[2/5] locating the in-VM scanner it deploys
[ok  ] clamd-python.py: C:\...\python\clamd\clamd-python.py
...
  note  file checks only - no SSH session opened
--- ready
```

The announcement is the intent (`echo` on each check), the row under it is the
evidence, and the numbering is the same numbering the step list below uses - so
a failure is attributable to a step rather than to a flat list of outcomes. The
header states how many steps ran and how many passed.

For TCP the client's own transcript follows the last step, ANSI stripped, in a
`socket_validator.py said:` block. Its per-adapter enumeration (one pair of
lines per network interface, most of them irrelevant to the target) is folded
into a single `… N interface lines omitted` line so the connect result is not
buried; everything else is kept. The text is generated server-side from the
same check list, so the console and the cards cannot disagree, and the last line
is always `--- ready` or `--- not ready`. Its **Copy** button copies the whole
transcript.

Below the pair, one card lists the same steps as a numbered stepper - number,
name, evidence, and `ok` / `fail` / `info` - with a segment strip in its header
so the whole result reads at a glance. Each step draws the glyph for the kind of
thing it checked (`file-code` for a driver, `code` for an imported module,
`wifi` for an address, `plug` for a socket, `activity` for the PING), and every
element of a row - bubble, connector, glyph, state pill - mixes from the row's
own state colour, so a failure is red from end to end rather than only in the
text. The other card lists **both** transports with their availability, so a
driver file that has gone missing is visible by name; only the selected one is
labelled *selected*. A zero-byte driver counts as missing: it imports cleanly
and then does nothing, which would be a transport offered that cannot run.

The console's own version of that colour is the hairline under its header - a
gradient in the console's state colour, green for ready, red for failed, and the
accent-to-violet brand run when there is no verdict yet.

## Submit sample

The one action with side effects. The operator picks a file; the transport is
the one in `config/dynamic_analysis.json`. The panel stages the upload in a
private temp directory (never in the repo), computes its SHA-256, starts a job,
and shows the driver's output live in the **Scan log** console. The console is
tall on this tab, numbers every line, follows the tail while the job runs -
scrolling up stops following - and its **Copy** button takes the whole log.

| transport | how the sample moves | limit |
| --- | --- | --- |
| **SFTP - analysis VM** | `scan_remote.py` deploys over SSH/SFTP, runs `clamd-python.py` in the guest, downloads the result JSON | 25 MiB |
| **TCP socket - INSTREAM** | `socket_validator.py` opens the TCP socket, then the panel sends `zINSTREAM` frames on it | 25 MiB |

The 25 MiB is clamd's `StreamMaxLength`, not an arbitrary panel limit: a larger
stream is refused by the daemon, so the uploader refuses it first.

**Why two transports.** SFTP is the path the lab's scripts already drive and the
only one that can update signatures and start a user-space daemon when the
configured one is down. The TCP path exists for a `clamd` that is reachable
directly from the host; it is one `INSTREAM` request and needs no SSH account.

**The TCP path uses the operator's client unchanged.** `socket_validator.py`
owns the interface check, the connection timeout and the socket itself; the
panel loads it by file path (so the operator's tool stays a standalone script
rather than a panel submodule), calls `establish_tcp_connection()`, and speaks
`INSTREAM` on the socket it returns.
Its `print()` narration is captured into the job log with ANSI stripped.

A request that carries a different `mode` is refused with `mode-locked` rather
than obeyed; omitting `mode` (what the page does) uses the config.

**Both transports write the same document**, so the Results tab cannot tell
which one produced a row:

```json
{"ok": true, "verdict": "clean|infected", "status": "OK|FOUND",
 "signature": "...", "filename": "...", "sha256": "...",
 "clamd_version": "...", "endpoint": "tcp:host:port", "seconds": 1.2,
 "date_of_analysis": "..."}
```

### Scan log

The driver's own lines, streamed as they arrive: the exact command, the SFTP
upload, the in-VM scan, and the result path. The last line is the verdict -
`CLEAN`, or `INFECTED` with the signature. A failed scan says why in the same
place (`connect-failed`, `timeout`, `no-result`, `scan-failed`), rather than
leaving a spinner.

The job lives in the shared job store (`python/panel/build/build.py`), so
`GET /api/build/<job_id>` follows it and a page reload reattaches with
`GET /api/clamd/submit` instead of orphaning a running upload. One scan at a
time: a second submission is refused with `409` while one is in progress.

## Scan results

Every row is read from `python/clamd/results/*.json` - newest first, capped at
200 files. Nothing is recomputed and nothing is re-scanned. Two details are
deliberate:

- a **zero-byte** result file (an interrupted SFTP download) is reported as
  failed with its reason, not skipped;
- a document with no `verdict` is **failed**, not clean. An answer from a
  scanner that was never asked is the one answer worse than "unavailable".

Counts are per file shown, not per file ever written. The tab is a rail and a
document viewer:

- three verdict tiles double as filters (click **Infected** to see only those,
  click again for all);
- a text filter matches sample name, file name, signature or failure detail;
- selecting a row reads that document through `GET /api/clamd/results/<name>`
  and shows it **verbatim** in the console on the right - pretty-printed when it
  parses, untouched when it does not, because a broken document is exactly what
  needs reading. A zero-byte file shows as an empty document rather than an
  error.

The viewer is evidence, not a summary: it is the exact JSON a verdict was read
from, with the `verdict` and `signature` lines coloured.

## Endpoints

| route | method | purpose |
| --- | --- | --- |
| `/api/clamd/status` | GET | transport-aware checks for the `communication` selection, endpoint, transports |
| `/api/clamd/results` | GET | result files, newest first |
| `/api/clamd/results/<name>` | GET | one result document verbatim (`name` must be a bare `.json` file name; `400 bad-name`, `404 not-found`) |
| `/api/clamd/submit` | GET | the scan in progress or the last one |
| `/api/clamd/submit` | POST | `multipart/form-data`: `file`; optional `mode`, refused with `mode-locked` unless it matches the config |
| `/api/build/<job_id>` | GET | output log and state for a submission |
