# DaOrcs Endpoint Agent

Version 0.2.0

The endpoint agent watches one or more folders, detects Windows PE files by
signature (not by extension), hashes them, splits them into bounded chunks and
publishes them to a Kafka topic. It runs as the `DaOrcsEndpointAgent` Windows
service and remembers what it already sent, so a restart does not resend every
sample.

## Installation

Setup shows the full terms and data-handling notice (`TERMS-OF-SERVICE.txt`) in
a scrollable text area and only continues after it is accepted. The next page
lists exactly which files are written and which Windows changes are made.

### Deploying to a specific machine

One installer is used for every endpoint; the per-target values are given on
the command line, and a fresh install writes them into `agent.json` before any
files are copied:

```powershell
# Seed this endpoint's own address so the panel can reach its heartbeat,
# plus the Kafka broker and topic it publishes to.
& .\DaOrcsAgent-Setup.exe /APIHOST=192.168.56.106 `
    /BROKERS=192.168.56.1:9092 /TOPIC=analysis-artifacts

# Same as above for a silent deployment
& .\DaOrcsAgent-Setup.exe /VERYSILENT /NORESTART `
    /APIHOST=192.168.56.106 /BROKERS=192.168.56.1:9092 `
    /TOPIC=analysis-artifacts
```

| Switch | Meaning | Default when omitted |
| --- | --- | --- |
| `/APIHOST=` | The address the agent's heartbeat API binds on **this** machine; the panel probes `http://<APIHOST>:<APIPORT>/api/v1/health`. | `0.0.0.0` |
| `/APIPORT=` | TCP port the heartbeat API binds on this machine. Must be 1-65535. | `8787` |
| `/BROKERS=` | Comma-separated `host:port` Kafka bootstrap entries (the panel host's broker). | `192.168.56.1:9092` |
| `/TOPIC=` | Kafka topic the agent publishes to. | `analysis-artifacts` |

The values are validated before setup runs: an invalid address, port, broker
list or topic aborts the install with an explanation rather than silently
producing a configuration that can never report. On an upgrade the switches are
ignored — the existing `agent.json` is kept — and they never overwrite an
`agent.json` that already exists on a fresh install. Whatever is written is
logged in `install.log`. The API port (8787 by default) still needs an inbound
firewall rule on the endpoint, restricted to the panel's subnet; the agent logs
a warning about the widened bind itself.

### Upgrading an existing install

Running the installer on a machine that already has the agent updates it in
place. Setup detects the previous version (from the uninstall registry entry or
the `DaOrcsEndpointAgent` service), shows an `UPGRADE DETECTED` note on the
contents page, and then:

1. stops the running service (and any stray `DaOrcsAgent.exe`) before files are
   replaced, so the executable is never locked;
2. replaces the program files, leaving `agent.json` and `state.sqlite3` intact;
3. points the existing service registration at the new executable, refreshes its
   log folder and failure actions, and restarts it;
4. reports the restart result in `install.log` and in the post-install window.

No manual uninstall is needed. A fresh machine takes the normal
`-Action install` path instead.

### Uninstalling

Uninstall removes the `DaOrcsEndpointAgent` service and the installed program
files. Before it starts, it asks whether to delete the log folder as well:

- **No** (the default) keeps `%APPDATA%\DaOrcs\Agent\logs` with `agent.log`,
  `detections.log`, rotations, `service.log`, `install.log` and `setup.log`
  (plus `uninstall.log` when the uninstaller log is enabled) for auditing.
- **Yes** removes that whole folder, including the empty `DaOrcs\Agent` parents,
  after the service is gone.

The prompt can be bypassed for automation:

```powershell
# Silent uninstall that also wipes the logs
& "$env:ProgramData\DaOrcs\Agent\unins000.exe" /VERYSILENT /NORESTART /WIPELOGS
```

Without `/WIPELOGS`, a silent uninstall keeps the logs. `state.sqlite3` stays
under `%ProgramData%\DaOrcs\Agent` either way; `agent.json` is removed with the
other installed files.

## Installed layout

| Path | What it is |
| --- | --- |
| `%ProgramData%\DaOrcs\Agent\DaOrcsAgent.exe` | Agent executable |
| `%ProgramData%\DaOrcs\Agent\agent.json` | Agent configuration |
| `%ProgramData%\DaOrcs\Agent\state.sqlite3` | Hashes already delivered |
| `%ProgramData%\DaOrcs\Agent\windows-service.ps1` | Service install/status/diagnose (self-elevates) |
| `%ProgramData%\DaOrcs\Agent\post-install.ps1` | Post-install health terminal |
| `%ProgramData%\DaOrcs\Agent\daorcs-agent-admin.cmd` | UAC launcher for the service script |
| `%ProgramData%\DaOrcs\Agent\TERMS-OF-SERVICE.txt` | The accepted terms and data-handling notice |
| `%ProgramData%\DaOrcs\Agent\kafka\` | Native Kafka installer (no Docker) |
| `%APPDATA%\DaOrcs\Agent\logs\agent.log` | Agent runtime log |
| `%APPDATA%\DaOrcs\Agent\logs\detections.log` | One JSON line per captured sample |
| `%APPDATA%\DaOrcs\Agent\logs\service.log` | Service startup failures |
| `%APPDATA%\DaOrcs\Agent\logs\install.log` | Installer + service-install log |
| `%APPDATA%\DaOrcs\Agent\logs\setup.log` | Copy of the Inno Setup installer log |
| `%APPDATA%\DaOrcs\Agent\logs\uninstall.log` | Copy of the Inno Setup uninstaller log (when enabled) |

Every log this project writes lives under `%APPDATA%\DaOrcs\Agent\logs`, not
ProgramData. Inno Setup's own log is enabled with `SetupLogging=yes` and copied
to `setup.log` when setup exits (the source is `%TEMP%\Setup Log *.txt`; pass
`/LOGLEVEL=verbose` to make it more detailed).

The service runs as LocalSystem. The installer sets a service-scoped
`DAORCS_LOG_DIR` environment variable to the installing user's AppData log
folder, and the agent reads it before loading `agent.json`, so the service and
the interactive scripts write to the same directory. `windows-service.ps1` also
rewrites `log_file` in `agent.json` to that absolute path. The program folder is
still `%ProgramData%\DaOrcs\Agent`; only logs moved to AppData.

## Configuration

`agent.json` is created on first install and is left alone on upgrades.

```json
{
  "watch_dirs": ["%PUBLIC%\\Downloads", "%PUBLIC%\\Desktop"],
  "scan_interval_seconds": 5,
  "stable_seconds": 2,
  "chunk_bytes": 262144,
  "state_file": "%PROGRAMDATA%\\DaOrcs\\Agent\\state.sqlite3",
  "log_file": "%APPDATA%\\DaOrcs\\Agent\\logs\\agent.log",
  "detections_file": "%APPDATA%\\DaOrcs\\Agent\\logs\\detections.log",
  "log_level": "INFO",
  "api": {
    "enabled": true,
    "host": "0.0.0.0",
    "port": 8787
  },
  "kafka": {
    "bootstrap_servers": "192.168.56.1:9092",
    "topic": "analysis-artifacts",
    "producer_config": {}
  }
}
```

`kafka.bootstrap_servers` must be an address the endpoint can reach. If the
broker runs on the analysis host, use that host's LAN/IP address, not
`127.0.0.1` (unless the broker runs on the same endpoint).

### Detections log

Every captured sample is appended to `detections.log` (JSON Lines, one object
per capture) and rotated at 5 MB with three backups. Runtime messages stay in
`agent.log`, so a collection job can read only detections. If
`detections_file` is omitted, the agent writes `detections.log` next to
`log_file`.

```json
{"detected_at":"2026-11-13T10:39:09.414+00:00","event":"sample_detected","file_name":"invoice.exe","file_path":"C:\\Users\\Public\\Downloads\\invoice.exe","file_size":360496,"sha256":"52a0…","host":"win-user","username":"vboxuser","kafka_topic":"analysis-artifacts","agent_version":"0.4.0"}
```

## Heartbeat API

The agent runs a small read-only HTTP server so an admin can check on it
without waiting for the next Kafka publish. It is part of the agent process:
if the service is up, the API is up, and it works even when Kafka is down (the
answer then says so).

`api` keys in `agent.json`:

| Key | Default | Meaning |
| --- | --- | --- |
| `enabled` | `true` | Set to `false` to run the agent with no HTTP listener at all |
| `host` | `127.0.0.1` | Bind address. Use `0.0.0.0` to accept remote checks |
| `port` | `8787` | TCP port |

**The API has no authentication.** It only answers `GET`, never changes state,
and never returns file contents - but it does return host names, watch
directories, sample names and SHA-256 hashes. A non-loopback bind is therefore
logged as a warning, and the port should be limited to the admin panel's
address with a firewall rule (see below). Binding `127.0.0.1` exposes it to the
endpoint only.

On install and upgrade, `windows-service.ps1` creates the `api` block if it is
missing entirely and fills in missing keys, so a very old config without an
`api` section ends up bound to `0.0.0.0`. A `host` key that is present is never
overwritten - even a loopback one, which only earns a warning in the log - so
a widened bind has to come from what was installed, not from the service
script. Since 0.4.1 it does: the panel's generated template binds `0.0.0.0`,
and the installer writes `/APIHOST=` (default `0.0.0.0`) into `agent.json` on a
fresh install. The service script also removes a leftover `token` key from
older installs, because the API no longer reads one.

### Endpoints

| Method | Path | Returns |
| --- | --- | --- |
| GET | `/health` | Minimal liveness: `status`, `version`, `host`, `time` |
| GET | `/api/v1/ping` | Same as `/health` |
| GET | `/api/v1/health` | Full heartbeat snapshot |
| GET | `/api/v1/heartbeat` | Same as `/api/v1/health` |
| GET | `/api/v1/agent` | Same as `/api/v1/health` |
| GET | `/api/v1/detections?limit=N` | Newest detections from `detections.log` (default 20, max 500) |
| POST | `/api/v1/control` | Body `{"action": "stop"}` pauses the scan loop after the current scan; `{"action": "start"}` resumes it. The heartbeat and detections keep answering in both states. This is the one deliberate write; it is how the panel's Terminate agent / Start agent buttons work, since a stopped Windows service could not answer a remote start anyway. |

Anything else returns `404`; other methods return `405`.

The snapshot includes the service state (`starting`, `running`, `scanning`,
`idle`, `paused`, `stopping`) plus `agent.scan_paused` (`true` while the scan
loop is parked), uptime, watch directories, Kafka broker and topic, last publish
result, counters, last scan duration, last detection and last error. Overall
`status` is `ok`, `degraded` (the last Kafka publish failed) or `starting`.

### Checking an agent

```powershell
Invoke-RestMethod http://127.0.0.1:8787/health

Invoke-RestMethod http://192.168.56.106:8787/api/v1/health
Invoke-RestMethod "http://192.168.56.106:8787/api/v1/detections?limit=5"
```

```bash
curl -s http://192.168.56.106:8787/health
curl -s http://192.168.56.106:8787/api/v1/health
curl -s "http://192.168.56.106:8787/api/v1/detections?limit=5"
```

The API adds no firewall rule. A remote check only works if the host firewall
allows the port, for example - scoped to the panel rather than every network:

```powershell
New-NetFirewallRule -DisplayName "DaOrcs Agent API" -Direction Inbound `
  -Protocol TCP -LocalPort 8787 -RemoteAddress 192.168.56.1 -Action Allow
```

To find the port on the agent:

```powershell
powershell -File "$env:ProgramData\DaOrcs\Agent\windows-service.ps1" -Action status
```

`-Action status` prints `Agent API: http://host:port (enabled=…)` and probes
whether the port is open.

## Commands

```powershell
# Service control
Get-Service DaOrcsEndpointAgent
Start-Service DaOrcsEndpointAgent
Restart-Service DaOrcsEndpointAgent
Stop-Service DaOrcsEndpointAgent

# Health check without publishing a sample
& "$env:ProgramData\DaOrcs\Agent\DaOrcsAgent.exe" --self-test `
  --config "$env:ProgramData\DaOrcs\Agent\agent.json"

# Same check plus one test record in the topic
& "$env:ProgramData\DaOrcs\Agent\DaOrcsAgent.exe" --self-test --produce-test `
  --config "$env:ProgramData\DaOrcs\Agent\agent.json"

# One scan, useful on a VM
& "$env:ProgramData\DaOrcs\Agent\DaOrcsAgent.exe" --once `
  --config "$env:ProgramData\DaOrcs\Agent\agent.json"

# Service installer / logs
powershell -File "$env:ProgramData\DaOrcs\Agent\windows-service.ps1" -Action install
powershell -File "$env:ProgramData\DaOrcs\Agent\windows-service.ps1" -Action upgrade
powershell -File "$env:ProgramData\DaOrcs\Agent\windows-service.ps1" -Action status
powershell -File "$env:ProgramData\DaOrcs\Agent\windows-service.ps1" -Action diagnose
Get-Content "$env:APPDATA\DaOrcs\Agent\logs\install.log" -Tail 80
```

Self-test exit codes: `0` healthy, `2` agent healthy but broker unreachable
(the service still runs and retries), `1` local install/config/runtime failure.

## Elevation (UAC)

The installer itself requests elevation (`PrivilegesRequired=admin`), so files
are written to `%ProgramData%` and the service is registered during setup.

The maintenance scripts also self-elevate: `install`, `upgrade` and `uninstall`
detect a non-elevated session, show the Windows UAC prompt and relaunch
themselves in an elevated PowerShell with the same arguments. The friendly
wrapper is:

```cmd
:: Double-click, or run from any prompt
%ProgramData%\DaOrcs\Agent\daorcs-agent-admin.cmd
%ProgramData%\DaOrcs\Agent\daorcs-agent-admin.cmd install
%ProgramData%\DaOrcs\Agent\daorcs-agent-admin.cmd diagnose
```

A Start Menu shortcut, **DaOrcs Endpoint Agent (Administrator)**, points at the
same wrapper. If you launch `windows-service.ps1` directly and UAC is declined,
the action exits with code `1` and nothing is changed.

## Kafka without Docker

Kafka does not require Docker. The installer ships a native Apache Kafka (KRaft)
installer that downloads Kafka and a portable JRE, formats the log directory and
registers `DaOrcsKafka` as a Windows service:

```powershell
# On the broker host, elevated
powershell -ExecutionPolicy Bypass -File "$env:ProgramData\DaOrcs\Agent\kafka\install-kafka-windows.ps1"

# Custom address/port/topic
powershell -ExecutionPolicy Bypass -File "$env:ProgramData\DaOrcs\Agent\kafka\install-kafka-windows.ps1" `
  -AdvertisedHost 192.168.56.1 -Port 9092 -Topic analysis-artifacts

# Remove it
powershell -ExecutionPolicy Bypass -File "$env:ProgramData\DaOrcs\Agent\kafka\uninstall-kafka-windows.ps1"
```

The script writes its own log, and the WinSW service output, under
`%APPDATA%\DaOrcs\Kafka\logs\`.

If you would rather not run Kafka at all, the current agent has only the Kafka
transport. Practical no-Docker options are: the native KRaft scripts above, a
Kafka-compatible broker on a Linux host (for example Redpanda) reached over the
LAN, or an existing managed Kafka endpoint. The agent itself needs no Docker.

## Troubleshooting

| Symptom | Where to look |
| --- | --- |
| Installer showed a service warning | `%APPDATA%\DaOrcs\Agent\logs\install.log`, then `service.log` |
| Service is installed but stopped | `windows-service.ps1 -Action diagnose` |
| Service starts then exits | `%APPDATA%\DaOrcs\Agent\logs\service.log` (config/import error) and `agent.log` |
| Service runs but nothing arrives | Run `--self-test`; check broker TCP reachability and topic |
| `[FAIL] broker ... did not answer` | Start the broker, or fix `bootstrap_servers` and restart the service |
| Files are ignored | They must be real PE files; the agent checks `MZ` + `PE\0\0`, not the extension |

The installer no longer turns a failed service start into a bare "Runtime error"
dialog. It writes the PowerShell exit code and the full service/agent log tails
to `install.log`, leaves the service installed so it can be inspected, and shows
the same result in the post-install terminal.
