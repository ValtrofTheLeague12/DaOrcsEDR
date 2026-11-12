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
| `%APPDATA%\DaOrcs\Agent\logs\service.log` | Service startup failures |
| `%APPDATA%\DaOrcs\Agent\logs\install.log` | Installer + service-install log |
| `%APPDATA%\DaOrcs\Agent\logs\setup.log` | Copy of the Inno Setup installer log |
| `%APPDATA%\DaOrcs\Agent\logs\uninstall.log` | Copy of the Inno Setup uninstaller log |

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
  "log_level": "INFO",
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
powershell -File "$env:ProgramData\DaOrcs\Agent\windows-service.ps1" -Action status
powershell -File "$env:ProgramData\DaOrcs\Agent\windows-service.ps1" -Action diagnose
Get-Content "$env:APPDATA\DaOrcs\Agent\logs\install.log" -Tail 80
```

Self-test exit codes: `0` healthy, `2` agent healthy but broker unreachable
(the service still runs and retries), `1` local install/config/runtime failure.

## Elevation (UAC)

The installer itself requests elevation (`PrivilegesRequired=admin`), so files
are written to `%ProgramData%` and the service is registered during setup.

The maintenance scripts also self-elevate: `install` and `uninstall` detect a
non-elevated session, show the Windows UAC prompt and relaunch themselves in an
elevated PowerShell with the same arguments. The friendly wrapper is:

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
