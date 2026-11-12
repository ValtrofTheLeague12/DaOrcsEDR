# Native Kafka for DaOrcs (no Docker)

These scripts install a single-node Apache Kafka broker on Windows without
Docker, WSL or an external JVM requirement. They ship with the DaOrcs endpoint
agent installer under `%ProgramData%\DaOrcs\Agent\kafka\`.

## What gets installed

| Path | Contents |
| --- | --- |
| `%ProgramFiles%\DaOrcs\Kafka` | Kafka 3.9.1 distribution and WinSW |
| `%ProgramData%\DaOrcs\Kafka\server.properties` | Generated KRaft broker config |
| `%ProgramData%\DaOrcs\Kafka\kafka-logs` | Broker data (topics, offsets) |
| `%ProgramData%\DaOrcs\Kafka\jre` | Portable Temurin 17 JRE, only if no Java 11+ was found |
| `%APPDATA%\DaOrcs\Kafka\logs` | Installer log and WinSW service console output |
| `%ProgramData%\DaOrcs\Kafka\endpoint-agent.json.example` | Agent config pointed at this broker |

The broker runs as the `DaOrcsKafka` Windows service. The default listener is
`PLAINTEXT://<advertised-host>:9092` (controller on `127.0.0.1:9093`).

## Install

Run it from any prompt on the broker host (it requests elevation itself):

```powershell
powershell -ExecutionPolicy Bypass -File "$env:ProgramData\DaOrcs\Agent\kafka\install-kafka-windows.ps1"
```

If the session is not elevated, the script shows the Windows UAC prompt and
restarts itself with the same options. It needs administrator rights to write
under `%ProgramFiles%` / `%ProgramData%`, register the service and add the
firewall rule. Both Kafka scripts abort with exit code `1` if UAC is declined.

Useful options:

```powershell
# Choose the address endpoints will connect to (use the host's LAN IP)
... -AdvertisedHost 192.168.56.1

# Change ports / topic / install locations
... -Port 9092 -ControllerPort 9093 -Topic analysis-artifacts `
    -InstallDir "D:\DaOrcs\Kafka" -DataDir "D:\DaOrcs\KafkaData"

# Download Java even if one is already installed / run without the Windows service
... -NoJavaDownload        # fail if Java 11+ is missing
... -NoService             # run in the background, no WinSW service (testing)
... -NoFirewall            # do not create the inbound TCP rule
```

The script is idempotent: re-running it stops the existing service, replaces
the distribution when `-Force` is given, reuses formatted storage and makes
sure the topic exists.

### Advertised host matters

`advertised.listeners` is the address Kafka tells clients to connect to after
the initial bootstrap connection. If remote endpoint agents must reach the
broker, pass the host's LAN IP:

```powershell
... -AdvertisedHost (Get-NetIPAddress -AddressFamily IPv4 |
        Where-Object { $_.IPAddress -notlike "127.*" } |
        Select-Object -First 1 -ExpandProperty IPAddress)
```

Using `127.0.0.1` only works for agents running on the broker machine. The
installer logs a warning when the advertised host is loopback.

## Verify

```powershell
Get-Service DaOrcsKafka
Get-NetTCPConnection -LocalPort 9092 -State Listen

# Topic listing through the bundled CLI
& "$env:ProgramFiles\DaOrcs\Kafka\bin\windows\kafka-topics.bat" `
    --bootstrap-server 127.0.0.1:9092 --list

# End-to-end check from the agent (exit 0 = healthy, 2 = broker offline)
& "$env:ProgramData\DaOrcs\Agent\DaOrcsAgent.exe" --self-test --produce-test `
    --config "$env:ProgramData\DaOrcs\Agent\agent.json"
```

## Logs

| Path | Contents |
| --- | --- |
| `%APPDATA%\DaOrcs\Kafka\logs\install-kafka-*.log` | Installer transcript |
| `%APPDATA%\DaOrcs\Kafka\logs\service\*.log` | WinSW service stdout/stderr |
| `%APPDATA%\DaOrcs\Kafka\logs\kafka-console*.log` | Output when run with `-NoService` |
| `%ProgramData%\DaOrcs\Kafka\kafka-logs\server.log` | Kafka broker log |

## Uninstall

```powershell
# Stop and unregister the service, remove the distribution, keep broker data
powershell -ExecutionPolicy Bypass -File "$env:ProgramData\DaOrcs\Agent\kafka\uninstall-kafka-windows.ps1"

# Also delete topics/offsets and the portable JRE
... -RemoveData

# Remove the service but keep the Kafka distribution on disk
... -KeepFiles
```

## Pointing endpoint agents at this broker

Edit `%ProgramData%\DaOrcs\Agent\agent.json` on each endpoint:

```json
"kafka": {
  "bootstrap_servers": "192.168.56.1:9092",
  "topic": "analysis-artifacts",
  "producer_config": {}
}
```

Then restart the agent service:

```powershell
Restart-Service DaOrcsEndpointAgent
```

The install script writes a ready-made copy of the agent config to
`%ProgramData%\DaOrcs\Kafka\endpoint-agent.json.example` with the advertised
host and topic already filled in.

## Notes

- Only one broker is installed. Replication factors are 1; that is fine for a
  lab/analysis network but is not highly available.
- KRaft storage is formatted once. Deleting `kafka-logs` requires re-running
  the installer so a new cluster id is written.
- `tar.exe` is required to unpack the Kafka archive; Windows 10 1803+ and
  Windows Server 2019+ include it.
