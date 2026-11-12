<#
.SYNOPSIS
    Runs after the DaOrcs endpoint agent installer finishes.

.DESCRIPTION
    Prints the DaOrcs logo, the installed agent version and the README note,
    then verifies that this endpoint can actually reach its Kafka broker.
    Every result is appended to the installer log so the window is not the
    only record of the check.

    Exit codes are informational; the installer already completed:
      0 - everything checked out
      2 - the agent is installed but the broker is not reachable yet
      1 - a local install problem (config or executable)
#>
param(
    [string]$AppDir = (Split-Path -Parent $MyInvocation.MyCommand.Path),
    [string]$Version = "0.0.0",
    [string]$LogPath = "",
    [switch]$NoPause
)

$ErrorActionPreference = "Continue"
$logFile = if ($LogPath) {
    $LogPath
} else {
    Join-Path $env:APPDATA "DaOrcs\Agent\logs\post-install.log"
}
$logDir = Split-Path -Parent $logFile
$script:Failures = 0
$script:Warnings = 0

try {
    [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new()
    $Host.UI.RawUI.WindowTitle = "DaOrcs Endpoint Agent - Installation Complete"
} catch {
    # A legacy console can refuse the encoding switch; keep going.
}

function Write-Log {
    param([string]$Message)
    try {
        $dir = Split-Path -Parent $logFile
        if ($dir) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
        Add-Content -LiteralPath $logFile -Encoding UTF8 -Value (
            "{0} {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Message)
    } catch {
        # The terminal output is still useful if the log cannot be written.
    }
}

function Write-Section {
    param([string]$Title)
    Write-Host ""
    Write-Host ("  " + ("-" * 68)) -ForegroundColor DarkGray
    Write-Host ("  " + $Title) -ForegroundColor Cyan
    Write-Host ("  " + ("-" * 68)) -ForegroundColor DarkGray
}

function Write-Ok {
    param([string]$Message)
    Write-Host ("  [ OK ]   " + $Message) -ForegroundColor Green
    Write-Log "OK   $Message"
}

function Write-Warn {
    param([string]$Message)
    $script:Warnings++
    Write-Host ("  [WARN]   " + $Message) -ForegroundColor Yellow
    Write-Log "WARN $Message"
}

function Write-Fail {
    param([string]$Message)
    $script:Failures++
    Write-Host ("  [FAIL]   " + $Message) -ForegroundColor Red
    Write-Log "FAIL $Message"
}

function Test-TcpPort {
    param([string]$HostName, [int]$Port, [int]$TimeoutMs = 2500)
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $async = $client.BeginConnect($HostName, $Port, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) {
            return $false
        }
        $client.EndConnect($async)
        return $true
    } catch {
        return $false
    } finally {
        $client.Close()
    }
}

function Show-Logo {
    $logo = Join-Path $AppDir "daorcs.logo"
    Write-Host ""
    if (Test-Path -LiteralPath $logo -PathType Leaf) {
        try {
            foreach ($line in (Get-Content -LiteralPath $logo -Encoding UTF8)) {
                Write-Host ("  " + $line) -ForegroundColor Cyan
            }
        } catch {
            Write-Host "  DaOrcs" -ForegroundColor Cyan
        }
    } else {
        Write-Host "  DaOrcs" -ForegroundColor Cyan
    }
}

Show-Logo
Write-Host ""
Write-Host "  DaOrcs Endpoint Agent" -ForegroundColor White -BackgroundColor DarkRed
Write-Host "  Version $Version" -ForegroundColor Gray
Write-Host "  Installation complete." -ForegroundColor White
Write-Log "===== Post-install check for DaOrcs Endpoint Agent $Version ====="

$configPath = Join-Path $AppDir "agent.json"
if (-not (Test-Path -LiteralPath $configPath -PathType Leaf)) {
    $configPath = Join-Path $env:ProgramData "DaOrcs\Agent\agent.json"
}
$exePath = Join-Path $AppDir "DaOrcsAgent.exe"

Write-Section "1. Installed files"
if (Test-Path -LiteralPath $exePath -PathType Leaf) {
    Write-Ok "Agent executable: $exePath"
} else {
    Write-Fail "Agent executable is missing: $exePath"
}
if (Test-Path -LiteralPath $configPath -PathType Leaf) {
    Write-Ok "Agent configuration: $configPath"
} else {
    Write-Fail "Agent configuration is missing: $configPath"
}
Write-Host ("  Installer log:  " + $logFile)
Write-Host ("  Service log:    " + (Join-Path $logDir "service.log"))
Write-Host ("  Agent log:      " + (Join-Path $logDir "agent.log"))
Write-Log "AppDir=$AppDir Config=$configPath"

Write-Section "2. Configuration"
$config = $null
if (Test-Path -LiteralPath $configPath -PathType Leaf) {
    try {
        $config = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
        Write-Ok "agent.json is valid JSON"
    } catch {
        Write-Fail "agent.json is not valid JSON: $($_.Exception.Message)"
    }
}
if ($config) {
    $brokers = [string]$config.kafka.bootstrap_servers
    $topic = [string]$config.kafka.topic
    Write-Host ("  Kafka brokers:  " + $brokers)
    Write-Host ("  Kafka topic:    " + $topic)
    Write-Log "Brokers=$brokers Topic=$topic"
    if (-not $brokers) { Write-Fail "kafka.bootstrap_servers is empty" }
    if (-not $topic) { Write-Fail "kafka.topic is empty" }
    foreach ($raw in @($config.watch_dirs)) {
        $expanded = [Environment]::ExpandEnvironmentVariables([string]$raw)
        if (Test-Path -LiteralPath $expanded -PathType Container) {
            Write-Ok "Watched folder: $expanded"
        } else {
            Write-Warn "Watched folder does not exist yet: $expanded"
        }
    }
}

Write-Section "3. Windows service"
$service = Get-Service -Name "DaOrcsEndpointAgent" -ErrorAction SilentlyContinue
if (-not $service) {
    Write-Fail "DaOrcsEndpointAgent is not installed as a Windows service"
} elseif ($service.Status -eq "Running") {
    Write-Ok "DaOrcsEndpointAgent is running (startup: $($service.StartType))"
} else {
    Write-Fail "DaOrcsEndpointAgent is installed but $($service.Status)"
    Write-Host "          Retry:  powershell -File `"$AppDir\windows-service.ps1`" -Action install" -ForegroundColor Yellow
    Write-Host "          Details: $logFile" -ForegroundColor Yellow
}

Write-Section "4. Broker TCP reachability"
if ($config -and $config.kafka.bootstrap_servers) {
    foreach ($entry in ([string]$config.kafka.bootstrap_servers -split ",")) {
        $entry = $entry.Trim()
        if (-not $entry) { continue }
        $parts = $entry.Split(":")
        if ($parts.Count -lt 2) {
            Write-Warn "Cannot parse broker address: $entry"
            continue
        }
        $port = 0
        [void][int]::TryParse($parts[-1], [ref]$port)
        $hostName = ($parts[0..($parts.Count - 2)] -join ":")
        if (Test-TcpPort -HostName $hostName -Port $port) {
            Write-Ok "Broker $hostName`:$port answered"
        } else {
            Write-Fail "Broker $hostName`:$port did not answer"
        }
    }
} else {
    Write-Warn "No broker configured, so reachability was not checked"
}

Write-Section "5. Agent self-test (runtime + Kafka metadata)"
if (Test-Path -LiteralPath $exePath -PathType Leaf) {
    $output = & $exePath --self-test --config $configPath 2>&1
    $code = $LASTEXITCODE
    foreach ($line in @($output)) {
        $text = "$line"
        $colour = "Gray"
        if ($text -match "^\s*OK") { $colour = "Green" }
        elseif ($text -match "^\s*WARN") { $colour = "Yellow" }
        elseif ($text -match "^\s*FAIL") { $colour = "Red" }
        Write-Host ("  " + $text) -ForegroundColor $colour
        Write-Log "selftest | $text"
    }
    switch ($code) {
        0 { Write-Ok "Agent runtime and Kafka connection are healthy" }
        2 { Write-Warn "Agent is healthy but the broker is offline; it will retry automatically" }
        default { Write-Fail "Agent self-test failed with exit code $code" }
    }
} else {
    Write-Fail "Cannot run the self-test because the executable is missing"
}

Write-Section "What to do next"
Write-Host "  * The agent reads its config from:" -ForegroundColor White
Write-Host "      $configPath"
Write-Host "  * Point kafka.bootstrap_servers at the machine running the broker,"
Write-Host "    then restart the service:"
Write-Host "      Restart-Service DaOrcsEndpointAgent"
Write-Host "  * Watch the agent log:"
Write-Host "      Get-Content `"$logDir\agent.log`" -Wait"
Write-Host "  * No Docker? Install a native Kafka broker with:"
Write-Host "      powershell -File `"$AppDir\kafka\install-kafka-windows.ps1`""
Write-Host "  * Full notes: $AppDir\README-AGENT.md" -ForegroundColor DarkGray
Write-Log "Post-install finished: failures=$script:Failures warnings=$script:Warnings"

Write-Host ""
if ($script:Failures -gt 0) {
    Write-Host "  RESULT: $script:Failures problem(s), $script:Warnings warning(s)." -ForegroundColor Red
} elseif ($script:Warnings -gt 0) {
    Write-Host "  RESULT: installed with $script:Warnings warning(s)." -ForegroundColor Yellow
} else {
    Write-Host "  RESULT: everything is healthy." -ForegroundColor Green
}
Write-Host "  Log: $logFile" -ForegroundColor DarkGray
Write-Host ""

if (-not $NoPause -and $Host.Name -eq "ConsoleHost") {
    Read-Host "  Press Enter to close this window" | Out-Null
}

if ($script:Failures -gt 0) { exit 1 }
if ($script:Warnings -gt 0) { exit 2 }
exit 0
