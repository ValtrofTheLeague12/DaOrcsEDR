param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("install", "upgrade", "uninstall", "status", "diagnose")]
    [string]$Action,
    [string]$LogPath = ""
)

$ErrorActionPreference = "Stop"
$serviceName = "DaOrcsEndpointAgent"
$taskName = "DaOrcs Endpoint Agent"

function Get-AgentLogDir {
    param([string]$RequestedLogPath = "")
    if ($RequestedLogPath) {
        return (Split-Path -Parent $RequestedLogPath)
    }
    # A repair/status run may be started by a different administrator than the
    # one who installed. The service's environment records the real log folder.
    try {
        $key = "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName"
        $environment = (Get-ItemProperty -Path $key -Name Environment -ErrorAction Stop).Environment
        foreach ($entry in @($environment)) {
            if ("$entry" -like "DAORCS_LOG_DIR=*") {
                return "$entry".Substring("DAORCS_LOG_DIR=".Length)
            }
        }
    } catch {
        # Service not installed yet, or no environment value: use this user.
    }
    return (Join-Path $env:APPDATA "DaOrcs\Agent\logs")
}

$script:LogDir = Get-AgentLogDir -RequestedLogPath $LogPath
$script:LogFile = if ($LogPath) {
    $LogPath
} else {
    Join-Path $script:LogDir "install.log"
}

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Restart-Elevated {
    param(
        [hashtable]$BoundParameters,
        [string]$Reason
    )
    # Rebuild the original command line from the bound parameters so the
    # elevated child performs exactly the same action. Start-Process joins the
    # list with spaces, so every value is quoted explicitly.
    $arguments = New-Object System.Collections.Generic.List[string]
    $arguments.Add("-NoProfile")
    $arguments.Add("-ExecutionPolicy")
    $arguments.Add("Bypass")
    $arguments.Add("-File")
    $arguments.Add("`"$PSCommandPath`"")
    foreach ($name in $BoundParameters.Keys) {
        $value = $BoundParameters[$name]
        if ($value -is [System.Management.Automation.SwitchParameter]) {
            if ($value.IsPresent) { $arguments.Add("-$name") }
        } elseif ($null -ne $value -and "$value" -ne "") {
            $arguments.Add("-$name")
            $arguments.Add("`"$value`"")
        }
    }

    Write-Host ""
    Write-Host "  $Reason requires administrator privileges." -ForegroundColor Yellow
    Write-Host "  Accept the Windows UAC prompt to continue..." -ForegroundColor Yellow
    try {
        $process = Start-Process `
            -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
            -Verb RunAs `
            -ArgumentList $arguments `
            -PassThru `
            -Wait
    } catch {
        Write-Host "  Elevation was cancelled: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
    exit $process.ExitCode
}

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO", "WARN", "ERROR")]
        [string]$Level = "INFO"
    )
    $line = "{0} {1,-5} {2}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Level, $Message
    Write-Host $line
    try {
        $dir = Split-Path -Parent $script:LogFile
        if ($dir) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
        Add-Content -LiteralPath $script:LogFile -Value $line -Encoding UTF8
    } catch {
        # Logging must never be the reason a service install fails.
    }
}

function Set-AgentLogLocation {
    param(
        [string]$ConfigPath,
        [string]$LogDir
    )
    if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) {
        Write-Log "No agent config to update at $ConfigPath" "WARN"
        return
    }
    try {
        $doc = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
        $doc.log_file = Join-Path $LogDir "agent.log"
        $doc.detections_file = Join-Path $LogDir "detections.log"
        $json = $doc | ConvertTo-Json -Depth 20
        # PowerShell 5.1's Set-Content -Encoding UTF8 adds a BOM, which Python's
        # json.loads does not strip. Write UTF-8 without a BOM instead.
        $utf8 = New-Object System.Text.UTF8Encoding($false)
        [IO.File]::WriteAllText($ConfigPath, $json, $utf8)
        Write-Log "Agent log configured: $($doc.log_file)"
    } catch {
        Write-Log "Could not set log_file in ${ConfigPath}: $($_.Exception.Message)" "WARN"
    }
}

function Set-AgentApiSettings {
    param(
        [string]$ConfigPath,
        [int]$Port = 8787
    )
    # The heartbeat API is read-only and unauthenticated. A fresh config gets a
    # 0.0.0.0 bind so the admin panel can reach it; the installer adds no
    # firewall rule, so that stays a deliberate step. A host an operator already
    # chose is never overwritten - narrowing back to loopback is a legitimate
    # decision, not a mistake to correct.
    if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) {
        Write-Log "No agent config to update at $ConfigPath" "WARN"
        return
    }
    try {
        $doc = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
        $changed = $false

        if ($null -eq $doc.api) {
            $doc | Add-Member -NotePropertyName api -NotePropertyValue (
                [pscustomobject]@{ enabled = $true; host = "0.0.0.0"; port = $Port }
            ) -Force
            $changed = $true
        }
        $api = $doc.api

        if (-not $api.PSObject.Properties["enabled"]) {
            $api | Add-Member -NotePropertyName enabled -NotePropertyValue $true
            $changed = $true
        }
        if (-not $api.PSObject.Properties["port"]) {
            $api | Add-Member -NotePropertyName port -NotePropertyValue $Port
            $changed = $true
        }
        if (-not $api.PSObject.Properties["host"]) {
            $api | Add-Member -NotePropertyName host -NotePropertyValue "0.0.0.0"
            $changed = $true
        }

        # Upgrades from 0.4.0 or earlier carry a bearer token. The API no longer
        # reads it; drop it so agent.json does not advertise auth that is gone.
        if ($api.PSObject.Properties["token"]) {
            $api.PSObject.Properties.Remove("token")
            $changed = $true
        }

        if ($changed) {
            $json = $doc | ConvertTo-Json -Depth 20
            $utf8 = New-Object System.Text.UTF8Encoding($false)
            [IO.File]::WriteAllText($ConfigPath, $json, $utf8)
            Write-Log ("Agent API configured: http://{0}:{1} (read-only, no auth)" -f
                $api.host, $api.port)
        } else {
            Write-Log ("Agent API unchanged: http://{0}:{1} (read-only, no auth)" -f
                $api.host, $api.port)
        }
        if ("$($api.host)" -in @("127.0.0.1", "localhost", "::1")) {
            Write-Log ("Agent API is loopback-bound; set api.host to 0.0.0.0 in " +
                "$ConfigPath to let the admin panel reach it") "WARN"
        }
    } catch {
        Write-Log "Could not configure the agent API in ${ConfigPath}: $($_.Exception.Message)" "WARN"
    }
}

function Set-ServiceLogEnvironment {
    param(
        [string]$Name,
        [string]$LogDir
    )
    # The service runs as LocalSystem, so its own %APPDATA% is the system
    # profile. Give the service an explicit log folder in the installing
    # user's AppData; the agent reads DAORCS_LOG_DIR before it loads config.
    $key = "HKLM:\SYSTEM\CurrentControlSet\Services\$Name"
    $value = @("DAORCS_LOG_DIR=$LogDir")
    New-ItemProperty -Path $key -Name Environment -PropertyType MultiString `
        -Value $value -Force | Out-Null
    Write-Log "Service $Name log folder: $LogDir"
}

function Invoke-Native {
    param(
        [string]$FilePath,
        [string[]]$ArgumentList,
        [string]$What
    )
    Write-Log ("RUN {0}: `"{1}`" {2}" -f $What, $FilePath, ($ArgumentList -join " "))
    # sc.exe/schtasks.exe write failures to stderr. With ErrorActionPreference
    # set to Stop, PowerShell 5.1 turns redirected native stderr into a
    # terminating error, which would hide the real exit code.
    $previous = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $output = & $FilePath @ArgumentList 2>&1
        $code = $LASTEXITCODE
    } catch {
        Write-Log ("{0} could not run: {1}" -f $What, $_.Exception.Message) "ERROR"
        $ErrorActionPreference = $previous
        return 1
    } finally {
        $ErrorActionPreference = $previous
    }
    foreach ($line in @($output)) {
        if ("$line".Trim()) { Write-Log ("  {0} | {1}" -f $What, "$line") }
    }
    Write-Log ("{0} exit code: {1}" -f $What, $code)
    return $code
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

function Get-AgentConfigPath {
    $local = Join-Path $PSScriptRoot "agent.json"
    if (Test-Path -LiteralPath $local -PathType Leaf) { return $local }
    return (Join-Path $env:ProgramData "DaOrcs\Agent\agent.json")
}

function Stop-AgentService {
    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if (-not $service) { return }
    if ($service.Status -ne "Stopped") {
        Write-Log "Stopping $serviceName (current status: $($service.Status))"
        Stop-Service -Name $serviceName -Force
        $service = Get-Service -Name $serviceName
        $service.WaitForStatus(
            [System.ServiceProcess.ServiceControllerStatus]::Stopped,
            [TimeSpan]::FromSeconds(30)
        )
    }
}

function Remove-AgentService {
    Stop-AgentService
    if (-not (Get-Service -Name $serviceName -ErrorAction SilentlyContinue)) {
        Write-Log "$serviceName is not installed"
        return
    }

    [void](Invoke-Native "$env:SystemRoot\System32\sc.exe" @("delete", $serviceName) "sc delete")
    $deadline = [DateTime]::UtcNow.AddSeconds(20)
    while ((Get-Service -Name $serviceName -ErrorAction SilentlyContinue) -and
           [DateTime]::UtcNow -lt $deadline) {
        Start-Sleep -Milliseconds 250
    }
    if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
        throw "Windows has not released the previous $serviceName service yet."
    }
    Write-Log "Removed the previous $serviceName service"
}

function Invoke-AgentSelfTest {
    $executable = Join-Path $PSScriptRoot "DaOrcsAgent.exe"
    $config = Get-AgentConfigPath
    if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) {
        throw "The agent executable was not found: $executable"
    }
    if (-not (Test-Path -LiteralPath $config -PathType Leaf)) {
        throw "The agent configuration was not found: $config"
    }

    Write-Log "Running the agent self-test"
    $previous = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $output = & $executable --self-test --config $config 2>&1
        $code = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previous
    }
    foreach ($line in @($output)) {
        Write-Log ("  selftest | {0}" -f "$line")
    }
    Write-Log "Self-test exit code: $code"
    return $code
}

function Write-ServiceDiagnostics {
    Write-Log "Collecting service diagnostics" "WARN"
    [void](Invoke-Native "$env:SystemRoot\System32\sc.exe" @("queryex", $serviceName) "sc queryex")
    [void](Invoke-Native "$env:SystemRoot\System32\sc.exe" @("qc", $serviceName) "sc qc")

    $since = (Get-Date).AddMinutes(-15)
    try {
        $events = Get-WinEvent -FilterHashtable @{
            LogName = "Application"
            StartTime = $since
        } -ErrorAction SilentlyContinue | Where-Object {
            $_.Message -match "DaOrcs|DaOrcsEndpointAgent|Python|service"
        } | Select-Object -First 10
        foreach ($event in @($events)) {
            Write-Log ("EVENT {0} {1} id={2}: {3}" -f
                $event.TimeCreated, $event.ProviderName, $event.Id,
                (($event.Message -split "`r?`n")[0])) "ERROR"
        }
    } catch {
        Write-Log "Could not read the Application event log: $($_.Exception.Message)" "WARN"
    }

    foreach ($name in @("agent.log", "service.log")) {
        $path = Join-Path $script:LogDir $name
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            Write-Log "Last lines of ${path}:"
            Get-Content -LiteralPath $path -Tail 25 -ErrorAction SilentlyContinue |
                ForEach-Object { Write-Log ("  {0} | {1}" -f $name, $_) }
        }
    }
}

function Show-AgentStatus {
    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($service) {
        Write-Log "Service: $serviceName status=$($service.Status) start=$($service.StartType)"
        [void](Invoke-Native "$env:SystemRoot\System32\sc.exe" @("qc", $serviceName) "sc qc")
    } else {
        Write-Log "Service: $serviceName is not installed" "WARN"
    }

    $config = Get-AgentConfigPath
    Write-Log "Config: $config (exists=$(Test-Path -LiteralPath $config))"
    Write-Log "Logs:   $script:LogDir"
    if (Test-Path -LiteralPath $config -PathType Leaf) {
        try {
            $doc = Get-Content -LiteralPath $config -Raw | ConvertFrom-Json
            Write-Log "Brokers: $($doc.kafka.bootstrap_servers)"
            Write-Log "Topic: $($doc.kafka.topic)"
            $api = $doc.api
            $apiHost = if ($api -and $api.host) { "$($api.host)" } else { "127.0.0.1" }
            $apiPort = if ($api -and $api.port) { [int]$api.port } else { 8787 }
            $apiEnabled = if ($api -and $api.PSObject.Properties["enabled"]) {
                [bool]$api.enabled
            } else { $true }
            Write-Log ("Agent API: http://{0}:{1} (enabled={2}, auth=none)" -f
                $apiHost, $apiPort, $apiEnabled)
            $probeHost = if ($apiHost -in @("0.0.0.0", "::")) { "127.0.0.1" } else { $apiHost }
            Write-Log ("Agent API probe {0}:{1} => {2}" -f
                $probeHost, $apiPort,
                $(if (Test-TcpPort -HostName $probeHost -Port $apiPort) { "OPEN" } else { "CLOSED" }))
            foreach ($entry in ("$($doc.kafka.bootstrap_servers)" -split ",")) {
                $entry = $entry.Trim()
                if (-not $entry) { continue }
                $parts = $entry.Split(":")
                if ($parts.Count -ge 2) {
                    $port = 0
                    [void][int]::TryParse($parts[-1], [ref]$port)
                    $hostName = ($parts[0..($parts.Count - 2)] -join ":")
                    $open = Test-TcpPort -HostName $hostName -Port $port
                    Write-Log ("Broker probe {0}:{1} => {2}" -f
                        $hostName, $port, $(if ($open) { "OPEN" } else { "CLOSED" }))
                }
            }
        } catch {
            Write-Log "Could not read config: $($_.Exception.Message)" "ERROR"
        }
    }
}

function Install-AgentService {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Installing the DaOrcs agent service requires an elevated administrator."
    }

    Write-Log "DaOrcs endpoint agent service install starting (user=$($identity.Name))"
    Write-Log "Log folder: $script:LogDir"
    Set-AgentLogLocation -ConfigPath (Get-AgentConfigPath) -LogDir $script:LogDir
    Set-AgentApiSettings -ConfigPath (Get-AgentConfigPath)
    $selfTest = Invoke-AgentSelfTest
    if ($selfTest -eq 1) {
        throw "The agent self-test failed before service installation. See $script:LogFile"
    }
    if ($selfTest -eq 2) {
        Write-Log "The Kafka broker is not reachable yet; the service will still be installed and will retry." "WARN"
    }

    $executable = Join-Path $PSScriptRoot "DaOrcsAgent.exe"
    $binaryPath = '"{0}" --service' -f $executable

    # Remove the task created by older installers so it cannot start a second copy.
    [void](Invoke-Native "$env:SystemRoot\System32\schtasks.exe" @("/End", "/TN", $taskName) "schtasks end")
    [void](Invoke-Native "$env:SystemRoot\System32\schtasks.exe" @("/Delete", "/TN", $taskName, "/F") "schtasks delete")

    Remove-AgentService

    try {
        New-Service `
            -Name $serviceName `
            -DisplayName "DaOrcs Endpoint Agent" `
            -Description "Monitors configured folders and publishes PE samples to Kafka." `
            -BinaryPathName $binaryPath `
            -StartupType Automatic | Out-Null
        Write-Log "Created service $serviceName -> $binaryPath"

        Set-ServiceLogEnvironment -Name $serviceName -LogDir $script:LogDir

        [void](Invoke-Native "$env:SystemRoot\System32\sc.exe" @(
            "config", $serviceName, "start=", "delayed-auto") "sc config")
        [void](Invoke-Native "$env:SystemRoot\System32\sc.exe" @(
            "failure", $serviceName, "reset=", "86400", "actions=",
            "restart/60000/restart/60000/restart/60000") "sc failure")

        Write-Log "Starting $serviceName"
        Start-Service -Name $serviceName
        $service = Get-Service -Name $serviceName
        $service.WaitForStatus(
            [System.ServiceProcess.ServiceControllerStatus]::Running,
            [TimeSpan]::FromSeconds(60)
        )
        Write-Log "Service $serviceName is running"
        return 0
    } catch {
        Write-Log "Service $serviceName did not start: $($_.Exception.Message)" "ERROR"
        Write-Log "The service is installed but stopped. Nothing was deleted so it can be inspected." "ERROR"
        Write-ServiceDiagnostics
        Write-Log "See $script:LogFile and $script:LogDir\service.log" "ERROR"
        return 3
    }
}

function Update-AgentService {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Updating the DaOrcs agent service requires an elevated administrator."
    }

    Write-Log "DaOrcs endpoint agent service update starting (user=$($identity.Name))"
    Write-Log "Log folder: $script:LogDir"

    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if (-not $service) {
        # A repair run on a half-installed endpoint: fall back to a full install.
        Write-Log "The existing $serviceName service was not found; performing a full install" "WARN"
        return (Install-AgentService)
    }

    Write-Log "Existing service detected: $serviceName status=$($service.Status) start=$($service.StartType)"
    Set-AgentLogLocation -ConfigPath (Get-AgentConfigPath) -LogDir $script:LogDir
    Set-AgentApiSettings -ConfigPath (Get-AgentConfigPath)
    $selfTest = Invoke-AgentSelfTest
    if ($selfTest -eq 1) {
        throw "The agent self-test failed before the service update. See $script:LogFile"
    }
    if ($selfTest -eq 2) {
        Write-Log "The Kafka broker is not reachable yet; the updated service will still be restarted and will retry." "WARN"
    }

    $executable = Join-Path $PSScriptRoot "DaOrcsAgent.exe"
    $binaryPath = '"{0}" --service' -f $executable

    [void](Invoke-Native "$env:SystemRoot\System32\schtasks.exe" @("/End", "/TN", $taskName) "schtasks end")
    [void](Invoke-Native "$env:SystemRoot\System32\schtasks.exe" @("/Delete", "/TN", $taskName, "/F") "schtasks delete")

    Stop-AgentService

    try {
        # Keep the same registration and configuration; only repoint it at the
        # updated files. This preserves the service SID and any local policy.
        [void](Invoke-Native "$env:SystemRoot\System32\sc.exe" @(
            "config", $serviceName, "binPath=", $binaryPath) "sc config")
        Set-ServiceLogEnvironment -Name $serviceName -LogDir $script:LogDir
        [void](Invoke-Native "$env:SystemRoot\System32\sc.exe" @(
            "config", $serviceName, "start=", "delayed-auto") "sc config")
        [void](Invoke-Native "$env:SystemRoot\System32\sc.exe" @(
            "failure", $serviceName, "reset=", "86400", "actions=",
            "restart/60000/restart/60000/restart/60000") "sc failure")

        Write-Log "Restarting $serviceName after the update"
        Start-Service -Name $serviceName
        $service = Get-Service -Name $serviceName
        $service.WaitForStatus(
            [System.ServiceProcess.ServiceControllerStatus]::Running,
            [TimeSpan]::FromSeconds(60)
        )
        Write-Log "Service $serviceName is running (updated in place)"
        return 0
    } catch {
        Write-Log "Service $serviceName did not restart after the update: $($_.Exception.Message)" "ERROR"
        Write-Log "The updated files are in place; nothing was rolled back." "ERROR"
        Write-ServiceDiagnostics
        Write-Log "See $script:LogFile and $script:LogDir\service.log" "ERROR"
        return 3
    }
}

if (-not (Test-IsAdministrator) -and
    ($Action -eq "install" -or $Action -eq "upgrade" -or $Action -eq "uninstall")) {
    Restart-Elevated -BoundParameters $PSBoundParameters -Reason "The '$Action' action"
}

try {
    switch ($Action) {
        "install" {
            exit (Install-AgentService)
        }
        "upgrade" {
            exit (Update-AgentService)
        }
        "uninstall" {
            Write-Log "DaOrcs endpoint agent service uninstall starting"
            Remove-AgentService
            [void](Invoke-Native "$env:SystemRoot\System32\schtasks.exe" @("/End", "/TN", $taskName) "schtasks end")
            [void](Invoke-Native "$env:SystemRoot\System32\schtasks.exe" @("/Delete", "/TN", $taskName, "/F") "schtasks delete")
            Write-Log "Uninstall complete"
            exit 0
        }
        "status" {
            Show-AgentStatus
            exit 0
        }
        "diagnose" {
            Show-AgentStatus
            $code = Invoke-AgentSelfTest
            exit $code
        }
    }
} catch {
    Write-Log "FATAL: $($_.Exception.Message)" "ERROR"
    Write-Log $_.ScriptStackTrace "ERROR"
    exit 1
}
