param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("install", "uninstall")]
    [string]$Action
)

$ErrorActionPreference = "Stop"
$serviceName = "DaOrcsEndpointAgent"
$taskName = "DaOrcs Endpoint Agent"

function Stop-AgentService {
    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($service -and $service.Status -ne "Stopped") {
        Stop-Service -Name $serviceName -Force
        $service = Get-Service -Name $serviceName
        $service.WaitForStatus(
            [System.ServiceProcess.ServiceControllerStatus]::Stopped,
            [TimeSpan]::FromSeconds(20)
        )
    }
}

function Remove-AgentService {
    Stop-AgentService
    if (-not (Get-Service -Name $serviceName -ErrorAction SilentlyContinue)) {
        return
    }

    & "$env:SystemRoot\System32\sc.exe" delete $serviceName | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Windows could not remove service $serviceName (exit $LASTEXITCODE)."
    }

    $deadline = [DateTime]::UtcNow.AddSeconds(15)
    while ((Get-Service -Name $serviceName -ErrorAction SilentlyContinue) -and
           [DateTime]::UtcNow -lt $deadline) {
        Start-Sleep -Milliseconds 250
    }
    if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
        throw "Windows has not released the previous $serviceName service yet."
    }
}

if ($Action -eq "uninstall") {
    Remove-AgentService
    & "$env:SystemRoot\System32\schtasks.exe" /End /TN $taskName 2>$null | Out-Null
    & "$env:SystemRoot\System32\schtasks.exe" /Delete /TN $taskName /F 2>$null | Out-Null
    exit 0
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Installing the DaOrcs agent service requires an elevated administrator."
}

$executable = Join-Path $PSScriptRoot "DaOrcsAgent.exe"
if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) {
    throw "The agent executable was not found: $executable"
}

# Remove the task created by older installers so it cannot start a second copy.
& "$env:SystemRoot\System32\schtasks.exe" /End /TN $taskName 2>$null | Out-Null
& "$env:SystemRoot\System32\schtasks.exe" /Delete /TN $taskName /F 2>$null | Out-Null

Remove-AgentService
$binaryPath = '"{0}" --service' -f $executable
try {
    New-Service `
        -Name $serviceName `
        -DisplayName "DaOrcs Endpoint Agent" `
        -Description "Monitors configured folders and publishes PE samples to Kafka." `
        -BinaryPathName $binaryPath `
        -StartupType Automatic | Out-Null

    & "$env:SystemRoot\System32\sc.exe" failure $serviceName `
        reset= 86400 actions= restart/60000/restart/60000/restart/60000 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Could not configure automatic service recovery (exit $LASTEXITCODE)."
    }

    Start-Service -Name $serviceName
    $service = Get-Service -Name $serviceName
    $service.WaitForStatus(
        [System.ServiceProcess.ServiceControllerStatus]::Running,
        [TimeSpan]::FromSeconds(20)
    )
} catch {
    Remove-AgentService
    throw
}
