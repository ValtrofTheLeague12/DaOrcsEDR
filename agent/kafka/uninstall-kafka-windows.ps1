<#
.SYNOPSIS
    Removes the native DaOrcs Kafka (KRaft) Windows service.

.DESCRIPTION
    Stops and unregisters the DaOrcsKafka service through WinSW, removes the
    optional firewall rule and (with -RemoveData) the broker data directory.
    The extracted distribution is removed unless -KeepFiles is given.

.PARAMETER InstallDir
    Must match the directory used by install-kafka-windows.ps1.

.PARAMETER DataDir
    Broker data and the portable JRE live here.

.PARAMETER LogDir
    Installer transcript and WinSW service output. Defaults to
    %APPDATA%\DaOrcs\Kafka\logs, not ProgramData.

.PARAMETER RemoveData
    Also delete DataDir. Without it the broker's data is kept so the service
    can be reinstalled without losing topics.

.PARAMETER KeepFiles
    Keep InstallDir (Kafka distribution and WinSW) on disk.
#>
[CmdletBinding()]
param(
    [string]$InstallDir = "$env:ProgramFiles\DaOrcs\Kafka",
    [string]$DataDir = "$env:ProgramData\DaOrcs\Kafka",
    [string]$LogDir = "",
    [int]$Port = 9092,
    [switch]$RemoveData,
    [switch]$KeepFiles,
    [switch]$NoPause
)

$ErrorActionPreference = "Stop"

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

if (-not (Test-IsAdministrator)) {
    Restart-Elevated -BoundParameters $PSBoundParameters -Reason "Removing native Kafka"
}

if (-not $LogDir) { $LogDir = Join-Path $env:APPDATA "DaOrcs\Kafka\logs" }
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
$script:LogFile = Join-Path $LogDir ("uninstall-kafka-{0}.log" -f (Get-Date -Format "yyyyMMdd-HHmmss"))
$script:ExitCode = 0

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO", "WARN", "ERROR")]
        [string]$Level = "INFO"
    )
    $line = "{0} {1,-5} {2}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Level, $Message
    Write-Host $line
    try { Add-Content -LiteralPath $script:LogFile -Value $line -Encoding UTF8 } catch { }
}

function Invoke-Native {
    param([string]$FilePath, [string[]]$ArgumentList, [string]$What)
    Write-Log ("RUN {0}: `"{1}`" {2}" -f $What, $FilePath, ($ArgumentList -join " "))
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

try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "This script must run from an elevated PowerShell (Run as administrator)."
    }

    Write-Log "DaOrcs native Kafka uninstall starting"

    $winsw = Join-Path $InstallDir "DaOrcsKafka.exe"
    $service = Get-Service -Name "DaOrcsKafka" -ErrorAction SilentlyContinue
    if ($service -and $service.Status -ne "Stopped") {
        Write-Log "Stopping DaOrcsKafka (status: $($service.Status))"
        Stop-Service -Name "DaOrcsKafka" -Force -ErrorAction SilentlyContinue
        $service = Get-Service -Name "DaOrcsKafka" -ErrorAction SilentlyContinue
        if ($service) {
            $service.WaitForStatus(
                [System.ServiceProcess.ServiceControllerStatus]::Stopped,
                [TimeSpan]::FromSeconds(45))
        }
    }

    if (Test-Path -LiteralPath $winsw -PathType Leaf) {
        [void](Invoke-Native $winsw @("stop") "WinSW stop")
        $code = Invoke-Native $winsw @("uninstall") "WinSW uninstall"
        if ($code -ne 0) {
            Write-Log "WinSW could not unregister the service (exit $code); falling back to sc delete." "WARN"
            [void](Invoke-Native "$env:SystemRoot\System32\sc.exe" @("delete", "DaOrcsKafka") "sc delete")
        }
    } elseif (Get-Service -Name "DaOrcsKafka" -ErrorAction SilentlyContinue) {
        [void](Invoke-Native "$env:SystemRoot\System32\sc.exe" @("delete", "DaOrcsKafka") "sc delete")
    } else {
        Write-Log "DaOrcsKafka is not installed"
    }

    $ruleName = "DaOrcs Kafka $Port"
    try {
        $rule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
        if ($rule) {
            Remove-NetFirewallRule -DisplayName $ruleName
            Write-Log "Removed firewall rule: $ruleName"
        }
    } catch {
        Write-Log "Could not remove firewall rule '$ruleName': $($_.Exception.Message)" "WARN"
    }

    if (-not $KeepFiles -and (Test-Path -LiteralPath $InstallDir)) {
        try {
            Remove-Item -LiteralPath $InstallDir -Recurse -Force
            Write-Log "Removed $InstallDir"
        } catch {
            Write-Log "Could not remove ${InstallDir}: $($_.Exception.Message)" "WARN"
        }
    } elseif ($KeepFiles) {
        Write-Log "Kept $InstallDir (-KeepFiles)"
    }

    if ($RemoveData -and (Test-Path -LiteralPath $DataDir)) {
        # The log lives inside DataDir; drop a copy beside the user profile first.
        try {
            Remove-Item -LiteralPath $DataDir -Recurse -Force
            Write-Host "  Broker data removed: $DataDir" -ForegroundColor Yellow
        } catch {
            Write-Log "Could not remove ${DataDir}: $($_.Exception.Message)" "WARN"
        }
    } elseif (Test-Path -LiteralPath $DataDir) {
        Write-Log "Kept broker data at $DataDir (pass -RemoveData to delete it)"
        Write-Host "  Broker data kept: $DataDir" -ForegroundColor DarkGray
    }

    Write-Log "Uninstall complete"
    $script:ExitCode = 0
} catch {
    Write-Log "FATAL: $($_.Exception.Message)" "ERROR"
    Write-Log $_.ScriptStackTrace "ERROR"
    $script:ExitCode = 1
}

Write-Host ""
if ($script:ExitCode -eq 0) {
    Write-Host "  DaOrcs Kafka has been removed." -ForegroundColor Green
} else {
    Write-Host "  Uninstall failed. See $script:LogFile" -ForegroundColor Red
}
Write-Host "  Log: $script:LogFile" -ForegroundColor DarkGray
Write-Host ""
if (-not $NoPause -and $Host.Name -eq "ConsoleHost") {
    Read-Host "  Press Enter to close this window" | Out-Null
}
exit $script:ExitCode
