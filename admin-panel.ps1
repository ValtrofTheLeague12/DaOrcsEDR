<#
.SYNOPSIS
    Start the admin orchestration panel (Flask backend + React UI).

.DESCRIPTION
    Serves the built React UI and the JSON API from one origin on
    127.0.0.1. The panel proxies to services that already exist - the static
    analyzer REST API, the ML scorer, MalAPI - and re-implements none of
    their health checks, so what the panel says about a service is what that
    service says about itself.

    Binds loopback only. There is deliberately no flag to widen it.

.PARAMETER Build
    Rebuild admin-web\dist before starting, even if it already exists.

.PARAMETER Dev
    Run the Vite dev server (hot reload) alongside the panel, which is started
    API-only. Open the Vite URL, not the panel URL.

.PARAMETER Port
    Override the panel port. Defaults to ADMIN_WEB_PORT in .env, else 60100.
    The Vite dev port in -Dev mode follows it (ADMIN_WEB_DEV_PORT pins it).

.PARAMETER NoBrowser
    Do not open a browser on start.

.PARAMETER NoUi
    API only. Skips building and serving admin-web\dist.

.PARAMETER Dev
    Run the Vite dev server (hot reload) alongside the panel, which is started
    API-only. Open the Vite URL, not the panel URL.

.NOTES
    Both the panel port and the Vite dev port are checked against the Windows
    *excluded* port ranges before anything starts. Hyper-V, WSL2 and Docker
    Desktop reserve blocks of TCP ports at boot, and a bind inside one fails
    with WinError 10013 even though nothing is listening on it. Those ranges
    move between reboots; `netsh interface ipv4 show excludedportrange
    protocol=tcp` lists them. Pass -Port (or set ADMIN_WEB_PORT) to move to a
    port outside every range.

.EXAMPLE
    .\admin-panel.ps1
    Build the UI if needed and serve it on 127.0.0.1:60100.

.EXAMPLE
    .\admin-panel.ps1 -Build
    Force a rebuild of the React bundle, then serve.

.EXAMPLE
    .\admin-panel.ps1 -Dev
    Vite dev server on the panel port + 1 (60101 by default), with the API
    proxied from the panel on 60100.

.EXAMPLE
    .\admin-panel.ps1 -Port 60600
    Serve on a port that is outside the Windows-reserved ranges.

.NOTES
    Stop with Ctrl+C. In -Dev mode the panel is in the foreground and the Vite
    dev server is a child process, so Ctrl+C tears both down.
#>
[CmdletBinding()]
param(
    [switch]$Build,
    [switch]$Dev,
    [int]$Port,
    [switch]$NoBrowser,
    [switch]$NoUi
)

$ErrorActionPreference = 'Stop'

Set-Location -LiteralPath $PSScriptRoot

$VenvPy     = Join-Path $PSScriptRoot 'python\.venv\Scripts\python.exe'
$ServerPy   = Join-Path $PSScriptRoot 'python\admin_server.py'
$WebDir     = Join-Path $PSScriptRoot 'admin-web'
$DistIndex  = Join-Path $WebDir  'dist\index.html'
$EnvFile    = Join-Path $PSScriptRoot '.env'

function Invoke-Checked {
    param(
        [Parameter(Mandatory)] [string]   $Command,
        [Parameter(ValueFromRemainingArguments)] [string[]] $Arguments
    )

    $display = "$Command $($Arguments -join ' ')"
    Write-Host "> $display" -ForegroundColor Cyan

    try {
        & $Command @Arguments
        $code = $LASTEXITCODE
        if ($null -eq $code) { $code = 0 }   # native command with no exit code
    }
    catch {
        Write-Host "launch failed: $($_.Exception.Message)" -ForegroundColor Red
        throw "Could not launch '$Command': $($_.Exception.Message)"
    }

    if ($code -ne 0) {
        Write-Host "command failed (exit $code): $display" -ForegroundColor Red
        throw "Command failed with exit code $code`: $display"
    }
}

function Get-PanelPort {
    if ($Port) { return $Port }
    if (Test-Path -LiteralPath $EnvFile) {
        foreach ($line in (Get-Content -LiteralPath $EnvFile)) {
            if ($line -match '^\s*ADMIN_WEB_PORT\s*=\s*(\d+)') { return [int]$Matches[1] }
        }
    }
    return 60100
}

function Get-ReservedPortRange {
    # Hyper-V, WSL2 and Docker Desktop ask WinNAT to reserve blocks of TCP ports
    # at boot: the blocks are recorded as *excluded* ranges, not as listeners.
    # A bind inside one fails with WSAEACCES (WinError 10013, "an attempt was
    # made to access a socket in a way forbidden by its access permissions"),
    # which is what Flask surfaces - in the system locale, so the message is as
    # cryptic as it is untranslatable.
    #
    # This is why Get-NetTCPConnection cannot be the preflight: nothing is
    # listening and no process owns the port, yet the bind is still refused.
    # The exclusion table is the only place the truth is visible. The ranges
    # also move between reboots, so this is re-read on every start.
    $ranges = @()
    $inTable = $false
    foreach ($line in (netsh interface ipv4 show excludedportrange protocol=tcp 2>$null)) {
        # Header match is deliberately accent-free: this file may be read as
        # anything from UTF-8 to CP1252 depending on how PowerShell was
        # invoked, and Windows localizes these headers ("Port de début" on a
        # French box). Matching on the unaccented stem survives both.
        if ($line -match '^\s*(Port de d|Start Port)') { $inTable = $true; continue }
        if (-not $inTable) { continue }
        if ($line -match '^\s*(\d+)\s+(\d+)') {
            $ranges += [pscustomobject]@{ Start = [int]$Matches[1]; End = [int]$Matches[2] }
        }
    }
    # Comma-wrap so a single range is still an array: PowerShell unwraps a
    # one-element return into the object itself, which would break -Reserved.
    return ,$ranges
}

function Assert-PanelPortBindable {
    param(
        [Parameter(Mandatory)] [int] $Candidate,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Reserved
    )

    foreach ($r in $Reserved) {
        if ($Candidate -ge $r.Start -and $Candidate -le $r.End) {
            $free = Get-FreePortNear -From $r.End
            Write-Host "Port $Candidate is inside a Windows-reserved TCP range ($($r.Start)-$($r.End))." -ForegroundColor Red
            Write-Host '  Hyper-V / WSL2 / Docker Desktop reserve port blocks at boot, so no process is' -ForegroundColor Yellow
            Write-Host '  listening and no process owns the port, but binding it is refused anyway' -ForegroundColor Yellow
            Write-Host '  (WinError 10013). The ranges move between reboots.' -ForegroundColor Yellow
            Write-Host "  See them with:  netsh interface ipv4 show excludedportrange protocol=tcp" -ForegroundColor Yellow
            if ($free) {
                Write-Host "  First free port above the range: $free" -ForegroundColor Green
                Write-Host "  Try:  .\admin-panel.ps1 -Port $free   (or set ADMIN_WEB_PORT in .env)" -ForegroundColor Green
            }
            else {
                Write-Host '  Try -Port with any port outside every range listed above.' -ForegroundColor Green
            }
            throw "Port $Candidate is reserved by Windows; pick another with -Port or ADMIN_WEB_PORT in .env."
        }
    }

    # Winsock's own answer, which also catches a range that appeared since the
    # netsh read. ExclusiveAddressUse keeps this from colliding with the real
    # start a moment later.
    $socket = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, $Candidate)
    $socket.ExclusiveAddressUse = $true
    try {
        $socket.Start()
    }
    catch {
        Write-Host "Port $Candidate cannot be bound on 127.0.0.1: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host '  Run with -Port to choose another (see -h for the reserved-range note).' -ForegroundColor Yellow
        throw "Port $Candidate is not bindable."
    }
    finally {
        $socket.Stop()
    }
}

function Get-FreePortNear {
    # Walk up from a reserved range's end for a port that Winsock actually
    # grants. The step budget cannot be a small constant: WinNAT reserves these
    # blocks back to back (60194-60293 follows 60094-60193 on a typical box),
    # so the first few dozen candidates after a range are usually reserved too
    # and a 64-deep search gives up precisely when the advice is needed.
    param([Parameter(Mandatory)] [int] $From)

    $end = [Math]::Min($From + 1024, 65535)
    foreach ($candidate in ($From + 1)..$end) {
        try {
            $socket = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, $candidate)
            $socket.ExclusiveAddressUse = $true
            $socket.Start()
            $socket.Stop()
            return $candidate
        }
        catch { }
    }
    return 0
}

function Get-DevPort {
    # The Vite port follows the same rules as the panel port: it is a loopback
    # bind, so a reserved block kills -Dev the same way. Derived from the panel
    # port rather than fixed so moving one moves both; .env can pin it.
    if (Test-Path -LiteralPath $EnvFile) {
        foreach ($line in (Get-Content -LiteralPath $EnvFile)) {
            if ($line -match '^\s*ADMIN_WEB_DEV_PORT\s*=\s*(\d+)') { return [int]$Matches[1] }
        }
    }
    $preferred = $PanelPort + 1
    $reserved  = Get-ReservedPortRange
    foreach ($r in $reserved) {
        if ($preferred -ge $r.Start -and $preferred -le $r.End) {
            return (Get-FreePortNear -From $r.End)
        }
    }
    return $preferred
}

function Wait-ForHealth {
    param(
        [Parameter(Mandatory)] [string] $Url,
        [int]$TimeoutSeconds = 20
    )
    # Poll rather than a fixed sleep: on a cold start Flask needs a moment, and
    # a fixed sleep is either too short (opens a dead tab) or too long (the UI
    # appears to hang).
    for ($i = 0; $i -lt $TimeoutSeconds; $i++) {
        try {
            $r = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 2
            if ($r.StatusCode -eq 200) { return $true }
        }
        catch { }
        Start-Sleep -Milliseconds 500
    }
    return $false
}

function Build-Ui {
    if (-not (Get-Command 'npm' -ErrorAction SilentlyContinue)) {
        throw "npm not on PATH. Install Node, or run the panel with -NoUi."
    }
    Write-Host 'Building React UI...' -ForegroundColor Cyan
    Push-Location $WebDir
    try {
        if (-not (Test-Path -LiteralPath (Join-Path $WebDir 'node_modules'))) {
            Write-Host 'node_modules missing; running npm install first...' -ForegroundColor Yellow
            Invoke-Checked 'npm' 'install' '--no-audit' '--no-fund'
        }
        Invoke-Checked 'npm' 'run' 'build'
    }
    finally {
        Pop-Location
    }
}

# --- preflight -------------------------------------------------------------

if (-not (Test-Path -LiteralPath $VenvPy)) {
    throw "Project venv missing: $VenvPy`n       Create it with:  python -m venv python\.venv"
}
if (-not (Test-Path -LiteralPath $ServerPy)) {
    throw "Panel entry point missing: $ServerPy"
}

$PanelPort = Get-PanelPort
$PanelUrl  = "http://127.0.0.1:$PanelPort"

# Fail loudly instead of starting a second panel that silently loses the bind
# race and leaves an orphan holding the port.
$Existing = Get-NetTCPConnection -LocalPort $PanelPort -State Listen -ErrorAction SilentlyContinue
if ($Existing) {
    $OwnerPid  = ($Existing | Select-Object -First 1).OwningProcess
    $OwnerName = try { (Get-Process -Id $OwnerPid -ErrorAction Stop).ProcessName } catch { 'unknown' }
    Write-Host "Port $PanelPort is already listening (pid $OwnerPid, $OwnerName)." -ForegroundColor Red
    throw "Stop it first (Stop-Process -Id $OwnerPid), or pass -Port to use another port."
}

# A port can be free *and* unbindable - see Get-ReservedPortRange. Checked here
# so the reason is stated in plain terms rather than arriving as a localized
# Winsock error from a Flask thread after the UI has already been built.
$Reserved = Get-ReservedPortRange
Assert-PanelPortBindable -Candidate $PanelPort -Reserved $Reserved
if ($Dev) {
    $DevPort = Get-DevPort
    Assert-PanelPortBindable -Candidate $DevPort -Reserved $Reserved
}

Write-Host 'Admin orchestration panel' -ForegroundColor Cyan
Write-Host "  python : $VenvPy"
Write-Host "  repo   : $PSScriptRoot"

# --- UI ---------------------------------------------------------------------

$NeedBuild = $false
if (-not $NoUi -and -not $Dev) {
    if ($Build -or -not (Test-Path -LiteralPath $DistIndex)) {
        $NeedBuild = $true
    }
}
if ($NeedBuild) { Build-Ui }

if (-not $NoUi -and -not $Dev -and -not (Test-Path -LiteralPath $DistIndex)) {
    throw "React UI not built and build did not produce $DistIndex. Try -Build."
}

# --- dev mode ---------------------------------------------------------------

if ($Dev) {
    if (-not (Test-Path -LiteralPath $WebDir)) {
        throw "admin-web not found at $WebDir"
    }
    if (-not (Get-Command 'npm' -ErrorAction SilentlyContinue)) {
        throw 'npm not on PATH; -Dev needs Node.'
    }

    Write-Host "  panel  : $PanelUrl/api (API only)"
    Write-Host "  vite   : http://127.0.0.1:$DevPort" -ForegroundColor Green

    $env:ADMIN_PANEL = $PanelUrl
    # Tell Vite which port to take: it cannot infer it, and a reserved-port
    # failure inside Vite is even less legible than one inside Flask.
    $env:ADMIN_WEB_DEV_PORT = "$DevPort"
    $Vite = Start-Process -FilePath 'npm.cmd' -ArgumentList 'run', 'dev' `
                -WorkingDirectory $WebDir -PassThru -WindowStyle Minimized

    # Give Vite a moment so its proxy target exists before the panel answers.
    Start-Sleep -Seconds 3

    if (-not $NoBrowser) {
        try { Start-Process "http://127.0.0.1:$DevPort" } catch { }
    }

    Write-Host "Starting panel (Ctrl+C to stop both)..." -ForegroundColor Cyan
    try {
        & $VenvPy $ServerPy '--no-ui' '--port' $PanelPort
    }
    finally {
        # Do not leave the dev server orphaned when the panel exits.
        if ($Vite -and -not $Vite.HasExited) {
            Write-Host 'Stopping Vite dev server...' -ForegroundColor Yellow
            try { $Vite.Kill() } catch { }
        }
    }
    exit 0
}

# --- serve ------------------------------------------------------------------

if ($NoUi) {
    Write-Host "  ui     : disabled (-NoUi)"
}
else {
    Write-Host "  ui     : admin-web\dist"
}
Write-Host "  listen : $PanelUrl" -ForegroundColor Green
Write-Host "Starting panel (Ctrl+C to stop)..." -ForegroundColor Cyan

$PanelProc = Start-Process -FilePath $VenvPy `
    -ArgumentList $ServerPy, '--port', $PanelPort `
    -WorkingDirectory $PSScriptRoot -PassThru -NoNewWindow

if (Wait-ForHealth -Url "$PanelUrl/api/health") {
    Write-Host ''
    Write-Host "Panel is up: $PanelUrl" -ForegroundColor Green
    if (-not $NoBrowser) { try { Start-Process $PanelUrl } catch { } }
}
else {
    Write-Host ''
    Write-Host "Panel did not answer $PanelUrl/api/health within 20s." -ForegroundColor Red
    Write-Host "It may still be starting; try $PanelUrl in a moment." -ForegroundColor Yellow
}

try {
    Wait-Process -Id $PanelProc.Id
}
finally {
    if (-not $PanelProc.HasExited) {
        Write-Host 'Stopping panel...' -ForegroundColor Yellow
        try { $PanelProc.Kill() } catch { }
    }
}