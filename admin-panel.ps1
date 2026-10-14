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

.PARAMETER NoBrowser
    Do not open a browser on start.

.PARAMETER NoUi
    API only. Skips building and serving admin-web\dist.

.EXAMPLE
    .\admin-panel.ps1
    Build the UI if needed and serve it on 127.0.0.1:60100.

.EXAMPLE
    .\admin-panel.ps1 -Build
    Force a rebuild of the React bundle, then serve.

.EXAMPLE
    .\admin-panel.ps1 -Dev
    Vite dev server on 60101 with the API proxied from the panel on 60100.

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
$DevPort    = 60101

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