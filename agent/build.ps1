$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

$Python = (Get-Command python -ErrorAction Stop).Source
$VenvPython = Join-Path $PSScriptRoot ".build\Scripts\python.exe"
$IsccCandidates = @(
    (Join-Path $env:ProgramFiles "Inno Setup 6\ISCC.exe"),
    (Join-Path ${env:ProgramFiles(x86)} "Inno Setup 6\ISCC.exe"),
    (Join-Path $env:LOCALAPPDATA "Programs\Inno Setup 6\ISCC.exe")
)

if (-not (Test-Path $VenvPython)) {
    & $Python -m venv .build
}
& $VenvPython -m pip install --upgrade pip
& $VenvPython -m pip install -r requirements.txt pyinstaller
if ($LASTEXITCODE -ne 0) {
    throw "Failed to install the endpoint-agent build dependencies."
}

& $VenvPython -m PyInstaller --noconfirm --clean --onedir `
    --name DaOrcsAgent --collect-all confluent_kafka `
    --hidden-import win32timezone --hidden-import win32service `
    --hidden-import win32serviceutil --hidden-import servicemanager `
    endpoint_agent.py
if ($LASTEXITCODE -ne 0) {
    throw "PyInstaller failed to package the endpoint agent."
}

$Iscc = Get-Command ISCC.exe -ErrorAction SilentlyContinue
if ($Iscc) {
    $Compiler = $Iscc.Source
} else {
    $Compiler = $IsccCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
}
if (-not $Compiler) {
    throw "Inno Setup 6 was not found. Install it, then rerun agent\build.ps1."
}

& $Compiler (Join-Path $PSScriptRoot "DaOrcsAgent.iss")
if ($LASTEXITCODE -ne 0) {
    throw "Inno Setup compilation failed."
}
