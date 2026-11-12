@echo off
setlocal EnableExtensions
title DaOrcs Endpoint Agent (Administrator)

rem ---------------------------------------------------------------------------
rem  UAC wrapper for windows-service.ps1.
rem
rem  Double-click it, or call it from a normal prompt. Windows shows the
rem  elevation prompt and the requested action runs in an elevated PowerShell.
rem
rem    daorcs-agent-admin.cmd              status
rem    daorcs-agent-admin.cmd install      install / repair the service
rem    daorcs-agent-admin.cmd uninstall    remove the service
rem    daorcs-agent-admin.cmd diagnose     status + self-test
rem ---------------------------------------------------------------------------

set "ACTION=%~1"
if "%ACTION%"=="" set "ACTION=status"
if /I "%ACTION%"=="install"   goto :action_ok
if /I "%ACTION%"=="uninstall" goto :action_ok
if /I "%ACTION%"=="status"    goto :action_ok
if /I "%ACTION%"=="diagnose"  goto :action_ok
echo Unknown action: %ACTION%
echo Use: install, uninstall, status or diagnose.
exit /b 2

:action_ok
set "PS=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
set "SCRIPT=%~dp0windows-service.ps1"
set "LOG=%APPDATA%\DaOrcs\Agent\logs\install.log"

if not exist "%SCRIPT%" (
    echo Agent script not found: %SCRIPT%
    exit /b 1
)

"%PS%" -NoProfile -ExecutionPolicy Bypass -Command ^
  "$q=[char]34;" ^
  "$script='%SCRIPT%';" ^
  "$action='%ACTION%';" ^
  "$inner='& ' + $q + $script + $q + ' -Action ' + $action + '; $code=$LASTEXITCODE; ' + 'Write-Host (' + $q + 'Exit code: ' + $q + ' + $code) -ForegroundColor Yellow; ' + 'Read-Host ' + $q + 'Press Enter to close' + $q + ' | Out-Null; exit $code';" ^
  "$encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($inner));" ^
  "$argumentLine='-NoExit -NoProfile -EncodedCommand ' + $encoded;" ^
  "Write-Host ('Requesting administrator privileges for: ' + $action) -ForegroundColor Cyan;" ^
  "try { $p = Start-Process -FilePath '%PS%' -Verb RunAs -ArgumentList $argumentLine -PassThru -Wait }" ^
  "catch { Write-Host ('Elevation cancelled: ' + $_.Exception.Message) -ForegroundColor Red; exit 1 };" ^
  "Write-Host ('Elevated process exit code: ' + $p.ExitCode) -ForegroundColor Yellow;"

set "CODE=%ERRORLEVEL%"
echo.
if exist "%LOG%" (
    echo --- last 15 lines of %LOG% ---
    "%PS%" -NoProfile -Command "Get-Content -LiteralPath '%LOG%' -Tail 15"
    echo --------------------------------
)
echo.
pause
exit /b %CODE%
