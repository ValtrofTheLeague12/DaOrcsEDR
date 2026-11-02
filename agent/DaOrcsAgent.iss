#define AppName "DaOrcs Endpoint Agent"
#define AppVersion "0.1.0"
#define AppPublisher "DaOrcs"
#define AgentDir "dist\DaOrcsAgent"

[Setup]
AppId={{8F9D61A3-BB80-498A-93D2-37D2E2B6D462}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
DefaultDirName={commonappdata}\DaOrcs\Agent
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=output
OutputBaseFilename=DaOrcsAgent-Setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
UninstallDisplayName={#AppName}

[Dirs]
Name: "{app}\logs"

[Files]
Source: "{#AgentDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "agent.example.json"; DestDir: "{app}"; DestName: "agent.json"; Flags: onlyifdoesntexist
Source: "windows-service.ps1"; DestDir: "{app}"; Flags: ignoreversion

[Code]
procedure RunServiceScript(const Action: string);
var
  ResultCode: Integer;
  Parameters: string;
begin
  Parameters :=
    '-NoProfile -ExecutionPolicy Bypass -File "' +
    ExpandConstant('{app}\windows-service.ps1') + '" -Action ' + Action;
  if not Exec(
    ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'),
    Parameters, '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
    RaiseException('Could not launch the Windows service installer.');
  if ResultCode <> 0 then
    RaiseException(
      'Windows service configuration failed (PowerShell exit code ' +
      IntToStr(ResultCode) + ').');
end;

procedure PrepareForUpgrade;
var
  ResultCode: Integer;
  Parameters: string;
begin
  Parameters :=
    '-NoProfile -Command "$ErrorActionPreference=''Stop''; ' +
    '$service=Get-Service -Name ''DaOrcsEndpointAgent'' ' +
    '-ErrorAction SilentlyContinue; ' +
    'if ($service -and $service.Status -ne ''Stopped'') { ' +
    'Stop-Service -Name ''DaOrcsEndpointAgent'' -Force; ' +
    '$service=Get-Service -Name ''DaOrcsEndpointAgent''; ' +
    '$service.WaitForStatus(' +
    '[System.ServiceProcess.ServiceControllerStatus]::Stopped, ' +
    '[TimeSpan]::FromSeconds(20)) }; ' +
    'try { & $env:SystemRoot\System32\schtasks.exe /End ' +
    '/TN ''DaOrcs Endpoint Agent'' 2>$null } catch {}; ' +
    'try { & $env:SystemRoot\System32\schtasks.exe /Delete ' +
    '/TN ''DaOrcs Endpoint Agent'' /F 2>$null } catch {}; exit 0"';
  if not Exec(
    ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'),
    Parameters, '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
    RaiseException('Could not stop the existing endpoint agent.');
  if ResultCode <> 0 then
    RaiseException(
      'Could not stop the existing endpoint agent (PowerShell exit code ' +
      IntToStr(ResultCode) + ').');
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssInstall then
    PrepareForUpgrade;
  if CurStep = ssPostInstall then
    RunServiceScript('install');
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usUninstall then
    RunServiceScript('uninstall');
end;
