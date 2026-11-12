#define AppName "DaOrcs Endpoint Agent"
#define AppVersion "0.2.0"
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
; Shown as a scrollable text area with Accept/Decline before anything is
; written. The same file is installed so it can be read again later.
LicenseFile=TERMS-OF-SERVICE.txt
; Inno's own logs (verbosity can be raised with /LOGLEVEL=verbose). Our
; install.log is separate and always written beside the agent logs. At exit,
; Setup's log is copied to logs\setup.log and Uninstall's to logs\uninstall.log.
SetupLogging=yes
CloseApplications=no

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Dirs]
; Logs live in the user's AppData, not ProgramData. The service is given the
; same absolute folder through DAORCS_LOG_DIR (set by windows-service.ps1).
Name: "{userappdata}\DaOrcs\Agent\logs"

[Registry]
Root: HKLM; Subkey: "Software\DaOrcs\Agent"; ValueType: string; \
    ValueName: "LogDir"; ValueData: "{userappdata}\DaOrcs\Agent\logs"; \
    Flags: uninsdeletekey

[Icons]
; The .cmd triggers the Windows UAC prompt itself, so the shortcut works even
; when it is started from a non-elevated Explorer session.
Name: "{group}\DaOrcs Endpoint Agent (Administrator)"; Filename: "{app}\daorcs-agent-admin.cmd"
Name: "{group}\DaOrcs Endpoint Agent README"; Filename: "{app}\README-AGENT.md"

[Files]
Source: "{#AgentDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "agent.example.json"; DestDir: "{app}"; DestName: "agent.json"; Flags: onlyifdoesntexist
Source: "windows-service.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "post-install.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "daorcs-agent-admin.cmd"; DestDir: "{app}"; Flags: ignoreversion
Source: "README-AGENT.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "TERMS-OF-SERVICE.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\logos\daorcs.logo"; DestDir: "{app}"; DestName: "daorcs.logo"; Flags: ignoreversion
; Native Kafka (KRaft) helpers. They are not run by this installer; they are
; shipped so the same media can bootstrap a broker without Docker.
Source: "kafka\*"; DestDir: "{app}\kafka"; Flags: ignoreversion recursesubdirs createallsubdirs

[Run]
; Runs on the Finish page, in a visible terminal, after a successful install.
; It prints the DaOrcs logo, the agent version, README next steps and then
; probes the configured Kafka broker. -NoExit keeps the window open.
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoExit -NoProfile -ExecutionPolicy Bypass -File ""{app}\post-install.ps1"" -AppDir ""{app}"" -Version ""{#AppVersion}"" -LogPath ""{userappdata}\DaOrcs\Agent\logs\install.log"" -NoPause"; Flags: postinstall nowait skipifsilent

[Code]
var
  LogDir: string;
  UninstallLogDir: string;
  InstallLogPath: string;
  ServiceInstallCode: Integer;
  ContentsPage: TWizardPage;
  ContentsMemo: TNewMemo;

procedure DaOrcsLog(const Message: string);
var
  Line: string;
begin
  Line := GetDateTimeString('yyyy-mm-dd hh:nn:ss', #0, #0) + ' ' + Message;
  Log(Message);
  try
    ForceDirectories(ExtractFileDir(InstallLogPath));
    SaveStringToFile(InstallLogPath, Line + #13#10, True);
  except
    { Logging must never turn an install into a runtime error. }
  end;
end;

function InstallSummaryText: string;
begin
  Result :=
    'DaOrcs Endpoint Agent {#AppVersion}' + #13#10 +
    '' + #13#10 +
    'This installer writes the following under:' + #13#10 +
    '  ' + ExpandConstant('{app}') + #13#10 +
    '' + #13#10 +
    '  DaOrcsAgent.exe            the agent executable' + #13#10 +
    '  _internal\                 bundled Python runtime and libraries' + #13#10 +
    '  agent.json                 configuration; not overwritten on upgrade' + #13#10 +
    '  windows-service.ps1        service install, status and diagnostics' + #13#10 +
    '  post-install.ps1           health-check window shown at the end' + #13#10 +
    '  daorcs-agent-admin.cmd     UAC launcher for the service script' + #13#10 +
    '  README-AGENT.md            layout, commands and troubleshooting' + #13#10 +
    '  TERMS-OF-SERVICE.txt       the agreement you accepted' + #13#10 +
    '  daorcs.logo                logo used by the health-check window' + #13#10 +
    '  kafka\                     optional native Kafka scripts (not run)' + #13#10 +
    '  unins*.exe/.dat            the Inno Setup uninstaller (automatic)' + #13#10 +
    '' + #13#10 +
    'SYSTEM CHANGES' + #13#10 +
    '  * Registers the Windows service "DaOrcsEndpointAgent" to start' + #13#10 +
    '    automatically (delayed start) as LocalSystem, and asks Windows to' + #13#10 +
    '    restart it up to three times if it fails.' + #13#10 +
    '  * Starts that service immediately.' + #13#10 +
    '  * Creates Start Menu shortcuts for the UAC launcher and the README.' + #13#10 +
    '  * Adds no firewall rule and installs no Kafka broker.' + #13#10 +
    '  * Does not reboot or schedule a reboot.' + #13#10 +
    '' + #13#10 +
    'LOGS AND RUNTIME STATE' + #13#10 +
    '  All logs go to your AppData folder, not ProgramData:' + #13#10 +
    '    ' + LogDir + #13#10 +
    '  This includes install.log, setup.log, uninstall.log, service.log and' + #13#10 +
    '  agent.log. The service is configured with DAORCS_LOG_DIR so LocalSystem' + #13#10 +
    '  writes to that same folder.' + #13#10 +
    '  Delivered-hash state: ' + ExpandConstant('{app}') + '\state.sqlite3' + #13#10 +
    '' + #13#10 +
    'WHAT THE AGENT THEN DOES' + #13#10 +
    '  It scans the watch folders in agent.json (default: %PUBLIC%\Downloads' + #13#10 +
    '  and %PUBLIC%\Desktop), detects PE files by signature, and sends their' + #13#10 +
    '  full contents, SHA-256 hash, name, size, host and account name to the' + #13#10 +
    '  configured Kafka topic. TERMS-OF-SERVICE.txt lists the exact records' + #13#10 +
    '  that are sent and the agreement you accepted.' + #13#10 +
    '' + #13#10 +
    'Runtime state (agent.json changes and state.sqlite3) stays under the' + #13#10 +
    'program folder above. Logs stay in AppData. Both may remain after' + #13#10 +
    'uninstall. Uninstall removes the service and installed program files.';
end;

procedure InitializeWizard;
begin
  ContentsPage := CreateCustomPage(
    wpSelectDir,
    'Files to be installed',
    'Review exactly what this installer writes and changes on this computer.');
  ContentsMemo := TNewMemo.Create(ContentsPage);
  ContentsMemo.Left := 0;
  ContentsMemo.Top := 0;
  ContentsMemo.Width := ContentsPage.SurfaceWidth;
  ContentsMemo.Height := ContentsPage.SurfaceHeight;
  ContentsMemo.ScrollBars := ssVertical;
  ContentsMemo.ReadOnly := True;
  ContentsMemo.WordWrap := True;
  ContentsMemo.Text := '';
  ContentsMemo.Parent := ContentsPage.Surface;
end;

procedure CurPageChanged(CurPageID: Integer);
begin
  if (ContentsMemo <> nil) and (CurPageID = ContentsPage.ID) then
    ContentsMemo.Text := InstallSummaryText;
end;

procedure CopyInnoLog(const TargetDir, LogName: string);
var
  SourceLog: string;
  TargetLog: string;
  Contents: AnsiString;
begin
  SourceLog := ExpandConstant('{log}');
  if SourceLog = '' then
    exit;

  TargetLog := TargetDir + '\' + LogName;
  if CompareText(SourceLog, TargetLog) = 0 then
    exit;

  try
    ForceDirectories(ExtractFileDir(TargetLog));
  except
    { The agent install log already reports an unwritable data folder. }
  end;

  if CopyFile(SourceLog, TargetLog, False) then
  begin
    Log('Copied the Inno Setup log to ' + TargetLog);
    exit;
  end;

  { Setup keeps its log open while DeinitializeSetup runs. CopyFile normally
    succeeds, but fall back to a byte-preserving read/write if it does not. }
  try
    if LoadStringFromFile(SourceLog, Contents) then
    begin
      SaveStringToFile(TargetLog, Contents, False);
      Log('Copied the Inno Setup log (read fallback) to ' + TargetLog);
    end
    else
      Log('Could not read the Inno Setup log at ' + SourceLog);
  except
    Log('Could not copy the Inno Setup log to ' + TargetLog);
  end;
end;

procedure DeinitializeSetup;
begin
  CopyInnoLog(LogDir, 'setup.log');
end;

function InitializeUninstall(): Boolean;
begin
  UninstallLogDir := ExpandConstant('{userappdata}\DaOrcs\Agent\logs');
  RegQueryStringValue(HKLM, 'Software\DaOrcs\Agent', 'LogDir', UninstallLogDir);
  { The service script runs during uninstall too; give it its own file so the
    Inno log copied below does not overwrite what it wrote. }
  InstallLogPath := UninstallLogDir + '\uninstall-service.log';
  Result := True;
end;

procedure DeinitializeUninstall;
begin
  CopyInnoLog(UninstallLogDir, 'uninstall.log');
end;

function InitializeSetup(): Boolean;
begin
  LogDir := ExpandConstant('{userappdata}\DaOrcs\Agent\logs');
  InstallLogPath := LogDir + '\install.log';
  DaOrcsLog('DaOrcs Endpoint Agent setup starting');
  DaOrcsLog('Log folder: ' + LogDir);
  Result := True;
end;

procedure RunServiceScript(const Action: string; var ExitCode: Integer);
var
  ResultCode: Integer;
  Parameters: string;
begin
  Parameters :=
    '-NoProfile -ExecutionPolicy Bypass -File "' +
    ExpandConstant('{app}\windows-service.ps1') + '" -Action ' + Action +
    ' -LogPath "' + InstallLogPath + '"';
  DaOrcsLog('Launching service script: ' + Parameters);
  if not Exec(
    ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'),
    Parameters, '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
  begin
    DaOrcsLog('Could not launch the Windows service installer.');
    ExitCode := -1;
    exit;
  end;
  DaOrcsLog('Service script "' + Action + '" exit code: ' + IntToStr(ResultCode));
  ExitCode := ResultCode;
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
    '[TimeSpan]::FromSeconds(30)) }; ' +
    'try { & $env:SystemRoot\System32\schtasks.exe /End ' +
    '/TN ''DaOrcs Endpoint Agent'' 2>$null } catch {}; ' +
    'try { & $env:SystemRoot\System32\schtasks.exe /Delete ' +
    '/TN ''DaOrcs Endpoint Agent'' /F 2>$null } catch {}; exit 0"';
  DaOrcsLog('Stopping an existing DaOrcs endpoint agent before upgrade');
  if not Exec(
    ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'),
    Parameters, '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
  begin
    DaOrcsLog('Could not launch the upgrade stop step.');
    exit;
  end;
  DaOrcsLog('Upgrade stop step exit code: ' + IntToStr(ResultCode));
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  Detail: string;
begin
  if CurStep = ssInstall then
    PrepareForUpgrade;

  if CurStep = ssPostInstall then
  begin
    RunServiceScript('install', ServiceInstallCode);
    if ServiceInstallCode <> 0 then
    begin
      Detail :=
        'The agent files were installed, but the Windows service did not ' +
        'start (exit code ' + IntToStr(ServiceInstallCode) + ').' + #13#10 + #13#10 +
        'Nothing was rolled back. The install log explains exactly what ' +
        'happened and the post-install window will test the connection:' + #13#10 +
        InstallLogPath + #13#10 +
        LogDir + '\service.log' + #13#10 + #13#10 +
        'You can retry with:' + #13#10 +
        '"' + ExpandConstant('{app}\windows-service.ps1') + '" -Action install';
      DaOrcsLog('WARNING: ' + Detail);
      if not WizardSilent then
        MsgBox(Detail, mbError, MB_OK);
    end
    else
      DaOrcsLog('Windows service installed and started successfully');
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  IgnoredCode: Integer;
begin
  if CurUninstallStep = usUninstall then
  begin
    DaOrcsLog('Uninstall: removing the Windows service');
    RunServiceScript('uninstall', IgnoredCode);
    DaOrcsLog('Uninstall: service removal exit code: ' + IntToStr(IgnoredCode));
  end;
end;
