#define AppName "DaOrcs Endpoint Agent"
#define AppVersion "0.4.1"
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
const
  { Inno records the installed version here, so an earlier install can be
    recognised even when the user picks a different folder this time. }
  UninstallKey =
    'Software\Microsoft\Windows\CurrentVersion\Uninstall\' +
    '{8F9D61A3-BB80-498A-93D2-37D2E2B6D462}_is1';
  AgentServiceKey = 'SYSTEM\CurrentControlSet\Services\DaOrcsEndpointAgent';

  { Per-target configuration seeded into agent.json on a fresh install.
    The tokens are replaced with the /APIHOST, /BROKERS and /TOPIC values
    (or the defaults below) before the file is written. The result must stay
    valid JSON: every value is character-validated, so a mistyped switch
    aborts setup instead of producing an agent that cannot reach the broker. }
  SeedConfigTemplate =
    '{"watch_dirs":["%PUBLIC%\\Downloads","%PUBLIC%\\Desktop"],' +
    '"scan_interval_seconds":5,' +
    '"stable_seconds":2,' +
    '"chunk_bytes":262144,' +
    '"state_file":"%PROGRAMDATA%\\DaOrcs\\Agent\\state.sqlite3",' +
    '"log_file":"%APPDATA%\\DaOrcs\\Agent\\logs\\agent.log",' +
    '"detections_file":"%APPDATA%\\DaOrcs\\Agent\\logs\\detections.log",' +
    '"log_level":"INFO",' +
    '"api":{"enabled":true,"host":"@APIHOST@","port":8787},' +
    '"kafka":{"bootstrap_servers":"@BROKERS@","topic":"@TOPIC@",' +
    '"producer_config":{}}}';

var
  LogDir: string;
  UninstallLogDir: string;
  InstallLogPath: string;
  ServiceInstallCode: Integer;
  IsUpgrade: Boolean;
  WipeLogs: Boolean;
  PreviousVersion: string;
  ContentsPage: TWizardPage;
  ContentsMemo: TNewMemo;
  DeployApiHost: string;
  DeployBrokers: string;
  DeployTopic: string;
  DeployParamsGiven: Boolean;

function DetectExistingInstall: Boolean;
begin
  PreviousVersion := '';
  { The uninstall key covers every install made by this installer. The service
    key catches a deployment that was registered but never completed, or one
    whose uninstall entry was removed. }
  Result := RegQueryStringValue(HKLM, UninstallKey, 'DisplayVersion', PreviousVersion);
  if not Result then
    Result := RegKeyExists(HKLM, AgentServiceKey);
  if Result and (PreviousVersion = '') then
    PreviousVersion := 'unknown version';
end;

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
var
  UpgradeNote: string;
  DeployNote: string;
begin
  if IsUpgrade then
    UpgradeNote :=
      'UPGRADE DETECTED' + #13#10 +
      '  DaOrcs Endpoint Agent ' + PreviousVersion + ' is already installed.' + #13#10 +
      '  This run updates the program files in place, keeps agent.json and' + #13#10 +
      '  state.sqlite3, and restarts the Windows service afterwards. Nothing' + #13#10 +
      '  needs to be uninstalled first.' + #13#10 +
      '' + #13#10 +
      ''
  else
    UpgradeNote :=
      'FRESH INSTALL' + #13#10 +
      '  No earlier DaOrcs Endpoint Agent was found on this computer.' + #13#10 +
      '' + #13#10 +
      '';

  if DeployParamsGiven then
    DeployNote :=
      'DEPLOY CONFIGURATION' + #13#10 +
      '  /APIHOST=' + DeployApiHost + #13#10 +
      '  /BROKERS=' + DeployBrokers + #13#10 +
      '  /TOPIC=' + DeployTopic + #13#10 +
      '  A fresh install writes these into agent.json. An upgrade keeps the' + #13#10 +
      '  existing agent.json and ignores them.' + #13#10 +
      '' + #13#10 +
      ''
  else
    DeployNote :=
      'DEPLOY CONFIGURATION' + #13#10 +
      '  Not supplied. A fresh install uses the defaults' + #13#10 +
      '  (APIHOST 0.0.0.0, broker 192.168.56.1:9092, topic analysis-artifacts).' + #13#10 +
      '  Run setup with /APIHOST=<this machine''s IP> so the panel can reach' + #13#10 +
      '  the heartbeat.' + #13#10 +
      '' + #13#10 +
      '';

  Result :=
    'DaOrcs Endpoint Agent {#AppVersion}' + #13#10 +
    '' + #13#10 +
    UpgradeNote +
    DeployNote +
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
    '  * Exposes a read-only heartbeat API on port 8787 (http://HOST:8787).' + #13#10 +
    '    The API has no authentication: restrict the port in the firewall.' + #13#10 +
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
    'Runtime state (agent.json and state.sqlite3) stays under the program' + #13#10 +
    'folder above. Uninstall removes agent.json with the other installed files' + #13#10 +
    'but keeps state.sqlite3. Logs stay in AppData; the uninstaller asks whether' + #13#10 +
    'to delete them (default: keep) and otherwise leaves them for auditing.';
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

function CommandLineSwitchExists(const Switch: string): Boolean;
var
  Index: Integer;
begin
  Result := False;
  for Index := 1 to ParamCount do
    if CompareText(ParamStr(Index), Switch) = 0 then
    begin
      Result := True;
      exit;
    end;
end;

{ ---------------------------------------------------------------------------
  Deploy-time configuration (/APIHOST, /BROKERS, /TOPIC).

  One installer for every endpoint; the target's own IP is given on the
  command line, so a fresh install writes an agent.json whose heartbeat the
  panel can reach. The parameters are validated before anything is written:
  an invalid value aborts setup, because a silently defaulting config is an
  agent that never reports.
  --------------------------------------------------------------------------- }

function GetDeployValue(const Param: string; var Value: string): Boolean;
var
  Index: Integer;
  Argument: string;
begin
  Result := False;
  Value := '';
  for Index := 1 to ParamCount do
  begin
    Argument := ParamStr(Index);
    if Pos(UpperCase(Param) + '=', UpperCase(Argument)) = 1 then
    begin
      Value := Copy(Argument, Length(Param) + 2, MaxInt);
      Result := True;
      exit;
    end;
  end;
end;

function OnlyAllowedChars(const Value: string; const Extra: string;
    MaxLength: Integer): Boolean;
var
  Index, ExtraIndex: Integer;
  C: Char;
  Allowed: Boolean;
begin
  Result := False;
  if (Value = '') or (Length(Value) > MaxLength) then
    exit;
  for Index := 1 to Length(Value) do
  begin
    C := Value[Index];
    if not ((C >= 'A') and (C <= 'Z')) and
       not ((C >= 'a') and (C <= 'z')) and
       not ((C >= '0') and (C <= '9')) then
    begin
      Allowed := False;
      for ExtraIndex := 1 to Length(Extra) do
        if C = Extra[ExtraIndex] then
        begin
          Allowed := True;
          Break;
        end;
      if not Allowed then
        exit;
    end;
  end;
  Result := True;
end;

function ValidDeployHost(const Value: string): Boolean;
begin
  { ':' is allowed so an IPv6 literal works too; spaces, slashes and quotes
    are not, which is what would break the JSON or the command line. }
  Result := OnlyAllowedChars(Value, '.:-', 253);
end;

function ValidDeployTopic(const Value: string): Boolean;
begin
  Result := OnlyAllowedChars(Value, '._-', 249);
end;

function ValidDeployBrokers(const Value: string): Boolean;
var
  Rest, Entry, Host, PortText: string;
  Sep, Colon, Index, PortNum: Integer;
  C: Char;
begin
  { A comma-separated list of host:port entries (IPv4 or host names; an IPv6
    bootstrap entry should be bracketed and is accepted via the host check). }
  Result := False;
  if (Value = '') or (Length(Value) > 1024) then
    exit;
  Rest := Value + ',';
  while Length(Rest) > 0 do
  begin
    Sep := Pos(',', Rest);
    if Sep = 0 then
      exit;
    Entry := Copy(Rest, 1, Sep - 1);
    Rest := Copy(Rest, Sep + 1, MaxInt);
    Colon := RPos(':', Entry);
    if (Colon < 2) or (Colon = Length(Entry)) then
      exit;
    Host := Copy(Entry, 1, Colon - 1);
    PortText := Copy(Entry, Colon + 1, MaxInt);
    if (Length(Host) > 253) or (Length(PortText) > 5) then
      exit;
    for Index := 1 to Length(Host) do
    begin
      C := Host[Index];
      if not ((C >= 'A') and (C <= 'Z')) and
         not ((C >= 'a') and (C <= 'z')) and
         not ((C >= '0') and (C <= '9')) and
         (C <> '.') and (C <> '-') and (C <> ':') and (C <> '[') and
         (C <> ']') then
        exit;
    end;
    for Index := 1 to Length(PortText) do
      if (PortText[Index] < '0') or (PortText[Index] > '9') then
        exit;
    PortNum := StrToInt(PortText);
    if (PortNum < 1) or (PortNum > 65535) then
      exit;
  end;
  Result := True;
end;

procedure LoadDeployParameters(var Problems: string);
var
  Value: string;
  HasApiHost, HasBrokers, HasTopic: Boolean;
begin
  DeployApiHost := '0.0.0.0';
  DeployBrokers := '192.168.56.1:9092';
  DeployTopic := 'analysis-artifacts';
  HasApiHost := GetDeployValue('/APIHOST', Value);
  if HasApiHost then
  begin
    if ValidDeployHost(Value) then
      DeployApiHost := Value
    else
      Problems := Problems +
        '  /APIHOST=' + Value +
        ' is not an IP address or host name.' + #13#10;
  end;
  HasBrokers := GetDeployValue('/BROKERS', Value);
  if HasBrokers then
  begin
    if ValidDeployBrokers(Value) then
      DeployBrokers := Value
    else
      Problems := Problems +
        '  /BROKERS=' + Value +
        ' is not a comma-separated list of host:port entries.' + #13#10;
  end;
  HasTopic := GetDeployValue('/TOPIC', Value);
  if HasTopic then
  begin
    if ValidDeployTopic(Value) then
      DeployTopic := Value
    else
      Problems := Problems +
        '  /TOPIC=' + Value +
        ' uses characters outside A-Z a-z 0-9 . _ -.' + #13#10;
  end;
  DeployParamsGiven := HasApiHost or HasBrokers or HasTopic;
end;

function PromptWipeLogs: Boolean;
begin
  { Wiping is opt-in: the safe default keeps the logs for auditing. A silent
    uninstall gets that default, unless /WIPELOGS is passed explicitly. }
  if CommandLineSwitchExists('/WIPELOGS') then
  begin
    Log('Uninstall log removal requested with /WIPELOGS');
    Result := True;
    exit;
  end;

  if not DirExists(UninstallLogDir) then
  begin
    Result := False;
    exit;
  end;

  Result := SuppressibleMsgBox(
    'Delete the DaOrcs agent logs as well?' + #13#10 +
    '' + #13#10 +
    'Log folder:' + #13#10 +
    '  ' + UninstallLogDir + #13#10 +
    '' + #13#10 +
    'Yes removes agent.log, detections.log, service.log, install.log and the' + #13#10 +
    'setup/uninstall logs. No keeps them for auditing.' + #13#10 +
    '' + #13#10 +
    'Only the log folder is removed; state.sqlite3 is left untouched.',
    mbConfirmation, MB_YESNO, IDNO) = IDYES;
end;

function InitializeUninstall(): Boolean;
begin
  UninstallLogDir := ExpandConstant('{userappdata}\DaOrcs\Agent\logs');
  RegQueryStringValue(HKLM, 'Software\DaOrcs\Agent', 'LogDir', UninstallLogDir);
  { The service script runs during uninstall too; give it its own file so the
    Inno log copied below does not overwrite what it wrote. }
  InstallLogPath := UninstallLogDir + '\uninstall-service.log';
  WipeLogs := PromptWipeLogs;
  if WipeLogs then
    Log('The agent log folder will be removed at the end of the uninstall')
  else
    Log('The agent log folder will be kept');
  Result := True;
end;

procedure DeinitializeUninstall;
begin
  CopyInnoLog(UninstallLogDir, 'uninstall.log');
  { Remove the whole folder last, so it also takes the copy just written. }
  if WipeLogs and DirExists(UninstallLogDir) then
  begin
    Log('Removing the agent log folder: ' + UninstallLogDir);
    if DelTree(UninstallLogDir, True, True, True) then
    begin
      Log('Removed the agent log folder');
      { Remove the now-empty DaOrcs\Agent and DaOrcs parents, but only when
        nothing else lives there. }
      RemoveDir(ExtractFileDir(UninstallLogDir));
      RemoveDir(ExtractFileDir(ExtractFileDir(UninstallLogDir)));
    end
    else
      Log('Could not remove the agent log folder: ' + UninstallLogDir);
  end;
end;

function InitializeSetup(): Boolean;
var
  Problems: string;
begin
  LogDir := ExpandConstant('{userappdata}\DaOrcs\Agent\logs');
  InstallLogPath := LogDir + '\install.log';
  DaOrcsLog('DaOrcs Endpoint Agent setup starting');
  DaOrcsLog('Log folder: ' + LogDir);

  Problems := '';
  LoadDeployParameters(Problems);
  if Problems <> '' then
  begin
    DaOrcsLog('Refusing to run: deploy parameters are invalid:' + #13#10 +
      Problems);
    SuppressibleMsgBox(
      'DaOrcs Endpoint Agent setup was given invalid deploy parameters:' + #13#10 + #13#10 +
      Problems + #13#10 +
      'Re-run with corrected /APIHOST, /BROKERS and /TOPIC values, or ' +
      'without them to use the defaults.',
      mbError, MB_OK, IDOK);
    Result := False;
    exit;
  end;
  if DeployParamsGiven then
    DaOrcsLog('Deploy parameters: APIHOST=' + DeployApiHost +
      ' BROKERS=' + DeployBrokers + ' TOPIC=' + DeployTopic)
  else
    DaOrcsLog('No deploy parameters: a fresh install will use the defaults');

  IsUpgrade := DetectExistingInstall;
  if IsUpgrade then
    DaOrcsLog('Existing installation detected (' + PreviousVersion +
      '); this run updates it in place and restarts the service')
  else
    DaOrcsLog('No existing installation detected; this is a fresh install');
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
    '$name=''DaOrcsEndpointAgent''; ' +
    '$service=Get-Service -Name $name ' +
    '-ErrorAction SilentlyContinue; ' +
    'if ($service -and $service.Status -ne ''Stopped'') { ' +
    'Stop-Service -Name $name -Force; ' +
    '$service=Get-Service -Name $name; ' +
    '$service.WaitForStatus(' +
    '[System.ServiceProcess.ServiceControllerStatus]::Stopped, ' +
    '[TimeSpan]::FromSeconds(30)) }; ' +
    'try { & $env:SystemRoot\System32\schtasks.exe /End ' +
    '/TN ''DaOrcs Endpoint Agent'' 2>$null } catch {}; ' +
    'try { & $env:SystemRoot\System32\schtasks.exe /Delete ' +
    '/TN ''DaOrcs Endpoint Agent'' /F 2>$null } catch {}; ' +
    { A manually started copy (or a stuck service process) would keep the
      executable locked while Inno replaces it. }
    'Get-Process -Name ''DaOrcsAgent'' -ErrorAction SilentlyContinue | ' +
    'Stop-Process -Force -ErrorAction SilentlyContinue; exit 0"';
  DaOrcsLog('Stopping the existing agent and service before the update');
  if not Exec(
    ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'),
    Parameters, '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
  begin
    DaOrcsLog('Could not launch the upgrade stop step.');
    exit;
  end;
  DaOrcsLog('Upgrade stop step exit code: ' + IntToStr(ResultCode));
end;

procedure SeedAgentConfig;
var
  Target: string;
  Payload: string;
begin
  if not DeployParamsGiven then
    exit;
  if IsUpgrade then
  begin
    { An upgrade must never rewrite a configuration the operator tuned. }
    DaOrcsLog('Deploy parameters ignored: an existing agent.json is kept ' +
      'on upgrade');
    exit;
  end;
  Target := ExpandConstant('{app}') + '\agent.json';
  if FileExists(Target) then
  begin
    DaOrcsLog('Deploy parameters ignored: agent.json already exists at ' +
      Target);
    exit;
  end;
  Payload := SeedConfigTemplate;
  StringChangeEx(Payload, '@APIHOST@', DeployApiHost, True);
  StringChangeEx(Payload, '@BROKERS@', DeployBrokers, True);
  StringChangeEx(Payload, '@TOPIC@', DeployTopic, True);
  try
    ForceDirectories(ExpandConstant('{app}'));
  except
    { A missing data folder is reported by the file write below. }
  end;
  if SaveStringToFile(Target, Payload + #13#10, False) then
    DaOrcsLog('Seeded agent.json: APIHOST=' + DeployApiHost +
      ' BROKERS=' + DeployBrokers + ' TOPIC=' + DeployTopic +
      ' (the panel can reach the heartbeat on port 8787; allow inbound ' +
      'port 8787 in this endpoint''s firewall, restricted to the panel''s ' +
      'subnet)')
  else
    DaOrcsLog('WARNING: could not write ' + Target +
      '; the example agent.json is installed instead');
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  Detail: string;
begin
  if CurStep = ssInstall then
  begin
    if IsUpgrade then
      PrepareForUpgrade
    else
    begin
      DaOrcsLog('Fresh install: no existing agent or service to stop');
      { Before the [Files] step: the seeded file makes the example copy's
        onlyifdoesntexist flag skip it, so the target's own address wins. }
      SeedAgentConfig;
    end;
  end;

  if CurStep = ssPostInstall then
  begin
    { An upgrade keeps the existing service registration and only points it at
      the new files before restarting; a fresh install creates it. }
    if IsUpgrade then
      RunServiceScript('upgrade', ServiceInstallCode)
    else
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
    else if IsUpgrade then
      DaOrcsLog('Windows service updated and restarted successfully')
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
