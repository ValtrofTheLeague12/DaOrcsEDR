<#
.SYNOPSIS
    Installs a single-node Apache Kafka (KRaft) broker on Windows.

.DESCRIPTION
    No Docker and no WSL. The script downloads Apache Kafka and, when the host
    has no Java 11+, a portable Temurin JRE. It formats the KRaft storage
    directory, registers DaOrcsKafka as a Windows service through WinSW,
    starts it, waits for the listener and creates the agent topic.

.PARAMETER InstallDir
    Kafka distribution and WinSW live here.

.PARAMETER DataDir
    Broker data and the bundled JRE live here (survives upgrades).

.PARAMETER LogDir
    Installer transcript and WinSW service output. Defaults to
    %APPDATA%\DaOrcs\Kafka\logs, not ProgramData.

.PARAMETER AdvertisedHost
    Address endpoints use to reach this broker. Defaults to the first
    non-loopback IPv4 address. Use the host's LAN IP, not 127.0.0.1, when
    remote endpoints must connect.
#>
[CmdletBinding()]
param(
    [string]$InstallDir = "$env:ProgramFiles\DaOrcs\Kafka",
    [string]$DataDir = "$env:ProgramData\DaOrcs\Kafka",
    [string]$LogDir = "",
    [string]$KafkaVersion = "3.9.1",
    [string]$ScalaVersion = "2.13",
    [int]$Port = 9092,
    [int]$ControllerPort = 9093,
    [string]$Topic = "analysis-artifacts",
    [string]$AdvertisedHost = "",
    [int]$TimeoutSeconds = 180,
    [switch]$NoService,
    [switch]$NoFirewall,
    [switch]$NoJavaDownload,
    [switch]$Force,
    [switch]$NoPause
)

$ErrorActionPreference = "Stop"
if (-not $LogDir) { $LogDir = Join-Path $env:APPDATA "DaOrcs\Kafka\logs" }
$script:LogFile = Join-Path $LogDir ("install-kafka-{0}.log" -f (Get-Date -Format "yyyyMMdd-HHmmss"))
$script:ExitCode = 0

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
    # Rebuild the command line from the bound parameters so the elevated child
    # installs with exactly the same options. Start-Process joins the list with
    # spaces, so every value is quoted explicitly.
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
    Restart-Elevated -BoundParameters $PSBoundParameters -Reason "Installing native Kafka"
}

function Initialize-Log {
    New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
    New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
    New-Item -ItemType Directory -Force -Path (Join-Path $DataDir "kafka-logs") | Out-Null
}

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

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "This script must run from an elevated PowerShell (Run as administrator)."
    }
}

function Invoke-Native {
    param([string]$FilePath, [string[]]$ArgumentList, [string]$What)
    Write-Log ("RUN {0}: `"{1}`" {2}" -f $What, $FilePath, ($ArgumentList -join " "))
    # Native tools (and the Kafka .bat wrappers in particular) write progress to
    # stderr. With ErrorActionPreference=Stop, PowerShell 5.1 turns redirected
    # native stderr into a terminating error, which would abort a healthy run.
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
    param([string]$HostName, [int]$PortNumber, [int]$TimeoutMs = 2000)
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $async = $client.BeginConnect($HostName, $PortNumber, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) { return $false }
        $client.EndConnect($async)
        return $true
    } catch {
        return $false
    } finally {
        $client.Close()
    }
}

function Get-DefaultAdvertisedHost {
    try {
        $addresses = [System.Net.Dns]::GetHostAddresses([System.Net.Dns]::GetHostName()) |
            Where-Object {
                $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork -and
                -not $_.IPAddressToString.StartsWith("127.") -and
                -not $_.IPAddressToString.StartsWith("169.254.")
            }
        if ($addresses) { return $addresses[0].IPAddressToString }
    } catch { }
    return "127.0.0.1"
}

function Get-ExistingJavaHome {
    $candidates = @()
    if ($env:JAVA_HOME) { $candidates += $env:JAVA_HOME }
    $candidates += (Join-Path $DataDir "jre")
    $java = Get-Command java.exe -ErrorAction SilentlyContinue
    if ($java) {
        $candidates += (Split-Path -Parent (Split-Path -Parent $java.Source))
    }
    foreach ($candidate in $candidates) {
        if ($candidate -and (Test-Path -LiteralPath (Join-Path $candidate "bin\java.exe"))) {
            $major = 0
            $text = (& (Join-Path $candidate "bin\java.exe") -version 2>&1 | Out-String)
            if ($text -match 'version "(?<v>\d+)') { $major = [int]$Matches.v }
            if ($major -ge 11) { return $candidate }
            Write-Log "Found Java at $candidate but version $major is too old (need 11+)" "WARN"
        }
    }
    return $null
}

function Install-PortableJre {
    $javaHome = Join-Path $DataDir "jre"
    if (Test-Path -LiteralPath (Join-Path $javaHome "bin\java.exe")) { return $javaHome }
    if ($NoJavaDownload) {
        throw "Java 11+ is not installed and -NoJavaDownload was given."
    }

    $zip = Join-Path $env:TEMP "daorcs-temurin-jre17.zip"
    if (-not (Test-Path -LiteralPath $zip)) {
        $url = "https://api.adoptium.net/v3/binary/latest/17/ga/windows/x64/jre/hotspot/normal/eclipse?project=jdk"
        Write-Log "Downloading a portable Temurin 17 JRE (this is a one-time ~45 MB download)"
        $ProgressPreference = "SilentlyContinue"
        Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing
    }

    $tmp = Join-Path $env:TEMP ("daorcs-jre-" + [Guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Force -Path $tmp | Out-Null
    Expand-Archive -LiteralPath $zip -DestinationPath $tmp -Force
    $root = Get-ChildItem -LiteralPath $tmp -Directory | Select-Object -First 1
    if (-not $root) { throw "The downloaded JRE archive did not contain a directory." }
    if (Test-Path -LiteralPath $javaHome) { Remove-Item -LiteralPath $javaHome -Recurse -Force }
    Move-Item -LiteralPath $root.FullName -Destination $javaHome
    Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
    Write-Log "Installed portable JRE at $javaHome"
    return $javaHome
}

function Install-KafkaDistribution {
    $startBat = Join-Path $InstallDir "bin\windows\kafka-server-start.bat"
    $versionFile = Join-Path $InstallDir ".kafka-version"
    $sameVersion = (Test-Path -LiteralPath $versionFile) -and
        (((Get-Content -LiteralPath $versionFile -Raw).Trim()) -eq $KafkaVersion)
    if ((Test-Path -LiteralPath $startBat) -and $sameVersion -and -not $Force) {
        Write-Log "Kafka $KafkaVersion is already extracted at $InstallDir"
        return
    }

    $tar = Get-Command tar.exe -ErrorAction SilentlyContinue
    if (-not $tar) {
        throw "tar.exe was not found. Windows 10 1803+ ships it; otherwise extract the Kafka .tgz manually."
    }

    $archive = Join-Path $env:TEMP ("kafka_{0}-{1}.tgz" -f $ScalaVersion, $KafkaVersion)
    if ($Force -or -not (Test-Path -LiteralPath $archive)) {
        $url = "https://archive.apache.org/dist/kafka/$KafkaVersion/kafka_$ScalaVersion-$KafkaVersion.tgz"
        Write-Log "Downloading Apache Kafka $KafkaVersion from $url"
        $ProgressPreference = "SilentlyContinue"
        Invoke-WebRequest -Uri $url -OutFile $archive -UseBasicParsing
    }

    $service = Get-Service -Name "DaOrcsKafka" -ErrorAction SilentlyContinue
    if ($service -and $service.Status -ne "Stopped") {
        Write-Log "Stopping DaOrcsKafka before replacing the distribution"
        Stop-Service -Name "DaOrcsKafka" -Force
        $service.WaitForStatus(
            [System.ServiceProcess.ServiceControllerStatus]::Stopped,
            [TimeSpan]::FromSeconds(30))
    }

    $tmp = Join-Path $env:TEMP ("daorcs-kafka-" + [Guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Force -Path $tmp | Out-Null
    Write-Log "Extracting $archive"
    $code = Invoke-Native $tar.Source @("-xzf", $archive, "-C", $tmp) "tar"
    if ($code -ne 0) { throw "Could not extract the Kafka archive (tar exit $code)." }
    $root = Get-ChildItem -LiteralPath $tmp -Directory | Select-Object -First 1
    if (-not $root) { throw "The Kafka archive did not contain a directory." }

    if (Test-Path -LiteralPath $InstallDir) { Remove-Item -LiteralPath $InstallDir -Recurse -Force }
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    Get-ChildItem -LiteralPath $root.FullName -Force |
        Copy-Item -Destination $InstallDir -Recurse -Force
    Set-Content -LiteralPath $versionFile -Value $KafkaVersion -Encoding ASCII
    Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
    Write-Log "Extracted Kafka to $InstallDir"
}

function Write-KafkaConfig {
    $configFile = Join-Path $DataDir "server.properties"
    $logDirs = (Join-Path $DataDir "kafka-logs").Replace("\", "/")
    $content = @"
# Generated by DaOrcs install-kafka-windows.ps1
process.roles=broker,controller
node.id=1
controller.quorum.voters=1@127.0.0.1:$ControllerPort
listeners=PLAINTEXT://0.0.0.0:$Port,CONTROLLER://127.0.0.1:$ControllerPort
advertised.listeners=PLAINTEXT://${AdvertisedHost}:$Port
controller.listener.names=CONTROLLER
listener.security.protocol.map=CONTROLLER:PLAINTEXT,PLAINTEXT:PLAINTEXT
inter.broker.listener.name=PLAINTEXT
log.dirs=$logDirs
num.partitions=3
default.replication.factor=1
offsets.topic.replication.factor=1
transaction.state.log.replication.factor=1
transaction.state.log.min.isr=1
group.initial.rebalance.delay.ms=0
auto.create.topics.enable=true
message.max.bytes=10485760
replica.fetch.max.bytes=10485760
"@
    Set-Content -LiteralPath $configFile -Value $content -Encoding ASCII
    Write-Log "Wrote broker configuration: $configFile"
    return $configFile
}

function Format-KafkaStorage {
    param([string]$ConfigFile)
    $storage = Join-Path $InstallDir "bin\windows\kafka-storage.bat"
    $previous = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $raw = (& $storage random-uuid 2>&1 | Out-String)
    } finally {
        $ErrorActionPreference = $previous
    }
    # The wrapper can print log lines around the value; take the last token that
    # looks like a KRaft cluster id instead of trusting the last line.
    $match = [regex]::Matches($raw, "[A-Za-z0-9_-]{22}") | Select-Object -Last 1
    if (-not $match) {
        Write-Log "kafka-storage random-uuid output: $raw" "ERROR"
        throw "kafka-storage.bat did not return a cluster id."
    }
    $clusterId = $match.Value
    Write-Log "Formatting KRaft storage with cluster id $clusterId"
    $code = Invoke-Native $storage @(
        "format", "-t", $clusterId, "-c", $ConfigFile, "--ignore-formatted") "kafka-storage format"
    if ($code -ne 0) { throw "KRaft storage formatting failed (exit $code)." }
}

function Install-KafkaService {
    param([string]$ConfigFile)
    $winsw = Join-Path $InstallDir "DaOrcsKafka.exe"
    if (-not (Test-Path -LiteralPath $winsw)) {
        $url = "https://github.com/winsw/winsw/releases/download/v2.12.0/WinSW-x64.exe"
        Write-Log "Downloading WinSW 2.12.0 from $url"
        $ProgressPreference = "SilentlyContinue"
        Invoke-WebRequest -Uri $url -OutFile $winsw -UseBasicParsing
    }

    $startBat = Join-Path $InstallDir "bin\windows\kafka-server-start.bat"
    $serviceLogDir = Join-Path $LogDir "service"
    New-Item -ItemType Directory -Force -Path $serviceLogDir | Out-Null
    $argumentLine = '/c ""{0}" "{1}""' -f $startBat, $ConfigFile
    $xml = @"
<service>
  <id>DaOrcsKafka</id>
  <name>DaOrcs Kafka Broker</name>
  <description>Apache Kafka (KRaft) broker used by DaOrcs endpoint agents.</description>
  <executable>$env:SystemRoot\System32\cmd.exe</executable>
  <arguments>$argumentLine</arguments>
  <workingdirectory>$InstallDir</workingdirectory>
  <env name="JAVA_HOME" value="$JavaHome"/>
  <logmode>rotate</logmode>
  <logpath>$serviceLogDir</logpath>
  <stoptimeout>30sec</stoptimeout>
  <onfailure action="restart" delay="10 sec"/>
  <onfailure action="restart" delay="30 sec"/>
  <onfailure action="none"/>
</service>
"@
    $xmlPath = Join-Path $InstallDir "DaOrcsKafka.xml"
    Set-Content -LiteralPath $xmlPath -Value $xml -Encoding ASCII
    Write-Log "Wrote WinSW configuration: $xmlPath"

    [void](Invoke-Native $winsw @("stop") "WinSW stop")
    [void](Invoke-Native $winsw @("uninstall") "WinSW uninstall")
    $code = Invoke-Native $winsw @("install") "WinSW install"
    if ($code -ne 0) { throw "WinSW could not install the DaOrcsKafka service (exit $code)." }
    $code = Invoke-Native $winsw @("start") "WinSW start"
    if ($code -ne 0) { throw "WinSW could not start the DaOrcsKafka service (exit $code)." }
}

function Wait-KafkaPort {
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    Write-Log "Waiting up to $TimeoutSeconds seconds for 127.0.0.1:$Port"
    while ((Get-Date) -lt $deadline) {
        if (Test-TcpPort -HostName "127.0.0.1" -PortNumber $Port) {
            Write-Log "Kafka is listening on 127.0.0.1:$Port"
            return
        }
        Start-Sleep -Seconds 2
    }

    # Explain the timeout instead of just reporting it. -NoService writes to the
    # kafka-console*.log files; the Windows service writes through WinSW.
    $candidates = @()
    $serviceLogDir = Join-Path $LogDir "service"
    if (Test-Path -LiteralPath $serviceLogDir) {
        $candidates += Get-ChildItem -LiteralPath $serviceLogDir -File -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending |
            Select-Object -First 3
    }
    foreach ($name in @("kafka-console.out.log", "kafka-console.err.log")) {
        $path = Join-Path $LogDir $name
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            $candidates += Get-Item -LiteralPath $path
        }
    }
    foreach ($file in $candidates) {
        Write-Log "Last log lines ($($file.FullName)):" "ERROR"
        Get-Content -LiteralPath $file.FullName -Tail 40 -ErrorAction SilentlyContinue |
            ForEach-Object { Write-Log ("  log | $_") "ERROR" }
    }
    $service = Get-Service -Name "DaOrcsKafka" -ErrorAction SilentlyContinue
    if ($service) {
        Write-Log "DaOrcsKafka status: $($service.Status) (see $serviceLogDir)" "ERROR"
    }

    throw "Kafka did not open port $Port within $TimeoutSeconds seconds."
}

function Ensure-Topic {
    $topics = Join-Path $InstallDir "bin\windows\kafka-topics.bat"
    $code = Invoke-Native $topics @(
        "--bootstrap-server", "127.0.0.1:$Port",
        "--create", "--if-not-exists",
        "--topic", $Topic,
        "--partitions", "3",
        "--replication-factor", "1") "kafka-topics create"
    if ($code -ne 0) {
        Write-Log "Topic creation returned $code; the broker may already have it." "WARN"
    }
}

function Start-KafkaConsole {
    param([string]$ConfigFile)
    $startBat = Join-Path $InstallDir "bin\windows\kafka-server-start.bat"
    $outLog = Join-Path $LogDir "kafka-console.out.log"
    $errLog = Join-Path $LogDir "kafka-console.err.log"
    $commandLine = '/c ""{0}" "{1}""' -f $startBat, $ConfigFile
    $process = Start-Process -FilePath "$env:SystemRoot\System32\cmd.exe" `
        -ArgumentList $commandLine -WorkingDirectory $InstallDir -WindowStyle Hidden `
        -RedirectStandardOutput $outLog -RedirectStandardError $errLog -PassThru
    $process.Id | Set-Content -LiteralPath (Join-Path $DataDir "kafka.pid") -Encoding ASCII
    Write-Log "Kafka started in the background (PID $($process.Id)); logs: $outLog"
}

function Write-AgentTemplate {
    $example = Join-Path (Split-Path -Parent $PSScriptRoot) "agent.example.json"
    $target = Join-Path $DataDir "endpoint-agent.json.example"
    if (Test-Path -LiteralPath $example) {
        try {
            $doc = Get-Content -LiteralPath $example -Raw | ConvertFrom-Json
            $doc.kafka.bootstrap_servers = "${AdvertisedHost}:$Port"
            $doc.kafka.topic = $Topic
            $doc | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $target -Encoding UTF8
        } catch {
            Write-Log "Could not build endpoint agent template: $($_.Exception.Message)" "WARN"
        }
    }
    return $target
}

try {
    Initialize-Log
    Write-Log "DaOrcs native Kafka installer starting"
    Write-Log "Kafka $KafkaVersion, install=$InstallDir, data=$DataDir, port=$Port"
    Assert-Administrator

    if (-not $AdvertisedHost) { $AdvertisedHost = Get-DefaultAdvertisedHost }
    if ($AdvertisedHost -in @("127.0.0.1", "localhost", "::1")) {
        Write-Log "Advertised listener is loopback; remote endpoints will not reach this broker. Pass -AdvertisedHost <LAN-IP>." "WARN"
    }
    Write-Log "Advertised listener: ${AdvertisedHost}:$Port"

    $JavaHome = Get-ExistingJavaHome
    if (-not $JavaHome) { $JavaHome = Install-PortableJre }
    $env:JAVA_HOME = $JavaHome
    $env:PATH = (Join-Path $JavaHome "bin") + ";" + $env:PATH
    Write-Log "Using JAVA_HOME=$JavaHome"

    Install-KafkaDistribution
    $ConfigFile = Write-KafkaConfig
    Format-KafkaStorage -ConfigFile $ConfigFile

    if ($NoService) {
        Start-KafkaConsole -ConfigFile $ConfigFile
    } else {
        Install-KafkaService -ConfigFile $ConfigFile
    }

    Wait-KafkaPort
    Ensure-Topic

    if (-not $NoFirewall) {
        $ruleName = "DaOrcs Kafka $Port"
        try {
            $existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
            if (-not $existing) {
                New-NetFirewallRule -DisplayName $ruleName -Direction Inbound `
                    -Protocol TCP -LocalPort $Port -Action Allow -Profile Any | Out-Null
                Write-Log "Created firewall rule: $ruleName"
            } else {
                Write-Log "Firewall rule already exists: $ruleName"
            }
        } catch {
            # A locked-down firewall policy must not undo a working broker.
            Write-Log "Could not create the firewall rule '$ruleName': $($_.Exception.Message)" "WARN"
            Write-Log "Endpoints on other machines may be blocked until TCP $Port is allowed." "WARN"
        }
    }

    $template = Write-AgentTemplate
    Write-Log "Broker is ready. Agent bootstrap_servers=${AdvertisedHost}:$Port topic=$Topic"
    Write-Log "Endpoint agent template: $template"
    Write-Log "Install log: $script:LogFile"
    Write-Log "Service: Get-Service DaOrcsKafka; logs: $(Join-Path $LogDir 'service')"
    $script:ExitCode = 0
} catch {
    Write-Log "FATAL: $($_.Exception.Message)" "ERROR"
    Write-Log $_.ScriptStackTrace "ERROR"
    $script:ExitCode = 1
}

Write-Host ""
if ($script:ExitCode -eq 0) {
    Write-Host "  Kafka is installed and listening." -ForegroundColor Green
} else {
    Write-Host "  Kafka installation failed. See $script:LogFile" -ForegroundColor Red
}
Write-Host "  Log: $script:LogFile" -ForegroundColor DarkGray
Write-Host ""
if (-not $NoPause -and $Host.Name -eq "ConsoleHost") {
    Read-Host "  Press Enter to close this window" | Out-Null
}
exit $script:ExitCode
