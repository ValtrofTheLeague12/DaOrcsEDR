[CmdletBinding()]
param(
    [switch]$Clean,
    [string]$InputFile,
    # Pipeline spec: a bare name (extract_strings), a .yaml/.json path,
    # 'default', or inline JSON like '["strings","model"]'.
    [string]$Pipeline,
    [switch]$ListPipelines,
    # Stop after linking. Skips the smoke test that runs the freshly built
    # analyzer against itself, which is useful interactively but floods a log
    # with several thousand lines of self-analysis and buries the compile
    # output it was meant to follow.
    [switch]$NoRun,
    # ---------------------------------------------------------------------
    # Hardening overrides.
    #
    # The settings live in config/hardening.json and are read below, so a
    # build from a terminal and a build from the panel produce the same
    # binary. These switches are the per-build override: each is a PRESENCE
    # switch, and a switch that was not passed leaves the file's value alone.
    # That is why they come in Enable/Disable pairs rather than being plain
    # booleans - a plain boolean cannot say "not specified".
    # ---------------------------------------------------------------------
    [switch]$EnableAslr,
    [switch]$DisableAslr,
    [switch]$EnableHighEntropyVa,
    [switch]$DisableHighEntropyVa,
    [switch]$EnableDepNx,
    [switch]$DisableDepNx,
    [switch]$EnableStackProtector,
    [switch]$DisableStackProtector
)

$ErrorActionPreference = 'Stop'

$env:PATH = "C:\msys64\ucrt64\bin;$env:PATH"
$env:STATIC_ANALYZER_CURSES = "0"

Set-Location -LiteralPath $PSScriptRoot

# ---------------------------------------------------------------------------
# The failure banner.
#
# A failed command used to end in a bare PowerShell error record while the
# analyzer's own CRASH presentation never appeared: the analyzer prints
# logos/crash.logo in red when it faults (banner::print_crash_banner in
# src/core/banner.cpp), and a build that ends in a throw looked nothing like
# the thing it wraps. This prints the same file the same way - red, centred,
# with the same STATIC_ANALYZER_CRASH_LOGO override and daorcs.logo fallback
# - so a failure at the bottom of a long build looks like the failure it is.
# ---------------------------------------------------------------------------
function Show-CrashBanner {
    $Candidates = if ($env:STATIC_ANALYZER_CRASH_LOGO) {
        @($env:STATIC_ANALYZER_CRASH_LOGO)
    } else {
        @((Join-Path $PSScriptRoot 'logos\crash.logo'),
          (Join-Path $PSScriptRoot 'logos\daorcs.logo'))
    }
    $LogoPath = $Candidates | Where-Object {
        $_ -and (Test-Path -LiteralPath $_)
    } | Select-Object -First 1
    if (-not $LogoPath) { return }

    try {
        $Art = @(Get-Content -LiteralPath $LogoPath -Encoding UTF8)
    } catch { return }

    # Trailing blank lines are padding in the file, not part of the art.
    $Last = $Art.Count - 1
    while ($Last -ge 0 -and [string]::IsNullOrWhiteSpace($Art[$Last])) { $Last-- }
    if ($Last -lt 0) { return }
    $Art = $Art[0..$Last]

    $Width = ($Art | Measure-Object -Property Length -Maximum).Maximum
    $Cols = 0
    try { $Cols = $Host.UI.RawUI.WindowSize.Width } catch { $Cols = 0 }
    $Margin = if ($Cols -gt $Width) { ' ' * [int](($Cols - $Width) / 2) } else { '' }

    Write-Host ''
    foreach ($Line in $Art) { Write-Host ($Margin + $Line) -ForegroundColor Red }
    Write-Host ''
}

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
        Show-CrashBanner
        Write-Host "command failed (exit $code): $display" -ForegroundColor Red

        # The analyzer's OWN exit-code vocabulary, said where it happens. Its
        # explanation is in the output above - 'Result: stopped: <reason>',
        # the crash report path when there was a real fault - so these lines
        # only name what the number means, to keep a policy stop from being
        # read as a crash (a crash writes logs/crash/<run>-<pid>.txt; exit 3
        # never does, because nothing faulted).
        $IsAnalyzer = [System.IO.Path]::GetFileNameWithoutExtension($Command) -ieq 'static_analyzer'
        if ($IsAnalyzer -and $code -eq 3) {
            Write-Host 'exit 3 is not a crash: the run stopped itself on a policy flag.' -ForegroundColor Yellow
            Write-Host "  The 'Result: stopped: <reason>' line above carries the detail - most" -ForegroundColor Yellow
            Write-Host '  often IA_INTERRUPT_IF_PACKED, which ends a packed run at the histogram' -ForegroundColor Yellow
            Write-Host '  phase. No crash report is written; the completed phases are kept.' -ForegroundColor Yellow
        } elseif ($IsAnalyzer -and $code -eq 130) {
            Write-Host 'exit 130: the run was interrupted; completed phases resume with --resume.' -ForegroundColor Yellow
        }
        # Air before PowerShell's own error record, so the banner and the
        # CategoryInfo block do not read as one wall of text.
        Write-Host ''
        throw "Command failed with exit code $code"
    }
}

if ($Clean -and (Test-Path -LiteralPath 'build-ucrt')) {
    Write-Host 'Removing build-ucrt...' -ForegroundColor Yellow
    Remove-Item -LiteralPath 'build-ucrt' -Recurse -Force
}

# ---------------------------------------------------------------------------
# Hardening settings.
#
# config/hardening.json is the shared source of truth: the panel writes it,
# this script reads it, and both produce the same binary. A missing file is
# not an error - the defaults below are then the settings, and they are ON
# because MinGW's linker already turns the first three on by default and the
# compiler already supports the fourth.
#
# A malformed file IS an error. Building with silently-ignored settings would
# produce a binary that does not match what the file claims to describe, and
# the whole point of the file is that it can be checked.
# ---------------------------------------------------------------------------
$HardeningConfig = Join-Path $PSScriptRoot 'config\hardening.json'

$Hardening = [ordered]@{
    Aslr           = $true
    HighEntropyVa  = $true
    DepNx          = $true
    StackProtector = $true
}

# The CMake option each one drives. Kept here rather than derived from the
# JSON key so the mapping is written down in one place.
$HardeningOptions = [ordered]@{
    Aslr           = 'STATIC_ANALYZER_HARDENING_ASLR'
    HighEntropyVa  = 'STATIC_ANALYZER_HARDENING_HIGH_ENTROPY_VA'
    DepNx          = 'STATIC_ANALYZER_HARDENING_DEP_NX'
    StackProtector = 'STATIC_ANALYZER_HARDENING_STACK_PROTECTOR'
}

if (Test-Path -LiteralPath $HardeningConfig) {
    try {
        $Raw = Get-Content -LiteralPath $HardeningConfig -Raw -Encoding UTF8
        $Parsed = $Raw | ConvertFrom-Json
    }
    catch {
        throw "Could not read '$HardeningConfig': $($_.Exception.Message)"
    }

    if ($null -ne $Parsed) {
        foreach ($Key in @('aslr', 'high_entropy_va', 'dep_nx', 'stack_protector')) {
            $Prop = $Parsed.PSObject.Properties[$Key]
            if ($null -eq $Prop) { continue }
            if ($Prop.Value -isnot [bool]) {
                throw "'$Key' in '$HardeningConfig' must be true or false"
            }
            switch ($Key) {
                'aslr'            { $Hardening.Aslr           = [bool]$Prop.Value }
                'high_entropy_va' { $Hardening.HighEntropyVa  = [bool]$Prop.Value }
                'dep_nx'          { $Hardening.DepNx          = [bool]$Prop.Value }
                'stack_protector' { $Hardening.StackProtector = [bool]$Prop.Value }
            }
        }
    }
}

# Per-build overrides, applied AFTER the settings above exist: they write into
# $Hardening. This order is load-bearing - with the sections the other way
# round, $Hardening was read while still $null, so config/hardening.json and
# these switches never reached the configure step (and passing a switch
# crashed with "Cannot index into a null array"). A switch that was not
# passed leaves the file's value alone, so an operator can turn ONE
# protection off for one build without editing the shared file.
$Overrides = @(
    @{ Name = 'Aslr';           Enable = $EnableAslr;           Disable = $DisableAslr }
    @{ Name = 'HighEntropyVa';  Enable = $EnableHighEntropyVa;  Disable = $DisableHighEntropyVa }
    @{ Name = 'DepNx';          Enable = $EnableDepNx;          Disable = $DisableDepNx }
    @{ Name = 'StackProtector'; Enable = $EnableStackProtector; Disable = $DisableStackProtector }
)

foreach ($O in $Overrides) {
    if ($O.Enable -and $O.Disable) {
        throw "Enable$($O.Name) and Disable$($O.Name) cannot both be given"
    }
    if ($O.Enable) { $Hardening[$O.Name] = $true }
    elseif ($O.Disable) { $Hardening[$O.Name] = $false }
}

Write-Host 'Hardening settings:' -ForegroundColor Cyan
foreach ($Name in $Hardening.Keys) {
    $State = if ($Hardening[$Name]) { 'on' } else { 'off' }
    Write-Host ("  {0,-16} {1}" -f $Name, $State) -ForegroundColor DarkGray
}

# The CMake options that carry the intent into the configure step. They are
# written into build-ucrt/CMakeCache.txt, so the configured tree records which
# protections this build was configured for - and the panel compares that
# against the finished binary's PE header.
$HardeningCmakeArgs = @()
foreach ($Name in $Hardening.Keys) {
    $Value = if ($Hardening[$Name]) { 'ON' } else { 'OFF' }
    $HardeningCmakeArgs += "-D$($HardeningOptions[$Name])=$Value"
}

Invoke-Checked 'cmake' '--preset' 'ucrt64' @HardeningCmakeArgs
Invoke-Checked 'cmake' '--build' '--preset' 'ucrt64-release'
$Analyzer = Join-Path $PSScriptRoot 'build-ucrt\static_analyzer.exe'

if (-not (Test-Path -LiteralPath $Analyzer)) {
    throw "Analyzer not found at '$Analyzer' (build may have failed)"
}

if ($ListPipelines) {
    Write-Host 'Available pipelines:' -ForegroundColor Cyan
    Invoke-Checked $Analyzer '--list-pipelines'
    Write-Host "Executable: $Analyzer" -ForegroundColor Green
    exit 0
}

$RunArgs = @()
if ($Pipeline) {
    $RunArgs += @('--pipeline', $Pipeline)
}

if ($NoRun) {
    # The exe existence check above is the last thing that can fail the build,
    # so linking really is done at this point.
    Write-Host "Built (not run -NoRun): $Analyzer" -ForegroundColor Green
    Write-Host 'Build completed successfully.' -ForegroundColor Green
    exit 0
}

if ($InputFile) {
    if (-not (Test-Path -LiteralPath $InputFile)) {
        throw "Input file '$InputFile' does not exist"
    }
    $ResolvedInput = (Resolve-Path -LiteralPath $InputFile).Path
    Write-Host "Analyzing: $ResolvedInput" -ForegroundColor Cyan
    Invoke-Checked $Analyzer @RunArgs $ResolvedInput
} elseif ($Pipeline) {
    # Default sample: a.exe next to the script when present, else the exe itself.
    $DefaultSample = Join-Path $PSScriptRoot 'a.exe'
    if (-not (Test-Path -LiteralPath $DefaultSample)) { $DefaultSample = $Analyzer }
    Write-Host "Analyzing (pipeline $Pipeline): $DefaultSample" -ForegroundColor Cyan
    Invoke-Checked $Analyzer @RunArgs $DefaultSample
} else {
    Write-Host "Analyzing (default): $Analyzer" -ForegroundColor Cyan
    Invoke-Checked $Analyzer $Analyzer
}

Write-Host "Executable: $Analyzer" -ForegroundColor Green
Write-Host 'Build completed successfully.' -ForegroundColor Green