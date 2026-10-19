<#
.SYNOPSIS
    Update the yarGen-Go databases, check everything, then run yarGen.

.DESCRIPTION
    yarGen needs three things to be in place before it can produce a rule, and
    two of them fail silently rather than loudly:

      * dbs/            goodware opcode and string databases, downloaded with
                        `yargen-util update`. They are generated, not committed
                        (.gitignore lists dbs/), so a fresh clone has none and
                        yarGen still starts - it just scores every string as
                        unseen noise.
      * config/config.yaml
                        read at startup; yargen -config defaults to exactly
                        this path. Only config.example.yml is committed, so the
                        default path is usually absent.
      * yargen.exe      the prebuilt binary. This script never rebuilds it; it
                        reports whether the Go toolchain is present so a
                        missing binary is diagnosable rather than mysterious.

    Every check runs BEFORE the database update and again after, so a failed
    download is reported as a failed download instead of leaving a half-updated
    catalog that only shows up as worse rules.

    Both binaries resolve ./dbs relative to the working directory, so the
    script pushes into its own directory and everything below is relative to
    the yarGen-Go checkout.

.PARAMETER Sample
    Single file to generate a rule from (passed to yargen -f).

.PARAMETER Directory
    Directory of samples to generate rules from (passed to yargen -m).

.PARAMETER Output
    Rule output path. Defaults to yargen's own yargen_rules.yar.

.PARAMETER Config
    Config file. Defaults to yargen's ./config/config.yaml.

.PARAMETER SkipUpdate
    Do not run `yargen-util update`; run the checks and go straight to yargen.

.PARAMETER NoRun
    Check only. Do not update the databases and do not run yargen.

.PARAMETER UpdateOnly
    Update the databases and re-run the checks, then stop. This is what the
    admin console's "Update yarGen-Go" button wants.

    It existed because the script had no such mode. -NoRun checks without
    updating, and the default updates but then runs yargen, which demands a
    -Sample or -Directory. So a button whose entire job is "download the
    databases and re-check the prerequisites" had no invocation that did that:
    it either failed on a missing input, or passed without downloading
    anything. Both look like success in a job list.

.PARAMETER NoLlm
    Pass -no-llm so string selection does not need an API key.

.PARAMETER Force
    Continue past warnings instead of stopping.

.EXAMPLE
    .\update_and_check.ps1 -Sample .\quick_test.exe

.EXAMPLE
    .\update_and_check.ps1 -Directory C:\samples -NoRun
#>
[CmdletBinding()]
param(
    [string] $Sample,
    [string] $Directory,
    [string] $Output,
    [string] $Config,
    [switch] $SkipUpdate,
    [switch] $NoRun,
[switch] $UpdateOnly,
    [switch] $NoLlm,
    [switch] $Force
)

# --------------------------------------------------------------------------
# Result collection
# --------------------------------------------------------------------------

$script:Results = New-Object System.Collections.ArrayList

function Add-Result {
    param([string] $Name, [string] $Status, [string] $Detail = '')
    $null = $script:Results.Add([pscustomobject]@{
        Name = $Name; Status = $Status; Detail = $Detail
    })
    $colour = switch ($Status) {
        'ok'   { 'Green' }
        'warn' { 'Yellow' }
        'fail' { 'Red' }
        'skip' { 'DarkGray' }
        default { 'Gray' }
    }
    Write-Host ('  [{0,-4}] {1}' -f $Status, $Name) -ForegroundColor $colour -NoNewline
    if ($Detail) { Write-Host ('  {0}' -f $Detail) -ForegroundColor DarkGray }
    else { Write-Host '' }
}

function Fmt-Num {
    param($Value)
    # Invariant culture on purpose: a locale thousands separator (a narrow
    # no-break space under a French locale) is not renderable on the legacy
    # console code page and comes out as '?'.
    if ($null -eq $Value) { return '0' }
    return ([double] $Value).ToString('N0', [System.Globalization.CultureInfo]::InvariantCulture)
}

function Step {
    param([string] $Title)
    $pad = '=' * [Math]::Max(3, 62 - $Title.Length)
    Write-Host ("`n== {0} {1}" -f $Title, $pad) -ForegroundColor Cyan
}

# --------------------------------------------------------------------------
# Environment
# --------------------------------------------------------------------------

# This script lives in tools/yarGen/, not in the yarGen-Go checkout, because
# the checkout is a nested git repository: anything inside it is invisible to
# this repository, so a maintenance script kept there is in no version control
# at all and every fix to it is one re-clone from being lost.
#
# yarGen resolves ./dbs and ./config against the working directory, so the root
# is the checkout rather than this file's own directory.
$Root = Resolve-Path (Join-Path $PSScriptRoot '..\..\yarGen-Go')
Push-Location $Root

$Yargen      = Join-Path $Root 'yargen.exe'
$YargenUtil  = Join-Path $Root 'yargen-util.exe'
$ExampleCfg  = Join-Path $Root 'config\config.example.yml'
$DbDir       = Join-Path $Root 'dbs'

if (-not $Config) { $Config = Join-Path $Root 'config\config.yaml' }
if (-not $Output) { $Output = Join-Path $Root 'yargen_rules.yar' }

$Failures = 0
$Warnings = 0

function Invoke-Native {
    param([string] $Exe, [string[]] $NativeArgs)
    # PS 5.1 does not raise on a non-zero native exit code, so capture both
    # streams and let the caller decide.
    $out = & $Exe @NativeArgs 2>&1
    return [pscustomobject]@{
        ExitCode = $LASTEXITCODE
        Output   = ($out | Out-String)
    }
}

function Get-DatabaseDigest {
    <#
      SHA-256 of a gzipped shard's decompressed content, or $null if it will not
      open. Hashing the compressed file would miss the duplicate case entirely,
      because a re-download that happens to compress differently is still the
      same database.
    #>
    param([string] $Path)
    if (-not $Path -or -not (Test-Path $Path)) { return $null }
    try {
        $fs  = [System.IO.File]::OpenRead($Path)
        $gz  = New-Object System.IO.Compression.GZipStream($fs, [System.IO.Compression.CompressionMode]::Decompress)
        $sha = [System.Security.Cryptography.SHA256]::Create()
        try {
            $hash = $sha.ComputeHash($gz)
            return [System.BitConverter]::ToString($hash).Replace('-','')
        } finally { $sha.Dispose(); $gz.Dispose(); $fs.Dispose() }
    } catch {
        # A shard that will not decompress is a problem Test-Databases reports in
        # its own terms; here it just means "no digest".
        if ($fs) { $fs.Dispose() }
        return $null
    }
}

function Get-DatabaseInventory {
    <#
      Reads `yargen-util list`, whose columns are
          NAME  TYPE  IDENTIFIER  ENTRIES
      and returns one object per database.
    #>
    if (-not (Test-Path $DbDir)) { return @() }
    $r = Invoke-Native $YargenUtil @('list', '-dbs-dir', $DbDir)
    if ($r.ExitCode -ne 0) { return @() }

    $rows = @()
    foreach ($line in ($r.Output -split "`r?`n")) {
        $t = $line.Trim()
        if (-not $t) { continue }
        if ($t -match '^-{3,}$') { continue }
        if ($t -match '^NAME\s+TYPE') { continue }
        $f = $t -split '\s+'
        if ($f.Count -lt 4) { continue }
        $entries = 0
        if (-not [int]::TryParse($f[-1], [ref] $entries)) { continue }
        $path = Join-Path $DbDir $f[0]
        $rows += [pscustomobject]@{
            File    = $f[0]
            Type    = $f[1]
            Entries = $entries
            Size    = if (Test-Path $path) { (Get-Item $path).Length } else { 0 }
            # Hash of the DECOMPRESSED bytes, not the file. The shards are gzipped,
            # so two different downloads can differ in bytes and still be the same
            # database - and that is exactly the case worth catching.
            Digest  = Get-DatabaseDigest $path
        }
    }
    return $rows
}

function Test-Databases {
    param([string] $Phase)

    if (-not (Test-Path $DbDir)) {
        Add-Result "databases ($Phase)" 'fail' "dbs/ is missing - run without -NoRun first"
        $script:Failures++
        return
    }

    $rows = Get-DatabaseInventory
    if (-not $rows -or $rows.Count -eq 0) {
        Add-Result "databases ($Phase)" 'fail' "dbs/ has no readable databases"
        $script:Failures++
        return
    }

    $total = ($rows | Measure-Object -Property Entries -Sum).Sum
    $empty = @($rows | Where-Object { $_.Entries -eq 0 })
    $tiny  = @($rows | Where-Object { $_.Entries -gt 0 -and $_.Entries -lt 100 })

    # Identical content under two names. The corpus reads as larger than it is:
    # `yargen-util list` counts every shard's entries, so four duplicate shards
    # inflate the total by their full size while adding nothing to what yarGen
    # can match against. Worth saying out loud, because the entry count is
    # otherwise the number an operator would trust.
    $dupes = @()
    $hashed = @($rows | Where-Object { $_.Digest })
    foreach ($grp in ($hashed | Group-Object Digest | Where-Object { $_.Count -gt 1 })) {
        $dupes += (($grp.Group.File) -join ' = ')
    }

    $detail = (Fmt-Num $rows.Count) + ' files, ' + (Fmt-Num $total) + ' entries'
    if ($empty.Count -gt 0 -or $tiny.Count -gt 0) {
        $detail += "; $($empty.Count) empty ($(@($empty.File) -join ', '))"
        if ($tiny.Count) { $detail += "; $($tiny.Count) near-empty ($(@($tiny.File) -join ', '))" }
    }
    if ($dupes.Count -gt 0) {
        $detail += "; $($dupes.Count) duplicated ($($dupes -join '; '))"
    }
    if ($detail -ne ((Fmt-Num $rows.Count) + ' files, ' + (Fmt-Num $total) + ' entries')) {
        Add-Result "databases ($Phase)" 'warn' $detail
        $script:Warnings++
    } else {
        Add-Result "databases ($Phase)" 'ok' $detail
    }

    foreach ($type in ($rows.Type | Sort-Object -Unique)) {
        $n = ($rows | Where-Object { $_.Type -eq $type } | Measure-Object -Property Entries -Sum).Sum
        Add-Result "  $type corpus" 'ok' ((Fmt-Num $n) + ' entries')
    }
}

try {

# --------------------------------------------------------------------------
Step 'preflight: binaries'
# --------------------------------------------------------------------------

foreach ($pair in @(@{ n = 'yargen.exe'; p = $Yargen; a = @('-version') }, @{ n = 'yargen-util.exe'; p = $YargenUtil; a = @('version') })) {
    if (Test-Path $pair.p) {
        $v = Invoke-Native $pair.p $pair.a
        if ($v.ExitCode -eq 0) {
            Add-Result $pair.n 'ok' ((Fmt-Num (Get-Item $pair.p).Length) + ' bytes, ' + ($v.Output.Trim() -split "`r?`n")[0])
        } else {
            Add-Result $pair.n 'fail' "present but `version` exited $($v.ExitCode)"
            $script:Failures++
        }
    } else {
        Add-Result $pair.n 'fail' "missing at $($pair.p)"
        $script:Failures++
    }
}

$go = Get-Command go -ErrorAction SilentlyContinue
if ($go) {
    $gv = (Invoke-Native $go.Source @('version')).Output.Trim()
    Add-Result 'go toolchain' 'ok' ($gv -replace '\s+', ' ')
} else {
    # Not required: the prebuilt binaries are what this script runs.
    Add-Result 'go toolchain' 'warn' 'not on PATH; only needed to rebuild the binaries'
    $script:Warnings++
}

# --------------------------------------------------------------------------
Step 'preflight: config'
# --------------------------------------------------------------------------

if (Test-Path $Config) {
    Add-Result 'config' 'ok' $Config.Replace($Root, '.')
    try {
        $cfg = Get-Content $Config -Raw
        $provider = if ($cfg -match '(?m)^\s*provider:\s*"([^"]+)"') { $Matches[1] } else { '' }
        if ($provider) { Add-Result '  llm provider' 'ok' $provider }

        # A non-ollama provider needs a key; without one string selection fails
        # at request time, long after the databases are loaded.
        if ($provider -and $provider -ne 'ollama') {
            $keyEnv = if ($cfg -match 'api_key:\s*"\$\{(\w+)\}"') { $Matches[1] } else { '' }
            if ($NoLlm) {
                Add-Result '  llm api key' 'skip' '-NoLlm: key not needed'
            } elseif ($keyEnv -and (Test-Path "Env:$keyEnv") -and (Get-Item "Env:$keyEnv").Value) {
                Add-Result '  llm api key' 'ok' "$keyEnv is set"
            } elseif ($keyEnv) {
                Add-Result '  llm api key' 'fail' "$keyEnv is not set and the provider is $provider"
                $script:Failures++
            }
        }
    } catch {
        Add-Result 'config parse' 'warn' $_.Exception.Message
        $script:Warnings++
    }
} else {
    if (Test-Path $ExampleCfg) {
        Add-Result 'config' 'warn' "missing at $(Split-Path -Leaf $Config); copy config.example.yml to config.yaml"
    } else {
        Add-Result 'config' 'fail' "missing at $Config and no example to copy from"
        $script:Failures++
    }
}

# --------------------------------------------------------------------------
Step 'preflight: databases'
# --------------------------------------------------------------------------

Test-Databases -Phase 'before'

# --------------------------------------------------------------------------
Step 'preflight: input'
# --------------------------------------------------------------------------

$haveInput = $false
if ($Sample) {
    if (Test-Path $Sample) {
        $item = Get-Item $Sample
        Add-Result 'sample' 'ok' ($item.Name + " (" + (Fmt-Num $item.Length) + " bytes)")
        $haveInput = $true
    } else {
        Add-Result 'sample' 'fail' "not found: $Sample"
        $script:Failures++
    }
}
if ($Directory) {
    if (Test-Path $Directory -PathType Container) {
        $n = @(Get-ChildItem $Directory -File -Recurse -ErrorAction SilentlyContinue).Count
        Add-Result 'directory' 'ok' "$Directory ($n files)"
        $haveInput = $true
    } else {
        Add-Result 'directory' 'fail' "not a directory: $Directory"
        $script:Failures++
    }
}
if (-not $haveInput) {
    if ($UpdateOnly) {
        # Checked before -NoRun because -UpdateOnly sets $NoRun itself further
        # down; testing it the other way round reports every update as a plain
        # no-run check and hides that the databases were being refreshed.
        Add-Result 'input' 'skip' '-UpdateOnly; no sample is needed'
    } elseif ($NoRun) {
        Add-Result 'input' 'skip' 'no -Sample/-Directory; -NoRun will not invoke yargen'
    } else {
        Add-Result 'input' 'fail' 'pass -Sample <file> or -Directory <dir>, or use -NoRun to check only'
        $script:Failures++
    }
}

$outDir = Split-Path -Parent $Output
if (-not (Test-Path $outDir)) { $null = New-Item -ItemType Directory -Path $outDir -Force }
try {
    $probe = Join-Path $outDir ('.write-probe-' + [guid]::NewGuid().ToString('N'))
    Set-Content -Path $probe -Value 'x' -Encoding UTF8
    Remove-Item $probe -Force
    Add-Result 'output writable' 'ok' $Output.Replace($Root, '.')
} catch {
    Add-Result 'output writable' 'fail' $_.Exception.Message
    $script:Failures++
}

# --------------------------------------------------------------------------
# Gate: nothing expensive runs on a broken environment.
# --------------------------------------------------------------------------

if ($script:Failures -gt 0 -and -not $Force) {
    Write-Host ''
    Write-Host "Preflight failed ($script:Failures problem(s)). Re-run with -Force to continue anyway." -ForegroundColor Red
    exit 1
}

if ($UpdateOnly) {
    # Implies NoRun, but NOT the other way round, and that ordering matters:
    # $NoRun short-circuits everything below, so it is set here, after the
    # database update has been arranged, never by the update step itself.
    $NoRun = $true
}

# --------------------------------------------------------------------------
Step 'update databases'
# --------------------------------------------------------------------------
#
# Deliberately outside the -NoRun branch. It was inside it, which meant the two
# switches had no usable combination: -NoRun skipped the update, and running
# without it demanded a sample to generate rules from. A button whose only job is
# "download the databases and re-check" therefore had no invocation - it either
# failed demanding input it did not want, or passed having downloaded nothing.
# Both look like success in a job list.

if ($SkipUpdate) {
    Add-Result 'yargen-util update' 'skip' '-SkipUpdate'
} else {
    Write-Host "  downloading built-in databases into $DbDir ..." -ForegroundColor DarkGray
    $u = Invoke-Native $YargenUtil @('update', '-dbs-dir', $DbDir)
    $u.Output.Trim() -split "`r?`n" | Where-Object { $_ } | Select-Object -Last 8 |
        ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }
    if ($u.ExitCode -eq 0) {
        Add-Result 'yargen-util update' 'ok' 'exit 0'
    } else {
        Add-Result 'yargen-util update' 'fail' "exit $($u.ExitCode)"
        $script:Failures++
        Write-Host ''
        Write-Host 'Database update failed; not running yargen against a stale catalog.' -ForegroundColor Red
        exit 1
    }

    Test-Databases -Phase 'after'
}

# --------------------------------------------------------------------------
Step 'run yargen'
# --------------------------------------------------------------------------

if ($NoRun) {
    # The databases are refreshed above and the checks have run; there is simply
    # no sample to generate rules from, which is the whole of -NoRun and -UpdateOnly.
    Write-Host ''
    if ($UpdateOnly) {
        Write-Host '-UpdateOnly: databases updated, prerequisites re-checked, stopping before yargen.' -ForegroundColor Yellow
    } else {
        Write-Host '-NoRun: stopping after the checks.' -ForegroundColor Yellow
    }
} else {

$yargenArgs = @('-config', $Config, '-o', $Output)
if ($NoLlm)    { $yargenArgs += '-no-llm' }
if ($Sample)   { $yargenArgs += @('-f', $Sample) }
if ($Directory){ $yargenArgs += @('-m', $Directory) }

Write-Host "  yargen $($yargenArgs -join ' ')" -ForegroundColor DarkGray
$run = Invoke-Native $Yargen $yargenArgs
$run.Output.Trim() -split "`r?`n" | Where-Object { $_ } |
    Select-Object -Last 25 | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }

if ($run.ExitCode -ne 0) {
    Add-Result 'yargen' 'fail' "exit $($run.ExitCode)"
    $script:Failures++
} elseif (Test-Path $Output) {
    $ruleCount = @(Select-String -Path $Output -Pattern '^\s*rule\s+' -ErrorAction SilentlyContinue).Count
    Add-Result 'yargen' 'ok' ("$(Split-Path -Leaf $Output) ($(Fmt-Num (Get-Item $Output).Length) bytes, $ruleCount rules)")
} else {
    Add-Result 'yargen' 'warn' 'exit 0 but no output file was written'
    $script:Warnings++
}

}

# --------------------------------------------------------------------------
Step 'summary'
# --------------------------------------------------------------------------

$script:Results | Format-Table -AutoSize | Out-String -Width 200 | Write-Host

Write-Host ("  {0} failed, {1} warnings" -f $script:Failures, $script:Warnings)
if ($script:Failures -gt 0) { Write-Host "`nRESULT: FAILED" -ForegroundColor Red; exit 1 }
if ($script:Warnings -gt 0 -and -not $Force) { Write-Host "`nRESULT: OK (with warnings)" -ForegroundColor Yellow; exit 0 }
Write-Host "`nRESULT: OK" -ForegroundColor Green
exit 0

} finally {
    Pop-Location
}