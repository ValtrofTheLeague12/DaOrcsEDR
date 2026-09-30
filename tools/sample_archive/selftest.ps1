# Self-test for sample_archive: round-trips, corruption/truncation rejection,
# exit-code contract, and the --verbose logging stream.
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File tools\sample_archive\selftest.ps1
#
# Exit 0 = all checks passed, 1 = at least one failure (artifacts kept in %TEMP%\sa_selftest).
param([string]$Exe = (Join-Path $PSScriptRoot "..\..\build-ucrt\sample_archive.exe"))

$fail = 0
function Check([string]$n, [bool]$c, [string]$d = "") {
    if ($c) { Write-Host "  PASS  $n" } else { Write-Host "  FAIL  $n  $d"; $script:fail++ }
}
$resolved = (Resolve-Path -LiteralPath $Exe -ErrorAction SilentlyContinue)
if (-not $resolved) { Write-Host "FATAL: sample_archive.exe not built (cmake --build build-ucrt)"; exit 1 }
$Exe = $resolved.ProviderPath

$T = Join-Path $env:TEMP "sa_selftest"
Remove-Item $T -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $T | Out-Null

function Invoke-SA([string[]]$a, [string]$tag) {
    $so = Join-Path $T "$tag.out"; $se = Join-Path $T "$tag.err"
    $p = Start-Process -FilePath $Exe -ArgumentList $a -NoNewWindow -Wait -PassThru `
         -RedirectStandardOutput $so -RedirectStandardError $se
    [pscustomobject]@{
        Exit = $p.ExitCode
        Out  = [string](Get-Content $so -Raw -ErrorAction SilentlyContinue)
        Err  = [string](Get-Content $se -Raw -ErrorAction SilentlyContinue)
    }
}
function ErrLines([string]$e) { @($e -split "`r?`n" | Where-Object { $_ -ne "" }).Count }

$sha = { param($f) (Get-FileHash -Algorithm SHA256 $f).Hash }

# Inputs: a compressible payload (text) and a zero-byte file.
$src = Join-Path $T "payload.bin"
$text = (1..4000 | ForEach-Object { "line $_ sample payload for compression testing" }) -join "`n"
[System.IO.File]::WriteAllText($src, $text)
$srcHash = & $sha $src
$empty = Join-Path $T "empty.bin"; [System.IO.File]::WriteAllBytes($empty, [byte[]]@())
$zst = Join-Path $T "payload.zst"

Write-Host "1) round-trip"
$r = Invoke-SA @("compress", $src, $zst) "c1"
Check "compress exit 0" ($r.Exit -eq 0) "exit=$($r.Exit) err=$($r.Err)"
Check "compressed smaller" ((Test-Path $zst) -and ((Get-Item $zst).Length -lt (Get-Item $src).Length))
$back = Join-Path $T "back.bin"
$r = Invoke-SA @("decompress", $zst, $back) "d1"
Check "decompress exit 0" ($r.Exit -eq 0) "err=$($r.Err)"
Check "SHA256 identical" ((& $sha $back) -eq $srcHash)

Write-Host "2) defaults and empty input"
$r = Invoke-SA @("compress", $empty) "c2"
Check "empty -> .zst exit 0" ($r.Exit -eq 0 -and (Test-Path "$empty.zst")) "exit=$($r.Exit)"
$r = Invoke-SA @("decompress", "$empty.zst", (Join-Path $T "empty.out")) "d4"
Check "empty round-trip exit 0" ($r.Exit -eq 0 -and (Get-Item (Join-Path $T "empty.out")).Length -eq 0)

Write-Host "3) info"
$r = Invoke-SA @("info", $zst) "i1"
Check "info exit 0" ($r.Exit -eq 0) "err=$($r.Err)"
Check "frames: 1" ($r.Out -match "frames:\s+1")
Check "quiet: stderr empty" ([string]::IsNullOrWhiteSpace($r.Err))

Write-Host "4) corruption (checksum trailer bit-flip)"
$bad = Join-Path $T "bad.zst"
$b = [System.IO.File]::ReadAllBytes($zst)
$b[$b.Length - 1] = [byte]($b[$b.Length - 1] -bxor 1)
[System.IO.File]::WriteAllBytes($bad, $b)
$r = Invoke-SA @("decompress", $bad, (Join-Path $T "bad.out")) "d2"
Check "exit 1" ($r.Exit -eq 1) "exit=$($r.Exit)"
Check "checksum message" ($r.Err -match "checksum") "err=$($r.Err)"
Check "exactly one error line" ((ErrLines $r.Err) -eq 1) "err=$($r.Err)"
Check "no output left" (-not (Test-Path (Join-Path $T "bad.out")))
Check "no .partial left" (-not (Test-Path (Join-Path $T "bad.out.partial")))

Write-Host "5) truncation (half file)"
$tr = Join-Path $T "trunc.zst"
$all = [System.IO.File]::ReadAllBytes($zst)
$half = [byte[]]($all[0..([int]($all.Length / 2) - 1)])
[System.IO.File]::WriteAllBytes($tr, $half)
$r = Invoke-SA @("decompress", $tr, (Join-Path $T "tr.out")) "d3"
Check "exit 1" ($r.Exit -eq 1) "exit=$($r.Exit)"
Check "truncated-input message" ($r.Err -match "truncated input") "err=$($r.Err)"
Check "no output left" (-not (Test-Path (Join-Path $T "tr.out")))
Check "no .partial left" (-not (Test-Path (Join-Path $T "tr.out.partial")))

Write-Host "6) verbose logging (--verbose)"
$vsrc = Join-Path $T "v.bin"
[System.IO.File]::WriteAllText($vsrc, $text)
$r = Invoke-SA @("--verbose", "compress", $vsrc, (Join-Path $T "v.zst")) "v1"
Check "verbose compress exit 0" ($r.Exit -eq 0) "exit=$($r.Exit)"
Check "stderr has [INFO]" ($r.Err -match "\[INFO\]") "err=$($r.Err)"
Check "stderr has [DEBUG]" ($r.Err -match "\[DEBUG\]") "err=$($r.Err)"
Check "timestamped HH:MM:SS" ($r.Err -match "^\[\d{2}:\d{2}:\d{2}\]") "err=$($r.Err)"
Check "stdout keeps the machine-readable report" ($r.Out -match "\[\+\] compressed to" -and $r.Out -notmatch "\[INFO\]")
$r = Invoke-SA @("compress", $vsrc, (Join-Path $T "n.zst")) "n1"
Check "quiet default: stderr empty" ([string]::IsNullOrWhiteSpace($r.Err)) "err=$($r.Err)"
$r = Invoke-SA @("--verbose", "decompress", $tr, (Join-Path $T "v2.restored")) "v2"
Check "verbose failure still logs the error line" ($r.Exit -eq 1 -and $r.Err -match "error: decompress failed: truncated input") "exit=$($r.Exit) err=$($r.Err)"

Write-Host "7) CLI contract"
$r = Invoke-SA @("--help") "h"
Check "--help exit 0" ($r.Exit -eq 0) "exit=$($r.Exit)"
Check "usage on stdout" ($r.Out -match "usage:")
$r = Invoke-SA @("frobnicate", $src) "u"
Check "unknown verb exit 2" ($r.Exit -eq 2) "exit=$($r.Exit)"
$r = Invoke-SA @("compress") "m"
Check "missing file arg exit 2" ($r.Exit -eq 2) "exit=$($r.Exit)"
$r = Invoke-SA @("compress", (Join-Path $T "nope.bin")) "x"
Check "missing input exit 1" ($r.Exit -eq 1) "exit=$($r.Exit)"
$r = Invoke-SA @("compress", $src, $zst) "o"
Check "refuse overwrite exit 1" ($r.Exit -eq 1) "exit=$($r.Exit)"
Check "overwrite message" ($r.Err -match "already exists") "err=$($r.Err)"

Write-Host ""
if ($fail -eq 0) {
    Write-Host "ALL PASS"
    Remove-Item $T -Recurse -Force -ErrorAction SilentlyContinue
    exit 0
}
Write-Host "$fail FAILURE(S) - artifacts kept in $T"
exit 1

