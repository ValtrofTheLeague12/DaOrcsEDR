# Real-PE round-trip check for sample_archive (complements selftest.ps1).
param([string]$Exe = (Join-Path $PSScriptRoot "..\..\build-ucrt\sample_archive.exe"),
      [string]$PE = (Join-Path $PSScriptRoot "..\..\tests\fixtures\suspicious_sample.exe"))
$resolved = (Resolve-Path -LiteralPath $Exe -ErrorAction SilentlyContinue)
if (-not $resolved) { Write-Host "FATAL: exe not built"; exit 1 }
$Exe = $resolved.ProviderPath
$PE = (Resolve-Path -LiteralPath $PE).Path

$T = Join-Path $env:TEMP "sa_pe"
Remove-Item $T -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $T | Out-Null
$z = Join-Path $T "s.zst"; $b = Join-Path $T "s.exe"

& $Exe compress $PE $z
if ($LASTEXITCODE -ne 0) { Write-Host "FAIL compress"; exit 1 }
& $Exe decompress $z $b
if ($LASTEXITCODE -ne 0) { Write-Host "FAIL decompress"; exit 1 }
$h1 = (Get-FileHash -Algorithm SHA256 $PE).Hash
$h2 = (Get-FileHash -Algorithm SHA256 $b).Hash
if ($h1 -ne $h2) { Write-Host "FAIL hash mismatch"; exit 1 }
Write-Host "PASS  PE SHA256 identical ($h1)"
$in = (Get-Item $PE).Length; $out = (Get-Item $z).Length
Write-Host ("PASS  {0} -> {1} ({2:P1} of original)" -f $in, $out, ($out / $in))

& $Exe info $z
if ($LASTEXITCODE -ne 0) { Write-Host "FAIL info"; exit 1 }
Write-Host "PASS  info exit 0"

Write-Host "-- verbose sample (first 5 stderr lines) --"
$e = Join-Path $T "v.err"
& $Exe --verbose compress $PE (Join-Path $T "v.zst") 2> $e
Get-Content $e | Select-Object -First 5
Remove-Item $T -Recurse -Force
Write-Host "ALL PASS"
exit 0
