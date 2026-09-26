$ErrorActionPreference = 'Stop'
$root = 'c:/Users/The4thReich/Desktop/IAProject'
Set-Location $root

function Get-Body([string]$path, [string]$openPat, [string]$closePat) {
    $L = Get-Content $path
    $o = -1
    for ($i = 0; $i -lt $L.Count; $i++) { if ($L[$i] -match $openPat) { $o = $i; break } }
    if ($o -lt 0) { throw "open pattern not found in $path" }
    $c = -1
    for ($i = $L.Count - 1; $i -ge 0; $i--) { if ($L[$i] -match $closePat) { $c = $i; break } }
    if ($c -lt $o) { throw "close pattern not found in $path" }
    if ($c -eq ($o + 1)) { return ,@() }
    return ,@($L[($o + 1)..($c - 1)])
}

# ---------------------------------------------------------------------------
# 1. Extract bodies (content strictly inside `namespace cti { ... }`)
# ---------------------------------------------------------------------------
$baseBody = Get-Body 'include/cti_base.hpp'      '^namespace cti \{' '^\}'
$netBody  = Get-Body 'include/cti_net.hpp'       '^namespace cti \{' '^\}'
$pipeBody = Get-Body 'include/cti_pipeline.hpp'  '^namespace cti \{' '^\}'
$expBody  = Get-Body 'include/cti_export.hpp'    '^namespace cti \{' '^\}'

$httpCpp  = Get-Body 'src/http_client.cpp'       '^namespace cti \{' '^\}'
$baseCpp  = Get-Body 'src/cti_base.cpp'          '^namespace cti \{' '^\}'
$netCpp   = Get-Body 'src/cti_net.cpp'           '^namespace cti \{' '^\}'
$pipeCpp  = Get-Body 'src/cti_pipeline.cpp'      '^namespace cti \{' '^\}'
$expCpp   = Get-Body 'src/cti_export.cpp'        '^namespace cti \{' '^\}'

# ---------------------------------------------------------------------------
# 2. Strip the duplicate anonymous `add_unique` from the pipeline body
#    (cti_net.cpp defines an identical one; one definition is enough once
#     everything lives in the same TU / anonymous namespace)
# ---------------------------------------------------------------------------
if (($netCpp -join "`n") -notmatch 'void add_unique\(') { throw "expected add_unique in cti_net.cpp" }
$pipeJoined = $pipeCpp -join "`n"
$auPat = 'void add_unique\(std::vector<std::string>& list, const std::string& value\) \{\r?\n[^\S\r\n]*if \([^\r\n]*\r?\n\}\r?\n\r?\n'
$pipeJoined2 = $pipeJoined -replace $auPat, ''
if ($pipeJoined2 -eq $pipeJoined) {
    $auPat2 = '(?s)void add_unique\(std::vector<std::string>& list, const std::string& value\) \{.*?\n\}\r?\n\r?\n'
    $pipeJoined2 = $pipeJoined -replace $auPat2, ''
}
if ($pipeJoined2 -match 'void add_unique\(') { throw 'failed to strip duplicate add_unique from pipeline body' }
$pipeCpp = $pipeJoined2 -split "`r?`n"

# ---------------------------------------------------------------------------
# 3. Assemble the merged HEADER  ->  include/cti.hpp
# ---------------------------------------------------------------------------
$hdr = @(
    '#pragma once'
    ''
    '// ============================================================================'
    '// cti.hpp - the complete CTI subsystem in ONE header + ONE source (cti.cpp).'
    '//'
    '// Merged from the former split files:'
    '//   cti_base.hpp     - model, string/ip/time helpers, rate limiter, file cache,'
    '//                      api keys / endpoints / config, and the HTTP layer'
    '//   http_client.hpp  - folded into the HTTP layer above (single copy now)'
    '//   cti_net.hpp      - ATT&CK + KEV knowledge bases, provider interface and'
    '//                      the built-in registry (make_default_providers)'
    '//   cti_pipeline.hpp - enrichment pipeline, progress, report, collect_from_*'
    '//   cti_export.hpp   - JSON / STIX 2.1 / console summary export'
    '//'
    '// Layout (single `namespace cti`):'
    '//   1. model          artifact / finding / enrichment / verdict'
    '//   2. http layer     http_client interface + make_curl_client (curl)'
    '//   3. helpers        string / ip / time utilities, rate_limiter, file_cache'
    '//   4. config         api_keys / endpoints / config (env + JSON overrides)'
    '//   5. knowledge      attack_db / kev_db / provider registry'
    '//   6. pipeline       enrichment pipeline + collect_from_* entry points'
    '//   7. export         JSON / STIX 2.1 / print_summary'
    '//'
    '// NOTE: the old prototype lookup API (ioc_entry / check_iocs / cti_result)'
    '// was dropped - it had no implementation and no callers anywhere. Use the'
    '// pipeline API (cti::pipeline + collect_from_*) instead.'
    '// ============================================================================'
    ''
    '#include <atomic>'
    '#include <chrono>'
    '#include <cstddef>'
    '#include <cstdint>'
    '#include <filesystem>'
    '#include <functional>'
    '#include <iosfwd>'
    '#include <map>'
    '#include <memory>'
    '#include <mutex>'
    '#include <optional>'
    '#include <set>'
    '#include <string>'
    '#include <string_view>'
    '#include <unordered_map>'
    '#include <utility>'
    '#include <vector>'
    ''
    '#include <nlohmann/json.hpp>'
    ''
    '#include "extractor.hpp"'
    '#include "ioc_extractor.hpp"'
    ''
    'namespace cti {'
)
$hdr += $baseBody
$hdr += ''
$hdr += '// ---------------------------------------------------------------------------'
$hdr += '// providers and knowledge bases (former cti_net.hpp)'
$hdr += '// ---------------------------------------------------------------------------'
$hdr += ''
$hdr += $netBody
$hdr += ''
$hdr += '// ---------------------------------------------------------------------------'
$hdr += '// pipeline (former cti_pipeline.hpp)'
$hdr += '// ---------------------------------------------------------------------------'
$hdr += ''
$hdr += $pipeBody
$hdr += ''
$hdr += '// ---------------------------------------------------------------------------'
$hdr += '// export (former cti_export.hpp)'
$hdr += '// ---------------------------------------------------------------------------'
$hdr += ''
$hdr += $expBody
$hdr += ''
$hdr += '}  // namespace cti'

# ---------------------------------------------------------------------------
# 4. Assemble the merged SOURCE  ->  src/cti.cpp
# ---------------------------------------------------------------------------
$cpp = @(
    '// ============================================================================'
    '// cti.cpp - implementation of the entire CTI subsystem (merged from'
    '//   http_client.cpp, cti_base.cpp, cti_net.cpp, cti_pipeline.cpp, cti_export.cpp).'
    '// Order matters: HTTP layer first, then base helpers, then providers,'
    '// then pipeline, then export.'
    '// ============================================================================'
    '#include "cti.hpp"'
    ''
    '#include <algorithm>'
    '#include <array>'
    '#include <atomic>'
    '#include <cctype>'
    '#include <chrono>'
    '#include <cmath>'
    '#include <cstdio>'
    '#include <cstdlib>'
    '#include <ctime>'
    '#include <filesystem>'
    '#include <fstream>'
    '#include <iomanip>'
    '#include <iostream>'
    '#include <iterator>'
    '#include <memory>'
    '#include <mutex>'
    '#include <set>'
    '#include <sstream>'
    '#include <thread>'
    '#include <unordered_map>'
    '#include <unordered_set>'
    ''
    '#include <curl/curl.h>'
    ''
    'namespace cti {'
    ''
    '// ---------------------------------------------------------------------------'
    '// HTTP transport (former http_client.cpp)'
    '// ---------------------------------------------------------------------------'
)
$cpp += $httpCpp
$cpp += ''
$cpp += '// ---------------------------------------------------------------------------'
$cpp += '// core: model, helpers, config, cache (former cti_base.cpp)'
$cpp += '// ---------------------------------------------------------------------------'
$cpp += ''
$cpp += $baseCpp
$cpp += ''
$cpp += '// ---------------------------------------------------------------------------'
$cpp += '// providers + ATT&CK/KEV knowledge (former cti_net.cpp)'
$cpp += '// ---------------------------------------------------------------------------'
$cpp += ''
$cpp += $netCpp
$cpp += ''
$cpp += '// ---------------------------------------------------------------------------'
$cpp += '// pipeline (former cti_pipeline.cpp)'
$cpp += '// ---------------------------------------------------------------------------'
$cpp += ''
$cpp += $pipeCpp
$cpp += ''
$cpp += '// ---------------------------------------------------------------------------'
$cpp += '// export: JSON / STIX / summary (former cti_export.cpp)'
$cpp += '// ---------------------------------------------------------------------------'
$cpp += ''
$cpp += $expCpp
$cpp += ''
$cpp += '}  // namespace cti'

# ---------------------------------------------------------------------------
# 5. Sanity checks before writing
# ---------------------------------------------------------------------------
$hdrText = $hdr -join "`r`n"
$cppText = $cpp -join "`r`n"

if ([regex]::Matches($hdrText, 'struct http_request \{').Count -ne 1) { throw 'header must contain exactly one http_request' }
if ([regex]::Matches($hdrText, 'struct http_options \{').Count -ne 1)  { throw 'header must contain exactly one http_options' }
if ($hdrText -notmatch 'make_curl_client')                              { throw 'header missing make_curl_client' }
if ($hdrText -notmatch 'class pipeline')                                { throw 'header missing pipeline' }
if ($hdrText -notmatch 'to_stix_bundle')                                { throw 'header missing to_stix_bundle' }
if ([regex]::Matches($cppText, 'void add_unique\(').Count -ne 1)        { throw 'cpp must contain exactly one add_unique' }
if ($cppText -notmatch 'make_curl_client\(const http_options& options\)') { throw 'cpp missing make_curl_client definition' }
if ($cppText -notmatch 'pipeline::run\(')                               { throw 'cpp missing pipeline::run definition' }
if ($hdr.Count -lt 500)  { throw "header suspiciously small ($($hdr.Count) lines)" }
if ($cpp.Count -lt 2500) { throw "cpp suspiciously small ($($cpp.Count) lines)" }

Write-Host "header lines: $($hdr.Count)   cpp lines: $($cpp.Count)"

# ---------------------------------------------------------------------------
# 6. Back up originals, write merged files, delete the old ones
# ---------------------------------------------------------------------------
New-Item -ItemType Directory -Force '_cti_backup' | Out-Null
$oldFiles = @(
    'include/cti.hpp', 'include/cti_base.hpp', 'include/cti_net.hpp',
    'include/cti_pipeline.hpp', 'include/cti_export.hpp', 'include/http_client.hpp',
    'src/cti.cpp', 'src/cti_base.cpp', 'src/cti_net.cpp',
    'src/cti_pipeline.cpp', 'src/cti_export.cpp', 'src/http_client.cpp'
)
foreach ($f in $oldFiles) {
    if (Test-Path $f) { Copy-Item $f ("_cti_backup/" + [IO.Path]::GetFileName($f)) -Force }
}

$hdr | Set-Content 'include/cti.hpp' -Encoding UTF8
$cpp  | Set-Content 'src/cti.cpp'     -Encoding UTF8

foreach ($f in $oldFiles) {
    if ($f -ne 'include/cti.hpp' -and $f -ne 'src/cti.cpp') {
        if (Test-Path $f) { Remove-Item $f -Force }
    }
}

# ---------------------------------------------------------------------------
# 7. Patch the only includer: local_api.hpp -> "cti.hpp"
# ---------------------------------------------------------------------------
$laPath = Join-Path $root 'include/local_api.hpp'
$laRaw  = [IO.File]::ReadAllText($laPath)
$laNew  = $laRaw.Replace('#include "cti_base.hpp"', '#include "cti.hpp"')
if ($laNew -eq $laRaw) { throw 'local_api.hpp include not patched (pattern not found)' }
[IO.File]::WriteAllText($laPath, $laNew)

Write-Host 'MERGE OK'
Get-ChildItem include/cti*.hpp, include/http_client.hpp, src/cti*.cpp, src/http_client.cpp -ErrorAction SilentlyContinue |
    Select-Object Name, Length | Format-Table -AutoSize | Out-String | Write-Host


