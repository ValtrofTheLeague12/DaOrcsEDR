[CmdletBinding()]
param(
    [switch]$Clean,
    [switch]$SkipTests,
    [string]$InputFile
)

$ErrorActionPreference = 'Stop'

$env:PATH = "C:\msys64\ucrt64\bin;$env:PATH"
$env:STATIC_ANALYZER_CURSES = "1"

Set-Location -LiteralPath $PSScriptRoot

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
        Write-Host "command failed (exit $code): $display" -ForegroundColor Red
        throw "Command failed with exit code $code`: $display"
    }
}

if ($Clean -and (Test-Path -LiteralPath 'build-ucrt')) {
    Write-Host 'Removing build-ucrt...' -ForegroundColor Yellow
    Remove-Item -LiteralPath 'build-ucrt' -Recurse -Force
}

Invoke-Checked 'cmake' '--preset' 'ucrt64'
Invoke-Checked 'cmake' '--build' '--preset' 'ucrt64-release'

if (-not $SkipTests) {
    Invoke-Checked 'ctest' '--preset' 'ucrt64-tests' '--output-on-failure'
}

$Analyzer = Join-Path $PSScriptRoot 'build-ucrt\static_analyzer.exe'

if (-not (Test-Path -LiteralPath $Analyzer)) {
    throw "Analyzer not found at '$Analyzer' (build may have failed)"
}

if ($InputFile) {
    if (-not (Test-Path -LiteralPath $InputFile)) {
        throw "Input file '$InputFile' does not exist"
    }
    $ResolvedInput = (Resolve-Path -LiteralPath $InputFile).Path
    Write-Host "Analyzing: $ResolvedInput" -ForegroundColor Cyan
    Invoke-Checked $Analyzer $ResolvedInput
} else {
    Write-Host "Analyzing (default): $Analyzer" -ForegroundColor Cyan
    Invoke-Checked $Analyzer $Analyzer
}

Write-Host "Executable: $Analyzer" -ForegroundColor Green
Write-Host 'Build completed successfully.' -ForegroundColor Green