# COMMANDS.md

Every command you need to build, test and run this project, each one runnable on
its own. Nothing here is aspirational — each command was executed before being
written down, and the expected output is what it actually printed.

All commands assume the repository root as the working directory, in PowerShell.

---

## Prerequisites

One-time. The build needs an MSYS2 UCRT64 toolchain plus nine libraries from
its repository; four more have to be built by hand (see
[Dependencies](#dependencies-that-are-not-installed-by-pacman)).

```powershell
# Toolchain and the nine pacman-provided libraries.
& C:\msys64\usr\bin\pacman.exe -S --needed `
  mingw-w64-ucrt-x86_64-gcc mingw-w64-ucrt-x86_64-make `
  mingw-w64-ucrt-x86_64-yaml-cpp mingw-w64-ucrt-x86_64-capstone `
  mingw-w64-ucrt-x86_64-re2 mingw-w64-ucrt-x86_64-pdcurses `
  mingw-w64-ucrt-x86_64-openssl mingw-w64-ucrt-x86_64-curl `
  mingw-w64-ucrt-x86_64-nlohmann-json mingw-w64-ucrt-x86_64-zstd
```

Put the toolchain on PATH for the current shell. Every build command below
assumes this:

```powershell
$env:PATH = "C:\msys64\ucrt64\bin;$env:PATH"
```

Python dependencies:

```powershell
python\.venv\Scripts\python.exe -m pip install -r python\requirements.txt
python\.venv\Scripts\python.exe -m pip install pytest
```

---

## Build

```powershell
# Configure. Creates build-ucrt\ and caches the toolchain path.
cmake -S . -B build-ucrt

# Configure through the preset, which pins the MinGW compiler path explicitly.
# Use this on a fresh clone - it is what build.ps1 does.
cmake --preset ucrt64

# Build the analyzer.
cmake --build build-ucrt --target static_analyzer -j 4

# Everything, including the sample_archive tool.
cmake --build build-ucrt -j 4

# From scratch: wipe the build directory first.
cmake --build build-ucrt --target static_analyzer --clean-first -j 4
```

`build.ps1` wraps configure, build and a run in one step:

```powershell
.\build.ps1                       # configure, build, then analyze .\a.exe
.\build.ps1 -InputFile .\sample.exe
.\build.ps1 -InputFile .\sample.exe -Pipeline quick
.\build.ps1 -Clean                 # delete build-ucrt\ first
.\build.ps1 -NoRun                 # build only
.\build.ps1 -ListPipelines         # list the pipelines it can see
```

### Verify the build

```powershell
.\build-ucrt\static_analyzer.exe --version
```

Prints the version, the commit it was built from, the branch, and whether the
tree was dirty at build time.

---

## Test

Three tiers. `unit/README.md` explains which one a test belongs in.

### C++ unit — 65 tests, no framework

```powershell
cmake --build build-ucrt --target unit_tests -j 4

# Build and run one suite at a time.
cmake --build build-ucrt --target run_test_app_paths
cmake --build build-ucrt --target run_test_resume
cmake --build build-ucrt --target run_test_default_pipeline
cmake --build build-ucrt --target run_test_pipeline_planner

# Or run the binaries directly.
.\build-ucrt\test_app_paths.exe
.\build-ucrt\test_resume.exe
.\build-ucrt\test_default_pipeline.exe
.\build-ucrt\test_pipeline_planner.exe
```

Each prints `N passed, M failed` and exits non-zero on failure.

### Python unit — 96 tests

```powershell
python\.venv\Scripts\python.exe -m pytest unit\python -q
python\.venv\Scripts\python.exe -m pytest unit\python\test_panel_config.py -q
python\.venv\Scripts\python.exe -m pytest unit\python\test_panel_env_options.py -q
```

### Black-box — 39 tests

Needs the built analyzer and a fixture sample.

```powershell
python\.venv\Scripts\python.exe -m pytest tests -q
python\.venv\Scripts\python.exe -m pytest tests\test_server_queue.py -q
```

### Everything at once

```powershell
cmake --build build-ucrt --target unit_tests -j 4
python\.venv\Scripts\python.exe -m pytest unit\python -q
python\.venv\Scripts\python.exe -m pytest tests -q
```

---

## Run the analyzer

Always set `IA_ARTIFACT_UPLOAD=0` unless you *want* an encrypted evidence
bundle uploaded to a remote account. `config/artifacts.yaml` has
`upload_artifacts: true`, and two test runs during development uploaded to a
real MEGA account before this was noticed. The flag can only ever disable
uploading, never enable it.

```powershell
$env:IA_ARTIFACT_UPLOAD = "0"     # do this before anything that analyzes

# Analyze with the built-in default pipeline.
.\build-ucrt\static_analyzer.exe .\tests\fixtures\suspicious_sample.exe

# Choose a pipeline.
.\build-ucrt\static_analyzer.exe --pipeline quick .\sample.exe
.\build-ucrt\static_analyzer.exe --pipeline pipelines\default.yaml .\sample.exe

# Inline phase list, no file needed.
.\build-ucrt\static_analyzer.exe --pipeline '["strings","model"]' .\sample.exe

# Generate YARA rules from the sample (opt-in; slow, output unreviewed).
.\build-ucrt\static_analyzer.exe --pipeline '["strings","yara_gen"]' .\sample.exe
```

### Inspect what is available

```powershell
.\build-ucrt\static_analyzer.exe --list-phases
.\build-ucrt\static_analyzer.exe --list-phases --json
.\build-ucrt\static_analyzer.exe --list-pipelines
.\build-ucrt\static_analyzer.exe --help
```

### Resume an interrupted run

Ctrl+C stops at the next phase boundary and records how far it got.

```powershell
.\build-ucrt\static_analyzer.exe --resume .\sample.exe
.\build-ucrt\static_analyzer.exe --from radare2 .\sample.exe
```

The checkpoint lives at `logs/resume/<stem>.json`.

---

## Crash, dump and signal handling

```powershell
# Prove the crash handlers and report paths work. Dereferences null on purpose.
.\build-ucrt\static_analyzer.exe --crash-selftest .\sample.exe

# Show what a crash LOOKS like without faulting: banner, report, minidump.
.\build-ucrt\static_analyzer.exe --crash-demo .\sample.exe

# Keep a dump when the process dies.
#   POSIX   raises RLIMIT_CORE to its hard limit
#   Windows widens the minidump in logs\crash\ to the whole address space
.\build-ucrt\static_analyzer.exe --allow-core-dump .\sample.exe

# Carry on after SIGTERM / SIGHUP / SIGUSR1 / SIGUSR2.
.\build-ucrt\static_analyzer.exe --continue-on-signal .\sample.exe

# Prove the above actually continues. Requires --continue-on-signal.
# POSIX only; prints "not applicable" and exits 1 on a Windows build.
.\build-ucrt\static_analyzer.exe --continue-on-signal --signal-selftest .\sample.exe
```

Both flags are also settable from a pipeline's `environment:` block, which is
what the admin console writes:

```powershell
$env:IA_ALLOW_CORE_DUMP = "1"
$env:IA_CONTINUE_ON_SIGNAL = "1"
```

Outputs land in `%APPDATA%\IAProject\logs\crash\`.

**Fault signals always terminate**, whatever `--continue-on-signal` is set to.
`SIGSEGV`, `SIGBUS`, `SIGFPE`, `SIGILL` and `SIGABRT` re-execute the faulting
instruction if their handler returns, so continuing them faults again
immediately. `--continue-on-signal` is POSIX-only and says so on a Windows
build.

---

## Admin console (web)

```powershell
# Build the SPA, start the panel, open a browser.
.\admin-panel.ps1

# Vite dev server on :60101 with HMR, proxying /api to the panel.
.\admin-panel.ps1 -Dev

# Start without opening a browser.
.\admin-panel.ps1 -NoBrowser

# Rebuild the SPA before starting.
.\admin-panel.ps1 -Build

# Start the backend only, with no UI.
.\admin-panel.ps1 -NoUi

# Move the port.
.\admin-panel.ps1 -Port 60110
```

Binds loopback only, on `127.0.0.1:60100` by default. `ADMIN_PANEL_TOKEN` puts
a login in front of it; `ADMIN_WEB_PORT` moves the port.

### Frontend checks

```powershell
cd admin-web
npx tsc --noEmit        # typecheck
npx vite build          # production build
cd ..
```

---

## Python API server

```powershell
python\.venv\Scripts\python.exe server.py --help
python\.venv\Scripts\python.exe server.py --analyzer .\build-ucrt\static_analyzer.exe
```

Host and port come from `.env` (`SA_API_HOST`, `SA_API_PORT`) or the defaults.

---

## Python services, individually

Each is callable on its own; the analyzer normally shells out to them.

```powershell
python\.venv\Scripts\python.exe python\malapi_pipeline.py --help
python\.venv\Scripts\python.exe python\yara_gen.py --help
python\.venv\Scripts\python.exe ml\serve.py --help
python\.venv\Scripts\python.exe ml\predict.py --help
```

`ml/serve.py` needs `lightgbm`, `scikit-learn` and `pefile`, which are not in
`python\.venv` — that is the ML venv's job.

---

## Environment variables that change a run

Set in the shell, or in a pipeline's `environment:` block, or in `.env`.

| Variable | Effect |
| --- | --- |
| `IA_ARTIFACT_UPLOAD` | `0` forces evidence upload off. Set this before any test run. |
| `IA_ALLOW_CORE_DUMP` | `1` keeps a dump when the process dies. |
| `IA_CONTINUE_ON_SIGNAL` | `1` carries on after a continuable signal. POSIX only. |
| `ML_SKIP` | `1` skips ML scoring; the phase still appears and reports itself skipped. |
| `ML_EXPLAIN` | `1` requests SHAP. Default on. |
| `ML_THRESHOLD` | ML decision threshold, `0.0`–`1.0`. Default `0.5`. |
| `ML_TOP_K` | SHAP rows in the explanation. Default `8`. |
| `CTI_SKIP` | `1` stops the CTI phase touching the internet. |
| `CTI_CONFIG` | Path to the JSON overlay for CTI providers. |
| `STATIC_ANALYZER_CURSES` | `0` turns off the PDCurses progress screen. |
| `TRACE_FILE` | Path for symbol/offset diagnostics. |
| `KNOWN_PE_HASHES_FILE` | Overrides `data\known_pe_hashes.jsonl`. |
| `SA_API_HOST`, `SA_API_PORT` | API server bind address. |
| `ADMIN_PANEL_TOKEN` | Requires a token for the admin console. |
| `ADMIN_WEB_PORT` | Admin console port. |

The full list with the source line that reads each one is in
[docs/admin-console/analysis-config.md](docs/admin-console/analysis-config.md).

---

## Signals: verifying the continuation design

The POSIX claims behind `--continue-on-signal` can be checked under WSL, since
the Windows build cannot exercise them. This compiles a standalone program that
reproduces the same `sigaction` setup — it does **not** link the analyzer, so it
proves the design rather than the integrated binary.

```powershell
wsl bash -c "cd /mnt/c/Users/The4thReich/Desktop/IAProject/unit/signals && gcc -std=gnu11 -O0 -g -o /tmp/sc signal_claims.c && /tmp/sc"
```

Expected output:

```text
  PASS  handler ran once and execution continued past it
  PASS  a second SIGUSR1 is also survivable (no SA_RESETHAND)
  PASS  the fault re-executed and killed the process anyway (SIGSEGV re-raised)
        -> continuing a fault signal is an infinite loop, not a recovery
  PASS  SIGTERM/SIGHUP/SIGUSR1/SIGUSR2 continuable; SIGSEGV/SIGBUS/SIGFPE/SIGILL/SIGABRT are not
ALL CLAIMS HOLD
```

`-std=gnu11` rather than `-std=c11`: strict ISO mode hides the POSIX signal
declarations. Note this applies to any POSIX build of the analyzer too.

---

## Repository maintenance

```powershell
# What is staged, and how big.
git status --porcelain
git diff --stat

# Track a file the whitelist would otherwise hide.
git check-ignore -v <path>       # explains which rule matched

# Size audit: biggest tracked blobs still in history.
git rev-list --objects --all |
  git cat-file --batch-check='%(objecttype) %(objectname) %(objectsize) %(rest)' |
  Where-Object { $_ -match '^blob' } |
  ForEach-Object { if ($_ -match '^blob (\S+) (\d+) (.*)$') {
    [pscustomobject]@{ MB = [math]::Round([int64]$Matches[2]/1MB,1); Path = $Matches[3] } } } |
  Sort-Object MB -Descending | Select-Object -First 20

# Repository size.
git count-objects -vH
```

`.git` was 3.67 GB before the EMBER training data was purged from history in
2026-10-19; it is now 3.5 MB. Do not re-add `data\` to `.gitignore`'s
whitelist.

---

## Where things land

| Path | What |
| --- | --- |
| `build-ucrt\static_analyzer.exe` | The analyzer. |
| `exports\<stem>_analysis\` | Per-sample results, dashboard and all. |
| `%APPDATA%\IAProject\logs\` | Run log, checkpoints, crash reports. |
| `%APPDATA%\IAProject\logs\crash\` | Crash report `.txt` and `.dmp`. |
| `logs\resume\<stem>.json` | Ctrl+C checkpoint, relative to the run's logs root. |
| `data\known_pe_hashes.jsonl` | Known-PE roster. Not in git; see below. |

**`data\known_pe_hashes.jsonl` is not tracked**, despite `app_paths.hpp`
documenting it as checked in. A fresh clone has no known-PE matching until you
supply it. Set `KNOWN_PE_HASHES_FILE` or drop the file in place.

---

## First-time clone

A clone builds once the vendored trees are present. `spdlog/`, `cpp-dump/` and
`os-libzstd/lib/` are required by `CMakeLists.txt` and are currently **not**
tracked in git, so a fresh clone fails at configure with
`add_subdirectory(spdlog)` missing. Restore them before building — see
[VENDOR.md](VENDOR.md) once it exists; until then, copy them from a working
tree.