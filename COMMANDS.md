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

Binary hardening is read from `config\hardening.json` (ASLR, high-entropy VA,
DEP/NX, stack protector - all on by default) and can be overridden per build:

```powershell
.\build.ps1 -DisableStackProtector
.\build.ps1 -DisableAslr -DisableDepNx
.\build.ps1 -EnableHighEntropyVa
```

`-EnableX` and `-DisableX` for the same protection cannot both be given. The
file is the project-wide intent; a switch changes one build and leaves it alone.
The admin panel's Build page edits the same file and reports what the finished
binary actually carries.

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

# Ctrl+C no longer stops the run: the first interrupt re-runs the phase it
# landed on and carries on. Only a second Ctrl+C stops it.
.\build-ucrt\static_analyzer.exe --continue-on-signal .\sample.exe
```

Both flags are also settable from a pipeline's `environment:` block, which is
what the admin console writes:

```powershell
$env:IA_ALLOW_CORE_DUMP = "1"
$env:IA_CONTINUE_ON_SIGNAL = "1"
```

Outputs land in `%APPDATA%\IAProject\logs\crash\`.

The re-run is the point, not a skip-forward: an interrupted phase can leave
partial output behind, and the next phase reading that is how a report ends up
quietly wrong. In the default plan `sections` is phase 2, so an interrupt there
re-runs `sections` and the run continues to the end. There is one rewind per
run, so a second Ctrl+C stops rather than walking the plan backwards.

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

Windows reserves blocks of TCP ports for Hyper-V / WSL2 / Docker Desktop at
boot. A bind inside one fails with `WinError 10013` even though nothing is
listening, and `60100`/`60101` fall inside such a block on some machines — so
the launch can fail on a port that `Get-NetTCPConnection` reports as free.
`admin-panel.ps1` checks both the panel port and the Vite port against the
exclusions before starting, explains the cause, and names a free port:

```powershell
netsh interface ipv4 show excludedportrange protocol=tcp   # the ranges
.\admin-panel.ps1 -Port 60600                              # outside them
```

`ADMIN_WEB_DEV_PORT` pins the Vite port (default: `ADMIN_WEB_PORT` + 1).

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
| `IA_CONTINUE_ON_SIGNAL` | `1` makes Ctrl+C re-run the interrupted phase and continue. |
| `ML_SKIP` | `1` skips ML scoring; the phase still appears and reports itself skipped. |
| `ML_EXPLAIN` | `1` requests SHAP. Default on. |
| `ML_THRESHOLD` | ML decision threshold, `0.0`–`1.0`. Default `0.5`. |
| `ML_TOP_K` | SHAP rows in the explanation. Default `8`. |
| `CTI_SKIP` | `1` stops the CTI phase touching the internet. |
| `CTI_CONFIG` | Path to the JSON overlay for CTI providers. |
| `STATIC_ANALYZER_CURSES` | `0` turns off the PDCurses progress screen. |
| `STATIC_ANALYZER_FORCE_LOGO` | `1` prints the startup `daorcs.logo` even when stdout is redirected. The admin panel sets it so captured Build and pipeline logs keep the banner. |
| `ENABLE_TRACING` | `false` silences symbol/offset tracing entirely - even where `TRACE_FILE` is set, and with it the last-calls tail in a crash report. Unset means on. |
| `TRACE_FILE` | Path for symbol/offset diagnostics. |
| `IA_INTERRUPT_IF_PACKED` | `1` stops the run right after the histogram phase when whole-file entropy is at or above the threshold; the message names both numbers, and `--resume` pushes through. |
| `IA_INTERRUPT_ENTROPY` | That threshold, `0.1`–`8.0` bits/byte. Default `7.5`. |
| `MEGA_UPLOAD` | `1` uploads the evidence bundle; overrides artifacts.yaml's `upload_artifacts`. |
| `MEGA_REMOTE_ROOT` | MEGA destination parent, `<root>/<sample>_artifact`. |
| `MEGA_SEAL` | `1` seals the bundle before upload; overrides `encrypt_artifacts`. |
| `MEGA_RECIPIENT` | `user` or `admin` - which sealing keypair. |
| `MEGA_ADMIN_PUBKEY` | Admin public key (or a path to it) for `admin` sealing. |
| `MEGA_TIMEOUT` | Upload command timeout in seconds, `1`–`86400`. Default `900`. |
| `KNOWN_PE_HASHES_FILE` | Overrides `data\known_pe_hashes.jsonl`. |
| `SA_API_HOST`, `SA_API_PORT` | API server bind address. |
| `ADMIN_PANEL_TOKEN` | Requires a token for the admin console. |
| `ADMIN_WEB_PORT` | Admin console port. |
| `ADMIN_WEB_DEV_PORT` | Vite dev-server port; defaults to `ADMIN_WEB_PORT` + 1. |

The full list with the source line that reads each one is in
[docs/admin-console/analysis-config.md](docs/admin-console/analysis-config.md)
(global layer) and
[docs/admin-console/pipelines-configuration.md](docs/admin-console/pipelines-configuration.md)
(per-pipeline layer). A key may be set in only one of the two.

---

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

A clone builds once the vendored trees are present. `spdlog/` and `cpp-dump/`
are required unconditionally by `CMakeLists.txt` — `add_subdirectory(spdlog)` at
line 174, and a `FATAL_ERROR` if `cpp-dump/cpp-dump.hpp` is absent — and both
are currently **not** tracked, so a fresh clone fails at configure.
`os-libzstd/` is needed too, but only with
`-DSTATIC_ANALYZER_USE_VENDORED_ZSTD=ON`, which is off by default.

Copy the three directories in from a machine that already has them, then
configure. The versions they came from:

| Tree | Upstream | Commit |
| --- | --- | --- |
| `spdlog/` | https://github.com/gabime/spdlog | `57cb5fb7` (v1.17.0-44) |
| `cpp-dump/` | https://github.com/sassan-dev/cpp-dump | `aabd98dd` (v0.7.0-35) |
| `os-libzstd/` | https://github.com/pexip/os-libzstd | `033868ce` |

Tracking them in git is the obvious fix and has not been done — about 6 MB of
vendored source, and it should be a deliberate decision rather than a side
effect of a build failing.
