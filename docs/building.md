# Building the analyzer

Requirements, the build itself, container images and the tree layout.

<!-- Source: README.md, split by topic. -->

## Requirements

The current build is configured for Windows with MSYS2 UCRT64 and MinGW Makefiles.

Required tools and libraries:

- Windows 10/11
- MSYS2 UCRT64 toolchain
- CMake 3.20+
- C++20 compiler
- LIEF, re2, Capstone, YARA, OpenSSL/libcrypto, libmagic, TLSH, and libcurl
- zlib, bzip2, lzma, zstd, and gnurx
- Graphviz (`dot`) for graph rendering
- radare2 available through the project runner/WSL setup
- Python 3 with packages from `python/requirements.txt`
- Jinja2 for dashboard generation

The CMake preset expects MSYS2 at `C:\msys64`. Adjust `CMakePresets.json` and `CMakeLists.txt` for another toolchain location.

## Build

From PowerShell in the repository root:

```powershell
cmake --preset ucrt64
cmake --build --preset ucrt64-release
```

There are two test tiers, and they answer different questions:

- **`unit/`** — fast, needs nothing but the code under test. 85 tests: 58 under
  `python\.venv\Scripts\python.exe -m pytest unit\python -q`, and 27 C++ tests
  built with `cmake --build build-ucrt --target unit_tests`. See
  [unit/README.md](../unit/README.md) for what belongs there and what does
  not.
- **`tests/`** — black-box. Needs the built analyzer, a sample, and sometimes a
  running service. Run with `pytest tests`.

The C++ test target is deliberately not in `all`: a test target that builds by
default is one nobody runs.

Build verification without the test suites is described in
[Validation](pipelines-and-phases.md#validation).

The convenience script performs the same steps and can analyze a file:

```powershell
.\build.ps1
.\build.ps1 -InputFile .\path\to\sample.exe
.\build.ps1 -Clean
```

### Binary hardening

The analyzer is built with four Windows protections, all ON by default because
MinGW's linker and compiler already default them on:

| setting | what it does |
| --- | --- |
| `aslr` | relocates the image at load time |
| `high_entropy_va` | relocates across the full 64-bit range |
| `dep_nx` | marks the stack and heap non-executable |
| `stack_protector` | checks a canary on every protected stack frame |

They are configured in `config/hardening.json`, which is the same file the
admin panel's Analysis Configuration page edits — so a build from a terminal
and a build from the panel produce the same binary. The switches exist to turn a
protection **off** deliberately, not to turn one on; a protection turned off and
genuinely absent from the binary is compliance, not a failure.

For a single build, override the file with the paired switches:

```powershell
.\build.ps1 -DisableStackProtector      # this build only; the file is untouched
.\build.ps1 -DisableAslr -DisableDepNx
```

`-EnableX` and `-DisableX` for the same protection cannot both be given. The
CMake options behind them (`STATIC_ANALYZER_HARDENING_*`) are written into
`build-ucrt/CMakeCache.txt`, so the configured tree records the intent, and the
panel's Analysis Configuration page compares that intent against what the
finished PE header actually carries.

The main executable is written to:

```text
build-ucrt/static_analyzer.exe
```

## Podman container images

For full Docker Compose run, test, custom-sample, and cleanup steps, see
[Container testing guide](../CONTAINER-TESTING.md).

`Containerfile` builds the analyzer as a native Linux CLI image for Podman running
inside WSL. The build installs the native libraries and tools, builds LIEF and the
analyzer, and installs the Python dashboard/API dependencies. Build and export an
OCI archive from PowerShell:

```powershell
.\build-image.ps1
```

This creates `artifacts\static-analyzer-linux.oci.tar` and leaves the image in the
WSL Podman image store as `localhost/static-analyzer:linux`. The analyzer writes
reports under `/opt/static-analyzer/exports`; mount that directory and mount input
samples read-only when running it:

```powershell
wsl.exe -- podman run --rm `
  --userns=keep-id:uid=10001 `
  -v /mnt/c/samples:/samples:ro `
  -v /mnt/c/analyzer-exports:/opt/static-analyzer/exports `
  -e CYBERCHEF_URL=http://127.0.0.1:3000 `
  localhost/static-analyzer:linux /samples/sample.exe
```

The shareable Linux stack is in `compose.yaml`. It builds the analyzer and the
CyberChef API server, pulls the official CyberChef web UI image, waits for the API
health check, and runs the sample analyzer. The official `ghcr.io/gchq/cyberchef`
image serves the web UI but does not implement the `/bake` and `/magic` API used
by this analyzer, so Compose builds the compatible API server from the upstream
`gchq/CyberChef-server` source using `Containerfile.cyberchef`.

With Docker Compose, run `docker compose up --build`; with Podman, use a compatible
Compose provider and run `podman compose up --build`. The CyberChef UI is available
on port 8081, and analyzer reports are written to `artifacts/compose-exports`.
The analyzer image defaults `CTI_SKIP=1` to avoid external CTI lookups. Curses is
disabled; analysis is a one-shot CLI operation.

`Containerfile.windows` is the separate Windows Server Core build definition. It
installs the MSYS2 UCRT64 compiler/libraries, Python packages, Graphviz, and
radare2, then builds the Windows executable. `compose.windows.yaml` builds and
runs that analyzer and uses `CYBERCHEF_URL` to connect to an already-running,
reachable CyberChef API service (default `http://host.docker.internal:3000`).
Run it with `docker compose -f compose.windows.yaml up --build` on a Windows
container-capable engine. Windows and Linux containers cannot be started together
by the same engine mode; run the Linux Compose stack separately to provide the
CyberChef API, or point `CYBERCHEF_URL` at another reachable API server.
Podman inside WSL is Linux-only and cannot build the Windows image.

For a quick resource profile while the Linux stack is running, use
`podman stats` (or `docker stats`) in another terminal. The CLI analysis is a
one-shot workload; compare repeat runs on the same sample and machine, and record
elapsed time together with peak CPU and memory. Image size can be checked with
`podman image inspect localhost/static-analyzer:linux --format '{{.Size}}'`.

## Project structure

```text
CMakeLists.txt                 Main C++ build definition
CMakePresets.json              MSYS2 UCRT64 configure/build/test presets
build.ps1                     PowerShell build convenience script
src/                          C++ pipeline and components, grouped by module
src/main.cpp                  Entry point: process lifecycle and stage order
src/main/                     The 25 stages, the report renderers, and the
                               shared pipeline context (include/main/pipeline.hpp)
include/                      Public C++ component headers, mirroring src/
python/_create_dashboard.py   Dashboard payload builder and renderer
python/stix_graph.py          Shared STIX -> graph / Navigator layer builder
python/_view_stix.py          Standalone STIX bundle viewer
python/_extract_stix.py       Recovers STIX objects from bare technique IDs
python/templates/              Jinja HTML/CSS/JavaScript template (dashboard.html.j2)
                               and the placeholder-based stix.html shell
python/api/server.py          Local MalAPI service used during a run
admin-web/                    Admin console SPA (React + Vite + HeroUI). dist/
                              is served by python/panel; only src/ is source
admin-panel.ps1               Builds the SPA, starts the panel, opens a browser
python/admin_server.py        Flask entry point for the admin console
python/panel/                 Panel backend: app.py holds the routes, grouped by
                              domain: core/ (config, auth, docs, YAML view),
                              utils/ (job runners and shared helpers), analysis/,
                              artifacts/, build/, clamd/, qiling/, samples/,
                              network/ (netmap, virt, vms, vmmetrics) and
                              host/ (services, containers, stats, logs, trace)
python/clamd/                 ClamAV host-side tooling: scanner client, SSH
                               driver, artifact collector, requirements.txt
python/qiling/                Qiling emulation tooling: the PE harness, VM
                               staging, artifact collector, dashboard and CTI
python/requirements.txt       Python dependencies
python/d3.min.js              Vendored dashboard plotting library
python/world-110m.json        Vendored offline world geometry
python/country-codes.json     Country code/name/centroid table
qiling_dlls/                  VM payload only: rootfs.tar.gz, examples/,
                               templates/, dll_collector.bat, vm_info.json.
                               Its basename is also the analysis VM's
                               remote_dir (admin-terminal/vms.json), so it
                               keeps the name even though the scripts moved
                               to python/qiling/
exports/                      Generated analysis artifacts, one <stem>_analysis/ per run
cache/                        Provider/tool caches - moved out of the tree, see below
logs/                         Runtime logs - moved out of the tree, see below
data/                         Corpus data, including known_pe_hashes.jsonl
tests/fixtures/               Sample sources and inert test inputs
```

Generated state is **not** in the tree. Run logs, crash reports and minidumps,
debug dumps, resume checkpoints, `trace.txt`, YARA rule caches, provider caches,
encryption keys and sealed credentials all live under one AppData directory named
after the application, `%APPDATA%/IAProject/`, holding `logs/`, `cache/`,
`panel-cache/`, `bundle-keys/` and `mega-secrets/`. Set `IA_APPDATA_DIR` to put
that tree elsewhere; see [Output layout](evidence-and-encryption.md#output-layout).

Important C++ components:

- `file_analyzer` — file type, magic, and basic metadata.
- `file_hasher` — cryptographic and fuzzy hashes.
- `known_pe_hashes` — SHA-256 lookup against the known-PE roster (`data/known_pe_hashes.jsonl`).
- `extractor` — sections, strings, imports, symbols, guards, packing, opcode data, the export table, and the YARA scan.
- `ioc_extractor` — strings-to-IOC normalization and classification.
- `capa_runner` — capa subprocess integration.
- `radare2_runner` — radare2 subprocess, artifacts, disassembly, and graphs. (The source file is spelled `src/r2/radar2_runner.cpp`.)
- `yara_scanner` — libyara rule loading and PE scanning.
- `dns_runner` — `dig` wrapper for DNS facts used by CTI.
- `cti` — threat-intelligence model, providers, normalization, and correlation.
- `exporter` — JSON/DOT/artifact serialization.
- `mega/seal.py` — public-key bundle encryption: X25519 + HKDF-SHA256 + AES-256-GCM via the `cryptography` library, in-process.
- `visualizer` — Python dashboard generation wrapper.
- `local_api` — local MalAPI service supervision (launch, health-poll, stop).
- `podman_runner` — long-lived container supervision through WSL.
- `net/cyberchef` — CyberChef-server client: screens ROT (13/47/printable), single-byte XOR, bit rotations, base64 (incl. `-enc` UTF-16LE), hex, `%`-encoding, and base32/58/85 forms — XOR / ROT / rotate / base64-NUL suspects are confirmed through `/bake`, encoding shapes through `/magic` — and matches PJW / DJB2 / FNV-1a API-hash constants locally; flags strings whose decoded form hits suspicious indicators (see `CYBERCHEF_URL` / `CYBERCHEF_DISABLE`).
- `secret_store` — Bitwarden (`bw serve`) credential retrieval, in memory only.
- `curses_ui` — PDCurses results browser.
- `process_runner` — bounded subprocess execution and process-tree handling.
- `trace` — optional diagnostic process/memory tracing.
- `resume` — Ctrl+C handling and the `logs/resume/<stem>.json` checkpoint.
- `banner` — centred ASCII banners; owns the `logos/crash.logo` printed in red on a fault.
- `crash_handler` — fault reports (text + minidump) and the `std::terminate` path.
- `logging` and `console` — logging and terminal presentation.
- `main/` — the stage functions (`phase_*.cpp`), the report renderers (`report_*.cpp`), and the `pipeline::context` they share.

