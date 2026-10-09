# Static Analyzer Project

A Windows-oriented static-analysis and threat-intelligence dashboard pipeline written in C++20, with Python-based report generation and optional CTI enrichment.

> **Safety note:** this repository is for defensive analysis of files you own or are authorized to inspect. The included EICAR/IOC fixture is deliberately inert and is not malware. EICAR is an industry antivirus test signature, so security software may quarantine the fixture executable.

## What the project does

`static_analyzer.exe` takes one binary path as its input and runs a staged static-analysis pipeline. It reports information to the terminal and writes normalized JSON, assembly, graph, CTI, and HTML artifacts under `exports/<stem>_analysis/` — one directory per run, so samples never share paths. The pipeline has 25 numbered stages, of which a given run executes 20 or 23 depending on the detected format — see [How a run works](#how-a-run-works).

The pipeline is designed around five ideas:

1. **Understand the file** — format, headers, sections, entropy, imports, symbols, strings, guards, and packing indicators.
2. **Extract intelligence** — URLs, domains, IPs, e-mail addresses, hashes, family hints, CVE/ATT&CK-related data, and provider findings.
3. **Understand behavior statically** — capa capabilities, radare2 functions, instruction data, call graphs, section CFGs, and IAT/GOT call sites.
4. **Export evidence** — machine-readable JSON and DOT artifacts suitable for automation.
5. **Present the result** — a self-contained offline HTML dashboard with maps, graphs, assembly, hexdump, CTI summaries, and detail panels.

## How a run works

### Invocation and startup

```text
static_analyzer.exe <input-file>
```

With no argument the analyzer falls back to `a.exe` in the current directory. Results are written relative to the working directory, so run from the repository root unless a different layout is intentional.

### Python API server

The root `server.py` provides a local REST API. Start it from the repository root
with:

```powershell
python\.venv\Scripts\python.exe server.py
```

Set `SA_API_HOST` and `SA_API_PORT` in `.env` to configure its bind address and
port (defaults: `127.0.0.1:60020`); command-line `--host` and `--port` override
those settings. The JSON service index is available at the configured address.
Submit samples with `POST /analyze` as a multipart `file` upload or raw request
body; use `--analyzer` to select a different analyzer executable.
During graceful shutdown, GET endpoints remain available for status and task
inspection, while new POST submissions receive `503`.
Run `python\.venv\Scripts\python.exe tests\test_server_queue.py` to test queuing
the included executable fixture and graceful draining without launching the analyzer.

### Qiling Analysis VM

The Analysis VM connection is configured in `admin-terminal/vms.json`
(`192.168.56.105:22` by default). Set its `username` and, if needed,
`identity_file`. Before connecting, add the VM's verified SSH host-key entry to
the current user's `~/.ssh/known_hosts` (override with `known_hosts_file` in
`vms.json`); connections use strict checking and never accept unknown keys.
Verify the VM fingerprint out of band before adding it.

In Admin Terminal → Analysis VMs, choose **q** to collect Windows registry/DLL
files into the local Qiling rootfs (Windows displays a UAC prompt), or **d** to
prepare the rootfs, upload it only if the VM does not already have it, send
`_qiling_script.py` and the selected executable over SFTP, run Qiling over SSH,
and download the result to `qiling_dlls/results/`. If SSH times out, the menu
offers optional, elevated Windows Firewall rules limited to TCP 22/80 and the
`192.168.56.0/24` subnet; it does not change the firewall without confirmation.

`main()` owns the process lifecycle and the stage order; the stages themselves live in `src/main/`. Startup is a fixed sequence:

1. `console::enable_utf8_output()`, `logging::init()` (opens the run-id-scoped log under `logs/`), and the process tracing hooks.
2. `proc::protect_env_var("BW_SESSION")`. This runs before the first child process exists on purpose: marking a variable protected is a process-wide policy, so doing it once here keeps the Bitwarden session token and every CTI key out of all later children.
3. The PDCurses results browser (`curses_ui::session`). Set `STATIC_ANALYZER_CURSES=0` to disable it and get plain terminal output.
4. The local Python API server (`python/api/server.py` via the `py` launcher, CWD `python/`, bound to `127.0.0.1:60000`). It is health-polled with a 10-second startup timeout and serves the MalAPI lookups. A failure here is logged and does not abort the run.

### Format detection and the phase plan

The file type is determined first, from libmagic plus LIEF, and reduced to one of **PE**, **ELF**, **Mach-O**, or unknown. That detection drives the plan, because several stages only mean something for one format:

- PE and ELF/Mach-O each have a dedicated section table, so the generic LIEF section view would be a duplicate and is dropped for them.
- Four stages are PE-only: the import table, the MalAPI lookup over its imports, the export address table, and the YARA rule scan.
- GOT/PLT is ELF/Mach-O only.

The arithmetic starts from 25 stages and subtracts what the format makes inapplicable, giving **23 for a PE**, **20 for an ELF or Mach-O**, and **20 for anything else**. The result becomes the progress total and the denominator in every `[phase n/total]` header. A stage the format excludes prints no header and advances nothing, so the numbering never runs past a format-inapplicable stage. The one exception is Graphviz, which is gated on `R2_RENDER` rather than on the format and keeps its slot in the total either way — see the note under the [phase table](#analysis-phases).

Before stage 1 the banner, the file identity, and the hashes are printed unnumbered; after the last stage the run prints a `summary` banner.

### Known PE hashes

For a PE sample the analyzer looks the computed SHA-256 up in `data/known_pe_hashes.jsonl` — the roster of known PE files built from the EMBER2024 Win64 corpus (train, test, and challenge; 216,310 distinct hashes after removing the repeats the corpus files contain). A hit reports the label the corpus recorded, the malware family, and which split the hash came from:

```text
    SHA-256:              6773fee7acd3cd311f68283230834a803f1549f20c338717f283bbeae823dfc3
    TLSH:                 1A343B926ACB4CF...
    Known PE:             yes
      Label:              malicious (EMBER label 1)
      Family:             emotet
      Split:              challenge
      Roster:             216310 hashes (C:\...\data\known_pe_hashes.jsonl)
```

This is a **corpus membership check, not a verdict**. A match means the file is in the reference set and the label is what that set says about it; it is not a fresh judgement about the file in front of you. The roster covers Win64 PEs only, so non-PE samples are never looked up — asking whether an ELF is in a list of PE hashes would be a category error.

The lookup is part of the hash stage rather than a numbered phase of its own, so it adds no `[phase n/total]` work and a run over a sample with no roster installed behaves exactly as before. A missing or unreadable roster is logged and skipped, never reported as an analysis error. Point `KNOWN_PE_HASHES_FILE` at another JSONL to use a different roster; malformed lines are skipped and counted rather than aborting the load. Results are written to `exports/<stem>_analysis/known_pe/<stem>_known_pe.json`, and only when a roster was actually consulted — a file recording `matched: false` for a run that never looked anything up would be indistinguishable from a real negative.

### Terminal output contract

Every stage writes through one small vocabulary, and the PDCurses browser depends on it. The browser captures `std::cout` and re-colours the captured text by matching these three line shapes:

```text
  -- Section heading
    Key:  value
      * bullet
```

Renderers therefore always paint ANSI colour into the text and always write to `std::cout` — never to `printf` and never to a stream parameter. The browser strips the escape sequences and applies its own styling, so the same code produces a readable terminal report and a colourised TUI without branching.

### Failure handling and exit code

Stages are independent: a missing external tool, an unavailable provider, or an unsupported file feature is recorded as a warning and the run continues. `extractor::recover_errors` collects the per-stage failures at the end.

The process exits non-zero when the input could not be analyzed at all, when capa failed, or when radare2 reported `not_found`, `launch_failed`, or `timed_out`. Every other outcome — including a run with zero findings — exits zero.

### Credentials and network

CTI API keys are read from the environment, or fetched in memory from a running `bw serve` (`CTI_BW_KEYS` names the vault items). A vault value is marked protected, applied with `_putenv_s`, zeroed in memory immediately afterwards, and unset again when the CTI stage ends, so it never rests on disk and does not reach a later child process.

CTI is the only stage that reaches the network, and the only stage that can be switched off wholesale with `CTI_SKIP=1`. When no network is reachable the stage reports that and skips. Because the STIX bundle and the ATT&CK Navigator layer are built from the techniques capa matched rather than from provider answers, both are still produced on a fully offline run.

## Assembly collection

Assembly is collected entirely by radare2, run through WSL on Windows (Windows paths are translated to `/mnt/...` first). One rule governs the whole design: **the r2 JSON is the source of truth, and the flat `.asm` file is a derived artifact that is never read back.** That keeps per-function boundaries, per-instruction bytes, and per-instruction virtual addresses exact — a text disassembly cannot.

The bulk pass, in order:

1. **Metadata** — `rabin2` is run once per flag (`-I`, `-S`, `-s`, `-i`, `-e`) and the JSON documents are merged. This yields file info, the section table (with VA ranges), symbols, imports, and entrypoints.
2. **Function list** — `r2 -c "aflj"`. One shared list is used for the whole pass, so every later stage agrees on what a function is.
3. **Disassembly** — one `pdfj @ 0x<offset>` command per function. Commands are chunked at **800 per r2 invocation** (roughly 20 KB of command line, well under the Windows 32K limit) and the JSON stream is parsed out of each batch. Explicit per-offset commands are used rather than a single `pdfj @@f` sweep because the sweep proved fragile across r2 versions; at most **2000 functions** are disassembled by default.
4. **Enrichment** — each instruction is recorded with its VA, raw bytes, disassembly, r2 type, and containing section (resolved by VA range against the rabin2 section table). Control-flow targets are resolved to an address plus a label — a function name or `dll!import` — and flagged when they land on an import. NOP counts are tallied per function and per section.

Two artifacts come out of this, both written atomically and in binary mode so no CRLF translation can corrupt them:

```text
exports/<stem>_analysis/radare2/<stem>_functions.json   structured, enriched instruction stream
exports/<stem>_analysis/radare2/<stem>_functions.asm    flat text rendering, derived from the JSON
```

The dashboard reads the JSON. The `.asm` is for reading by eye.

**Graphs.** `agCd` produces the whole-program call graph (`<stem>_callgraph.dot`); `agfd` produces the entry function's CFG (`<stem>_entry.dot`); `agfd` run per executable section produces one `_section_<name>.dot` per section, skipping sections with no nodes.

**IAT/GOT call sites** are collected separately, because they need to be found before they can be disassembled. Target addresses are gathered first — for a PE, image base plus each IAT RVA; for ELF and Mach-O, each GOT slot address — then `axtj @ <slot>` resolves the cross-references, `aflj` maps each one to its enclosing function, and only those functions are disassembled with `pdfj @ <fn>`. The result is `<stem>_iat_calls.asm` plus its JSON. This pass is capped at 2000 slots and 500 functions and de-duplicates functions so a hot import is not dumped repeatedly.

**Rendering.** With `R2_RENDER` set to a format (for example `svg`), every non-empty `.dot` file is rendered by Graphviz `dot -T<fmt>`, invoked through `proc::run` like every other external tool — so it inherits the same timeout, output cap, and process-tree kill. `R2_DOT_EXE` overrides the location of the `dot` binary.

Two properties make the output reproducible: radare2's analysis configuration is pinned with `-e` overrides (`pin_analysis_config`), so results do not drift with r2 defaults between versions, and the resolved `r2` and `rabin2` versions are recorded alongside the artifacts.

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

The project currently has no automated unit-test targets. Build verification is described in [Validation](#validation).

The convenience script performs the same steps and can analyze a file:

```powershell
.\build.ps1
.\build.ps1 -InputFile .\path\to\sample.exe
.\build.ps1 -Clean
```

The main executable is written to:

```text
build-ucrt/static_analyzer.exe
```

## Podman container images

For full Docker Compose run, test, custom-sample, and cleanup steps, see
[Container testing guide](CONTAINER-TESTING.md).

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

## Output layout

Typical output directories are:

```text
exports/<stem>_analysis/
  fileinfo/       file metadata and magic/header information
  hash/           SHA-256 and fuzzy hashes
  extraction/     sections, strings, guards, packing, signatures, opcodes
  ioc/            extracted IPs, domains, URLs, e-mails, hashes, family hints
  iat/            PE import table data
  got/            ELF/Mach-O GOT/PLT data
  capa/           capa capabilities and technique mappings
  radare2/        functions, assembly JSON, call graph DOT, section CFG DOT
  malapi/         structured MalAPI hits
  cti/            provider findings, correlation, and CTI summary
  known_pe/       corpus-membership result for the sample's SHA-256
  stix/           STIX 2.1 bundle and ATT&CK Navigator layer
  dashboard/      final self-contained HTML report
```

Every run gets its own `<stem>_analysis/` directory under `exports/`, named after the sample's
stem, so two runs never read or overwrite each other's artifacts and re-running the same sample
replaces only its own results. The shared caches (`cache/`, `cti-cache/`, `data/`) stay outside
the per-run directory.

JSON artifacts are composable. The dashboard generator reads these files and embeds a normalized payload into one HTML document, so the report can be opened locally without a web server or network fetch.

## Dashboard

The dashboard is generated by:

```text
python/_create_dashboard.py
python/templates/dashboard.html.j2
```

The C++ `visualizer` component launches the Python generator with artifact paths. The generated report is normally:

```text
exports/<sample-stem>_analysis/dashboard/<sample-stem>.html
```

Open that file directly in a browser. It is self-contained and does not require a CDN.

Dashboard areas include:

- **Overview** — score, hashes, file metadata, and summary statistics.
- **Sections** — section sizes, virtual addresses, entropy, and chi-squared values.
- **Imports** — DLL grouping, named/ordinal imports, delay imports, and MalAPI flags.
- **Capabilities** — capa matches, ATT&CK IDs, MBC IDs, namespaces, and scopes.
- **IOCs** — domains, IPs, URLs, e-mails, hashes, and family hints.
- **Assembly** — function selector, instruction search, category filters, basic blocks, byte-length visualization, call targets, and a control-flow mini-map.
- **Call Graph / CFG** — ranked call graph and compact section CFG with zoom, search, and neighborhood highlighting.
- **Analytics** — score gauge, opcode/mnemonic charts, section entropy, function sizes, IOC counts, capability scope, and imports per DLL.
- **ML Score** — the EMBER2024 verdict, a P(malicious) gauge needle against the model's decision threshold, SHAP log-odds bars for the group attribution and for the top features (red towards malicious, green towards benign), and the model/attribution tables. When no scoring service ran the section degrades to a "skipped" note instead of an empty chart.
- **Threat Map** — offline world map for CTI-geolocated IOCs, IOC filters, country drill-down, ASN links, and a separate info graph.
- **ATT&CK / STIX** — four views. *Coverage* lays every technique capa matched out as a kill-chain matrix and can export an ATT&CK Navigator layer. *Procedures & Tooling* expands each observed tactic into its techniques and, for each one, the tools and malware ATT&CK records as implementing it, the groups known to use it, its sub-techniques, its mitigation count, and its detection guidance — searchable and filterable by tactic and by data type. *Object Graph* is the force-directed view of the STIX 2.1 objects and their relationships. *D3FEND Defenses* answers the defensive side: for every tactic capa recovered, the D3FEND countermeasures that defeat each technique (technique → D3-FA *File Analysis* *analyzes* *File*), grouped by tactic and labelled with the D3FEND tactic — Detect, Isolate, Harden, Model, Evict, Restore.

  ATT&CK v19 moved detection guidance off the technique object: `attack-pattern` entries no longer carry `x_mitre_detection`, so it is reached through `detects` → `x-mitre-detection-strategy` → `x-mitre-analytic`. All of this comes from the local `cti-cache/knowledge/enterprise-attack.json`, so it is present on an offline run and under `CTI_SKIP=1`.

  The *Procedures & Tooling* tab is always offered once ATT&CK data exists. When the CTI report carries no tactic view (CTI skipped, no provider answered, no CTI artifact written), the dashboard rebuilds it from capa's technique ids against the local ATT&CK cache — `source: attack-cache` in the payload — so the tooling is there offline; if neither source has anything the tab still opens, with the reason instead of missing data.

  D3FEND data comes from the `d3fend.mitre.org` API (the `mitre/d3fend` repo cannot even be checked out on Windows — several of its paths contain `:`), fetched once per technique and cached in `cti-cache/knowledge/d3fend.json`. `D3FEND_OFFLINE=1` forbids the network, so a later run renders from the cache alone; a technique that is neither cached nor reachable simply shows no chip instead of failing the dashboard.

The map uses vendored offline world/country data. CTI country values are distinguished from country values inferred from a TLD. IOCs without a usable country remain in the unmapped list rather than being silently dropped.

## STIX and ATT&CK

Every run writes two artifacts under `exports/<stem>_analysis/stix/`:

```text
<sample-stem>_stix21.json     STIX 2.1 bundle: identity, indicators, malware
                              families, CVEs, attack-patterns, relationships
<sample-stem>_navigator.json  ATT&CK Navigator layer (layer format 4.5)
```

Both are built from the techniques capa matched, not from the CTI phase, so they are complete
on an offline run and with `CTI_SKIP` set — a scan with no provider answers still emits its TTPs.
The Navigator layer can be loaded into the official ATT&CK Navigator.

A STIX bundle can also be viewed on its own:

```text
python/_view_stix.py <bundle.json> [--out-dir DIR] [--navigator]
```

This renders any STIX 2.1 file — this project's own bundles, the ones
`python/_extract_stix.py` recovers from technique IDs, or bundles downloaded from OTX, MISP or
the MITRE CTI repo — as a self-contained HTML page with the same coverage matrix and object
graph. As with the dashboard, the output is one file that opens by double-clicking.

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
python/requirements.txt       Python dependencies
python/d3.min.js              Vendored dashboard plotting library
python/world-110m.json        Vendored offline world geometry
python/country-codes.json     Country code/name/centroid table
exports/                      Generated analysis artifacts, one <stem>_analysis/ per run
cache/                        Provider/tool caches
logs/                         Runtime logs
data/                         Corpus data, including known_pe_hashes.jsonl
tests/fixtures/               Sample sources and inert test inputs
```

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
- `visualizer` — Python dashboard generation wrapper.
- `local_api` — local MalAPI service supervision (launch, health-poll, stop).
- `podman_runner` — long-lived container supervision through WSL.
- `net/cyberchef` — CyberChef-server client: screens ROT (13/47/printable), single-byte XOR, bit rotations, base64 (incl. `-enc` UTF-16LE), hex, `%`-encoding, and base32/58/85 forms — XOR / ROT / rotate / base64-NUL suspects are confirmed through `/bake`, encoding shapes through `/magic` — and matches PJW / DJB2 / FNV-1a API-hash constants locally; flags strings whose decoded form hits suspicious indicators (see `CYBERCHEF_URL` / `CYBERCHEF_DISABLE`).
- `secret_store` — Bitwarden (`bw serve`) credential retrieval, in memory only.
- `curses_ui` — PDCurses results browser.
- `process_runner` — bounded subprocess execution and process-tree handling.
- `trace` — optional diagnostic process/memory tracing.
- `logging` and `console` — logging and terminal presentation.
- `main/` — the stage functions (`phase_*.cpp`), the report renderers (`report_*.cpp`), and the `pipeline::context` they share.

## Safe test fixture

The project retains defensive sample inputs and fixtures under:

```text
tests/fixtures/eicar_ioc_fixture.cpp
```

It is a defensive test input generator containing the standard EICAR antivirus test signature, documentation/reserved domain strings, documentation IP addresses from `TEST-NET` ranges, example URLs, e-mail addresses, and labels intended to exercise IOC and threat-summary paths.

It does **not** contain a real payload, exploit, downloader, persistence mechanism, credential theft, evasion logic, or network client. It is intended to be compiled and passed to the analyzer for extraction/report testing.

Because the source contains EICAR, antivirus software may flag or quarantine the executable. This is expected for an EICAR test fixture.

## Validation

Automated unit and smoke tests have been removed for now. The analyzer's defensive input fixtures remain available for manual verification. Build and syntax-check the Python dashboard tools with:

```powershell
cmake --build --preset ucrt64-release
py -m py_compile python\_create_dashboard.py python\stix_graph.py python\_view_stix.py
```

For a manual end-to-end check, run the analyzer over the included PE fixture:

```powershell
$env:STATIC_ANALYZER_CURSES = "0"; $env:CTI_SKIP = "1"
.\build-ucrt\static_analyzer.exe .\tests\fixtures\suspicious_sample.exe
```

The PE fixture should report **23** stages. `CTI_SKIP=1` keeps the run offline while still exercising the other stages, including STIX and Navigator output.

When changing the dashboard template, regenerate the report and verify that it has no unrendered Jinja markers, valid embedded JSON, working `file://` behavior, expected graph/assembly data, and syntactically valid inline JavaScript.

The STIX viewer has no third-party dependencies — `python/stix_graph.py` and
`python/templates/stix.html` use only the standard library — so it can be checked on its own:

```powershell
py python\_view_stix.py exports\<stem>_analysis\stix\<stem>_stix21.json --navigator
```

## Troubleshooting

### Python cannot import Jinja2

The analyzer uses the Python launcher (`py`) by default. Confirm the selected interpreter has Jinja2:

```powershell
py -c "import jinja2; print(jinja2.__version__)"
```

The first `python3` on PATH may not be the interpreter selected by the Windows `py` launcher.

### radare2 output is missing

Check that the configured runner can find radare2. On Windows it may execute through WSL. Confirm the WSL distribution, radare2 installation, and mounted repository path. `bad_output` means valid JSON/DOT was not obtained; it is different from a valid analysis with zero findings.

### Dashboard is stale

The generated HTML is an artifact, not a live view of the source template. After changing `python/templates/dashboard.html.j2` or `python/_create_dashboard.py`, regenerate `exports/<stem>_analysis/dashboard/<stem>.html`.

### Large sample or empty assembly

Assembly is embedded under a configurable size budget. Large assembly JSON can be omitted or truncated while the rest of the report remains available. Increase the budget only when the resulting HTML size is acceptable.

### External providers fail

Provider failures are recorded in the CTI report. Check logs, provider configuration, proxy/TLS settings, API keys, and network policy. A provider failure does not automatically mean the sample analysis failed.

## Security and responsible use

- Analyze only files you own or have permission to inspect.
- Do not run unknown samples on a normal workstation.
- Use a disposable VM or isolated environment for dynamic testing.
- Treat extracted URLs, domains, and IPs as untrusted data.
- Do not click links from reports automatically.
- Keep CTI keys and logs out of source control.
- Review generated HTML before sharing it because it embeds sample-derived strings and metadata.

## License and repository status

External libraries, rule sets, caches, and vendored data retain their own licenses and notices. Review `.gitignore` and repository status before committing; generated and local files may appear untracked because this working tree may not have a committed Git baseline.

## CTI and network behavior

CTI collection is enabled in the main build through `CTI_WITH_COLLECT`. Providers can perform DNS, RDAP, certificate transparency, IP reputation, vulnerability, or other configured lookups. Provider results are cached under `cache/` and the CTI report is written under `exports/<stem>_analysis/cti/`.

Common configuration categories include API keys, cache directories, proxy/TLS settings, provider enable/disable settings, timeouts, and retries. Use an isolated analysis environment and review provider configuration before enabling external collection. Offline runs represent missing provider data as unknown/skipped rather than fabricating findings.

## Running the analyzer

The command-line interface is positional:

```text
static_analyzer.exe <input-file>
```

Example:

```powershell
.\build-ucrt\static_analyzer.exe .\a.exe
```

With no path, the program defaults to `a.exe` in the current working directory. The analyzer writes results relative to the current working directory, so run it from the repository root unless a different output layout is intentional.

## Analysis phases

The stages run in the order below. The number a stage actually prints is assigned at run time to the stages that apply to this file, so a stage's printed number shifts when an earlier stage is skipped — an ELF's "strings + IOC" prints as `[phase 2/20]` where a PE's prints as `[phase 3/23]`.

| Order | Stage | Applies to |
|---:|---|---|
| 1 | Format-specific section analysis (PE, ELF, or Mach-O) | all |
| 2 | Generic section table, virtual addresses, entropy, chi-squared | formats without a dedicated view |
| 3 | String extraction and IOC classification | all |
| 4 | PE import table (IAT) | PE |
| 5 | MalAPI lookups over the imported function names | PE |
| 6 | ELF/Mach-O GOT and PLT | ELF, Mach-O |
| 7 | Byte histogram and entropy | all |
| 8 | Packer detection | all |
| 9 | Opcode-byte statistics | all |
| 10 | Debug sections and symbols | all |
| 11 | Authenticode/signature checks | all |
| 12 | capa capability analysis | all |
| 13 | radare2 functions and assembly artifacts | all |
| 14 | Graphviz rendering of call graphs and section CFGs | `R2_RENDER` set (see note) |
| 15 | IAT/GOT call-site assembly and cross-references | all |
| 16 | Compilation guards and mitigation flags | all |
| 17 | Export address table (EAT) | PE |
| 18 | YARA rule scan | PE |
| 19 | xxd hex dump | all |
| 20 | cminer code caves | all |
| 21 | Pipeline error recovery and warnings | all |
| 22 | CTI provider collection and correlation | all |
| 23 | Structured artifact export | all |
| 24 | Self-contained HTML dashboard generation | all |
| 25 | Invalid-input sanity checks | all |

Every stage above except Graphviz is gated on the file format alone. Graphviz is the exception: its slot is still counted in the 25/23/20 total, but the stage returns before printing its header unless `R2_RENDER` is set. On a default run, therefore, the printed numbers skip that slot and the last stage reports one less than the total — `[phase 22/23]` for a PE, `[phase 19/20]` for an ELF or Mach-O. Setting `R2_RENDER` (for example `R2_RENDER=svg`) makes the run fill all of its advertised slots.

A stage can be partial when an external dependency, provider, or file feature is missing. The analyzer records warnings and continues where possible; the final result can still be `FAILED` if a required analysis fails.
