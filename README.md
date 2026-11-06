# Static Analyzer Project

A Windows-oriented static-analysis and threat-intelligence dashboard pipeline written in C++20, with Python-based report generation and optional CTI enrichment.

> **Safety note:** this repository is for defensive analysis of files you own or are authorized to inspect. The included EICAR/IOC fixture is deliberately inert and is not malware. EICAR is an industry antivirus test signature, so security software may quarantine the fixture executable.

`static_analyzer.exe` takes one binary path as its input and runs a staged static-analysis pipeline over it: format detection, section and import tables, strings and IOC mining, YARA scanning, capa capability rules, radare2 disassembly, packer and compiler identification, CTI enrichment, an ML verdict, and an artifact set. Nothing is executed.

```powershell
cmake -S . -B build-ucrt
cmake --build build-ucrt --target static_analyzer -j 4
.\build-ucrt\static_analyzer.exe .\a.exe
```

Around that there are three more things, and they are easy to confuse with one
another because none of them is the analyzer:

| | What it is | Where |
| --- | --- | --- |
| **Admin console** | A React web UI served on `127.0.0.1:60100`. Live, interactive, for driving the stack. | `admin-web/`, `python/panel/` |
| **Static-analysis dashboard** | A per-sample HTML report written into `exports/`. A file, not a service. | `exports/<stem>_analysis/` |
| **Admin Terminal** | A TUI menu over the same services. | `admin-terminal/` |

## Documentation

Split by functionality, so you read the part you need and not the other nine
hundred lines. Start at **[docs/README.md](docs/README.md)**.

| Page | Covers |
| --- | --- |
| [Getting started](docs/getting-started.md) | Invoking it, running the analyzer, the Python API server |
| [Pipelines and analysis phases](docs/pipelines-and-phases.md) | The phase catalog, format detection, validation |
| [Evidence bundles, encryption and output](docs/evidence-and-encryption.md) | What is written, and what happens before anything leaves |
| [Admin console](docs/admin-console/README.md) | The web UI — overview, networking, artifacts, analysis configuration, pipelines configuration, build identity, utils |
| [Qiling analysis VM](docs/qiling-vm.md) | The emulated VM and its rootfs |
| [Failure handling and recovery](docs/failure-and-recovery.md) | Exit codes, stopping and resuming a run, faults |
| [Results](docs/results.md) | HTML dashboard, STIX/ATT&CK, assembly collection |
| [Building](docs/building.md) | Requirements, the build, Compose services, layout, tests |
| [Security](docs/security.md) | Scope and responsible use |
| [Troubleshooting](docs/troubleshooting.md) | Common failures |

## Tests

```powershell
python\.venv\Scripts\python.exe -m pytest unit\python -q    # fast: no analyzer needed
cmake --build build-ucrt --target unit_tests                # C++, no framework
python\.venv\Scripts\python.exe -m pytest tests -q          # black-box
```

`unit/README.md` explains which tier a test belongs in. Both suites are
currently green.

## Repository layout

| Area | Paths |
| --- | --- |
| Analyzer and build | `src/`, `include/`, `CMakeLists.txt`, `CMakePresets.json`, `build.ps1` |
| Operator interfaces | `admin-web/`, `python/panel/`, `admin-terminal/`, `admin-panel.ps1` |
| Services and integrations | `python/`, `agent/`, `ml/`, `mega/`, `python/qiling/`, `python/clamd/` |
| Configuration and detection content | `config/`, `pipelines/`, `capa-rules/`, `capa-sigs/`, `yara-rules/`, `data/` |
| Documentation and tests | `docs/`, `unit/`, `tests/`, `tools/`, `COMMANDS.md` |
| Local output | `build-ucrt/`, `exports/`, `logs/`, `artifacts/`, `ressources/` |

These are existing paths used by build scripts and runtime configuration; the
grouping is by responsibility, not by a new directory layout. See
[docs/building.md](docs/building.md#project-structure) for the detailed tree.

Vendored integrations and rules such as `yarGen-Go/`, `malt/`, `kafka-agent/`,
and `yara-rules/` are maintained through the [Utils](docs/admin-console/utils.md)
page rather than by hand.
