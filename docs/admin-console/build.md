# Build identity and tests

<!-- Source: README.md, split by topic. -->

#### Build identity

The **Build** page answers the three questions worth opening it for, in this
order, because they are not independent: a binary built from the wrong commit
passes every functional check there is.

*Identity.* `static_analyzer --version` prints what the executable is, wherever
it ends up, with nothing shipped beside it:

```
static_analyzer 1.0.0+bd93684.dirty (master, C:/…/build-ucrt)
commit    : bd93684266d2dfda0bc865e893ff73f2ad71e0cd
branch    : master  (uncommitted changes at build time)
```

CMake resolves git once at configure time and compiles it in (`IA_BUILD_*`, see
`include/core/build_info.hpp`). `.dirty` is recorded rather than omitted, because
a binary from a dirty tree cannot be reproduced from its commit and the version
string is the only place that fact can live. `GET /api/build/inspect` compares
that against the working tree, and a disagreement is the loudest thing on the
page: you are not running what you just edited.

*Freshness.* Newest mtime under `src/`, `include/`, `CMakeLists.txt` and
`CMakePresets.json` against the executable's, reporting the files that are
newer. `CMakeLists.txt` counts because a changed option changes the binary with
no `.cpp` touching it.

*Validation.* Read-only checks, none of which build or write to the repo:

| check | asserts |
| --- | --- |
| executable | present and non-empty |
| identity | `--version` exits 0 and parses |
| CLI surface | `--list-pipelines` answers |
| fault path | `--crash-demo` exits 0 **and** wrote a report |
| runtime DLLs | every non-API-set import resolves beside the exe or in System32 |

The fault check asserts the report, not just the exit code — a demo that exits 0
having printed nothing has proved nothing. The DLL check is permanent because
this project has already failed that way: Graphviz ships its own `zlib1.dll`, it
sat earlier on `PATH` than the MinGW one, and the analyzer died at load time with
`STATUS_ENTRYPOINT_NOT_FOUND` and no output at all.

`GET /api/build/inspect` returns all three plus the `STATIC_ANALYZER_*` options
read from `CMakeCache.txt`. Those say what was *compiled in*, which is not what
`Build toolchain` says — that one reports what is *installed*. A library present
on disk with its option `OFF` is code that is not in the executable.

#### Running tests from the console

`GET /api/build/tests` returns a catalogue; `POST /api/build/tests` with
`{"ids": [...]}` runs the chosen ones as a job that streams into the same log
pane as a build (the job's `kind` is what tells them apart).

| id | what it runs | touches |
| --- | --- | --- |
| `identity` | `--version` | nothing |
| `cli` | `--version`, `--help`, `--list-phases`, `--list-pipelines` | nothing |
| `crash-demo` | renders the red banner, report and minidump | one crash report |
| `crash-selftest` | dereferences null on purpose | report + minidump, faults |
| `seal` | bundle seal/open round-trip and every tamper case | nothing |
| `analysis` | the default pipeline over the inert fixture | `exports/`, the run log |
| `pytest:<file>` | each `tests/test_*.py` | as that suite declares |

Selection is a multi-select rather than one suite because the entries are not
equivalent: two write files and one runs the analyzer end to end. Each entry
declares what it touches and the UI shows it as a chip, because a generic "Run
tests" button cannot say which of those it is about to do. `crash-selftest`
passes only on exit `0xC0000005` — a clean exit means the handler never ran, so a
clean exit is a failure.

Analyzer-backed entries execute with `IA_ARTIFACT_UPLOAD=0`. That is not
optional: `config/artifacts.yaml` ships `upload_artifacts: true`, so without it a
button in a browser would push an evidence bundle to the operator's cloud
account. The variable only ever turns uploading *off*, so it cannot be used to
defeat the operator's intent — only to override it where it was asked for by
name. It is also what CI should set.

pytest suites are listed whether or not pytest is installed, marked unavailable
with the reason rather than hidden, so their absence is visible instead of
looking like they do not exist. Install with
`python\.venv\Scripts\python.exe -m pip install pytest`.

