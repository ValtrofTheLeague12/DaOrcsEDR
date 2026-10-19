# Build panel: provenance, freshness, validation, and a test picker

## Why

The Build page today shows four things: Analysis stack, Build toolchain, Built
executables, Build log. Everything it knows about your binary is its name, size
and mtime.

That is not enough to answer the only three questions anyone actually opens this
page with:

1. **Is what I am running current?**
2. **What exactly is it?**
3. **Does it work?**

And it cannot do anything except build. The admin has to drop to a shell to
check any of that.

## What gets added

### 1. Provenance — "what is this binary?"

`git rev-parse` for branch, commit, dirty state and subject, plus the commit baked
into the binary at compile time (`STATIC_ANALYZER_GIT_*` via CMake), so an
executable identifies itself wherever it ends up:

    static_analyzer --version
    static_analyzer 1.0.0+bd93684.dirty (master)

The panel shows both and compares them. A binary whose baked commit differs from
HEAD is the single most useful fact this page can state, and it is also how you
find out you are running someone else's build.

### 2. Freshness — "is it current?"

Newest mtime under `src/`, `include/`, `CMakeLists.txt`, `CMakePresets.json`
versus the executable's. Reports `stale` plus the N most recent sources that are
newer than the exe, each as a clickable path.

This is not hypothetical: `build-ucrt/pipelines/*.yaml` silently lagging the repo
copy is exactly this failure, and it cost real debugging time.

### 3. Validation — "does it work?"

Read-only checks, each with pass/fail and the captured output:

| check | asserts |
|---|---|
| executable present | the binary exists and is non-empty |
| identity | `--version` exits 0 and parses |
| CLI surface | `--list-phases`, `--list-pipelines`, `--help` all exit 0 |
| fault path | `--crash-demo` exits 0 and writes a crash report |
| runtime DLLs | every imported DLL is present beside the exe |

The DLL check is the `0xC0000139` failure this project already hit once. It is a
permanent check now, not a CMake comment.

### 4. Test picker — "run the test *I* want"

A catalogue the admin selects from, rather than one fixed suite. Each entry says
what it touches, so a destructive test is never a surprise:

| id | kind | side effects |
|---|---|---|
| `identity` | smoke | none |
| `cli` | smoke | none |
| `crash-demo` | smoke | writes one report under `%APPDATA%` |
| `crash-selftest` | smoke | writes report + minidump; faults on purpose |
| `seal` | smoke | none (crypto round-trip, no network) |
| `analysis` | integration | writes `exports/<sample>_analysis/` |
| `analyzer` | integration | writes `exports/` and the run log |
| `pytest:<file>` | pytest | as declared by the file |

Three properties that matter:

- **Selection, not a single target.** Multi-select, run chosen, or run all quick.
- **Side effects are declared per test**, shown as chips, because two of these
  touch disk and one reaches the network.
- **No accidental uploads.** Analyzer runs from the panel execute with
  `IA_ARTIFACT_UPLOAD=0`, a new escape hatch honoured by
  `load_artifact_options()`. Without it, pressing "run analysis test" with
  `upload_artifacts: true` in config would push evidence to MEGA from a browser
  button. CI wants this too.

Runs are jobs, like builds: streamed log, pass/fail per entry, never more than
one at a time.

### 5. Build configuration

The seven CMake options that decide what is compiled in
(`STATIC_ANALYZER_USE_GRAPHVIZ`, `USE_MEGA_SDK`, `LINK_ZSTD`, `STATIC_RUNTIME`,
...) read out of `CMakeCache.txt`. The panel already knows whether Graphviz is
*installed*; this says whether it was *compiled in* — which is the difference
between "the parser exists" and "the parser is in this binary".

## Layout

The page becomes three bands:

1. **Status strip** — provenance, freshness, and an overall verdict chip.
   The answer to "can I trust this binary?" before scrolling.
2. **Checks** — validation results and build configuration, side by side.
3. **Run tests** — the picker, then the job log.

## Files

- `CMakeLists.txt` — bake git identity in; add `IA_ARTIFACT_UPLOAD=0` docs
- `src/main.cpp`, `include/core/build_info.hpp` — `--version`
- `python/panel/build.py` — provenance, freshness, validation, test catalogue,
  test runner
- `python/panel/app.py` — routes
- `admin-web/src/panels/Build.tsx`, `types.ts`, `api.ts` — the UI
- `README.md` — document it

## Not doing

- A second build system. The existing job runner is reused.
- Running the analyzer against real malware from a browser button. The sample is
  the project's own inert fixture, and anything else needs the shell.