# VMProtect: compatibility evaluation

Status: **evaluated, not implemented.** This page records whether VMProtect can
protect our build, what it would cost us, and what a safe integration would look
like. Nothing here is wired into `build.ps1` yet.

## Verdict

The binary is **compatible**: VMProtect operates on the finished PE, and our
output is a single x86-64 PE built with MinGW-w64 GCC (UCRT64), with the GCC/C++
runtime statically linked. VMProtect's release notes explicitly mention improved
support for MinGW-compiled binaries, and our EXE is not stripped, so functions
can be selected by name in the project file.

The recommendation is **not** whole-binary virtualization. For an analyzer that
runs for minutes per sample, the sensible profile is:

- mutation of `.text`, import protection and output packing, plus
- full virtualization of at most a handful of *small leaf* functions that carry
  a secret, and
- a separate project for QA/lab runs with anti-debug and anti-VM turned **off**.

Prerequisites before this is worth doing: a VMProtect licence (the demo is for
evaluation only) and a code-signing certificate, because protection invalidates
Authenticode and has to be applied *before* signing.

## It does not need a virtual machine

"Virtualization" here is a property of the protected binary, not of the build
machine. VMProtect is a normal Windows application (GUI plus the console build
`VMProtect_Con.exe`) that runs as a post-link step. Selected machine code is
converted into bytecode executed by an interpreter that VMProtect adds to the
EXE. No Hyper-V, VMware, guest OS or extra runtime is involved.

The anti-VM feature works in the opposite direction: it makes the protected
program *detect* that it is running inside a virtual machine. Because we build
for external distribution, that check is wanted in the shipped project and
unwanted in the project used for our own QA runs.

## What the protector sees

| Property | Our build | Relevance |
| --- | --- | --- |
| Format | PE32+ x86-64, single EXE | Supported input |
| Toolchain | MinGW-w64 GCC, UCRT64 preset | Supported; MinGW support has had dedicated fixes |
| Runtime | static GCC/C++ (`STATIC_ANALYZER_STATIC_RUNTIME=ON`) | No DLL dependency to preserve |
| Size | `build-ucrt/static_analyzer.exe`, ~187 MB | Accepted; protection time and added sections scale with size |
| Symbols | not stripped (`run_ml_score` is present in the image) | Name-based function selection works |
| Other targets | `sample_archive`, `dot2json`, ... | Leave unprotected; only the analyzer ships |
| Dependencies | LIEF, capstone, yara, OpenSSL, libmagic, re2 — all static | No interaction with the protector |

## Risks measured against this codebase

| Risk | Evidence in the tree | Mitigation |
| --- | --- | --- |
| C++ exceptions through virtualized frames | ~70 `try` blocks across 54 `.cpp` files | Do not virtualize functions that throw or catch; use mutation there |
| Thread-local storage | 5 `thread_local` sites | Never virtualize CRT init, TLS initialisation or TLS accessors |
| Analysis throughput | every run performs heavy parsing, YARA, ML scoring | Virtualize only cold, small functions; never the phase hot path |
| Anti-debug/anti-VM vs our own lab | the analyzer is deployed into analysis VMs | Ship a second project with those checks disabled for QA and lab use |
| AV/EDR false positives | packed + virtualized + anti-debug equals malware heuristics | Scan the protected build with Defender and our own YARA packs before release |
| Our own detections | `src/extractor.cpp` flags `.vmp0`/`.vmp1` sections on samples | Protected analyzer will be described as packed if it is ever analysed as a sample |
| Crash diagnostics | minidump/`--crash-selftest` symbolication | Accept degraded stacks inside virtualized functions; keep them few |
| Reproducible bytes | build identity is commit/`--version` based, not hash based | Unaffected; but binary hashes change on every protection run |
| Authenticode | VMProtect rewrites the image | Sign **after** protection; `signtool` is not installed on this machine yet |
| Cost | commercial licence; Ultimate edition adds a serial-key licensing system | Budget decision; the demo is evaluation-only |

## Recommended profile (external distribution)

| Option | Setting | Reason |
| --- | --- | --- |
| Compilation type, whole file | Mutation | Cheap, no unwind changes outside marked functions |
| Compilation type, selected functions | Virtualization | Only 1–3 small leaf functions that hold a secret |
| Import protection | On | Hides the API surface cheaply |
| Resource protection | Off | We ship no protected resources worth the breakage |
| Pack the output | On | Compresses the 187 MB image |
| Memory protection | On | Raises the cost of runtime dumping |
| Anti-debug | On | External distribution |
| Anti-VM | On in the shipped project, off in the QA project | Avoids fighting our own hypervisors during testing |
| Debug information | Build with symbols for selection, ship stripped | Symbols in the distributed file undo much of the work |

If a native secret is ever added (serial check, bundle-seal key derivation,
integrity self-check), virtualize exactly that function and nothing else. Today
the valuable logic lives in the Python panel and in `ml/`, which VMProtect
cannot touch — see below.

## What this does not protect

- **Python panel / admin server.** VMProtect is native-only. That side would
  need a different tool (PyArmor, Nuitka) if it ever needs protection.
- **`ml/model.txt` and the corpus.** The model is a separate 37 MB file loaded
  at runtime; protecting the EXE says nothing about the weights.
- **Configuration and pipelines.** YAML files are data.
- **Secrets at rest.** Keys in `mega/`, the evidence bundle format and its
  documentation remain readable.

## Evaluation plan without a licence

1. Install the current VMProtect Ultimate demo (Windows build) on the build
   machine. Treat any finding as provisional: demo builds are limited and are
   not licensed output.
2. Protect a copy of `build-ucrt/static_analyzer.exe` with mutation + import
   protection only, then with one virtualized leaf function.
3. Run the acceptance checks: `--version`, `--list-pipelines`,
   `--crash-selftest`, one full pipeline on `quick_test.exe`, one run with ML
   scoring enabled, and the admin console's "run a pipeline" card.
4. Record wall-clock deltas against the unprotected binary on the same sample.
5. Scan the protected binary with Windows Defender and with our own YARA packs;
   record what fires.
6. Trigger a crash and compare minidump stack quality.

If the demo cannot run these checks meaningfully, stop here until a licence is
purchased.

## Integration sketch (only after approval)

- `build.ps1 -Protect` runs `VMProtect_Con.exe` after `cmake --build` and writes
  `build-ucrt/static_analyzer.protected.exe`; the raw EXE stays untouched for
  tests and the console.
- The protection settings live in a checked-in `.vmp` project (XML), created
  once in the GUI so the schema is guaranteed to match the installed version.
  A project file generated by hand is not worth the risk of a silent
  misconfiguration.
- The protector path comes from `$env:VMPROTECT_CON` with a documented default;
  a missing protector fails the build loudly instead of shipping an unprotected
  artifact.
- An optional `-Sign` step runs `signtool` on the protected output.
- Two projects: `distribution` (anti-debug/anti-VM on) and `qa` (both off).

## Decision checklist

- [ ] Licence purchased, or evaluation explicitly time-boxed with the demo
- [ ] Code-signing certificate available (otherwise SmartScreen warns on every
      download)
- [ ] A concrete native secret worth virtualizing, or accept mutation-only
- [ ] QA/lab project with anti-debug and anti-VM disabled
- [ ] Acceptance run includes one real pipeline and one ML-scored sample
