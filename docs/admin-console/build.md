# Build identity and tests

<!-- Source: README.md, split by topic. -->

#### Build identity

The **Build** page answers the three questions worth opening it for, in this
order, because they are not independent: a binary built from the wrong commit
passes every functional check there is. The page is organised into six numbered
sections, in work order: identity, environment, build output, the sample
factory, running a pipeline, and automated tests. The number is the order you
work through them in when something breaks; each section's subtitle is the one
line of why it sits there.

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

#### Binary hardening

This lives on **Analysis Configuration**, not on the Build page, and it answers
a narrower question than `Build configuration` does, and a more consequential
one: *does the binary actually carry the protections the settings ask for?* The
CMake cache records what the build was configured for; the PE header records
what the linker and compiler did. Those two can disagree — a stale binary, a
link line that did not take, a flag the toolchain ignored — and only the second
one is worth trusting.

It is on Analysis Configuration because what it describes is the binary every
analysis on this machine runs, which is the same class of standing question the
rest of that page answers. It is the only card there that edits a build-time
file: the four switches take effect at the **next build** and change nothing
about a run already in progress. That distinction is stated on the card itself
rather than left to be inferred from the file path.

Four protections, each ON by default because MinGW's linker already turns the
first three on and the compiler already supports the fourth:

| setting | what it does | how it shows in the binary |
| --- | --- | --- |
| `aslr` | relocates the image at load time | `IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE` |
| `high_entropy_va` | relocates across the full 64-bit range | `IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA` |
| `dep_nx` | marks the stack and heap non-executable | `IMAGE_DLLCHARACTERISTICS_NX_COMPAT` |
| `stack_protector` | checks a canary on every protected frame | the canary runtime being linked in |

The switches exist to turn a protection **off** deliberately, not to turn one
on. The settings are persisted in `config/hardening.json` — project-wide, not
per-build, so the binary in `build-ucrt/` is the one the file describes. The
panel writes it and `build.ps1` reads it (with `-EnableX`/`-DisableX` overrides
for a single build), so a build from the panel and a build from a terminal
produce the same artefact. The file is tracked in git: a re-clone that silently
reset every protection would produce a binary nobody can tell from a
deliberately weakened one.

*Compliance, not "everything on".* The rows compare *requested* against
*present*, and a protection deliberately turned off that is genuinely absent is
compliance — turning something off is as valid an intent as turning it on. The
only failing state is a mismatch, and its fix is the one instruction the note
carries: **rebuild**.

*Three header bits, one inference.* ASLR, high-entropy VA and DEP/NX are single
bits in `DllCharacteristics`, the word Windows itself reads. The stack
protector has no header bit — it is a compiler feature — so it is inferred from
the canary runtime being linked in. That is a weaker signal, and the card says
so rather than presenting the inference as a header fact: a vendored library can
pull the canary in on its own, so finding the symbol proves the binary *can*
detect an overflow, not that the project's own frames are the ones protected.

`GET /api/build/hardening` returns both halves, and `PUT` writes a partial patch
— only the keys in the body move. Values are `true`/`false` only: a stringified
`"false"` is refused rather than accepted, because a client that stringified its
payload must never silently flip a protection off. A malformed file is refused,
not defaulted away, and an unknown key is refused because it means the file was
written by a different version of the project.

#### The test sample factory

Identity answers what the binary is; the sample factory answers the question
under both: where does a sample come from at all.

Section 4 of the Build page composes an `int main()` - written in C or C++, as
chosen - and compiles it into `samples/<name>.exe` with the same MSYS2 UCRT64
gcc/g++ tree the analyzer build uses, statically linked, so the result runs
without the sysroot's DLLs. The source is rendered from
`python/panel/c2.j2`: the template carries the header, includes, helper
functions, the generated `func_*` block and the `int main` that calls it
(`int main(void)` in C, `int main()` in C++), ending in `return EXIT_SUCCESS`.
The composed source pair (.c/.cpp and .exe) lands in `samples/`, which is
gitignored like every generated artefact tree here; the directory keeps the
newest twelve pairs and prunes the older ones itself.

*Sample name.* The **Sample name** field beside the language buttons sets the
file stem. Leave it blank and the backend names the pair
`<template-id-with-dashes>-<6-digit timestamp fragment>`; type a stem or press
**Generate name** to fill `<language>-<template label>-<6 hex chars>`. The field
accepts letters, digits, dots, dashes and underscores, must start with a letter
or digit, and is capped at 64 characters. An invalid value is marked in the
field and Generate stays disabled, so a name that could escape `samples/` never
reaches the writer.

*Two routes to the same source.* Either pick one of the named templates -
Empty main (the nothing-baseline), String talker, Import talker, Math and
randomness, Loop and arithmetic, Noise only, Memory faults, Loopback socket -
or fill the composition from checkboxes. Templates are exactly bundles of those
checkboxes, and the radio keeps answering which preset - if any - the current
checkbox set matches. The vocabulary is shared by C and C++:

- `strings`, `wide` - Faker strings printed with `puts`, plus one UTF-16
  (`wchar_t`) literal printed with `%ls`.
- `imports` - kernel32 opened with `LoadLibraryA`, `"Sleep"` looked up with
  `GetProcAddress`, the pointer printed, the library freed. The lookup runs;
  the API does not.
- `sus` - **Use suspicious functions**: read-only calls (`GetTickCount`,
  `IsDebuggerPresent`, `GetProcessHeap`, `HeapSize`) plus the heavyweight names
  (`VirtualAlloc`, `WriteProcessMemory`, `CreateRemoteThread`,
  `SetWindowsHookEx`) as inert string literals. Nothing is executed.
- `math`, `random`, `loop` - two arithmetic blocks with their results printed,
  a `srand(time(NULL))` value, and a counted loop that breaks at a drawn
  iteration.
- `buffer_overflow`, `double_free`, `uaf`, `stack_crash`, `integer_overflow` -
  stated fault archetypes: `malloc(8)` then `strcpy` of a longer string, one
  allocation freed twice, a pointer printed after `free`, an 8 MiB local array,
  and `INT_MAX + 1`. They are generated on purpose and labelled as such in the
  source; they are what the crash-detection passes test against.
- `socket` - **Loopback socket**: `WSAStartup` and a connect to `127.0.0.1`
  only, with `-lws2_32` added to the compile. It proves the network pass sees a
  connect without anything external being dialled.
- `noise`, `iocs` - below.

*Noise* plants two literals into the source: a faulty IP drawn from
TEST-NET-3 (RFC 5737, 203.0.113.0/24 - unroutable by design, so the IOC miner
finds a candidate nothing will ever actually dial) and one of the known benign
domains. The pair is drawn at preview time, so the code block on the page
shows the very IP and domain the artefact will contain. Nothing in the
generated source touches the network; every literal is read, none is dialled.

*Seed.* The **Seed** field beside the encoding pins every draw: the noise
pair, the resource picks, each value's encoding, the XOR keys and the generated
variable and function names. Leave it empty and the preview draws a fresh
32-bit seed; the field's note shows the seed that preview used, and Generate
sends that seed back, so the artefact replays the source shown instead of
quietly sampling again. Type a seed to reproduce an earlier sample exactly.
An out-of-range value is refused in the field rather than passed on.

*CodeFactory knobs.* A compact group under the checkbox list exposes the
generator methods' own parameters instead of hiding fixed defaults:

- **Math blocks** - the count handed to `create_math_ops_c`.
- **Loop variables** - `create_random_vars` supplies the independent
  instruction pool; **Body instructions** is how many the loop body draws from
  it through `gen_instruction`, and the loop itself is
  `generate_for_loop` with **Loop count**, **Loop step** and **Break after**
  (0 = never break, blank = draw one).
- **Malloc size** - the `create_malloc_pointer` size used by the overflow,
  double-free and use-after-free archetypes; **Frees** is the free count for
  `create_double_free_issues`.

Blank fields keep the previous default or let the backend draw it. The values
are validated server-side (`compose` refuses an out-of-range knob with a
sentence) and echoed in the preview's `shape`, so a preview and its Generate
press cannot disagree about the shape any more than about the seed.

*Generator resources.* **Resource IOCs** draws one IP and one domain from the
pools an admin maintains in **Utils → Generator resources**, and stores each in
the encoding the select names. While either pool is empty the checkbox is not
hidden - it is shown disabled with the sentence that says which source is
missing, because a vocabulary that changes between visits is harder to trust
than one that explains itself. The preview names the exact value, GitHub source
and encoding behind it, and those are the values the compiled artefact carries.
Resource values are bait literals, not detection rules, and are never dialled.

*IOC encoding.* A select beside the checkbox says how the sampled values are
stored: `plain`, `rot13`, `xor`, `base64`, `chained`, or `mixed` (the default),
which draws a shape per value. `chained` stores XOR(Base64(ROT13(value))) and
the generated source unwinds it in reverse, one labelled stage at a time.
`mixed` never picks an encoding that would leave a value unchanged - ROT13 over
an all-digit IPv4 address is the identity, so that value gets XOR, Base64 or the
chained form - while an explicit `rot13` is honoured as chosen and the select's
note states the limitation. Every encoded value is decoded at runtime before it
is printed; the preview's provenance chips name the encoding each sampled value
actually got.

*Sleep.* A checkbox with a whole-second duration (1-3600) appends a stated
`Sleep(<ms>)` from `<windows.h>` before `return EXIT_SUCCESS`, and adds the
include. The duration is exactly the operator's - no random delay hidden in the
source - and the header comment records it.

*Post-compile flags.* Three checkboxes in the **Build** panel change the artefact
after the compiler succeeds:
- **Pack with UPX** runs the in-tree `upx/upx.exe --best` and reports the
  before/after sizes and ratio. The tool is not on `PATH`: the version that
  packed a sample is the one in the tree. If `upx/upx.exe` is absent the
  checkbox is disabled with that sentence, and Generate refuses before
  compiling rather than failing after. A failed pack keeps the unpacked exe.
- **Strip the import table** zeros the PE optional header's IMPORT and IAT
  data-directory entries (`python/panel/pe_tools.py`). This is destructive by
  design: the Windows loader has no imports to resolve, so the file will not
  run - it crashes before `main`. It is static-analysis bait for the PE and
  YARA passes, not a runnable sample, and both the card and the Generate
  answer say so. With both flags on, UPX runs first and the strip runs second.
- **Write a Makefile** leaves `samples/<name>.mk` beside the source with the
  same `-O0 -g -static` flags, so the artefact can be rebuilt with
  `make -f samples/<name>.mk` after the panel is gone.

*Where it goes.* Generate sets the run card's sample picker to the new .exe; the
pipeline selector on the factory card is the run card's selector - one
shared choice, two views. **Create pipeline** hands off to the Pipelines
Configuration section, to equip or author the pipeline this sample will test.
A stripped sample is still selected there, but running it will fail as
described; the warning above the result is the sentence to read first.

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
optional: the analysis settings say `MEGA_UPLOAD: true`, so without it a button
in a browser would push an evidence bundle to the operator's cloud account. The
variable only ever turns uploading *off*, so it cannot be used to defeat the
operator's intent — only to override it where it was asked for by name. It is
also what CI should set.

pytest suites are listed whether or not pytest is installed, marked unavailable
with the reason rather than hidden, so their absence is visible instead of
looking like they do not exist. Install with
`python\.venv\Scripts\python.exe -m pip install pytest`.


#### Run a pipeline from the console

The Tests section runs *the project's own* samples to verify the code. The
**Run a pipeline** section, at the bottom of the same page, answers the older
question: what does one of the **operator's** pipelines do on one of the
operator's samples, watched live. It starts
`static_analyzer.exe --no-curses --pipeline <name> <sample>` as a job whose
combined output streams into the card - the exact command line and cwd the
analyzer would get in a terminal. The card prints that command under the
selectors: before a run it is a preview built from the chosen pipeline and
sample; once a run exists it is the server's exact argv, including the absolute
executable and the resolved sample path, so the line on screen is the line that
was spawned.

*Choosing.* The pipeline dropdown is the analyzer's own `pipelines/` list, the
same data the Pipelines Configuration page serves - the panel never invents a
name. The sample is a combobox over the executables under the repo's sample
roots (`samples/`, `tests/fixtures/`, `exports/`), so a path that escapes them
cannot be picked in the first place; the run gate re-validates the chosen path
anyway. **Upload** admits an operator's own file into `samples/`: the name rules,
the size cap and the clamd scan all apply, and only a file that passes every
step is offered in the list. When the box is empty, the card seeds it from the
listing - preferring the in-tree fixture under `tests/fixtures/` - so Run does
something sensible before anyone chooses. The Tests section's root-level
`quick_test.exe` fixture is not a valid default here because it sits outside
the run gate's sample roots.

*Reading.* The **Cursor** switch is a display preference, remembered in the
browser, not in the doctrine: with the cursor on, the output streams in the
build-log renderer, kept pinned to the tail with a blinking caret while the
analyzer is speaking; with it off, the identical lines appear in a plain text
area to copy whole. Nothing about what the run *does* depends on the switch.

The panel sets `STATIC_ANALYZER_FORCE_LOGO=1` on the child because captured
stdout is a pipe, where the analyzer normally suppresses its startup banner.
That keeps `logos/daorcs.logo` at the top of the log; a fault still appends the
red `logos/crash.logo` through the normal crash handler.

*Rules of the run.*

- Exactly one run at a time; the refusal names the job in progress.
- `IA_ARTIFACT_UPLOAD=0` is forced on the child, as for the tests above - a
  browser button must not upload evidence anywhere. Upload is the Artifacts
  page's job, on purpose.
- **Uploaded samples land in `samples/`, never in a path the client chooses.**
  The upload route accepts only a file name (no separators or `..`), applies
  the same executable-extension and Win32-name rules as the run gate, streams
  the body under `SAMPLE_UPLOAD_MAX_BYTES`, refuses an existing name rather
  than overwriting it, and quarantines an infected file as evidence. If clamd
  is unreachable the upload is refused; the explicit **Upload without a scan**
  retry is offered only for that refusal and is logged.
- **The duration limit is opt-in.** The **Limit** field beside the Cursor switch
  takes a number of seconds and bounds the run; left blank, the run is unbounded,
  which is the default. A bound is never assumed, because a watchdog that armed
  itself would start killing long-but-legitimate runs whose operator never asked
  for one. The value is kept in the browser alongside the cursor preference - it
  is a standing decision about how this operator runs the analyzer, not the state
  of one run.
- **When the limit is reached, the run is killed.** The analyzer is `terminate()`d
  first - `SIGTERM` on POSIX, which its own handler turns into a flush - and then,
  if it has not exited within a short grace period, `kill()`d outright: `SIGKILL`
  on POSIX, `TerminateProcess` on Windows. Neither the signal nor the kill can be
  caught, which is why the hard kill is the fallback rather than the first move.
  The countdown to the deadline is shown live next to the job's state.
- **A bounded run that hits its limit ends in state `stopped`, not `failed`.** A
  killed child exits non-zero, and reporting that as an analyzer failure would
  blame the binary for a decision the panel made. `timed_out: true` marks it as
  the clock's doing, distinct from a Stop.
- The floor is 10s and the ceiling 24h; anything outside that is refused with the
  reason rather than clamped, so the number shown back is the number that was
  asked for. (`duration: true` is refused too - `isinstance(True, int)` is `True`
  in Python, and a stray boolean must not become a one-second limit.)
- Stop terminates the child the same two-stage way; every line it already printed
  stays on screen. A stop that also wiped the log would destroy the only thing
  worth keeping. A stopped run also reports `stopped`.
- The log keeps head *and* tail with the same 4000-line arithmetic as the
  build log, and reports how many lines were dropped from the head.

