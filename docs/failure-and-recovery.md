# Failure handling and recovery

Exit codes, stopping a run, resuming it, and what a fault prints.

<!-- Source: README.md, split by topic. -->

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

### Stopping a run, and continuing it

Ctrl+C does not kill the run. The handler only raises a flag:

```text
[interrupt] Ctrl+C received - stopping after this phase.
[interrupt] press Ctrl+C again to stop immediately.
```

Both lines are coloured — amber for the one that answers *"did you just stop my
run?"*, dim grey for the hint that follows it, and red for the second-interrupt
notice. The escape sequences are written as string literals in `resume.cpp`
rather than taken from `console::yellow` and friends, even though those are
`inline constexpr` and would cost nothing: this runs from a signal handler on
POSIX, where the one thing a handler must not do is take a lock or reach the
allocator.

Colour needs `ENABLE_VIRTUAL_TERMINAL_PROCESSING`, which `console::enable_utf8_output()`
now sets on **stderr** as well as stdout. The interrupt notice and the whole
crash report go to stderr, and enabling it on stdout alone left every diagnostic
the project cares most about emitting raw escape codes — which is worse than no
colour, because `[33m[interrupt]` reads as garbage rather than as an
admonishment.

The phase loop checks that flag **between phases, never inside one** — a phase can be part way through writing its artifacts, and abandoning it there is how a run leaves a half-written JSON that the next run reads as truth. So the run finishes the phase in flight, prints where it is stopping, writes `run_summary.json` as usual (with `result: "interrupted"` and `exit_code: 130`), and exits **130**, the shell convention for "terminated by SIGINT", so a wrapper script can tell it apart from a failed analysis without parsing the output. A second Ctrl+C stops immediately.

### Two flags for faults

Both are off by default, both are settable from the console's
[Analysis configuration](admin-console/analysis-config.md) page, and both are
read in `main.cpp` in the one window where the pipeline's `environment:` block
has already landed and the handlers are not yet installed.

| Flag | Env var | What it does |
| --- | --- | --- |
| `--allow-core-dump` | `IA_ALLOW_CORE_DUMP` | **POSIX:** raises `RLIMIT_CORE`'s soft limit to the hard limit. Distributions commonly ship a soft limit of 0, which is why there is usually no core file. **Windows:** there is no core dump, so this widens the minidump in `logs/crash/` to carry the whole address space. |
| `--continue-on-signal` | `IA_CONTINUE_ON_SIGNAL` | Report `SIGTERM`, `SIGHUP`, `SIGUSR1` and `SIGUSR2` and carry on instead of dying. |

**Fault signals still terminate, whatever this is set to.** `SIGSEGV`, `SIGBUS`,
`SIGFPE`, `SIGILL` and `SIGABRT` are not notifications that the process is in
trouble — they are reports that it already is. Returning from their handler
re-executes the instruction that faulted, so "continuing" does not resume the
work; it faults again immediately, now from inside the handler. When one of
those arrives with the flag on, the report says so in as many words rather than
terminating silently against an explicit request.

On Windows, `--allow-core-dump` does **not** use WER LocalDumps. Microsoft's
documentation for that feature states that "applications that do their own
custom crash reporting are not supported by", and this analyzer writes its own
minidump from its unhandled-exception filter — so a LocalDumps key would have
been a setting that silently does nothing, plus a registry write on the
operator's machine. The flag widens the dump that already works instead. Off,
the minidump carries thread info, indirect memory and unloaded modules; on, it
adds `MiniDumpWithFullMemory`, which is the whole address space. On a small
sample that is the difference between a 0.2 MB and a 256 MB file.

Where it got to is recorded in `logs/resume/<stem>.json`, keyed by sample so two samples cannot overwrite each other's point:

```json
{ "pipeline": "recon", "input": "quick_test.exe", "run_id": "2e915363e47caa0e",
  "saved_at": 1792169425, "stem": "quick_test",
  "completed": ["sections", "histogram", "packer"] }
```

The checkpoint is written by the planner after each phase returns, not by the signal handler. That is deliberate: a handler-written checkpoint is only correct in the polite case, whereas a planner-written one is also correct after a crash, a kill, or a power cut. The file is deleted when a run reaches the end, so a successful analysis leaves nothing to resume.

```powershell
static_analyzer.exe --pipeline recon quick_test.exe            # interrupted at packer
static_analyzer.exe --pipeline recon --resume quick_test.exe   # sections/histogram/packer skipped
static_analyzer.exe --pipeline recon --from strings quick_test.exe
```

`--resume` reads the checkpoint for the sample in front of it; `--from <phase>` starts the plan at a named phase instead. Both resolve before anything runs, so a bad `--from` is a start-up error rather than a surprise halfway through.

**Resuming is not free, and the run says so.** Results live in `pipeline::context`, not on disk: a phase that is skipped leaves nothing in memory for the phases after it, so anything that declares a prerequisite on a skipped phase runs with less than it expects. The affected phases are named from the catalog's own dependency list rather than guessed at:

```text
[*] resuming: 1 phase(s) already completed, skipping [radare2]
[!] resume is not free: a skipped phase leaves nothing in memory for the phases after it
[!]   'graphs' needs 'radare2', which is being skipped
[!]   'xref' needs 'radare2', which is being skipped
[*] resume from before 'radare2' instead if those results matter
```

`run_summary.json` keeps the two lists apart for the same reason: `phases.ran` is what *this* process executed, `phases.resumed_from` is what it inherited, and a `resume` block records the checkpoint path that got it there. A resumed manifest that claimed the skipped phases ran here would be lying about its own provenance.

### Faults

A fault produces `%APPDATA%\IAProject\logs\crash\<run_id>-<pid>.txt` (reason, active phase, stack, loaded modules, memory map, tail of the debug dump, tail of the trace) and `<run_id>-<pid>.dmp` for the debugger. The report is **printed as well as written** - the file is for later, beside the run log and the minidump; the console copy is for the moment of the fault, where "where did it die and can I resume" should not require opening a file. The trace is flushed from the handler for the same reason: `trace_disable()` never runs on the way out, and without the flush the last megabyte of call graph - the calls immediately before the fault - would never reach the disk.

The first thing printed is the **crash banner**: `logos/crash.logo`, centred in the console and painted red, on stderr. It is deliberately not suppressed when the stream is redirected - the startup logo is, because 30 lines of art in a captured log is noise, but a crash banner in a captured log is the whole point. If `crash.logo` is missing it falls back to `daorcs.logo`, then `pdcursor.logo`, so a crash never prints an empty box; `STATIC_ANALYZER_CRASH_LOGO` overrides the file outright.

Two ways to see it, which prove different things:

| command | faults for real | proves |
|---|---|---|
| `--crash-selftest` | yes (null deref, exit `0xC0000005`) | the handlers and the write path fire |
| `--crash-demo` | no, exits 0 | what an operator will actually *see* |

A handler that fires can still print a banner that is empty, mis-centred or the wrong colour, and that is only discovered during a real crash unless something exercises it deliberately. `--crash-demo` renders the entire presentation - banner, report, memory map, trace tail, minidump - through the real code path with nothing dereferenced; its report is stamped `DEMONSTRATION (no fault occurred)`. It does write real files into `logs/crash/`, because not writing them would mean not testing that step.

### Credentials and network

CTI API keys are read from the environment, or fetched in memory from a running `bw serve` (`CTI_BW_KEYS` names the vault items). A vault value is marked protected, applied with `_putenv_s`, zeroed in memory immediately afterwards, and unset again when the CTI stage ends, so it never rests on disk and does not reach a later child process.

CTI is the only stage that reaches the network, and the only stage that can be switched off wholesale with `CTI_SKIP=1`. When no network is reachable the stage reports that and skips. Because the STIX bundle and the ATT&CK Navigator layer are built from the techniques capa matched rather than from provider answers, both are still produced on a fully offline run.

