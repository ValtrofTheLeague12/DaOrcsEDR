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

### Carrying on when the run is interrupted

Ctrl+C stops a run. That is the right default and it stays the default — but
there are runs where it is the wrong answer: an unattended analysis that takes
an hour, in a CI job, or behind a terminal multiplexer that delivers a signal
nobody meant to send. Losing all of it to a stray Ctrl+C is the expensive kind
of wrong.

`--continue-on-signal` (or `IA_CONTINUE_ON_SIGNAL=1`) changes that. **The first
interrupt is consumed by the run loop, which re-runs the phase it landed on and
carries on with the plan.**

```text
[interrupt] Ctrl+C received - continuing with the next phase.
[interrupt] press Ctrl+C again to stop the run.
[*] interrupted during 'sections'; re-running it and continuing with the plan
```

Cyan rather than amber, because amber means "this is stopping" everywhere else
in this file, and a warning that turns out to be nothing is worse than none.

**Re-running the interrupted phase, rather than skipping past it, is the whole
point.** A phase that was interrupted may have left partial output behind — a
half-written JSON, a truncated artifact — and running the *next* phase over that
is how a report ends up quietly wrong. Starting the interrupted phase again
produces a clean result, at the cost of one phase of work. In the default plan
`sections` is phase 2, so an interrupt there re-runs `sections` and the run
carries on to the end.

**A second interrupt still stops the run**, at the usual next-phase boundary,
with the usual exit 130. There is one rewind per run, not one per interrupt —
otherwise a second Ctrl+C would rewind again and walk the pipeline backwards to
the start. And absorbing every interrupt would leave no way to stop a run that
was not going where the operator wanted, which is the one thing the handler
exists to guarantee.

Underneath it is one flag and one branch in `run_phases()`:

```cpp
if (resume::stop_requested()) {
  if (resume::continues_on_interrupt() && !redone) {
    redone = true;
    resume::clear_interrupt();
    if (step > 0) { --step; /* ... re-runs this phase ... */ }
    continue;
  }
  ctx.interrupted = true;
  break;
}
```

`stop_requested()` is unchanged — it is still a plain "an interrupt arrived".
The loop has to see the first one in order to act on it, so the decision about
what to do with it belongs here, where the phase list is, rather than in the
handler.

### Keeping a dump

`--allow-core-dump` (or `IA_ALLOW_CORE_DUMP=1`), off by default.

**POSIX:** raises `RLIMIT_CORE` soft limit to the hard limit. Distributions
commonly ship a soft limit of 0, which is why there is usually no core file
after a crash — that is not a bug in the program that crashed.

**Windows:** there is no core dump, and WER LocalDumps is not the substitute it
looks like. Microsoft documentation for that feature states that "applications
that do their own custom crash reporting are not supported by", and this
analyzer writes its own minidump from its unhandled-exception filter. A
LocalDumps key would therefore have been a setting that silently does nothing,
plus a registry write on the operator's machine. The flag widens the dump that
already works instead: off, the minidump carries thread info, indirect memory
and unloaded modules; on, it adds `MiniDumpWithFullMemory` and carries the
whole address space. On a small sample that is the difference between 0.2 MB
and 256 MB.

To see the whole crash presentation — banner, report, minidump — without waiting
for a crash, and without faulting:

```powershell
.\build-ucrt\static_analyzer.exe --pipeline quick --crash-demo .\sample.exe
```
