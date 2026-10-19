# unit/signals/

`signal_claims.c` — standalone proof of the two claims behind
`--continue-on-signal`.

## Why this is here and not in `c++/`

The continuable-signal handling in `src/core/crash_handler.cpp` lives inside
`#if !defined(_WIN32)`. This project builds with MinGW for Windows, so **the
Windows binary cannot exercise it at all** — `--signal-selftest` reports
"not applicable" and exits 1 there, deliberately, rather than passing
vacuously.

So the claims are checked on a POSIX host instead. This file does not link the
analyzer; it reproduces the same `sigaction` setup and the same
continuable/fault split. That proves the *design*. It does not prove the
integrated binary works, and should not be read as if it did.

## What it proves

1. **Returning from a continuable handler resumes the interrupted work.**
   `raise(SIGUSR1)` with a handler that returns reaches the next line. Raised
   twice to show the disposition is installed *without* `SA_RESETHAND`, because
   these signals are expected repeatedly and each delivery must be reported.

2. **Returning from a fault handler does not recover.** A null store inside a
   `SIGSEGV` handler that returns re-executes the same store, faults again, and
   kills the process. Demonstrated by counting entries and restoring `SIG_DFL`
   on the second, so the experiment shows re-execution without looping forever.

That second claim is the entire reason `SIGSEGV`, `SIGBUS`, `SIGFPE`, `SIGILL`
and `SIGABRT` are excluded from `--continue-on-signal` regardless of how it is
set. Without this, "catch and continue" on a fault is an infinite loop with a
report file — which looks, at a glance, a great deal like a successful
recovery.

## Running it

```powershell
wsl bash -c "cd /mnt/c/Users/The4thReich/Desktop/IAProject/unit/signals && gcc -std=gnu11 -O0 -g -o /tmp/sc signal_claims.c && /tmp/sc"
```

Exit code 0 when every claim holds.

`-std=gnu11`, not `-std=c11`: strict ISO mode hides `sigaction`, `sigemptyset`
and `struct sigaction`, and the file will not compile. Worth knowing for any
POSIX build of the analyzer — the same flag is needed there.

## Two things that bit during writing

Recorded because both produced a test that passed while proving nothing:

- `1 / zero` with `zero` a `volatile int` initialised to `0` was **constant
  folded away** at `-O0`; the division never executed. The divisor now comes
  from `argv`.
- `1 / 0` raises **`SIGFPE`, not `SIGSEGV`**, so the `SIGSEGV` handler never
  ran and the child exited normally. The fault is now a null dereference,
  which does raise `SIGSEGV` on Linux.