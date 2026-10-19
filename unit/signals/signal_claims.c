// Standalone check of the two claims behind --continue-on-signal.
//
// Built to run under WSL, because the continuable-signal handling in
// crash_handler.cpp is POSIX-only and cannot be exercised by the Windows build
// this project ships. This does not link the analyzer - it reproduces the same
// sigaction setup and the same continuable/fault split, so what it proves is
// the *design*, not the integrated binary.
//
// Claim 1: returning from a continuable handler resumes the interrupted work.
// Claim 2: returning from a FAULT handler re-executes the faulting instruction,
//          so "continue" faults again - which is why SIGSEGV and friends are
//          excluded from the flag no matter how it is set.
//
// Claim 2 is tested by counting entries and restoring SIG_DFL on the second one,
// so the experiment demonstrates re-execution without looping forever.

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

static volatile sig_atomic_t g_usr1_hits = 0;
static volatile sig_atomic_t g_segv_hits = 0;
static volatile int* g_zero_ptr = NULL;

static void on_usr1(int sig) {
  (void)sig;
  g_usr1_hits++;
  // Return. This is the whole of the continuation mechanism.
}

static void on_segv(int sig) {
  (void)sig;
  g_segv_hits++;
  if (g_segv_hits == 1) {
    // First entry: return, exactly as a "continue" handler would.
    return;
  }
  // Second entry proves the first return re-executed the faulting instruction.
  // Give the signal back so this terminates instead of looping.
  signal(SIGSEGV, SIG_DFL);
}

static int is_continuable(int sig) {
  return sig == SIGTERM || sig == SIGHUP || sig == SIGUSR1 || sig == SIGUSR2;
}

// A null dereference through a volatile pointer, so the compiler cannot fold
// it away. (An earlier version used 1/0, which raises SIGFPE rather than the
// SIGSEGV being tested, and so never reached the handler at all.)
__attribute__((noinline)) static void deref_null(volatile int* p) {
  *p = 1;
}

int main(int argc, char** argv) {
  int failures = 0;

  // ---- claim 1 ---------------------------------------------------------
  struct sigaction soft;
  memset(&soft, 0, sizeof soft);
  soft.sa_handler = &on_usr1;
  sigemptyset(&soft.sa_mask);
  soft.sa_flags = 0;
  sigaction(SIGUSR1, &soft, NULL);

  printf("raise(SIGUSR1) with a returning handler...\n");
  raise(SIGUSR1);
  if (g_usr1_hits == 1) {
    printf("  PASS  handler ran once and execution continued past it\n");
  } else {
    printf("  FAIL  handler hits = %d\n", (int)g_usr1_hits);
    failures++;
  }

  // Repeated delivery: the continuable handler must survive being hit again,
  // which is why it is installed without SA_RESETHAND.
  raise(SIGUSR1);
  if (g_usr1_hits == 2) {
    printf("  PASS  a second SIGUSR1 is also survivable (no SA_RESETHAND)\n");
  } else {
    printf("  FAIL  second delivery hits = %d\n", (int)g_usr1_hits);
    failures++;
  }

  // ---- claim 2 ---------------------------------------------------------
  // Runs in a child: the first SIGSEGV entry returns, which re-executes the
  // faulting instruction, so the second entry restores SIG_DFL and dies.
  printf("dereferencing null inside a returning SIGSEGV handler...\n");
  fflush(stdout);
  pid_t pid = fork();
  if (pid == 0) {
    struct sigaction fault;
    memset(&fault, 0, sizeof fault);
    fault.sa_handler = &on_segv;
    sigemptyset(&fault.sa_mask);
    fault.sa_flags = 0;
    sigaction(SIGSEGV, &fault, NULL);

    g_zero_ptr = NULL;
    deref_null(g_zero_ptr);   // faults; handler returns; this STORE RE-RUNS
    _exit(0);                 // only reached if the fault never happened
  }
  int status = 0;
  waitpid(pid, &status, 0);

  if (WIFSIGNALED(status) && WTERMSIG(status) == SIGSEGV) {
    printf("  PASS  the fault re-executed and killed the process anyway "
           "(SIGSEGV re-raised)\n");
    printf("        -> continuing a fault signal is an infinite loop, not a "
           "recovery\n");
  } else if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
    printf("  UNEXPECTED  division completed; the platform does not fault\n");
    failures++;
  } else {
    printf("  NOTE  child ended with status %d (signalled=%d sig=%d)\n",
           status, WIFSIGNALED(status), WIFSIGNALED(status) ? WTERMSIG(status) : 0);
  }

  // ---- the split itself ------------------------------------------------
  const int kContinuable[] = {SIGTERM, SIGHUP, SIGUSR1, SIGUSR2};
  const int kFault[] = {SIGSEGV, SIGBUS, SIGFPE, SIGILL, SIGABRT};
  int ok = 1;
  for (unsigned i = 0; i < sizeof(kContinuable) / sizeof(int); i++)
    if (!is_continuable(kContinuable[i])) ok = 0;
  for (unsigned i = 0; i < sizeof(kFault) / sizeof(int); i++)
    if (is_continuable(kFault[i])) ok = 0;
  if (ok) {
    printf("  PASS  SIGTERM/SIGHUP/SIGUSR1/SIGUSR2 continuable; "
           "SIGSEGV/SIGBUS/SIGFPE/SIGILL/SIGABRT are not\n");
  } else {
    printf("  FAIL  the continuable set is wrong\n");
    failures++;
  }

  printf("\n%s\n", failures == 0 ? "ALL CLAIMS HOLD" : "SOME CLAIMS FAILED");
  return failures;
}