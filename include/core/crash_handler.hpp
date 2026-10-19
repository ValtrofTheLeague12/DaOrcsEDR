#pragma once

// Crash capture for the analyzer.
//
// install() registers an unhandled-exception filter (Windows) / fatal signal
// handlers (POSIX) plus std::set_terminate, so an unexpected death writes
//
//   logs/crash/<run_id>-<pid>.txt   symbolized stack, modules, active phase,
//                                   tail of the --debug dump file
//   logs/crash/<run_id>-<pid>.dmp   minidump (Windows), for Windbg/cdb
//
// before the process goes away. The existing logging layer already recovers
// the JSONL run log after a crash; this adds *where* it crashed and *what the
// state was*, which the JSONL alone cannot tell you.

#include <filesystem>
#include <string>
#include <string_view>

namespace crash {

// What install() should and should not let the process do after a fault.
//
// Both default to off. Neither is something to want by accident: one changes a
// machine-level setting, the other changes what happens after the kernel has
// already decided the process is in trouble.
struct options {
  // Keep a dump of the process when it dies.
  //
  // POSIX: raises RLIMIT_CORE's soft limit to the hard limit. Distributions
  // commonly ship a soft limit of 0, which is why "the process crashed and
  // there is no core file" is usually not a bug in the crashing program.
  //
  // Windows: there is no core dump, and WER LocalDumps is not the substitute it
  // looks like - Microsoft's documentation says applications that do their own
  // crash reporting are not supported by it, and this one does. So the flag
  // widens the minidump the analyzer already writes, adding MiniDumpWithFullMemory
  // so it carries the whole address space rather than a minidump selection.
  // Off by default because a full dump is a large file per crash.
  bool allow_core_dump = false;

};

// Registers the handlers. logs_root is where the crash/ directory is created
// (usually the same "logs" root logging::init() writes to), run_id correlates
// the report with the JSONL run log. Safe to call once from main().
void install(const std::filesystem::path& logs_root, std::string_view run_id,
             const options& opts = {});

// Active phase / input sample, printed at the top of every report. Uses fixed
// buffers published atomically so the handler never blocks on a lock that the
// crashing thread may already hold. Call this before each phase starts.
void set_state(std::string_view phase, std::string_view input_path);
std::string state_line();

// Deliberate null dereference used by --crash-selftest to prove the handlers
// and the report paths work. Does not return.
[[noreturn]] void self_test();

// Renders the whole crash presentation - banner, report, trace tail, minidump -
// and RETURNS normally. Used by --crash-demo.
//
// Deliberately separate from self_test(): self_test() proves the handlers fire,
// this proves what an operator will actually see when one does. A handler that
// fires can still print a banner that is empty, mis-centred or the wrong
// colour, and that is only discovered during a real crash unless something
// exercises it deliberately.
void demo();


}  // namespace crash
