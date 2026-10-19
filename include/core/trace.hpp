#ifdef _WIN32
  #include <windows.h>
  #include <psapi.h>
#endif
// <csignal>, not <csginal>: the typo made every translation unit that includes
// this header fail to compile, so the file could only be built on a toolchain
// that shipped a header nobody has asked for. It is included on both the
// Windows and the POSIX branch because the crash handler's signal names below
// the _WIN32 split need sig_atomic_t-like constants either way.
#include <csignal>
#include <string>
#include <string_view>

std::string PrintMemoryInfo();

// Symbol name for an address from the COFF table that trace_enable() loaded
// from the executable, e.g. "analyzer::run_sections(pipeline::context&)".
// Returns "" when the address has no known symbol. Safe to call from a crash
// handler: the table is immutable once loaded and only the returned string
// allocates. The Windows build fills it; other builds return "".
std::string trace_symbolize(const void* address);

extern "C" void __attribute__((no_instrument_function))
trace_write_text(std::string_view text);
extern "C" void __attribute__((no_instrument_function)) trace_enable();
extern "C" void __attribute__((no_instrument_function)) trace_disable();

// Push whatever is buffered to disk without closing the trace.
//
// trace_disable() only runs if the process exits normally, and the buffered
// tail is exactly the part a crash report needs: the calls immediately before
// the fault. The crash handler calls this before it writes anything, so the
// trace it quotes is the trace that existed at the moment of the fault. Cheap
// and idempotent - a no-op when nothing is buffered.
extern "C" void __attribute__((no_instrument_function)) trace_flush();

// Path trace.txt was opened as, or "" when tracing is off. For a crash report
// to name the file it is splicing a tail out of.
std::string trace_path_name();

// Bytes of trace actually written.
//
// NOT the file's length. The file is created at its full 512 MB so it can be
// memory-mapped, and trace_disable() is what truncates it to what was written -
// which never happens on the way out of a fault. Reading a "tail" by file size
// on a crashed run therefore returns megabytes of zeros, which is how a crash
// report ends up with an empty trace section and no explanation.
std::size_t trace_used_bytes();

extern "C" void __attribute__((no_instrument_function))
__cyg_profile_func_enter(void *func, void *caller);
extern "C" void __attribute__((no_instrument_function))
__cyg_profile_func_exit(void *func, void *caller);
