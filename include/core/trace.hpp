#ifdef _WIN32
  #include <windows.h>
  #include <psapi.h>
#endif
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
extern "C" void __attribute__((no_instrument_function))
__cyg_profile_func_enter(void *func, void *caller);
extern "C" void __attribute__((no_instrument_function))
__cyg_profile_func_exit(void *func, void *caller);
