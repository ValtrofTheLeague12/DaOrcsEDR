#include <windows.h>
#include <psapi.h>
#include <string>
#include <string_view>

std::string PrintMemoryInfo();
extern "C" void __attribute__((no_instrument_function))
trace_write_text(std::string_view text);
extern "C" void __attribute__((no_instrument_function)) trace_enable();
extern "C" void __attribute__((no_instrument_function)) trace_disable();
extern "C" void __attribute__((no_instrument_function))
__cyg_profile_func_enter(void *func, void *caller);
extern "C" void __attribute__((no_instrument_function))
__cyg_profile_func_exit(void *func, void *caller);

