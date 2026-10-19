#include "crash_handler.hpp"

#include "debug_dump.hpp"

#include <atomic>
#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <exception>
#include <string>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <dbghelp.h>
#include <psapi.h>
#else
#include <csignal>
#include <unistd.h>

// For enable_core_dump(): RLIMIT_CORE, and the soft/hard pair that has to be
// raised together. Only on the POSIX side - the Windows branch writes a
// registry key instead and needs neither.
#include <sys/resource.h>

#if defined(__has_include)
#if __has_include(<execinfo.h>)
#include <execinfo.h>
#define CRASH_HAVE_BACKTRACE 1
#endif
#endif
#endif

#include "banner.hpp"
#include "trace.hpp"
#include "resume.hpp"

namespace {

constexpr std::size_t k_max_stack = 64;
constexpr std::size_t k_dump_tail_bytes = 8u * 1024u;
// Enough of the tail to show the call sequence that led into the fault. Bigger
// than the dump tail on purpose: a call graph is only useful when several
// frames of context are visible around the break.
constexpr std::size_t k_trace_tail_bytes = 64u * 1024u;
// The report is printed as well as written; a console operator who just hit a
// crash should not have to go and open a file to find out what happened. The
// body is capped so a fault inside a phase that fills the trace cannot bury the
// first screenful under 512 MB of call graph.
constexpr std::size_t k_max_printed_bytes = 96u * 1024u;

std::atomic<bool> g_installed{false};
std::atomic<bool> g_handling{false};
std::filesystem::path g_crash_dir;
std::string g_run_id;

// Phase/input state: fixed buffers + atomically published lengths, so the
// handler can read them without ever taking a mutex (the crashing thread may
// be the one holding it).
std::atomic<std::uint32_t> g_phase_len{0};
std::atomic<std::uint32_t> g_input_len{0};
constexpr std::size_t k_phase_cap = 127;
constexpr std::size_t k_input_cap = 511;
char g_phase[k_phase_cap + 1] = {};
char g_input[k_input_cap + 1] = {};

std::string iso_now() {
  using namespace std::chrono;
  const std::time_t t = system_clock::to_time_t(system_clock::now());
  std::tm tm{};
#if defined(_WIN32)
  localtime_s(&tm, &t);
#else
  localtime_r(&t, &tm);
#endif
  char buf[32];
  std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &tm);
  return buf;
}

std::string sanitized_run_id() {
  std::string out;
  out.reserve(g_run_id.size());
  for (char c : g_run_id) {
    const bool ok = std::isalnum(static_cast<unsigned char>(c)) != 0 || c == '-' ||
                    c == '_' || c == '.';
    out.push_back(ok ? c : '_');
  }
  if (out.empty()) out = "run";
  return out;
}

unsigned long current_pid() {
#if defined(_WIN32)
  return static_cast<unsigned long>(GetCurrentProcessId());
#else
  return static_cast<unsigned long>(::getpid());
#endif
}

std::FILE* open_file(const std::filesystem::path& path, const char* mode) {
#if defined(_WIN32)
  const std::wstring wmode(mode, mode + std::strlen(mode));
  return _wfopen(path.wstring().c_str(), wmode.c_str());
#else
  return std::fopen(path.string().c_str(), mode);
#endif
}

bool write_file(const std::filesystem::path& path, const std::string& body) {
  std::FILE* f = open_file(path, "wb");
  if (f == nullptr) return false;
  const bool ok =
      body.empty() || std::fwrite(body.data(), 1, body.size(), f) == body.size();
  std::fflush(f);
  std::fclose(f);
  return ok;
}

// Last max_bytes of a file - used to splice the dump and trace tails into the
// report. `end` overrides where "the end" is, which matters for the trace: its
// file is pre-sized to the whole 512 MB buffer and only trace_disable()
// truncates it, so on a crashed run the file's length is the buffer's and a
// tail taken from there is megabytes of zeros.
std::string file_tail(const std::filesystem::path& path, std::size_t max_bytes,
                      std::size_t end = 0) {
  std::string out;
  std::FILE* f = open_file(path, "rb");
  if (f == nullptr) return out;
  if (std::fseek(f, 0, SEEK_END) == 0) {
    const long size = std::ftell(f);
    long stop = end > 0 ? static_cast<long>(end) : size;
    if (stop > size) stop = size;
    const long want = static_cast<long>(max_bytes);
    std::fseek(f, stop > want ? stop - want : 0, SEEK_SET);
    char buf[4096];
    std::size_t n;
    while ((n = std::fread(buf, 1, sizeof(buf), f)) > 0) out.append(buf, n);
  }
  std::fclose(f);
  return out;
}

#if defined(_WIN32)

std::string hex64(std::uint64_t value) {
  char buf[32];
  std::snprintf(buf, sizeof(buf), "0x%016llx", static_cast<unsigned long long>(value));
  return buf;
}

std::string module_path_of(void* address) {
  HMODULE mod = nullptr;
  if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                             GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                         reinterpret_cast<LPCSTR>(address), &mod) &&
      mod != nullptr) {
    char path[MAX_PATH] = {};
    if (GetModuleFileNameA(mod, path, MAX_PATH) > 0) return path;
  }
  return {};
}

// Walks the faulting thread's stack with dbghelp (line/symbol info when the
// exe still has its COFF table) and falls back to the COFF table trace.cpp
// already loaded, which works even when SymFromAddr does not.
void append_stack(std::string& out, EXCEPTION_POINTERS* ep) {
  out += "stack:\n";

  CONTEXT fallback{};
  CONTEXT* ctx = (ep != nullptr && ep->ContextRecord != nullptr) ? ep->ContextRecord
                                                                 : &fallback;
  if (ctx == &fallback) RtlCaptureContext(&fallback);

  const HANDLE proc = GetCurrentProcess();
  const HANDLE thread = GetCurrentThread();

  SymSetOptions(SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_LINES | SYMOPT_UNDNAME);
  const bool sym_ok = SymInitialize(proc, nullptr, TRUE);

  STACKFRAME64 frame{};
  DWORD machine = IMAGE_FILE_MACHINE_I386;
#if defined(_M_X64) || defined(__x86_64__)
  machine = IMAGE_FILE_MACHINE_AMD64;
  frame.AddrPC.Offset = ctx->Rip;
  frame.AddrStack.Offset = ctx->Rsp;
  frame.AddrFrame.Offset = ctx->Rbp;
#else
  frame.AddrPC.Offset = ctx->Eip;
  frame.AddrStack.Offset = ctx->Esp;
  frame.AddrFrame.Offset = ctx->Ebp;
#endif
  frame.AddrPC.Mode = AddrModeFlat;
  frame.AddrStack.Mode = AddrModeFlat;
  frame.AddrFrame.Mode = AddrModeFlat;

  alignas(SYMBOL_INFO) char sym_buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME] = {};
  SYMBOL_INFO* sym = reinterpret_cast<SYMBOL_INFO*>(sym_buffer);
  sym->SizeOfStruct = sizeof(SYMBOL_INFO);
  sym->MaxNameLen = MAX_SYM_NAME;

  for (int i = 0; i < static_cast<int>(k_max_stack); ++i) {
    if (!StackWalk64(machine, proc, thread, &frame, ctx, nullptr,
                     SymFunctionTableAccess64, SymGetModuleBase64, nullptr)) {
      break;
    }
    const std::uint64_t pc = frame.AddrPC.Offset;
    if (pc == 0) break;

    std::string name;
    if (sym_ok) {
      DWORD64 displacement = 0;
      if (SymFromAddr(proc, pc, &displacement, sym) && sym->Name[0] != '\0') {
        name = sym->Name;
        if (displacement != 0) {
          char disp[32];
          std::snprintf(disp, sizeof(disp), " + 0x%llx",
                        static_cast<unsigned long long>(displacement));
          name += disp;
        }
      }
    }
    const std::string coff =
        trace_symbolize(reinterpret_cast<const void*>(static_cast<std::uintptr_t>(pc)));
    if (name.empty()) name = coff;
    else if (!coff.empty() && coff != name) name += " / " + coff;

    const std::string module = module_path_of(reinterpret_cast<void*>(
        static_cast<std::uintptr_t>(pc)));
    std::string module_label = module;
    const std::size_t slash = module.find_last_of("\\/");
    if (slash != std::string::npos) module_label = module.substr(slash + 1);

    char line[1024];
    std::snprintf(line, sizeof(line), "  #%-2d %-18s %-38s %s\n", i, hex64(pc).c_str(),
                  module_label.empty() ? "?" : module_label.c_str(), name.c_str());
    out += line;
  }

  if (sym_ok) SymCleanup(proc);
}

void append_modules(std::string& out) {
  out += "modules:\n";
  const HANDLE proc = GetCurrentProcess();
  HMODULE modules[256] = {};
  DWORD needed = 0;
  if (!EnumProcessModulesEx(proc, modules, sizeof(modules), &needed,
                            LIST_MODULES_ALL)) {
    out += "  (EnumProcessModulesEx failed)\n";
    return;
  }
  DWORD count = needed / sizeof(HMODULE);
  if (count > sizeof(modules) / sizeof(HMODULE)) {
    count = sizeof(modules) / sizeof(HMODULE);
  }
  for (DWORD i = 0; i < count; ++i) {
    char path[MAX_PATH] = {};
    GetModuleFileNameA(modules[i], path, MAX_PATH);
    MODULEINFO info{};
    GetModuleInformation(proc, modules[i], &info, sizeof(info));
    char line[600];
    std::snprintf(line, sizeof(line), "  %s .. %s  %s\n",
                  hex64(reinterpret_cast<std::uintptr_t>(info.lpBaseOfDll)).c_str(),
                  hex64(reinterpret_cast<std::uintptr_t>(info.lpBaseOfDll) +
                        info.SizeOfImage)
                      .c_str(),
                  path);
    out += line;
  }
}

std::string exception_text(EXCEPTION_POINTERS* ep) {
  if (ep == nullptr || ep->ExceptionRecord == nullptr) return "no exception record";
  const DWORD code = ep->ExceptionRecord->ExceptionCode;
  const void* address = ep->ExceptionRecord->ExceptionAddress;

  char code_text[32];
  std::snprintf(code_text, sizeof(code_text), "0x%08lX",
                static_cast<unsigned long>(code));

  const char* name = nullptr;
  switch (code) {
    case EXCEPTION_ACCESS_VIOLATION:      name = "EXCEPTION_ACCESS_VIOLATION"; break;
    case EXCEPTION_ILLEGAL_INSTRUCTION:   name = "EXCEPTION_ILLEGAL_INSTRUCTION"; break;
    case EXCEPTION_INT_DIVIDE_BY_ZERO:    name = "EXCEPTION_INT_DIVIDE_BY_ZERO"; break;
    case EXCEPTION_STACK_OVERFLOW:        name = "EXCEPTION_STACK_OVERFLOW"; break;
    case EXCEPTION_BREAKPOINT:            name = "EXCEPTION_BREAKPOINT"; break;
    case EXCEPTION_DATATYPE_MISALIGNMENT: name = "EXCEPTION_DATATYPE_MISALIGNMENT"; break;
    default: break;
  }

  std::string text = code_text;
  if (name != nullptr) {
    text += " (";
    text += name;
    text += ")";
  }
  char at_text[40];
  std::snprintf(at_text, sizeof(at_text), " at %p", address);
  text += at_text;

  // AV and friends carry the faulting address as ExceptionInformation[1].
  if (ep->ExceptionRecord->NumberParameters >= 2) {
    char fault_text[40];
    std::snprintf(fault_text, sizeof(fault_text), ", fault address 0x%llx",
                  static_cast<unsigned long long>(
                      ep->ExceptionRecord->ExceptionInformation[1]));
    text += fault_text;
  }
  return text;
}

// Set by install() when a full dump was asked for, read by write_minidump().
// Read on the crashing thread, written before any fault can happen.
std::atomic<bool> g_full_dump{false};

void write_minidump(const std::filesystem::path& path, EXCEPTION_POINTERS* ep) {
  const HANDLE file =
      CreateFileW(path.wstring().c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                  FILE_ATTRIBUTE_NORMAL, nullptr);
  if (file == INVALID_HANDLE_VALUE) return;

  MINIDUMP_EXCEPTION_INFORMATION info{};
  MINIDUMP_EXCEPTION_INFORMATION* info_ptr = nullptr;
  if (ep != nullptr) {
    info.ThreadId = GetCurrentThreadId();
    info.ExceptionPointers = ep;
    info.ClientPointers = FALSE;
    info_ptr = &info;
  }
  MINIDUMP_TYPE flags = static_cast<MINIDUMP_TYPE>(
      MiniDumpWithThreadInfo | MiniDumpWithIndirectlyReferencedMemory |
      MiniDumpWithUnloadedModules);
  // Widened only when crash::options::allow_core_dump asked for it. The default
  // selection above is a few MB and is enough to see the stack and the objects
  // near it; FullMemory is the entire address space and is a large file, which
  // is exactly why it is not the default.
  if (g_full_dump.load(std::memory_order_relaxed)) {
    flags = static_cast<MINIDUMP_TYPE>(flags | MiniDumpWithFullMemory |
                                       MiniDumpWithFullMemoryInfo);
  }
  MiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(), file, flags, info_ptr,
                    nullptr, nullptr);
  CloseHandle(file);
}

#endif  // _WIN32

#if !defined(_WIN32)
void append_stack(std::string& out, const void*) {
  out += "stack:\n";
#if defined(CRASH_HAVE_BACKTRACE)
  void* frames[k_max_stack] = {};
  const int count = ::backtrace(frames, static_cast<int>(k_max_stack));
  char** symbols = ::backtrace_symbols(frames, count);
  for (int i = 0; i < count; ++i) {
    char line[512];
    if (symbols != nullptr && symbols[i] != nullptr) {
      std::snprintf(line, sizeof(line), "  #%-2d %s\n", i, symbols[i]);
    } else {
      std::snprintf(line, sizeof(line), "  #%-2d %p\n", i, frames[i]);
    }
    out += line;
  }
  std::free(symbols);
#else
  out += "  (no backtrace support in this build)\n";
#endif
}

const char* signal_text(int sig) {
  switch (sig) {
    case SIGSEGV: return "SIGSEGV (segmentation fault)";
    case SIGBUS:  return "SIGBUS (bad memory access)";
    case SIGFPE:  return "SIGFPE (arithmetic fault)";
    case SIGILL:  return "SIGILL (illegal instruction)";
    case SIGABRT: return "SIGABRT (abort)";
    default:      return "fatal signal";
  }
}
#endif  // !_WIN32

// Assembles the report. arch is EXCEPTION_POINTERS* on Windows and unused
// elsewhere; every step is best-effort, a failure only loses a section.
void build_report(const char* reason, const char* detail, const void* arch) {
  std::string body;
  try {
    // The banner goes up BEFORE anything else, including the trace flush. It is
    // the one part of the output an operator can read at a glance, and it costs
    // one small file read.
    banner::print_crash_banner();

    // Push whatever the tracer has buffered to disk. On Windows the trace lives
    // in a mapped view that is only flushed a megabyte at a time, so a fault
    // could otherwise cost us exactly the frames that explain it.
    trace_flush();

    body += "static_analyzer crash report\n";
    body += "=============================\n";
    body += std::string("reason   : ") + reason + "\n";
    if (detail != nullptr && detail[0] != '\0') {
      body += std::string("detail   : ") + detail + "\n";
    }
    body += "time     : " + iso_now() + "\n";
    body += "run_id   : " + g_run_id + "\n";
    body += "pid      : " + std::to_string(current_pid()) + "\n";
    body += "state    : " + crash::state_line() + "\n";

    const std::string dump_path = debug_dump::log_path();
    body += "dump     : " + (dump_path.empty() ? std::string("(disabled)")
                                               : dump_path) +
            "\n";
    body += "log dir  : " + g_crash_dir.string() + "\n";
    // The resume point is written after every completed phase, so it is already
    // correct here - naming it in the report is what turns "the run died" into
    // "the run died, and here is how much of it survived".
    body += "resume   : " + resume::describe() + "\n";
    body += "\n";

#if defined(_WIN32)
    append_stack(body, static_cast<EXCEPTION_POINTERS*>(
                           const_cast<void*>(arch)));
    body += "\n";
    append_modules(body);
    body += "\n";
#else
    append_stack(body, arch);
    body += "\n";
#endif

    if (!dump_path.empty()) {
      const std::string tail = file_tail(dump_path, k_dump_tail_bytes);
      if (!tail.empty()) {
        body += "tail of debug dump:\n";
        body += tail;
        if (body.back() != '\n') body += "\n";
        body += "---- end of dump tail ----\n";
      }
    }

    // The trace tail. This is the part that was at risk of being lost:
    // trace_disable() never runs on the way out of a fault, so without the
    // flush above the last megabyte of call graph - the calls immediately
    // before the fault - would never have reached the disk.
    {
      const std::string trace_path = trace_path_name();
      if (!trace_path.empty()) {
        const std::filesystem::path trace_file(trace_path);
        std::error_code ec;
        const auto on_disk = std::filesystem::file_size(trace_file, ec);
        // What the tracer says it wrote, not what the file is sized to.
        const std::size_t used = trace_used_bytes();
        if (!ec && used > 0) {
          const std::string tail = file_tail(trace_file, k_trace_tail_bytes, used);
          if (!tail.empty()) {
            body += "\ntail of trace (" + std::to_string(used) +
                    " bytes written, showing the last " +
                    std::to_string(std::min<std::size_t>(used, k_trace_tail_bytes)) +
                    "):\n";
            body += tail;
            if (body.back() != '\n') body += "\n";
            body += "---- end of trace tail ----\n";
          }
        } else if (used == 0) {
          body += "\ntrace    : " + trace_path +
                  " (nothing written before the fault)\n";
        } else if (ec) {
          body += "\ntrace    : " + trace_path + " (unreadable: " + ec.message() + ")\n";
        } else {
          body += "\ntrace    : " + trace_path + " (empty, on-disk size " +
                  std::to_string(on_disk) + ")\n";
        }
      }
    }
  } catch (...) {
    body += "\n(report truncated: out of memory while building it)\n";
  }

  const std::string stem =
      sanitized_run_id() + "-" + std::to_string(current_pid());
  const std::filesystem::path text_path = g_crash_dir / (stem + ".txt");
  const bool wrote = write_file(text_path, body);

  // Printed as well as written.
  //
  // The file is for later, when there is time to read it in an editor with the
  // run log and the minidump beside it. This is for the moment of the fault,
  // where the operator is looking at a console that has just stopped and the
  // question is "where did it die and can I resume". Answering that only by
  // naming a path means the answer is on the other side of opening a file.
  {
    std::string shown = body;
    if (shown.size() > k_max_printed_bytes) {
      // Keep the head: reason, state, stack, modules. The tail is the trace,
      // which is also in the file.
      shown = body.substr(0, k_max_printed_bytes);
      shown += "\n... [report truncated on the console; the full text is in the file below] ...\n";
    }
    std::fputs("\n", stderr);
    std::fputs(shown.c_str(), stderr);
    std::fflush(stderr);
  }

#if defined(_WIN32)
  const std::filesystem::path dump_file = g_crash_dir / (stem + ".dmp");
  write_minidump(dump_file, static_cast<EXCEPTION_POINTERS*>(
                                const_cast<void*>(arch)));
#endif

  if (wrote) {
    std::fprintf(stderr, "[crash] full report written to '%s'\n", text_path.string().c_str());
  } else {
    std::fprintf(stderr, "[crash] could not write '%s' (the report above is all "
                         "there is)\n", text_path.string().c_str());
  }
#if defined(_WIN32)
  std::fprintf(stderr, "[crash] minidump: '%s'\n", dump_file.string().c_str());
#endif
  // The point of the checkpoint is that it survives this, so the operator is
  // told exactly how to use it rather than being left to find it.
  {
    const std::size_t input_len = g_input_len.load(std::memory_order_acquire);
    const std::string sample = input_len > 0 ? std::string(g_input, input_len) : std::string();
    std::fprintf(stderr,
                 "[crash] phases that finished are recorded; resume with:\n"
                 "[crash]   static_analyzer%s%s --resume\n",
                 sample.empty() ? "" : " ", sample.c_str());
  }
  std::fflush(stderr);
}

// Published from install() and read from the signal handler, which is on
// another thread by the time it matters. Relaxed is enough: the only ordering
// requirement is that a signal arriving after install() returns sees the value
// install() stored.
std::atomic<bool> g_continue_after_signal{false};

// Bumped by the handler on the path where it returns instead of exiting. This is
// the only way to observe that continuation actually happened, rather than
// inferring it from the process still being alive.
std::atomic<int> g_signal_continuations{0};

// Single entry point: guards against recursion and writes the report once.
void report_once(const char* reason, const char* detail, const void* arch) {
  if (g_handling.exchange(true)) return;
  build_report(reason, detail, arch);
}

void on_terminate() {
  const char* detail = nullptr;
  std::string message;
  try {
    if (std::current_exception()) std::rethrow_exception(std::current_exception());
  } catch (const std::exception& e) {
    message = std::string("unhandled std::exception: ") + e.what();
    detail = message.c_str();
  } catch (...) {
    detail = "unhandled non-std exception";
  }
  report_once("std::terminate", detail, nullptr);
  std::abort();
}

void enable_core_dump(bool want) {
  if (!want) return;
#if defined(_WIN32)
  // Windows has no core dump, and WER LocalDumps is not the substitute it looks
  // like: Microsoft's own documentation states that "applications that do
  // their own custom crash reporting are not supported by this feature", and
  // this analyzer writes its own minidump from its unhandled-exception filter.
  // Writing a LocalDumps key here would have created a setting that silently
  // does nothing - and worse, a registry write on the user's machine.
  //
  // So the flag does the thing that actually works here: it widens the dump
  // the analyzer already writes. Off, that is a minidump with thread info,
  // indirect memory and unloaded modules. On, it adds MiniDumpWithFullMemory,
  // which is the full-address-space dump - much larger, but it shows the heap,
  // which is usually where a crash has to be understood from.
  g_full_dump.store(true, std::memory_order_relaxed);
  std::fprintf(stderr, "[crash] full dumps enabled (logs/crash/*.dmp will carry "
                       "the whole address space, not just the minidump selection)\n");
#else
  struct rlimit limit{};
  if (getrlimit(RLIMIT_CORE, &limit) != 0) {
    std::fprintf(stderr, '[crash] core dump requested but RLIMIT_CORE could not '
                         'be read; no core file will be written\n');
    return;
  }
  if (limit.rlim_cur < limit.rlim_max) {
    limit.rlim_cur = limit.rlim_max;
    if (setrlimit(RLIMIT_CORE, &limit) != 0) {
      std::fprintf(stderr, '[crash] core dump requested but RLIMIT_CORE could not '
                           'be raised; no core file will be written\n');
      return;
    }
  }
  std::fprintf(stderr, '[crash] core dumps enabled (RLIMIT_CORE raised to %llu)\n',
               static_cast<unsigned long long>(limit.rlim_cur));
#endif
  std::fflush(stderr);
}

#if defined(_WIN32)

LONG WINAPI on_unhandled_exception(EXCEPTION_POINTERS* ep) {
  const std::string text = exception_text(ep);
  report_once("unhandled structured exception", text.c_str(), ep);
  return EXCEPTION_EXECUTE_HANDLER;
}

#else

// Signals that mean "something happened" rather than "the process is broken".
// Returning from these is safe: the interrupted instruction runs again.
bool is_continuable(int sig) {
  return sig == SIGTERM || sig == SIGHUP || sig == SIGUSR1 || sig == SIGUSR2;
}

void on_signal(int sig) {
  if (g_handling.load(std::memory_order_acquire)) {
    // Recursion (e.g. a second fatal signal while the report was being
    // written): hand the signal back to the kernel so the real cause is not
    // hidden behind a nested report.
    std::signal(sig, SIG_DFL);
    std::raise(sig);
    ::_exit(128 + sig);
  }
  report_once(signal_text(sig), "fatal signal received", nullptr);

  if (g_continue_after_signal.load(std::memory_order_acquire) && is_continuable(sig)) {
    // Return, and the interrupted work resumes. The report has been written;
    // the run carries on and the fault is in the record rather than at the
    // end of it.
    g_signal_continuations.fetch_add(1, std::memory_order_relaxed);
    return;
  }
  if (g_continue_after_signal.load(std::memory_order_acquire) && !is_continuable(sig)) {
    // The operator asked to continue, but this is one of the four that cannot
    // be continued - returning would re-execute the faulting instruction. Say
    // so in the record rather than exiting silently against an explicit
    // request, because the obvious next question is "why did my flag not work".
    std::fprintf(stderr,
                 "[crash] catch-and-continue was requested but %s is a fault "
                 "signal: returning from its handler re-executes the faulting "
                 "instruction, so the process is terminating. Continuable "
                 "signals are SIGTERM, SIGHUP, SIGUSR1 and SIGUSR2.\n",
                 signal_text(sig).c_str());
  }
  ::_exit(128 + sig);
}

#endif

}  // namespace

namespace crash {

void set_state(std::string_view phase, std::string_view input_path) {
  const std::size_t phase_len = phase.size() > k_phase_cap ? k_phase_cap : phase.size();
  const std::size_t input_len = input_path.size() > k_input_cap ? k_input_cap : input_path.size();
  std::memcpy(g_phase, phase.data(), phase_len);
  g_phase_len.store(static_cast<std::uint32_t>(phase_len), std::memory_order_release);
  std::memcpy(g_input, input_path.data(), input_len);
  g_input_len.store(static_cast<std::uint32_t>(input_len), std::memory_order_release);
}

std::string state_line() {
  const std::size_t phase_len = g_phase_len.load(std::memory_order_acquire);
  const std::size_t input_len = g_input_len.load(std::memory_order_acquire);
  std::string out;
  if (phase_len > 0) out += "phase=" + std::string(g_phase, phase_len);
  if (input_len > 0) {
    if (!out.empty()) out += " ";
    out += "input=" + std::string(g_input, input_len);
  }
  if (out.empty()) out = "(no phase recorded)";
  return out;
}

void install(const std::filesystem::path& logs_root, std::string_view run_id,
             const options& opts) {
  if (g_installed.exchange(true)) return;

  g_run_id = std::string(run_id);
  std::error_code ec;
  g_crash_dir = logs_root / "crash";
  std::filesystem::create_directories(g_crash_dir, ec);
  if (ec) {
    std::fprintf(stderr, "[crash] cannot create '%s': %s\n",
                 g_crash_dir.string().c_str(), ec.message().c_str());
    g_crash_dir = logs_root;
  }

  std::set_terminate(&on_terminate);

  g_continue_after_signal.store(opts.continue_after_signal,
                                std::memory_order_relaxed);

#if defined(_WIN32)
  SetUnhandledExceptionFilter(&on_unhandled_exception);
#else
  struct sigaction action{};
  action.sa_handler = &on_signal;
  sigemptyset(&action.sa_mask);
  // SA_RESETHAND: after one delivery the disposition goes back to the default,
  // so a fault that happens inside the handler still kills the process instead
  // of looping. It does NOT set SA_NODEFER, so the signals below stay blocked
  // while the handler runs - which is what makes returning safe.
  action.sa_flags = SA_RESETHAND;
  const int signals[] = {SIGSEGV, SIGBUS, SIGFPE, SIGILL, SIGABRT};
  for (const int sig : signals) sigaction(sig, &action, nullptr);

  if (g_continue_after_signal.load(std::memory_order_acquire)) {
    // Separate disposition for the continuable set: no SA_RESETHAND, because
    // these are expected to arrive repeatedly and each one has to be reported.
    struct sigaction soft{};
    soft.sa_handler = &on_signal;
    sigemptyset(&soft.sa_mask);
    soft.sa_flags = 0;
    const int continuable[] = {SIGTERM, SIGHUP, SIGUSR1, SIGUSR2};
    for (const int sig : continuable) sigaction(sig, &soft, nullptr);
  }
#endif

  enable_core_dump(opts.allow_core_dump);

  if (debug_dump::enabled()) {
    std::fprintf(stderr, "[crash] handlers installed; reports go to '%s'\n",
                 g_crash_dir.string().c_str());
    std::fflush(stderr);
  }
}

[[noreturn]] void self_test() {
  std::fprintf(stderr, "[crash-selftest] dereferencing null to exercise the "
                       "crash handler...\n");
  std::fflush(stderr);
  set_state("crash-selftest", "<none>");
  volatile int* probe = nullptr;
  *probe = 0xdead;
  // Only reachable when the fault did not happen (e.g. an exotic runtime).
  std::fprintf(stderr, "[crash-selftest] SURVIVED - the handler did not run\n");
  std::fflush(stderr);
  std::abort();
}

bool signal_selftest() {
#if defined(_WIN32)
  // Not a gap in the test, a gap in the platform. Windows has no SIGUSR1 and no
  // SIGTERM the analyzer can catch from the OS; the things that actually stop a
  // process here are console control events, and CTRL_CLOSE/CTRL_LOGOFF/
  // CTRL_SHUTDOWN give a process about five seconds before Windows kills it, so
  // "carry on after the signal" has no meaning there.
  //
  // Reporting false rather than true is the point. A selftest that passed on a
  // build where the feature is absent would be worse than no selftest.
  std::fprintf(stderr,
               "[signal-selftest] not applicable on Windows: the continuable-signal\n"
               "[signal-selftest] handling is POSIX-only. --continue-on-signal has\n"
               "[signal-selftest] no effect in this build. Verified on a Linux build.\n");
  std::fflush(stderr);
  return false;
#else
  if (!g_continue_after_signal.load(std::memory_order_relaxed)) {
    std::fprintf(stderr,
                 "[signal-selftest] --continue-on-signal (or IA_CONTINUE_ON_SIGNAL=1)\n"
                 "[signal-selftest] is not set, so the signal would be fatal. Nothing\n"
                 "[signal-selftest] was raised.\n");
    std::fflush(stderr);
    return false;
  }

  const int before = g_signal_continuations.load(std::memory_order_relaxed);
  std::fprintf(stderr, "[signal-selftest] raising SIGUSR1; if the handler did not\n"
                       "[signal-selftest] return, this process would die here.\n");
  std::fflush(stderr);
  ::raise(SIGUSR1);

  const int after = g_signal_continuations.load(std::memory_order_relaxed);
  const bool continued = after > before;
  std::fprintf(stderr, continued
      ? "[signal-selftest] PASS - the handler caught SIGUSR1, wrote its report\n"
        "[signal-selftest] and returned; execution reached this line.\n"
      : "[signal-selftest] FAIL - execution reached this line but the handler\n"
        "[signal-selftest] never recorded a continuation.\n");
  std::fflush(stderr);
  return continued;
#endif
}

void demo() {
  // Renders the entire crash presentation - banner, report, minidump - and
  // returns normally.
  //
  // A separate entry point from self_test() on purpose. self_test() proves the
  // HANDLERS fire; demo() proves the OUTPUT looks right. Those fail differently:
  // a handler that fires can still print a banner that is empty, mis-centred or
  // the wrong colour, and nobody finds out until the one time it matters.
  report_once("DEMONSTRATION (no fault occurred)",
              "crash::demo() - real banner, report, trace tail and minidump, "
              "with nothing dereferenced",
              nullptr);
  std::fprintf(stderr,
               "\n[crash-demo] That was the full crash presentation, rendered "
               "without crashing.\n"
               "[crash-demo] Use --crash-selftest to fault for real and prove "
               "the handlers fire.\n");
  std::fflush(stderr);
}

}  // namespace crash
