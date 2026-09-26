#include "trace.hpp"

#include <windows.h>
#include <dbghelp.h>
#include <psapi.h>

#include <algorithm>
#include <atomic>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

#if defined(__GNUC__)
#include <cxxabi.h>
#define TRACE_NO_INSTRUMENT __attribute__((no_instrument_function))
#else
#define TRACE_NO_INSTRUMENT
#endif

namespace {

SRWLOCK trace_lock = SRWLOCK_INIT;
std::atomic<bool> tracing_enabled{false};

HANDLE      s_trace_file     = INVALID_HANDLE_VALUE;
HANDLE      s_trace_mapping  = nullptr;
void*       s_trace_map_view = nullptr;
std::size_t s_trace_map_cap  = 0;
std::size_t s_trace_used     = 0;
std::size_t s_trace_flushed  = 0;
std::string s_trace_path;

std::string trace_path() {
#ifdef STATIC_ANALYZER_SOURCE_DIR
    const std::filesystem::path root(STATIC_ANALYZER_SOURCE_DIR);
#else
    const std::filesystem::path root = std::filesystem::current_path();
#endif
    const char* override_path = std::getenv("TRACE_FILE");
    if (override_path != nullptr && *override_path != '\0') return override_path;
    return (root / "logs" / "trace.txt").string();
}

constexpr std::size_t k_trace_map_size    = 512ull * 1024ull * 1024ull;
constexpr std::size_t k_trace_flush_chunk = 1ull * 1024ull * 1024ull;

LARGE_INTEGER qpc_freq = {};
long long trace_start_qpc = 0;

struct symbol_entry {
    std::uintptr_t addr;
    std::uintptr_t end;
    std::string    name;
    bool           is_project = false;
};
std::vector<symbol_entry> g_symbols;
std::atomic<bool> g_symbols_ready{false};

TRACE_NO_INSTRUMENT bool is_project_symbol(const char* name) {
    if (!name) return false;
    const std::string_view symbol(name);
    return symbol == "main"
        || symbol == "PrintMemoryInfo"
        || symbol.find("analyzer::")  != std::string_view::npos
        || symbol.find("hasher::")    != std::string_view::npos
        || symbol.find("console::")   != std::string_view::npos
        || symbol.find("extractor::") != std::string_view::npos;
}

TRACE_NO_INSTRUMENT void load_symbols_from_self() {
    HMODULE mod = GetModuleHandleA(nullptr);
    if (!mod) return;

    char exe_path[MAX_PATH] = {};
    DWORD n = GetModuleFileNameA(mod, exe_path, MAX_PATH);
    if (n == 0 || n == MAX_PATH) return;

    HANDLE f = CreateFileA(exe_path, GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) return;

    LARGE_INTEGER size{};
    if (!GetFileSizeEx(f, &size) || size.QuadPart <= 0) {
        CloseHandle(f);
        return;
    }

    std::vector<std::uint8_t> file(static_cast<std::size_t>(size.QuadPart));
    DWORD total = 0;
    while (total < file.size()) {
        DWORD got = 0;
        if (!ReadFile(f, file.data() + total,
                      static_cast<DWORD>(file.size() - total),
                      &got, nullptr) || got == 0) {
            break;
        }
        total += got;
    }
    CloseHandle(f);
    if (total != file.size()) return;

    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(file.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;

    if (dos->e_lfanew < 0 ||
        static_cast<std::size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS) > file.size()) {
        return;
    }

    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(file.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return;

    DWORD sym_off  = nt->FileHeader.PointerToSymbolTable;
    DWORD num_syms = nt->FileHeader.NumberOfSymbols;
    if (sym_off == 0 || num_syms == 0) {
        std::fprintf(stderr, "[trace] no COFF symbol table in binary\n");
        return;
    }
    if (static_cast<std::size_t>(sym_off) + num_syms * sizeof(IMAGE_SYMBOL) > file.size()) return;

    auto* sym = reinterpret_cast<IMAGE_SYMBOL*>(file.data() + sym_off);
    const char* str_table = reinterpret_cast<const char*>(sym + num_syms);
    const std::size_t str_table_size = file.size() -
        (reinterpret_cast<const std::uint8_t*>(str_table) - file.data());

    auto* loaded_dos = reinterpret_cast<IMAGE_DOS_HEADER*>(mod);
    if (loaded_dos->e_lfanew < 0) return;

    auto* loaded_nt = reinterpret_cast<IMAGE_NT_HEADERS*>(
        reinterpret_cast<std::uint8_t*>(mod) + loaded_dos->e_lfanew);
    auto* loaded_sections = IMAGE_FIRST_SECTION(loaded_nt);
    const std::uint8_t* module_base = reinterpret_cast<const std::uint8_t*>(mod);

    for (DWORD i = 0; i < num_syms; ++i) {
        IMAGE_SYMBOL& s = sym[i];
        DWORD aux = s.NumberOfAuxSymbols;

        if (s.SectionNumber > 0 &&
            s.SectionNumber <= nt->FileHeader.NumberOfSections &&
            (s.Type & 0xF0) == (IMAGE_SYM_DTYPE_FUNCTION << 4) &&
            s.StorageClass != IMAGE_SYM_CLASS_FILE) {

            const char* raw_name = nullptr;
            if (s.N.Name.Short) {
                raw_name = reinterpret_cast<const char*>(s.N.ShortName);
            } else {
                DWORD off = s.N.Name.Long;
                if (off < str_table_size) raw_name = str_table + off;
            }

            if (raw_name && raw_name[0] != '\0') {
                char demangled[1024] = {};
                int status = 0;
                char* dm = abi::__cxa_demangle(raw_name, nullptr, nullptr, &status);
                const char* final_name = (status == 0 && dm) ? dm : raw_name;

                auto& loaded_sec = loaded_sections[s.SectionNumber - 1];
                std::uintptr_t runtime_addr =
                    reinterpret_cast<std::uintptr_t>(module_base)
                  + loaded_sec.VirtualAddress
                  + s.Value;

                symbol_entry e;
                e.addr       = runtime_addr;
                e.end        = 0;
                e.name       = std::string(final_name);
                e.is_project = is_project_symbol(final_name);

                g_symbols.push_back(std::move(e));
                if (dm) std::free(dm);
            }
        }
        i += aux;
    }

    std::sort(g_symbols.begin(), g_symbols.end(),
              [](const symbol_entry& a, const symbol_entry& b) {
                  return a.addr < b.addr;
              });

    for (std::size_t i = 0; i + 1 < g_symbols.size(); ++i) {
        g_symbols[i].end = g_symbols[i + 1].addr;
    }

    g_symbols_ready.store(!g_symbols.empty(), std::memory_order_release);
    std::fprintf(stderr, "[trace] loaded %zu symbols (%zu project)\n",
                 g_symbols.size(),
                 std::count_if(g_symbols.begin(), g_symbols.end(),
                               [](const symbol_entry& s) { return s.is_project; }));
}

TRACE_NO_INSTRUMENT int symbol_index_for(void* address) {
    if (!g_symbols_ready.load(std::memory_order_acquire)) return -1;
    const auto key = reinterpret_cast<std::uintptr_t>(address);
    auto it = std::upper_bound(
        g_symbols.begin(), g_symbols.end(), key,
        [](std::uintptr_t v, const symbol_entry& s) { return v < s.addr; });
    if (it == g_symbols.begin()) return -1;
    --it;
    return static_cast<int>(it - g_symbols.begin());
}

struct frame {
    void*     func;
    long long start_qpc;
};

constexpr std::size_t max_depth = 1024;
thread_local frame       t_stack[max_depth];
thread_local std::size_t t_depth = 0;

thread_local void* t_cached_func = nullptr;
thread_local int   t_cached_idx  = -1;

TRACE_NO_INSTRUMENT inline int symbol_index_for_cached(void* address) {
    if (address == t_cached_func) return t_cached_idx;
    int idx = symbol_index_for(address);
    t_cached_func = address;
    t_cached_idx  = idx;
    return idx;
}

TRACE_NO_INSTRUMENT long long now_qpc() {
    LARGE_INTEGER t;
    QueryPerformanceCounter(&t);
    return t.QuadPart;
}


TRACE_NO_INSTRUMENT void flush_range_to_disk_locked() {
    if (s_trace_flushed >= s_trace_used) return;
    if (s_trace_map_view != nullptr) {
        FlushViewOfFile(
            static_cast<char*>(s_trace_map_view) + s_trace_flushed,
            s_trace_used - s_trace_flushed);
    }
    s_trace_flushed = s_trace_used;
}

TRACE_NO_INSTRUMENT void write_line_locked(const char* fmt, ...) {
    if (s_trace_file == INVALID_HANDLE_VALUE) return;
    if (s_trace_used >= k_trace_map_size) return;

    char buf[640];
    va_list args;
    va_start(args, fmt);
    int len = std::vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    if (len <= 0) return;

    std::size_t need = static_cast<std::size_t>(len);
    if (s_trace_used + need > k_trace_map_size) {
        need = k_trace_map_size - s_trace_used;
    }

    if (s_trace_map_view != nullptr) {
        std::memcpy(static_cast<char*>(s_trace_map_view) + s_trace_used, buf, need);
    } else {
        LARGE_INTEGER offset{};
        offset.QuadPart = static_cast<LONGLONG>(s_trace_used);
        SetFilePointerEx(s_trace_file, offset, nullptr, FILE_BEGIN);
        DWORD written = 0;
        WriteFile(s_trace_file, buf, static_cast<DWORD>(need), &written, nullptr);
    }
    s_trace_used += need;

    if (s_trace_used - s_trace_flushed >= k_trace_flush_chunk) {
        flush_range_to_disk_locked();
    }
}

} 


extern "C" TRACE_NO_INSTRUMENT void trace_enable() {
    AcquireSRWLockExclusive(&trace_lock);

    if (s_trace_file == INVALID_HANDLE_VALUE) {
        s_trace_path = trace_path();
        s_trace_used = 0;
        s_trace_flushed = 0;
        std::error_code ec;
        const std::filesystem::path parent = std::filesystem::path(s_trace_path).parent_path();
        if (!parent.empty()) std::filesystem::create_directories(parent, ec);
        if (ec) {
            std::fprintf(stderr, "[trace] cannot create directory '%s': %s\n",
                         parent.string().c_str(), ec.message().c_str());
        }
        QueryPerformanceFrequency(&qpc_freq);
        LARGE_INTEGER t{};
        QueryPerformanceCounter(&t);
        trace_start_qpc = t.QuadPart;

        s_trace_file = CreateFileA(
            s_trace_path.c_str(), GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ, nullptr, CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL, nullptr);

        if (s_trace_file != INVALID_HANDLE_VALUE) {
            LARGE_INTEGER li{};
            li.QuadPart = static_cast<LONGLONG>(k_trace_map_size);
            SetFilePointerEx(s_trace_file, li, nullptr, FILE_BEGIN);
            SetEndOfFile(s_trace_file);

            s_trace_mapping = CreateFileMappingA(
                s_trace_file, nullptr, PAGE_READWRITE,
                static_cast<DWORD>(k_trace_map_size >> 32),
                static_cast<DWORD>(k_trace_map_size),
                nullptr);

            if (s_trace_mapping != nullptr) {
                s_trace_map_view = MapViewOfFile(
                    s_trace_mapping, FILE_MAP_WRITE, 0, 0,
                    static_cast<SIZE_T>(k_trace_map_size));
                if (s_trace_map_view != nullptr) {
                    s_trace_map_cap = k_trace_map_size;
                }
            }
            if (s_trace_map_view == nullptr) {
                std::fprintf(stderr, "[trace] memory mapping unavailable; using direct writes to '%s'\n",
                             s_trace_path.c_str());
            }
        } else {
            std::fprintf(stderr, "[trace] cannot create '%s' (Windows error %lu)\n",
                         s_trace_path.c_str(), static_cast<unsigned long>(GetLastError()));
        }

        if (!g_symbols_ready.load(std::memory_order_acquire)) {
            load_symbols_from_self();
        }
    }

    tracing_enabled.store(true, std::memory_order_release);
    ReleaseSRWLockExclusive(&trace_lock);
}

extern "C" TRACE_NO_INSTRUMENT void trace_disable() {
    tracing_enabled.store(false, std::memory_order_release);

    AcquireSRWLockExclusive(&trace_lock);
    if (s_trace_map_view != nullptr) {
        flush_range_to_disk_locked();
        UnmapViewOfFile(s_trace_map_view);
        s_trace_map_view = nullptr;
    }
    if (s_trace_mapping != nullptr) {
        CloseHandle(s_trace_mapping);
        s_trace_mapping = nullptr;
    }
    if (s_trace_file != INVALID_HANDLE_VALUE) {
        LARGE_INTEGER li{};
        li.QuadPart = static_cast<LONGLONG>(s_trace_used);
        SetFilePointerEx(s_trace_file, li, nullptr, FILE_BEGIN);
        SetEndOfFile(s_trace_file);

        FlushFileBuffers(s_trace_file);
        CloseHandle(s_trace_file);
        s_trace_file = INVALID_HANDLE_VALUE;
        s_trace_map_cap = 0;
    }
    ReleaseSRWLockExclusive(&trace_lock);
}

extern "C" TRACE_NO_INSTRUMENT void trace_write_text(std::string_view text) {
    if (text.empty()) return;
    if (!tracing_enabled.load(std::memory_order_acquire)) return;

    AcquireSRWLockExclusive(&trace_lock);
    if (s_trace_map_view != nullptr && s_trace_used < s_trace_map_cap) {
        std::size_t need = text.size();
        if (s_trace_used + need > s_trace_map_cap) {
            need = s_trace_map_cap - s_trace_used;
        }
        std::memcpy(static_cast<char*>(s_trace_map_view) + s_trace_used,
                    text.data(), need);
        s_trace_used += need;
    } else if (s_trace_file != INVALID_HANDLE_VALUE) {
        LARGE_INTEGER offset{};
        offset.QuadPart = static_cast<LONGLONG>(s_trace_used);
        SetFilePointerEx(s_trace_file, offset, nullptr, FILE_BEGIN);
        DWORD written = 0;
        WriteFile(s_trace_file, text.data(), static_cast<DWORD>(text.size()), &written, nullptr);
        s_trace_used += written;
    }
    ReleaseSRWLockExclusive(&trace_lock);
}



extern "C" TRACE_NO_INSTRUMENT void __cyg_profile_func_enter(void* func,
                                                              void* caller) {
    (void)caller;

    if (!tracing_enabled.load(std::memory_order_relaxed)) return;
    if (t_depth >= max_depth) return;

    int idx = symbol_index_for_cached(func);
    if (idx < 0) return;
    if (!g_symbols[idx].is_project) return;

    if (t_depth < max_depth) {
        t_stack[t_depth].func      = func;
        t_stack[t_depth].start_qpc = now_qpc();
        ++t_depth;
    }

    const auto& sym = g_symbols[idx];
    std::uintptr_t f = reinterpret_cast<std::uintptr_t>(func);
    const double elapsed_ms = qpc_freq.QuadPart
        ? (double(now_qpc() - trace_start_qpc) * 1000.0) / double(qpc_freq.QuadPart)
        : 0.0;

    AcquireSRWLockExclusive(&trace_lock);
    write_line_locked(
        "[trace] %10.3f ms | depth=%02zu | ENTER | %s | addr=0x%llX | size=%llu\n",
        elapsed_ms, t_depth - 1, sym.name.c_str(),
        static_cast<unsigned long long>(f),
        static_cast<unsigned long long>(sym.end ? sym.end - f : 0));
    ReleaseSRWLockExclusive(&trace_lock);
}

extern "C" TRACE_NO_INSTRUMENT void __cyg_profile_func_exit(void* func,
                                                             void* caller) {
    (void)caller;

    if (!tracing_enabled.load(std::memory_order_relaxed)) return;
    if (t_depth == 0) return;

    // Symbol lookup without lock
    int idx = symbol_index_for_cached(func);
    if (idx < 0) return;
    if (!g_symbols[idx].is_project) return;

    --t_depth;
    long long start = t_stack[t_depth].start_qpc;
    long long end   = now_qpc();

    double seconds = qpc_freq.QuadPart
        ? double(end - start) / double(qpc_freq.QuadPart) : 0.0;
    double micros  = seconds * 1e6;
    const double elapsed_ms = qpc_freq.QuadPart
        ? (double(end - trace_start_qpc) * 1000.0) / double(qpc_freq.QuadPart)
        : 0.0;

    const auto& sym = g_symbols[idx];

    AcquireSRWLockExclusive(&trace_lock);
    write_line_locked(
        "[trace] %10.3f ms | depth=%02zu | LEAVE | %s | duration=%.3f us (%.6f s)\n",
        elapsed_ms, t_depth, sym.name.c_str(), micros, seconds);
    ReleaseSRWLockExclusive(&trace_lock);
}
std::string PrintMemoryInfo() {
    char buffer[2048] = {};
    const DWORD process_id = GetCurrentProcessId();
    PROCESS_MEMORY_COUNTERS_EX memory{};

    if (!GetProcessMemoryInfo(GetCurrentProcess(),
                              reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&memory),
                              sizeof(memory))) {
        std::snprintf(buffer, sizeof(buffer),
                      "\n=== Memory Info ===\nProcess ID: %u (no info available)\n",
                      static_cast<unsigned>(process_id));
        return buffer;
    }

    auto mib = [](std::size_t bytes) -> double {
        return static_cast<double>(bytes) / (1024.0 * 1024.0);
    };
    auto pct = [](std::size_t part, std::size_t total) -> double {
        return total ? (static_cast<double>(part) / static_cast<double>(total)) * 100.0 : 0.0;
    };

    std::snprintf(
        buffer, sizeof(buffer),
        "\n=== Memory Info ===\n"
        "Process ID              : %u\n"
        "\n-- Working Set --\n"
        "Working Set Size        : %10zu B  (%8.2f MiB)\n"
        "Peak Working Set Size   : %10zu B  (%8.2f MiB)\n"
        "Page Fault Count        : %10u\n"
        "\n-- Pagefile --\n"
        "Pagefile Usage          : %10zu B  (%8.2f MiB)\n"
        "Peak Pagefile Usage     : %10zu B  (%8.2f MiB)\n"
        "Pagefile Usage %%        : %8.2f %%\n"
        "\n-- Paged Pool --\n"
        "Quota Paged Pool        : %10zu B  (%8.2f MiB)\n"
        "Quota Peak Paged Pool   : %10zu B  (%8.2f MiB)\n"
        "\n-- Non-Paged Pool --\n"
        "Quota Non-Paged Pool    : %10zu B  (%8.2f MiB)\n"
        "Quota Peak Non-Paged    : %10zu B  (%8.2f MiB)\n"
        "\n-- Structure --\n"
        "ProcessMemoryCounters.cb: %10u\n"
        "Private Usage           : %10zu B  (%8.2f MiB)\n",
        static_cast<unsigned>(process_id),
        memory.WorkingSetSize,        mib(memory.WorkingSetSize),
        memory.PeakWorkingSetSize,    mib(memory.PeakWorkingSetSize),
        static_cast<unsigned>(memory.PageFaultCount),
        memory.PagefileUsage,         mib(memory.PagefileUsage),
        memory.PeakPagefileUsage,     mib(memory.PeakPagefileUsage),
        pct(memory.PagefileUsage, memory.PeakPagefileUsage),
        memory.QuotaPagedPoolUsage,        mib(memory.QuotaPagedPoolUsage),
        memory.QuotaPeakPagedPoolUsage,    mib(memory.QuotaPeakPagedPoolUsage),
        memory.QuotaNonPagedPoolUsage,     mib(memory.QuotaNonPagedPoolUsage),
        memory.QuotaPeakNonPagedPoolUsage, mib(memory.QuotaPeakNonPagedPoolUsage),
        static_cast<unsigned>(memory.cb),
        memory.PrivateUsage,          mib(memory.PrivateUsage));

    return buffer;
}