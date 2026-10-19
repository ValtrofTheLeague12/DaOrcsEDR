#define NOMINMAX
#define WIN32_LEAN_AND_MEAN

#include "logging.hpp"

#include "app_paths.hpp"
#include "redact.hpp"

#include <spdlog/async.h>
#include <spdlog/details/log_msg.h>
#include <spdlog/logger.h>
#include <spdlog/pattern_formatter.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <map>
#include <memory>
#include <mutex>
#include <random>
#include <string>
#include <string_view>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#include <psapi.h>
#else
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace logging {

namespace {

struct payload_info {
    char status = 'i';
    std::string_view op;
    std::string_view ctx;
    std::string_view res;
    std::string_view msg;
};

// FIX: original only consumed 3 of the 4 \x1f separators, so when
// op/ctx/res were empty the 4th separator leaked into msg as a literal
// \x1f, which json_escape rendered as \u001f.
void split_payload(std::string_view p, payload_info& out) {
    if (p.empty()) {
        return;
    }
    out.status = p.front();
    const std::string_view sep = "\x1f";

    std::size_t p0 = p.find(sep, 1);
    if (p0 == std::string_view::npos) {
        out.msg = p.substr(1);
        return;
    }
    out.op = p.substr(1, p0 - 1);

    std::size_t p1 = p.find(sep, p0 + 1);
    if (p1 == std::string_view::npos) {
        out.msg = p.substr(p0 + 1);
        return;
    }
    out.ctx = p.substr(p0 + 1, p1 - p0 - 1);

    std::size_t p2 = p.find(sep, p1 + 1);
    if (p2 == std::string_view::npos) {
        out.msg = p.substr(p1 + 1);
        return;
    }
    out.res = p.substr(p1 + 1, p2 - p1 - 1);

    std::size_t p3 = p.find(sep, p2 + 1);
    if (p3 == std::string_view::npos) {
        out.msg = p.substr(p2 + 1);
        return;
    }
    out.msg = p.substr(p3 + 1);
}

std::string json_escape(std::string_view s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (unsigned char ch : s) {
        switch (ch) {
            case '"':
                out += "\\\"";
                break;
            case '\\':
                out += "\\\\";
                break;
            case '\n':
                out += "\\n";
                break;
            case '\r':
                out += "\\r";
                break;
            case '\t':
                out += "\\t";
                break;
            case '\b':
                out += "\\b";
                break;
            case '\f':
                out += "\\f";
                break;
            default:
                if (ch < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof buf, "\\u%04x", static_cast<unsigned>(ch));
                    out += buf;
                } else {
                    out.push_back(static_cast<char>(ch));
                }
        }
    }
    return out;
}

const char* status_word(char c) noexcept {
    switch (c) {
        case 's':
            return "success";
        case 'f':
            return "failure";
        case 'w':
            return "warning";
        case 'd':
            return "debug";
        case 'i':
        default:
            return "info";
    }
}

const char* json_level_name(spdlog::level::level_enum lv) noexcept {
    switch (lv) {
        case spdlog::level::trace:
            return "trace";
        case spdlog::level::debug:
            return "debug";
        case spdlog::level::info:
            return "info";
        case spdlog::level::warn:
            return "warn";
        case spdlog::level::err:
            return "error";
        case spdlog::level::critical:
            return "critical";
        case spdlog::level::off:
        default:
            return "info";
    }
}

const char* display_level_name(spdlog::level::level_enum lv) noexcept {
    switch (lv) {
        case spdlog::level::trace:
            return "TRACE";
        case spdlog::level::debug:
            return "DEBUG";
        case spdlog::level::info:
            return "INFO";
        case spdlog::level::warn:
            return "WARN";
        case spdlog::level::err:
            return "ERROR";
        case spdlog::level::critical:
            return "CRITICAL";
        case spdlog::level::off:
        default:
            return "INFO";
    }
}

const char* level_enum_name(level l) noexcept {
    switch (l) {
        case level::trace:
            return "trace";
        case level::debug:
            return "debug";
        case level::info:
            return "info";
        case level::warn:
            return "warn";
        case level::error:
            return "error";
        case level::critical:
            return "critical";
    }
    return "info";
}

std::int64_t floor_div(std::int64_t a, std::int64_t b) {
    std::int64_t q = a / b;
    std::int64_t r = a % b;
    if (r != 0 && ((r < 0) != (b < 0))) {
        --q;
    }
    return q;
}

// FIX: the civil-from-days algorithm expects days since 0000-03-01, but it
// was being fed days since 1970-01-01. Off by 719468 days -> year 0056.
void to_iso8601_ms(std::chrono::system_clock::time_point t, char* out, std::size_t cap) {
    std::int64_t ms = static_cast<std::int64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(t.time_since_epoch()).count());
    std::int64_t secs = floor_div(ms, 1000);
    std::int64_t msec = ms - secs * 1000;

    std::int64_t z_unix = floor_div(secs, 86400);
    std::int64_t sod = secs - z_unix * 86400;
    if (sod < 0) {
        sod += 86400;
    }
    std::int64_t hh = sod / 3600;
    std::int64_t mi = (sod % 3600) / 60;
    std::int64_t ss = sod % 60;

    std::int64_t z = z_unix + 719468;
    std::int64_t era = (z >= 0 ? z : z - 146096) / 146097;
    unsigned doe = static_cast<unsigned>(z - era * 146097);
    unsigned yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    int y = static_cast<int>(yoe) + static_cast<int>(era * 400);
    unsigned doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    unsigned mp = (5 * doy + 2) / 153;
    unsigned d = doy - (153 * mp + 2) / 5 + 1;
    unsigned m = mp < 10 ? mp + 3 : mp - 9;
    y += (m <= 2) ? 1 : 0;

    std::snprintf(out, cap, "%04d-%02u-%02uT%02lld:%02lld:%02lld.%03lldZ", y, m, d,
                  static_cast<long long>(hh), static_cast<long long>(mi),
                  static_cast<long long>(ss), static_cast<long long>(msec));
}

std::string iso_of_timepoint(std::chrono::system_clock::time_point t) {
    char buf[32];
    to_iso8601_ms(t, buf, sizeof buf);
    return std::string(buf);
}

struct module_state {
    std::mutex mtx;
    bool initialized = false;
    bool async = true;
    bool to_stderr = false;   // console output disabled by default
    bool track_resources = true;
    bool atexit_registered = false;
    level min_level_value = level::info;
    // Under the AppData root rather than the working directory: run logs are
    // machine state, and writing them into the source tree kept `git status`
    // permanently dirty and put a copy of every run into every backup.
    std::filesystem::path directory = app_paths::logs_root();
    std::string basename{"static_analyzer"};
    std::size_t max_bytes = 200u * 1024u * 1024u;
    std::size_t max_files = 5;
    std::string logger_name{"static_analyzer"};
    std::string run_id;
    long host_pid = 0;
    std::string host_hostname;
    std::string host_platform;
    std::string host_arch;
    std::shared_ptr<spdlog::logger> logger;
    std::shared_ptr<spdlog::sinks::rotating_file_sink_mt> file;
    std::shared_ptr<spdlog::sinks::stderr_color_sink_mt> console;
};

module_state* state() {
    static module_state* st = new module_state();
    return st;
}

std::string generate_run_id() {
    std::random_device rd;
    unsigned char b[8];
    for (unsigned char& x : b) {
        x = static_cast<unsigned char>(rd() & 0xffu);
    }
    char hex[17];
    for (int i = 0; i < 8; ++i) {
        std::snprintf(hex + i * 2, 3, "%02x", static_cast<unsigned>(b[i]));
    }
    return std::string(hex, 16);
}

void collect_host_info(module_state* st) {
#ifdef _WIN32
    st->host_platform = "windows";
    st->host_pid = static_cast<long>(::GetCurrentProcessId());
    char buf[256] = {};
    DWORD sz = sizeof buf;
    if (::GetComputerNameA(buf, &sz) != 0) {
        st->host_hostname = buf;
    }
#else
    st->host_platform = "linux";
    st->host_pid = static_cast<long>(::getpid());
    char buf[256] = {};
    if (::gethostname(buf, sizeof buf) == 0) {
        st->host_hostname = buf;
    }
#endif
#if defined(__x86_64__) || defined(_M_X64)
    st->host_arch = "x86_64";
#elif defined(__aarch64__) || defined(_M_ARM64)
    st->host_arch = "aarch64";
#elif defined(__i386__) || defined(_M_IX86)
    st->host_arch = "x86";
#else
    st->host_arch = "unknown";
#endif
}

struct paths_t {
    std::filesystem::path directory = app_paths::logs_root();
    std::string basename{"static_analyzer"};
    std::size_t max_files = 5;
};

paths_t snapshot_paths(module_state* st) {
    paths_t p;
    std::lock_guard<std::mutex> lock(st->mtx);
    p.directory = st->directory;
    p.basename = st->basename;
    p.max_files = st->max_files;
    return p;
}

std::filesystem::path base_log_path(const paths_t& p) {
    return p.basename == "static_analyzer"
             ? p.directory / "logs.jsonl"
             : p.directory / (p.basename + ".log");
}

std::filesystem::path indexed_log_path(const paths_t& p, std::size_t i) {
  return p.basename == "static_analyzer"
             ? p.directory / ("logs.jsonl." + std::to_string(i))
             : p.directory / (p.basename + "." + std::to_string(i) + ".log");
}

std::vector<std::filesystem::path> log_files(const paths_t& p) {
    std::vector<std::filesystem::path> out;
    out.reserve(p.max_files);
    for (std::size_t i = p.max_files > 0 ? p.max_files - 1 : 0; i > 0; --i) {
        out.push_back(indexed_log_path(p, i));
    }
    out.push_back(base_log_path(p));
    return out;
}

std::size_t last_complete_offset(const std::filesystem::path& path) {
    std::error_code ec;
    auto fsz = std::filesystem::file_size(path, ec);
    if (ec) {
        return 0;
    }
    std::size_t size = static_cast<std::size_t>(fsz);
    if (size == 0) {
        return 0;
    }
    const std::size_t chunk = 1u << 20;
    std::vector<char> buf(chunk);
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        return 0;
    }
    std::size_t pos = size;
    std::size_t newline_pos = static_cast<std::size_t>(-1);
    while (pos > 0) {
        std::size_t take = std::min(chunk, pos);
        std::size_t from = pos - take;
        f.clear();
        f.seekg(static_cast<std::streamoff>(from));
        f.read(buf.data(), static_cast<std::streamsize>(take));
        std::size_t got = static_cast<std::size_t>(f.gcount());
        for (std::size_t i = got; i-- > 0;) {
            if (buf[i] == '\n') {
                newline_pos = from + i;
                break;
            }
        }
        if (newline_pos != static_cast<std::size_t>(-1)) {
            break;
        }
        if (got == 0) {
            break;
        }
        pos = from;
    }
    if (newline_pos == static_cast<std::size_t>(-1)) {
        return 0;
    }
    return newline_pos + 1;
}

bool truncate_at(const std::filesystem::path& path, std::size_t offset) {
#ifdef _WIN32
    HANDLE h = ::CreateFileA(path.string().c_str(), GENERIC_WRITE,
                             FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                             OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        return false;
    }
    LARGE_INTEGER li;
    li.QuadPart = static_cast<LONGLONG>(offset);
    BOOL ok = ::SetFilePointerEx(h, li, nullptr, FILE_BEGIN) && ::SetEndOfFile(h);
    ::CloseHandle(h);
    return ok != 0;
#else
    return ::truncate(path.string().c_str(), static_cast<off_t>(offset)) == 0;
#endif
}

std::size_t recover_from_crash_locked(module_state* st) {
    paths_t p;
    p.directory = st->directory;
    p.basename = st->basename;
    std::filesystem::path base = base_log_path(p);
    std::error_code ec;
    if (!std::filesystem::exists(base, ec)) {
        return 0;
    }
    std::size_t off = last_complete_offset(base);
    std::size_t sz = static_cast<std::size_t>(std::filesystem::file_size(base, ec));
    if (off == sz) {
        return 0;
    }
    if (!truncate_at(base, off)) {
        return 0;
    }
    return sz - off;
}

class ts_flag final : public spdlog::custom_flag_formatter {
public:
    void format(const spdlog::details::log_msg& msg, const std::tm&,
                spdlog::memory_buf_t& dest) override {
        char buf[32];
        to_iso8601_ms(msg.time, buf, sizeof buf);
        dest.append(buf, buf + std::strlen(buf));
    }
    std::unique_ptr<spdlog::custom_flag_formatter> clone() const override {
        return std::unique_ptr<spdlog::custom_flag_formatter>(new ts_flag(*this));
    }
};

class level_flag final : public spdlog::custom_flag_formatter {
public:
    void format(const spdlog::details::log_msg& msg, const std::tm&,
                spdlog::memory_buf_t& dest) override {
        const char* s = display_level_name(msg.level);
        dest.append(s, s + std::strlen(s));
    }
    std::unique_ptr<spdlog::custom_flag_formatter> clone() const override {
        return std::unique_ptr<spdlog::custom_flag_formatter>(new level_flag(*this));
    }
};

class status_flag final : public spdlog::custom_flag_formatter {
public:
    void format(const spdlog::details::log_msg& msg, const std::tm&,
                spdlog::memory_buf_t& dest) override {
        payload_info p;
        split_payload(std::string_view(msg.payload.data(), msg.payload.size()), p);
        const char* s = status_word(p.status);
        dest.append(s, s + std::strlen(s));
    }
    std::unique_ptr<spdlog::custom_flag_formatter> clone() const override {
        return std::unique_ptr<spdlog::custom_flag_formatter>(new status_flag(*this));
    }
};

class thread_flag final : public spdlog::custom_flag_formatter {
public:
    void format(const spdlog::details::log_msg& msg, const std::tm&,
                spdlog::memory_buf_t& dest) override {
        char buf[24];
        int n = std::snprintf(buf, sizeof buf, "0x%zx", msg.thread_id);
        dest.append(buf, buf + (n > 0 ? static_cast<std::size_t>(n) : 0));
    }
    std::unique_ptr<spdlog::custom_flag_formatter> clone() const override {
        return std::unique_ptr<spdlog::custom_flag_formatter>(new thread_flag(*this));
    }
};

class source_flag final : public spdlog::custom_flag_formatter {
public:
    void format(const spdlog::details::log_msg& msg, const std::tm&,
                spdlog::memory_buf_t& dest) override {
        if (!msg.source.filename) {
            const char* ph = "?";
            dest.append(ph, ph + 1);
            return;
        }
        const char* fn = msg.source.filename;
        const char* sl = std::strrchr(fn, '/');
        const char* bs = std::strrchr(fn, '\\');
        const char* base = (sl && bs) ? std::max(sl, bs) : (sl ? sl : bs);
        if (base) {
            ++base;
        } else {
            base = fn;
        }
        char linebuf[16];
        int n = std::snprintf(linebuf, sizeof linebuf, ":%d", msg.source.line);
        std::string text(base);
        if (n > 0) {
            text.append(linebuf, static_cast<std::size_t>(n));
        }
        std::string esc = json_escape(text);
        dest.append(esc.data(), esc.data() + esc.size());
    }
    std::unique_ptr<spdlog::custom_flag_formatter> clone() const override {
        return std::unique_ptr<spdlog::custom_flag_formatter>(new source_flag(*this));
    }
};

class json_tail_flag final : public spdlog::custom_flag_formatter {
public:
    void format(const spdlog::details::log_msg& msg, const std::tm&,
                spdlog::memory_buf_t& dest) override {
        payload_info p;
        split_payload(std::string_view(msg.payload.data(), msg.payload.size()), p);
        std::string tmp;
        if (!p.op.empty()) {
            tmp += ",\"operation\":";
            tmp.append(p.op);
        }
        if (!p.ctx.empty()) {
            tmp += ",\"context\":";
            tmp.append(p.ctx);
        }
        if (!p.res.empty()) {
            tmp += ",\"resource\":";
            tmp.append(p.res);
        }
        tmp += ",\"msg\":\"";
        tmp += json_escape(p.msg);
        tmp += "\"";
        dest.append(tmp.data(), tmp.data() + tmp.size());
    }
    std::unique_ptr<spdlog::custom_flag_formatter> clone() const override {
        return std::unique_ptr<spdlog::custom_flag_formatter>(new json_tail_flag(*this));
    }
};

class ndjson_flag final : public spdlog::custom_flag_formatter {
public:
    void format(const spdlog::details::log_msg& msg, const std::tm&,
                spdlog::memory_buf_t& dest) override {
        payload_info p;
        split_payload(std::string_view(msg.payload.data(), msg.payload.size()), p);
        char ts[32];
        to_iso8601_ms(msg.time, ts, sizeof ts);
        char th[24];
        int thn = std::snprintf(th, sizeof th, "0x%zx", msg.thread_id);
        module_state* st = state();
        std::string out;
        out.reserve(256);
        out += "{\"ts\":\"";
        out += ts;
        out += "\",\"level\":\"";
        out += json_level_name(msg.level);
        out += "\",\"status\":\"";
        out += status_word(p.status);
        out += "\",\"thread\":\"";
        out.append(th, th + (thn > 0 ? static_cast<std::size_t>(thn) : 0));
        out += "\"";
        if (msg.source.filename) {
            const char* fn = msg.source.filename;
            const char* sl = std::strrchr(fn, '/');
            const char* bs = std::strrchr(fn, '\\');
            const char* base = (sl && bs) ? std::max(sl, bs) : (sl ? sl : bs);
            if (base) {
                ++base;
            } else {
                base = fn;
            }
            char linebuf[16];
            int ln = std::snprintf(linebuf, sizeof linebuf, ":%d", msg.source.line);
            std::string src(base);
            if (ln > 0) {
                src.append(linebuf, static_cast<std::size_t>(ln));
            }
            out += ",\"source\":\"";
            out += json_escape(src);
            out += "\"";
        }
        out += ",\"logger\":\"";
        out += json_escape(std::string(msg.logger_name.data(), msg.logger_name.size()));
        out += "\"";
        if (st) {
            // snapshot run_id and host fields under the lock
            std::string run_id;
            long host_pid = 0;
            std::string host_hostname, host_platform, host_arch;
            {
                std::lock_guard<std::mutex> lock(st->mtx);
                run_id = st->run_id;
                host_pid = st->host_pid;
                host_hostname = st->host_hostname;
                host_platform = st->host_platform;
                host_arch = st->host_arch;
            }
            out += ",\"run_id\":\"";
            out += json_escape(run_id);
            out += "\",\"host\":{\"pid\":";
            out += std::to_string(host_pid);
            out += ",\"hostname\":\"";
            out += json_escape(host_hostname);
            out += "\",\"platform\":\"";
            out += json_escape(host_platform);
            out += "\",\"arch\":\"";
            out += json_escape(host_arch);
            out += "\"}";
        }
        if (!p.op.empty()) {
            out += ",\"operation\":";
            out += std::string(p.op);
        }
        if (!p.ctx.empty()) {
            out += ",\"context\":";
            out += std::string(p.ctx);
        }
        if (!p.res.empty()) {
            out += ",\"resource\":";
            out += std::string(p.res);
        }
        out += ",\"msg\":\"";
        out += json_escape(p.msg);
        out += "\"}";
        dest.append(out.data(), out.data() + out.size());
    }
    std::unique_ptr<spdlog::custom_flag_formatter> clone() const override {
        return std::unique_ptr<spdlog::custom_flag_formatter>(new ndjson_flag(*this));
    }
};

spdlog::pattern_formatter::custom_flags make_flags() {
    spdlog::pattern_formatter::custom_flags flags;
    flags['R'] = std::unique_ptr<spdlog::custom_flag_formatter>(new ts_flag());
    flags['L'] = std::unique_ptr<spdlog::custom_flag_formatter>(new level_flag());
    flags['S'] = std::unique_ptr<spdlog::custom_flag_formatter>(new status_flag());
    flags['T'] = std::unique_ptr<spdlog::custom_flag_formatter>(new thread_flag());
    flags['Q'] = std::unique_ptr<spdlog::custom_flag_formatter>(new source_flag());
    flags['J'] = std::unique_ptr<spdlog::custom_flag_formatter>(new json_tail_flag());
    flags['N'] = std::unique_ptr<spdlog::custom_flag_formatter>(new ndjson_flag());
    return flags;
}

char status_char(status st) noexcept {
    switch (st) {
        case status::success:
            return 's';
        case status::failure:
            return 'f';
        case status::warning:
            return 'w';
        case status::debug:
            return 'd';
        case status::info:
        default:
            return 'i';
    }
}

resource_sample_t sample_current_impl() noexcept {
    resource_sample_t r;
#ifdef _WIN32
    HANDLE h = ::GetCurrentProcess();
    FILETIME create, exit, kernel, user;
    if (::GetProcessTimes(h, &create, &exit, &kernel, &user) != 0) {
        auto to_ms = [](const FILETIME& ft) -> double {
            ULARGE_INTEGER v;
            v.LowPart = ft.dwLowDateTime;
            v.HighPart = ft.dwHighDateTime;
            return static_cast<double>(v.QuadPart / 10000ULL);
        };
        r.cpu_user_ms = to_ms(user);
        r.cpu_sys_ms = to_ms(kernel);
        r.elapsed_ms = r.cpu_user_ms + r.cpu_sys_ms;
    }
    PROCESS_MEMORY_COUNTERS pmc;
    std::memset(&pmc, 0, sizeof pmc);
    if (::GetProcessMemoryInfo(h, &pmc, sizeof pmc) != 0) {
        r.memory_mb = static_cast<double>(pmc.WorkingSetSize) / (1024.0 * 1024.0);
        r.peak_memory_mb = static_cast<double>(pmc.PeakWorkingSetSize) / (1024.0 * 1024.0);
    }
    IO_COUNTERS io;
    if (::GetProcessIoCounters(h, &io) != 0) {
        r.disk_read_kb = static_cast<double>(io.ReadTransferCount) / 1024.0;
        r.disk_write_kb = static_cast<double>(io.WriteTransferCount) / 1024.0;
    }
#else
    struct rusage ru;
    std::memset(&ru, 0, sizeof ru);
    if (::getrusage(RUSAGE_SELF, &ru) == 0) {
        r.cpu_user_ms = ru.ru_utime.tv_sec * 1000.0 + ru.ru_utime.tv_usec / 1000.0;
        r.cpu_sys_ms = ru.ru_stime.tv_sec * 1000.0 + ru.ru_stime.tv_usec / 1000.0;
        r.elapsed_ms = r.cpu_user_ms + r.cpu_sys_ms;
        // ru_maxrss is KB on Linux, bytes on macOS
        double maxrss = static_cast<double>(ru.ru_maxrss);
#if defined(__APPLE__)
        r.peak_memory_mb = maxrss / (1024.0 * 1024.0);
#else
        r.peak_memory_mb = maxrss / 1024.0;
#endif
    }
    std::ifstream statm("/proc/self/statm");
    long total_pages = 0;
    long rss_pages = 0;
    if (statm >> total_pages >> rss_pages) {
        (void)total_pages;
        long page = ::sysconf(_SC_PAGESIZE);
        r.memory_mb =
            static_cast<double>(static_cast<long long>(rss_pages) * page) / (1024.0 * 1024.0);
    }
    std::ifstream io("/proc/self/io");
    std::string key;
    unsigned long long rd = 0;
    unsigned long long wr = 0;
    while (io >> key) {
        if (key == "read_bytes:") {
            unsigned long long v = 0;
            if (io >> v) {
                rd = v;
            }
        } else if (key == "write_bytes:") {
            unsigned long long v = 0;
            if (io >> v) {
                wr = v;
            }
        }
    }
    r.disk_read_kb = static_cast<double>(rd) / 1024.0;
    r.disk_write_kb = static_cast<double>(wr) / 1024.0;
#endif
    return r;
}

std::string resource_json(const resource_sample_t& r) {
    nlohmann::ordered_json j;
    j["elapsed_ms"] = r.elapsed_ms;
    j["cpu_user_ms"] = r.cpu_user_ms;
    j["cpu_sys_ms"] = r.cpu_sys_ms;
    j["memory_mb"] = r.memory_mb;
    j["peak_memory_mb"] = r.peak_memory_mb;
    j["disk_read_kb"] = r.disk_read_kb;
    j["disk_write_kb"] = r.disk_write_kb;
    return std::string(j.dump());
}

void shutdown_wrapper() noexcept {
    shutdown();
}

bool record_matches(const nlohmann::json& j, const log_filter_t& f, const std::string& since_iso,
                    const std::string& until_iso) {
    if (!f.run_id.empty() && j.value("run_id", std::string()) != f.run_id) {
        return false;
    }
    if (!f.level.empty()) {
        std::string lv = j.value("level", std::string());
        std::string fl = f.level;
        std::transform(lv.begin(), lv.end(), lv.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        std::transform(fl.begin(), fl.end(), fl.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (lv != fl) {
            return false;
        }
    }
    if (!f.status.empty() && j.value("status", std::string()) != f.status) {
        return false;
    }
    if (!f.module.empty()) {
        std::string source = j.value("source", std::string());
        std::string logger = j.value("logger", std::string());
        if (source.find(f.module) == std::string::npos &&
            logger.find(f.module) == std::string::npos) {
            return false;
        }
    }
    std::string ts = j.value("ts", std::string());
    if (!since_iso.empty() && ts < since_iso) {
        return false;
    }
    if (!until_iso.empty() && ts > until_iso) {
        return false;
    }
    return true;
}

std::string render_tail(const nlohmann::json& j) {
    std::string tail;
    auto opit = j.find("operation");
    if (opit != j.end() && !opit->is_null()) {
        tail += ",\"operation\":";
        tail += opit->dump();
    }
    auto ctxit = j.find("context");
    if (ctxit != j.end() && !ctxit->is_null()) {
        tail += ",\"context\":";
        tail += ctxit->dump();
    }
    auto resit = j.find("resource");
    if (resit != j.end() && !resit->is_null()) {
        tail += ",\"resource\":";
        tail += resit->dump();
    }
    tail += ",\"msg\":\"";
    tail += json_escape(j.value("msg", std::string()));
    tail += "\"";
    return tail;
}

}  // namespace

void init(const config_t& cfg) {
    module_state* st = state();
    nlohmann::ordered_json meta_ctx;
    bool should_emit = false;
    {
        std::lock_guard<std::mutex> lock(st->mtx);
        if (st->initialized) {
            return;
        }
        std::error_code ec;
        std::filesystem::create_directories(cfg.directory, ec);
        st->directory = cfg.directory;
        st->basename = cfg.basename;
        st->logger_name = cfg.basename;
        st->max_bytes = cfg.max_bytes;
        st->max_files = cfg.max_files;
        st->async = cfg.async;
        st->to_stderr = cfg.to_stderr;
        st->track_resources = cfg.track_resources;
        st->min_level_value = cfg.min_level;
        st->run_id = generate_run_id();
        collect_host_info(st);
        std::size_t recovered = 0;
        if (cfg.recover_on_init) {
            recovered = recover_from_crash_locked(st);
        }
        std::filesystem::path base =
            base_log_path(paths_t{cfg.directory, cfg.basename, cfg.max_files});
        spdlog::sink_ptr fs = std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
            base.string(), st->max_bytes, st->max_files);
        std::shared_ptr<spdlog::sinks::stderr_color_sink_mt> cs;
        if (st->to_stderr) {
            cs = std::make_shared<spdlog::sinks::stderr_color_sink_mt>(
                spdlog::color_mode::automatic);
        }
        std::vector<spdlog::sink_ptr> sinks;
        if (cs) {
            sinks.push_back(cs);
        }
        sinks.push_back(fs);
        std::unique_ptr<spdlog::formatter> file_fmt(new spdlog::pattern_formatter(
            "%N", spdlog::pattern_time_type::utc, "\n", make_flags()));
        fs->set_formatter(std::move(file_fmt));
        if (cs) {
            std::unique_ptr<spdlog::formatter> con_fmt(new spdlog::pattern_formatter(
                "%^%R|%L|%S|%T|%Q|%J%$", spdlog::pattern_time_type::utc, "\n", make_flags()));
            cs->set_formatter(std::move(con_fmt));
#ifdef _WIN32
            cs->set_color(spdlog::level::trace,
                          static_cast<std::uint16_t>(FOREGROUND_GREEN | FOREGROUND_BLUE));
#else
            cs->set_color(spdlog::level::trace, "\033[0;36m");
#endif
        }
        std::shared_ptr<spdlog::logger> lg;
        if (st->async) {
            spdlog::init_thread_pool(8192, 1);
            lg = std::make_shared<spdlog::async_logger>(
                st->logger_name, sinks.begin(), sinks.end(), spdlog::thread_pool(),
                spdlog::async_overflow_policy::block);
        } else {
            lg = std::make_shared<spdlog::logger>(st->logger_name, sinks.begin(), sinks.end());
        }
        lg->set_level(internal::to_spdlog(st->min_level_value));
        st->logger = lg;
        st->file = std::static_pointer_cast<spdlog::sinks::rotating_file_sink_mt>(fs);
        st->console = cs;
        st->initialized = true;
        if (!st->atexit_registered) {
            st->atexit_registered = true;
            std::atexit(&shutdown_wrapper);
        }
        meta_ctx["dir"] = st->directory.string();
        meta_ctx["file"] = base.string();
        meta_ctx["max_mb"] = static_cast<double>(st->max_bytes) / (1024.0 * 1024.0);
        meta_ctx["max_files"] = st->max_files;
        meta_ctx["async"] = st->async;
        meta_ctx["min_level"] = level_enum_name(st->min_level_value);
        meta_ctx["run_id"] = st->run_id;
        meta_ctx["recovered_tail_bytes"] = recovered;
        should_emit = true;
    }
    if (should_emit) {
        try {
            std::string ctx = meta_ctx.dump();
            internal::emit_impl(spdlog::level::info, status::success, nullptr, ctx.c_str(),
                                nullptr, __FILE__, __LINE__, "logging initialized");
        } catch (...) {
        }
    }
}

void shutdown() noexcept {
    module_state* st = state();
    {
        std::lock_guard<std::mutex> lock(st->mtx);
        if (!st->logger) {
            return;
        }
        try {
            st->logger->flush();
        } catch (...) {
        }
        st->logger.reset();
        st->file.reset();
        st->console.reset();
        st->initialized = false;
    }
    try {
        spdlog::shutdown();
    } catch (...) {
    }
}

std::shared_ptr<spdlog::logger> get() {
    module_state* st = state();
    std::lock_guard<std::mutex> lock(st->mtx);
    return st->logger;
}

void set_level(level l) {
    module_state* st = state();
    std::shared_ptr<spdlog::logger> lg;
    {
        std::lock_guard<std::mutex> lock(st->mtx);
        st->min_level_value = l;
        lg = st->logger;
    }
    if (lg) {
        lg->set_level(internal::to_spdlog(l));
    }
}

level get_level() {
    module_state* st = state();
    std::lock_guard<std::mutex> lock(st->mtx);
    return st->min_level_value;
}

void rotate_now() {
    module_state* st = state();
    std::shared_ptr<spdlog::sinks::rotating_file_sink_mt> f;
    {
        std::lock_guard<std::mutex> lock(st->mtx);
        f = st->file;
    }
    if (f) {
        try {
            f->rotate_now();
        } catch (...) {
        }
    }
}

std::string current_run_id() {
    module_state* st = state();
    std::lock_guard<std::mutex> lock(st->mtx);
    return st->run_id;
}

nlohmann::json host_info() {
    module_state* st = state();
    std::lock_guard<std::mutex> lock(st->mtx);
    nlohmann::json j;
    j["pid"] = st->host_pid;
    j["hostname"] = st->host_hostname;
    j["platform"] = st->host_platform;
    j["arch"] = st->host_arch;
    return j;
}

// ---------------------------------------------------------------------------
// Trace helpers. No macros: they call internal::emit_impl directly.
// ---------------------------------------------------------------------------

void trace_attached(std::string_view path) {
    internal::emit_impl(spdlog::level::info, status::info, nullptr, nullptr, nullptr,
                        __FILE__, __LINE__,
                        "trace attached to '" + std::string(path) + "'");
}

void trace_detached(std::size_t lines, std::size_t bytes) {
    internal::emit_impl(spdlog::level::info, status::info, nullptr, nullptr, nullptr,
                        __FILE__, __LINE__,
                        "trace detached: " + std::to_string(lines) + " lines, " +
                            std::to_string(bytes) + " bytes");
}

void trace_line_written(std::size_t bytes) {
    internal::emit_impl(spdlog::level::debug, status::debug, nullptr, nullptr, nullptr,
                        __FILE__, __LINE__,
                        "trace line written: " + std::to_string(bytes) + " bytes");
}

void trace_error(std::string_view reason) {
    internal::emit_impl(spdlog::level::err, status::failure, nullptr, nullptr, nullptr,
                        __FILE__, __LINE__,
                        "trace error: " + std::string(reason));
}

void trace_buffer_full() {
    internal::emit_impl(spdlog::level::warn, status::warning, nullptr, nullptr, nullptr,
                        __FILE__, __LINE__, "trace buffer full");
}

resource_sample_t sample_current() noexcept {
    try {
        return sample_current_impl();
    } catch (...) {
        return resource_sample_t{};
    }
}

resource_sample_t sample_delta(const resource_sample_t& a, const resource_sample_t& b) noexcept {
    resource_sample_t r;
    auto d = [](double x, double y) { return y > x ? y - x : 0.0; };
    r.elapsed_ms = b.elapsed_ms - a.elapsed_ms;
    r.cpu_user_ms = d(a.cpu_user_ms, b.cpu_user_ms);
    r.cpu_sys_ms = d(a.cpu_sys_ms, b.cpu_sys_ms);
    r.memory_mb = d(a.memory_mb, b.memory_mb);
    r.peak_memory_mb = d(a.peak_memory_mb, b.peak_memory_mb);
    r.disk_read_kb = d(a.disk_read_kb, b.disk_read_kb);
    r.disk_write_kb = d(a.disk_write_kb, b.disk_write_kb);
    return r;
}

void set_resource_tracking(bool on) {
    module_state* st = state();
    std::lock_guard<std::mutex> lock(st->mtx);
    st->track_resources = on;
}

std::size_t recover_from_crash() {
    module_state* st = state();
    std::lock_guard<std::mutex> lock(st->mtx);
    return recover_from_crash_locked(st);
}

recovered_run_t recover_run(const std::string& run_id) {
    module_state* st = state();
    paths_t p = snapshot_paths(st);
    recovered_run_t out;
    out.run_id = run_id;
    for (const std::filesystem::path& path : log_files(p)) {
        std::error_code ec;
        if (!std::filesystem::exists(path, ec)) {
            continue;
        }
        out.files.push_back(path.string());
        std::ifstream f(path, std::ios::binary);
        std::string line;
        while (std::getline(f, line)) {
            ++out.total_lines;
            out.bytes_read += line.size() + 1;
            if (!line.empty() && line.back() == '\r') {
                line.pop_back();
            }
            if (line.empty()) {
                continue;
            }
            nlohmann::json j;
            try {
                j = nlohmann::json::parse(line);
            } catch (...) {
                ++out.skipped_lines;
                continue;
            }
            if (!j.is_object() || j.value("run_id", std::string()) != run_id) {
                ++out.skipped_lines;
                continue;
            }
            out.records.push_back(std::move(j));
        }
    }
    return out;
}

std::vector<run_summary_t> list_runs() {
    module_state* st = state();
    paths_t p = snapshot_paths(st);
    std::map<std::string, std::size_t> counts;
    std::map<std::string, std::string> firsts;
    std::map<std::string, std::string> lasts;
    for (const std::filesystem::path& path : log_files(p)) {
        std::error_code ec;
        if (!std::filesystem::exists(path, ec)) {
            continue;
        }
        std::ifstream f(path, std::ios::binary);
        std::string line;
        while (std::getline(f, line)) {
            if (!line.empty() && line.back() == '\r') {
                line.pop_back();
            }
            if (line.empty()) {
                continue;
            }
            nlohmann::json j;
            try {
                j = nlohmann::json::parse(line);
            } catch (...) {
                continue;
            }
            if (!j.is_object() || !j.contains("ts")) {
                continue;
            }
            std::string rid = j.value("run_id", std::string());
            if (rid.empty()) {
                rid = "<none>";
            }
            std::string ts = j.value("ts", std::string());
            ++counts[rid];
            auto fit = firsts.find(rid);
            if (fit == firsts.end()) {
                firsts.emplace(rid, ts);
            } else if (ts < fit->second) {
                fit->second = ts;
            }
            auto lit = lasts.find(rid);
            if (lit == lasts.end()) {
                lasts.emplace(rid, ts);
            } else if (ts > lit->second) {
                lit->second = ts;
            }
        }
    }
    std::vector<run_summary_t> out;
    out.reserve(counts.size());
    for (const auto& kv : counts) {
        run_summary_t s;
        s.run_id = kv.first;
        s.records = kv.second;
        auto fit = firsts.find(kv.first);
        auto lit = lasts.find(kv.first);
        s.first_ts = fit != firsts.end() ? fit->second : std::string();
        s.last_ts = lit != lasts.end() ? lit->second : std::string();
        out.push_back(std::move(s));
    }
    std::sort(out.begin(), out.end(), [](const run_summary_t& a, const run_summary_t& b) {
        return a.first_ts < b.first_ts;
    });
    return out;
}

std::string recover_as_text(const log_filter_t& filter) {
    module_state* st = state();
    paths_t p = snapshot_paths(st);
    std::string since_iso = filter.since ? iso_of_timepoint(*filter.since) : std::string();
    std::string until_iso = filter.until ? iso_of_timepoint(*filter.until) : std::string();
    std::string out;
    std::size_t taken = 0;
    for (const std::filesystem::path& path : log_files(p)) {
        std::error_code ec;
        if (!std::filesystem::exists(path, ec)) {
            continue;
        }
        std::ifstream f(path, std::ios::binary);
        std::string line;
        while (std::getline(f, line)) {
            if (!line.empty() && line.back() == '\r') {
                line.pop_back();
            }
            if (line.empty()) {
                continue;
            }
            nlohmann::json j;
            try {
                j = nlohmann::json::parse(line);
            } catch (...) {
                continue;
            }
            if (!j.is_object() || !record_matches(j, filter, since_iso, until_iso)) {
                continue;
            }
            std::string status = j.value("status", std::string());
            const char* color = "32";
            if (status == "failure") {
                color = "31";
            } else if (status == "warning") {
                color = "33";
            } else if (status == "debug") {
                color = "36";
            }
            std::string ts = j.value("ts", std::string());
            std::string lvl = j.value("level", std::string());
            std::transform(lvl.begin(), lvl.end(), lvl.begin(),
                           [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
            std::string rendered = ts + "|" + lvl + "|" + status + "|" +
                                   j.value("thread", std::string()) + "|" +
                                   j.value("source", std::string()) + render_tail(j);
            out += "\033[0;";
            out += color;
            out += "m";
            out += rendered;
            out += "\033[0m\n";
            ++taken;
            if (filter.limit != 0 && taken >= filter.limit) {
                return out;
            }
        }
    }
    return out;
}

std::string recover_as_json(const log_filter_t& filter) {
    module_state* st = state();
    paths_t p = snapshot_paths(st);
    std::string since_iso = filter.since ? iso_of_timepoint(*filter.since) : std::string();
    std::string until_iso = filter.until ? iso_of_timepoint(*filter.until) : std::string();
    std::string out;
    std::size_t taken = 0;
    for (const std::filesystem::path& path : log_files(p)) {
        std::error_code ec;
        if (!std::filesystem::exists(path, ec)) {
            continue;
        }
        std::ifstream f(path, std::ios::binary);
        std::string line;
        while (std::getline(f, line)) {
            if (!line.empty() && line.back() == '\r') {
                line.pop_back();
            }
            if (line.empty()) {
                continue;
            }
            nlohmann::json j;
            try {
                j = nlohmann::json::parse(line);
            } catch (...) {
                continue;
            }
            if (!j.is_object() || !record_matches(j, filter, since_iso, until_iso)) {
                continue;
            }
            out += line;
            out += '\n';
            ++taken;
            if (filter.limit != 0 && taken >= filter.limit) {
                return out;
            }
        }
    }
    return out;
}

operation_t::operation_t(std::string name, nlohmann::json ctx, const char* file, int line)
    : name_(std::move(name)),
      ctx_(std::move(ctx)),
      start_(std::chrono::steady_clock::now()),
      file_(file),
      line_(line),
      active_(true) {
    try {
        start_sample_ = sample_current_impl();
        std::string op, ctx_frag;
        if (!name_.empty()) {
            op = "\"";
            op += json_escape(name_);
            op += "\"";
        }
        if (ctx_.is_object() && !ctx_.empty()) {
            ctx_frag = std::string(ctx_.dump());
        }
        internal::emit_impl(spdlog::level::info, status::info, op.empty() ? nullptr : op.c_str(),
                            ctx_frag.empty() ? nullptr : ctx_frag.c_str(), nullptr, file_, line_,
                            "start");
    } catch (...) {
    }
}

operation_t::operation_t(operation_t&& other) noexcept
    : name_(std::move(other.name_)),
      ctx_(std::move(other.ctx_)),
      start_(other.start_),
      start_sample_(other.start_sample_),
      file_(other.file_),
      line_(other.line_),
      active_(other.active_) {
    other.active_ = false;
}

operation_t& operation_t::operator=(operation_t&& other) noexcept {
    if (this != &other) {
        close_(status::success, "completed", nlohmann::json{});
        name_ = std::move(other.name_);
        ctx_ = std::move(other.ctx_);
        start_ = other.start_;
        start_sample_ = other.start_sample_;
        file_ = other.file_;
        line_ = other.line_;
        active_ = other.active_;
        other.active_ = false;
    }
    return *this;
}

operation_t::~operation_t() noexcept {
    close_(status::success, "completed", nlohmann::json{});
}

void operation_t::success(nlohmann::json extra) {
    close_(status::success, "completed", std::move(extra));
}

void operation_t::failure(std::string reason, nlohmann::json extra) {
    if (reason.empty()) {
        reason = "failed";
    }
    close_(status::failure, std::move(reason), std::move(extra));
}

void operation_t::warning(std::string reason, nlohmann::json extra) {
    if (reason.empty()) {
        reason = "warning";
    }
    close_(status::warning, std::move(reason), std::move(extra));
}

void operation_t::context(nlohmann::json data) {
    if (!active_ || !data.is_object() || data.empty()) {
        return;
    }
    if (ctx_.is_object()) {
        ctx_.update(data);
    } else {
        ctx_ = std::move(data);
    }
}

void operation_t::close_(status st, std::string msg, nlohmann::json extra) noexcept {
    if (!active_) {
        return;
    }
    active_ = false;
    try {
        spdlog::level::level_enum lvl;
        switch (st) {
            case status::failure:
                lvl = spdlog::level::err;
                break;
            case status::warning:
                lvl = spdlog::level::warn;
                break;
            case status::debug:
                lvl = spdlog::level::debug;
                break;
            case status::success:
            case status::info:
            default:
                lvl = spdlog::level::info;
                break;
        }
        nlohmann::json ctx = ctx_;
        if (extra.is_object() && !extra.empty()) {
            if (ctx.is_object()) {
                ctx.update(extra);
            } else {
                ctx = std::move(extra);
            }
        }
        std::string op, ctx_frag, res_frag;
        if (!name_.empty()) {
            op = "\"";
            op += json_escape(name_);
            op += "\"";
        }
        if (ctx.is_object() && !ctx.empty()) {
            ctx_frag = std::string(ctx.dump());
        }
        module_state* mstate = state();
        bool tracking = false;
        {
            std::lock_guard<std::mutex> lock(mstate->mtx);
            tracking = mstate->track_resources;
        }
        if (tracking) {
            resource_sample_t now = sample_current_impl();
            resource_sample_t delta = sample_delta(start_sample_, now);
            delta.elapsed_ms = static_cast<double>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - start_)
                    .count());
            res_frag = resource_json(delta);
        }
        if (msg.empty()) {
            msg = "completed";
        }
        internal::emit_impl(lvl, st, op.empty() ? nullptr : op.c_str(),
                            ctx_frag.empty() ? nullptr : ctx_frag.c_str(),
                            res_frag.empty() ? nullptr : res_frag.c_str(), file_, line_,
                            std::move(msg));
    } catch (...) {
    }
}

namespace internal {

bool enabled() {
    module_state* st = state();
    if (!st) {
        return false;
    }
    std::lock_guard<std::mutex> lock(st->mtx);
    return static_cast<bool>(st->logger);
}

spdlog::level::level_enum to_spdlog(level l) noexcept {
    switch (l) {
        case level::trace:
            return spdlog::level::trace;
        case level::debug:
            return spdlog::level::debug;
        case level::info:
            return spdlog::level::info;
        case level::warn:
            return spdlog::level::warn;
        case level::error:
            return spdlog::level::err;
        case level::critical:
            return spdlog::level::critical;
    }
    return spdlog::level::info;
}

void emit_impl(spdlog::level::level_enum lvl, status st, const char* op_json,
               const char* ctx_json, const char* res_json, const char* file, int line,
               std::string msg) {
    try {
        (void)file;
        (void)line;
        module_state* stt = state();
        if (!stt) {
            return;
        }
        std::shared_ptr<spdlog::logger> lg;
        {
            std::lock_guard<std::mutex> lock(stt->mtx);
            lg = stt->logger;
        }
        if (!lg || !lg->should_log(lvl)) {
            return;
        }
        std::string payload;
        payload.reserve(msg.size() + 64);
        payload.push_back(status_char(st));
        payload.push_back('\x1f');
        if (op_json) {
            payload += op_json;
        }
        payload.push_back('\x1f');
        if (ctx_json) {
            payload += ctx_json;
        }
        payload.push_back('\x1f');
        if (res_json) {
            payload += res_json;
        }
        payload.push_back('\x1f');
        payload += msg;
        // Single choke point for the whole record: message plus the JSON
        // context of LOG_OPERATION. Anything that quoted a credential (a
        // config dump, a curl header, a pipeline environment value) loses it
        // here, before it reaches the JSONL file on disk.
        payload = redact::scrub(payload);
        spdlog::source_loc loc{};
#ifndef NDEBUG
        if (file) {
            loc.filename = file;
            loc.line = line;
        }
#endif
        lg->log(loc, lvl, spdlog::string_view_t(payload.data(), payload.size()));
    } catch (...) {
    }
}

} 

}  