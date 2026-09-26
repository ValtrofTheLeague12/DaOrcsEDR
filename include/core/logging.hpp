#pragma once

#include <chrono>
#include <cstddef>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

namespace logging {

enum class level { trace, debug, info, warn, error, critical };
enum class status { success, failure, warning, debug, info };


#define LOG_TRACE(...)    ::logging::trace(__FILE__, __LINE__, __VA_ARGS__)
#define LOG_DEBUG(...)    ::logging::debug(__FILE__, __LINE__, __VA_ARGS__)
#define LOG_INFO(...)     ::logging::info(__FILE__, __LINE__, __VA_ARGS__)
#define LOG_WARN(...)     ::logging::warn(__FILE__, __LINE__, __VA_ARGS__)
#define LOG_ERROR(...)    ::logging::error(__FILE__, __LINE__, __VA_ARGS__)
#define LOG_CRITICAL(...) ::logging::critical(__FILE__, __LINE__, __VA_ARGS__)
#define LOG_OPERATION(name, ctx) \
    ::logging::operation_t _logging_operation_guard_(name, ctx, __FILE__, __LINE__)

struct config_t {
    std::filesystem::path directory{"logs"};
    std::string basename{"static_analyzer"};
    std::size_t max_bytes = 200u * 1024u * 1024u;
    std::size_t max_files = 5;
    level min_level = level::info;
    bool async = true;
    bool to_stderr = false;
    bool track_resources = true;
    bool recover_on_init = true;
};

struct resource_sample_t {
    double elapsed_ms = 0.0;
    double cpu_user_ms = 0.0;
    double cpu_sys_ms = 0.0;
    double memory_mb = 0.0;
    double peak_memory_mb = 0.0;
    double disk_read_kb = 0.0;
    double disk_write_kb = 0.0;
};

struct recovered_run_t {
    std::string run_id;
    std::vector<nlohmann::json> records;
    std::vector<std::string> files;
    std::size_t total_lines = 0;
    std::size_t skipped_lines = 0;
    std::size_t bytes_read = 0;
    std::size_t bytes_repaired = 0;
};

struct run_summary_t {
    std::string run_id;
    std::size_t records = 0;
    std::string first_ts;
    std::string last_ts;
};

struct log_filter_t {
    std::string run_id;
    std::string level;
    std::string status;
    std::string module;
    std::optional<std::chrono::system_clock::time_point> since;
    std::optional<std::chrono::system_clock::time_point> until;
    std::size_t limit = 0;
};

void init(const config_t& cfg = config_t{});
void shutdown() noexcept;
std::shared_ptr<spdlog::logger> get();
void set_level(level l);
level get_level();
void rotate_now();
std::string current_run_id();
nlohmann::json host_info();
void trace_attached(std::string_view path);
void trace_detached(std::size_t lines, std::size_t bytes);
void trace_line_written(std::size_t bytes);
void trace_error(std::string_view reason);
void trace_buffer_full();
resource_sample_t sample_current() noexcept;
resource_sample_t sample_delta(const resource_sample_t& a, const resource_sample_t& b) noexcept;
void set_resource_tracking(bool on);
std::size_t recover_from_crash();
recovered_run_t recover_run(const std::string& run_id);
std::vector<run_summary_t> list_runs();
std::string recover_as_text(const log_filter_t& filter);
std::string recover_as_json(const log_filter_t& filter);

class operation_t {
public:
    operation_t(std::string name, nlohmann::json ctx = nlohmann::json{},
                const char* file = nullptr, int line = 0);
    operation_t(operation_t&& other) noexcept;
    operation_t& operator=(operation_t&& other) noexcept;
    operation_t(const operation_t&) = delete;
    operation_t& operator=(const operation_t&) = delete;
    ~operation_t() noexcept;

    void success(nlohmann::json extra = nlohmann::json{});
    void failure(std::string reason, nlohmann::json extra = nlohmann::json{});
    void warning(std::string reason, nlohmann::json extra = nlohmann::json{});
    void context(nlohmann::json data);

private:
    void close_(status st, std::string msg, nlohmann::json extra) noexcept;
    std::string name_;
    nlohmann::json ctx_;
    std::chrono::steady_clock::time_point start_;
    resource_sample_t start_sample_;
    const char* file_;
    int line_;
    bool active_;
};

namespace internal {

bool enabled();
spdlog::level::level_enum to_spdlog(level l) noexcept;
void emit_impl(spdlog::level::level_enum lvl, status st, const char* op_json,
               const char* ctx_json, const char* res_json, const char* file, int line,
               std::string msg);

template <typename... Args>
inline void emit_fmt(level lvl, status st, const char* file, int line,
                     const char* fmt, Args&&... args) {
    std::string msg;
    try {
        msg = spdlog::fmt_lib::format(spdlog::fmt_lib::runtime(fmt ? fmt : ""),
                                      std::forward<Args>(args)...);
    } catch (...) {
        msg = fmt ? fmt : "";
    }
    emit_impl(to_spdlog(lvl), st, nullptr, nullptr, nullptr, file, line, std::move(msg));
}

}  

template <typename... Args>
inline void trace(const char* file, int line, const char* fmt, Args&&... args) {
    if (internal::enabled()) {
        internal::emit_fmt(level::trace, status::debug, file, line, fmt,
                           std::forward<Args>(args)...);
    }
}

template <typename... Args>
inline void debug(const char* file, int line, const char* fmt, Args&&... args) {
    if (internal::enabled()) {
        internal::emit_fmt(level::debug, status::debug, file, line, fmt,
                           std::forward<Args>(args)...);
    }
}

template <typename... Args>
inline void info(const char* file, int line, const char* fmt, Args&&... args) {
    if (internal::enabled()) {
        internal::emit_fmt(level::info, status::info, file, line, fmt,
                           std::forward<Args>(args)...);
    }
}

template <typename... Args>
inline void warn(const char* file, int line, const char* fmt, Args&&... args) {
    if (internal::enabled()) {
        internal::emit_fmt(level::warn, status::warning, file, line, fmt,
                           std::forward<Args>(args)...);
    }
}

template <typename... Args>
inline void error(const char* file, int line, const char* fmt, Args&&... args) {
    if (internal::enabled()) {
        internal::emit_fmt(level::error, status::failure, file, line, fmt,
                           std::forward<Args>(args)...);
    }
}

template <typename... Args>
inline void critical(const char* file, int line, const char* fmt, Args&&... args) {
    if (internal::enabled()) {
        internal::emit_fmt(level::critical, status::failure, file, line, fmt,
                           std::forward<Args>(args)...);
    }
}

}  // namespace logging