#include "sample_archive/archive_log.hpp"

#include <chrono>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <sstream>

namespace archive_log {

namespace {

bool g_verbose = false;
std::mutex g_mu;

const char* to_tag(level lv) {
    switch (lv) {
        case level::debug: return "DEBUG";
        case level::info:  return "INFO";
        case level::warn:  return "WARN";
        case level::error: return "ERROR";
    }
    return "?";
}

std::string timestamp() {
    const auto now = std::chrono::system_clock::now();
    const std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
#if defined(_WIN32)
    localtime_s(&tm, &t);
#else
    localtime_r(&t, &tm);
#endif
    std::ostringstream os;
    os << std::put_time(&tm, "%H:%M:%S");
    return os.str();
}

void emit(level lv, const std::string& msg) {
    std::lock_guard<std::mutex> lock(g_mu);
    std::cerr << "[" << timestamp() << "] [" << to_tag(lv) << "] " << msg << "\n";
}

}  // namespace

void set_verbose(bool on) { g_verbose = on; }
bool verbose() { return g_verbose; }

void error(const std::string& msg) { emit(level::error, msg); }

void debug(const std::string& msg) {
    if (g_verbose) emit(level::debug, msg);
}

void info(const std::string& msg) {
    if (g_verbose) emit(level::info, msg);
}

void warn(const std::string& msg) { emit(level::warn, msg); }

}  // namespace archive_log
