#include "debug_dump_macro.hpp"

#include "redact.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <sstream>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <unistd.h>
#endif

namespace debug_dump {
namespace {

std::mutex g_mtx;
std::ofstream g_out;
// The path is published atomically instead of being read from behind g_mtx:
// the crash handler calls log_path() and must never block on a mutex the
// crashing thread may already hold.
std::atomic<std::uint32_t> g_path_len{0};
char g_path_buf[512] = {};
std::atomic<bool> g_enabled{false};
std::atomic<bool> g_mirror{false};

std::string iso_now() {
  using namespace std::chrono;
  const auto now = system_clock::now();
  const std::time_t t = system_clock::to_time_t(now);
  const auto ms =
      duration_cast<milliseconds>(now.time_since_epoch()).count() % 1000;
  std::tm tm{};
#if defined(_WIN32)
  localtime_s(&tm, &t);
#else
  localtime_r(&t, &tm);
#endif
  std::ostringstream os;
  os << std::put_time(&tm, "%Y-%m-%dT%H:%M:%S") << '.'
     << std::setw(3) << std::setfill('0') << ms;
  return os.str();
}

unsigned long current_pid() {
#if defined(_WIN32)
  return static_cast<unsigned long>(GetCurrentProcessId());
#else
  return static_cast<unsigned long>(::getpid());
#endif
}

}  // namespace

void init(const std::filesystem::path& logs_root, std::string_view run_id,
          bool mirror_stderr) {
  g_mirror.store(mirror_stderr, std::memory_order_release);

  std::error_code ec;
  const std::filesystem::path dir = logs_root / "dumps";
  std::filesystem::create_directories(dir, ec);

  const std::string run(run_id.empty() ? "run" : std::string(run_id));
  const std::filesystem::path path = dir / (run + "-dumps.log");

  bool opened = false;
  {
    std::lock_guard<std::mutex> lock(g_mtx);
    g_out.open(path, std::ios::out | std::ios::app);
    if (g_out.is_open()) {
      g_out << "# static_analyzer debug dump\n"
            << "# run_id=" << run << " pid=" << current_pid()
            << " started=" << iso_now() << "\n"
            << "# redaction: " << redact::secret_count()
            << " secret value(s) registered with redact::seed()\n"
            << "# label format: [<file>:<line>] <expression> = <value>\n";
      g_out.flush();
      opened = true;
    }
  }

  if (!opened) {
    g_path_len.store(0, std::memory_order_release);
    g_enabled.store(false, std::memory_order_release);
    std::cerr << "[debug-dump] cannot open '" << path.string()
              << "'; dumps stay disabled\n";
    return;
  }

  {
    const std::string path_string = path.string();
    const std::size_t copy = path_string.size() > sizeof(g_path_buf) - 1
                                 ? sizeof(g_path_buf) - 1
                                 : path_string.size();
    std::memcpy(g_path_buf, path_string.data(), copy);
    g_path_buf[copy] = '\0';
    g_path_len.store(static_cast<std::uint32_t>(copy), std::memory_order_release);
  }

  // Plain text into a file: no ANSI colour, labels that carry the source
  // location so a dump line can be read without the stack trace.
  CPP_DUMP_SET_OPTION(max_line_width, 160);
  CPP_DUMP_SET_OPTION(max_depth, 6);
  CPP_DUMP_SET_OPTION(print_expr, true);
  CPP_DUMP_SET_OPTION(es_style, cpp_dump::types::es_style_t::no_es);
  CPP_DUMP_SET_OPTION(log_label_func, cpp_dump::log_label::basename(false, 0));

  g_enabled.store(true, std::memory_order_release);
  std::cerr << "[debug-dump] writing to '" << path.string() << "'\n";
}

bool enabled() { return g_enabled.load(std::memory_order_acquire); }

void write(std::string_view record) {
  if (!g_enabled.load(std::memory_order_acquire) || record.empty()) return;

  // A dump that cannot be written is a diagnostic failure, never a reason to
  // abort the analysis it is supposed to explain, so everything below swallows
  // its own exceptions.
  try {
    // Redact before anything touches the disk, and flush per record: the file
    // has to be complete when the process dies on the next line.
    const std::string clean = redact::scrub(record);
    const bool mirror = g_mirror.load(std::memory_order_acquire);

    std::lock_guard<std::mutex> lock(g_mtx);
    if (g_out.is_open()) {
      g_out << clean;
      if (clean.back() != '\n') g_out << '\n';
      g_out.flush();
    }
    if (mirror) {
      std::cerr << clean;
      if (clean.back() != '\n') std::cerr << '\n';
    }
  } catch (...) {
    // Deliberately silent: reporting this would itself need the I/O that just
    // failed, and the crash handler (if that is where we are) reads the dump
    // file by path, not through this mutex.
  }
}

std::string log_path() {
  // Lock-free on purpose: called from the crash handler, where taking g_mtx
  // could deadlock against the dump write that was in flight.
  const std::uint32_t len = g_path_len.load(std::memory_order_acquire);
  if (len == 0) return {};
  return std::string(g_path_buf, len);
}

}  // namespace debug_dump
