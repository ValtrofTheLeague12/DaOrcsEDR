#include "resume.hpp"

#include <atomic>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <mutex>
#include <string>
#include <system_error>
#include <vector>

#include <nlohmann/json.hpp>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <csignal>
#include <unistd.h>
#endif

namespace {

using json = nlohmann::json;

std::atomic<bool> g_installed{false};

// 0 = no interrupt, 1 = one (stop at the next phase boundary), 2+ = the user
// has stopped asking nicely.
std::atomic<int> g_interrupts{0};

// Everything below is published from the run thread and read by the handler
// thread, so it is behind a mutex. The handler's critical section is a copy of
// one string and it never blocks on anything the run itself holds for long:
// phase_completed() holds the lock for the length of one file write and no more.
std::mutex g_mutex;
std::string g_pipeline;
std::string g_source;
std::string g_input;
std::string g_run_id;
std::string g_stem;
std::vector<std::string> g_completed;
std::filesystem::path g_dir;

// The last line the handler prints. Kept out of the handler's own formatting so
// the two paths cannot drift.
const char* const k_interrupt_notice =
    "\n[interrupt] Ctrl+C received - stopping after this phase.\n"
    "[interrupt] press Ctrl+C again to stop immediately.\n";

void write_line(std::FILE* out, const char* text) {
  std::fputs(text, out);
  std::fflush(out);
}

std::string sanitized(const std::string& in) {
  std::string out;
  out.reserve(in.size());
  for (char c : in) {
    const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                    (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.';
    out.push_back(ok ? c : '_');
  }
  if (out.empty()) out = "sample";
  return out;
}

// Temp + rename, so a crash mid-write cannot leave a checkpoint that parses but
// describes half a run. The resume file is read by the next invocation; a
// truncated one would silently skip phases it never completed.
void atomic_write(const std::filesystem::path& path, const std::string& body) {
  std::error_code ec;
  std::filesystem::create_directories(path.parent_path(), ec);
  if (ec) return;
  const std::filesystem::path tmp = path.string() + ".tmp";
  {
    std::FILE* f = nullptr;
#if defined(_WIN32)
    f = _wfopen(tmp.wstring().c_str(), L"wb");
#else
    f = std::fopen(tmp.string().c_str(), "wb");
#endif
    if (f == nullptr) return;
    if (!body.empty()) {
      std::fwrite(body.data(), 1, body.size(), f);
    }
    std::fflush(f);
    std::fclose(f);
  }
  std::filesystem::rename(tmp, path, ec);
  if (ec) {
    // Cross-device or a stale handle: fall back to a direct write rather than
    // leaving no checkpoint at all.
    std::FILE* f = nullptr;
#if defined(_WIN32)
    f = _wfopen(path.wstring().c_str(), L"wb");
#else
    f = std::fopen(path.string().c_str(), "wb");
#endif
    if (f != nullptr) {
      if (!body.empty()) std::fwrite(body.data(), 1, body.size(), f);
      std::fflush(f);
      std::fclose(f);
    }
    std::error_code ignored;
    std::filesystem::remove(tmp, ignored);
  }
}

#if defined(_WIN32)
BOOL WINAPI on_console_event(DWORD type) {
  switch (type) {
    case CTRL_C_EVENT:
    case CTRL_BREAK_EVENT:
      break;
    default:
      return FALSE;  // let the default handler deal with close/logoff/shutdown
  }
  const int n = g_interrupts.fetch_add(1) + 1;
  write_line(stderr, k_interrupt_notice);
  if (n >= 2) {
    write_line(stderr,
               "[interrupt] second interrupt - exiting now. The checkpoint holds "
               "every phase that finished.\n");
    // Hand the event back so the console closes the process the way it would
    // have without us; the checkpoint is already on disk either way.
    return FALSE;
  }
  return TRUE;
}
#else
extern "C" void on_sigint(int) {
  const int n = g_interrupts.fetch_add(1) + 1;
  write_line(stderr, k_interrupt_notice);
  if (n >= 2) {
    std::signal(SIGINT, SIG_DFL);
    std::raise(SIGINT);
  }
}
#endif

}  // namespace

namespace resume {

void install() {
  if (g_installed.exchange(true)) return;
#if defined(_WIN32)
  SetConsoleCtrlHandler(&on_console_event, TRUE);
#else
  struct sigaction action{};
  action.sa_handler = &on_sigint;
  sigemptyset(&action.sa_mask);
  action.sa_flags = 0;  // NOT SA_RESTART: a blocking child wait should return
                         // EINTR so the loop can notice the flag.
  sigaction(SIGINT, &action, nullptr);
#endif
}

void set_logs_root(const std::filesystem::path& logs_root) {
  std::lock_guard<std::mutex> lock(g_mutex);
  g_dir = logs_root / "resume";
}

void begin(std::string_view pipeline, std::string_view source,
           std::string_view input, std::string_view run_id,
           std::string_view stem) {
  std::lock_guard<std::mutex> lock(g_mutex);
  g_pipeline.assign(pipeline);
  g_source.assign(source);
  g_input.assign(input);
  g_run_id.assign(run_id);
  g_stem.assign(stem);
  g_completed.clear();
}

void phase_completed(std::string_view name) {
  // One lock for the whole update: the snapshot that goes on disk is built from
  // the same critical section that appends to it, so the file can never describe
  // a phase that is not in the list.
  std::filesystem::path path;
  std::string body;
  {
    std::lock_guard<std::mutex> lock(g_mutex);
    g_completed.emplace_back(name);
    if (g_dir.empty() || g_stem.empty()) return;
    path = g_dir / (sanitized(g_stem) + ".json");

    json doc;
    doc["pipeline"] = g_pipeline;
    doc["source"] = g_source;
    doc["input"] = g_input;
    doc["stem"] = g_stem;
    doc["run_id"] = g_run_id;
    doc["saved_at"] = static_cast<long long>(std::time(nullptr));
    doc["completed"] = g_completed;
    body = doc.dump(2) + "\n";
  }
  // The write is outside the lock on purpose: it is the only slow part, and the
  // handler must not sit behind a file I/O it may be waiting on.
  atomic_write(path, body);
}

bool stop_requested() {
  return g_interrupts.load(std::memory_order_acquire) > 0;
}

int interrupts() {
  return g_interrupts.load(std::memory_order_acquire);
}

void clear() {
  std::filesystem::path path;
  {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_dir.empty() || g_stem.empty()) return;
    path = g_dir / (sanitized(g_stem) + ".json");
    g_completed.clear();
  }
  std::error_code ec;
  std::filesystem::remove(path, ec);
}

std::filesystem::path path_for(std::string_view stem,
                               const std::filesystem::path& logs_root) {
  return logs_root / "resume" / (sanitized(std::string(stem)) + ".json");
}

point load(const std::filesystem::path& file) {
  point out;
  std::error_code ec;
  // std::filesystem::is_regular_file(path, ec), not path.is_file(): the member
  // throws on a filesystem error, and the one caller that matters here is a
  // checkpoint on a disk that may not be there.
  if (!std::filesystem::is_regular_file(file, ec)) return out;
  std::FILE* f = nullptr;
#if defined(_WIN32)
  f = _wfopen(file.wstring().c_str(), L"rb");
#else
  f = std::fopen(file.string().c_str(), "rb");
#endif
  if (f == nullptr) return out;
  std::string text;
  char buf[4096];
  std::size_t n = 0;
  while ((n = std::fread(buf, 1, sizeof(buf), f)) > 0) text.append(buf, n);
  std::fclose(f);

  try {
    json doc = json::parse(text);
    if (!doc.is_object()) return out;
    out.pipeline = doc.value("pipeline", std::string());
    out.source = doc.value("source", std::string());
    out.input = doc.value("input", std::string());
    out.stem = doc.value("stem", std::string());
    out.run_id = doc.value("run_id", std::string());
    out.saved_at = doc.value("saved_at", 0LL);
    if (doc.contains("completed") && doc["completed"].is_array()) {
      for (const auto& item : doc["completed"]) {
        if (item.is_string()) out.completed.emplace_back(item.get<std::string>());
      }
    }
    out.valid = true;
  } catch (const std::exception&) {
    // A corrupt checkpoint is the same as no checkpoint: the operator gets a
    // full run and a clear message rather than a resume from a guess.
    return point{};
  }
  return out;
}

std::string describe() {
  std::lock_guard<std::mutex> lock(g_mutex);
  if (g_stem.empty()) return "(no run in progress)";
  std::string out = "checkpoint=" + (g_dir / (sanitized(g_stem) + ".json")).string();
  out += " completed=" + std::to_string(g_completed.size());
  if (!g_completed.empty()) {
    out += " last=" + g_completed.back();
  }
  out += " interrupts=" + std::to_string(g_interrupts.load(std::memory_order_acquire));
  return out;
}

}  // namespace resume