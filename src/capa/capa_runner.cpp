#include "capa_runner.hpp"
#include "logging.hpp"
#include "console.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <thread>

#include <nlohmann/json.hpp>

#include "process_runner.hpp"

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <io.h>
#include <windows.h>
#else
#include <unistd.h>
#endif

namespace capa {

namespace fs = std::filesystem;
using json = nlohmann::json;

// ---------------------------------------------------------------------------
// Size-based escalation
// ---------------------------------------------------------------------------
//
// capa's runtime scales with sample size and complexity. A 200 MB installer
// with thousands of functions takes orders of magnitude longer than a 2 MB
// loader. Rather than forcing the caller to guess a single timeout, we use:
//
//   * samples <= kLargeSampleBytes:  opts.timeout        (default 5 min)
//   * samples >  kLargeSampleBytes:  opts.large_timeout  (default 30 min)
//
// The threshold and both timeouts are configurable via options. The defaults
// live in capa_runner.hpp.

namespace {
constexpr std::uintmax_t kLargeSampleBytes = 50ull * 1024ull * 1024ull;  // 50 MiB
}

const char* to_string(status s) {
  switch (s) {
    case status::ok:               return "ok";
    case status::file_missing:     return "file_missing";
    case status::not_found:        return "not_found";
    case status::launch_failed:    return "launch_failed";
    case status::timed_out:        return "timed_out";
    case status::output_too_large: return "output_too_large";
    case status::exit_error:       return "exit_error";
    case status::bad_output:       return "bad_output";
    case status::rules_missing:    return "rules_missing";
  }
  return "unknown";
}

std::string describe_exit_code(int code) {
  switch (code) {
    case 0:  return {};
    case 10: return "capa could not find its rules (set options.rules_dir, or use the standalone capa build)";
    case 11: return "capa reports that the sample file is missing";
    case 12: return "capa rejected a rule file (invalid rule in the rules directory)";
    case 13: return "capa reports that the sample is corrupt";
    case 14: return "capa cannot analyze this file (file limitation, e.g. packed or obfuscated sample)";
    case 15: return "capa could not load its signatures (set options.signatures_dir)";
    case 16: return "capa does not support this file type (needs PE, ELF, .NET or shellcode)";
    case 17: return "capa does not support this file architecture";
    case 18: return "capa does not support this file's operating system (try options.os)";
    case 19: return "unsupported IDA version";
    case 20: return "unsupported Ghidra version";
    case 23: return "capa produced an empty report";
    case 25: return "invalid input format for the selected backend (see options.format / options.backend)";
    case 26: return "invalid feature extractor / backend selected (see options.backend)";
    case 127: return "the capa executable could not be started";
    default: break;
  }
  if (code > 128 && code < 160) return "capa was killed by signal " + std::to_string(code - 128);
  return "capa exited with code " + std::to_string(code);
}

namespace {

using clock_type = std::chrono::steady_clock;

double seconds_since(clock_type::time_point start) {
  return std::chrono::duration<double>(clock_type::now() - start).count();
}

std::string str_of(const json& object, const char* key) {
  if (!object.is_object()) return {};
  const auto it = object.find(key);
  return (it != object.end() && it->is_string()) ? it->get<std::string>() : std::string();
}

bool bool_of(const json& object, const char* key) {
  if (!object.is_object()) return false;
  const auto it = object.find(key);
  return it != object.end() && it->is_boolean() && it->get<bool>();
}

const json* child(const json& object, const char* key) {
  if (!object.is_object()) return nullptr;
  const auto it = object.find(key);
  return it == object.end() ? nullptr : &*it;
}

constexpr const char* kDiscardedKeys[] = {
    "source",
    "children",
    "node", "success", "captures", "locations",
    "layout",
    "feature_counts",
    "library_functions"
};

bool keep_value(int /*depth*/, json::parse_event_t event, json& parsed) {
  if (event == json::parse_event_t::key) {
    const std::string& key = parsed.get_ref<const std::string&>();
    for (const char* discarded : kDiscardedKeys) {
      if (key == discarded) return false;
    }
  }
  return true;
}

bool parse_document(std::string_view text, json& doc, std::string& error) {
  LOG_TRACE("capa: parse_document: input size={}", text.size());

  const std::size_t brace = text.find('{');
  if (brace == std::string_view::npos) {
    LOG_DEBUG("capa: parse_document: no '{{' found in output");
    error = "no JSON object in capa output";
    return false;
  }
  if (brace > 0) {
    LOG_DEBUG("capa: parse_document: skipping {} byte(s) of banner before JSON", brace);
  }
  text.remove_prefix(brace);

  doc = json::parse(text.begin(), text.end(), keep_value, /*allow_exceptions=*/false);
  if (doc.is_discarded() || !doc.is_object()) {
    LOG_WARN("capa: parse_document: output is not valid JSON (discarded={}, is_object={})",
             doc.is_discarded(), doc.is_object());
    error = "capa output is not valid JSON";
    return false;
  }

  const json* meta = child(doc, "meta");
  const json* rules = child(doc, "rules");
  if (meta == nullptr || !meta->is_object() || rules == nullptr || !rules->is_object()) {
    LOG_WARN("capa: parse_document: missing 'meta' or 'rules' (meta={}, rules={})",
             meta != nullptr, rules != nullptr);
    error = "JSON is not a capa result document (missing 'meta' / 'rules')";
    return false;
  }

  LOG_TRACE("capa: parse_document: valid capa document ({} top-level keys)", doc.size());
  return true;
}

bool address_value(const json& address, std::uint64_t& out) {
  if (!address.is_object()) return false;
  const std::string type = str_of(address, "type");
  if (type != "absolute" && type != "relative") return false;
  const json* value = child(address, "value");
  if (value == nullptr || !value->is_number_unsigned()) {
    if (value != nullptr && value->is_number_integer() && value->get<std::int64_t>() >= 0) {
      out = static_cast<std::uint64_t>(value->get<std::int64_t>());
      return true;
    }
    return false;
  }
  out = value->get<std::uint64_t>();
  return true;
}

report_t build_report(const json& doc, const options& opts) {
  LOG_DEBUG("capa: build_report: parsing capa document");

  report_t report;
  const json& meta = doc.at("meta");
  const json& rules = doc.at("rules");

  report.capa_version = str_of(meta, "version");
  report.flavor = str_of(meta, "flavor");
  if (const json* sample = child(meta, "sample")) {
    report.md5 = str_of(*sample, "md5");
    report.sha1 = str_of(*sample, "sha1");
    report.sha256 = str_of(*sample, "sha256");
  }
  if (const json* analysis = child(meta, "analysis")) {
    report.format = str_of(*analysis, "format");
    report.arch = str_of(*analysis, "arch");
    report.os = str_of(*analysis, "os");
    report.backend = str_of(*analysis, "extractor");
  }
  const bool dynamic = report.flavor == "dynamic";

  LOG_DEBUG("capa: build_report: version='{}', flavor='{}', format='{}', "
            "arch='{}', os='{}', extractor='{}'",
            report.capa_version, report.flavor, report.format,
            report.arch, report.os, report.backend);

  std::size_t skipped_no_meta = 0;

  for (auto it = rules.begin(); it != rules.end(); ++it) {
    const json& rule = it.value();
    const json* rule_meta = child(rule, "meta");
    if (rule_meta == nullptr || !rule_meta->is_object()) {
      ++skipped_no_meta;
      continue;
    }

    ++report.rules_matched;
    const bool library = bool_of(*rule_meta, "lib");
    if (library) ++report.library_rules;
    if (library && !opts.include_library_rules) continue;

    capability_t cap;
    cap.name = str_of(*rule_meta, "name");
    if (cap.name.empty()) cap.name = it.key();
    cap.namespace_path = str_of(*rule_meta, "namespace");
    cap.description = str_of(*rule_meta, "description");
    cap.library = library;

    if (const json* scopes = child(*rule_meta, "scopes")) {
      cap.scope = str_of(*scopes, dynamic ? "dynamic" : "static");
    } else {
      cap.scope = str_of(*rule_meta, "scope");
    }

    if (const json* attack = child(*rule_meta, "attack"); attack != nullptr && attack->is_array()) {
      for (const json& a : *attack) {
        attack_t entry{str_of(a, "tactic"), str_of(a, "technique"), str_of(a, "subtechnique"),
                       str_of(a, "id")};
        if (!entry.id.empty() || !entry.technique.empty()) cap.attack.push_back(std::move(entry));
      }
    }
    if (const json* mbc = child(*rule_meta, "mbc"); mbc != nullptr && mbc->is_array()) {
      for (const json& m : *mbc) {
        mbc_t entry{str_of(m, "objective"), str_of(m, "behavior"), str_of(m, "method"),
                    str_of(m, "id")};
        if (!entry.id.empty() || !entry.behavior.empty()) cap.mbc.push_back(std::move(entry));
      }
    }
    if (const json* matches = child(rule, "matches"); matches != nullptr && matches->is_array()) {
      cap.match_count = matches->size();
      for (const json& match : *matches) {
        if (cap.addresses.size() >= opts.max_addresses) break;
        if (!match.is_array() || match.empty()) continue;
        std::uint64_t address = 0;
        if (address_value(match[0], address)) cap.addresses.push_back(address);
      }
    }
    report.capabilities.push_back(std::move(cap));
  }

  std::sort(report.capabilities.begin(), report.capabilities.end(),
            [](const capability_t& a, const capability_t& b) {
              return a.namespace_path != b.namespace_path ? a.namespace_path < b.namespace_path
                                                          : a.name < b.name;
            });
  report.st = status::ok;

  if (skipped_no_meta > 0) {
    LOG_DEBUG("capa: build_report: skipped {} rule(s) without a 'meta' object", skipped_no_meta);
  }
  LOG_INFO("capa: build_report: matched={}, library_rules={}, capabilities={}",
           report.rules_matched, report.library_rules, report.capabilities.size());

  return report;
}

// --- command line --------------------------------------------------------------
std::vector<std::string> build_args(const std::string& sample, const options& opts) {
  std::vector<std::string> args = {"-j", "-q", "--color", "never"};
  auto add = [&](const char* flag, const std::string& value) {
    if (!value.empty()) {
      args.push_back(flag);
      args.push_back(value);
    }
  };
  add("-r", "C:/Users/The4thReich/Desktop/IAProject/capa-rules/");
  add("-s", "C:/Users/The4thReich/Desktop/IAProject/capa-sigs/");
  add("-b", opts.backend);
  add("-f", opts.format);
  add("--os", opts.os);
  for (const std::string& tag : opts.tags) add("-t", tag);
  args.insert(args.end(), opts.extra_args.begin(), opts.extra_args.end());
  args.push_back(sample);
  LOG_TRACE("capa: build_args: produced {} argument(s)", args.size());
  return args;
}

std::string join_command(const std::string& program, const std::vector<std::string>& args) {
  std::string line = program;
  for (const std::string& a : args) {
    line += ' ';
    if (a.find_first_of(" \t\"") != std::string::npos) line += '"' + a + '"';
    else line += a;
  }
  return line;
}

// Quote an argv vector so the line can be copy-pasted into a shell. An
// argument is wrapped in double quotes only when it contains a space, tab,
// double quote, or backslash — otherwise it's left bare. Existing double
// quotes inside an argument are escaped with a backslash.
std::string describe_argv(const std::string& program,
                          const std::vector<std::string>& args) {
  std::string line = program;
  for (const std::string& a : args) {
    line += ' ';
    const bool needs_quotes = a.find_first_of(" \t\"\\") != std::string::npos;
    if (!needs_quotes) { line += a; continue; }
    line += '"';
    for (char c : a) {
      if (c == '"' || c == '\\') line += '\\';
      line += c;
    }
    line += '"';
  }
  return line;
}

std::string tail_of(const std::string& text, std::size_t max_chars) {
  std::string out;
  out.reserve(std::min<std::size_t>(text.size(), max_chars * 2));
  bool pending_space = false;
  for (unsigned char ch : text) {
    if (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n') {
      pending_space = !out.empty();
      continue;
    }
    if (pending_space) out += ' ';
    pending_space = false;
    out += static_cast<char>(ch);
  }
  if (out.size() > max_chars) out = "..." + out.substr(out.size() - max_chars);
  return out;
}

std::uint64_t fnv1a(const std::string& text) {
  std::uint64_t hash = 1469598103934665603ull;
  for (unsigned char c : text) {
    hash ^= c;
    hash *= 1099511628211ull;
  }
  return hash;
}

std::string file_stamp(const std::string& path) {
  std::error_code ec;
  const auto size = fs::file_size(path, ec);
  const auto time = fs::last_write_time(path, ec);
  return path + "|" + (ec ? std::string("?") : std::to_string(size)) + "|" +
         (ec ? std::string("?") : std::to_string(time.time_since_epoch().count()));
}

fs::path cache_file(const std::string& sample, const options& opts, const std::string& exe) {
  std::error_code ec;
  const fs::path canonical = fs::weakly_canonical(sample, ec);
  std::string key = "v1|" + file_stamp(ec ? sample : canonical.string()) + "|" + file_stamp(exe) +
                    "|" + opts.rules_dir + "|" + opts.signatures_dir + "|" + opts.backend + "|" +
                    opts.format + "|" + opts.os + "|" + opts.cache_salt;
  for (const std::string& tag : opts.tags) key += "|t:" + tag;
  for (const std::string& arg : opts.extra_args) key += "|x:" + arg;
  char name[40];
  std::snprintf(name, sizeof(name), "capa-%016llx.json",
                static_cast<unsigned long long>(fnv1a(key)));
  const fs::path result = fs::path(opts.cache_dir) / name;
  LOG_TRACE("capa: cache_file: sample='{}' -> '{}'", sample, result.string());
  return result;
}

bool read_file(const fs::path& path, std::string& out) {
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    LOG_TRACE("capa: read_file: cannot open '{}'", path.string());
    return false;
  }
  out.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
  if (out.empty()) {
    LOG_DEBUG("capa: read_file: '{}' is empty", path.string());
    return false;
  }
  LOG_TRACE("capa: read_file: read {} bytes from '{}'", out.size(), path.string());
  return true;
}

void write_cache(const fs::path& path, const std::string& text) {
  std::error_code ec;
  fs::create_directories(path.parent_path(), ec);
  if (ec) {
    LOG_WARN("capa: write_cache: create_directories('{}') failed: {}",
             path.parent_path().string(), ec.message());
    return;
  }

  const fs::path tmp = path.string() + ".tmp";
  {
    std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
    if (!out) {
      LOG_WARN("capa: write_cache: cannot open '{}' for writing", tmp.string());
      return;
    }
    out.write(text.data(), static_cast<std::streamsize>(text.size()));
    if (!out) {
      LOG_WARN("capa: write_cache: write to '{}' failed (disk full?)", tmp.string());
      out.close();
      fs::remove(tmp, ec);
      return;
    }
  }
  fs::rename(tmp, path, ec);
  if (ec) {
    LOG_WARN("capa: write_cache: rename '{}' -> '{}' failed: {}",
             tmp.string(), path.string(), ec.message());
    fs::remove(tmp, ec);
    return;
  }
  LOG_DEBUG("capa: write_cache: wrote {} bytes to '{}'", text.size(), path.string());
}

// --- diagnostics helpers ---------------------------------------------------------
std::string show(const std::string& value) {
  return value.empty() ? std::string("<empty>") : value;
}

std::string absolute_of(const std::string& path) {
  if (path.empty()) return "<empty>";
  std::error_code ec;
  const fs::path resolved = fs::weakly_canonical(path, ec);
  return ec ? path : resolved.string();
}

std::string human_size(std::uintmax_t bytes) {
  char buf[32];
  if (bytes < 1024ull) {
    std::snprintf(buf, sizeof(buf), "%llu B", static_cast<unsigned long long>(bytes));
  } else if (bytes < 1024ull * 1024ull) {
    std::snprintf(buf, sizeof(buf), "%.1f KiB", static_cast<double>(bytes) / 1024.0);
  } else if (bytes < 1024ull * 1024ull * 1024ull) {
    std::snprintf(buf, sizeof(buf), "%.1f MiB", static_cast<double>(bytes) / (1024.0 * 1024.0));
  } else {
    std::snprintf(buf, sizeof(buf), "%.1f GiB",
                  static_cast<double>(bytes) / (1024.0 * 1024.0 * 1024.0));
  }
  return buf;
}

// --- spinner ---------------------------------------------------------------------
//
// A single-line terminal spinner that runs on its own thread while capa is
// executing. It prints frames like:
//
//   | capa is analyzing 'evil.exe' [normal phase] (12.3s elapsed) ...
//   / capa is analyzing 'evil.exe' [normal phase] (12.4s elapsed) ...
//
// The line is overwritten in place using a carriage return. When the spinner
// stops, the line is cleared so the caller's own output starts on a clean line.
//
// If stdout is not a terminal (piped, redirected, or in a CI environment), the
// spinner does nothing — this keeps log files and CI output readable.

bool stdout_is_tty() {
#if defined(_WIN32)
  return _isatty(_fileno(stdout)) != 0;
#else
  return ::isatty(STDOUT_FILENO) != 0;
#endif
}

class spinner {
public:
  spinner() = default;

  ~spinner() { stop(); }

  spinner(const spinner&) = delete;
  spinner& operator=(const spinner&) = delete;

  void start(std::string label) {
    if (running_.load(std::memory_order_acquire)) return;
    if (!stdout_is_tty()) {
      LOG_DEBUG("capa: spinner: stdout is not a terminal, disabled");
      return;
    }
    LOG_TRACE("capa: spinner: starting with label='{}'", label);
    label_ = std::move(label);
    running_.store(true, std::memory_order_release);
    start_time_ = clock_type::now();
    thread_ = std::thread([this] { run(); });
  }

  void stop() {
    if (!running_.exchange(false, std::memory_order_acq_rel)) {
      if (thread_.joinable()) thread_.join();
      return;
    }
    if (thread_.joinable()) thread_.join();

    std::fputs("\r\x1b[2K", stdout);  // CR + erase-in-line
    std::fflush(stdout);
    LOG_TRACE("capa: spinner: stopped after {:.3f}s", seconds_since(start_time_));
  }

private:
  void run() {
    static const char frames[] = {'|', '/', '-', '\\'};
    std::size_t i = 0;
    while (running_.load(std::memory_order_acquire)) {
      const double elapsed = seconds_since(start_time_);
      char buf[320];
      std::snprintf(buf, sizeof(buf),
                    "\r%c %s (%.1fs elapsed) ...",
                    frames[i % 4], label_.c_str(), elapsed);
      std::fputs(buf, stdout);
      std::fflush(stdout);
      ++i;
      std::this_thread::sleep_for(std::chrono::milliseconds(120));
    }
  }

  std::atomic<bool>        running_{false};
  std::string              label_;
  std::thread              thread_;
  clock_type::time_point   start_time_{};
};

// --- concise console helpers -----------------------------------------------------

void say(std::string_view msg) {
  console::info(std::string(msg));
}

void ok(std::string_view msg) {
  console::success(std::string(msg));
}

void warn(std::string_view msg) {
  console::info(console::paint(console::yellow, "[!] ") + std::string(msg));
}

void fail(std::string_view msg) {
  console::error(std::string("[!] ") + std::string(msg));
}

}  // namespace

// --- rules directory check -------------------------------------------------------
bool rules_dir_exists(const options& opts) {
  if (opts.rules_dir.empty()) {
    LOG_DEBUG("capa: rules_dir_exists: rules_dir empty, relying on capa default");
    return true;
  }

  std::error_code ec;
  if (!fs::exists(opts.rules_dir, ec) || ec) {
    LOG_WARN("capa: rules_dir_exists: '{}' not found (ec='{}')",
             opts.rules_dir, ec.message());
    warn("rules dir not found: " + absolute_of(opts.rules_dir));
    return false;
  }
  if (ec) {
    LOG_WARN("capa: rules_dir_exists: stat failed on '{}': {}",
             opts.rules_dir, ec.message());
    warn("rules dir stat failed: " + ec.message());
    return false;
  }

  std::error_code dec;
  if (!fs::is_directory(opts.rules_dir, dec) || dec) {
    LOG_WARN("capa: rules_dir_exists: '{}' is not a directory (ec='{}')",
             opts.rules_dir, dec.message());
    warn("rules dir is not a directory: " + absolute_of(opts.rules_dir));
    return false;
  }

  // capa's rules repo is a tree (collection/, anti-analysis/, nursery/, ...),
  // so a flat directory_iterator finds nothing. Recurse; skip_permission_denied
  // keeps the walk cheap when one subdirectory is unreadable.
  std::error_code cec;
  std::size_t rule_files = 0;
  for (auto it = fs::recursive_directory_iterator(
           opts.rules_dir, fs::directory_options::skip_permission_denied, cec);
       !cec && it != fs::recursive_directory_iterator();
       it.increment(cec)) {
    if (cec) break;
    if (!it->is_regular_file(cec) || cec) continue;
    const std::string ext = it->path().extension().string();
    if (ext == ".yml" || ext == ".yaml") {
      ++rule_files;
      if (rule_files >= 64) break;   // enough to prove the tree is populated
    }
  }
  if (cec) {
    LOG_WARN("capa: rules_dir_exists: enumeration failed for '{}': {}",
             opts.rules_dir, cec.message());
    warn("could not enumerate rules dir: " + cec.message());
    return true;
  }
  if (rule_files == 0) {
    LOG_WARN("capa: rules_dir_exists: '{}' has no .yml/.yaml rule files",
             opts.rules_dir);
    warn("rules dir exists but contains no .yml/.yaml rule files: " +
         absolute_of(opts.rules_dir));
    return false;
  }
  LOG_DEBUG("capa: rules_dir_exists: OK ({} rule file(s) found)", rule_files);
  return true;
}

// --- self check ------------------------------------------------------------------
bool self_check(const options& opts, const std::string& sample) {
  LOG_DEBUG("capa: self_check: starting (sample='{}')", sample);
  say("== capa self-check ==");
  bool all_ok = true;

  const std::string exe = find_executable(opts);
  if (exe.empty()) {
    LOG_WARN("capa: self_check: executable '{}' not found", opts.executable);
    fail("executable '" + opts.executable + "' NOT FOUND in PATH");
    all_ok = false;
  } else {
    ok("executable: " + exe);
  }

  if (opts.require_rules_dir) {
    if (rules_dir_exists(opts)) {
      ok("rules dir: " + absolute_of(opts.rules_dir));
    } else {
      all_ok = false;
    }
  } else {
    LOG_DEBUG("capa: self_check: rules dir check skipped (require_rules_dir=false)");
  }

  if (!opts.signatures_dir.empty()) {
    options probe;
    probe.rules_dir = opts.signatures_dir;
    if (rules_dir_exists(probe)) {
      ok("signatures dir: " + absolute_of(opts.signatures_dir));
    } else {
      all_ok = false;
    }
  }

  if (!sample.empty()) {
    std::error_code ec;
    if (fs::is_regular_file(sample, ec)) {
      ok("sample: " + absolute_of(sample));
    } else {
      LOG_WARN("capa: self_check: sample '{}' not found", sample);
      fail("sample not found: " + absolute_of(sample));
      all_ok = false;
    }
  }

  if (all_ok) {
    LOG_INFO("capa: self_check: PASSED");
    ok("self-check PASSED");
  } else {
    LOG_WARN("capa: self_check: FAILED");
    fail("self-check FAILED — see [!] lines above");
  }
  return all_ok;
}

std::string find_executable(const options& opts) {
  const std::string resolved = proc::find_in_path(opts.executable);
  if (resolved.empty()) {
    LOG_WARN("capa: find_executable: '{}' not found in PATH", opts.executable);
  } else {
    LOG_DEBUG("capa: find_executable: '{}' -> '{}'", opts.executable, resolved);
  }
  return resolved;
}

report_t parse_json(std::string_view json_text, const options& opts) {
  LOG_DEBUG("capa: parse_json: parsing {} bytes of capa output", json_text.size());
  const auto started = clock_type::now();

  report_t report;
  json doc;
  std::string error;
  if (!parse_document(json_text, doc, error)) {
    LOG_WARN("capa: parse_json: bad output: {}", error);
    report.st = status::bad_output;
    report.error = error;
    return report;
  }
  try {
    report = build_report(doc, opts);
  } catch (const std::exception& e) {
    LOG_ERROR("capa: parse_json: unexpected document layout: {}", e.what());
    report = report_t{};
    report.st = status::bad_output;
    report.error = std::string("unexpected capa document layout: ") + e.what();
  }
  if (opts.keep_raw_json) report.raw_json.assign(json_text.data(), json_text.size());

  LOG_DEBUG("capa: parse_json: done in {:.3f}s (status={})",
            seconds_since(started), to_string(report.st));
  return report;
}

report_t analyze_file(const std::string& sample, const options& opts) {
  LOG_INFO("capa: analyze_file: '{}' starting", sample);
  say("== capa analyze_file ==");

  const auto started = std::chrono::steady_clock::now();
  auto elapsed = [&]() {
    return std::chrono::duration<double>(std::chrono::steady_clock::now() - started).count();
  };

  report_t report;

  // --- sample check -------------------------------------------------------------
  std::error_code ec;
  if (sample.empty()) {
    LOG_WARN("capa: analyze_file: sample path is empty");
    fail("sample path is empty");
    report.st = status::file_missing;
    report.error = "sample path is empty";
    return report;
  }
  if (!fs::is_regular_file(sample, ec)) {
    LOG_WARN("capa: analyze_file: sample '{}' not found (ec='{}')",
             sample, ec.message());
    fail("sample not found: " + absolute_of(sample));
    report.st = status::file_missing;
    report.error = "sample not found: " + sample;
    return report;
  }

  // --- sample size / phase selection -------------------------------------------
  std::uintmax_t sample_bytes = 0;
  {
    std::error_code sec;
    sample_bytes = fs::file_size(sample, sec);
    if (sec) {
      LOG_WARN("capa: analyze_file: could not stat sample size for '{}': {}",
               sample, sec.message());
      sample_bytes = 0;
    }
  }
  const bool large_sample = sample_bytes > kLargeSampleBytes;
  ok("sample OK: " + fs::path(sample).filename().string() +
     " (" + human_size(sample_bytes) + ")");

  std::chrono::milliseconds effective_timeout = opts.timeout;
  const char* phase = "normal";
  if (large_sample) {
    effective_timeout = opts.large_timeout;
    phase = "large";
  }
  LOG_INFO("capa: analyze_file: phase={} (sample={}, timeout={} ms)",
           phase, human_size(sample_bytes), effective_timeout.count());
  if (large_sample) {
    say("[*] large sample (" + human_size(sample_bytes) +
        ") — allowing up to " +
        std::to_string(effective_timeout.count() / 1000) + " s for capa");
  }

  // --- executable check ---------------------------------------------------------
  const std::string exe = find_executable(opts);
  if (exe.empty()) {
    LOG_WARN("capa: analyze_file: executable '{}' not found", opts.executable);
    fail("capa executable not found ('" + opts.executable + "')");
    LOG_DEBUG("capa: analyze_file: install capa or set options.executable");
    report.st = status::not_found;
    report.error = "capa executable not found ('" + opts.executable +
                   "'): install capa or set options.executable";
    report.seconds = elapsed();
    return report;
  }

  // ---------------------------------------------------------------------------
  // Build the argv once, up front, and PRINT the full command before doing
  // anything else — so the invocation is visible even when the rules check or
  // cache logic bails out. `console::info` prefixes each line with [*].
  // ---------------------------------------------------------------------------
  const std::vector<std::string> args = build_args(sample, opts);
  report.command_line = join_command(exe, args);                 // log-friendly
  const std::string display_command = describe_argv(exe, args);  // shell-friendly

  say("capa command:");
  say("  " + display_command);

  LOG_DEBUG("capa: analyze_file: command='{}'", report.command_line);
  LOG_DEBUG("capa: analyze_file: display_command='{}'", display_command);

  // --- rules dir check ----------------------------------------------------------
  if (opts.require_rules_dir && !rules_dir_exists(opts)) {
    LOG_WARN("capa: analyze_file: refusing to run, rules_dir invalid");
    fail("refusing to run capa: rules_dir is missing or invalid");
    LOG_DEBUG("capa: analyze_file: set options.rules_dir to a valid directory, "
              "or options.require_rules_dir=false to skip this check");
    report.st = status::rules_missing;
    report.error = "capa rules directory not found: '" + opts.rules_dir + "'";
    report.seconds = elapsed();
    return report;
  }

  // --- cache --------------------------------------------------------------------
  fs::path cache_path;
  if (!opts.cache_dir.empty()) {
    cache_path = cache_file(sample, opts, exe);
    LOG_DEBUG("capa: analyze_file: cache path='{}'", cache_path.string());

    std::string cached;
    if (read_file(cache_path, cached)) {
      LOG_DEBUG("capa: analyze_file: cache hit ({} bytes)", cached.size());

      report_t hit = parse_json(cached, opts);
      if (hit.ok()) {
        hit.from_cache = true;
        hit.command_line = display_command;   // same command, printed above
        hit.seconds = elapsed();
        LOG_INFO("capa: analyze_file: '{}' served from cache in {:.3f}s "
                 "({} capabilities)",
                 sample, hit.seconds, hit.capabilities.size());
        ok("served from cache in " + std::to_string(hit.seconds) + "s — " +
           "capabilities=" + std::to_string(hit.capabilities.size()));
        return hit;
      }
      LOG_WARN("capa: analyze_file: cached entry invalid, removing '{}'",
               cache_path.string());
      fs::remove(cache_path, ec);
    } else {
      LOG_DEBUG("capa: analyze_file: cache miss");
    }
  } else {
    LOG_DEBUG("capa: analyze_file: cache disabled");
  }

  // --- run capa -----------------------------------------------------------------
  proc::run_options run_options;
  run_options.timeout = effective_timeout;
  run_options.max_stdout_bytes = opts.max_stdout_bytes;
  run_options.low_priority = opts.low_priority;
  run_options.extra_env = {"PYTHONUTF8=1", "PYTHONIOENCODING=utf-8"};

  LOG_DEBUG("capa: analyze_file: timeout={} ms, max_stdout_bytes={}, low_priority={}",
            run_options.timeout.count(), run_options.max_stdout_bytes,
            run_options.low_priority);

  spinner spin;
  spin.start("capa is analyzing '" + fs::path(sample).filename().string() +
             "' [" + phase + " phase]");

  proc::run_result run = proc::run(exe, args, run_options);

  spin.stop();

  report.exit_code = run.exit_code;
  report.stderr_tail = tail_of(run.std_err, 600);
  if (run.stderr_truncated) report.warnings.push_back("capa stderr was truncated");

  LOG_INFO("capa: analyze_file: capa exited with code {} in {:.3f}s "
           "(stdout={} B, stderr={} B)",
           run.exit_code, run.seconds, run.std_out.size(), run.std_err.size());

  switch (run.status) {
    case proc::launch_status::ok:
      break;
    case proc::launch_status::not_found:
      LOG_WARN("capa: analyze_file: launch not_found: {}", run.error);
      fail("capa launch not_found: " + run.error);
      report.st = status::not_found;
      report.error = run.error;
      report.seconds = elapsed();
      return report;
    case proc::launch_status::launch_failed:
      LOG_ERROR("capa: analyze_file: launch_failed: {}", run.error);
      fail("capa launch_failed: " + run.error);
      report.st = status::launch_failed;
      report.error = run.error;
      report.seconds = elapsed();
      return report;
    case proc::launch_status::timed_out:
      LOG_WARN("capa: analyze_file: timed out after {} ms (phase={}): {}",
               effective_timeout.count(), phase, run.error);
      fail("capa timed out: " + run.error);
      report.st = status::timed_out;
      report.error = "capa " + run.error +
                     (large_sample ? " (large-sample phase already applied)"
                                   : " (raise options.timeout for large samples)");
      report.seconds = elapsed();
      return report;
    case proc::launch_status::output_too_large:
      LOG_WARN("capa: analyze_file: output too large: {}", run.error);
      fail("capa output too large: " + run.error);
      report.st = status::output_too_large;
      report.error = "capa " + run.error;
      report.seconds = elapsed();
      return report;
  }

  if (run.exit_code != 0) {
    const std::string reason = describe_exit_code(run.exit_code);
    LOG_WARN("capa: analyze_file: capa exited with code {}: {}",
             run.exit_code, reason);
    fail("capa exited with code " + std::to_string(run.exit_code) + ": " + reason);
    if (!report.stderr_tail.empty()) {
      LOG_WARN("capa: analyze_file: stderr tail: {}", report.stderr_tail);
      const std::string short_tail = report.stderr_tail.size() > 200
          ? report.stderr_tail.substr(0, 200) + "..."
          : report.stderr_tail;
      warn("stderr: " + short_tail);
    }
    report.st = status::exit_error;
    report.error = reason;
    report.seconds = elapsed();
    return report;
  }

  std::string exit_zero_error;
  json doc;
  if (!parse_document(run.std_out, doc, exit_zero_error)) {
    LOG_WARN("capa: analyze_file: bad output: {}", exit_zero_error);
    fail("bad output from successful capa run: " + exit_zero_error);
    report.st = status::bad_output;
    report.error = exit_zero_error;
    report.seconds = elapsed();
    return report;
  }

  report_t parsed;
  try {
    parsed = build_report(doc, opts);
  } catch (const std::exception& e) {
    LOG_ERROR("capa: analyze_file: unexpected document layout: {}", e.what());
    fail(std::string("unexpected capa document layout: ") + e.what());
    report.st = status::bad_output;
    report.error = std::string("unexpected capa document layout: ") + e.what();
    report.seconds = elapsed();
    return report;
  }
  parsed.command_line = std::move(report.command_line);
  parsed.stderr_tail = std::move(report.stderr_tail);
  parsed.warnings = std::move(report.warnings);
  parsed.exit_code = 0;
  if (opts.keep_raw_json) parsed.raw_json = std::move(run.std_out);

  if (!cache_path.empty()) {
    const std::string filtered = doc.dump();
    write_cache(cache_path, filtered);
  }
  parsed.seconds = elapsed();

  ok("capa finished in " + std::to_string(parsed.seconds) + "s [" +
     phase + " phase] — " +
     "matched=" + std::to_string(parsed.rules_matched) +
     ", capabilities=" + std::to_string(parsed.capabilities.size()) +
     (parsed.library_rules > 0
        ? ", library=" + std::to_string(parsed.library_rules)
        : std::string()) +
     (parsed.warnings.empty()
        ? std::string()
        : ", warnings=" + std::to_string(parsed.warnings.size())));

  LOG_INFO("capa: analyze_file: '{}' done in {:.3f}s [phase={}] — matched={}, "
           "library_rules={}, capabilities={}, warnings={}, stderr_tail='{}'",
           sample, parsed.seconds, phase, parsed.rules_matched,
           parsed.library_rules, parsed.capabilities.size(),
           parsed.warnings.size(), parsed.stderr_tail);

  return parsed;
}

std::vector<std::string> attack_ids(const report_t& report) {
  std::set<std::string> ids;
  for (const capability_t& cap : report.capabilities)
    for (const attack_t& a : cap.attack)
      if (!a.id.empty()) ids.insert(a.id);
  LOG_TRACE("capa: attack_ids: {} unique ID(s)", ids.size());
  return {ids.begin(), ids.end()};
}

std::vector<std::string> mbc_ids(const report_t& report) {
  std::set<std::string> ids;
  for (const capability_t& cap : report.capabilities)
    for (const mbc_t& m : cap.mbc)
      if (!m.id.empty()) ids.insert(m.id);
  LOG_TRACE("capa: mbc_ids: {} unique ID(s)", ids.size());
  return {ids.begin(), ids.end()};
}

std::vector<std::string> namespaces(const report_t& report) {
  std::set<std::string> values;
  for (const capability_t& cap : report.capabilities)
    if (!cap.namespace_path.empty()) values.insert(cap.namespace_path);
  LOG_TRACE("capa: namespaces: {} unique namespace(s)", values.size());
  return {values.begin(), values.end()};
}

std::vector<std::pair<std::string, std::size_t>> capabilities_by_category(const report_t& report) {
  std::map<std::string, std::size_t> counts;
  for (const capability_t& cap : report.capabilities) {
    const std::size_t slash = cap.namespace_path.find('/');
    counts[cap.namespace_path.empty() ? std::string("(none)") : cap.namespace_path.substr(0, slash)]++;
  }
  std::vector<std::pair<std::string, std::size_t>> out(counts.begin(), counts.end());
  std::sort(out.begin(), out.end(), [](const auto& a, const auto& b) {
    return a.second != b.second ? a.second > b.second : a.first < b.first;
  });
  LOG_TRACE("capa: capabilities_by_category: {} categor(y|ies)", out.size());
  return out;
}

} 