// radare2_runner.cpp

#include "radare2_runner.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <regex>
#include <set>
#include <sstream>
#include <string>
#include <system_error>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <nlohmann/json.hpp>

#include "logging.hpp"
#include "process_runner.hpp"

namespace r2 {

namespace fs = std::filesystem;
using clock_type = std::chrono::steady_clock;
using json = nlohmann::json;

// ---------------------------------------------------------------------------
// Status names
// ---------------------------------------------------------------------------

const char* to_string(status s) {
  switch (s) {
    case status::ok:               return "ok";
    case status::partial:          return "partial";
    case status::file_missing:     return "file_missing";
    case status::not_found:        return "not_found";
    case status::launch_failed:    return "launch_failed";
    case status::timed_out:        return "timed_out";
    case status::output_too_large: return "output_too_large";
    case status::exit_error:       return "exit_error";
    case status::bad_output:       return "bad_output";
    case status::write_failed:     return "write_failed";
  }
  return "unknown";
}

namespace {

// ---------------------------------------------------------------------------
// Small utilities
// ---------------------------------------------------------------------------

double seconds_since(clock_type::time_point start) {
  return std::chrono::duration<double>(clock_type::now() - start).count();
}

// Resolve a sample path to an absolute one. radare2 normalises ".\a.exe" into
// the unusable ".a.exe", and WSL resolves relative paths against its own
// working directory rather than the Windows one, so both back ends need a
// fully-qualified path.
std::string absolute_sample_path(const std::string& sample) {
  if (sample.empty()) return sample;
  if (sample.size() >= 2 && sample[1] == ':') return sample;  // already absolute
  std::error_code ec;
  const fs::path abs = fs::absolute(fs::path(sample), ec);
  if (ec) return sample;
  return abs.string();
}

std::string to_wsl_path(const std::string& win_path) {
  if (win_path.size() >= 2 && win_path[1] == ':') {
    std::string drive = win_path.substr(0, 1);
    std::transform(drive.begin(), drive.end(), drive.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    std::string rest = win_path.substr(2);
    std::replace(rest.begin(), rest.end(), '\\', '/');
    if (rest.empty() || rest.front() != '/') rest = "/" + rest;
    const std::string out = "/mnt/" + drive + rest;
    LOG_TRACE("r2: to_wsl_path: '{}' -> '{}'", win_path, out);
    return out;
  }
  return win_path;
}

std::vector<std::string> wsl_prefix(const options& opts) {
  std::vector<std::string> prefix;
  if (!opts.use_wsl) return prefix;
  prefix.push_back("wsl");
  if (!opts.wsl_distro.empty()) {
    prefix.push_back("-d");
    prefix.push_back(opts.wsl_distro);
  }
  return prefix;
}

std::string tail_of(const std::string& text, std::size_t max_chars) {
  if (text.size() <= max_chars) return text;
  return "..." + text.substr(text.size() - max_chars);
}

// First *max_chars* characters of *text* with control characters collapsed to
// single spaces. Used in error messages so a failed parse reports what the
// tool actually printed instead of an opaque "bad output".
std::string output_head(const std::string& text, std::size_t max_chars = 160) {
  std::string out;
  out.reserve(std::min(max_chars + 3, text.size()));
  for (const char c : text) {
    if (out.size() >= max_chars) {
      out += "...";
      break;
    }
    out.push_back((c == '\n' || c == '\r' || c == '\t') ? ' ' : c);
  }
  return out;
}

// Same, but from the end of the buffer (tool diagnostics usually land there).
std::string output_tail_head(const std::string& text, std::size_t max_chars = 160) {
  return output_head(tail_of(text, max_chars * 4), max_chars);
}

std::string trim_trailing(std::string s) {
  while (!s.empty() && (s.back() == '\n' || s.back() == '\r' || s.back() == ' '))
    s.pop_back();
  return s;
}

std::string join_command(const std::string& program,
                         const std::vector<std::string>& args) {
  std::string line = program;
  for (const std::string& a : args) {
    line += ' ';
    if (a.find_first_of(" \t\"") != std::string::npos) line += '"' + a + '"';
    else line += a;
  }
  return line;
}

std::string sanitize_section_name(const std::string& name) {
  std::string out;
  out.reserve(name.size());
  for (char c : name) {
    if (std::isalnum(static_cast<unsigned char>(c)) || c == '-' || c == '_') {
      out.push_back(c);
    } else {
      out.push_back('_');
    }
  }
  if (out.empty()) out = "section";
  return out;
}

std::string substitute_pattern(std::string pattern,
                               const std::string& stem,
                               const std::string& section) {
  const std::string safe_section = sanitize_section_name(section);
  auto replace_all = [](std::string& s, const std::string& from, const std::string& to) {
    if (from.empty()) return;
    std::size_t pos = 0;
    while ((pos = s.find(from, pos)) != std::string::npos) {
      s.replace(pos, from.size(), to);
      pos += to.size();
    }
  };
  replace_all(pattern, "{stem}", stem);
  replace_all(pattern, "{section}", safe_section);
  return pattern;
}

std::string hex_u64(std::uint64_t v) {
  std::ostringstream os;
  os << "0x" << std::hex << v;
  return os.str();
}

// Extract the first 0x-prefixed hex operand from a disasm string. Used as a
// fallback when r2's `jump` field is absent for a branch instruction.
std::uint64_t first_hex_operand(const std::string& s) {
  const std::size_t p = s.find("0x");
  if (p == std::string::npos) return 0;
  std::uint64_t v = 0;
  for (std::size_t i = p + 2; i < s.size() && (i - p) <= 18; ++i) {
    const char c = s[i];
    int d;
    if (c >= '0' && c <= '9')      d = c - '0';
    else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
    else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
    else break;
    v = v * 16 + static_cast<std::uint64_t>(d);
  }
  return v;
}

// ---------------------------------------------------------------------------
// Atomic binary writer
// ---------------------------------------------------------------------------

bool write_bytes_atomic(const std::string& path, const std::string& content) {
  try {
    const fs::path target(path);
    if (target.has_parent_path()) {
      std::error_code ec;
      fs::create_directories(target.parent_path(), ec);
      if (ec) {
        LOG_ERROR("r2: write_bytes_atomic: cannot create '{}': {}",
                  target.parent_path().string(), ec.message());
        return false;
      }
    }

    // Unique temp file name to avoid collisions under concurrency.
    const auto pid =
#if defined(_WIN32)
        static_cast<unsigned long>(::_getpid());
#else
        static_cast<unsigned long>(::getpid());
#endif
    std::ostringstream tmp_name;
    tmp_name << target.string() << ".tmp."
             << pid << '.' << clock_type::now().time_since_epoch().count();
    const fs::path tmp = tmp_name.str();

    {
      std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
      if (!out) {
        LOG_ERROR("r2: write_bytes_atomic: cannot open '{}'", tmp.string());
        return false;
      }
      out.write(content.data(), static_cast<std::streamsize>(content.size()));
      out.flush();
      if (!out) {
        LOG_ERROR("r2: write_bytes_atomic: write failed for '{}'", tmp.string());
        return false;
      }
    }

    std::error_code ec;
    // On Windows, rename fails if the destination exists. Remove first.
    fs::remove(target, ec);
    ec.clear();
    fs::rename(tmp, target, ec);
    if (ec) {
      LOG_ERROR("r2: write_bytes_atomic: rename failed for '{}': {}",
                target.string(), ec.message());
      std::error_code ignore;
      fs::remove(tmp, ignore);
      return false;
    }
    return true;
  } catch (const std::exception& e) {
    LOG_ERROR("r2: write_bytes_atomic: {}", e.what());
    return false;
  }
}

std::size_t file_size_or_zero(const std::string& path) {
  std::error_code ec;
  const auto n = fs::file_size(path, ec);
  if (ec) return 0;
  return static_cast<std::size_t>(n);
}

// ---------------------------------------------------------------------------
// JSON helpers
// ---------------------------------------------------------------------------

std::string jstr(const json& o, const char* key) {
  if (!o.is_object()) return {};
  const auto it = o.find(key);
  if (it == o.end()) return {};
  if (it->is_string()) return it->get<std::string>();
  if (it->is_number_integer()) return std::to_string(it->get<long long>());
  if (it->is_number_unsigned()) return std::to_string(it->get<std::uint64_t>());
  if (it->is_boolean()) return it->get<bool>() ? "true" : "false";
  return {};
}

std::uint64_t jnum(const json& o, const char* key, std::uint64_t fallback = 0) {
  if (!o.is_object()) return fallback;
  const auto it = o.find(key);
  if (it == o.end()) return fallback;
  if (it->is_number_unsigned()) return it->get<std::uint64_t>();
  if (it->is_number_integer()) return static_cast<std::uint64_t>(it->get<long long>());
  if (it->is_number_float()) return static_cast<std::uint64_t>(it->get<double>());
  return fallback;
}

double jdouble(const json& o, const char* key, double fallback = 0.0) {
  if (!o.is_object()) return fallback;
  const auto it = o.find(key);
  if (it == o.end()) return fallback;
  if (it->is_number()) return it->get<double>();
  return fallback;
}

bool jbool(const json& o, const char* key, bool fallback = false) {
  if (!o.is_object()) return fallback;
  const auto it = o.find(key);
  if (it == o.end()) return fallback;
  if (it->is_boolean()) return it->get<bool>();
  return fallback;
}

void set_if_nonempty(std::string& dst, const std::string& v) {
  if (!v.empty()) dst = v;
}

void set_if_nonzero(std::uint64_t& dst, std::uint64_t v) {
  if (v != 0) dst = v;
}

bool is_nop_instruction(const instruction_t& instruction) {
  if (instruction.type == "nop") return true;
  std::string mnemonic;
  const std::size_t split = instruction.disasm.find_first_of(" \t");
  mnemonic = instruction.disasm.substr(0, split);
  std::transform(mnemonic.begin(), mnemonic.end(), mnemonic.begin(),
                 [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  return mnemonic == "nop" || mnemonic.rfind("nop", 0) == 0;
}

template <typename Fn>
void for_each(const json& value, Fn&& fn) {
  if (value.is_array()) {
    for (const json& item : value) fn(item);
  } else if (value.is_object()) {
    fn(value);
  }
}

// Parse a concatenation of top-level JSON values (objects or arrays) as a
// stream. r2 commands that use `@@` (pdfj @@f, axtj @@f, ...) and repeated
// single commands (axtj @ a; axtj @ b; ...) emit one JSON value per
// invocation with no separator. json::parse on the whole string fails.
//
// The scanner walks the stream one value at a time: it finds the next '{' or
// '[', parses from there with nlohmann's iterator overload (allow_exceptions =
// false), then re-scans forward to the matching close brace/bracket at depth 0
// so the next iteration starts at the following value. Strings are tracked so
// braces inside string literals don't confuse the depth counter.
std::vector<json> parse_json_stream(const std::string& text) {
  std::vector<json> docs;
  std::size_t pos = 0;

  while (pos < text.size()) {
    // Skip any non-JSON prefix (r2 progress / banner noise).
    while (pos < text.size() && text[pos] != '{' && text[pos] != '[') ++pos;
    if (pos >= text.size()) break;

    const char open_ch  = text[pos];
    const char close_ch = (open_ch == '{') ? '}' : ']';

    // 1. Find the extent of THIS value by depth counting first. Parsing
    //    straight to text.end() would be wrong: nlohmann's parse() over an
    //    iterator range is strict, so a stream of concatenated objects fails
    //    on the first value ("trailing content"), returns discarded, and the
    //    old code broke out with zero docs. Slicing each value means every
    //    parse sees exactly one complete JSON value.
    int depth = 0;
    bool in_string = false;
    bool escape = false;
    std::size_t end_pos = pos;
    bool complete = false;
    for (; end_pos < text.size(); ++end_pos) {
      const char c = text[end_pos];
      if (in_string) {
        if (escape) { escape = false; continue; }
        if (c == '\\') { escape = true; continue; }
        if (c == '"') in_string = false;
        continue;
      }
      if (c == '"') { in_string = true; continue; }
      if (c == open_ch) ++depth;
      else if (c == close_ch) {
        --depth;
        if (depth == 0) { ++end_pos; complete = true; break; }
      }
    }
    if (!complete) break;  // unterminated value: stop

    // 2. Parse exactly [pos, end_pos).
    const json doc = json::parse(text.begin() + static_cast<std::ptrdiff_t>(pos),
                                 text.begin() + static_cast<std::ptrdiff_t>(end_pos),
                                 nullptr, false);
    if (!doc.is_discarded()) docs.push_back(doc);
    // Always advance so a malformed value can't spin forever.
    pos = end_pos;
  }
  return docs;
}

// Parse a tool's stdout as a single JSON value. The text is tried as-is first;
// if that fails the concatenated-value scanner is used, so launcher noise in
// front of the payload does not break the parse. On some WSL builds wsl.exe
// prints its own diagnostics (e.g. "wsl: Unknown key ... in /etc/wsl.conf")
// to stdout, which used to make every r2 JSON command look like bad output.
json parse_json_payload(const std::string& text, std::string& err) {
  err.clear();
  if (text.empty()) {
    err = "empty output";
    return json();
  }

  const json direct = json::parse(text, nullptr, false);
  if (!direct.is_discarded()) return direct;

  const std::vector<json> docs = parse_json_stream(text);
  if (!docs.empty()) return docs.front();

  err = (text.find_first_not_of(" \t\r\n") == std::string::npos)
            ? "output is blank"
            : "no JSON value found in output";
  return json();
}

// Same, but the caller needs a top-level JSON array (r2's `aflj`).
json parse_json_array_payload(const std::string& text, std::string& err) {
  const json doc = parse_json_payload(text, err);
  if (!err.empty()) return json();
  if (doc.is_array()) return doc;

  err = doc.is_object() ? "expected a JSON array, got a single object"
                        : "top-level JSON value is not an array";
  return json();
}

// ---------------------------------------------------------------------------
// WSL warm-up
// ---------------------------------------------------------------------------

// A cold WSL distro can take much longer to answer than the per-tool timeout
// (VM boot + init + mount namespace). Killing wsl.exe while it is still
// booting leaves the session broken: every later wsl.exe call then returns
// immediately with a non-zero exit code and a short diagnostic blob on
// stdout, i.e. no r2 output at all — which surfaces as "aflj output is not a
// valid JSON array" / "r2 produced no valid DOT output" even though r2 and
// the flags are fine. Paying the start-up cost once, up front, keeps the
// per-tool timeouts meaningful.
void ensure_wsl_ready(const options& opts, bool force = false) {
  if (!opts.use_wsl) return;

  static std::mutex mtx;
  static bool ready = false;

  std::lock_guard<std::mutex> lock(mtx);
  if (ready && !force) return;

  std::vector<std::string> cmd = wsl_prefix(opts);
  cmd.push_back("-e");
  cmd.push_back("true");

  proc::run_options ro;
  ro.timeout = std::chrono::minutes(3);
  ro.max_stdout_bytes = 4096;
  ro.max_stderr_bytes = 4096;

  const auto started = clock_type::now();
  const proc::run_result r = proc::run(
      cmd.front(), std::vector<std::string>(cmd.begin() + 1, cmd.end()), ro);
  const double secs = seconds_since(started);

  if (r.status == proc::launch_status::ok && r.exit_code == 0) {
    ready = true;
    LOG_INFO("r2: wsl warm-up ok in {:.3f}s", secs);
  } else {
    ready = false;
    LOG_WARN("r2: wsl warm-up failed after {:.3f}s (status={}, exit={}{})",
             secs, proc::to_string(r.status), r.exit_code,
             r.std_out.empty() ? std::string()
                               : ", stdout: \"" + output_head(r.std_out) + "\"");
  }
}

// ---------------------------------------------------------------------------
// r2 execution
// ---------------------------------------------------------------------------

struct run_out {
  status      st = status::ok;
  std::string error;
  std::string stdout_text;
  std::string stderr_tail;
  int         exit_code = 0;
  double      seconds = 0.0;
  std::string command_line;
};

// Common -e override block so runs are reproducible. Only applied when
// opts.pin_analysis_config is true.
void append_config_overrides(std::vector<std::string>& cmd, const options& opts) {
  cmd.push_back("-e"); cmd.push_back("scr.color=0");
  cmd.push_back("-e"); cmd.push_back("scr.utf8=0");
  cmd.push_back("-e"); cmd.push_back("scr.interactive=false");
  cmd.push_back("-e"); cmd.push_back("scr.prompt=false");
  if (!opts.pin_analysis_config) return;
  if (opts.anal_timeout_ms > 0) {
    cmd.push_back("-e");
    cmd.push_back("anal.timeout=" + std::to_string(opts.anal_timeout_ms));
  }
  if (opts.anal_bb_maxsize > 0) {
    cmd.push_back("-e");
    cmd.push_back("anal.bb.maxsize=" + std::to_string(opts.anal_bb_maxsize));
  }
}

// Run a generic tool (r2 / rabin2). `program` is the binary name; args are
// appended after the WSL prefix.
run_out run_tool(const std::string& program,
                 const std::vector<std::string>& args,
                 const options& opts,
                 std::chrono::milliseconds timeout) {
  run_out out;
  const auto started = clock_type::now();

  // Make sure the distro is booted before the (short) per-tool timeout starts.
  ensure_wsl_ready(opts);

  std::vector<std::string> cmd = wsl_prefix(opts);
  cmd.push_back(program);
  for (const auto& a : args) cmd.push_back(a);

  out.command_line = join_command(cmd.front(),
                                  std::vector<std::string>(cmd.begin() + 1, cmd.end()));
  LOG_DEBUG("r2: run_tool: '{}'", out.command_line);

  proc::run_options ro;
  ro.timeout = timeout;
  ro.max_stdout_bytes = opts.max_stdout_bytes;
  ro.max_stderr_bytes = opts.max_stderr_bytes;
  ro.low_priority = opts.low_priority;

  const std::vector<std::string> program_args(cmd.begin() + 1, cmd.end());

  // One retry for transient launcher failures. A non-zero exit code means the
  // launcher itself failed (typically a broken WSL session following a killed
  // call); re-warming the distro and trying once more recovers it instead of
  // failing the whole phase.
  proc::run_result r;
  for (int attempt = 1;; ++attempt) {
    r = proc::run(cmd.front(), program_args, ro);
    const bool transient = (r.status == proc::launch_status::ok && r.exit_code != 0);
    if (!transient || attempt >= 2) break;
    LOG_WARN("r2: run_tool: '{}' exited with {} (attempt {}){}; re-warming and retrying",
             program, r.exit_code, attempt,
             r.std_out.empty() ? std::string()
                               : " — stdout: \"" + output_head(r.std_out) + "\"");
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    ensure_wsl_ready(opts, /*force=*/true);
  }

  out.exit_code = r.exit_code;
  out.stderr_tail = tail_of(r.std_err, 4096);
  out.stdout_text = r.std_out;
  out.seconds = seconds_since(started);

  LOG_INFO("r2: run_tool: exit={} status={} in {:.3f}s (stdout={} B, stderr={} B)",
           r.exit_code, proc::to_string(r.status), r.seconds,
           r.std_out.size(), r.std_err.size());

  if (r.exit_code != 0) {
    LOG_WARN("r2: run_tool: '{}' exit={} diagnosis: stdout=\"{}\" stderr=\"{}\"",
             program, r.exit_code, output_head(r.std_out), output_tail_head(r.std_err));
  }

  switch (r.status) {
    case proc::launch_status::ok: break;
    case proc::launch_status::not_found:
      out.st = status::not_found; out.error = r.error; return out;
    case proc::launch_status::launch_failed:
      out.st = status::launch_failed; out.error = r.error; return out;
    case proc::launch_status::timed_out:
      out.st = status::timed_out; out.error = r.error; return out;
    case proc::launch_status::output_too_large:
      out.st = status::output_too_large; out.error = r.error; return out;
  }

  if (r.exit_code != 0 && r.std_out.empty()) {
    out.st = status::exit_error;
    out.error = program + " exited with code " + std::to_string(r.exit_code) +
                (out.stderr_tail.empty() ? "" : ": " + out.stderr_tail);
    return out;
  }

  out.st = status::ok;
  return out;
}

run_out run_r2(const std::string& sample,
               const options& opts,
               const std::vector<std::string>& extra_cmds,
               std::chrono::milliseconds timeout_override = std::chrono::milliseconds{0}) {
  run_out out;
  const auto started = clock_type::now();

  std::error_code ec;
  if (sample.empty() || !fs::is_regular_file(sample, ec)) {
    out.st = status::file_missing;
    out.error = "sample not found: " + sample;
    LOG_WARN("r2: run_r2: {}", out.error);
    out.seconds = seconds_since(started);
    return out;
  }

  const std::string resolved = absolute_sample_path(sample);
  const std::string wsl_sample = opts.use_wsl ? to_wsl_path(resolved) : resolved;

  std::vector<std::string> args;
  if (opts.quiet) args.push_back("-q");
  append_config_overrides(args, opts);
  if (opts.analysis) args.push_back("-A");
  for (const auto& c : extra_cmds) {
    args.push_back("-c");
    args.push_back(c);
  }
  args.push_back("-c");
  args.push_back("q");
  args.push_back(wsl_sample);

  const auto t = (timeout_override.count() > 0) ? timeout_override : opts.timeout;
  return run_tool(opts.executable, args, opts, t);
}

}  // namespace

// ---------------------------------------------------------------------------
// Discovery and versions
// ---------------------------------------------------------------------------

std::string find_executable(const options& opts) {
  if (!opts.use_wsl) return proc::find_in_path(opts.executable);
  ensure_wsl_ready(opts);
  std::vector<std::string> cmd = wsl_prefix(opts);
  cmd.push_back("which");
  cmd.push_back(opts.executable);
  proc::run_options ro;
  ro.timeout = std::chrono::seconds(20);
  ro.max_stdout_bytes = 4096;
  const proc::run_result r = proc::run(cmd.front(),
                                       std::vector<std::string>(cmd.begin() + 1, cmd.end()),
                                       ro);
  if (r.status != proc::launch_status::ok || r.exit_code != 0) return {};
  return trim_trailing(r.std_out);
}

std::string find_rabin2(const options& opts) {
  if (!opts.use_wsl) return proc::find_in_path(opts.rabin2);
  ensure_wsl_ready(opts);
  std::vector<std::string> cmd = wsl_prefix(opts);
  cmd.push_back("which");
  cmd.push_back(opts.rabin2);
  proc::run_options ro;
  ro.timeout = std::chrono::seconds(20);
  ro.max_stdout_bytes = 4096;
  const proc::run_result r = proc::run(cmd.front(),
                                       std::vector<std::string>(cmd.begin() + 1, cmd.end()),
                                       ro);
  if (r.status != proc::launch_status::ok || r.exit_code != 0) return {};
  return trim_trailing(r.std_out);
}

std::string version(const options& opts) {
  const run_out r = run_tool(opts.executable, {"-v"}, opts, std::chrono::seconds(10));
  if (r.st != status::ok) return {};
  std::string out = r.stdout_text;
  const std::size_t nl = out.find_first_of("\r\n");
  if (nl != std::string::npos) out.resize(nl);
  return out;
}

std::string rabin2_version(const options& opts) {
  const run_out r = run_tool(opts.rabin2, {"-v"}, opts, std::chrono::seconds(10));
  if (r.st != status::ok) return {};
  std::string out = r.stdout_text;
  const std::size_t nl = out.find_first_of("\r\n");
  if (nl != std::string::npos) out.resize(nl);
  return out;
}

// ---------------------------------------------------------------------------
// rabin2 metadata — one invocation per flag, then merge without clobbering
// ---------------------------------------------------------------------------

namespace {

void parse_info_doc(const json& doc, info_t& out) {
  const json* info = &doc;
  if (doc.is_object()) {
    if (auto it = doc.find("info"); it != doc.end() && it->is_object()) info = &*it;
  }
  set_if_nonempty(out.arch,     jstr(*info, "arch"));
  set_if_nonempty(out.bits,     jstr(*info, "bits"));
  set_if_nonempty(out.bintype,  jstr(*info, "bintype"));
  set_if_nonempty(out.endian,   jstr(*info, "endian"));
  set_if_nonempty(out.machine,  jstr(*info, "machine"));
  set_if_nonempty(out.os,       jstr(*info, "os"));
  set_if_nonempty(out.compiler, jstr(*info, "compiler"));
  set_if_nonempty(out.stripped, jstr(*info, "stripped"));
  set_if_nonempty(out.class_,   jstr(*info, "class"));
  set_if_nonzero(out.baddr, jnum(*info, "baddr"));
  set_if_nonzero(out.entry, jnum(*info, "entry"));
  set_if_nonzero(out.size,  jnum(*info, "size"));

  if (auto it = info->find("file_hashes"); it != info->end() && it->is_object()) {
    set_if_nonempty(out.file_hash_md5,    jstr(*it, "md5"));
    set_if_nonempty(out.file_hash_sha256, jstr(*it, "sha256"));
  } else {
    set_if_nonempty(out.file_hash_md5,    jstr(*info, "file_hash_md5"));
    set_if_nonempty(out.file_hash_sha256, jstr(*info, "file_hash_sha256"));
  }
}

void parse_sections_doc(const json& doc, std::vector<section_t>& out) {
  const json* sections = nullptr;
  if (auto it = doc.find("sections"); it != doc.end()) sections = &*it;
  else if (auto it = doc.find("section"); it != doc.end()) sections = &*it;
  if (sections == nullptr) return;

  auto visit = [&](const json& s) {
    section_t e;
    e.name    = jstr(s, "name");
    e.vaddr   = jnum(s, "vaddr");
    e.paddr   = jnum(s, "paddr");
    e.size    = jnum(s, "size");
    e.perms   = jstr(s, "perm");
    e.type    = jstr(s, "type");
    e.entropy = jdouble(s, "entropy");
    out.push_back(std::move(e));
  };
  for_each(*sections, visit);
}

void parse_symbols_doc(const json& doc, std::vector<symbol_t>& out) {
  const json* symbols = nullptr;
  if (auto it = doc.find("symbols"); it != doc.end()) symbols = &*it;
  else if (auto it = doc.find("symbol"); it != doc.end()) symbols = &*it;
  if (symbols == nullptr) return;

  auto visit = [&](const json& s) {
    symbol_t e;
    e.name    = jstr(s, "name");
    e.vaddr   = jnum(s, "vaddr");
    e.type    = jstr(s, "type");
    e.bind    = jstr(s, "bind");
    e.import  = jbool(s, "is_imported");
    e.export_ = jbool(s, "is_exported");
    out.push_back(std::move(e));
  };
  for_each(*symbols, visit);
}

void parse_imports_doc(const json& doc, std::vector<import_t>& out) {
  const json* imports = nullptr;
  if (auto it = doc.find("imports"); it != doc.end()) imports = &*it;
  else if (auto it = doc.find("import"); it != doc.end()) imports = &*it;
  if (imports == nullptr) return;

  auto visit = [&](const json& s) {
    import_t e;
    e.library = jstr(s, "libname");
    e.name    = jstr(s, "name");
    e.plt     = jnum(s, "plt");
    e.ordinal = jnum(s, "ordinal");
    out.push_back(std::move(e));
  };
  for_each(*imports, visit);
}

void parse_entrypoints_doc(const json& doc, std::vector<entrypoint_t>& out) {
  const json* entries = nullptr;
  if (auto it = doc.find("entries"); it != doc.end()) entries = &*it;
  else if (auto it = doc.find("entrypoints"); it != doc.end()) entries = &*it;
  if (entries == nullptr) {
    if (doc.is_object()) {
      if (auto it = doc.find("entry"); it != doc.end() && !it->is_null()) {
        entrypoint_t e;
        e.vaddr = jnum(doc, "entry");
        out.push_back(e);
      }
    }
    return;
  }

  auto visit = [&](const json& s) {
    entrypoint_t e;
    if (s.is_object()) {
      e.vaddr = jnum(s, "vaddr");
      e.paddr = jnum(s, "paddr");
      e.name  = jstr(s, "name");
    } else if (s.is_number_unsigned()) {
      e.vaddr = s.get<std::uint64_t>();
    } else if (s.is_number_integer()) {
      e.vaddr = static_cast<std::uint64_t>(s.get<long long>());
    }
    out.push_back(std::move(e));
  };
  for_each(*entries, visit);
}

// Run rabin2 for a single flag, parse the output as one JSON document.
// Returns false on hard failure (not_found / launch_failed / timeout).
bool rabin2_one(const std::string& sample,
                const options& opts,
                const std::string& flag,
                json& out_doc,
                std::string& err,
                std::string& cmd_line) {
  const std::string resolved = absolute_sample_path(sample);
  const std::string wsl_sample = opts.use_wsl ? to_wsl_path(resolved) : resolved;
  std::vector<std::string> args;
  if (opts.quiet) args.push_back("-q");
  args.push_back("-j");
  args.push_back(flag);
  args.push_back(wsl_sample);

  const run_out r = run_tool(opts.rabin2, args, opts, opts.timeout);
  cmd_line = r.command_line;
  if (r.st != status::ok) { err = r.error; return false; }

  std::string parse_error;
  json parsed = parse_json_payload(r.stdout_text, parse_error);
  if (!parse_error.empty()) {
    err = "rabin2 " + flag + " output is not valid JSON (" + parse_error +
          ", output head: \"" + output_head(r.stdout_text) + "\")";
    LOG_WARN("r2: rabin2_one: {} — cmd: {}", err, r.command_line);
    return false;
  }
  out_doc = std::move(parsed);
  return true;
}

}  // namespace

result_t analyze_file(const std::string& sample, const options& opts) {
  result_t out;
  const auto started = clock_type::now();

  std::error_code ec;
  if (sample.empty() || !fs::is_regular_file(sample, ec)) {
    out.st = status::file_missing;
    out.error = "sample not found: " + sample;
    out.seconds = seconds_since(started);
    return out;
  }

  const std::string exe = find_rabin2(opts);
  if (exe.empty()) {
    out.st = status::not_found;
    out.error = "rabin2 not found" +
                (opts.use_wsl ? std::string(" inside WSL") : std::string());
    out.seconds = seconds_since(started);
    return out;
  }

  // One exec per flag. Each output is a complete JSON document.
  json info_doc, sections_doc, symbols_doc, imports_doc, entries_doc;
  std::string err;
  std::string cmd_line;

  if (!rabin2_one(sample, opts, "-I", info_doc, err, cmd_line)) {
    out.st = status::bad_output; out.error = err; out.command_line = cmd_line;
    out.seconds = seconds_since(started); return out;
  }
  rabin2_one(sample, opts, "-S", sections_doc, err, cmd_line);
  rabin2_one(sample, opts, "-s", symbols_doc, err, cmd_line);
  rabin2_one(sample, opts, "-i", imports_doc, err, cmd_line);
  rabin2_one(sample, opts, "-e", entries_doc, err, cmd_line);

  try {
    parse_info_doc(info_doc, out.info);
    parse_sections_doc(sections_doc, out.sections);
    parse_symbols_doc(symbols_doc, out.symbols);
    parse_imports_doc(imports_doc, out.imports);
    parse_entrypoints_doc(entries_doc, out.entrypoints);
    out.raw = json::object();
    out.raw["info"]      = info_doc;
    out.raw["sections"]  = sections_doc;
    out.raw["symbols"]   = symbols_doc;
    out.raw["imports"]   = imports_doc;
    out.raw["entries"]   = entries_doc;
  } catch (const std::exception& e) {
    out.st = status::bad_output;
    out.error = std::string("unexpected rabin2 output layout: ") + e.what();
    out.seconds = seconds_since(started);
    return out;
  }

  out.command_line = cmd_line;
  out.st = status::ok;
  out.seconds = seconds_since(started);

  LOG_INFO("r2: analyze_file: '{}' — arch={}, bits={}, bintype={}, sections={}, symbols={}, imports={}",
           sample, out.info.arch, out.info.bits, out.info.bintype,
           out.sections.size(), out.symbols.size(), out.imports.size());
  return out;
}

// ---------------------------------------------------------------------------
// Function listing (r2 -c "aflj")
// ---------------------------------------------------------------------------

// The `aflj` payload shared by list_functions() and the combined
// function-list + xref run in collect_xref_stage().
void parse_function_list(const json& parsed, std::vector<function_info_t>& out) {
  if (!parsed.is_array()) return;
  for (const json& fn : parsed) {
    if (!fn.is_object()) continue;
    function_info_t f;
    f.name    = jstr(fn, "name");
    f.offset  = jnum(fn, "offset");
    f.size    = jnum(fn, "size");
    // nbbs is the modern field; nblocks is older. Use whichever exists.
    f.blocks  = jnum(fn, "nbbs", jnum(fn, "nblocks", 0));
    if (f.blocks == 0) {
      if (auto it = fn.find("blocks"); it != fn.end() && it->is_array()) {
        f.blocks = it->size();
      }
    }
    f.is_pure = jbool(fn, "is-pure");
    out.push_back(std::move(f));
  }
}

function_list_result_t list_functions(const std::string& sample,
                                      const options& opts) {
  function_list_result_t res;
  const auto started = clock_type::now();

  const run_out run = run_r2(sample, opts, {"aflj"}, opts.timeout);
  res.command_line = run.command_line;
  res.stderr_tail = run.stderr_tail;
  res.exit_code = run.exit_code;

  if (run.st != status::ok) {
    res.st = run.st;
    res.error = run.error;
    res.seconds = seconds_since(started);
    return res;
  }

  std::string parse_error;
  const json parsed = parse_json_array_payload(run.stdout_text, parse_error);
  if (!parsed.is_array()) {
    res.st = status::bad_output;
    res.error = "aflj output is not a valid JSON array (" + parse_error +
                ", exit=" + std::to_string(run.exit_code);
    if (!run.stdout_text.empty()) {
      res.error += ", stdout: \"" + output_head(run.stdout_text) + "\"";
    }
    if (!run.stderr_tail.empty()) {
      res.error += ", stderr: \"" + output_tail_head(run.stderr_tail) + "\"";
    }
    res.error += ")";
    LOG_WARN("r2: list_functions: {} — cmd: {}", res.error, run.command_line);
    res.seconds = seconds_since(started);
    return res;
  }

  parse_function_list(parsed, res.functions);

  res.st = status::ok;
  res.seconds = seconds_since(started);

  LOG_INFO("r2: list_functions: '{}' — {} function(s) in {:.3f}s",
           sample, res.functions.size(), res.seconds);
  return res;
}

// ---------------------------------------------------------------------------
// DOT post-processing
//
// r2's agfd / agCd output is correct but verbose: node definitions are
// duplicated for every incoming edge, section DOTs repeat graph/node/edge
// attribute blocks per function, and agfd labels embed the *entire*
// disassembly.  The helpers below de-clutter the text before it is written to
// disk so both the .dot files and the dashboard's SVG renderer stay readable.
// ---------------------------------------------------------------------------

namespace {

// Returns true if *line* (already left-trimmed) is a DOT attribute block:
//   "graph [...] ;"  /  "node [...] ;"  /  "edge [...] ;"
bool is_attr_block(const std::string& trimmed) {
    return (trimmed.starts_with("graph") && trimmed.find('[') != std::string::npos) ||
           (trimmed.starts_with("node")   && trimmed.find('[') != std::string::npos) ||
           (trimmed.starts_with("edge")   && trimmed.find('[') != std::string::npos);
}

// Extract the compact "function_name" from a r2 agfd label.
// Labels look like: "  ;-- entry0:\l  ;-- mainCRTStartup:\l  ...\l42: dbg.mainCRTStartup ();\l..."
std::string extract_func_name(const std::string& label) {
    // Prefer the "N: name();" signature line.
    {
        std::smatch m;
        if (std::regex_search(label, m, std::regex(R"(\d+:\s+([A-Za-z0-9_.:<>][A-Za-z0-9_.:<>\s]*?)\s*\(\))"))) {
            std::string name = m[1].str();
            // Trim trailing spaces
            while (!name.empty() && (name.back() == ' ' || name.back() == '\t'))
                name.pop_back();
            if (!name.empty()) return name;
        }
    }
    // Fall back to ";-- name:" comment (skip generic ones).
    {
        std::string remaining = label;
        while (!remaining.empty()) {
            std::size_t pos = remaining.find(";--");
            if (pos == std::string::npos) break;
            std::size_t colon = remaining.find(':', pos);
            if (colon == std::string::npos) break;
            std::string after = remaining.substr(pos + 3);
            std::size_t s = after.find_first_not_of(" \t");
            if (s != std::string::npos) {
                std::string name = after.substr(s);
                std::size_t e = name.find_first_of(":\n\r");
                if (e != std::string::npos) name = name.substr(0, e);
                // Trim
                while (!name.empty() && (name.back() == ' ' || name.back() == '\t'))
                    name.pop_back();
                static const std::set<std::string> kSkip = {
                    "entry0", "rip", "section..text", "section__text"
                };
                if (!name.empty() && kSkip.count(name) == 0 &&
                    name.find("section") == std::string::npos)
                    return name;
            }
            remaining = remaining.substr(colon + 1);
        }
    }
    return {};
}

// Count instruction lines in a label (lines starting with fn-prefix or 0x).
std::size_t count_label_instructions(const std::string& label) {
    std::size_t count = 0;
    std::size_t pos = 0;
    while (pos < label.size()) {
        std::size_t next = label.find("\\l", pos);
        std::string part = (next == std::string::npos)
                               ? label.substr(pos)
                               : label.substr(pos, next - pos);
        if (!part.empty()) {
            std::size_t s = part.find_first_not_of(" \t");
            if (s != std::string::npos) {
                std::string trimmed_part = part.substr(s);
                if (trimmed_part.find("fn") == 0 ||
                    (trimmed_part.size() > 2 &&
                     trimmed_part[0] == '0' && trimmed_part[1] == 'x'))
                    ++count;
            }
        }
        if (next == std::string::npos) break;
        pos = next + 2;
    }
    return count;
}

// Replace a verbose agfd label with a compact: "func_name()\l  N instructions\l"
std::string compact_label(const std::string& raw_label) {
    std::string name = extract_func_name(raw_label);
    std::size_t icount = count_label_instructions(raw_label);
    if (!name.empty()) {
        return name + "()\\l  " + std::to_string(icount) + " instructions\\l";
    }
    // Fallback: hard-truncate.
    if (raw_label.size() > 200) {
        return raw_label.substr(0, 200) + "\\l  [truncated]\\l";
    }
    return raw_label;
}

// Post-process raw DOT text:
//   * deduplicate node definitions  (same "addr" [label=...] ; appearing more than once)
//   * trim long labels              (> max_label_chars → compact summary)
//   * drop duplicate graph/node/edge attribute blocks
std::string clean_dot_text(const std::string& text,
                           std::size_t max_label_chars = 200) {
    std::ostringstream out;
    std::unordered_set<std::string> seen_nodes;
    bool have_graph_attr = false, have_node_attr = false, have_edge_attr = false;

    std::istringstream iss(text);
    std::string line;

    while (std::getline(iss, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();

        std::size_t lt = line.find_first_not_of(" \t");
        if (lt == std::string::npos) continue;  // blank line
        std::string_view tv(line.data() + lt, line.size() - lt);

        // Attribute blocks: keep only the first of each kind.
        if (tv.starts_with("graph") || tv.starts_with("node") || tv.starts_with("edge")) {
            if (is_attr_block(std::string(tv))) {
                bool dup = false;
                if (tv.starts_with("graph"))      { dup = have_graph_attr; have_graph_attr = true; }
                else if (tv.starts_with("node"))  { dup = have_node_attr;  have_node_attr  = true; }
                else                              { dup = have_edge_attr;  have_edge_attr  = true; }
                if (dup) continue;
                out << line << '\n';
                continue;
            }
        }

        // Node vs edge.  A node definition is  "id" [attrs];  (no ->).
        if (tv.starts_with("\"") && tv.find("->") == std::string_view::npos) {
            // Extract the quoted node ID.
            std::size_t end_q = line.find('"', lt + 1);
            if (end_q != std::string::npos) {
                std::string nid(line, lt + 1, end_q - lt - 1);
                if (seen_nodes.count(nid)) continue;       // duplicate node → drop
                seen_nodes.insert(nid);

                // Trim verbose labels (section DOT from agfd).
                std::size_t lbl_pos = line.find("label=");
                if (lbl_pos != std::string::npos) {
                    std::size_t q1 = line.find('"', lbl_pos);
                    if (q1 != std::string::npos) {
                        std::size_t i = q1 + 1;
                        while (i < line.size()) {
                            if (line[i] == '\\' && i + 1 < line.size()) { i += 2; continue; }
                            if (line[i] == '"') break;
                            ++i;
                        }
                        if (i < line.size()) {
                            std::size_t label_len = i - q1 - 1;
                            if (label_len > max_label_chars) {
                                std::string raw_label = line.substr(q1 + 1, label_len);
                                std::string compact = compact_label(raw_label);
                                line.replace(q1 + 1, label_len, compact);
                            }
                        }
                    }
                }
            }
        }

        out << line << '\n';
    }

    return out.str();
}

}  // namespace

// Drop any leading non-DOT noise (launcher diagnostics, r2 warnings) so the
// written .dot file starts at the graph header. Keeps "strict digraph" intact.
std::string strip_dot_preamble(const std::string& text) {
  const std::size_t pos = text.find("digraph");
  if (pos == std::string::npos) return text;
  const std::size_t line_start = text.rfind('\n', pos);
  if (line_start == std::string::npos) return text;
  const std::size_t start = line_start + 1;
  if (start >= pos) return text;
  LOG_DEBUG("r2: strip_dot_preamble: dropped {} leading byte(s)", start);
  return text.substr(start);
}

// ---------------------------------------------------------------------------
// .dot extraction (r2 -c "agfd" / "agCd")
// ---------------------------------------------------------------------------

dot_result_t extract_dot(const std::string& sample,
                         const std::string& out_path,
                         const options& opts,
                         const dot_options& dot) {
  dot_result_t res;
  const auto started = clock_type::now();

  std::vector<std::string> cmds;
  if (!dot.function.empty()) {
    cmds.push_back("s " + dot.function);
  } else if (dot.address != 0) {
    cmds.push_back("s " + hex_u64(dot.address));
  }
  cmds.push_back(dot.whole_program ? "agCd" : "agfd");

  const run_out run = run_r2(sample, opts, cmds, dot.timeout);
  res.command_line = run.command_line;
  res.stderr_tail = run.stderr_tail;
  res.exit_code = run.exit_code;

  if (run.st != status::ok) {
    res.st = run.st;
    res.error = run.error;
    res.seconds = seconds_since(started);
    return res;
  }

  if (run.stdout_text.empty() || run.stdout_text.find("digraph") == std::string::npos) {
    res.st = status::bad_output;
    res.error = "r2 produced no valid DOT output (exit=" + std::to_string(run.exit_code);
    if (!run.stdout_text.empty()) {
      res.error += ", stdout: \"" + output_head(run.stdout_text) + "\"";
    }
    if (!run.stderr_tail.empty()) {
      res.error += ", stderr: \"" + output_tail_head(run.stderr_tail) + "\"";
    }
    res.error += ")";
    LOG_WARN("r2: extract_dot: {} — cmd: {}", res.error, run.command_line);
    res.seconds = seconds_since(started);
    return res;
  }

  std::string cleaned = clean_dot_text(strip_dot_preamble(run.stdout_text));
  if (!write_bytes_atomic(out_path, cleaned)) {
    res.st = status::write_failed;
    res.error = "cannot write " + out_path;
    res.seconds = seconds_since(started);
    return res;
  }

  res.st = status::ok;
  res.bytes_written = file_size_or_zero(out_path);
  res.seconds = seconds_since(started);
  res.raw = std::move(cleaned);

  LOG_INFO("r2: extract_dot: '{}' ({}) in {:.3f}s",
           out_path, res.bytes_written, res.seconds);
  return res;
}

// ---------------------------------------------------------------------------
// Raw assembly extraction
//
// Pipeline:
//   1. aflj                     -> function list (name, offset, size)
//   2. pdfj @ <offset> batches  -> per-function JSON (robust; @@f is avoided)
//   3. Branch-target enrichment -> function / "dll!import" labels per call
//   4. Render a flat .asm from the JSON; JSON is the source of truth.
//
// The flat .asm is NEVER parsed back into structured data.
// ---------------------------------------------------------------------------

namespace {

raw_function_t parse_pdfj_function(const json& fn, std::string& err) {
  raw_function_t out;
  out.name   = jstr(fn, "name");
  // r2's pdfj reports the function VA as "addr" (not "offset"); ops use
  // "offset". Accept both so callers never see a 0 address.
  out.offset = jnum(fn, "addr");
  if (out.offset == 0) out.offset = jnum(fn, "offset");
  out.size   = jnum(fn, "size");

  const json* ops = nullptr;
  if (auto it = fn.find("ops"); it != fn.end() && it->is_array()) ops = &*it;
  else if (auto it = fn.find("instructions"); it != fn.end() && it->is_array()) ops = &*it;

  if (ops == nullptr) {
    err = "no ops array in pdfj entry";
    return out;
  }

  out.instructions.reserve(ops->size());
  for (const json& op : *ops) {
    instruction_t ins;
    ins.offset = jnum(op, "offset");
    ins.bytes  = jstr(op, "bytes");
    ins.disasm = jstr(op, "disasm");
    if (ins.disasm.empty()) ins.disasm = jstr(op, "opcode");
    ins.type   = jstr(op, "type");
    ins.valid  = !ins.disasm.empty();

    // Direct branch target: r2 reports it in `jump` for call/jmp/cjmp.
    // Fall back to the first hex operand for r2 builds that omit it.
    ins.target = jnum(op, "jump");
    if (ins.target == 0) {
      const bool branch = (ins.type == "call" || ins.type == "jmp" ||
                           ins.type == "cjmp" || ins.type == "ujmp" ||
                           ins.type == "ucall");
      if (branch) ins.target = first_hex_operand(ins.disasm);
    }

    out.instructions.push_back(std::move(ins));
  }

  out.n_instr = out.instructions.size();

  // Truncation detection: r2 reports the function's true size in `size`.
  // If the sum of instruction bytes is materially less than `size`, the
  // disassembly was cut short (anal.bb.maxsize / asm.bytes / anal.timeout).
  std::uint64_t covered = 0;
  for (const auto& i : out.instructions) covered += (i.bytes.size() / 2);
  if (out.size > 0 && covered + 16 < out.size) out.truncated = true;

  return out;
}

std::string render_flat_asm(const std::vector<raw_function_t>& fns,
                            const raw_asm_options& dump) {
  std::string body;
  body.reserve(64 * 1024);

  for (const auto& fn : fns) {
    if (dump.include_function_header) {
      body += ";;; ------------------------------------------------------------\n";
      body += ";;; function: " + fn.name + " @ " + hex_u64(fn.offset) +
              " size=" + std::to_string(fn.size) +
              " instr=" + std::to_string(fn.n_instr) +
              (fn.truncated ? " (TRUNCATED)" : "") + "\n";
      body += ";;; ------------------------------------------------------------\n";
    }

    for (const auto& i : fn.instructions) {
      if (dump.include_addresses) {
        body += hex_u64(i.offset);
        body += "  ";
      }
      body += i.disasm;
      if (dump.include_target_labels && !i.target_label.empty()) {
        body += "  ; -> " + i.target_label;
      }
      if (dump.include_raw_bytes && !i.bytes.empty()) {
        body += "  ; bytes=" + i.bytes;
      }
      body += '\n';
    }
    body += '\n';
  }
  return body;
}

// Names that count as "entry or main" when a large function list forces a
// hard cut: r2's entryNN flags plus the CRT entry names PE/ELF actually use.
// The dashboard applies the same rule when it shrinks the embedded assembly
// dataset, so both sides keep the same functions.
bool is_main_like_name(const std::string& name) {
  std::string lowered = name;
  std::transform(lowered.begin(), lowered.end(), lowered.begin(),
                 [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  for (const char* prefix : {"sym.", "imp.", "reloc."}) {
    const std::size_t len = std::strlen(prefix);
    if (lowered.size() >= len && lowered.compare(0, len, prefix) == 0) {
      lowered.erase(0, len);
      break;
    }
  }
  while (!lowered.empty() && lowered.front() == '_') lowered.erase(lowered.begin());
  if (lowered.rfind("entry", 0) == 0) return true;  // entry0, entry1, ...
  for (const char* candidate : {"main", "wmain", "winmain", "wwinmain", "dllmain",
                                "start", "maincrtstartup", "wmaincrtstartup",
                                "dllcrtstartup"}) {
    if (lowered == candidate) return true;
  }
  return false;
}

}  // namespace

raw_asm_result_t dump_function_assembly(const std::string& sample,
                                        const std::string& out_dir,
                                        const std::string& stem,
                                        const options& opts,
                                        const raw_asm_options& dump) {
  raw_asm_result_t res;
  const auto started = clock_type::now();

  const std::string asm_path = dump.output_path.empty()
      ? (fs::path(out_dir) / (stem + "_functions.asm")).string()
      : dump.output_path;
  const std::string json_path = dump.json_output_path.empty()
      ? (fs::path(out_dir) / (stem + "_functions.json")).string()
      : dump.json_output_path;

  std::error_code ec;
  fs::create_directories(out_dir, ec);
  if (ec) {
    res.st = status::write_failed;
    res.error = "cannot create '" + out_dir + "': " + ec.message();
    res.seconds = seconds_since(started);
    return res;
  }

  // Step 1: function list.
  function_list_result_t fl = list_functions(sample, opts);
  if (fl.st != status::ok) {
    res.st = fl.st;
    res.error = "list_functions failed: " + fl.error;
    res.seconds = seconds_since(started);
    return res;
  }
  res.functions_requested = fl.functions.size();
  res.r2_version = opts.r2_version;

  // Label sources for coherent disassembly: function names (aflj), import
  // thunks (rabin2 -i, keyed by PLT address) and symbols (rabin2 -s).
  std::unordered_map<std::uint64_t, std::string> label_by_addr;
  std::unordered_set<std::uint64_t> import_addrs;
  std::unordered_set<std::uint64_t> entry_offsets;
  std::vector<section_t> section_metadata;
  {
    result_t rabin = analyze_file(sample, opts);
    if (rabin.st == status::ok) {
      section_metadata = rabin.sections;
      for (const auto& imp : rabin.imports) {
        if (imp.plt == 0 || imp.name.empty()) continue;
        const std::string label =
            (imp.library.empty() ? std::string() : imp.library + "!") + imp.name;
        label_by_addr[imp.plt] = label;
        import_addrs.insert(imp.plt);
      }
      for (const auto& sym : rabin.symbols) {
        if (sym.vaddr == 0 || sym.name.empty()) continue;
        label_by_addr.emplace(sym.vaddr, sym.name);  // never overwrites
      }
      for (const auto& ep : rabin.entrypoints) {
        if (ep.vaddr != 0) entry_offsets.insert(ep.vaddr);
      }
    } else {
      LOG_WARN("r2: dump_function_assembly: rabin2 metadata unavailable ({}); "
               "target labels will be limited", rabin.error);
    }
  }
  for (const auto& f : fl.functions) {
    if (!f.name.empty()) label_by_addr[f.offset] = f.name;  // functions win
  }

  // Step 2: choose the functions to dump, then `pdfj @ <offset>` batches.
  //
  // The previous implementation used the r2 iterator `pdfj @@f`, which is
  // fragile across r2 versions and produced no parseable JSON on some
  // setups. Explicit `pdfj @ <offset>` commands (the same proven pattern
  // dump_xref_calls uses) are deterministic: one JSON object per command,
  // parsed with parse_json_stream. Commands are chunked so a single
  // Windows command line stays well under its 32K limit.
  //
  // Selection: everything up to max_functions, address order as before.
  // When the list is larger than the cap, the first-N-by-address cut would
  // bury the entry point and main among thousands of helpers, so the cut
  // keeps only entry-point functions and main-like names - the same subset
  // the dashboard falls back to when the assembly dataset is too large to
  // embed. If neither rule matches anything (unusual naming), the old
  // first-N behaviour is the fallback.
  std::vector<const function_info_t*> selected;
  selected.reserve(fl.functions.size());
  for (const auto& f : fl.functions) {
    if (dump.include_function && !dump.include_function(f)) continue;
    if (f.size == 0 && f.name.empty()) continue;
    selected.push_back(&f);
  }
  if (selected.size() > dump.max_functions) {
    std::vector<const function_info_t*> important;
    important.reserve(selected.size());
    for (const function_info_t* f : selected) {
      if (entry_offsets.count(f->offset) > 0 || is_main_like_name(f->name)) {
        important.push_back(f);
        if (important.size() >= dump.max_functions) break;
      }
    }
    if (!important.empty()) {
      LOG_WARN("r2: dump_function_assembly: {} function(s) exceed the {} cap; "
               "keeping only the {} entry/main function(s)",
               selected.size(), dump.max_functions, important.size());
      selected = std::move(important);
    } else {
      LOG_WARN("r2: dump_function_assembly: {} function(s) exceed the {} cap "
               "and no entry/main function was recognised; keeping the first {}",
               selected.size(), dump.max_functions, dump.max_functions);
      selected.resize(dump.max_functions);
    }
  }

  std::vector<std::uint64_t> dump_offsets;
  dump_offsets.reserve(selected.size());
  for (const function_info_t* f : selected) dump_offsets.push_back(f->offset);

  std::vector<json> docs;
  {
    constexpr std::size_t kCmdsPerRun = 800;  // ~20 KB of command line
    std::string hard_err;
    bool hard_fail = false;

    for (std::size_t base = 0; base < dump_offsets.size(); base += kCmdsPerRun) {
      const std::size_t end = std::min(base + kCmdsPerRun, dump_offsets.size());
      std::vector<std::string> cmds;
      cmds.reserve((end - base) + 1);
      for (std::size_t i = base; i < end; ++i) {
        cmds.push_back("pdfj @ " + hex_u64(dump_offsets[i]));
      }

      const run_out run = run_r2(sample, opts, cmds, opts.timeout);
      res.command_line = run.command_line;
      res.stderr_tail  = run.stderr_tail;
      res.exit_code    = run.exit_code;

      if (run.st != status::ok) {
        if (run.st == status::not_found || run.st == status::launch_failed ||
            run.st == status::timed_out || run.st == status::output_too_large) {
          hard_fail = true;
          hard_err  = run.error;
          break;
        }
        res.errors.emplace_back("batch", run.error);
        continue;
      }

      for (json& d : parse_json_stream(run.stdout_text)) {
        docs.push_back(std::move(d));
      }
    }

    if (docs.empty()) {
      res.st = status::bad_output;
      res.error = hard_fail ? hard_err
                            : "pdfj batches produced no parseable JSON objects";
      res.seconds = seconds_since(started);
      return res;
    }
  }

  // Step 3: parse + enrich with coherence labels.
  std::vector<raw_function_t> kept;
  kept.reserve(docs.size());

  std::unordered_map<std::string, section_nop_stat_t> nop_by_section;
  const auto section_for_address = [&](std::uint64_t address) {
    for (const section_t& section : section_metadata) {
      if (address >= section.vaddr && address < section.vaddr + section.size) return section.name;
    }
    return std::string("<unmapped>");
  };

  for (const json& fn : docs) {
    if (!fn.is_object()) continue;

    std::string per_err;
    raw_function_t rf = parse_pdfj_function(fn, per_err);
    if (!per_err.empty()) {
      res.errors.emplace_back(rf.name.empty() ? hex_u64(rf.offset) : rf.name, per_err);
      continue;
    }

    for (auto& ins : rf.instructions) {
      const std::string section_name = section_for_address(ins.offset);
      ins.section = section_name;
      section_nop_stat_t& stat = nop_by_section[section_name];
      ++stat.instructions;
      if (is_nop_instruction(ins)) {
        ++stat.nop_count;
        ++rf.nop_count;
        ++res.nop_total;
      }
      if (ins.target == 0) continue;
      auto it = label_by_addr.find(ins.target);
      if (it == label_by_addr.end()) continue;
      ins.target_label   = it->second;
      ins.targets_import = import_addrs.count(ins.target) > 0;
    }

    if (rf.truncated) ++res.functions_truncated;
    res.instructions_total += rf.n_instr;
    kept.push_back(std::move(rf));
  }

  res.functions_dumped = kept.size();
  res.functions = std::move(kept);
  res.section_nop_stats.clear();
  for (auto& [name, stat] : nop_by_section) {
    stat.section = name;
    res.section_nop_stats.push_back(stat);
  }
  std::sort(res.section_nop_stats.begin(), res.section_nop_stats.end(),
            [](const section_nop_stat_t& a, const section_nop_stat_t& b) {
              return a.section < b.section;
            });

  if (res.functions.empty()) {
    res.st = status::bad_output;
    res.error = "no functions matched the filter";
    res.seconds = seconds_since(started);
    return res;
  }

  // Structured JSON artifact: enriched ops (target + label) so downstream
  // consumers (the dashboard) never need the raw r2 stream.
  if (!json_path.empty()) {
    json arr = json::array();
    for (const auto& f : res.functions) {
      json jf;
      jf["name"]      = f.name;
      jf["offset"]    = f.offset;
      jf["size"]      = f.size;
      jf["n_instr"]   = f.n_instr;
      jf["nop_count"] = f.nop_count;
      jf["truncated"] = f.truncated;
      json ops = json::array();
      for (const auto& i : f.instructions) {
        json jo = {{"offset", i.offset}, {"bytes", i.bytes},
                   {"disasm", i.disasm}, {"type", i.type}, {"section", i.section}};
        if (i.target != 0) {
          jo["target"] = i.target;
          if (!i.target_label.empty()) jo["target_label"] = i.target_label;
          if (i.targets_import) jo["import"] = true;
        }
        ops.push_back(std::move(jo));
      }
      jf["ops"] = std::move(ops);
      arr.push_back(std::move(jf));
    }
    if (!write_bytes_atomic(json_path, arr.dump(2))) {
      res.errors.emplace_back("json", "write failed: " + json_path);
    } else {
      res.json_path = json_path;
    }
  }

  // Step 4: render flat .asm (derived artifact).
  if (dump.emit_asm) {
    const std::string body = render_flat_asm(res.functions, dump);
    if (!write_bytes_atomic(asm_path, body)) {
      res.st = status::write_failed;
      res.error = "cannot write " + asm_path;
      res.seconds = seconds_since(started);
      return res;
    }
    res.asm_path = asm_path;
    res.asm_bytes = file_size_or_zero(asm_path);
  }

  res.st = res.errors.empty() ? status::ok : status::partial;
  res.seconds = seconds_since(started);

  LOG_INFO("r2: dump_function_assembly: '{}' — {}/{} function(s), {} instr, {} truncated in {:.3f}s",
           asm_path, res.functions_dumped, res.functions_requested,
           res.instructions_total, res.functions_truncated, res.seconds);
  return res;
}

// ---------------------------------------------------------------------------
// Per-section .dot
// ---------------------------------------------------------------------------

section_dot_result_t dump_section_dots(const std::string& sample,
                                       const std::string& out_dir,
                                       const std::string& stem,
                                       const options& opts,
                                       const section_dot_options& dump) {
  section_dot_result_t res;
  const auto started = clock_type::now();

  LOG_INFO("r2: dump_section_dots: '{}' -> '{}' (stem='{}')",
           sample, out_dir, stem);

  const std::string target_dir = dump.output_dir.empty() ? out_dir : dump.output_dir;
  std::error_code ec;
  fs::create_directories(target_dir, ec);
  if (ec) {
    res.st = status::write_failed;
    res.error = "cannot create '" + target_dir + "': " + ec.message();
    return res;
  }

  result_t rabin = analyze_file(sample, opts);
  if (rabin.st != status::ok) {
    res.st = rabin.st;
    res.error = "rabin2 failed: " + rabin.error;
    res.seconds = seconds_since(started);
    return res;
  }

  function_list_result_t fl = list_functions(sample, opts);
  if (fl.st != status::ok) {
    res.st = fl.st;
    res.error = "list_functions failed: " + fl.error;
    res.seconds = seconds_since(started);
    return res;
  }

  // Bucket functions by containing section (by start address).
  for (const auto& s : rabin.sections) {
    if (s.name.empty()) continue;
    if (dump.executable_only && s.perms.find('x') == std::string::npos) continue;
    if (s.size == 0) continue;
    ++res.sections_considered;

    std::vector<const function_info_t*> in_section;
    for (const auto& f : fl.functions) {
      if (f.offset >= s.vaddr && f.offset < s.vaddr + s.size) {
        in_section.push_back(&f);
        if (in_section.size() >= dump.max_functions_per_section) break;
      }
    }

    const std::string filename = substitute_pattern(dump.filename_pattern, stem, s.name);
    const std::string path = (fs::path(target_dir) / filename).string();

    if (in_section.empty()) {
      if (dump.skip_empty) continue;
      const std::string empty_dot =
          "digraph section_" + sanitize_section_name(s.name) + " {}\n";
      if (write_bytes_atomic(path, empty_dot)) {
        res.files.push_back({s.name, path, file_size_or_zero(path), 0, true});
        ++res.sections_written;
      }
      continue;
    }

    // One seek + agfd per function; each produces its own digraph. We then
    // namespace node IDs per digraph and merge them into a single graph so
    // that identically-numbered nodes in different functions don't collide.
    //
    // The commands are chunked: one run with up to max_functions_per_section
    // x 2 commands overshot the 32K Windows command-line limit on large
    // sections and CreateProcess failed with error 206 before r2 started.
    std::string stdout_text;
    {
      constexpr std::size_t kFnsPerRun = 400;  // 800 commands ~ 20 KB
      bool hard_fail = false;
      std::string hard_err;
      for (std::size_t base = 0; base < in_section.size();
           base += kFnsPerRun) {
        const std::size_t end = std::min(base + kFnsPerRun, in_section.size());
        std::vector<std::string> cmds;
        cmds.reserve((end - base) * 2);
        for (std::size_t i = base; i < end; ++i) {
          cmds.push_back("s " + hex_u64(in_section[i]->offset));
          cmds.push_back("agfd");
        }

        const run_out run = run_r2(sample, opts, cmds, dump.per_section_timeout);
        if (run.st != status::ok) {
          if (run.st == status::not_found || run.st == status::launch_failed ||
              run.st == status::timed_out || run.st == status::output_too_large) {
            hard_fail = true;
            hard_err  = run.error;
            break;
          }
          res.errors.push_back({s.name, run.error});
          continue;
        }
        stdout_text += run.stdout_text;
      }
      if (hard_fail) {
        LOG_WARN("r2: dump_section_dots: section '{}' failed: {}", s.name, hard_err);
        res.errors.push_back({s.name, hard_err});
        continue;
      }
    }

    if (stdout_text.find("digraph") == std::string::npos) continue;

    std::string combined;
    {
      std::size_t pos = 0;
      std::size_t fn_index = 0;
      combined += "digraph section_" + sanitize_section_name(s.name) + " {\n";
      combined += "  node [shape=box, fontname=\"Courier\"];\n";

      while (true) {
        const std::size_t dg = stdout_text.find("digraph", pos);
        if (dg == std::string::npos) break;
        const std::size_t brace_open = stdout_text.find('{', dg);
        if (brace_open == std::string::npos) break;

        int depth = 1;
        std::size_t cursor = brace_open + 1;
        while (cursor < stdout_text.size() && depth > 0) {
          if (stdout_text[cursor] == '{') ++depth;
          else if (stdout_text[cursor] == '}') --depth;
          ++cursor;
        }
        if (depth != 0) break;

        std::string body = stdout_text.substr(brace_open + 1,
                                              cursor - brace_open - 2);

        // Namespace node IDs by prefixing each `0x...` token with fn<N>_.
        const std::string prefix = "fn" + std::to_string(fn_index) + "_";
        std::string remapped;
        remapped.reserve(body.size() + 64);
        for (std::size_t i = 0; i < body.size();) {
          if (i + 2 < body.size() && body[i] == '0' && body[i + 1] == 'x' &&
              std::isxdigit(static_cast<unsigned char>(body[i + 2]))) {
            std::size_t e = i + 2;
            while (e < body.size() &&
                   std::isxdigit(static_cast<unsigned char>(body[e]))) ++e;
            remapped += prefix;
            remapped.append(body, i, e - i);
            i = e;
          } else {
            remapped.push_back(body[i]);
            ++i;
          }
        }

        combined += "  // ---- function " + std::to_string(fn_index) + " ----\n";
        combined += remapped;
        if (!remapped.empty() && remapped.back() != '\n') combined += '\n';
        ++fn_index;
        pos = cursor;
      }
      combined += "}\n";
    }

    std::string cleaned = clean_dot_text(combined);
    if (!write_bytes_atomic(path, cleaned)) {
      res.errors.push_back({s.name, "write failed"});
      continue;
    }

    res.files.push_back({s.name, path, file_size_or_zero(path),
                         in_section.size(), false});
    ++res.sections_written;
  }

  if (res.errors.empty()) {
    res.st = status::ok;
  } else if (res.sections_written == 0) {
    res.st = status::bad_output;
  } else {
    res.st = status::partial;
  }
  res.seconds = seconds_since(started);

  LOG_INFO("r2: dump_section_dots: '{}' — {}/{} section(s) written in {:.3f}s",
           sample, res.sections_written, res.sections_considered, res.seconds);
  return res;
}

// ---------------------------------------------------------------------------
// Graphviz rendering (dot.exe -> svg / png / pdf / ...)
// ---------------------------------------------------------------------------

std::string default_dot() {
#ifdef _WIN32
  for (const char* p : {
           "C:\\Program Files\\Graphviz\\bin\\dot.exe",
           "C:\\Program Files (x86)\\Graphviz\\bin\\dot.exe",
       }) {
    std::error_code ec;
    if (fs::exists(p, ec) && !ec) return p;
  }
#endif
  return proc::find_in_path("dot");
}

std::string render_dot(const std::string& dot_exe,
                       const std::string& in_dot,
                       const std::string& out_path,
                       const std::string& format) {
  if (dot_exe.empty())
    return "graphviz 'dot' not found (install Graphviz or pass an explicit path)";
  if (in_dot.empty())
    return "empty dot input path";
  if (out_path.empty())
    return "empty dot output path";

  const std::string tmp = out_path + ".tmp";

  std::error_code ec;
  fs::remove(tmp, ec);   // stale tmp from a previous crash
  ec.clear();

  proc::run_options ro;
  ro.timeout = std::chrono::seconds(60);

  const proc::run_result r = proc::run(dot_exe, {"-T" + format, "-o", tmp, in_dot}, ro);

  switch (r.status) {
    case proc::launch_status::ok:
      break;
    case proc::launch_status::not_found:
      return "dot executable not found: " + dot_exe;
    case proc::launch_status::timed_out:
      fs::remove(tmp, ec);
      return "dot timed out";
    case proc::launch_status::output_too_large:
      fs::remove(tmp, ec);
      return "dot produced too much output";
    case proc::launch_status::launch_failed:
    default:
      fs::remove(tmp, ec);
      return "dot launch failed: " + r.error;
  }

  if (r.exit_code != 0) {
    fs::remove(tmp, ec);
    std::string msg = "dot exited with code " + std::to_string(r.exit_code);
    if (!r.std_err.empty()) msg += ": " + r.std_err;
    return msg;
  }

#ifdef _WIN32
  fs::remove(out_path, ec);
  ec.clear();
#endif
  fs::rename(tmp, out_path, ec);
  if (ec) {
    fs::remove(tmp, ec);
    return "failed to move dot output into place: " + ec.message();
  }

  return {};
}

std::vector<std::pair<std::string, std::string>>
render_section_dots(const section_dot_result_t& sections,
                    const std::string& dot_exe,
                    const std::string& format) {
  std::vector<std::pair<std::string, std::string>> errors;
  if (sections.files.empty()) return errors;

  const std::string exe = dot_exe.empty() ? default_dot() : dot_exe;
  if (exe.empty()) {
    errors.emplace_back("", "graphviz 'dot' not found");
    return errors;
  }

  for (const auto& f : sections.files) {
    if (f.empty || f.path.empty()) continue;

    fs::path p = f.path;
    p.replace_extension("." + format);
    const std::string out = p.string();

    if (auto err = render_dot(exe, f.path, out, format); !err.empty())
      errors.emplace_back(f.section, err);
  }

  return errors;
}

// ---------------------------------------------------------------------------
// IAT / GOT call-site assembly
//
// Uses axtj (JSON xrefs) instead of parsing `axt` text, and pdfj for the
// enclosing function instead of `pD` with an implicit block size.
// ---------------------------------------------------------------------------

namespace {

// Given a call-site address, find the enclosing function in the aflj list.
const function_info_t* find_enclosing(const std::vector<function_info_t>& fns,
                                      std::uint64_t addr) {
  const function_info_t* best = nullptr;
  for (const auto& f : fns) {
    if (addr < f.offset) continue;
    if (f.size == 0) continue;
    if (addr >= f.offset && addr < f.offset + f.size) {
      if (best == nullptr || f.offset > best->offset) best = &f;
    }
  }
  return best;
}

// Stages 0-1 of dump_xref_calls, shared with resolve_call_sites: the function
// list (aflj) and one batched axtj run, keeping the sites per slot so a caller
// can map an individual import slot to the code that references it.
struct xref_stage_t {
  status      st = status::ok;
  std::string error;

  function_list_result_t functions;
  std::vector<std::uint64_t> slots;                    // after the max_slots cap
  std::vector<std::vector<std::uint64_t>> sites_per_slot;  // parallel to slots
  std::vector<std::uint64_t> call_sites;               // deduped, first-seen order
  std::size_t slots_with_xrefs = 0;

  std::string command_line;
  std::string stderr_tail;
  int         exit_code = 0;
};

xref_stage_t collect_xref_stage(const std::string& sample,
                                const std::vector<std::uint64_t>& targets,
                                const options& opts,
                                std::size_t max_slots) {
  xref_stage_t s;

  s.slots = targets;
  if (s.slots.size() > max_slots) s.slots.resize(max_slots);
  s.sites_per_slot.assign(s.slots.size(), {});

  // One r2 process, one analysis pass: aflj first (so call sites can be
  // mapped to their enclosing function), then one axtj per slot. Analysis is
  // by far the most expensive part of this - running the two commands in
  // separate processes would pay for it twice.
  std::vector<std::string> cmds;
  cmds.reserve(s.slots.size() + 1);
  cmds.push_back("aflj");
  for (const std::uint64_t a : s.slots) {
    cmds.push_back("axtj @ " + hex_u64(a));
  }

  const run_out run = run_r2(sample, opts, cmds, opts.timeout);
  s.command_line = run.command_line;
  s.stderr_tail  = run.stderr_tail;
  s.exit_code    = run.exit_code;

  if (run.st != status::ok) {
    s.st = run.st;
    s.error = "xref resolution failed: " + run.error;
    return s;
  }

  // r2 emits one JSON value per command, concatenated with no separator: the
  // aflj array first, then one array per slot, in order.
  const std::vector<json> docs = parse_json_stream(run.stdout_text);
  const std::size_t expected = s.slots.size() + 1;
  if (docs.size() != expected) {
    s.st = status::bad_output;
    s.error = "r2 produced " + std::to_string(docs.size()) +
              " JSON document(s), expected " + std::to_string(expected);
    return s;
  }
  if (!docs.front().is_array()) {
    s.st = status::bad_output;
    s.error = "aflj output is not a JSON array";
    return s;
  }
  parse_function_list(docs.front(), s.functions.functions);

  std::unordered_set<std::uint64_t> seen_global;
  for (std::size_t i = 0; i < s.slots.size(); ++i) {
    const json& doc = docs[i + 1];
    bool had = false;
    auto collect = [&](const json& x) {
      if (!x.is_object()) return;
      const std::uint64_t from = jnum(x, "from");
      if (from == 0) return;
      std::vector<std::uint64_t>& per_slot = s.sites_per_slot[i];
      if (std::find(per_slot.begin(), per_slot.end(), from) == per_slot.end()) {
        per_slot.push_back(from);
      }
      if (seen_global.insert(from).second) s.call_sites.push_back(from);
      had = true;
    };
    if (doc.is_array()) { for (const auto& x : doc) collect(x); }
    else collect(doc);
    if (had) ++s.slots_with_xrefs;
  }
  return s;
}

}  // namespace

xref_asm_result_t dump_xref_calls(const std::string& sample,
                                  const std::string& out_dir,
                                  const std::string& stem,
                                  const std::vector<std::uint64_t>& targets,
                                  const options& opts,
                                  const xref_asm_options& dump) {
  xref_asm_result_t res;
  const auto started = clock_type::now();

  const std::string path = dump.output_path.empty()
      ? (fs::path(out_dir) / (stem + "_iat_calls.asm")).string()
      : dump.output_path;
  const std::string json_path = dump.json_output_path.empty()
      ? (fs::path(out_dir) / (stem + "_iat_calls.json")).string()
      : dump.json_output_path;

  std::error_code ec;
  fs::create_directories(out_dir, ec);
  if (ec) {
    res.st = status::write_failed;
    res.error = "cannot create '" + out_dir + "': " + ec.message();
    res.seconds = seconds_since(started);
    return res;
  }

  if (targets.empty()) {
    res.st = status::bad_output;
    res.error = "no target slots provided";
    res.seconds = seconds_since(started);
    return res;
  }

  // --- Stage 0 + 1: function list, then xrefs for every slot --------------
  const xref_stage_t stage = collect_xref_stage(sample, targets, opts, dump.max_slots);
  if (stage.st != status::ok) {
    res.st = stage.st;
    res.error = stage.error;
    res.seconds = seconds_since(started);
    return res;
  }
  res.r2_version = opts.r2_version;
  res.command_line = stage.command_line;
  res.stderr_tail = stage.stderr_tail;
  res.exit_code = stage.exit_code;
  res.slots_input = stage.slots.size();
  res.xrefs_found = stage.call_sites.size();
  res.slots_with_xrefs = stage.slots_with_xrefs;

  if (stage.call_sites.empty()) {
    res.st = status::bad_output;
    res.error = "no xrefs found for any slot";
    res.seconds = seconds_since(started);
    return res;
  }

  // Map each call site to its enclosing function.
  std::vector<std::uint64_t> functions_to_dump;
  std::unordered_set<std::uint64_t> seen_fn;
  for (auto a : stage.call_sites) {
    const function_info_t* f = find_enclosing(stage.functions.functions, a);
    if (f == nullptr) continue;
    if (dump.dedup_functions) {
      if (!seen_fn.insert(f->offset).second) continue;
    }
    functions_to_dump.push_back(f->offset);
    if (functions_to_dump.size() >= dump.max_functions) break;
  }

  if (functions_to_dump.empty()) {
    res.st = status::bad_output;
    res.error = "no call sites mapped to a known function";
    res.seconds = seconds_since(started);
    return res;
  }

  // --- Stage 2: pdfj @ <fn_offset> for each enclosing function -----------
  std::vector<std::string> pdf_cmds;
  pdf_cmds.reserve(functions_to_dump.size());
  for (auto a : functions_to_dump) {
    pdf_cmds.push_back("pdfj @ " + hex_u64(a));
  }

  const run_out pdf_run = run_r2(sample, opts, pdf_cmds, opts.timeout);
  if (pdf_run.st != status::ok) {
    res.st = pdf_run.st;
    res.error = "function dump failed: " + pdf_run.error;
    res.seconds = seconds_since(started);
    return res;
  }

  // pdfj @ <addr> emits one JSON object per invocation, concatenated.
  const std::vector<json> pdf_docs = parse_json_stream(pdf_run.stdout_text);

  std::vector<raw_function_t> dumped_fns;
  dumped_fns.reserve(pdf_docs.size());
  for (const json& doc : pdf_docs) {
    std::string per_err;
    raw_function_t rf = parse_pdfj_function(doc, per_err);
    if (per_err.empty()) dumped_fns.push_back(std::move(rf));
    else res.errors.emplace_back(hex_u64(jnum(doc, "offset")), per_err);
  }

  if (dumped_fns.empty()) {
    res.st = status::bad_output;
    res.error = "pdfj produced no usable function objects";
    res.seconds = seconds_since(started);
    return res;
  }

  // Write the raw JSON next to the .asm for provenance.
  {
    json arr = json::array();
    for (const auto& f : dumped_fns) {
      json jf;
      jf["name"]      = f.name;
      jf["offset"]    = f.offset;
      jf["size"]      = f.size;
      jf["truncated"] = f.truncated;
      json ops = json::array();
      for (const auto& i : f.instructions) {
        ops.push_back({
          {"offset", i.offset},
          {"bytes",  i.bytes},
          {"disasm", i.disasm},
          {"type",   i.type}
        });
      }
      jf["ops"] = std::move(ops);
      arr.push_back(std::move(jf));
    }
    if (write_bytes_atomic(json_path, arr.dump(2))) res.json_path = json_path;
  }

  // Render the .asm.
  raw_asm_options render;
  render.include_addresses       = dump.include_addresses;
  render.include_function_header = dump.include_function_header;
  render.include_raw_bytes       = dump.include_raw_bytes;

  std::string body;
  body += ";;; ============================================================\n";
  body += ";;; IAT/GOT call-site disassembly of " + stem + "\n";
  body += ";;; targets:      " + std::to_string(res.slots_input) + " slot(s)\n";
  body += ";;; slots w/xref: " + std::to_string(res.slots_with_xrefs) + "\n";
  body += ";;; call sites:   " + std::to_string(res.xrefs_found) + "\n";
  body += ";;; functions:    " + std::to_string(dumped_fns.size()) + "\n";
  body += ";;; ============================================================\n\n";
  body += render_flat_asm(dumped_fns, render);

  if (!write_bytes_atomic(path, body)) {
    res.st = status::write_failed;
    res.error = "cannot write " + path;
    res.seconds = seconds_since(started);
    return res;
  }

  for (const auto& f : dumped_fns) {
    res.instructions_total += f.n_instr;
    if (f.truncated) ++res.functions_truncated;
  }

  res.st = res.errors.empty() ? status::ok : status::partial;
  res.path = path;
  res.bytes = file_size_or_zero(path);
  res.functions_dumped = dumped_fns.size();
  res.seconds = seconds_since(started);

  LOG_INFO("r2: dump_xref_calls: '{}' done in {:.3f}s — {} function(s), {} call site(s), {} bytes",
           path, res.seconds, res.functions_dumped, res.xrefs_found, res.bytes);
  return res;
}

call_sites_result_t resolve_call_sites(const std::string& sample,
                                       const std::vector<std::uint64_t>& targets,
                                       const options& opts,
                                       std::size_t max_slots) {
  call_sites_result_t res;
  const auto started = clock_type::now();

  if (targets.empty()) {
    res.st = status::bad_output;
    res.error = "no target slots provided";
    res.seconds = seconds_since(started);
    return res;
  }

  const xref_stage_t stage = collect_xref_stage(sample, targets, opts, max_slots);
  res.command_line = stage.command_line;
  res.stderr_tail  = stage.stderr_tail;
  res.exit_code    = stage.exit_code;
  res.r2_version   = opts.r2_version;

  if (stage.st != status::ok) {
    res.st = stage.st;
    res.error = stage.error;
    res.seconds = seconds_since(started);
    return res;
  }

  res.slots_input       = stage.slots.size();
  res.slots_with_xrefs  = stage.slots_with_xrefs;

  // Every input target gets an entry, even an empty one: the caller uses that
  // to tell "nothing references this slot" from "this was never resolved".
  for (std::size_t i = 0; i < stage.slots.size(); ++i) {
    std::vector<callsite_t>& sites = res.by_target[stage.slots[i]];
    for (const std::uint64_t a : stage.sites_per_slot[i]) {
      const function_info_t* f = find_enclosing(stage.functions.functions, a);
      if (f == nullptr) continue;
      callsite_t c;
      c.address         = a;
      c.function        = f->name;
      c.function_offset = f->offset;
      c.function_size   = f->size;
      sites.push_back(std::move(c));
      ++res.sites_found;
    }
  }

  res.st = status::ok;
  res.seconds = seconds_since(started);
  LOG_INFO("r2: resolve_call_sites done in {:.3f}s — {} slot(s), {} with xrefs, {} site(s)",
           res.seconds, res.slots_input, res.slots_with_xrefs, res.sites_found);
  return res;
}

// ---------------------------------------------------------------------------
// Bulk extraction
// ---------------------------------------------------------------------------

bulk_result_t extract_all(const std::string& sample,
                          const std::string& out_dir,
                          const std::string& stem,
                          const options& opts) {
  bulk_result_t res;
  const auto started = clock_type::now();

  LOG_INFO("r2: extract_all: '{}' -> '{}' (stem='{}')", sample, out_dir, stem);

  std::error_code ec;
  fs::create_directories(out_dir, ec);
  if (ec) {
    res.st = status::write_failed;
    res.errors.push_back({"mkdir", ec.message()});
    return res;
  }

  // One shared function list for the whole bulk pass.
  function_list_result_t fl = list_functions(sample, opts);
  if (fl.st == status::ok) {
    res.functions = fl.functions;
  } else {
    res.errors.push_back({"list_functions", fl.error});
  }

  // 1. Whole-program call graph
  {
    dot_options dot;
    dot.whole_program = true;
    const std::string path = (fs::path(out_dir) / (stem + "_callgraph.dot")).string();
    dot_result_t r = extract_dot(sample, path, opts, dot);
    if (r.st == status::ok) res.files.push_back({path, r.bytes_written, "callgraph"});
    else res.errors.push_back({"callgraph", r.error});
  }

  // 2. Entry function basic blocks
  {
    dot_options dot;
    dot.whole_program = false;
    const std::string path = (fs::path(out_dir) / (stem + "_entry.dot")).string();
    dot_result_t r = extract_dot(sample, path, opts, dot);
    if (r.st == status::ok) res.files.push_back({path, r.bytes_written, "entry"});
    else res.errors.push_back({"entry", r.error});
  }

  // 3. Flat assembly listing (JSON-backed)
  {
    raw_asm_options dump;
    raw_asm_result_t r = dump_function_assembly(sample, out_dir, stem, opts, dump);
    if (r.st == status::ok || r.st == status::partial) {
      if (!r.asm_path.empty())  res.files.push_back({r.asm_path,  r.asm_bytes, "asm"});
      if (!r.json_path.empty()) res.files.push_back({r.json_path,
                                                     file_size_or_zero(r.json_path),
                                                     "asm_json"});
      res.nop_total = r.nop_total;
      res.section_nop_stats = r.section_nop_stats;
    } else {
      res.errors.push_back({"asm", r.error});
    }
    for (const auto& [k, v] : r.errors) res.errors.push_back({"asm:" + k, v});
  }

  // 4. Per-section .dot graphs
  {
    section_dot_options dump;
    dump.executable_only = true;
    dump.skip_empty      = true;
    section_dot_result_t r = dump_section_dots(sample, out_dir, stem, opts, dump);
    for (const auto& f : r.files) {
      res.files.push_back({f.path, f.bytes, "section:" + f.section});
    }
    for (const auto& [section, msg] : r.errors) {
      res.errors.push_back({"section:" + section, msg});
    }
  }

  if (res.errors.empty()) res.st = status::ok;
  else if (res.files.empty()) res.st = status::bad_output;
  else res.st = status::partial;

  res.seconds = seconds_since(started);

  LOG_INFO("r2: extract_all: '{}' done in {:.3f}s — {} file(s), {} function(s), {} error(s)",
           sample, res.seconds, res.files.size(), res.functions.size(), res.errors.size());
  return res;
}

}  // namespace r2