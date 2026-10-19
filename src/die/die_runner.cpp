// die_runner.cpp
//
// Thin wrapper around python/die_scan.py --json (see python/die_scan.py for
// the document contract and exit-code table). Mirrors the capa / visualizer
// runner shape: pre-flight checks, proc::run with timeout and output caps,
// then a strict parse of the single JSON document on stdout.

#include "die_runner.hpp"

#include <chrono>
#include <filesystem>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#include "logging.hpp"
#include "process_runner.hpp"

namespace die_runner {

namespace fs = std::filesystem;
using clock_type = std::chrono::steady_clock;

const char* to_string(status st) {
  switch (st) {
    case status::ok:               return "ok";
    case status::script_missing:   return "script_missing";
    case status::not_installed:    return "not_installed";
    case status::launch_failed:    return "launch_failed";
    case status::timed_out:        return "timed_out";
    case status::output_too_large: return "output_too_large";
    case status::exit_error:       return "exit_error";
    case status::bad_output:       return "bad_output";
  }
  return "unknown";
}

namespace {

std::string tail_of(const std::string& text, std::size_t max_chars) {
  if (text.size() <= max_chars) return text;
  return "..." + text.substr(text.size() - max_chars);
}

// Reads one entry object {name,version,type,info,string}; anything missing
// becomes an empty string rather than an error - the script's schema is
// stable, but a future DIE release adding fields must not break us.
entry_t read_entry(const nlohmann::json& j) {
  entry_t e;
  if (j.contains("name") && j["name"].is_string())       e.name    = j["name"].get<std::string>();
  if (j.contains("version") && j["version"].is_string()) e.version = j["version"].get<std::string>();
  if (j.contains("type") && j["type"].is_string())       e.type    = j["type"].get<std::string>();
  if (j.contains("info") && j["info"].is_string())       e.info    = j["info"].get<std::string>();
  if (j.contains("string") && j["string"].is_string())   e.string  = j["string"].get<std::string>();
  return e;
}

void read_entries(const nlohmann::json& doc, const char* key,
                  std::vector<entry_t>& out) {
  const auto it = doc.find(key);
  if (it == doc.end() || !it->is_array()) return;
  out.reserve(it->size());
  for (const auto& item : *it) {
    if (item.is_object()) out.push_back(read_entry(item));
  }
}

}  // namespace

result_t scan_file(const std::string& sample, const options& opts) {
  result_t res;
  res.attempted = true;
  const auto started = clock_type::now();

  if (!fs::is_regular_file(opts.script)) {
    res.st = status::script_missing;
    res.error = "die_scan.py not found: '" + opts.script + "'";
    LOG_ERROR("die: {}", res.error);
    return res;
  }

  std::vector<std::string> args;
  args.push_back(opts.script);
  args.push_back("--json");
  if (opts.deep) args.push_back("--deep");
  args.push_back(sample);

  {
    std::string line = opts.python;
    for (const auto& a : args) {
      line += ' ';
      if (a.find_first_of(" \t\"") != std::string::npos) line += '"' + a + '"';
      else line += a;
    }
    res.command_line = line;
  }
  LOG_INFO("die: run: {}", res.command_line);

  proc::run_options ro;
  ro.timeout          = opts.timeout;
  ro.max_stdout_bytes = opts.max_stdout_bytes;
  ro.max_stderr_bytes = opts.max_stderr_bytes;

  const proc::run_result r = proc::run(opts.python, args, ro);
  res.exit_code   = r.exit_code;
  res.seconds     = std::chrono::duration<double>(clock_type::now() - started).count();
  res.stderr_tail = tail_of(r.std_err, 4096);

  switch (r.status) {
    case proc::launch_status::ok:
      break;
    case proc::launch_status::not_found:
      res.st = status::launch_failed;
      res.error = "python interpreter not found: '" + opts.python + "'";
      LOG_ERROR("die: {}", res.error);
      return res;
    case proc::launch_status::timed_out:
      res.st = status::timed_out;
      res.error = "die scan timed out after " +
                  std::to_string(opts.timeout.count()) + " s";
      LOG_ERROR("die: {}", res.error);
      return res;
    case proc::launch_status::output_too_large:
      res.st = status::output_too_large;
      res.error = "die output exceeded " +
                  std::to_string(opts.max_stdout_bytes) + " bytes";
      LOG_ERROR("die: {}", res.error);
      return res;
    case proc::launch_status::launch_failed:
    default:
      res.st = status::launch_failed;
      res.error = "cannot launch die scan: " +
                  (r.error.empty() ? proc::to_string(r.status) : r.error);
      LOG_ERROR("die: {}", res.error);
      return res;
  }

  // Exit-code table of die_scan.py: 0 ok, 2 usage, 3 die missing,
  // 4 sample unreadable, 5 scan failed. 3 maps to not_installed so the phase
  // can report a missing optional dependency as a skip, not a failure.
  if (r.exit_code == 3) {
    res.st = status::not_installed;
    // No stderr tail here: die_scan.py's --json mode writes progress lines to
    // stderr, and appending them turned the skip reason into a multi-line
    // blob ("...: [die_scan] checking signature databases..."). The message
    // alone already names the fix.
    res.error = "die module not installed (pip install die-python)";
    LOG_WARN("die: {}", res.error);
    return res;
  }
  if (r.exit_code != 0) {
    res.st = status::exit_error;
    res.error = "die scan exited with code " + std::to_string(r.exit_code);
    if (!r.std_err.empty()) res.error += ": " + tail_of(r.std_err, 400);
    LOG_WARN("die: {}", res.error);
    return res;
  }

  nlohmann::json doc;
  try {
    doc = nlohmann::json::parse(r.std_out);
  } catch (const std::exception& ex) {
    res.st = status::bad_output;
    res.error = std::string("die output is not valid JSON: ") + ex.what();
    LOG_ERROR("die: {}", res.error);
    return res;
  }
  if (!doc.is_object()) {
    res.st = status::bad_output;
    res.error = "die output is not a JSON object";
    LOG_ERROR("die: {}", res.error);
    return res;
  }

  // The script exits 0 only with ok=true, but verify the document itself so a
  // future script regression still surfaces through the parse, not a crash.
  if (doc.contains("ok") && doc["ok"].is_boolean() && !doc["ok"].get<bool>()) {
    res.st = status::exit_error;
    res.error = doc.value("error", "die reported ok=false");
    LOG_WARN("die: {}", res.error);
    return res;
  }

  res.packed        = doc.value("packed", false);
  res.unknown_only  = doc.value("unknown_only", false);
  res.unknown_count = doc.value("unknown_count", std::size_t{0});
  res.databases     = doc.value("databases", std::size_t{0});
  if (doc.contains("die_version") && doc["die_version"].is_string())
    res.die_version = doc["die_version"].get<std::string>();
  read_entries(doc, "packers",   res.packers);
  read_entries(doc, "compilers", res.compilers);
  read_entries(doc, "linkers",   res.linkers);
  read_entries(doc, "others",    res.others);
  res.raw = std::move(doc);
  res.st  = status::ok;

  LOG_INFO("die: ok in {:.3f}s - packed={}, packers={}, compilers={}, linkers={}, others={}, unknown={}",
           res.seconds, res.packed, res.packers.size(), res.compilers.size(),
           res.linkers.size(), res.others.size(), res.unknown_count);
  return res;
}

}  // namespace die_runner
