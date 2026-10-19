// yara_gen.cpp
//
// Spawns python/yara_gen.py and parses the single JSON document it prints.
//
// Deliberately the same shape as die_runner.cpp: pre-flight, proc::run with a
// timeout and output caps, then a strict parse. Nothing here knows how rule
// generation works - it only knows how to ask and how to read the answer, so
// there is exactly one place to fix when yarGen's CLI changes.

#include "yara_gen.hpp"

#include <algorithm>
#include <filesystem>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "logging.hpp"
#include "process_runner.hpp"

namespace yara_gen {

namespace {

std::string tail_of(const std::string& text, std::size_t max) {
  if (text.size() <= max) return text;
  return text.substr(text.size() - max);
}

std::string join_command(const std::string& exe,
                         const std::vector<std::string>& args) {
  std::string line = exe;
  for (const auto& a : args) {
    line += ' ';
    line += (a.find_first_of(" \t\"") != std::string::npos) ? '"' + a + '"' : a;
  }
  return line;
}

std::vector<std::string> json_strings(const nlohmann::json& doc,
                                      const char* key) {
  std::vector<std::string> out;
  if (!doc.contains(key) || !doc[key].is_array()) return out;
  for (const auto& v : doc[key]) {
    if (v.is_string()) out.push_back(v.get<std::string>());
  }
  return out;
}

}  // namespace

const char* to_string(status st) {
  switch (st) {
    case status::ok:              return "ok";
    case status::script_missing:  return "script missing";
    case status::yargen_missing:  return "yarGen-Go not installed";
    case status::sample_unreadable: return "sample unreadable";
    case status::timed_out:       return "timed out";
    case status::output_too_large: return "output too large";
    case status::spawn_failed:    return "launch failed";
    case status::yargen_failed:   return "yarGen failed";
    case status::no_rules:        return "no rules produced";
    case status::bad_output:      return "unparseable output";
  }
  return "unknown";
}

result_t generate(const std::string& sample, options opts) {
  using clock_type = std::chrono::steady_clock;
  result_t res;

  // Relative to the working directory, like every other runner's script
  // option. The analyzer runs from the repo root, which is where these live.
  if (!std::filesystem::exists(std::filesystem::path(opts.script))) {
    res.st = status::script_missing;
    res.error = opts.script + " does not exist";
    LOG_ERROR("yara_gen: {}", res.error);
    return res;
  }

  std::error_code ec;
  if (!std::filesystem::exists(sample, ec)) {
    res.st = status::sample_unreadable;
    res.error = "sample not found: " + sample;
    LOG_ERROR("yara_gen: {}", res.error);
    return res;
  }

  std::vector<std::string> args{
      opts.script, "--json", sample, "--out", opts.out_path,
      "--author", opts.author};
  if (!opts.identifier.empty()) {
    args.push_back("--identifier");
    args.push_back(opts.identifier);
  }
  args.push_back("--timeout");
  args.push_back(std::to_string(opts.timeout.count()));

  res.command_line = join_command(opts.python, args);
  LOG_INFO("yara_gen: run: {}", res.command_line);

  proc::run_options ro;
  ro.timeout          = std::chrono::duration_cast<std::chrono::milliseconds>(opts.timeout);
  ro.max_stdout_bytes = opts.max_stdout_bytes;
  ro.max_stderr_bytes = opts.max_stderr_bytes;

  const auto started = clock_type::now();
  const proc::run_result r = proc::run(opts.python, args, ro);
  res.exit_code   = r.exit_code;
  res.seconds     = std::chrono::duration<double>(clock_type::now() - started).count();
  res.stderr_tail = tail_of(r.std_err, 4096);

  switch (r.status) {
    case proc::launch_status::ok:
      break;
    case proc::launch_status::not_found:
      res.st = status::spawn_failed;
      res.error = "python interpreter not found: '" + opts.python + "'";
      LOG_ERROR("yara_gen: {}", res.error);
      return res;
    case proc::launch_status::timed_out:
      res.st = status::timed_out;
      res.error = "rule generation timed out after " +
                  std::to_string(opts.timeout.count()) + "s";
      LOG_ERROR("yara_gen: {}", res.error);
      return res;
    case proc::launch_status::output_too_large:
      res.st = status::output_too_large;
      res.error = "output exceeded " + std::to_string(opts.max_stdout_bytes) + " bytes";
      LOG_ERROR("yara_gen: {}", res.error);
      return res;
    default:
      res.st = status::spawn_failed;
      res.error = "cannot launch yara_gen: " +
                  (r.error.empty() ? proc::to_string(r.status) : r.error);
      LOG_ERROR("yara_gen: {}", res.error);
      return res;
  }

  res.attempted = true;

  // The script prints one JSON document on stdout even when it fails, so the
  // parse comes first and the exit code second. Trusting the exit code alone
  // would throw away the reason - which is the only useful part of a failure.
  nlohmann::json doc;
  try {
    doc = nlohmann::json::parse(r.std_out);
  } catch (const std::exception& e) {
    res.st = status::bad_output;
    res.error = std::string("could not parse the wrapper's output: ") + e.what();
    res.error += " (stdout tail: " + tail_of(r.std_out, 200) + ")";
    LOG_ERROR("yara_gen: {}", res.error);
    return res;
  }

  res.hints    = json_strings(doc, "hints");
  res.rule_file = doc.value("rule_file", std::string{});
  res.identifier = doc.value("identifier", opts.identifier);
  res.author     = doc.value("author", opts.author);
  res.llm_used    = doc.value("llm_used", false);
  res.llm_reason = doc.value("llm_reason", std::string{});
  res.db_files    = doc.value("db_files", 0);
  res.rule_bytes  = static_cast<std::size_t>(doc.value("rule_bytes", 0));
  res.simple_rules = doc.value("simple_rules", 0);
  res.super_rules  = doc.value("super_rules", 0);

  const std::string status_name = doc.value("status", std::string{"yargen_failed"});
  if (doc.value("ok", false)) {
    res.st = status::ok;
    return res;
  }

  const std::string message = doc.value("message", std::string{"yarGen failed"});
  if (status_name == "yargen_missing")   res.st = status::yargen_missing;
  else if (status_name == "sample_unreadable") res.st = status::sample_unreadable;
  else if (status_name == "timeout")      res.st = status::timed_out;
  else if (status_name == "no_rules")     res.st = status::no_rules;
  else                                    res.st = status::yargen_failed;
  res.error = message;
  LOG_ERROR("yara_gen: {}", message);
  return res;
}

}  // namespace yara_gen