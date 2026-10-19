// die_runner.hpp
//
// Detect It Easy scan via the die-python bindings. The analyzer never links
// the bindings itself: it spawns python/die_scan.py in --json machine mode
// (proc::run, timeout, output caps) and parses the one JSON document the
// script prints on stdout - the same shape as the capa / visualizer runners.

#pragma once

#include <chrono>
#include <cstddef>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace die_runner {

enum class status {
  ok,
  script_missing,      // options.script does not exist
  not_installed,       // python could not import die (pip install die-python)
  launch_failed,
  timed_out,
  output_too_large,
  exit_error,
  bad_output,          // stdout was not the expected JSON document
};

const char* to_string(status st);

struct options {
#ifdef _WIN32
  std::string python = "python/.venv/Scripts/python.exe";
#else
  std::string python = "python3";
#endif
  std::string script = "python/die_scan.py";

  std::chrono::seconds timeout{120};
  std::size_t max_stdout_bytes = 16u * 1024u * 1024u;
  std::size_t max_stderr_bytes = 1u * 1024u * 1024u;

  bool deep = false;   // pass --deep (DEEP_SCAN; slower, more complete)
};

// One classified detection value, mirrored from die_scan.py's normalized doc.
struct entry_t {
  std::string name;
  std::string version;
  std::string type;     // "Packer", "Compiler", "Linker", ...
  std::string info;
  std::string string;
};

struct result_t {
  bool attempted = false;   // the scan was launched (vs skipped before spawn)
  status st = status::launch_failed;
  std::string error;        // human-readable when st != ok
  std::string command_line;
  std::string stderr_tail;
  double seconds = 0.0;     // wall time of the subprocess
  int exit_code = 0;

  bool packed = false;
  bool unknown_only = false;   // every value came back Unknown
  std::size_t unknown_count = 0;
  std::size_t databases = 0;   // signature database paths reported
  std::string die_version;
  std::vector<entry_t> packers;
  std::vector<entry_t> compilers;
  std::vector<entry_t> linkers;
  std::vector<entry_t> others;

  // The full normalized document as die_scan.py emitted it; this is exactly
  // what write_die_json() dumps, so the artifact is the script's contract.
  nlohmann::json raw = nlohmann::json::object();
};

// Spawns "python die_scan.py --json [--deep] <sample>" and classifies the
// result. Never throws; every failure lands in result_t::st / ::error.
result_t scan_file(const std::string& sample, const options& opts);

}  // namespace die_runner
