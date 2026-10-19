// yara_gen.hpp
//
// YARA rule GENERATION, as opposed to yara_scanner's rule matching.
//
// The two answer opposite questions and it is worth being explicit about which
// is which, because "yara" in a pipeline name means the scan:
//
//   yara      does this sample match a rule that already exists?
//   yara_gen  what rule would have caught it?
//
// The rule packs in yara-rules/ are the past - last year's malware. This phase
// is how the next one gets written, and it is opt-in per pipeline because it is
// slow (tens of seconds to minutes), needs a tool the project does not always
// have built, and is something only an analyst wants on every run.
//
// The analyzer never links yarGen. It spawns python/yara_gen.py, which in turn
// runs yarGen-Go/yargen.exe - the same three-layer shape as die_scan.py and
// ml/serve.py, so there is one place where a missing tool is diagnosed instead
// of three.
//
// The one thing this wrapper exists to guarantee: the script's working
// directory. yarGen resolves its database directory relative to cwd, so run
// from anywhere else it fails with "failed to read database directory ./dbs",
// which reads like a missing download rather than the wrong directory.

#pragma once

#include <chrono>
#include <cstddef>
#include <string>
#include <vector>

namespace yara_gen {

enum class status {
  ok,
  script_missing,     // python/yara_gen.py does not exist
  yargen_missing,     // the yarGen-Go checkout or yargen.exe is absent
  sample_unreadable,  // the input path does not exist
  timed_out,
  output_too_large,
  spawn_failed,
  yargen_failed,      // yargen.exe ran and failed (bad config, no rules, ...)
  no_rules,           // yargen wrote a file containing no `rule` blocks
  bad_output,         // stdout was not the expected JSON document
};

const char* to_string(status st);

struct options {
#ifdef _WIN32
  std::string python = "python/.venv/Scripts/python.exe";
#else
  std::string python = "python3";
#endif
  std::string script = "python/yara_gen.py";
  // yargen copies the sample into a temp dir and scores it; a large sample is
  // genuinely slow, so the default is generous rather than matching the other
  // runners' 120s. Overridable with YARGEN_TIMEOUT.
  std::chrono::seconds timeout{600};
  std::size_t max_stdout_bytes = 16u * 1024u * 1024u;
  std::size_t max_stderr_bytes = 1u * 1024u * 1024u;

  // Written into every generated rule. yarGen's own default is the literal
  // string "yarGen", and a rule set attributed to nobody is one nobody
  // maintains.
  std::string author = "IAProject";
  // Defaults to the sample's stem.
  std::string identifier;
  // Where the generated .yar is written. Empty means "next to the analysis
  // output", which the phase fills in.
  std::string out_path;
};

struct result_t {
  bool attempted = false;   // the wrapper was launched (vs skipped before spawn)
  status st = status::spawn_failed;
  std::string error;        // human-readable when st != ok
  std::string command_line;
  std::string stderr_tail;
  double seconds = 0.0;
  int exit_code = 0;

  // What came back.
  std::string rule_file;
  std::size_t rule_bytes = 0;
  int simple_rules = 0;
  int super_rules = 0;
  std::string identifier;
  std::string author;
  // False when the LLM pass was skipped. That is a documented downgrade, not a
  // failure - the rules are still real.
  bool llm_used = false;
  // Why it was skipped, e.g. "OPENAI_API_KEY is not set". Reported instead of a
  // fixed string, because "no config.yaml" stopped being true the moment the
  // config existed, and a message that is confidently wrong is worse than none.
  std::string llm_reason;
  int db_files = 0;
  std::vector<std::string> hints;   // numbered fix steps yargen printed
};

// Runs python/yara_gen.py over `sample` and returns the parsed result.
result_t generate(const std::string& sample, options opts);

}  // namespace yara_gen