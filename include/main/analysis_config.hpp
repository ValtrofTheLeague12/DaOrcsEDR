#pragma once

// Global analysis settings - config/analysis.yaml.
//
// Every other knob in this project is either per-pipeline (the `environment:`
// block in pipelines/*.yaml) or a credential (.env). These are the settings that
// describe the *analysis itself* and are meant to apply to every run: whether
// the ML phase runs, where the CTI phase looks things up, what a crash leaves
// behind.
//
// Why a file rather than more pipeline `environment:` blocks:
//
//   Per-pipeline settings make the answer to "is CTI running?" depend on which
//   pipeline was selected, which is a question nobody can answer without
//   remembering the contents of thirteen files. And a pipeline that hardcodes a
//   value cannot be overridden by the operator's shell at all - pipelines/
//   default.yaml shipped ML_SKIP and CTI_SKIP pinned to 1, so those settings
//   were set by nobody, in a place designed for per-run differences, and were
//   unreachable from anywhere else.
//
// Precedence, deliberately inverted from the usual:
//
//     .env / shell  <  pipeline `environment:`  <  config/analysis.yaml
//
// Global last, so an operator's standing choice wins over anything a pipeline
// or a shell happens to say. A pipeline can still set a key this file does not
// mention - that is how a one-off run turns CTI on for an investigation and off
// again afterwards - but it cannot override a key this file does mention.
//
// That is the whole reason this file exists. The alternative, global first, is
// what the pipeline block already was, and it is why the pinned defaults went
// unnoticed.

#include <filesystem>
#include <string>
#include <utility>
#include <vector>

namespace pipeline {

struct analysis_settings {
  // Ordered key/value pairs, exactly as written. An empty `value` means the
  // setting is deliberately absent, which is different from the key being
  // missing: it is how a global default is turned off without editing this
  // header's idea of the default.
  std::vector<std::pair<std::string, std::string>> settings;

  // Where they came from, for the run banner and run_summary.json. Empty when
  // there is no config file, which is the normal case for a source checkout.
  std::string source;
};

// Every key this build understands, in the order the panel lists them.
//
// This is the analyzer's own list, not the panel's: the panel offers what the
// binary reads, and unit/python/test_panel_env_options.py fails if the two
// disagree, by checking that every panel key appears somewhere under src/.
//
// A key in the file that is not here is a hard error rather than a warning.
// Silently ignoring it would leave an operator who mistyped `ML_SKP` believing
// they had skipped the model.
const std::vector<std::string>& known_analysis_keys();

// config/analysis.yaml, searched next to the executable and in the working
// directory, mirroring how config/artifacts.yaml is found. A missing file is
// not an error: it yields empty settings, which is the same as no file.
// Throws std::runtime_error with a user-facing message on a malformed file or
// an unknown key.
analysis_settings load_analysis_settings();

// Put the settings into the process environment, both the OS block (so child
// processes - the MalAPI and ML services - see them) and the CRT copy (so
// getenv() sees them). Called AFTER the pipeline's apply_environment(), which is
// what makes this file win.
void apply_analysis_settings(const analysis_settings& settings);

}  // namespace pipeline