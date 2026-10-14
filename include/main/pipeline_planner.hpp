#pragma once

// ---------------------------------------------------------------------------
// Pipeline planner
//
// Decides *which* analysis phases run and *in what order*. main() no longer
// hardcodes the 27 run_* calls: it loads a pipeline config (YAML or JSON,
// Jenkins-style stages or a flat phase list) and hands it to run_phases().
//
//   static_analyzer.exe sample.exe                       # built-in default
//   static_analyzer.exe --pipeline pipelines/quick.yaml sample.exe
//   static_analyzer.exe --pipeline extract_strings sample.exe   # bare name:
//     resolved against ./pipelines and <exe dir>/pipelines
//   static_analyzer.exe --pipeline '["strings","model"]' sample.exe
//   static_analyzer.exe --list-phases [--json]
//   static_analyzer.exe --list-pipelines
//
// Config shapes (YAML shown; JSON is the same structure):
//
//   name: quick
//   stages:                        # optional; stages run in order
//     - name: triage
//       phases: [sections, strings, iat]
//   phases: [...]                  # or a flat list (no stages)
//   environment:                   # optional; exported to the process env
//     ML_THRESHOLD: "0.6"
//
// Two phases are appended when a config omits them: `export` (so the run
// writes its artifacts even for a two-phase pipeline) and `summary` (the
// closing report). Prerequisites (e.g. `extraction` for `hexdump`) are
// inserted the same way, so a config can never select a phase whose inputs
// were never computed.

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace pipeline {

struct context;

namespace planner {

// One entry per selectable phase. The order of the enumerators is the order
// of the built-in default pipeline; YAML/JSON configs use the string names
// from phase_info, never the enum values.
enum class phase_id : std::uint8_t {
  compression = 0,
  sections,
  generic_sections,
  strings,
  iat,
  got,
  histogram,
  packer,
  die,
  opcodes,
  debug,
  signature,
  capa,
  radare2,
  graphs,
  xref,
  guards,
  extraction,
  hexdump,
  cminer,
  recovery,
  cti,
  model,
  report_export,  // YAML name is "export" (a keyword in C++)
  dashboard,
  sanity,
  summary,
  count
};

constexpr int kPhaseCount = static_cast<int>(phase_id::count);
using mask_t = std::uint64_t;
static_assert(kPhaseCount <= 63, "phase_id must fit a 64-bit ran-mask");

constexpr mask_t bit(phase_id p) {
  return mask_t{1} << static_cast<unsigned>(p);
}

struct phase_info {
  phase_id id;
  const char* name;         // canonical name in YAML/JSON configs and --pipeline
  const char* description;
  const char* artifact;     // where its output lands ("" = console only)
  const char* service;      // local service it uses ("" = none)
  std::vector<phase_id> requires_phases;  // auto-inserted when missing
};

struct artifact_options {
  bool store_artifact = false;
  bool upload_artifacts = false;
  std::string remote_root = "/";
  int timeout_seconds = 900;
  std::string source;
  std::string uploader_script;
};

struct pipeline_config {
  std::string name = "default";
  std::string description;
  std::string source = "builtin:default";  // file path, "inline", or builtin
  std::vector<phase_id> phases;            // final ordered set (deduped, closed
                                           // under prerequisites, epilogue added)
  std::vector<std::string> inserted;       // names auto-inserted into `phases`
  // Stages exactly as written (informational; execution follows `phases`).
  std::vector<std::pair<std::string, std::vector<phase_id>>> stages;
  std::vector<std::pair<std::string, std::string>> environment;
  artifact_options artifacts;
  bool full = false;  // contains the complete default phase set
};

// The catalog every reader, error message, and --list-phases renders from.
const std::vector<phase_info>& catalog();

// Case-insensitive, alias-aware ("ml" -> model, "eat" -> sections, ...).
// "preamble" and "hashes" resolve to false: they always run and are not
// selectable. Returns false (and leaves out untouched) for unknown names.
bool from_name(const std::string& name, phase_id& out);
std::string to_name(phase_id p);

bool has(const pipeline_config& cfg, phase_id p);
bool has(const context& ctx, phase_id p);  // via ctx.active_plan

// The classic 27-phase order, built into the binary.
pipeline_config parse_default();

// spec: a file path (.yaml/.yml/.json), a bare pipeline name resolved
// against ./pipelines and <exe dir>/pipelines (e.g. "extract_strings"),
// an inline JSON array/object, or "default".
// Throws std::runtime_error with a user-facing message.
pipeline_config load(const std::string& spec);

// Load config/artifacts.yaml from the working directory or beside the
// executable. A missing file uses safe defaults (no archive or cloud upload).
artifact_options load_artifact_options();

// Export cfg.environment into the process environment (both the OS block, so
// children see it, and the CRT copy, so getenv() sees it).
void apply_environment(const pipeline_config& cfg);

std::string catalog_json();
void print_catalog(bool as_json);

// Named pipeline configs: the built-in default plus every loadable file in
// the pipelines/ directories, with name, description and source.
void print_pipelines();

// How many "[phase n/total]" headers the config will print for this file
// (format-gated phases and the ML service gate are applied). Mirrors the
// phase() calls inside the run_* functions.
int header_count(const pipeline_config& cfg, const context& ctx);

// Prologue (preamble + hashes) + every config phase in order. Sets
// ctx.active_plan and ctx.ran_mask.
void run_phases(context& ctx, const pipeline_config& cfg);

// exports/<stem>_analysis/run_summary.json - the machine-readable manifest
// the API layer reads back: requested/ran phases, artifacts, result.
// Never throws; a write failure is logged, not fatal.
void write_run_summary(const context& ctx, const pipeline_config& cfg,
                       int exit_code, long long duration_ms);

}  // namespace planner
}  // namespace pipeline
