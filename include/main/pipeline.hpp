#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "curses_ui.hpp"
#include "extractor.hpp"
#include "ioc_extractor.hpp"
#include "known_pe_hashes.hpp"
#include "local_api.hpp"
#include "malapi.hpp"
#include "ml_api.hpp"
#include "radare2_runner.hpp"
#include "report.hpp"

namespace pipeline {

// Defined in pipeline_planner.hpp; fwd-declared here so context can hold a
// pointer to the active config without forcing every phase TU to include the
// planner header.
namespace planner {
struct pipeline_config;
}

// Everything the pipeline phases read from or write to each other. main() fills
// in the inputs, hands out its own long-lived services, and reads the results
// back out at the end; nothing else crosses a phase boundary.
//
// Phases that keep their working set private (the IAT entry list, the extracted
// strings, the GOT table) deliberately do not appear here - they stay locals of
// the phase function that owns them.
struct context {
  // -------- inputs --------
  std::string path;
  std::string stem;              // exporter::make_stem(); set by the radare2 phase

  // -------- detection --------
  analyzer::file_info_t info;
  file_format fmt = file_format::unknown;
  bool failed   = false;
  bool is_pe    = false;
  bool is_elf   = false;
  bool is_macho = false;

  // -------- phase numbering --------
  int  phase_no     = 0;
  int  total_phases = 0;

  // -------- services owned by main(), outliving every phase --------
  local_api::local_api_server* api    = nullptr;
  // The EMBER2024 scoring service. Null when it was never started or failed to
  // come up, which is the signal run_ml_score() uses to skip its phase instead
  // of reporting a failure - an absent optional model is not an analysis error.
  local_api::local_api_server* ml_api_server = nullptr;
  curses_ui::session*          curses = nullptr;

  // -------- results produced by one phase, consumed by a later one --------
  file_hash_t                    file_hash{};
  fuzzy_hash_t                   fuzzy_hash{};
  // Whether this exact PE is already in the EMBER2024 corpus the model was
  // trained on. Set by run_hashes(), which is the first stage that knows the
  // sample's SHA-256. `attempted` is false for a non-PE sample or when no
  // roster is installed, so callers can tell "not known" from "not checked".
  known_pe::result_t             known_pe_match{};
  ioc::ioc_results_t             ioc_results{};
  std::vector<malapi_hit_t>      malapi_hits{};
  capa::report_t                 capa_report;
  r2::bulk_result_t              r2_result{};
  r2::xref_asm_result_t          xref_result{};
  extractor::extraction_result_t full{};
  cti::report                    cti_report{};
  ml_api::score_result_t         ml_score{};
  // Why the ML phase did not run, empty once it did. run_summary() prints this
  // so an absent model reads as "skipped, and here is why" rather than as a
  // missing section.
  std::string                    ml_skip_reason;

  // Graphviz / call-site bookkeeping the summary reads back.
  std::string render_format;
  std::size_t rendered_ok        = 0;
  std::size_t rendered_attempted = 0;
  bool        xref_skipped       = false;

  // radare2 options, built once by the radare2 phase and reused by the
  // graphviz and call-site phases that follow it.
  r2::options r2_opts;
  std::string out_dir;

  // -------- pipeline plan (set by planner::run_phases) --------
  // The config this run executes; also the gate for "did phase X run?" checks
  // in the summary and the export.
  const planner::pipeline_config* active_plan = nullptr;
  // One bit per planner::phase_id, set after each configured phase returns.
  std::uint64_t ran_mask = 0;

  // -------- phase outputs kept for partial-pipeline export --------
  // The default pipeline re-reads these from ctx.full (produced by
  // run_full_extraction), and each producer releases its copy when extraction
  // is also in the plan. A pipeline without extraction keeps them here so the
  // export can still write the strings/IAT/GOT/EAT artifacts.
  extractor::strings_result_t strings_result{};
  extractor::iat_result_t      iat_result{};
  extractor::got_result_t      got_result{};
  extractor::pe_sections_t     pe_sections_result{};
  // Every artifact path this run wrote - the run_summary.json manifest.
  std::vector<std::string>     exported_artifacts;
};

// Numbers and prints the next stage that applies: a stage that does not apply
// advances the counter by nothing and prints nothing, so the "[phase n/total]"
// headers only ever advertise work that really happens.
void phase(context& ctx, bool applies, const std::string& label);

// One function per stage, in the order main() calls them.
void run_preamble(context& ctx);          // banner, file info, format detection, phase-plan arithmetic
void run_hashes(context& ctx);
void run_sections(context& ctx);          // PE / ELF / Mach-O section table
void run_generic_sections(context& ctx);
void run_strings_and_ioc(context& ctx);
void run_iat_and_malapi(context& ctx);    // PE IAT render + MalAPI lookup
void run_got(context& ctx);               // ELF / Mach-O GOT
void run_byte_histogram(context& ctx);
void run_packer(context& ctx);
void run_opcodes(context& ctx);
void run_debug_symbols(context& ctx);
void run_signature(context& ctx);
void run_capa(context& ctx);
void run_radare2(context& ctx);
void run_graphviz(context& ctx);
void run_xref_asm(context& ctx);
void run_guards(context& ctx);
void run_full_extraction(context& ctx);   // analyze() + export table + YARA
void run_hexdump(context& ctx);
void run_cminer(context& ctx);
void run_error_recovery(context& ctx);
void run_cti(context& ctx);
void run_ml_score(context& ctx);            // EMBER2024 model, via ml/serve.py
void run_export(context& ctx);            // report files + CTI JSON + STIX + MalAPI
void run_dashboard(context& ctx);
void run_sanity(context& ctx);
void run_summary(context& ctx);

}  // namespace pipeline
