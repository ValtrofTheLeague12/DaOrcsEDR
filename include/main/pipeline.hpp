#pragma once

#include <string>
#include <vector>

#include "curses_ui.hpp"
#include "ioc_extractor.hpp"
#include "local_api.hpp"
#include "malapi.hpp"
#include "radare2_runner.hpp"
#include "report.hpp"

namespace pipeline {

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
  curses_ui::session*          curses = nullptr;

  // -------- results produced by one phase, consumed by a later one --------
  file_hash_t                    file_hash{};
  fuzzy_hash_t                   fuzzy_hash{};
  ioc::ioc_results_t             ioc_results{};
  std::vector<malapi_hit_t>      malapi_hits{};
  capa::report_t                 capa_report;
  r2::bulk_result_t              r2_result{};
  r2::xref_asm_result_t          xref_result{};
  extractor::extraction_result_t full{};
  cti::report                    cti_report{};

  // Graphviz / call-site bookkeeping the summary reads back.
  std::string render_format;
  std::size_t rendered_ok        = 0;
  std::size_t rendered_attempted = 0;
  bool        xref_skipped       = false;

  // radare2 options, built once by the radare2 phase and reused by the
  // graphviz and call-site phases that follow it.
  r2::options r2_opts;
  std::string out_dir;
};

// Numbers and prints the next stage that applies: a stage that does not apply
// advances the counter by nothing and prints nothing, so the "[phase n/total]"
// headers only ever advertise work that really happens.
void phase(context& ctx, bool applies, const std::string& label);

// One function per stage, in the order main() calls them.
void run_preamble(context& ctx);          // banner, file info, phase-plan arithmetic
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
void run_xxd(context& ctx);
void run_cminer(context& ctx);
void run_error_recovery(context& ctx);
void run_cti(context& ctx);
void run_export(context& ctx);            // report files + CTI JSON + STIX + MalAPI
void run_dashboard(context& ctx);
void run_sanity(context& ctx);
void run_summary(context& ctx);

}  // namespace pipeline
