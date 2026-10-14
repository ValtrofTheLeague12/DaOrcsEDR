// exporter.hpp

#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

#include <nlohmann/json.hpp>

#include "file_analyzer.hpp"
#include "file_hasher.hpp"
#include "extractor.hpp"
#include "ioc_extractor.hpp"
#include "known_pe_hashes.hpp"
#include "capa_runner.hpp"
#include "die_runner.hpp"
#include "radare2_runner.hpp"
#include "yara_scanner.hpp"
#include "cti.hpp"
#include "ml_api.hpp"

namespace exporter {

using nlohmann::json;

namespace dir {
// Shared root holding one results directory per run. Everything a run
// produces lives inside its own `<root>/<stem>_analysis/` directory, so two
// runs over different samples never share a path (and a re-run over the same
// sample overwrites its own results only).
inline constexpr const char* root = "exports";

// exports/<stem>_analysis
std::filesystem::path run_root(const std::string& stem);

// exports/<stem>_analysis/<category> - created on demand by the writers.
std::filesystem::path run(const std::string& stem,
                          std::string_view category);

// exports/<stem>_analysis/<category>/<stem>_<artifact>.json
std::filesystem::path artifact(const std::string& stem,
                               std::string_view category,
                               std::string_view artifact_name);
} // namespace dir

// ---------------------------------------------------------------------------
// to_json overloads
// ---------------------------------------------------------------------------

json to_json(const analyzer::file_info_t& info);
json to_json(const file_hash_t& sha256, const fuzzy_hash_t& tlsh);
json to_json(const ioc::ioc_results_t& r);
json to_json(const extractor::extraction_result_t& r);
json to_json(const capa::report_t& r);
json to_json(const die_runner::result_t& r);
json to_json(const extractor::iat_result_t& r);
json to_json(const extractor::pe_export_table_t& r);
json to_json(const extractor::hexdump_result_t& r);
json to_json(const extractor::cminer_result_t& r);
json to_json(const yara_scanner::result_t& r);
json to_json(const extractor::got_result_t& r);
json to_json(const r2::bulk_result_t& r);
json to_json(const r2::xref_asm_result_t& r);
json to_json(const ml_api::score_result_t& r);
json to_json(const known_pe::result_t& r);

// ---------------------------------------------------------------------------
// Filename helpers
// ---------------------------------------------------------------------------

std::string artifact_stem(std::string_view stem, std::string_view artifact);

std::string make_stem(const analyzer::file_info_t& info,
                      const file_hash_t& sha256);
std::string sanitize_stem(const std::string& raw);

// ---------------------------------------------------------------------------
// Public writers (each writes one artifact under exports/<stem>_analysis/<dir>/)
// ---------------------------------------------------------------------------

std::filesystem::path write_fileinfo_json(const std::string& stem,
                                          const analyzer::file_info_t& info);

std::filesystem::path write_hash_json(const std::string& stem,
                                      const file_hash_t& sha256,
                                      const fuzzy_hash_t& tlsh);

std::filesystem::path write_ioc_json(const std::string& stem,
                                     const ioc::ioc_results_t& r);

// Extracted strings (offset + value + section) for partial pipelines. The
// full pipeline embeds the same data in the extraction JSON instead, which is
// why this writer is not part of write_all().
std::filesystem::path write_strings_json(const std::string& stem,
                                         const extractor::strings_result_t& r);

// Structured MalAPI lookup hits (function, status, parsed yaml payload) so
// the dashboard can flag malicious imports. `hits` is a pre-built JSON array.
std::filesystem::path write_malapi_json(const std::string& stem,
                                        const json& hits);

std::filesystem::path write_extraction_json(const std::string& stem,
                                            const extractor::extraction_result_t& r);

std::filesystem::path write_capa_json(const std::string& stem,
                                      const capa::report_t& r);

// Detect It Easy scan result (exports/<stem>_analysis/die/<stem>_die.json).
// Written only when the scan succeeded - run_export gates on st == ok - so a
// run without the optional die-python install leaves no placeholder file.
std::filesystem::path write_die_json(const std::string& stem,
                                     const die_runner::result_t& r);

std::filesystem::path write_iat_json(const std::string& stem,
                                     const extractor::iat_result_t& r);

std::filesystem::path write_eat_json(const std::string& stem,
                                     const extractor::pe_export_table_t& r);

std::filesystem::path write_got_json(const std::string& stem,
                                     const extractor::got_result_t& r);

std::filesystem::path write_radare2_json(const std::string& stem,
                                         const r2::bulk_result_t& r);

std::filesystem::path write_xref_asm_json(const std::string& stem,
                                          const r2::xref_asm_result_t& r);

// Non-JSON artifacts (flat .asm text). The .dot files are written directly by
// the r2 runner; this writer exists for callers who want the exporter to own
// the flat disassembly file too.
std::filesystem::path write_asm_text(const std::string& stem,
                                     const std::string& text);

// Raw overlay bytes extracted from a PE. Returns an empty path when the sample
// has no overlay, so callers can treat it as an optional artifact.
std::filesystem::path write_overlay_bin(const std::string& stem,
                                        const extractor::pe_overlay_t& overlay);


// ---------------------------------------------------------------------------
// CTI report writer
// ---------------------------------------------------------------------------

std::filesystem::path write_cti_json(const std::string& stem,
                                     const cti::report& report);

// ---------------------------------------------------------------------------
// EMBER2024 model score writer
//
// Written separately from write_all() because the score is optional: it exists
// only when the scoring service ran, so folding it into write_all() would have
// to invent a "skipped" payload for every run that has no model.
// ---------------------------------------------------------------------------

std::filesystem::path write_ml_json(const std::string& stem,
                                    const ml_api::score_result_t& score);

// ---------------------------------------------------------------------------
// Known-PE roster writer
//
// Written separately from write_all() for the same reason as write_ml_json:
// the roster is optional. A run without data/known_pe_hashes.jsonl has nothing
// to record, and emitting a file that says "matched: false" for every such run
// would be indistinguishable from a genuine "this PE is not in the roster".
// Only a lookup that actually consulted a roster produces a file.
// ---------------------------------------------------------------------------

std::filesystem::path write_known_pe_json(const std::string& stem,
                                          const known_pe::result_t& match);

// ---------------------------------------------------------------------------
// STIX 2.1 writers
// ---------------------------------------------------------------------------

// STIX 2.1 bundle for the report (identity, indicators, malware families, CVEs,
// ATT&CK attack-patterns and the relationships between them). Written as
// <stem>_stix21.json. Returns an empty path if the bundle cannot be produced.
std::filesystem::path write_stix_bundle(const std::string& stem,
                                        const cti::report& report,
                                        const cti::stix_options& options = {});

// ATT&CK Navigator layer (layer format 4.5) covering every technique the run
// observed, written as <stem>_navigator.json. Techniques come from both the
// capa report and the (enriched) CTI report, and EACH technique is mapped to
// ALL of its ATT&CK tactics - not just the one capa happened to report - with
// the matched capa capabilities as the procedure text in the comment. The CTI
// report is also why the layer is complete offline: its per-technique knowledge
// was filled from the local ATT&CK cache. capa alone still drives the score
// (number of matching capabilities), so a CTI-only technique scores the
// baseline 1. Built from capa + report on purpose: capa runs offline, so the
// layer is complete even when no CTI provider answered. Returns an empty path
// when no technique was observed at all.
std::filesystem::path write_navigator_layer(const std::string& stem,
                                            const capa::report_t& capa_report,
                                            const cti::report& report = {},
                                            const std::string& attack_version = "");

// ---------------------------------------------------------------------------
// write_result_t and write_all overloads
// ---------------------------------------------------------------------------

struct write_result_t {
  std::filesystem::path fileinfo;
  std::filesystem::path hash;
  std::filesystem::path ioc;
  std::filesystem::path extraction;
  std::filesystem::path capa;
  std::filesystem::path iat;
  std::filesystem::path eat;
  std::filesystem::path got;
  std::filesystem::path radare2;
  std::filesystem::path iat_calls;
  std::filesystem::path asm_text;
  std::filesystem::path overlay;

  // Number of artifacts write_all() was actually asked to produce for this
  // sample: the 4 mandatory JSON files plus every optional stage that was
  // supplied, plus the overlay dump when the PE actually carries overlay
  // bytes. Populated by write_all() so callers never have to re-derive it
  // from the arguments and drift out of sync (which is how the optional
  // overlay previously went uncounted and turned a healthy run into a
  // spurious "export files failed to write" error).
  std::size_t expected = 0;

  // True when every artifact write_all() promised was written. This is the
  // authoritative completeness check: paths().size() == expected.
  bool complete() const {
    return expected != 0 && paths().size() == expected;
  }

  bool all_ok() const {
    return !fileinfo.empty() && !hash.empty() &&
           !ioc.empty() && !extraction.empty() &&
           !capa.empty() && !iat.empty() && !got.empty() &&
           !radare2.empty() && !iat_calls.empty() && !asm_text.empty();
  }

  bool all_ok_five() const {
    return !fileinfo.empty() && !hash.empty() &&
           !ioc.empty() && !extraction.empty() && !capa.empty();
  }

  bool all_ok_four() const {
    return !fileinfo.empty() && !hash.empty() &&
           !ioc.empty() && !extraction.empty();
  }

  std::vector<std::filesystem::path> paths() const {
    std::vector<std::filesystem::path> out;
    if (!fileinfo.empty())   out.push_back(fileinfo);
    if (!hash.empty())       out.push_back(hash);
    if (!ioc.empty())        out.push_back(ioc);
    if (!extraction.empty()) out.push_back(extraction);
    if (!capa.empty())       out.push_back(capa);
    if (!iat.empty())        out.push_back(iat);
    if (!got.empty())        out.push_back(got);
    if (!radare2.empty())    out.push_back(radare2);
    if (!iat_calls.empty())  out.push_back(iat_calls);
    if (!asm_text.empty())   out.push_back(asm_text);
    if (!overlay.empty())    out.push_back(overlay);
    return out;
  }
};

write_result_t write_all(const std::string& stem,
                         const analyzer::file_info_t& info,
                         const file_hash_t& sha256,
                         const fuzzy_hash_t& tlsh,
                         const ioc::ioc_results_t& iocs,
                         const extractor::extraction_result_t& extraction);

write_result_t write_all(const std::string& stem,
                         const analyzer::file_info_t& info,
                         const file_hash_t& sha256,
                         const fuzzy_hash_t& tlsh,
                         const ioc::ioc_results_t& iocs,
                         const extractor::extraction_result_t& extraction,
                         const capa::report_t& capa_report);

write_result_t write_all(const std::string& stem,
                         const analyzer::file_info_t& info,
                         const file_hash_t& sha256,
                         const fuzzy_hash_t& tlsh,
                         const ioc::ioc_results_t& iocs,
                         const extractor::extraction_result_t& extraction,
                         const capa::report_t& capa_report,
                         const extractor::iat_result_t& iat,
                         const extractor::got_result_t& got);

write_result_t write_all(const std::string& stem,
                         const analyzer::file_info_t& info,
                         const file_hash_t& sha256,
                         const fuzzy_hash_t& tlsh,
                         const ioc::ioc_results_t& iocs,
                         const extractor::extraction_result_t& extraction,
                         const capa::report_t& capa_report,
                         const extractor::iat_result_t& iat,
                         const extractor::got_result_t& got,
                         const r2::bulk_result_t& radare2);

write_result_t write_all(const std::string& stem,
                         const analyzer::file_info_t& info,
                         const file_hash_t& sha256,
                         const fuzzy_hash_t& tlsh,
                         const ioc::ioc_results_t& iocs,
                         const extractor::extraction_result_t& extraction,
                         const capa::report_t& capa_report,
                         const extractor::iat_result_t& iat,
                         const extractor::got_result_t& got,
                         const r2::bulk_result_t& radare2,
                         const r2::xref_asm_result_t& xref_asm);

// Fullest overload: also writes the flat .asm disassembly text artifact.
write_result_t write_all(const std::string& stem,
                         const analyzer::file_info_t& info,
                         const file_hash_t& sha256,
                         const fuzzy_hash_t& tlsh,
                         const ioc::ioc_results_t& iocs,
                         const extractor::extraction_result_t& extraction,
                         const capa::report_t& capa_report,
                         const extractor::iat_result_t& iat,
                         const extractor::got_result_t& got,
                         const r2::bulk_result_t& radare2,
                         const r2::xref_asm_result_t& xref_asm,
                         const std::string& asm_text);

// ---------------------------------------------------------------------------
// Export summaries
//
//   summarize_exports / summarize_export_paths
//     Stat a list of files and try to parse each as JSON. Use this for the
//     JSON artifacts the exporter writes.
//
//   summarize_artifacts
//     Stat a list of non-JSON files (.dot, .asm). Parses nothing, just reports
//     existence, size and mtime. Use this for the files the r2 runner writes
//     directly.
//
//   inspect_file / inspect_artifact
//     Single-file variants used internally by the two summarizers above. Kept
//     public so callers can inspect one file without building a summary.
// ---------------------------------------------------------------------------

struct export_file_info_t {
  std::filesystem::path path;
  std::uintmax_t        size_bytes   = 0;
  std::size_t           record_count = 0;
  std::filesystem::file_time_type last_write{};
  bool                  exists       = false;
  bool                  parse_ok     = false;
  std::string           parse_error;
};

struct export_summary_t {
  std::vector<export_file_info_t> files;
  std::uintmax_t total_bytes   = 0;
  std::size_t    total_records = 0;
  std::size_t    parsed_files  = 0;
  std::size_t    missing_files = 0;
};

export_file_info_t inspect_file(const std::filesystem::path& path);
export_file_info_t inspect_artifact(const std::filesystem::path& path);

export_summary_t summarize_exports(const write_result_t& result);
export_summary_t summarize_export_paths(
    const std::vector<std::filesystem::path>& paths);
export_summary_t summarize_artifacts(
    const std::vector<std::filesystem::path>& paths);

void print_export_summary(const export_summary_t& summary);

} // namespace exporter