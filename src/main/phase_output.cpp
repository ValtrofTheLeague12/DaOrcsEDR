#include "pipeline.hpp"

#include <iomanip>
#include <ios>
#include <set>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

#include "console.hpp"
#include "exporter.hpp"
#include "graphviz_parser.hpp"
#include "logging.hpp"
#include "pipeline_planner.hpp"
#include "visualizer.hpp"

namespace pipeline {

namespace {

// ===========================================================================
// ATT&CK artifacts
// ---------------------------------------------------------------------------
// These four helpers exist so run_export() reads as a short sequence of steps
// instead of one deeply nested block. All of them work from the local ATT&CK
// cache, which is why none is gated on the CTI phase having reached a provider -
// an offline scan (or CTI_SKIP=1) still gets a full STIX bundle, Navigator
// layer and tactic view.
// ===========================================================================

// Techniques normally reach the report through cti::collect_from_extraction()
// inside the network-gated CTI phase, so on an offline run the report holds
// none. Seed every capa technique that is missing, deduplicated by upper-case
// id, so both artifacts exist regardless of the network.
void seed_capa_techniques(const capa::report_t& capa_report, cti::report& report) {
  std::set<std::string> present;
  for (const cti::enrichment& item : report.items)
    if (item.art.type == cti::artifact_type::technique)
      present.insert(cti::to_upper(item.art.value));

  for (const std::string& raw_id : capa::attack_ids(capa_report)) {
    const std::string id = cti::to_upper(raw_id);
    if (id.empty() || !present.insert(id).second) continue;
    cti::enrichment item;
    item.art.type = cti::artifact_type::technique;
    item.art.value = id;
    item.art.sources.insert("capa");
    report.items.push_back(std::move(item));
  }
}

// Fill ATT&CK detail (name, url, tactics, platforms, description) from the
// local knowledge cache for every technique in the report. Only keys that are
// absent are written, so anything the online mitre_attack provider already
// resolved wins. A missing cache fills nothing - never an error.
void enrich_techniques_from_cache(cti::report& report) {
  std::set<std::string> wanted;
  for (const cti::enrichment& item : report.items)
    if (item.art.type == cti::artifact_type::technique)
      wanted.insert(cti::to_upper(item.art.value));
  if (wanted.empty()) return;

  const auto details = cti::attack_details_for(wanted);
  if (details.empty()) return;

  std::size_t enriched = 0;
  for (cti::enrichment& item : report.items) {
    if (item.art.type != cti::artifact_type::technique) continue;
    const auto it = details.find(cti::to_upper(item.art.value));
    if (it == details.end()) continue;
    const cti::attack_detail& d = it->second;
    nlohmann::json& knowledge = item.knowledge["mitre_attack"];
    if (!knowledge.is_object()) knowledge = nlohmann::json::object();
    const auto fill = [&knowledge](const char* key, const nlohmann::json& value) {
      if (!knowledge.contains(key)) knowledge[key] = value;
    };
    if (!d.name.empty())               fill("name", d.name);
    if (!d.url.empty())                fill("url", d.url);
    if (!d.tactic_shortnames.empty())  fill("tactic_shortnames", d.tactic_shortnames);
    if (!d.platforms.empty())          fill("platforms", d.platforms);
    if (!d.description.empty())        fill("description", d.description);
    if (!d.detection.empty())          fill("detection", d.detection);
    fill("subtechnique", d.is_subtechnique);
    ++enriched;
  }
  LOG_DEBUG("export: ATT&CK detail for {} technique(s) read from the knowledge cache", enriched);
}

// Build the tactic view (the "Procedures & Tooling" dashboard section): every
// observed technique grouped under its tactics, with tooling, groups,
// sub-techniques and detection guidance attached. Built here rather than reused
// from the CTI phase's correlation because that correlation is empty when no
// provider answered, while ATT&CK knowledge itself comes from the local cache
// and is always available. The result is copied onto ctx.cti_report so the CTI
// JSON written below carries it.
void build_tactic_view(context& ctx, cti::report& report) {
  std::vector<std::string> ids;
  for (const cti::enrichment& item : report.items)
    if (item.art.type == cti::artifact_type::technique && !item.skipped)
      ids.push_back(item.art.value);

  const cti::attack_db& db = cti::shared_attack_db();
  if (!db.loaded()) {
    LOG_WARN("export: ATT&CK knowledge cache unavailable; tactic view will be empty");
    return;
  }

  report.attack_matrix = cti::build_attack_matrix(db, ids, cti::capa_hit_counts(ctx.capa_report));
  report.likely_groups = cti::build_likely_groups(db, ids);
  if (report.likely_groups.size() > 8) report.likely_groups.resize(8);

  // Copy, do not move: write_attack_artifacts() below still hands `report` to
  // the STIX writer, and moving it left the bundle with bare attack-patterns and
  // no relationships - the "empty object graph" symptom. A few KB of ids and
  // names per run is not worth that silent data loss. Skipped when empty so a
  // matrix the CTI phase already computed is not wiped by an empty rebuild.
  if (!report.attack_matrix.empty()) {
    ctx.cti_report.attack_matrix = report.attack_matrix;
    ctx.cti_report.likely_groups = report.likely_groups;
  }

  std::size_t procedures = 0;
  for (const cti::tactic_coverage& t : report.attack_matrix) procedures += t.procedures.size();
  LOG_DEBUG("export: ATT&CK tactic view: {} tactic(s), {} procedure(s)",
            report.attack_matrix.size(), procedures);
}

// Write the three artifacts that carry the ATT&CK view:
//   exports/<stem>_analysis/stix/<stem>_stix21.json    STIX 2.1 bundle
//   exports/<stem>_analysis/stix/<stem>_navigator.json ATT&CK Navigator layer (4.5)
//   exports/<stem>_analysis/cti/<stem>_cti.json        CTI report, incl. the tactic view
// The CTI report is written from ctx.cti_report (the CTI phase's own report plus
// the tactic view built above), not from `report`, which holds the seeded copy.
void write_attack_artifacts(context& ctx, const cti::report& report) {
  cti::stix_options stix_opts;
  stix_opts.producer = "static_analyzer";
  const auto stix_path = exporter::write_stix_bundle(ctx.stem, report, stix_opts);
  if (!stix_path.empty()) {
    console::success("STIX bundle written to " + stix_path.string());
    ctx.exported_artifacts.push_back(stix_path.string());
  }

  const auto nav_path =
      exporter::write_navigator_layer(ctx.stem, ctx.capa_report, report, report.attack_version);
  if (!nav_path.empty()) {
    console::success("ATT&CK Navigator layer written to " + nav_path.string());
    ctx.exported_artifacts.push_back(nav_path.string());
  }

  const auto cti_path = exporter::write_cti_json(ctx.stem, ctx.cti_report);
  if (cti_path.empty()) return;
  console::success("CTI report written to " + cti_path.string());
  ctx.exported_artifacts.push_back(cti_path.string());

  if (ctx.cti_report.attack_matrix.empty()) return;
  std::size_t procedures = 0;
  for (const cti::tactic_coverage& t : ctx.cti_report.attack_matrix)
    procedures += t.procedures.size();
  console::success("ATT&CK tactics: " + std::to_string(ctx.cti_report.attack_matrix.size()) +
                   " tactic(s), " + std::to_string(procedures) + " procedure(s) with tooling");
}

// ---------------------------------------------------------------------------
// Selected export (partial pipelines)
// ---------------------------------------------------------------------------
// Writes the same artifact names as the full write_all() path, but only the
// artifacts the configured phases can actually back: a ["strings"] run gets
// strings + ioc (plus the fileinfo/hash identity files), never an empty
// extraction JSON. The full pipeline keeps write_all() - unchanged behavior,
// same expected-artifact accounting as before.
void export_selected(context& ctx) {
  namespace ex = exporter;
  std::vector<std::filesystem::path> written;
  std::size_t attempted = 0;
  auto add = [&](std::filesystem::path p) {
    ++attempted;
    if (!p.empty()) written.push_back(std::move(p));
  };

  // Identity files always: the manifest keys off them and every pipeline
  // has ctx.info + hashes by the time export runs.
  add(ex::write_fileinfo_json(ctx.stem, ctx.info));
  add(ex::write_hash_json(ctx.stem, ctx.file_hash, ctx.fuzzy_hash));

  if (planner::has(ctx, planner::phase_id::strings)) {
    add(ex::write_ioc_json(ctx.stem, ctx.ioc_results));
    add(ex::write_strings_json(ctx.stem, ctx.strings_result));
  }
  if (planner::has(ctx, planner::phase_id::extraction)) {
    add(ex::write_extraction_json(ctx.stem, ctx.full));
  }
  if (planner::has(ctx, planner::phase_id::capa)) {
    add(ex::write_capa_json(ctx.stem, ctx.capa_report));
  }
  if (planner::has(ctx, planner::phase_id::iat)) {
    const extractor::iat_result_t& src =
        ctx.full.pe.iat.entries.empty() ? ctx.iat_result : ctx.full.pe.iat;
    if (!src.entries.empty()) add(ex::write_iat_json(ctx.stem, src));
  }
  if (planner::has(ctx, planner::phase_id::got)) {
    const extractor::got_result_t& src =
        !ctx.full.elf.got.entries.empty() ? ctx.full.elf.got
        : (!ctx.full.got.entries.empty() ? ctx.full.got : ctx.got_result);
    if (!src.entries.empty()) add(ex::write_got_json(ctx.stem, src));
  }
  if (planner::has(ctx, planner::phase_id::extraction) ||
      planner::has(ctx, planner::phase_id::sections)) {
    const extractor::pe_export_table_t* eat = nullptr;
    if (ctx.full.pe.export_table.present) {
      eat = &ctx.full.pe.export_table;
    } else if (ctx.pe_sections_result.export_table.present) {
      eat = &ctx.pe_sections_result.export_table;
    }
    if (eat != nullptr) add(ex::write_eat_json(ctx.stem, *eat));
  }
  if (planner::has(ctx, planner::phase_id::radare2)) {
    add(ex::write_radare2_json(ctx.stem, ctx.r2_result));
  }
  if (planner::has(ctx, planner::phase_id::xref) && !ctx.xref_skipped) {
    add(ex::write_xref_asm_json(ctx.stem, ctx.xref_result));
  }

  for (const auto& p : written) ctx.exported_artifacts.push_back(p.string());

  if (attempted != 0 && written.size() == attempted) {
    console::success("exported " + std::to_string(written.size()) +
                     " report files under " + ex::dir::run_root(ctx.stem).string() + "/");
    for (const auto& p : written) print_bullet(p.string(), console::green);
  } else {
    console::error("some export files failed to write (expected " +
                   std::to_string(attempted) + ", got " +
                   std::to_string(written.size()) + ")");
    for (const auto& p : written) print_bullet(p.string());
  }
}

}  // namespace

// ---------------------------------------------------------------------------
// Phase 21: export, plus the structured side-artifacts the dashboard reads
// ---------------------------------------------------------------------------
void run_export(context& ctx) {
  phase(ctx, true, "export");
  {
    const auto started = report_clock::now();

    if (ctx.active_plan != nullptr && ctx.active_plan->full) {
      // Full pipeline: the classic write_all() path, byte-for-byte the same
      // artifact set as before the planner existed.
      const extractor::iat_result_t& iat = ctx.full.pe.iat;
      const extractor::got_result_t& got =
          ctx.full.elf.got.entries.empty() ? ctx.full.got : ctx.full.elf.got;

      const auto paths = exporter::write_all(
          ctx.stem, ctx.info, ctx.file_hash, ctx.fuzzy_hash, ctx.ioc_results, ctx.full,
          ctx.capa_report, iat, got, ctx.r2_result);

      // write_all() reports exactly how many artifacts it promised to produce
      // (the 4 mandatory files + every supplied stage + the overlay dump when
      // the PE actually carries one). Do not recompute it here: the hand-rolled
      // version forgot the conditional overlay, so any PE with overlay bytes
      // reported a false "export files failed to write" error.
      const std::size_t expected_artifacts = paths.expected;

      if (paths.complete()) {
        console::success("exported " + std::to_string(expected_artifacts) +
                         " report files under " +
                         exporter::dir::run_root(ctx.stem).string() + "/");
        for (const auto& p : paths.paths()) print_bullet(p.string(), console::green);
      } else {
        console::error("some export files failed to write (expected " +
                       std::to_string(expected_artifacts) + ", got " +
                       std::to_string(paths.paths().size()) + ")");
        for (const auto& p : paths.paths()) print_bullet(p.string());
      }

      for (const auto& p : paths.paths()) ctx.exported_artifacts.push_back(p.string());

      const auto summary = exporter::summarize_exports(paths);
      exporter::print_export_summary(summary);
    } else {
      // Partial pipeline: only the artifacts the configured phases produced.
      export_selected(ctx);
    }
    print_duration(elapsed_ms(started));
  }

  // ---------- ML model score export ----------
  // Only when the phase actually ran: with no model there is no score, and a
  // file recording "ok: false" for every sample that happens to lack a service
  // would be noise dressed up as data. The has() gate also covers a pipeline
  // that never selected the model phase at all (skip reason stays empty there).
  if (planner::has(ctx, planner::phase_id::model) && ctx.ml_skip_reason.empty()) {
    const auto ml_path = exporter::write_ml_json(ctx.stem, ctx.ml_score);
    if (!ml_path.empty()) {
      console::success("ML score written to " + ml_path.string());
      ctx.exported_artifacts.push_back(ml_path.string());
    }
  }

  // ---------- Detect It Easy export ----------
  // Same policy as the ML score: only a scan that actually ran (and succeeded)
  // is worth recording. A skipped phase (die module not installed) or a failed
  // scan leaves no artifact rather than a file full of "ok: false".
  if (planner::has(ctx, planner::phase_id::die) &&
      ctx.die_result.st == die_runner::status::ok) {
    const auto die_path = exporter::write_die_json(ctx.stem, ctx.die_result);
    if (!die_path.empty()) {
      console::success("Detect It Easy result written to " + die_path.string());
      ctx.exported_artifacts.push_back(die_path.string());
    }
  }

  // ---------- known-PE roster export ----------
  // Same reasoning as the ML score: only a lookup that consulted a roster is
  // worth recording. write_known_pe_json() enforces that, so the check here is
  // just about telling the user where the answer landed.
  // Plan-gated as well: the roster exists to contextualise the ML score, so a
  // pipeline that did not select the model phase gets no roster artifact. The
  // default pipeline always contains model, so its behaviour is unchanged.
  if (ctx.known_pe_match.available &&
      (ctx.active_plan == nullptr ||
       planner::has(ctx, planner::phase_id::model))) {
    const auto kp_path = exporter::write_known_pe_json(ctx.stem, ctx.known_pe_match);
    if (!kp_path.empty()) {
      console::success(ctx.known_pe_match.matched
                           ? "Known PE match written to " + kp_path.string()
                           : "Known PE roster result written to " + kp_path.string());
      ctx.exported_artifacts.push_back(kp_path.string());
    }
  }

  // ---------- STIX 2.1 bundle + Navigator layer + CTI report ----------
  // Deliberately not gated on the CTI phase having produced anything: the capa
  // technique ids are known from the local capa run alone and they are the point
  // of all three artifacts. An offline scan (or CTI_SKIP=1, where the CTI phase
  // never touches a provider) must still emit them.
  //
  // The four steps are the helpers at the top of this file. `attack_report` is a
  // working copy of the CTI phase's report; ctx.cti_report only ever receives the
  // tactic view back, so the CTI phase's own artifact list stays as it was.
  //
  // Plan-gated too: a pipeline that selected neither cti nor capa owes the user
  // no ATT&CK artifacts at all (a [strings] run exports strings, not STIX). The
  // default pipeline selects both, so its behaviour is unchanged.
  if (ctx.active_plan == nullptr ||
      planner::has(ctx, planner::phase_id::cti) ||
      planner::has(ctx, planner::phase_id::capa)) {
    cti::report attack_report = ctx.cti_report;
    seed_capa_techniques(ctx.capa_report, attack_report);

    enrich_techniques_from_cache(attack_report);

    build_tactic_view(ctx, attack_report);

    // The bundle and layer need techniques to describe, so they share this guard.
    // When there are none, build_tactic_view() produced nothing either - the two
    // are driven by the same seeded technique set.
    if (attack_report.items.empty()) {
      LOG_DEBUG("export: no techniques observed; skipping STIX bundle and Navigator layer");
    } else {
      write_attack_artifacts(ctx, attack_report);
    }
  }

  // Structured MalAPI hits for the dashboard (exports/<stem>_analysis/malapi/...).
  // Plan-gated: only an iat run can have produced hits, and a pipeline that
  // never asked for the iat phase must never write the artifact either.
    if (planner::has(ctx, planner::phase_id::iat) && !ctx.malapi_hits.empty()) {
      nlohmann::json marr = nlohmann::json::array();
      for (const auto& h : ctx.malapi_hits) {
        nlohmann::json mh = {
            {"function",       h.function},
            {"status",         h.status},
            {"dll",            h.dll},
            {"hint",           h.hint},
            {"ordinal",        h.ordinal},
            {"is_ordinal",     h.is_ordinal},
            {"is_delay",       h.is_delay},
            {"iat_rva",        h.iat_rva},
            {"sites_resolved", h.sites_resolved},
            {"call_sites",     nlohmann::json::array()},
        };
        for (const auto& site : h.call_sites) {
          mh["call_sites"].push_back({{"function",         site.function},
                                      {"function_offset",  site.function_offset},
                                      {"address",          site.address}});
        }
        try {
          mh["data"] = nlohmann::json::parse(h.raw_json);
        } catch (const std::exception&) {
          mh["raw"] = h.raw_json;
        }
        marr.push_back(std::move(mh));
      }
      const auto malapi_path = exporter::write_malapi_json(ctx.stem, marr);
      if (!malapi_path.empty()) ctx.exported_artifacts.push_back(malapi_path.string());
    }
  {
    std::vector<malapi_hit_t> empty;
    std::swap(ctx.malapi_hits, empty);
  }
}

// ---------------------------------------------------------------------------
// Phase 22: dashboard (HTML)
// ---------------------------------------------------------------------------
void run_dashboard(context& ctx) {
  const auto started = report_clock::now();
  phase(ctx, true, "dashboard");

  // Collect the artifacts the dashboard consumes. The .dot graphs and the
  // enriched assembly JSON are produced by the radare2 runner.
  std::string asm_json, callgraph_dot, section_dot;
  for (const auto& f : ctx.r2_result.files) {
    if (f.kind == "asm_json")          asm_json      = f.path;
    else if (f.kind == "callgraph")    callgraph_dot = f.path;
    else if (f.kind.rfind("section:", 0) == 0 && section_dot.empty())
      section_dot = f.path;
  }

  // Parse the .dot graphs with cgraph into a normalized graphs.json so the
  // dashboard does not have to regex-parse them (it gets edges wrong). The
  // .dot files are still passed as-is: they are the fallback path when cgraph
  // is unavailable, and graphs.json is best-effort.
  //
  // Only the .dot files this run produced are converted: ctx.r2_result.files
  // lists exactly what the radare2 phase wrote (the run directory only ever
  // holds this sample's artifacts), so folding anything else in would make
  // graphs.json identical for every sample.
  std::string graphs_json;
  if (graphviz::available()) {
    const std::string dot_dir = exporter::dir::run(ctx.stem, "radare2").string();
    const std::string json_path =
        dot_dir + "/" + ctx.stem + "_graphs.json";

    std::vector<std::string> dot_paths;
    for (const auto& f : ctx.r2_result.files) {
      if (f.path.size() >= 4 &&
          f.path.compare(f.path.size() - 4, 4, ".dot") == 0) {
        dot_paths.push_back(f.path);
      }
    }

    const auto gr = graphviz::convert_files(dot_paths, json_path);
    if (gr.ok) {
      graphs_json = gr.written_path;
      LOG_INFO("dashboard: cgraph parsed {}/{} .dot file(s) -> {}",
               gr.files_parsed, gr.files_seen, gr.written_path);
    } else {
      // Not fatal: the dashboard falls back to parse_dot().
      LOG_WARN("dashboard: graphs.json not written ({}); "
               "the dashboard will regex-parse the .dot files", gr.error);
    }
  }

  visualizer::options vopts;
#ifdef _WIN32
  vopts.python = "python/.venv/Scripts/python.exe";
#else
  vopts.python = "python3";
#endif
  vopts.output_name   = ctx.stem;
  // Every artifact path is rooted in this run's directory:
  // exports/<stem>_analysis/<category>/<stem>_<x>.json
  vopts.fileinfo      = exporter::dir::artifact(ctx.stem, "fileinfo", "fileinfo").string();
  vopts.hash          = exporter::dir::artifact(ctx.stem, "hash", "hash").string();
  vopts.ioc           = exporter::dir::artifact(ctx.stem, "ioc", "ioc").string();
  vopts.extraction    = exporter::dir::artifact(ctx.stem, "extraction", "extraction").string();
  vopts.capa          = exporter::dir::artifact(ctx.stem, "capa", "capa").string();
  vopts.iat           = exporter::dir::artifact(ctx.stem, "iat", "iat").string();
  vopts.got           = exporter::dir::artifact(ctx.stem, "got", "got").string();
  vopts.radare2       = exporter::dir::artifact(ctx.stem, "radare2", "radare2").string();
  vopts.malapi        = exporter::dir::artifact(ctx.stem, "malapi", "malapi").string();
  vopts.cti           = exporter::dir::artifact(ctx.stem, "cti", "cti").string();
  vopts.stix          = exporter::dir::artifact(ctx.stem, "stix", "stix21").string();
  vopts.navigator     = exporter::dir::artifact(ctx.stem, "stix", "navigator").string();
  // Same reconstruct-every-path pattern as the siblings: add_opt() skips the
  // flag when the file was never written (ML skipped), and load_json() treats
  // a missing path as "no ML section" rather than an error.
  vopts.ml            = exporter::dir::artifact(ctx.stem, "ml", "ml").string();
  // Detect It Easy result (same reconstruct-every-path pattern: the generator
  // treats a missing file as "no DIE section" rather than an error).
  vopts.die           = exporter::dir::artifact(ctx.stem, "die", "die").string();
  // The dashboard's file catalog is rooted at this run's directory, so it
  // lists only this sample's artifacts instead of every sample under exports/.
  vopts.files_root    = exporter::dir::run_root(ctx.stem).string();
  vopts.output_dir    = exporter::dir::run(ctx.stem, "dashboard").string();
  vopts.asm_json      = asm_json;
  vopts.callgraph_dot = callgraph_dot;
  vopts.section_dot   = section_dot;
  vopts.graphs_json   = graphs_json;

  const auto vr = visualizer::render(vopts);
  if (vr.ok) {
    if (ctx.curses != nullptr) ctx.curses->set_dashboard_path(vr.html_path);
    print_kv_colored("Dashboard", vr.html_path, console::green);
  } else {
    print_warn("dashboard not generated: " + vr.error);
  }
  print_duration(elapsed_ms(started));
}

// ---------------------------------------------------------------------------
// Phase 23: sanity
// ---------------------------------------------------------------------------
void run_sanity(context& ctx) {
  phase(ctx, true, "sanity: invalid input");
  const auto started = report_clock::now();
  bool hash_failed = false;
  bool fuzzy_failed = false;
  {
    file_hash_t invalid_hash{};
    analyzer::file_info_t invalid_info{};
    invalid_info.filepath = "definitely_missing_hash_target.bin";
    hash_failed = !hasher::hash_file(invalid_hash, invalid_info);
  }
  {
    fuzzy_hash_t invalid_fuzzy_hash{};
    analyzer::file_info_t invalid_info{};
    invalid_info.filepath = "definitely_missing_fuzzy_target.bin";
    fuzzy_failed = !hasher::fuzzy_hash_file(invalid_fuzzy_hash, invalid_info);
  }
  if (hash_failed && fuzzy_failed) console::success("invalid inputs correctly rejected");
  else console::error("one or more invalid inputs were accepted");
  print_duration(elapsed_ms(started));
}

// ---------------------------------------------------------------------------
// Summary, and the release of the extraction bundle it was the last reader of
// ---------------------------------------------------------------------------
void run_summary(context& ctx) {
  print_banner("summary");
  print_kv("File",    ctx.info.filename);
  print_kv("Format",  format_name(ctx.fmt));
  print_kv("SHA-256", ctx.file_hash.hash.empty() ? "(failed)" : ctx.file_hash.hash);
  const std::string words = hasher::human_words(ctx.file_hash.hash);
  if (!words.empty()) print_kv("Words", words);
  // Lines for phases that never ran would read as failures ("Capa: failed:
  // not_run"), so each is gated on the phase being in the active pipeline.
  if (planner::has(ctx, planner::phase_id::capa)) {
    print_kv("Capa",
             ctx.capa_report.ok()
                 ? (std::to_string(ctx.capa_report.capabilities.size()) + " capabilities")
                 : std::string("failed: ") + capa::to_string(ctx.capa_report.st));
  }

  // Detect It Easy. Skipped (optional die-python install) and failed scans are
  // reported distinctly, mirroring the ML score block below.
  if (planner::has(ctx, planner::phase_id::die)) {
    using die_st = die_runner::status;
    if (!ctx.die_skip_reason.empty()) {
      print_kv("DIE", "skipped (" + ctx.die_skip_reason + ")");
    } else if (ctx.die_result.st != die_st::ok) {
      print_kv_colored("DIE",
                       std::string("failed: ") +
                           die_runner::to_string(ctx.die_result.st),
                       console::red);
    } else {
      std::ostringstream os;
      os << ctx.die_result.packers.size() << " packer(s), "
         << ctx.die_result.compilers.size() << " compiler(s)";
      if (ctx.die_result.packed) os << ", PACKED";
      else if (ctx.die_result.unknown_only) os << ", no match";
      print_kv("DIE", os.str());
    }
  }

  // ML score. Reported in the banded vocabulary the service uses, never as a
  // bare "malicious/benign", because the score is uncalibrated and can be
  // not_applicable.
  if (planner::has(ctx, planner::phase_id::model)) {
    if (!ctx.ml_skip_reason.empty()) {
      print_kv("ML score", "skipped (" + ctx.ml_skip_reason + ")");
    } else if (!ctx.ml_score.ok) {
      print_kv_colored("ML score", "failed: " + ctx.ml_score.error, console::red);
    } else {
      std::ostringstream os;
      os << std::fixed << std::setprecision(6) << ctx.ml_score.probability
         << "  (" << (ctx.ml_score.verdict_raw.empty()
                          ? ml_api::to_string(ctx.ml_score.verdict)
                          : ctx.ml_score.verdict_raw)
         << ")";
      print_kv("ML score", os.str());
    }
  }

  if (planner::has(ctx, planner::phase_id::radare2)) {
    std::size_t core = 0, sections = 0;
    for (const auto& f : ctx.r2_result.files) {
      if (f.kind.rfind("section:", 0) == 0) ++sections;
      else                                   ++core;
    }
    std::ostringstream os;
    if (ctx.r2_result.st == r2::status::ok || ctx.r2_result.st == r2::status::partial) {
      os << core << " core file(s), " << sections << " section file(s), "
         << ctx.r2_result.functions.size() << " function(s)";
      if (ctx.r2_result.st == r2::status::partial) {
        os << " (" << ctx.r2_result.errors.size() << " error(s))";
      }
      print_kv("Radare2", os.str());
    } else {
      print_kv_colored("Radare2",
                       std::string("failed: ") + r2::to_string(ctx.r2_result.st),
                       console::red);
    }
  }

  if (!ctx.render_format.empty() && ctx.rendered_attempted > 0) {
    std::ostringstream os;
    os << ctx.rendered_ok << " / " << ctx.rendered_attempted
       << " graph(s) rendered (" << ctx.render_format << ")";
    print_kv_colored("Graphviz", os.str(),
                     ctx.rendered_ok == ctx.rendered_attempted ? console::green
                                                               : console::yellow);
  }

  if (planner::has(ctx, planner::phase_id::xref)) {
    if (ctx.xref_skipped) {
      print_kv("IAT/GOT calls", "skipped (no IAT/GOT targets)");
    } else if (ctx.xref_result.st == r2::status::ok ||
               ctx.xref_result.st == r2::status::partial) {
      std::ostringstream os;
      os << ctx.xref_result.xrefs_found << " call site(s) -> "
         << ctx.xref_result.functions_dumped << " function(s)";
      if (ctx.xref_result.st == r2::status::partial) {
        os << " (" << ctx.xref_result.errors.size() << " error(s))";
      }
      print_kv("IAT/GOT calls", os.str());
    } else if (ctx.xref_result.st == r2::status::bad_output) {
      print_kv("IAT/GOT calls", "no call sites found");
    } else {
      print_kv_colored("IAT/GOT calls",
                       std::string("failed: ") + r2::to_string(ctx.xref_result.st),
                       console::red);
    }
  }

  // IAT: extraction's copy when it ran, the iat phase's own copy otherwise
  // (partial pipelines keep it on the context instead of releasing it).
  if (ctx.is_pe && (planner::has(ctx, planner::phase_id::iat) ||
                    planner::has(ctx, planner::phase_id::extraction))) {
    const std::size_t entries = !ctx.full.pe.iat.entries.empty()
                                    ? ctx.full.pe.iat.entries.size()
                                    : ctx.iat_result.entries.size();
    print_kv("IAT", std::to_string(entries) + " entries");
  }
  {
    const extractor::got_result_t* g = &ctx.got_result;
    if (!ctx.full.elf.got.entries.empty()) g = &ctx.full.elf.got;
    else if (!ctx.full.got.entries.empty()) g = &ctx.full.got;
    if (!g->entries.empty()) {
      print_kv("GOT", std::to_string(g->entries.size()) + " entries");
    }
  }

  // Release the full extraction bundle - the largest single allocation in
  // the pipeline - before shutdown. Nothing else reads it any more.
  {
    extractor::extraction_result_t empty{};
    std::swap(ctx.full, empty);
  }
}

}  // namespace pipeline
