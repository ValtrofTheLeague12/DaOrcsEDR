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
#include "visualizer.hpp"

namespace pipeline {

// ---------------------------------------------------------------------------
// Phase 21: export, plus the structured side-artifacts the dashboard reads
// ---------------------------------------------------------------------------
void run_export(context& ctx) {
  phase(ctx, true, "export");
  {
    const auto started = report_clock::now();

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
                       " report files under exports/");
      for (const auto& p : paths.paths()) print_bullet(p.string(), console::green);
    } else {
      console::error("some export files failed to write (expected " +
                     std::to_string(expected_artifacts) +
                     ", got " + std::to_string(paths.paths().size()) + ")");
      for (const auto& p : paths.paths()) print_bullet(p.string());
    }

    const auto summary = exporter::summarize_exports(paths);
    exporter::print_export_summary(summary);
    print_duration(elapsed_ms(started));
  }

  // ---------- CTI JSON export ----------
  {
    if (!ctx.cti_report.items.empty()) {
      const auto cti_path = exporter::write_cti_json(ctx.stem, ctx.cti_report);
      if (!cti_path.empty()) {
        console::success("CTI report written to " + cti_path.string());
      }
    }
  }

  // ---------- STIX 2.1 bundle + ATT&CK Navigator layer ----------
  // Deliberately not gated on the CTI phase having produced anything. The
  // techniques capa matched are known from the local capa run alone, and they
  // are the point of both artifacts - so an offline scan (or one with CTI_SKIP
  // set, where the CTI phase never touches a provider) must still emit them.
  {
    // Techniques normally reach the report through cti::collect_from_extraction()
    // inside the network-gated CTI phase, so on an offline run the report holds
    // none. Seed any capa technique that is missing: cti::to_stix_bundle() falls
    // back to the raw technique id as the object name and builds the
    // attack.mitre.org URL itself when the ATT&CK knowledge was never loaded,
    // which is exactly the offline case.
    cti::report stix_report = ctx.cti_report;
    {
      std::set<std::string> present;
      for (const cti::enrichment& item : stix_report.items) {
        if (item.art.type == cti::artifact_type::technique) {
          present.insert(cti::to_upper(item.art.value));
        }
      }
      for (const std::string& raw_id : capa::attack_ids(ctx.capa_report)) {
        const std::string id = cti::to_upper(raw_id);
        if (id.empty() || !present.insert(id).second) continue;
        cti::enrichment item;
        item.art.type = cti::artifact_type::technique;
        item.art.value = id;
        item.art.sources.insert("capa");
        stix_report.items.push_back(std::move(item));
      }
    }

    // ATT&CK detail (name, description, detection, URL, platforms, ALL tactics)
    // for every technique in the report, read from the local knowledge cache.
    // The CTI phase only resolves techniques it looked up online, and its
    // attack_db drops description/detection for memory anyway - so an offline
    // run (or CTI_SKIP) would otherwise ship a bundle of bare "T1234" ids.
    // Fill only keys that are absent: anything the online mitre_attack provider
    // already resolved wins. A missing cache simply fills nothing (no error).
    {
      std::set<std::string> wanted;
      for (const cti::enrichment& item : stix_report.items) {
        if (item.art.type == cti::artifact_type::technique) {
          wanted.insert(cti::to_upper(item.art.value));
        }
      }
      const auto details = cti::attack_details_for(wanted);
      std::size_t enriched = 0;
      for (cti::enrichment& item : stix_report.items) {
        if (item.art.type != cti::artifact_type::technique) continue;
        const auto it = details.find(cti::to_upper(item.art.value));
        if (it == details.end()) continue;
        const cti::attack_detail& d = it->second;
        nlohmann::json& knowledge = item.knowledge["mitre_attack"];
        if (!knowledge.is_object()) knowledge = nlohmann::json::object();
        const auto fill = [&knowledge](const char* key, const nlohmann::json& value) {
          if (!knowledge.contains(key)) knowledge[key] = value;
        };
        if (!d.name.empty())              fill("name", d.name);
        if (!d.url.empty())               fill("url", d.url);
        if (!d.tactic_shortnames.empty()) fill("tactic_shortnames", d.tactic_shortnames);
        if (!d.platforms.empty())         fill("platforms", d.platforms);
        if (!d.description.empty())       fill("description", d.description);
        if (!d.detection.empty())         fill("detection", d.detection);
        fill("subtechnique", d.is_subtechnique);
        ++enriched;
      }
      LOG_DEBUG("export: ATT&CK detail for {} technique(s) read from the knowledge cache",
                enriched);
    }

    if (!stix_report.items.empty()) {
      cti::stix_options stix_opts;
      stix_opts.producer = "static_analyzer";
      const auto stix_path = exporter::write_stix_bundle(ctx.stem, stix_report, stix_opts);
      if (!stix_path.empty()) {
        console::success("STIX bundle written to " + stix_path.string());
      }

      const auto nav_path = exporter::write_navigator_layer(
          ctx.stem, ctx.capa_report, stix_report, stix_report.attack_version);
      if (!nav_path.empty()) {
        console::success("ATT&CK Navigator layer written to " + nav_path.string());
      }
    }
  }

  // Structured MalAPI hits for the dashboard (exports/malapi/<stem>_malapi.json).
  if (!ctx.malapi_hits.empty()) {
    nlohmann::json marr = nlohmann::json::array();
    for (const auto& h : ctx.malapi_hits) {
      nlohmann::json mh = {{"function", h.function}, {"status", h.status}};
      try {
        mh["data"] = nlohmann::json::parse(h.raw_json);
      } catch (const std::exception&) {
        mh["raw"] = h.raw_json;
      }
      marr.push_back(std::move(mh));
    }
    exporter::write_malapi_json(ctx.stem, marr);
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
  // Only the .dot files this run produced are converted. exports/radare2 is a
  // single shared directory that accumulates artifacts from every sample ever
  // analyzed, so converting the whole directory would fold unrelated samples'
  // graphs into this sample's graphs.json and make that file identical for
  // every sample.
  std::string graphs_json;
  if (graphviz::available()) {
    const std::string dot_dir = exporter::dir::radare2;
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
  vopts.output_name   = ctx.stem;
  vopts.fileinfo      = (exporter::dir::fileinfo   + ("/" + ctx.stem + "_fileinfo.json"));
  vopts.hash          = (exporter::dir::hash       + ("/" + ctx.stem + "_hash.json"));
  vopts.ioc           = (exporter::dir::ioc        + ("/" + ctx.stem + "_ioc.json"));
  vopts.extraction    = (exporter::dir::extraction + ("/" + ctx.stem + "_extraction.json"));
  vopts.capa          = (exporter::dir::capa       + ("/" + ctx.stem + "_capa.json"));
  vopts.iat           = (exporter::dir::iat        + ("/" + ctx.stem + "_iat.json"));
  vopts.got           = (exporter::dir::got        + ("/" + ctx.stem + "_got.json"));
  vopts.radare2       = (exporter::dir::radare2    + ("/" + ctx.stem + "_radare2.json"));
  vopts.malapi        = (exporter::dir::malapi     + ("/" + ctx.stem + "_malapi.json"));
  vopts.cti           = (exporter::dir::cti        + ("/" + ctx.stem + "_cti.json"));
  vopts.stix          = (exporter::dir::stix       + ("/" + ctx.stem + "_stix21.json"));
  vopts.navigator     = (exporter::dir::stix       + ("/" + ctx.stem + "_navigator.json"));
  vopts.files_root    = exporter::dir::root;
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
  print_kv("Capa",
           ctx.capa_report.ok()
               ? (std::to_string(ctx.capa_report.capabilities.size()) + " capabilities")
               : std::string("failed: ") + capa::to_string(ctx.capa_report.st));

  {
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

  if (ctx.is_pe) {
    print_kv("IAT", std::to_string(ctx.full.pe.iat.entries.size()) + " entries");
  }
  {
    const auto& g = ctx.full.elf.got.entries.empty() ? ctx.full.got : ctx.full.elf.got;
    if (!g.entries.empty()) {
      print_kv("GOT", std::to_string(g.entries.size()) + " entries");
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
