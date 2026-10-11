#include "report.hpp"

#include "cti.hpp"

#include <iomanip>
#include <sstream>
#include <string>
#include <string_view>

// ---------------------------------------------------------------------------
// Capa rendering
// ---------------------------------------------------------------------------

void print_capa_report(const capa::report_t& r) {
  if (!r.ok()) {
    console::error(std::string("capa failed: ") + capa::to_string(r.st));
    if (!r.error.empty())       console::error("  reason: " + r.error);
    if (!r.stderr_tail.empty()) console::error("  stderr: " + r.stderr_tail);
    for (const auto& w : r.warnings) print_warn("  warning: " + w);
    return;
  }

  print_section("capa summary");
  print_kv("Version",    r.capa_version);
  print_kv("Flavor",     r.flavor);
  print_kv("Format",     r.format);
  print_kv("Arch",       r.arch);
  print_kv("OS",         r.os);
  print_kv("Extractor",  r.backend);
  print_kv("From cache", r.from_cache ? "yes" : "no");
  print_kv("Duration",   std::to_string(r.seconds) + "s");

  std::ostringstream counts;
  counts << r.rules_matched << " matched"
         << "  |  " << r.library_rules << " library"
         << "  |  " << r.capabilities.size() << " capabilities";
  print_kv_colored("Rules", counts.str(), console::green);

  if (r.capabilities.empty()) return;

  print_section("capabilities by category");
  for (const auto& [category, count] : capa::capabilities_by_category(r)) {
    std::ostringstream os;
    os << std::left << std::setw(30) << category << "  " << count;
    print_bullet(os.str());
  }

  print_section("capabilities (first 25)");
  constexpr std::size_t kMax = 25;
  std::size_t shown = 0;
  for (const auto& cap : r.capabilities) {
    if (shown++ >= kMax) break;
    std::string line = "[" + cap.namespace_path + "] " + cap.name;
    if (cap.library) line += "  (lib)";
    std::ostringstream tail;
    tail << "  x" << cap.match_count;
    if (!cap.scope.empty()) tail << "  scope=" << cap.scope;
    print_bullet(line + tail.str());
  }
  if (r.capabilities.size() > shown)
    print_bullet("... and " + std::to_string(r.capabilities.size() - shown) + " more");

  const auto att = capa::attack_ids(r);
  const auto mbc = capa::mbc_ids(r);
  if (!att.empty() || !mbc.empty()) {
    print_section("mappings");
    if (!att.empty()) {
      std::string line;
      for (const auto& id : att) { if (!line.empty()) line += ", "; line += id; }
      print_kv("ATT&CK", line);
    }
    if (!mbc.empty()) {
      // Name the ids from the local MBC catalog when it is available; a
      // missing catalog degrades to the bare ids, never an error.
      const auto details = cti::mbc_details_for({mbc.begin(), mbc.end()});
      std::string line;
      for (const auto& id : mbc) {
        if (!line.empty()) line += ", ";
        line += id;
        const auto it = details.find(cti::to_upper(id));
        if (it != details.end() && !it->second.name.empty())
          line += ' ' + it->second.name;
      }
      print_kv("MBC", line);
    }
  }
}

// ---------------------------------------------------------------------------
// Radare2 rendering
// ---------------------------------------------------------------------------

void print_radare2_report(const r2::bulk_result_t& r) {
  const bool has_output = !r.files.empty() || !r.functions.empty();
  const bool okish = (r.st == r2::status::ok) || (r.st == r2::status::partial);
  if (!has_output && !okish) {
    console::error(std::string("radare2: ") + r2::to_string(r.st));
    for (const auto& [kind, msg] : r.errors) {
      console::error("  " + kind + ": " + msg);
    }
    return;
  }

  print_section("radare2 summary");
  {
    std::string_view color = console::green;
    if (r.st == r2::status::partial)       color = console::yellow;
    else if (r.st != r2::status::ok)       color = console::red;
    print_kv_colored("Status", r2::to_string(r.st), color);
  }
  print_kv("Duration", std::to_string(r.seconds) + "s");

  std::size_t core_files = 0;
  std::size_t section_files = 0;
  for (const auto& f : r.files) {
    if (f.kind.rfind("section:", 0) == 0) ++section_files;
    else                                   ++core_files;
  }

  std::ostringstream counts;
  counts << r.files.size() << " file(s)"
         << " (" << core_files << " core, " << section_files << " per-section)"
         << "  |  " << r.functions.size() << " function(s)";
  if (!r.errors.empty())
    counts << "  |  " << r.errors.size() << " error(s)";
  print_kv_colored("Artifacts", counts.str(), console::green);

  if (!r.files.empty()) {
    print_section("generated artifacts");
    for (const auto& f : r.files) {
      std::ostringstream os;
      os << std::left << std::setw(22) << ("[" + f.kind + "]")
         << "  " << f.path
         << "  (" << f.bytes << " bytes)";
      print_bullet(os.str());
    }
  }

  if (!r.section_nop_stats.empty()) {
    print_section("NOP statistics by section");
    for (const auto& section : r.section_nop_stats) {
      std::ostringstream os;
      os << std::left << std::setw(24) << section.section
         << "  NOPs " << std::setw(6) << section.nop_count
         << " / " << std::setw(8) << section.instructions
         << "  (" << std::fixed << std::setprecision(2) << section.nop_percent() << "%)";
      print_bullet(os.str());
    }
  }

  if (!r.functions.empty()) {
    print_section("functions (first 25)");
    constexpr std::size_t kMax = 25;
    std::size_t shown = 0;
    for (const auto& f : r.functions) {
      if (shown++ >= kMax) break;
      std::ostringstream os;
      os << "0x" << std::hex << std::setw(8) << std::setfill('0') << f.offset
         << std::dec << std::setfill(' ')
         << "  " << std::left << std::setw(40) << f.name
         << "  size=" << std::setw(6) << f.size
         << "  blocks=" << f.blocks;
      if (f.is_pure) os << "  [pure]";
      print_bullet(os.str());
    }
    if (r.functions.size() > shown) {
      print_bullet("... and " + std::to_string(r.functions.size() - shown) + " more");
    }
  }

  if (!r.errors.empty()) {
    print_section("radare2 warnings");
    for (const auto& [kind, msg] : r.errors) {
      print_bullet("[" + kind + "] " + msg, console::yellow);
    }
  }
}

// ---------------------------------------------------------------------------
// Graphviz rendering
// ---------------------------------------------------------------------------

void print_render_report(const std::string& format,
                         std::size_t rendered_ok,
                         std::size_t rendered_attempted,
                         const std::vector<std::pair<std::string, std::string>>& errors) {
  print_section("graphviz rendering");
  print_kv("Format", format);
  std::ostringstream counts;
  counts << rendered_ok << " / " << rendered_attempted << " rendered";
  std::string_view color = (errors.empty() && rendered_ok == rendered_attempted)
                               ? console::green
                               : (rendered_ok == 0 ? console::red : console::yellow);
  print_kv_colored("Graphs", counts.str(), color);

  if (!errors.empty()) {
    print_section("render warnings");
    for (const auto& [section, msg] : errors) {
      print_bullet("[" + section + "] " + msg, console::yellow);
    }
  }
}

// ---------------------------------------------------------------------------
// EMBER2024 model verdict
//
// The probability is printed with the caveat it deserves. The score is a
// ranking signal from an uncalibrated LightGBM model, not "there is a 0.99
// chance this is malware", so the verdict line is the banded one the service
// computed and the number is labelled as a score. `not_applicable` is a real
// outcome, not an error: the model only ever saw Win64 PE images.
// ---------------------------------------------------------------------------
void print_ml_score_report(const ml_api::score_result_t& r,
                           const std::string& skip_reason) {
  if (!skip_reason.empty()) {
    // The service never came up, or was switched off, so nothing was scored.
    // Informational, not a failure: an absent optional model is not an analysis
    // error, and a report full of red would misrepresent that.
    console::info("ML score: skipped (" + skip_reason + ")");
    return;
  }

  if (!r.ok) {
    console::error(std::string("ML score failed: ") + r.error);
    if (!r.detail.empty()) console::error("  reason: " + r.detail);
    return;
  }

  print_section("EMBER2024 model score");

  std::ostringstream prob;
  prob << std::fixed << std::setprecision(6) << r.probability;
  print_kv("Score (p)", prob.str() + "   (ranking signal, not calibrated)");

  // The threat level is the same number read against the threshold that was
  // applied, so it stays meaningful when ML_THRESHOLD is moved off 0.5. It is
  // a band over an uncalibrated score, never a confidence - which is why the
  // margin next to it is printed rather than left to be inferred.
  const ml_api::threat_level lvl = ml_api::level_for(r);
  std::string_view lvl_color = console::grey;
  switch (lvl) {
    case ml_api::threat_level::low:             lvl_color = console::green;  break;
    case ml_api::threat_level::moderate:        lvl_color = console::yellow; break;
    case ml_api::threat_level::high:            lvl_color = console::red;    break;
    case ml_api::threat_level::critical:        lvl_color = console::red;    break;
    case ml_api::threat_level::not_applicable:  lvl_color = console::grey;   break;
  }
  print_kv_colored("Threat level", ml_api::to_string(lvl), lvl_color);

  {
    const double margin = ml_api::threshold_margin(r);
    std::ostringstream mg;
    mg << std::fixed << std::setprecision(6) << (margin >= 0.0 ? "+" : "")
       << margin << (margin >= 0.0 ? " above" : " below") << " (p - t)";
    print_kv_colored("vs threshold", mg.str(),
                     margin >= 0.0 ? console::red : console::green);
  }

  std::string_view vcolor = console::yellow;
  if (r.verdict == ml_api::verdict::malicious)      vcolor = console::red;
  else if (r.verdict == ml_api::verdict::benign)    vcolor = console::green;
  print_kv_colored("Verdict", r.verdict_raw.empty()
                                     ? std::string(ml_api::to_string(r.verdict))
                                     : r.verdict_raw,
                   vcolor);
  if (r.low_confidence) {
    // A score built from a non-thrember vector or one that failed the
    // train/serve skew check must not read like a normal verdict.
    print_warn("LOW CONFIDENCE: " + r.confidence_note);
  }

  {
    std::ostringstream thr;
    thr << std::fixed << std::setprecision(4) << r.threshold;
    print_kv("Threshold used", thr.str());
  }
  print_kv("PE image", r.is_pe ? "yes" : "no");

  if (!r.verdict_note.empty()) {
    print_warn(r.verdict_note);
  }

  print_kv("Features", r.feature_source.empty() ? "thrember (service-side)"
                                                : r.feature_source);
  if (r.skew.present) {
    // Train/serve skew: the C++ exporter's own histogram/byteentropy against
    // the thrember vector the model actually scored.
    double worst = -1.0;
    std::string worst_group;
    std::size_t n_groups = 0;
    for (const auto& [name, g] : r.skew.groups) {
      ++n_groups;
      if (g.max_abs_diff > worst) {
        worst = g.max_abs_diff;
        worst_group = name;
      }
    }
    std::ostringstream sk;
    sk << std::scientific << std::setprecision(1) << "max |C++ - thrember| = "
       << (worst < 0.0 ? 0.0 : worst) << " (tolerance " << r.skew.tolerance
       << ", " << n_groups << " group(s))";
    if (r.skew.ok) {
      print_kv_colored("Skew check", "OK  " + sk.str(), console::green);
    } else {
      print_kv_colored("Skew check",
                       "MISMATCH in " + worst_group + ": " + sk.str(),
                       console::red);
    }
  }
  if (!r.model_sha256.empty()) {
    // Short hash: enough to identify the model build in a log, short enough not
    // to wrap the report line.
    print_kv("Model", r.model + "  sha256:" + r.model_sha256.substr(0, 12));
  }
  if (r.trees > 0) {
    print_kv("Model size", std::to_string(r.trees) + " trees, " +
                             std::to_string(r.features) + " features");
  }

  if (r.explained && !r.top_features.empty()) {
    print_section("why (TreeSHAP, log-odds)");
    std::ostringstream head;
    head << std::fixed << std::setprecision(3)
         << "base " << r.base_log_odds << " -> " << r.prediction_log_odds
         << "   (SHAP sum " << r.sum_shap << ")";
    print_kv("Attribution", head.str());

    for (const ml_api::feature_evidence_t& f : r.top_features) {
      // Prefer the concrete evidence (an import/export name) over the generic
      // label: "library:kernel32.dll" says far more than "hashed bucket".
      std::string what = f.evidence;
      if (what.empty()) what = f.label;
      if (what.empty()) what = "column " + std::to_string(f.feature_index);

      std::ostringstream os;
      os << (f.shap_log_odds >= 0 ? "+" : "") << std::fixed
         << std::setprecision(3) << std::setw(7) << f.shap_log_odds << "  "
         << what;
      // The feature's own value next to its contribution: a SHAP of +1.4 on
      // an entropy feature reads very differently at value=0.1 than at 7.9.
      os << "   [value " << std::setprecision(4) << f.value << "]";
      if (f.shared_bucket && f.bucket_occupancy > 1) {
        // A shared hash bucket's SHAP is the sum over every name in it, so the
        // number must not be read as this one import's contribution.
        os << "  [+" << std::to_string(f.bucket_occupancy - 1)
           << " more in this hash bucket]";
      }
      print_bullet(os.str(),
                   f.shap_log_odds >= 0 ? console::red : console::cyan);
    }
  }

  if (r.explained && !r.group_rollup.empty()) {
    print_section("contribution by EMBER feature group");
    for (const ml_api::group_rollup_t& g : r.group_rollup) {
      std::ostringstream os;
      os << std::left << std::setw(18) << g.group
         << std::fixed << std::setprecision(3) << std::setw(8)
         << g.shap_log_odds;
      if (!g.analyzer_implemented) {
        // Worth surfacing: these are the groups the C++ exporter cannot
        // produce yet, i.e. where exporter work would pay off.
        os << "   (not produced by the C++ exporter)";
      }
      print_bullet(os.str());
    }
  }
}
