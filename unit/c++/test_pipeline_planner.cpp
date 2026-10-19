// Pipeline planner: catalog integrity, name resolution, and config loading.
//
// The planner is the piece that decides which phases run and in what order, so
// its failures are silent and expensive: a phase that never runs leaves no
// error, just a missing section in the report. That makes it worth testing the
// invariants that are easy to break by accident and hard to notice.
//
// Scope is the pure half of the planner - everything reachable from a
// pipeline_config without a live sample. run_phases() and header_count() need
// a context and are deliberately out of scope; they are exercised end-to-end by
// the analyzer itself.
//
// What this file is for, specifically: the invariants below are the ones that
// were true by construction when written and would now fail quietly if broken.
// The yara_gen ordering test is the load-bearing one - that phase is opt-in and
// writes into the artifact set, so it has to land before `export`.

#include "test_main.hpp"

#include "pipeline_planner.hpp"

#include <nlohmann/json.hpp>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>

using pipeline::planner::artifact_options;
using pipeline::planner::catalog;
using pipeline::planner::catalog_json;
using pipeline::planner::from_name;
using pipeline::planner::has;
using pipeline::planner::load;
using pipeline::planner::parse_default;
using pipeline::planner::phase_id;
using pipeline::planner::pipeline_config;
using pipeline::planner::to_name;

namespace {

// Index of p in the phase list, or -1. to_name() indexes the catalog by enum
// value, so position and index are the same thing by construction - which is
// itself one of the invariants under test.
int index_of(const pipeline_config& cfg, phase_id p) {
  for (std::size_t i = 0; i < cfg.phases.size(); ++i) {
    if (cfg.phases[i] == p) return static_cast<int>(i);
  }
  return -1;
}

bool throws_with(const std::string& spec, const std::string& needle) {
  try {
    load(spec);
  } catch (const std::exception& e) {
    return std::string(e.what()).find(needle) != std::string::npos;
  }
  return false;
}

// Writes a temp config file and hands back its path. YAML is only reachable
// through a file, so the inline-JSON path alone would leave half the loader
// untested.
std::filesystem::path write_temp(const std::string& name, const std::string& body) {
  const std::filesystem::path dir = std::filesystem::temp_directory_path();
  const std::filesystem::path path = dir / ("ia_planner_" + name);
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  out << body;
  out.close();
  return path;
}

}  // namespace

// ---------------------------------------------------------------------------
// Catalog integrity
// ---------------------------------------------------------------------------

TEST(catalog_size_matches_the_enum) {
  CHECK_EQ(catalog().size(),
           static_cast<std::size_t>(pipeline::planner::kPhaseCount));
}

// to_name() indexes the catalog with the raw enum value, so if the two ever
// fall out of step every name lookup silently returns the wrong phase. This is
// the cheapest possible guard against that.
TEST(catalog_is_ordered_by_enum_value) {
  const auto& cat = catalog();
  for (std::size_t i = 0; i < cat.size(); ++i) {
    CHECK(cat[i].id == static_cast<phase_id>(i));
  }
}

TEST(catalog_names_are_unique_and_non_empty) {
  const auto& cat = catalog();
  for (std::size_t i = 0; i < cat.size(); ++i) {
    CHECK(std::string(cat[i].name).size() > 0);
    CHECK(std::string(cat[i].description).size() > 0);
    for (std::size_t j = i + 1; j < cat.size(); ++j) {
      CHECK(std::string(cat[i].name) != std::string(cat[j].name));
    }
  }
}

TEST(name_round_trips_through_from_name) {
  for (const auto& info : catalog()) {
    phase_id out = phase_id::count;
    CHECK(from_name(to_name(info.id), out));
    CHECK(out == info.id);
  }
}

TEST(from_name_ignores_case_and_surrounding_space) {
  phase_id out = phase_id::count;
  CHECK(from_name("SECTIONS", out));
  CHECK(out == phase_id::sections);
  CHECK(from_name("  Model\t", out));
  CHECK(out == phase_id::model);
}

// The documented contract is that out is left untouched on failure, so a
// caller can reuse one variable across a loop of lookups without it drifting.
TEST(from_name_rejects_unknown_names_without_touching_out) {
  phase_id out = phase_id::cti;
  CHECK(!from_name("no_such_phase", out));
  CHECK(out == phase_id::cti);
  CHECK(!from_name("", out));
  CHECK(out == phase_id::cti);
}

// "export" is a C++ keyword, so the enum is report_export while the config
// name is plain "export". If someone ever changed only one side, every config
// naming that phase would stop resolving.
TEST(export_is_named_export_in_configs) {
  CHECK_EQ(to_name(phase_id::report_export), std::string("export"));
}

TEST(has_reflects_the_config) {
  const pipeline_config cfg = load("[\"strings\",\"model\"]");
  CHECK(has(cfg, phase_id::strings));
  CHECK(has(cfg, phase_id::model));
  CHECK(!has(cfg, phase_id::radare2));
}

// ---------------------------------------------------------------------------
// The built-in default
// ---------------------------------------------------------------------------

TEST(parse_default_is_labelled_as_builtin) {
  const pipeline_config cfg = parse_default();
  CHECK_EQ(cfg.name, std::string("default"));
  CHECK_EQ(cfg.source, std::string("builtin:default"));
}

// yara_gen is opt-in by design: it is slow, needs yarGen-Go, and produces
// unreviewed rules. A run must never get it just because the default changed,
// which is why it is absent from the explicit phase list in parse_default()
// rather than being filtered out later.
TEST(default_pipeline_omits_yara_gen) {
  CHECK(!has(parse_default(), phase_id::yara_gen));
}

// A consequence worth pinning: because yara_gen is a catalog entry the default
// does not contain, the default is not "full". If someone ever adds yara_gen to
// parse_default(), this fails and says so.
TEST(default_pipeline_is_not_full_because_yara_gen_is_opt_in) {
  CHECK(!parse_default().full);
}

TEST(default_pipeline_ends_with_export_then_summary) {
  const pipeline_config cfg = parse_default();
  const int ex = index_of(cfg, phase_id::report_export);
  const int sum = index_of(cfg, phase_id::summary);
  CHECK(ex >= 0);
  CHECK(sum >= 0);
  CHECK(ex < sum);
  // summary is last.
  CHECK_EQ(index_of(cfg, phase_id::summary),
           static_cast<int>(cfg.phases.size()) - 1);
}

// ---------------------------------------------------------------------------
// Loading configs
// ---------------------------------------------------------------------------

TEST(loads_an_inline_json_array) {
  const pipeline_config cfg = load("[\"strings\",\"iat\"]");
  CHECK(index_of(cfg, phase_id::strings) < index_of(cfg, phase_id::iat));
  // The epilogue is added even to a two-phase config.
  CHECK(has(cfg, phase_id::report_export));
  CHECK(has(cfg, phase_id::summary));
}

TEST(loads_an_inline_json_object_with_a_name) {
  const pipeline_config cfg =
      load("{\"name\":\"smoke\",\"description\":\"d\",\"phases\":[\"strings\"]}");
  CHECK_EQ(cfg.name, std::string("smoke"));
  CHECK_EQ(cfg.description, std::string("d"));
}

TEST(keeps_stages_separate_from_the_flat_phase_list) {
  const pipeline_config cfg = load(R"({
    "name": "staged",
    "stages": [
      {"name": "triage", "phases": ["sections", "strings"]},
      {"name": "deep",    "phases": ["radare2"]}
    ]})");
  CHECK_EQ(cfg.stages.size(), static_cast<std::size_t>(2));
  CHECK_EQ(cfg.stages[0].first, std::string("triage"));
  CHECK_EQ(cfg.stages[1].first, std::string("deep"));
  CHECK_EQ(cfg.stages[0].second.size(), static_cast<std::size_t>(2));
  // The flat list is the execution order, so it holds everything.
  CHECK(has(cfg, phase_id::radare2));
}

TEST(dedupes_keeping_the_first_occurrence) {
  const pipeline_config cfg = load("[\"strings\",\"iat\",\"strings\",\"model\",\"iat\"]");
  int strings = 0, iat = 0;
  for (phase_id p : cfg.phases) {
    if (p == phase_id::strings) ++strings;
    if (p == phase_id::iat) ++iat;
  }
  CHECK_EQ(strings, 1);
  CHECK_EQ(iat, 1);
  // First occurrence wins, so order is strings, iat, model.
  CHECK(index_of(cfg, phase_id::strings) < index_of(cfg, phase_id::iat));
  CHECK(index_of(cfg, phase_id::iat) < index_of(cfg, phase_id::model));
}

// A phase can never select one whose inputs were never computed. The
// prerequisite goes in *before* its dependent, or the dependent reads nothing.
TEST(inserts_prerequisites_before_the_phase_that_needs_them) {
  const pipeline_config cfg = load("[\"graphs\"]");
  CHECK(has(cfg, phase_id::radare2));
  CHECK(index_of(cfg, phase_id::radare2) < index_of(cfg, phase_id::graphs));
}

TEST(prerequisite_closure_is_transitive) {
  // extraction is required by hexdump, cminer and recovery; nothing here
  // requires extraction directly, so it can only arrive via those.
  const pipeline_config cfg = load("[\"cminer\",\"recovery\"]");
  CHECK(has(cfg, phase_id::extraction));
  CHECK(index_of(cfg, phase_id::extraction) < index_of(cfg, phase_id::cminer));
  CHECK(index_of(cfg, phase_id::extraction) < index_of(cfg, phase_id::recovery));
}

TEST(records_what_it_inserted) {
  const pipeline_config cfg = load("[\"graphs\"]");
  bool saw_radare2 = false, saw_export = false;
  for (const std::string& n : cfg.inserted) {
    if (n == "radare2") saw_radare2 = true;
    if (n == "export") saw_export = true;
  }
  CHECK(saw_radare2);
  CHECK(saw_export);
}

TEST(export_is_inserted_before_the_dashboard) {
  const pipeline_config cfg = load("[\"strings\",\"dashboard\"]");
  CHECK(index_of(cfg, phase_id::report_export) < index_of(cfg, phase_id::dashboard));
}

// The dashboard renders from the files export just wrote, so exporting after
// it would show an empty report.
TEST(export_lands_before_dashboard_even_when_dashboard_was_not_named) {
  const pipeline_config cfg = load("[\"dashboard\"]");
  CHECK(index_of(cfg, phase_id::report_export) < index_of(cfg, phase_id::dashboard));
}

// yara_gen writes yara_gen/<stem>_generated.yar into the artifact set, so it
// must complete before export writes the set. If that order ever inverts the
// generated rules silently land outside the bundle.
TEST(yara_gen_runs_before_export) {
  const pipeline_config cfg = load("[\"strings\",\"yara_gen\"]");
  CHECK(has(cfg, phase_id::yara_gen));
  CHECK(index_of(cfg, phase_id::yara_gen) < index_of(cfg, phase_id::report_export));
  CHECK(index_of(cfg, phase_id::report_export) < index_of(cfg, phase_id::summary));
}

// Because it is a real phase and not a flag, requesting it must not drag in
// anything else - it stays opt-in however it is spelled.
TEST(yara_gen_pulls_in_no_other_phase) {
  const pipeline_config cfg = load("[\"yara_gen\"]");
  CHECK_EQ(cfg.phases.size(), static_cast<std::size_t>(3));  // yara_gen, export, summary
}

// Aliases exist so configs read naturally. They are resolved by the loader's
// internal resolve_name(), not by the public from_name() - see the header note.
TEST(accepts_documented_aliases) {
  struct { const char* alias; phase_id target; } kCases[] = {
      {"ml", phase_id::model},
      {"malapi", phase_id::iat},
      {"graphviz", phase_id::graphs},
      {"eat", phase_id::sections},
      {"ioc", phase_id::strings},
  };
  for (const auto& c : kCases) {
    const pipeline_config cfg =
        load(std::string("[\"") + c.alias + "\"]");
    CHECK(has(cfg, c.target));
  }
}

// preamble and hashes always run and are not selectable, so naming them is
// silently ignored rather than an error.
TEST(ignores_the_always_on_phases) {
  const pipeline_config with = load("[\"preamble\",\"hashes\",\"strings\"]");
  const pipeline_config without = load("[\"strings\"]");
  CHECK_EQ(with.phases.size(), without.phases.size());
}

TEST(rejects_an_unknown_phase_with_a_suggestion) {
  CHECK(throws_with("[\"sectionz\"]", "unknown phase"));
  // One edit away from "sections", so the message should offer it.
  CHECK(throws_with("[\"sectionz\"]", "did you mean 'sections'"));
}

TEST(rejects_an_empty_phase_name) {
  CHECK(throws_with("[\"  \"]", "empty phase name"));
}

TEST(rejects_a_non_list_phases_key) {
  CHECK(throws_with("{\"phases\": \"strings\"}", "must be a list"));
}

TEST(rejects_a_non_string_phase_name) {
  CHECK(throws_with("[\"strings\", 7]", "must be strings"));
}

TEST(rejects_invalid_json) {
  CHECK(throws_with("{not json", "invalid JSON"));
}

TEST(rejects_a_non_scalar_environment_value) {
  CHECK(throws_with("{\"phases\":[\"strings\"],\"environment\":{\"A\":{\"b\":1}}}",
                    "must be a scalar"));
}

// ---------------------------------------------------------------------------
// YAML, which is only reachable through a file
// ---------------------------------------------------------------------------

TEST(loads_yaml_with_stages_and_environment) {
  const auto path = write_temp("staged.yaml", R"(name: smoke
description: two stages
environment:
  ML_THRESHOLD: "0.6"
stages:
  - name: triage
    phases: [sections, strings]
  - name: deep
    phases: [radare2]
)");
  const pipeline_config cfg = load(path.string());
  CHECK_EQ(cfg.name, std::string("smoke"));
  CHECK_EQ(cfg.description, std::string("two stages"));
  CHECK_EQ(cfg.stages.size(), static_cast<std::size_t>(2));
  CHECK(has(cfg, phase_id::radare2));
  bool found_threshold = false;
  for (const auto& [key, value] : cfg.environment) {
    if (key == "ML_THRESHOLD") {
      CHECK_EQ(value, std::string("0.6"));
      found_threshold = true;
    }
  }
  CHECK(found_threshold);
  std::error_code ec;
  std::filesystem::remove(path, ec);
}

TEST(yaml_accepts_aliases_too) {
  const auto path = write_temp("alias.yaml", "phases:\n  - ml\n  - eat\n");
  const pipeline_config cfg = load(path.string());
  CHECK(has(cfg, phase_id::model));
  CHECK(has(cfg, phase_id::sections));
  std::error_code ec;
  std::filesystem::remove(path, ec);
}

TEST(a_missing_file_names_the_thing_it_looked_for) {
  CHECK(throws_with("definitely_not_a_pipeline_xyz", "not found"));
}

// ---------------------------------------------------------------------------
// Environment
// ---------------------------------------------------------------------------

// The loader parses .env; the analyzer only redacts it. apply_environment is
// where a config's environment block reaches both getenv() and child
// processes, so it is worth pinning that it actually exports rather than
// merely records.
TEST(apply_environment_exports_to_getenv_and_overrides) {
  const char* kKey = "IA_PLANNER_TEST_VAR";
  const char* prior = std::getenv(kKey);
  const std::string saved = prior ? prior : "";

  pipeline_config cfg;
  cfg.environment.emplace_back(kKey, "first");
  apply_environment(cfg);
  CHECK_EQ(std::string(std::getenv(kKey) ? std::getenv(kKey) : ""),
           std::string("first"));

  // Second application overwrites rather than being ignored.
  cfg.environment.emplace_back(kKey, "second");
  apply_environment(cfg);
  CHECK_EQ(std::string(std::getenv(kKey) ? std::getenv(kKey) : ""),
           std::string("second"));

  if (prior) {
    _putenv_s(kKey, saved.c_str());
  } else {
    _putenv_s(kKey, "");
  }
}

TEST(a_config_without_environment_changes_nothing) {
  const pipeline_config cfg = load("[\"strings\"]");
  CHECK(cfg.environment.empty());
  apply_environment(cfg);  // must not crash or clear the environment
}

// ---------------------------------------------------------------------------
// Catalog JSON, which the panel and the API both read
// ---------------------------------------------------------------------------

TEST(catalog_json_lists_every_phase) {
  const nlohmann::json j = nlohmann::json::parse(catalog_json());
  CHECK(j.is_array());
  CHECK_EQ(j.size(), catalog().size());
  for (const auto& entry : j) {
    CHECK(entry.contains("name"));
    CHECK(entry.contains("description"));
  }
}

// The panel renders phase names straight out of this JSON, so a phase whose
// name is missing here is a phase the admin cannot select.
TEST(catalog_json_names_match_the_catalog) {
  const nlohmann::json j = nlohmann::json::parse(catalog_json());
  for (std::size_t i = 0; i < catalog().size(); ++i) {
    CHECK_EQ(j[i]["name"].get<std::string>(), std::string(catalog()[i].name));
  }
}

UT_MAIN("pipeline planner")