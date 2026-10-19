// test_default_pipeline.cpp
//
// The default pipeline, checked against the analyzer's own phase catalog.
//
// This is the test that would have caught a class of mistake nobody had made
// yet: adding or renaming a phase in the catalog and not updating
// pipelines/default.yaml. The analyzer does not fail helpfully for that - it
// exits 2, before any analysis, with "no phase named X in the catalog". The
// cost of finding that out is one build plus one run.
//
// It is checked here rather than in tests/ because it needs no sample, no
// service and no output directory: one subprocess to read the catalog, and then
// string work. Everything it asserts is a property of configuration.
//
// The catalog comes from the BUILT binary rather than from a copy in this file.
// A hardcoded list would pass forever after the catalog moved on, which is the
// bug being tested for.

#include "test_main.hpp"

#include <algorithm>
#include <array>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <regex>
#include <set>
#include <sstream>
#include <string>
#include <vector>

namespace fs = std::filesystem;

namespace {

std::string slurp(const fs::path& p) {
  std::ifstream in(p, std::ios::binary);
  std::ostringstream os;
  os << in.rdbuf();
  return os.str();
}

// Every phase name the binary reports. One subprocess, run once.
//
// Hand-parsed rather than pulled through nlohmann/json, because this executable
// links no analyzer code and dragging a JSON library in for one array of strings
// would be a poor trade. The pattern tolerates both `"name":"x"` and
// `"name": "x"`: the analyzer pretty-prints with a space, and a parser written
// against the compact form returns an empty catalog and passes vacuously - which
// is worse than not parsing at all.
std::vector<std::string> catalog_names(const fs::path& exe) {
  std::vector<std::string> names;
  if (!fs::is_regular_file(exe)) return names;

  FILE* pipe = ::_popen((("\"" + exe.string() + "\" --list-phases --json 2>NUL").c_str()),
                        "r");
  if (pipe == nullptr) return names;
  char buf[4096];
  std::string all;
  while (std::fgets(buf, sizeof buf, pipe) != nullptr) all += buf;
  ::_pclose(pipe);

  // A custom raw-string delimiter, because the pattern itself contains )" -
  // which terminates the default R"( ... )" form at exactly the wrong place.
  static const std::regex field(R"RE("name"\s*:\s*"([^"]+)")RE");
  for (auto it = std::sregex_iterator(all.begin(), all.end(), field);
       it != std::sregex_iterator(); ++it) {
    names.push_back((*it)[1].str());
  }
  std::sort(names.begin(), names.end());
  names.erase(std::unique(names.begin(), names.end()), names.end());
  return names;
}

// Phase names appearing in any inline `phases: [a, b, c]` list.
//
// Block-style lists (- name: x\n    phases:\n      - y) are deliberately not
// handled: the analyzer supports both, but if default.yaml ever switches shape
// this should fail loudly rather than silently find nothing and pass.
std::vector<std::string> declared_phases(const fs::path& pipeline) {
  std::vector<std::string> out;
  std::istringstream in(slurp(pipeline));
  std::string line;
  while (std::getline(in, line)) {
    if (line.find(':') != line.rfind(':')) continue;   // a comment or a URL
    const auto colon = line.find("phases:");
    if (colon == std::string::npos) continue;
    std::string rest = line.substr(colon + 7);
    const auto open = rest.find('[');
    const auto close = rest.find(']');
    if (open == std::string::npos || close == std::string::npos || close < open)
      continue;
    rest = rest.substr(open + 1, close - open - 1);
    for (std::string token : {rest}) {
      std::stringstream ss(token);
      std::string name;
      while (std::getline(ss, name, ',')) {
        while (!name.empty() && (name.front() == ' ' || name.front() == '\t'))
          name.erase(name.begin());
        while (!name.empty() && (name.back() == ' ' || name.back() == '\r'))
          name.pop_back();
        if (!name.empty() && name != "[]") out.push_back(name);
      }
    }
  }
  return out;
}

fs::path repo() {
  // Compiled with the repo root as the working directory by the unit_tests
  // target, so this is "." - but not assumed: walking up from the cwd until
  // pipelines/ appears means the test runs from anywhere inside the tree.
  fs::path here = fs::current_path();
  for (int i = 0; i < 6 && !here.empty(); ++i) {
    if (fs::is_directory(here / "pipelines")) return here;
    if (!here.has_parent_path() || here.parent_path() == here) break;
    here = here.parent_path();
  }
  return fs::current_path();
}

const fs::path exe = repo() / "build-ucrt" / "static_analyzer.exe";
const fs::path default_pipeline = repo() / "pipelines" / "default.yaml";

}  // namespace

TEST(the_analyzer_is_built) {
  // Everything below is vacuous without it, and a green run that tested nothing
  // is the worst possible outcome for a first suite.
  if (!fs::is_regular_file(exe)) {
    std::fprintf(stderr,
                 "  the analyzer is not built at %s\n"
                 "  build it first: cmake --build build-ucrt --target static_analyzer\n",
                 exe.string().c_str());
  }
  CHECK(fs::is_regular_file(exe));
}

TEST(the_catalog_is_not_empty) {
  CHECK(!catalog_names(exe).empty());
}

TEST(every_declared_phase_exists_in_the_catalog) {
  const std::vector<std::string> known = catalog_names(exe);
  CHECK(!known.empty());
  for (const std::string& phase : declared_phases(default_pipeline)) {
    if (std::find(known.begin(), known.end(), phase) == known.end()) {
      std::fprintf(stderr,
                   "  default.yaml selects '%s', which the analyzer's catalog does "
                   "not contain\n  known: %zu phases\n",
                   phase.c_str(), known.size());
    }
    CHECK(std::find(known.begin(), known.end(), phase) != known.end());
  }
}

TEST(no_phase_is_declared_twice) {
  // The analyzer dedups, so a repeat is harmless at runtime - but it means the
  // file was edited twice without anyone reading it back.
  const std::vector<std::string> phases = declared_phases(default_pipeline);
  const std::set<std::string> unique(phases.begin(), phases.end());
  CHECK_EQ(phases.size(), unique.size());
}

TEST(export_and_summary_are_present) {
  // Both are appended when a config omits them, so their absence is legal. But
  // the default pipeline states them, and a pipeline that stops stating them is
  // relying on an implicit behaviour - worth seeing the change.
  const std::vector<std::string> phases = declared_phases(default_pipeline);
  CHECK(std::find(phases.begin(), phases.end(), "export") != phases.end());
  CHECK(std::find(phases.begin(), phases.end(), "summary") != phases.end());
}

TEST(export_comes_after_the_phases_that_feed_it) {
  // Everything that writes an artifact has to run before export assembles the
  // set. A phase appended after export would produce output that silently never
  // reaches the bundle - the same class of bug as yara_gen had to be guarded
  // against.
  const std::vector<std::string> phases = declared_phases(default_pipeline);
  const auto at = [&](const std::string& n) {
    return std::find(phases.begin(), phases.end(), n);
  };
  const auto export_at = at("export");
  if (export_at != phases.end()) {
    for (const char* producer : {"capa", "radare2", "extraction", "strings",
                                 "iat", "model", "cti"}) {
      const auto p = at(producer);
      if (p != phases.end() && p > export_at) {
        std::fprintf(stderr, "  '%s' runs after export at position %zu of %zu\n",
                     producer, static_cast<std::size_t>(p - phases.begin()),
                     phases.size());
      }
      CHECK(!(p != phases.end() && p > export_at));
    }
  }
}

TEST(yaragen_is_not_in_the_default_pipeline) {
  // Opt-in by design, and the design is only meaningful if the default stays
  // free of it. This is the test that keeps that decision from eroding one
  // quiet edit at a time.
  const std::vector<std::string> phases = declared_phases(default_pipeline);
  CHECK(std::find(phases.begin(), phases.end(), "yara_gen") == phases.end());
}

TEST(the_user_skip_flags_survive) {
  // Not a general test - a regression guard on a deliberate choice. The default
  // pipeline carries `CTI_SKIP: 1` and `ML_SKIP: 1`, which keeps a default run
  // off the network and out of the ML scorer. Losing those turns a two-minute
  // offline run into one that phones home, and nothing else would notice.
  const std::string text = slurp(default_pipeline);
  CHECK(text.find("CTI_SKIP") != std::string::npos);
  CHECK(text.find("ML_SKIP") != std::string::npos);
}

UT_MAIN("default_pipeline")