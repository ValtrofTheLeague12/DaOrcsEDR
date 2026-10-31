#include "pipeline_planner.hpp"

#include "app_paths.hpp"
#include "crash_handler.hpp"
#include "debug_dump_macro.hpp"
#include "exporter.hpp"
#include "logging.hpp"
#include "phase_compression.hpp"
#include "pipeline.hpp"
#include "redact.hpp"
#include "resume.hpp"

#include <nlohmann/json.hpp>
#include <yaml-cpp/yaml.h>

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace pipeline {
namespace planner {

namespace {

using json = nlohmann::json;

// ---------------------------------------------------------------------------
// Catalog
// ---------------------------------------------------------------------------
// `requires_phases` are prerequisites that are silently inserted before the
// phase when missing: hexdump/cminer/recovery read the extraction bundle,
// graphs/xref need the radare2 options and output directory, dashboard reads
// the artifacts export just wrote.
const std::vector<phase_info>& build_catalog() {
  static const std::vector<phase_info> kCatalog = {
      {phase_id::compression, "compression",
       "compressed copy of the sample + run notes",
       "artifacts/ (next to the sample)", "", {}},
      {phase_id::sections, "sections",
       "format-specific section table (PE/ELF/Mach-O); on PE also the export table",
       "eat/<stem>_eat.json (PE)", "", {}},
      {phase_id::generic_sections, "generic_sections",
       "format-agnostic LIEF section view (only for formats without a dedicated view)",
       "", "", {}},
      {phase_id::strings, "strings",
       "extracted strings, IOC mining (IPs/domains/URLs) and CyberChef decode pass",
       "strings/<stem>_strings.json + ioc/<stem>_ioc.json", "cyberchef", {}},
      {phase_id::iat, "iat",
       "PE import address table + MalAPI classification of imported functions",
       "iat/<stem>_iat.json + malapi/<stem>_malapi.json", "malapi", {}},
      {phase_id::got, "got", "ELF/Mach-O GOT/PLT entries",
       "got/<stem>_got.json", "", {}},
      {phase_id::histogram, "histogram", "byte histogram and entropy", "", "", {}},
      {phase_id::packer, "packer", "packer / compiler detection", "", "", {}},
      {phase_id::die, "die",
       "Detect It Easy packer/compiler identification (python bindings)",
       "die/<stem>_die.json", "", {}},
      {phase_id::opcodes, "opcodes", "opcode statistics", "", "", {}},
      {phase_id::debug, "debug", "debug symbols / DWARF information", "", "", {}},
      {phase_id::signature, "signature", "Authenticode signature status", "", "", {}},
      {phase_id::capa, "capa", "capa capability detection rules",
       "capa/<stem>_capa.json", "", {}},
      {phase_id::radare2, "radare2", "radare2 disassembly and function analysis",
       "radare2/<stem>_radare2.json", "", {}},
      {phase_id::graphs, "graphs", "Graphviz rendering of r2 .dot call graphs",
       "radare2/<stem>_graphs.json", "",
       {phase_id::radare2}},
      {phase_id::xref, "xref", "IAT/GOT call-site disassembly via radare2",
       "radare2/ (call-site dump)", "",
       {phase_id::radare2}},
      {phase_id::guards, "guards", "binary compilation guards / mitigations", "", "", {}},
      {phase_id::extraction, "extraction",
       "full LIEF extraction: sections, exports, imports, YARA scan",
       "extraction/<stem>_extraction.json", "", {}},
      {phase_id::hexdump, "hexdump", "head-of-file hexdump",
       "inside extraction JSON", "",
       {phase_id::extraction}},
      {phase_id::cminer, "cminer", "code-cave detection",
       "inside extraction JSON", "",
       {phase_id::extraction}},
      {phase_id::recovery, "recovery", "pipeline error recovery report", "", "",
       {phase_id::extraction}},
      {phase_id::cti, "cti", "CTI enrichment of IOCs (network providers, ATT&CK)",
       "cti/<stem>_cti.json", "", {}},
      {phase_id::model, "model",
       "EMBER2024 LightGBM score (features are extracted inside ml/serve.py)",
       "ml/<stem>_ml.json", "ml", {}},
      {phase_id::yara_gen, "yara_gen",
       "generate NEW yara rules from this sample with yarGen-Go (opt-in: slow, "
       "and the output is unreviewed - validate before deploying)",
       "yara_gen/<stem>_generated.yar", "", {}},
      {phase_id::report_export, "export",
       "write the artifact set for everything that ran",
       "exports/<stem>_analysis/", "", {}},
      {phase_id::dashboard, "dashboard", "HTML results dashboard",
       "dashboard/", "", {phase_id::report_export}},
      {phase_id::sanity, "sanity", "self-test: invalid inputs must be rejected", "", "", {}},
      {phase_id::summary, "summary", "closing report (+ run_summary.json manifest)",
       "run_summary.json", "", {}},
  };
  return kCatalog;
}

// Names that resolve to a different phase. Kept tiny: these exist so configs
// can read naturally ("ml", "malapi", "eat") without duplicating phases.
const std::pair<const char*, const char*>& alias_pair(std::size_t i) {
  static const std::pair<const char*, const char*> kAliases[] = {
      {"ml", "model"},
      {"malapi", "iat"},
      {"graphviz", "graphs"},
      {"eat", "sections"},
      {"ioc", "strings"},
  };
  return kAliases[i];
}

std::string lower(std::string s) {
  std::transform(s.begin(), s.end(), s.begin(),
                 [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  return s;
}

std::string trim(const std::string& s) {
  const auto b = s.find_first_not_of(" \t\r\n");
  if (b == std::string::npos) return "";
  const auto e = s.find_last_not_of(" \t\r\n");
  return s.substr(b, e - b + 1);
}

// Classic Levenshtein distance, used only to suggest a phase name on typos.
std::size_t edit_distance(const std::string& a, const std::string& b) {
  std::vector<std::size_t> prev(b.size() + 1), cur(b.size() + 1);
  for (std::size_t j = 0; j <= b.size(); ++j) prev[j] = j;
  for (std::size_t i = 1; i <= a.size(); ++i) {
    cur[0] = i;
    for (std::size_t j = 1; j <= b.size(); ++j) {
      const std::size_t cost = a[i - 1] == b[j - 1] ? 0 : 1;
      cur[j] = std::min({prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost});
    }
    prev = cur;
  }
  return prev[b.size()];
}

std::string suggestion_for(const std::string& name) {
  std::string best;
  std::size_t best_d = 3;  // only suggest close matches
  for (const phase_info& info : build_catalog()) {
    const std::size_t d = edit_distance(name, info.name);
    if (d < best_d) {
      best_d = d;
      best = info.name;
    }
  }
  return best;
}

bool contains(const std::vector<phase_id>& phases, phase_id p) {
  return std::find(phases.begin(), phases.end(), p) != phases.end();
}

// ---------------------------------------------------------------------------
// Reading and normalization
// ---------------------------------------------------------------------------

// Alias-aware lookup. Non-selectable names ("preamble"/"hashes") are filtered
// out by the callers before this point: they always run and never appear here.
phase_id resolve_name(const std::string& raw, const std::string& origin) {
  const std::string name = lower(trim(raw));
  if (name.empty()) {
    throw std::runtime_error(origin + ": empty phase name");
  }
  for (std::size_t i = 0; i < 5; ++i) {
    const auto& [alias, target] = alias_pair(i);
    if (name == alias) {
      phase_id out{};
      from_name(target, out);
      return out;
    }
  }
  phase_id out{};
  if (from_name(name, out)) return out;
  const std::string sug = suggestion_for(name);
  throw std::runtime_error(origin + ": unknown phase '" + raw + "'" +
                           (sug.empty() ? "" : " (did you mean '" + sug + "'?)") +
                           "; run --list-phases for the catalog");
}

// Fills cfg.phases (and cfg.stages when the caller passes a stage name).
// Non-selectable names (preamble/hashes) are skipped with a debug log.
void read_phase_list(const json& arr, pipeline_config& cfg,
                     const std::string& origin, const std::string& stage) {
  if (!arr.is_array()) {
    throw std::runtime_error(origin + ": '" + (stage.empty() ? "phases" : stage) +
                             "' must be a list of phase names");
  }
  for (const json& entry : arr) {
    if (!entry.is_string()) {
      throw std::runtime_error(origin + ": phase names must be strings");
    }
    const std::string name = lower(trim(entry.get<std::string>()));
    if (name == "preamble" || name == "hashes") {
      LOG_DEBUG("planner: '{}' always runs; ignoring it in the config", name);
      continue;
    }
    const phase_id id = resolve_name(name, origin);
    cfg.phases.push_back(id);
    if (!stage.empty()) {
      for (auto& [sname, ids] : cfg.stages) {
        if (sname == stage) ids.push_back(id);
      }
    }
  }
}

std::string json_scalar_string(const json& v, const std::string& origin,
                               const std::string& key) {
  if (v.is_string()) return v.get<std::string>();
  if (v.is_number() || v.is_boolean()) return v.dump();
  throw std::runtime_error(origin + ": environment value for '" + key +
                           "' must be a scalar");
}

void read_yaml_phase_list(const YAML::Node& arr, pipeline_config& cfg,
                          const std::string& origin, const std::string& stage) {
  if (!arr || !arr.IsSequence()) {
    throw std::runtime_error(origin + ": '" + (stage.empty() ? "phases" : stage) +
                             "' must be a list of phase names");
  }
  for (const YAML::Node& entry : arr) {
    if (!entry.IsScalar()) {
      throw std::runtime_error(origin + ": phase names must be strings");
    }
    const std::string name = lower(trim(entry.Scalar()));
    if (name == "preamble" || name == "hashes") {
      LOG_DEBUG("planner: '{}' always runs; ignoring it in the config", name);
      continue;
    }
    const phase_id id = resolve_name(name, origin);
    cfg.phases.push_back(id);
    if (!stage.empty()) {
      for (auto& [sname, ids] : cfg.stages) {
        if (sname == stage) ids.push_back(id);
      }
    }
  }
}

void normalize(pipeline_config& cfg) {
  // ---- dedupe (first occurrence wins, order preserved) ----
  {
    std::set<phase_id> seen;
    std::vector<phase_id> uniq;
    uniq.reserve(cfg.phases.size());
    for (phase_id p : cfg.phases) {
      if (seen.insert(p).second) uniq.push_back(p);
      else LOG_DEBUG("planner: duplicate phase '{}' dropped", to_name(p));
    }
    cfg.phases.swap(uniq);
  }

  // ---- prerequisites, until closed ----
  for (int guard = 0; guard < 4; ++guard) {
    bool changed = false;
    for (std::size_t i = 0; i < cfg.phases.size(); ++i) {
      for (phase_id req : build_catalog()[static_cast<std::size_t>(cfg.phases[i])].requires_phases) {
        if (!contains(cfg.phases, req)) {
          cfg.phases.insert(cfg.phases.begin() + static_cast<std::ptrdiff_t>(i), req);
          cfg.inserted.push_back(to_name(req));
          changed = true;
        }
      }
    }
    if (!changed) break;
  }

  // ---- epilogue: export (before dashboard/summary) and summary ----
  if (!contains(cfg.phases, phase_id::report_export)) {
    std::size_t pos = cfg.phases.size();
    for (std::size_t i = 0; i < cfg.phases.size(); ++i) {
      if (cfg.phases[i] == phase_id::dashboard ||
          cfg.phases[i] == phase_id::summary) {
        pos = i;
        break;
      }
    }
    cfg.phases.insert(cfg.phases.begin() + static_cast<std::ptrdiff_t>(pos),
                      phase_id::report_export);
    cfg.inserted.push_back("export");
  }
  if (!contains(cfg.phases, phase_id::summary)) {
    cfg.phases.push_back(phase_id::summary);
    cfg.inserted.push_back("summary");
  }

  // ---- full = every phase present (deduped, so size is exact) ----
  cfg.full = cfg.phases.size() == static_cast<std::size_t>(kPhaseCount);
}

pipeline_config from_json_text(const std::string& text, const std::string& origin) {
  pipeline_config cfg;
  cfg.source = origin;
  json j;
  try {
    j = json::parse(text);
  } catch (const std::exception& e) {
    throw std::runtime_error(origin + ": invalid JSON: " + e.what());
  }

  if (j.is_array()) {
    read_phase_list(j, cfg, origin, "");
  } else if (j.is_object()) {
    cfg.name = j.value("name", cfg.name);
    cfg.description = j.value("description", std::string{});
    if (j.contains("environment")) {
      if (!j["environment"].is_object()) {
        throw std::runtime_error(origin + ": 'environment' must be a map");
      }
      for (auto it = j["environment"].begin(); it != j["environment"].end(); ++it) {
        cfg.environment.emplace_back(it.key(), json_scalar_string(it.value(), origin, it.key()));
      }
    }
    if (j.contains("stages")) {
      if (!j["stages"].is_array()) {
        throw std::runtime_error(origin + ": 'stages' must be a list");
      }
      int index = 0;
      for (const json& stage : j["stages"]) {
        if (!stage.is_object() || !stage.contains("phases")) {
          throw std::runtime_error(origin +
                                   ": each stage needs a 'phases' list");
        }
        const std::string sname =
            stage.value("name", "stage " + std::to_string(++index));
        cfg.stages.emplace_back(sname, std::vector<phase_id>{});
        read_phase_list(stage["phases"], cfg, origin, sname);
      }
    } else if (j.contains("phases")) {
      read_phase_list(j["phases"], cfg, origin, "");
    } else {
      throw std::runtime_error(origin +
                               ": config must contain 'stages' or 'phases'");
    }
  } else {
    throw std::runtime_error(origin +
                             ": pipeline must be a JSON array of phases or an object");
  }

  normalize(cfg);
  return cfg;
}

pipeline_config from_yaml_text(const std::string& text, const std::string& origin) {
  pipeline_config cfg;
  cfg.source = origin;
  YAML::Node root;
  try {
    root = YAML::Load(text);
  } catch (const std::exception& e) {
    throw std::runtime_error(origin + ": invalid YAML: " + e.what());
  }
  if (!root || root.IsNull()) {
    throw std::runtime_error(origin + ": empty pipeline config");
  }

  if (root.IsSequence()) {
    read_yaml_phase_list(root, cfg, origin, "");
  } else if (root.IsMap()) {
    if (root["name"]) cfg.name = root["name"].as<std::string>();
    if (root["description"]) cfg.description = root["description"].as<std::string>();
    if (root["environment"]) {
      const YAML::Node env = root["environment"];
      if (!env.IsMap()) {
        throw std::runtime_error(origin + ": 'environment' must be a map");
      }
      for (const auto& it : env) {
        if (!it.first.IsScalar() || !it.second.IsScalar()) {
          throw std::runtime_error(origin +
                                   ": environment values must be scalars");
        }
        cfg.environment.emplace_back(it.first.as<std::string>(),
                                     it.second.Scalar());
      }
    }
    if (root["stages"]) {
      const YAML::Node stages = root["stages"];
      if (!stages.IsSequence()) {
        throw std::runtime_error(origin + ": 'stages' must be a list");
      }
      int index = 0;
      for (const YAML::Node& stage : stages) {
        if (!stage["phases"]) {
          throw std::runtime_error(origin + ": each stage needs a 'phases' list");
        }
        const std::string sname = stage["name"]
                                      ? stage["name"].as<std::string>()
                                      : "stage " + std::to_string(++index);
        cfg.stages.emplace_back(sname, std::vector<phase_id>{});
        read_yaml_phase_list(stage["phases"], cfg, origin, sname);
      }
    } else if (root["phases"]) {
      read_yaml_phase_list(root["phases"], cfg, origin, "");
    } else {
      throw std::runtime_error(origin +
                               ": config must contain 'stages' or 'phases'");
    }
  } else {
    throw std::runtime_error(origin +
                             ": pipeline must be a YAML list or a map with 'stages'/'phases'");
  }

  normalize(cfg);
  return cfg;
}

// ---------------------------------------------------------------------------
// Phase counting - mirrors the phase() calls inside the run_* functions
// ---------------------------------------------------------------------------
int headers_for(phase_id p, const context& ctx) {
  switch (p) {
    case phase_id::compression:
      // run_compression returns before phase() for non-executables / failures.
      return (ctx.is_pe || ctx.is_elf || ctx.is_macho) && !ctx.failed ? 1 : 0;
    case phase_id::generic_sections:
      return (ctx.is_pe || ctx.is_elf || ctx.is_macho) ? 0 : 1;
    case phase_id::iat:
      return ctx.is_pe ? 2 : 0;  // IAT + MalAPI headers, both PE-gated
    case phase_id::got:
      return (ctx.is_elf || ctx.is_macho) ? 1 : 0;
    case phase_id::extraction:
      return ctx.is_pe ? 2 : 0;  // export table + YARA headers, both PE-gated
    case phase_id::model: {
      if (ctx.ml_api_server == nullptr || ctx.failed) return 0;
      const char* v = std::getenv("ML_SKIP");
      if (v != nullptr && (*v != '\0')) {
        const std::string s(v);
        if (s == "1" || s == "true" || s == "yes") return 0;
      }
      return 1;
    }
    case phase_id::summary:
      return 0;  // prints a banner, never a "[phase n/total]" header
    default:
      return 1;
  }
}

// ---------------------------------------------------------------------------
// Bare-name resolution: -p extract_strings -> pipelines/extract_strings.yaml
// ---------------------------------------------------------------------------
// Where named pipeline configs live, in preference order: ./pipelines first,
// then the directory of the executable (so a pipeline shipped next to the
// binary is callable by name from any working directory).
const std::vector<std::filesystem::path>& pipeline_roots() {
  static const std::vector<std::filesystem::path> roots = [] {
    std::filesystem::path exe;
#ifdef _WIN32
    char buf[MAX_PATH] = {};
    const DWORD n = GetModuleFileNameA(nullptr, buf, MAX_PATH);
    if (n > 0 && n < MAX_PATH) exe = std::filesystem::path(buf).parent_path();
#else
    std::error_code ec;
    std::filesystem::path self = std::filesystem::read_symlink("/proc/self/exe", ec);
    if (!ec) exe = self.parent_path();
#endif
    return std::vector<std::filesystem::path>{
        std::filesystem::current_path() / "pipelines", exe / "pipelines"};
  }();
  return roots;
}

// Candidates for a bare pipeline name, in preference order.
std::vector<std::filesystem::path> bare_candidates(const std::string& name) {
  std::vector<std::filesystem::path> out;
  for (const std::filesystem::path& root : pipeline_roots()) {
    for (const char* ext : {".yaml", ".yml", ".json"}) {
      out.push_back(root / (name + ext));
    }
  }
  return out;
}

std::vector<std::filesystem::path> artifact_config_candidates() {
  std::vector<std::filesystem::path> out{
      std::filesystem::current_path() / "config" / "artifacts.yaml"};
  for (const std::filesystem::path& root : pipeline_roots()) {
    out.push_back(root.parent_path() / "config" / "artifacts.yaml");
    out.push_back(root.parent_path().parent_path() / "config" / "artifacts.yaml");
  }
  std::vector<std::filesystem::path> unique;
  for (const auto& path : out) {
    if (std::find(unique.begin(), unique.end(), path) == unique.end())
      unique.push_back(path);
  }
  return unique;
}

}  // namespace

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------
const std::vector<phase_info>& catalog() { return build_catalog(); }

bool from_name(const std::string& name, phase_id& out) {
  const std::string n = lower(trim(name));
  for (const phase_info& info : build_catalog()) {
    if (n == info.name) {
      out = info.id;
      return true;
    }
  }
  return false;
}

std::string to_name(phase_id p) {
  const auto& cat = build_catalog();
  const auto idx = static_cast<std::size_t>(p);
  return idx < cat.size() ? cat[idx].name : "?";
}

bool has(const pipeline_config& cfg, phase_id p) {
  return contains(cfg.phases, p);
}

bool has(const context& ctx, phase_id p) {
  return ctx.active_plan != nullptr && contains(ctx.active_plan->phases, p);
}

pipeline_config parse_default() {
  pipeline_config cfg;
  cfg.name = "default";
  cfg.description = "Complete static analysis (classic phase order)";
  cfg.source = "builtin:default";
  // Explicit so the order is greppable next to pipelines/default.yaml (which
  // must stay identical); generated from the catalog would hide drift.
  cfg.phases = {
      phase_id::compression,      phase_id::sections,
      phase_id::generic_sections, phase_id::strings,
      phase_id::iat,              phase_id::got,
      phase_id::histogram,        phase_id::packer,
      phase_id::die,              phase_id::opcodes,
      phase_id::debug,            phase_id::signature,
      phase_id::capa,
      phase_id::radare2,          phase_id::graphs,
      phase_id::xref,             phase_id::guards,
      phase_id::extraction,       phase_id::hexdump,
      phase_id::cminer,           phase_id::recovery,
      phase_id::cti,              phase_id::model,
      phase_id::report_export,    phase_id::dashboard,
      phase_id::sanity,           phase_id::summary,
  };
  normalize(cfg);
  return cfg;
}

pipeline_config load(const std::string& spec) {
  const std::string cleaned = trim(spec);
  if (cleaned.empty() || cleaned == "default") {
    // `default` is not only a built-in: it is also pipelines/default.yaml, and
    // the Analysis Configuration page lists and edits that file like any other
    // pipeline. Returning the built-in instead meant those edits - the
    // environment skip flags above all - were silently discarded, because the
    // file was never opened. A skip flag that does not skip is worse than no
    // flag: it reads as protection that is not there.
    //
    // So: read the file when it exists, and keep the built-in as the fallback,
    // so a missing or relocated pipelines/default.yaml still analyses a sample
    // exactly as it always did.
    for (const std::filesystem::path& cand : bare_candidates("default")) {
      std::error_code ec;
      if (!std::filesystem::exists(cand, ec) || ec) continue;
      std::ifstream in(cand, std::ios::binary);
      if (!in) continue;
      const std::string text((std::istreambuf_iterator<char>(in)),
                             std::istreambuf_iterator<char>());
      pipeline_config from_file = from_yaml_text(text, cand.string());
      // An empty phase list is a config that would analyse nothing while
      // looking configured. Said plainly rather than silently run as the
      // built-in, which is a different plan than the operator is looking at.
      if (from_file.phases.empty()) {
        throw std::runtime_error(
            cand.string() + ": selects no phases; the built-in default is used "
                           "only when this file is absent");
      }
      return from_file;
    }
    return parse_default();
  }

  const std::size_t first = cleaned.find_first_not_of(" \t\r\n");
  if (first != std::string::npos &&
      (cleaned[first] == '[' || cleaned[first] == '{')) {
    return from_json_text(cleaned, "inline");
  }

  // Bare name (no path separator, no extension): resolve against
  // ./pipelines and <exe dir>/pipelines, so "-p extract_strings" works.
  std::string path = cleaned;
  const std::size_t dot = cleaned.find_last_of('.');
  const bool is_path = cleaned.find_first_of("/\\") != std::string::npos ||
                       (!cleaned.empty() && cleaned.front() == '.');
  if (!is_path && dot == std::string::npos) {
    const std::vector<std::filesystem::path> candidates = bare_candidates(cleaned);
    for (const std::filesystem::path& cand : candidates) {
      std::error_code ec;
      if (std::filesystem::exists(cand, ec) && !ec) {
        path = cand.string();
        break;
      }
    }
    if (path == cleaned) {
      std::string tried;
      for (const std::filesystem::path& cand : candidates) {
        tried += (tried.empty() ? "" : ", ") + cand.string();
      }
      throw std::runtime_error("pipeline '" + cleaned + "' not found (tried " +
                               tried + "); run --list-pipelines");
    }
  }

  std::ifstream in(path, std::ios::binary);
  if (!in) {
    throw std::runtime_error("pipeline file not found: " + path);
  }
  const std::string text((std::istreambuf_iterator<char>(in)),
                         std::istreambuf_iterator<char>());

  const auto pext_dot = path.find_last_of('.');
  const std::string ext =
      pext_dot == std::string::npos ? "" : lower(path.substr(pext_dot));
  if (ext == ".json") return from_json_text(text, path);
  if (ext == ".yaml" || ext == ".yml") return from_yaml_text(text, path);

  // Unknown extension: sniff the content (inline JSON saved to a file).
  const auto text_first = text.find_first_not_of(" \t\r\n");
  if (text_first != std::string::npos && (text[text_first] == '[' || text[text_first] == '{')) {
    return from_json_text(text, path);
  }
  return from_yaml_text(text, path);
}

artifact_options load_artifact_options() {
  artifact_options options;
  std::filesystem::path path;
  for (const auto& candidate : artifact_config_candidates()) {
    std::error_code ec;
    if (std::filesystem::is_regular_file(candidate, ec) && !ec) {
      path = candidate;
      break;
    }
  }
  if (path.empty()) return options;

  options.source = path.string();
  YAML::Node root;
  try {
    root = YAML::LoadFile(path.string());
  } catch (const std::exception& e) {
    throw std::runtime_error(path.string() + ": invalid artifact config: " + e.what());
  }
  if (!root || !root.IsMap()) {
    throw std::runtime_error(path.string() + ": artifact config must be a YAML map");
  }

  const std::set<std::string> allowed{
      "store_artifact", "upload_artifacts", "remote_root", "timeout_seconds",
      "encrypt_artifacts"};
  for (const auto& entry : root) {
    if (!entry.first.IsScalar()) {
      throw std::runtime_error(path.string() + ": artifact config keys must be strings");
    }
    const std::string key = entry.first.Scalar();
    if (allowed.find(key) == allowed.end()) {
      throw std::runtime_error(path.string() + ": unknown artifact option '" + key + "'");
    }
  }
  try {
    if (root["store_artifact"]) options.store_artifact = root["store_artifact"].as<bool>();
    if (root["upload_artifacts"]) options.upload_artifacts = root["upload_artifacts"].as<bool>();
    if (root["remote_root"]) options.remote_root = root["remote_root"].as<std::string>();
    if (root["timeout_seconds"]) options.timeout_seconds = root["timeout_seconds"].as<int>();
    if (root["encrypt_artifacts"]) options.encrypt_artifacts = root["encrypt_artifacts"].as<bool>();
  } catch (const YAML::Exception& e) {
    throw std::runtime_error(path.string() + ": invalid artifact option value: " + e.what());
  }
  if (options.remote_root.empty()) {
    throw std::runtime_error(path.string() + ": 'remote_root' must not be empty");
  }
  if (options.timeout_seconds < 1 || options.timeout_seconds > 86400) {
    throw std::runtime_error(path.string() + ": 'timeout_seconds' must be between 1 and 86400");
  }
  // IA_ARTIFACT_UPLOAD=0 is the escape hatch for anything that must not put
  // evidence on a third-party account: CI, and the panel's test runner, which
  // starts the analyzer from a browser button. It only ever turns uploading
  // OFF - nothing can re-enable it - so it cannot be used to disable the
  // operator's intent, only to override it in a context that asks for it
  // explicitly by name.
  if (const char* off = std::getenv("IA_ARTIFACT_UPLOAD");
      off != nullptr && (std::string(off) == "0" || std::string(off) == "false")) {
    if (options.upload_artifacts) {
      LOG_WARN("artifacts: upload suppressed by IA_ARTIFACT_UPLOAD=0");
    }
    options.upload_artifacts = false;
  }
  // The console's home for the MEGA upload-and-seal settings is
  // config/analysis.yaml now - they are applied as ordinary analysis settings
  // at startup and arrive here as environment variables, so the Analysis
  // Configuration page can hold them as one section. artifacts.yaml keeps
  // working so an existing checkout keeps its behaviour, but where the env
  // var is set the file's line loses, and both sides are named in the log:
  // a value with two possible homes is exactly the state nobody can diagnose
  // from the YAML. store_artifact stays file-only - building a local bundle
  // is not a question anyone asks per machine-level configuration.
  bool mega_applied = false;
  const auto env_truthy = [&](const char* name, bool& target) {
    const char* v = std::getenv(name);
    if (v == nullptr || *v == '\0') return false;
    const std::string s = lower(trim(v));
    if (s == "1" || s == "true" || s == "yes" || s == "on") target = true;
    else if (s == "0" || s == "false" || s == "no" || s == "off") target = false;
    else {
      LOG_WARN("artifacts: {} for '{}' is not a flag value; the file's value stands",
               name, v);
      return false;
    }
    mega_applied = true;
    return true;
  };
  env_truthy("MEGA_UPLOAD", options.upload_artifacts);
  env_truthy("MEGA_SEAL", options.encrypt_artifacts);
  if (const char* v = std::getenv("MEGA_REMOTE_ROOT"); v != nullptr && *v != '\0') {
    options.remote_root = v;
    mega_applied = true;
  }
  if (const char* v = std::getenv("MEGA_TIMEOUT"); v != nullptr && *v != '\0') {
    try {
      const int seconds = std::stoi(v);
      if (seconds >= 1 && seconds <= 86400) {
        options.timeout_seconds = seconds;
        mega_applied = true;
      } else {
        LOG_WARN("artifacts: MEGA_TIMEOUT={} is outside 1..86400; the file's value stands", v);
      }
    } catch (const std::exception&) {
      LOG_WARN("artifacts: MEGA_TIMEOUT={} is not a number; the file's value stands", v);
    }
  }
  if (mega_applied) {
    LOG_INFO("artifacts: MEGA_* from the analysis settings decided the upload "
             "configuration, overriding '{}' where both are set", path.string());
  }
  // MEGA_SEAL only decides WHETHER the bundle is protected. The password is
  // never a configuration value here: it lives in the operator password file
  // outside the repo, managed on the Analysis Configuration page, and the
  // uploader (mega/protect.py) reads it from there. A password in a repo-read
  // YAML would put evidence protection one `cat` away from anything that can
  // read the checkout.
  std::vector<std::filesystem::path> script_candidates{
      path.parent_path().parent_path() / "mega" / "upload.py",
      std::filesystem::current_path() / "mega" / "upload.py"};
  for (const auto& root : pipeline_roots())
    script_candidates.push_back(root.parent_path() / "mega" / "upload.py");
  for (const auto& candidate : script_candidates) {
    std::error_code ec;
    if (std::filesystem::is_regular_file(candidate, ec) && !ec) {
      options.uploader_script = candidate.string();
      break;
    }
  }
  return options;
}

void apply_environment(const pipeline_config& cfg) {
  for (const auto& [key, value] : cfg.environment) {
#ifdef _WIN32
    // SetEnvironmentVariable covers CreateProcess inheritance (the MalAPI/ML
    // services); _putenv_s covers getenv() in this process (ML_SKIP etc.).
    SetEnvironmentVariableA(key.c_str(), value.empty() ? nullptr : value.c_str());
    _putenv_s(key.c_str(), value.c_str());
#else
    setenv(key.c_str(), value.c_str(), 1);
#endif
    // Name-gated, not just scrubbed: redact::seed() only learns about a
    // pipeline-exported value *after* apply_environment() put it in the
    // environment, so a late-registered secret must not be printed here in the
    // first place.
    if (redact::is_secret_name(key)) {
      LOG_DEBUG("planner: environment {}=<redacted>", key);
    } else {
      LOG_DEBUG("planner: environment {}={}", key, redact::scrub(value));
    }
  }
}

std::string catalog_json() {
  json out = json::array();
  for (const phase_info& info : build_catalog()) {
    json entry = {{"name", info.name},
                  {"description", info.description},
                  {"artifact", info.artifact},
                  {"service", info.service},
                  {"requires", json::array()}};
    for (phase_id req : info.requires_phases) entry["requires"].push_back(to_name(req));
    out.push_back(std::move(entry));
  }
  return out.dump(2);
}

void print_catalog(bool as_json) {
  if (as_json) {
    std::cout << catalog_json() << "\n";
    return;
  }
  std::cout << "pipeline phases (use as --pipeline '[\"<name>\", ...]' or in a "
               "YAML 'phases:' list):\n\n";
  for (const phase_info& info : build_catalog()) {
    std::cout << "  " << info.name;
    for (std::size_t pad = std::string(info.name).size(); pad < 17; ++pad)
      std::cout << ' ';
    std::cout << info.description << "\n";
    if (*info.artifact != '\0') std::cout << "      artifact: " << info.artifact << "\n";
    if (*info.service != '\0') std::cout << "      service:   " << info.service << "\n";
    if (!info.requires_phases.empty()) {
      std::cout << "      requires:  ";
      for (std::size_t i = 0; i < info.requires_phases.size(); ++i) {
        if (i) std::cout << ", ";
        std::cout << to_name(info.requires_phases[i]);
      }
      std::cout << "\n";
    }
  }
}

void print_pipelines() {
  struct entry {
    std::string name;
    std::string description;
    std::string source;
  };
  std::vector<entry> entries;
  std::set<std::string> seen;
  entries.push_back({"default",
                     "Complete static analysis (classic 27-phase order)",
                     "builtin"});
  seen.insert("default");

  for (const std::filesystem::path& root : pipeline_roots()) {
    std::error_code dir_ec;
    std::vector<std::filesystem::path> files;
    for (const auto& e : std::filesystem::directory_iterator(root, dir_ec)) {
      if (dir_ec) break;
      std::error_code file_ec;
      if (!e.is_regular_file(file_ec) || file_ec) continue;
      const std::string ext = lower(e.path().extension().string());
      if (ext == ".yaml" || ext == ".yml" || ext == ".json") files.push_back(e.path());
    }
    std::sort(files.begin(), files.end());
    for (const std::filesystem::path& file : files) {
      // Bare "-p default" always means the built-in pipeline, so a file named
      // default.yaml never shadows it in this listing either.
      std::string name = file.stem().string();
      std::string description;
      try {
        const pipeline_config cfg = load(file.string());
        name = cfg.name;
        description = cfg.description.empty() ? "(no description)" : cfg.description;
      } catch (const std::exception& e) {
        description = std::string("unreadable: ") + e.what();
      }
      if (!seen.insert(name).second) continue;
      entries.push_back({std::move(name), std::move(description), file.string()});
    }
  }

  std::sort(entries.begin() + 1, entries.end(),
            [](const entry& a, const entry& b) { return a.name < b.name; });

  std::cout << "available pipelines (use as --pipeline <name>, a file path, or "
               "'[\"<phase>\", ...]'):\n\n";
  for (const entry& e : entries) {
    std::cout << "  " << e.name;
    for (std::size_t pad = e.name.size(); pad < 17; ++pad) std::cout << ' ';
    std::cout << e.description << "\n      from: " << e.source << "\n";
  }
  std::cout << "\nnamed pipelines are found in .\\pipelines and next to the "
               "executable; --list-phases shows the selectable phases.\n";
}

int header_count(const pipeline_config& cfg, const context& ctx) {
  int total = 0;
  for (phase_id p : cfg.phases) total += headers_for(p, ctx);
  return total;
}

void run_phases(context& ctx, const pipeline_config& cfg) {
  ctx.active_plan = &cfg;

  // --debug: what is about to run. Only the *names* of the environment
  // entries are dumped - their values are credentials, which is exactly what
  // must never reach a dump file.
  {
    std::vector<std::string> phase_names;
    phase_names.reserve(cfg.phases.size());
    for (phase_id p : cfg.phases) phase_names.push_back(to_name(p));
    std::vector<std::string> env_names;
    env_names.reserve(cfg.environment.size());
    for (const auto& entry : cfg.environment) env_names.push_back(entry.first);
    SA_DUMP("pipeline plan", "name", cfg.name, "source", cfg.source,
            "phases", phase_names, "environment names", env_names);
  }

  // Prologue: always, unnumbered (hashes) or self-numbering (preamble sets
  // the phase total from the config).
  //
  // Both always run, even on a resume. They are cheap - open the file, hash it -
  // and everything after them reads what they fill in (ctx.info, ctx.stem,
  // ctx.file_hash), so skipping them would break the run rather than save time.
  run_preamble(ctx);
  run_hashes(ctx);

  // Checkpointing starts here, not in main: the stem the point file is keyed by
  // is produced by the prologue, so anything earlier would key every run of
  // every sample under the same name.
  resume::begin(cfg.name, cfg.source, ctx.path, logging::current_run_id(), ctx.stem);

  const std::vector<phase_id> skipped = cfg.resumed;

  if (!skipped.empty()) {
    ctx.resumed_phases.emplace();
    ctx.resume_source = cfg.resume_source;
    for (phase_id p : cfg.phases) {
      if (std::find(skipped.begin(), skipped.end(), p) != skipped.end()) {
        ctx.resumed_phases->push_back(to_name(p));
      }
    }

    std::string list;
    for (const std::string& name : *ctx.resumed_phases) {
      if (!list.empty()) list += ", ";
      list += name;
    }
    console::info("resuming: " + std::to_string(ctx.resumed_phases->size()) +
                  " phase(s) already completed, skipping [" + list + "]");
    if (!cfg.resume_source.empty()) {
      console::info("resume source: " + cfg.resume_source);
    }

    // What a skip costs, named.
    //
    // Results live in `context`, not on disk: a phase that is skipped leaves
    // nothing in memory for the phases after it, so anything that declares a
    // dependency on a skipped phase runs with less than it expects. The
    // catalog's own `requires` list decides which phases those are, rather than
    // a guess about which phases look dependent.
    std::vector<std::string> warnings;
    for (phase_id p : cfg.phases) {
      if (std::find(skipped.begin(), skipped.end(), p) != skipped.end()) continue;
      for (phase_id req : build_catalog()[static_cast<std::size_t>(p)].requires_phases) {
        if (std::find(skipped.begin(), skipped.end(), req) == skipped.end()) continue;
        warnings.push_back("'" + to_name(p) + "' needs '" + to_name(req) +
                           "', which is being skipped");
      }
    }
    if (!warnings.empty()) {
      print_warn("resume is not free: a skipped phase leaves nothing in memory for "
                 "the phases after it");
      for (const std::string& w : warnings) print_warn("  " + w);
      console::info("resume from before '" + to_name(skipped.front()) +
                    "' instead if those results matter");
    }
  }

  // Index-based rather than a range-for: with --continue-on-signal an
  // interrupt rewinds one step so the phase that was interrupted runs again,
  // which a range-for has no way to express.
  std::size_t step = 0;
  // At most one rewind per run. The first interrupt means "redo the phase I was
  // on"; anything after that means "stop". Without this guard a second Ctrl+C
  // would rewind again and walk the run backwards to the start.
  bool redone = false;
  while (step < cfg.phases.size()) {
    phase_id p = cfg.phases[step];
    const std::string phase_name = to_name(p);

    // Ctrl+C is honoured between phases, never inside one: a phase can be part
    // way through writing its artifacts, and abandoning it there is how a run
    // leaves a half-written JSON that the next run reads as truth.
    if (resume::stop_requested()) {
      if (resume::continues_on_interrupt() && !redone) {
        redone = true;
        resume::clear_interrupt();
        if (step > 0) {
          --step;   // back to the phase that was interrupted, so it runs again
          console::info("interrupted during '" + to_name(cfg.phases[step]) +
                        "'; re-running it and continuing with the plan");
        } else {
          console::info("interrupted before the first phase; continuing");
        }
        continue;
      }
      ctx.interrupted = true;
      console::info("stopping before '" + phase_name +
                    "' at the operator's request; resume this run with --resume");
      break;
    }

    if (!ctx.stop_reason.empty()) {
      console::info("stopping before '" + phase_name + "' (" +
                    ctx.stop_reason + "); the completed phases stay resumable");
      break;
    }

    if (std::find(skipped.begin(), skipped.end(), p) != skipped.end()) {
      // Marked in ran_mask so a phase gated on "did radare2 run?" behaves the
      // way it would after a real run - `ran` in run_summary.json stays honest
      // because that list is built from what this run actually executed.
      ctx.ran_mask |= bit(p);
      console::info("skipping '" + phase_name + "' (completed in an earlier run)");
      ++step;
      continue;
    }

    // The crash report leads with this, so a dump and a crash report of the
    // same run name the same phase.
    crash::set_state(phase_name, ctx.path);
    SA_DUMP("phase start", phase_name, "ran_mask", ctx.ran_mask, "input", ctx.path);
    switch (p) {
      case phase_id::compression:
        run_compression(ctx, "artifacts", 6);
        break;
      case phase_id::sections:          run_sections(ctx);          break;
      case phase_id::generic_sections:  run_generic_sections(ctx);  break;
      case phase_id::strings:           run_strings_and_ioc(ctx);   break;
      case phase_id::iat:               run_iat_and_malapi(ctx);    break;
      case phase_id::got:               run_got(ctx);               break;
      case phase_id::histogram:         run_byte_histogram(ctx);    break;
      case phase_id::packer:            run_packer(ctx);            break;
      case phase_id::die:               run_die(ctx);               break;
      case phase_id::opcodes:           run_opcodes(ctx);           break;
      case phase_id::debug:             run_debug_symbols(ctx);     break;
      case phase_id::signature:         run_signature(ctx);         break;
      case phase_id::capa:              run_capa(ctx);              break;
      case phase_id::radare2:           run_radare2(ctx);           break;
      case phase_id::graphs:            run_graphviz(ctx);          break;
      case phase_id::xref:              run_xref_asm(ctx);          break;
      case phase_id::guards:            run_guards(ctx);            break;
      case phase_id::extraction:        run_full_extraction(ctx);   break;
      case phase_id::hexdump:           run_hexdump(ctx);           break;
      case phase_id::cminer:            run_cminer(ctx);            break;
      case phase_id::recovery:          run_error_recovery(ctx);    break;
      case phase_id::cti:               run_cti(ctx);               break;
      case phase_id::model:             run_ml_score(ctx);          break;
      case phase_id::yara_gen:           run_yara_gen(ctx);           break;
      case phase_id::report_export:     run_export(ctx);            break;
      case phase_id::dashboard:         run_dashboard(ctx);         break;
      case phase_id::sanity:            run_sanity(ctx);            break;
      case phase_id::summary:           run_summary(ctx);           break;
      default:                                                  break;
    }
    ctx.ran_mask |= bit(p);
    ctx.executed_mask |= bit(p);
    // The checkpoint is written here rather than from the interrupt handler, so
    // it is also correct when the process dies the ungraceful way. One small
    // file per phase, next to work that takes seconds.
    resume::phase_completed(phase_name);
    ++step;
  }
}

void write_run_summary(const context& ctx, const pipeline_config& cfg,
                       int exit_code, long long duration_ms) try {
  const std::filesystem::path root = exporter::dir::run_root(ctx.stem);

  json stages = json::array();
  for (const auto& [sname, ids] : cfg.stages) {
    json phases = json::array();
    for (phase_id p : ids) phases.push_back(to_name(p));
    stages.push_back({{"name", sname}, {"phases", std::move(phases)}});
  }
  json environment = json::array();
  for (const auto& [k, v] : cfg.environment)
    environment.push_back({{"name", k}, {"value", redact::scrub(v)}});

  json requested = json::array();
  for (phase_id p : cfg.phases) requested.push_back(to_name(p));
  json inserted = json::array();
  for (const std::string& s : cfg.inserted) inserted.push_back(s);
  // `ran` is what THIS run executed. `resumed_from` is what it inherited, kept
  // separate because the two answer different questions: "what did this process
  // do" and "what does the report contain". A resumed manifest that claimed
  // the skipped phases ran here would be lying about its own provenance.
  json ran = json::array();
  for (phase_id p : cfg.phases) {
    if ((ctx.executed_mask & bit(p)) != 0) ran.push_back(to_name(p));
  }
  json resumed_from = json::array();
  if (ctx.resumed_phases) {
    for (const std::string& s : *ctx.resumed_phases) resumed_from.push_back(s);
  }

  json j = {
      {"pipeline", {{"name", cfg.name},
                    {"description", cfg.description},
                    {"source", cfg.source},
                    {"stages", std::move(stages)},
                    {"environment", std::move(environment)},
                    {"artifacts", {
                        {"store_artifact", cfg.artifacts.store_artifact},
                        {"upload_artifacts", cfg.artifacts.upload_artifacts},
                        {"remote_root", cfg.artifacts.remote_root},
                        {"timeout_seconds", cfg.artifacts.timeout_seconds},
                        {"encrypt_artifacts", cfg.artifacts.encrypt_artifacts},
                    }}}},
      {"input", ctx.path},
      {"stem", ctx.stem},
      {"format", {{"pe", ctx.is_pe}, {"elf", ctx.is_elf}, {"macho", ctx.is_macho}}},
      {"phases", {{"requested", std::move(requested)},
                  {"auto_inserted", std::move(inserted)},
                  {"ran", std::move(ran)},
                  {"resumed_from", std::move(resumed_from)}}},
      {"artifacts", ctx.exported_artifacts},
      {"artifact_bundle", {
          {"created", ctx.artifact_bundle_created},
          {"uploaded", ctx.artifact_bundle_uploaded},
          {"encrypted", ctx.artifact_bundle_encrypted},
          {"error", ctx.artifact_action_error},
      }},
      {"result", ctx.interrupted ? "interrupted"
             : !ctx.stop_reason.empty()
                 ? ("stopped:" + ctx.stop_reason)
                 : (exit_code == 0 ? "success" : "failed")},
      {"exit_code", exit_code},
      {"failed", ctx.failed},
      {"duration_ms", duration_ms},
  };
  if (!ctx.stop_reason.empty()) {
    // Interrupted runs say WHY in resume; a policy stop says why here, so the
    // manifest explains itself to a script that only reads the JSON.
    j["stop_reason"] = ctx.stop_reason;
  }
  if (ctx.interrupted || ctx.resumed_phases) {
    // Why this manifest is partial, and how to make it whole. The point file is
    // named so the next step does not have to be guessed at.
    j["resume"] = {
        {"interrupted", ctx.interrupted},
        {"source", ctx.resume_source},
        {"checkpoint", resume::path_for(ctx.stem, app_paths::logs_root()).string()},
        {"completed_count", ctx.resumed_phases ? ctx.resumed_phases->size() : 0u},
    };
  }
  if (!ctx.ml_skip_reason.empty()) j["ml_skip_reason"] = ctx.ml_skip_reason;
  // Generated rules in the run manifest, for the same reason ml_skip_reason is
  // here: the .yar file is the artifact, and the manifest should say what
  // produced it without anyone having to open the yara_gen/ folder to learn
  // whether the LLM pass ran.
  if (!ctx.yara_gen_skip_reason.empty())
    j["yara_gen_skip_reason"] = ctx.yara_gen_skip_reason;
  if ((ctx.ran_mask & bit(phase_id::yara_gen)) != 0) {
    const auto& g = ctx.yara_gen_result;
    if (g.st == yara_gen::status::ok) {
      j["yara_gen"] = {
          {"rule_file", g.rule_file},
          {"rule_bytes", g.rule_bytes},
          {"simple_rules", g.simple_rules},
          {"super_rules", g.super_rules},
          {"identifier", g.identifier},
          {"author", g.author},
          // False is a downgrade worth recording: without config.yaml the
          // strings are scored without the LLM pass, so the rules are weaker
          // than the tool can produce and nobody should assume otherwise.
          {"llm_used", g.llm_used},
          {"llm_reason", g.llm_reason},
          {"db_files", g.db_files},
          {"reviewed", false},   // generated rules are never pre-reviewed
      };
    } else if (g.attempted) {
      j["yara_gen_error"] = g.error;
    }
  }
  // Model provenance in the run manifest: which model build and which decision
  // point produced this run's verdict, without hunting through the ml/ JSON.
  if ((ctx.ran_mask & bit(phase_id::model)) != 0) {
    if (ctx.ml_score.ok) {
      j["ml"] = {
          {"verdict", ctx.ml_score.verdict_raw},
          {"malicious_probability", ctx.ml_score.probability},
          {"threshold", ctx.ml_score.threshold},
          {"model_sha256", ctx.ml_score.model_sha256},
          {"feature_source", ctx.ml_score.feature_source},
          {"low_confidence", ctx.ml_score.low_confidence},
      };
      if (!ctx.ml_score.confidence_note.empty())
          j["ml"]["confidence_note"] = ctx.ml_score.confidence_note;
    } else if (ctx.ml_skip_reason.empty()) {
      j["ml_error"] = ctx.ml_score.error;
    }
  }

  std::error_code ec;
  std::filesystem::create_directories(root, ec);
  const std::filesystem::path path = root / "run_summary.json";
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  if (!out) {
    LOG_ERROR("planner: cannot write run summary {}", path.string());
    return;
  }
  // Scrub the serialized document, not just the fields we know about: this
  // manifest is the one artifact a later step reads back, and a pipeline name
  // or description copied from a config that also holds a token must not leak
  // through it. Replacing a value with ***REDACTED*** cannot break the JSON
  // (the mask has no quotes or backslashes).
  out << redact::scrub(j.dump(2)) << "\n";
  LOG_DEBUG("planner: run summary written to {}", path.string());
} catch (const std::exception& e) {
  LOG_ERROR("planner: run summary failed: {}", e.what());
}

}  // namespace planner
}  // namespace pipeline
