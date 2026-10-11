#include "pipeline_planner.hpp"

#include "exporter.hpp"
#include "logging.hpp"
#include "phase_compression.hpp"
#include "pipeline.hpp"

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
      phase_id::opcodes,          phase_id::debug,
      phase_id::signature,        phase_id::capa,
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
  if (cleaned.empty() || cleaned == "default") return parse_default();

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
    LOG_DEBUG("planner: environment {}={}", key, value);
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
                     "Complete static analysis (classic 26-phase order)",
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

  // Prologue: always, unnumbered (hashes) or self-numbering (preamble sets
  // the phase total from the config).
  run_preamble(ctx);
  run_hashes(ctx);

  for (phase_id p : cfg.phases) {
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
      case phase_id::report_export:     run_export(ctx);            break;
      case phase_id::dashboard:         run_dashboard(ctx);         break;
      case phase_id::sanity:            run_sanity(ctx);            break;
      case phase_id::summary:           run_summary(ctx);           break;
      default:                                                  break;
    }
    ctx.ran_mask |= bit(p);
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
    environment.push_back({{"name", k}, {"value", v}});

  json requested = json::array();
  for (phase_id p : cfg.phases) requested.push_back(to_name(p));
  json inserted = json::array();
  for (const std::string& s : cfg.inserted) inserted.push_back(s);
  json ran = json::array();
  for (phase_id p : cfg.phases) {
    if ((ctx.ran_mask & bit(p)) != 0) ran.push_back(to_name(p));
  }

  json j = {
      {"pipeline", {{"name", cfg.name},
                    {"description", cfg.description},
                    {"source", cfg.source},
                    {"stages", std::move(stages)},
                    {"environment", std::move(environment)}}},
      {"input", ctx.path},
      {"stem", ctx.stem},
      {"format", {{"pe", ctx.is_pe}, {"elf", ctx.is_elf}, {"macho", ctx.is_macho}}},
      {"phases", {{"requested", std::move(requested)},
                  {"auto_inserted", std::move(inserted)},
                  {"ran", std::move(ran)}}},
      {"artifacts", ctx.exported_artifacts},
      {"result", exit_code == 0 ? "success" : "failed"},
      {"exit_code", exit_code},
      {"failed", ctx.failed},
      {"duration_ms", duration_ms},
  };
  if (!ctx.ml_skip_reason.empty()) j["ml_skip_reason"] = ctx.ml_skip_reason;
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
  out << j.dump(2) << "\n";
  LOG_DEBUG("planner: run summary written to {}", path.string());
} catch (const std::exception& e) {
  LOG_ERROR("planner: run summary failed: {}", e.what());
}

}  // namespace planner
}  // namespace pipeline
