// yara_scanner.cpp — libyara integration.
//
// Rule-set hygiene (single pass over the tree, parallel compile, deduped
// scan):
//   * excluded trees: deprecated/, mobile_malware/, APK/, Android/,
//     Malekith_Rules/rules/ (byte-identical mirror of the set root),
//     aggregator index files (*index*.yar), and *_ELF rule files for PE
//     targets; androguard/cuckoo rules only live under those trees.
//   * externals that community rules expect from a loader are defined
//     before compilation (is__elf=false for PE targets).
//   * libyara (assertions enabled) refuses add_file after any compile error
//     and refuses get_rules when errors != 0, so the file list is split
//     into deterministic chunks that compile in parallel; a chunk that hits
//     an error classifies its files individually and reassembles only the
//     clean ones. Each chunk is then scanned separately; matches are merged
//     and deduped by (namespace, rule).
//   * compiled chunks are cached by rule-set hash: in-process map first,
//     then logs/yara_rules_<hash>_c<i>.cache (yr_rules_save/yr_rules_load).
//   * compiler errors go to logs/yara_errors.log; the result only carries
//     a capped summary, and a one-line console summary is printed.
#include "yara_scanner.hpp"

#include <yara.h>

#include "console.hpp"
#include "logging.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <sstream>
#include <string_view>
#include <system_error>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace yara_scanner {
namespace {

// --- small utilities ---------------------------------------------------------

std::string lower(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  return value;
}

std::string rule_error(const std::filesystem::path& path, const std::string& message) {
  return path.string() + ": " + message;
}

// FNV-1a 64 — cheap content-agnostic hash for cache keys.
constexpr std::uint64_t kFnvOffset = 14695981039346656037ull;
constexpr std::uint64_t kFnvPrime = 1099511628211ull;

void fnv_mix(std::uint64_t& hash, const void* data, std::size_t size) {
  const auto* bytes = static_cast<const unsigned char*>(data);
  for (std::size_t i = 0; i < size; ++i) {
    hash ^= bytes[i];
    hash *= kFnvPrime;
  }
}

void fnv_mix(std::uint64_t& hash, const std::string& text) {
  fnv_mix(hash, text.data(), text.size());
}

std::string hex16(std::uint64_t value) {
  std::ostringstream out;
  out << std::hex << std::setw(16) << std::setfill('0') << value;
  return out.str();
}

// --- include / error callbacks ------------------------------------------------

// Root of the rule tree currently being compiled; set for the duration of
// the compile (guarded by g_scan_mutex) so includes can resolve against it.
std::string g_include_root;

void include_free(const char* result, void*) {
  std::free(const_cast<char*>(result));
}

char* read_rule_file(const std::filesystem::path& path) {
  std::FILE* file = std::fopen(path.string().c_str(), "rb");
  if (!file) return nullptr;
  if (std::fseek(file, 0, SEEK_END) != 0) {
    std::fclose(file);
    return nullptr;
  }
  const long size = std::ftell(file);
  if (size < 0 || std::fseek(file, 0, SEEK_SET) != 0) {
    std::fclose(file);
    return nullptr;
  }
  char* data = static_cast<char*>(std::malloc(static_cast<std::size_t>(size) + 1));
  if (!data) {
    std::fclose(file);
    return nullptr;
  }
  const std::size_t read = std::fread(data, 1, static_cast<std::size_t>(size), file);
  std::fclose(file);
  data[read] = '\0';
  return data;
}

const char* resolve_include(const char* include_name,
                             const char* calling_rule_filename,
                             const char*, void*) {
  if (!include_name || !*include_name) return nullptr;
  std::filesystem::path include_path(include_name);
  std::error_code ec;
  if (include_path.is_absolute()) {
    return std::filesystem::is_regular_file(include_path, ec)
               ? read_rule_file(include_path)
               : nullptr;
  }
  if (calling_rule_filename && *calling_rule_filename) {
    const std::filesystem::path candidate =
        std::filesystem::path(calling_rule_filename).parent_path() / include_path;
    if (std::filesystem::is_regular_file(candidate, ec)) return read_rule_file(candidate);
  }
  if (!g_include_root.empty()) {
    const std::filesystem::path candidate =
        std::filesystem::path(g_include_root) / include_path;
    if (std::filesystem::is_regular_file(candidate, ec)) return read_rule_file(candidate);
  }
  return nullptr;
}

// Error sink for one compile: appends formatted lines and bumps two
// counters so the caller knows whether the CURRENT add_file call (and thus
// the current file) produced errors. Either counter may be null.
struct error_sink_t {
  std::vector<std::string>* lines = nullptr;
  std::size_t* attempt_errors = nullptr;
  std::size_t* current_file_errors = nullptr;
};

void compiler_message(int level, const char* file_name, int line_number,
                      const YR_RULE*, const char* message, void* user_data) {
  if (!user_data || level != YARA_ERROR_LEVEL_ERROR) return;
  auto* sink = static_cast<error_sink_t*>(user_data);
  std::ostringstream out;
  if (file_name) out << file_name << ':' << line_number << ": ";
  out << (message ? message : "YARA compilation error");
  sink->lines->push_back(out.str());
  if (sink->attempt_errors) ++*sink->attempt_errors;
  if (sink->current_file_errors) ++*sink->current_file_errors;
}

// --- scan callback ------------------------------------------------------------

struct scan_sink_t {
  std::vector<rule_match_t>* matches = nullptr;
};

int scan_callback(YR_SCAN_CONTEXT* context, int message, void* message_data,
                  void* user_data) {
  if (message != CALLBACK_MSG_RULE_MATCHING || !message_data || !user_data)
    return CALLBACK_CONTINUE;
  auto* sink = static_cast<scan_sink_t*>(user_data);
  auto* rule = static_cast<YR_RULE*>(message_data);
  rule_match_t match;
  match.identifier = rule->identifier ? rule->identifier : "<unnamed rule>";
  match.tags = rule->tags ? rule->tags : "";
  if (rule->ns && rule->ns->name) match.ns = rule->ns->name;

  for (YR_STRING* string = rule->strings; string && !STRING_IS_LAST_IN_RULE(string);
       ++string) {
    string_match_t sm;
    sm.identifier = string->identifier ? string->identifier : "$unnamed";
    YR_MATCH* ymatch = nullptr;
    yr_string_matches_foreach(context, string, ymatch) {
      if (sm.offsets.size() < 32)
        sm.offsets.push_back(static_cast<std::int64_t>(ymatch->base + ymatch->offset));
    }
    if (!sm.offsets.empty()) match.strings.push_back(std::move(sm));
  }
  sink->matches->push_back(std::move(match));
  return CALLBACK_CONTINUE;
}

// --- rule-set enumeration and hygiene filters --------------------------------

std::vector<std::filesystem::path> rglob_rule_files(
    const std::filesystem::path& root, std::size_t& found) {
  std::vector<std::filesystem::path> files;
  found = 0;
  std::error_code ec;
  if (!std::filesystem::is_directory(root, ec)) return files;
  for (const auto& entry : std::filesystem::recursive_directory_iterator(
           root, std::filesystem::directory_options::skip_permission_denied, ec)) {
    if (ec) break;
    if (!entry.is_regular_file(ec)) continue;
    const std::string ext = lower(entry.path().extension().string());
    if (ext == ".yar" || ext == ".yara") {
      ++found;
      files.push_back(entry.path());
    }
  }
  std::sort(files.begin(), files.end());
  return files;
}

// Path segments that never apply to a PE target, or that duplicate rules
// compiled elsewhere in the tree. Patterns are forward-slash because the
// filter runs on path::generic_string().
constexpr std::string_view kExcludedSubdirs[] = {
    "/malekith_rules/rules/",  // byte-identical mirror of the set root
    "/deprecated/",            // retired rules (androguard/cuckoo live here)
    "/mobile_malware/",        // Android rules
    "/apk/",                   // Android rules (fsYara/executable/APK)
    "/android/",               // any explicit Android tree
    "/.github/",               // CI helpers
};

struct skip_stats_t {
  std::size_t mirror = 0;
  std::size_t deprecated = 0;
  std::size_t android = 0;
  std::size_t index = 0;
  std::size_t elf = 0;
  std::size_t total() const { return mirror + deprecated + android + index + elf; }
};

// Returns true when the file must not be compiled for a PE target.
bool is_excluded(const std::string& rel_lower_with_leading_sep,
                 const std::string& name_lower, skip_stats_t& stats) {
  if (name_lower.find("index") != std::string::npos) {
    // Aggregator files (index.yar, *_index.yar, malware_index.yar): every
    // rule they include is also compiled from its own file, so compiling
    // them duplicates each match.
    ++stats.index;
    return true;
  }
  if (name_lower.find("_elf") != std::string::npos) {
    // ELF-only signatures: the target is a PE file.
    ++stats.elf;
    return true;
  }
  for (const std::string_view subdir : kExcludedSubdirs) {
    if (rel_lower_with_leading_sep.find(subdir) == std::string::npos) continue;
    if (subdir == "/deprecated/") ++stats.deprecated;
    else if (subdir == "/malekith_rules/rules/") ++stats.mirror;
    else ++stats.android;
    return true;
  }
  return false;
}

// Top-level set directory of a rule file, e.g. "fsYara" for
// fsYara/executable/.../foo.yar.
std::string rule_set_of(const std::filesystem::path& rel) {
  const auto it = rel.begin();
  if (it == rel.end()) return "unknown";
  return it->string();
}

// Path of `file` relative to the rules root. Purely lexical: the paths come
// from rglob over the root itself, so the prefix always matches.
// std::filesystem::relative() would resolve both sides against the disk
// (two handle opens per call) — measured at ~17s over the rule tree.
std::filesystem::path rel_to_root(const std::filesystem::path& file,
                                  const std::filesystem::path& root) {
  const std::string f = file.generic_string();
  std::string r = root.generic_string();
  while (!r.empty() && r.back() == '/') r.pop_back();
  const auto ieq = [](char a, char b) {
    return std::tolower(static_cast<unsigned char>(a)) ==
           std::tolower(static_cast<unsigned char>(b));
  };
  if (f.size() > r.size() && std::equal(r.begin(), r.end(), f.begin(), ieq) &&
      f[r.size()] == '/') {
    return std::filesystem::path(f.substr(r.size() + 1));
  }
  return file;
}

// Quality tier per rule set: vetted vendor / research packs versus community
// aggregations. Weights feed the match scoring (curated 1.0, community 0.5).
struct quality_t {
  const char* tier;
  double weight;
};

quality_t quality_of(const std::string& set) {
  static const std::unordered_map<std::string, quality_t> kCurated = {
      {"CDI_yara", {"curated", 1.0}},              // CyberDefenders intel packs
      {"fsYara", {"curated", 1.0}},                // Filescan.io curated service rules
      {"malware-signatures", {"curated", 1.0}},    // Citizen Lab research signatures
      {"protections-artifacts", {"curated", 1.0}}, // Elastic Security detections
  };
  const auto it = kCurated.find(set);
  if (it != kCurated.end()) return it->second;
  return {"community", 0.5};
}

// Unique YARA namespace per rule file: "<set>__<sanitised rel path>_<fnv8>".
std::string make_namespace(const std::string& set, const std::string& rel) {
  std::string ns = set + "__" + rel;
  for (char& c : ns) {
    const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                    (c >= '0' && c <= '9') || c == '_' || c == '.' || c == '-';
    if (!ok) c = '_';
  }
  std::uint64_t h = kFnvOffset;
  fnv_mix(h, rel);
  std::ostringstream suffix;
  suffix << '_' << std::hex << std::setw(8) << std::setfill('0')
         << static_cast<std::uint32_t>(h & 0xffffffffu);
  return ns + suffix.str();
}

// --- compiled rule-set cache --------------------------------------------------

struct compiled_set_t {
  std::uint64_t hash = 0;
  // One YR_RULES per compile chunk; never destroyed (process lifetime).
  std::vector<YR_RULES*> rules;
  std::size_t files_loaded = 0;
  std::size_t files_failed = 0;
  double compile_seconds = 0.0;
  bool compiled_here = false;  // false = loaded from disk cache
  // Full compiler output for this hash (all runs report the same numbers).
  std::vector<std::string> errors;
  // namespace -> set name, rebuilt from the current file list.
  std::unordered_map<std::string, std::string> ns_to_set;
};

std::mutex g_scan_mutex;
std::unordered_map<std::uint64_t, std::unique_ptr<compiled_set_t>> g_cache;
std::once_flag g_init_once;

void ensure_yara_initialized() {
  std::call_once(g_init_once, [] {
    const int rc = yr_initialize();
    if (rc != ERROR_SUCCESS)
      LOG_WARN("yara: yr_initialize failed with error {}", rc);
  });
}

std::filesystem::path disk_cache_path(std::uint64_t hash, std::size_t chunk) {
  std::ostringstream name;
  name << "yara_rules_" << hex16(hash) << "_c" << chunk << ".cache";
  return std::filesystem::path("logs") / name.str();
}

std::filesystem::path disk_cache_errors_path(std::uint64_t hash) {
  return std::filesystem::path("logs") / ("yara_rules_" + hex16(hash) + ".errors");
}

std::size_t choose_chunks(std::size_t file_count) {
  const std::size_t hardware = std::max(1u, std::thread::hardware_concurrency());
  return std::min({hardware, static_cast<std::size_t>(8), file_count});
}

// Hash of the rule set as the compiler sees it: paths + sizes + mtimes of the
// kept files, the rules root, the externals, the chunk layout, and the
// libyara version.
std::uint64_t hash_rule_set(const std::string& rules_dir,
                            const std::vector<std::filesystem::path>& kept,
                            const std::vector<std::filesystem::path>& all,
                            std::size_t chunks) {
  std::uint64_t hash = kFnvOffset;
  fnv_mix(hash, rules_dir);
  fnv_mix(hash, "externals:none;v2");
  const auto version = static_cast<std::uint64_t>(YR_VERSION_HEX);
  fnv_mix(hash, reinterpret_cast<const char*>(&version), sizeof(version));
  const auto chunk_word = static_cast<std::uint64_t>(chunks);
  fnv_mix(hash, reinterpret_cast<const char*>(&chunk_word), sizeof(chunk_word));
  const auto mixed_size = static_cast<std::uint64_t>(all.size());
  fnv_mix(hash, reinterpret_cast<const char*>(&mixed_size), sizeof(mixed_size));
  for (const auto& file : kept) {
    const std::string rel = file.generic_string();
    fnv_mix(hash, rel);
    std::error_code ec;
    const auto size = static_cast<std::uint64_t>(
        std::filesystem::file_size(file, ec));
    fnv_mix(hash, reinterpret_cast<const char*>(&size), sizeof(size));
    const auto mtime = static_cast<std::uint64_t>(
        std::filesystem::last_write_time(file, ec).time_since_epoch().count());
    fnv_mix(hash, reinterpret_cast<const char*>(&mtime), sizeof(mtime));
  }
  return hash;
}

// Sidecar next to the disk cache: without it a disk-cache hit would report
// "0 errors, ? loaded" instead of the compile-time numbers. `pieces` is the
// exact number of cache files the compile produced (one or two per chunk,
// depending on how many files needed the is__elf external).
struct cache_stats_t {
  std::size_t pieces = 0;
  std::size_t files_loaded = 0;
  std::size_t files_failed = 0;
  std::vector<std::string> errors;
};

bool write_cache_sidecar(std::uint64_t hash, const cache_stats_t& stats) {
  std::ofstream out(disk_cache_errors_path(hash), std::ios::trunc);
  if (!out) return false;
  out << "pieces=" << stats.pieces << '\n';
  out << "loaded=" << stats.files_loaded << '\n';
  out << "failed=" << stats.files_failed << '\n';
  for (const auto& line : stats.errors) out << line << '\n';
  return static_cast<bool>(out);
}

bool read_cache_sidecar(std::uint64_t hash, cache_stats_t& stats) {
  std::ifstream in(disk_cache_errors_path(hash));
  if (!in) return false;
  std::string line;
  if (!std::getline(in, line) || line.rfind("pieces=", 0) != 0) return false;
  stats.pieces = static_cast<std::size_t>(std::strtoull(line.c_str() + 7, nullptr, 10));
  if (stats.pieces == 0) return false;
  if (!std::getline(in, line) || line.rfind("loaded=", 0) != 0) return false;
  stats.files_loaded = static_cast<std::size_t>(std::strtoull(line.c_str() + 7, nullptr, 10));
  if (!std::getline(in, line) || line.rfind("failed=", 0) != 0) return false;
  stats.files_failed = static_cast<std::size_t>(std::strtoull(line.c_str() + 7, nullptr, 10));
  while (std::getline(in, line)) {
    if (!line.empty()) stats.errors.push_back(std::move(line));
  }
  return true;
}

// --- is__elf external mode ----------------------------------------------------
//
// The kept sets contain both patterns:
//   * files that reference `is__elf` without shipping a definition (they
//     expect a loader-defined external), and
//   * files that define `rule is__elf` themselves (directly or through an
//     include), which collide with a same-named external
//     ("duplicated identifier").
// The mode is decided statically per file: definition text present, or
// reachable through includes -> compile WITHOUT the external; a bare
// reference -> compile WITH is__elf=false (PE target).

bool defines_elf_identifier(const std::string& text) {
  const std::string needle = "is__elf";
  const auto ident_char = [](char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '_';
  };
  std::size_t pos = 0;
  while ((pos = text.find(needle, pos)) != std::string::npos) {
    const bool boundary_before =
        pos == 0 || !ident_char(text[pos - 1]);
    const bool boundary_after =
        pos + needle.size() >= text.size() || !ident_char(text[pos + needle.size()]);
    if (boundary_before && boundary_after) {
      // Walk back over whitespace: the declaration keyword `rule` must
      // directly precede the identifier (`private rule`/`global rule` too).
      std::size_t i = pos;
      while (i > 0 && (text[i - 1] == ' ' || text[i - 1] == '\t' ||
                       text[i - 1] == '\r' || text[i - 1] == '\n'))
        --i;
      if (i >= 4 && text.compare(i - 4, 4, "rule") == 0 &&
          (i == 4 || !ident_char(text[i - 5])))
        return true;
    }
    pos += needle.size();
  }
  return false;
}

// Collect `include "..."` targets of a rule file (best effort).
std::vector<std::string> include_directives(const std::string& text) {
  std::vector<std::string> out;
  const std::string needle = "include";
  std::size_t pos = 0;
  while ((pos = text.find(needle, pos)) != std::string::npos) {
    const std::size_t quote = text.find('"', pos + needle.size());
    if (quote == std::string::npos) break;
    const std::size_t end = text.find('"', quote + 1);
    if (end == std::string::npos) break;
    out.push_back(text.substr(quote + 1, end - quote - 1));
    pos = end + 1;
  }
  return out;
}

bool read_text_file(const std::filesystem::path& path, std::string& out) {
  std::ifstream in(path, std::ios::binary);
  if (!in) return false;
  std::ostringstream buffer;
  buffer << in.rdbuf();
  out = buffer.str();
  return true;
}

// Does the file, or its transitive includes, declare `rule is__elf`?
bool closure_defines_elf(const std::filesystem::path& file,
                         const std::string& include_root, int depth,
                         std::unordered_map<std::string, bool>& cache) {
  if (depth <= 0) return false;
  const std::string key = file.generic_string();
  const auto cached = cache.find(key);
  if (cached != cache.end()) return cached->second;

  std::string text;
  bool found = false;
  if (read_text_file(file, text)) {
    if (defines_elf_identifier(text)) {
      found = true;
    } else {
      for (const auto& include_name : include_directives(text)) {
        std::filesystem::path target(include_name);
        if (target.is_relative()) {
          std::error_code ec;
          const std::filesystem::path from_parent =
              file.parent_path() / target;
          if (std::filesystem::is_regular_file(from_parent, ec))
            target = from_parent;
          else
            target = std::filesystem::path(include_root) / include_name;
        }
        std::error_code ec;
        if (std::filesystem::is_regular_file(target, ec) &&
            closure_defines_elf(target, include_root, depth - 1, cache)) {
          found = true;
          break;
        }
      }
    }
  }
  cache[key] = found;
  return found;
}

// True when the file must be compiled WITH the is__elf external.
bool file_needs_elf_external(const std::filesystem::path& file,
                             const std::string& include_root,
                             std::unordered_map<std::string, bool>& cache) {
  std::string text;
  if (!read_text_file(file, text)) return false;
  if (text.find("is__elf") == std::string::npos) return false;
  if (defines_elf_identifier(text)) return false;
  return !closure_defines_elf(file, include_root, 5, cache);
}

// --- chunk compilation ---------------------------------------------------------

struct chunk_result_t {
  // One or two compiled pieces per chunk: mode A (no external) and, when
  // the chunk holds files that reference `is__elf`, mode B (external
  // defined as false — PE target).
  std::vector<YR_RULES*> rules;
  std::vector<std::string> errors;
  std::size_t files_loaded = 0;
  std::size_t files_failed = 0;
  std::unordered_map<std::string, std::string> ns_to_set;
};

// Compile `files` into one YR_RULES. Returns nullptr as soon as a file
// produces an error (libyara forbids add_file after an error); on failure
// `out_clean` holds the files verified clean before the failure.
YR_RULES* try_compile(const std::filesystem::path& rules_dir,
                      const std::vector<std::filesystem::path>& files,
                      std::vector<std::string>& errors,
                      std::unordered_map<std::string, std::string>* ns_to_set,
                      std::vector<std::filesystem::path>* out_clean,
                      bool with_elf_external) {
  YR_COMPILER* compiler = nullptr;
  const int compiler_error = yr_compiler_create(&compiler);
  if (compiler_error != ERROR_SUCCESS || !compiler) {
    errors.push_back("yr_compiler_create failed with error " +
                     std::to_string(compiler_error));
    return nullptr;
  }
  std::size_t attempt_errors = 0;
  std::size_t current_file_errors = 0;
  error_sink_t sink{&errors, &attempt_errors, &current_file_errors};
  yr_compiler_set_callback(compiler, compiler_message, &sink);
  yr_compiler_set_include_callback(compiler, resolve_include, include_free,
                                   nullptr);
  if (with_elf_external) {
    // Mode B: the file references `is__elf` but ships no definition, so
    // supply the loader external (always false for a PE target).
    yr_compiler_define_boolean_variable(compiler, "is__elf", 0);
  }
  for (const auto& file : files) {
    const std::filesystem::path rel = rel_to_root(file, rules_dir);
    const std::string set = rule_set_of(rel);
    const std::string ns = make_namespace(set, rel.generic_string());

    std::FILE* handle = std::fopen(file.string().c_str(), "rb");
    if (!handle) {
      errors.push_back(rule_error(file, "could not open rule file"));
      yr_compiler_destroy(compiler);
      return nullptr;
    }
    current_file_errors = 0;
    const int add_error = yr_compiler_add_file(compiler, handle, ns.c_str(),
                                              file.string().c_str());
    std::fclose(handle);
    if (current_file_errors > 0 || add_error > 0) {
      if (current_file_errors == 0) {
        char message[512]{};
        yr_compiler_get_error_message(compiler, message, sizeof(message));
        errors.push_back(rule_error(
            file, message[0] ? message : "rule compilation failed"));
      }
      yr_compiler_destroy(compiler);
      return nullptr;
    }
    if (out_clean) out_clean->push_back(file);
    if (ns_to_set) ns_to_set->emplace(ns, set);
  }

  YR_RULES* rules = nullptr;
  const int get_rules_error = yr_compiler_get_rules(compiler, &rules);
  yr_compiler_destroy(compiler);
  if (get_rules_error != ERROR_SUCCESS || !rules) {
    errors.push_back("yr_compiler_get_rules failed with error " +
                     std::to_string(get_rules_error));
    return nullptr;
  }
  return rules;
}

// Assemble `files` in one external mode: optimistic compile first (the
// common case after static mode detection), and if libyara reports any
// error, classify each file with throwaway compilers (trying the other
// external mode as a safety net), then reassemble the clean groups —
// without poisoning the rest of the chunk. Compiled pieces are appended
// to `out.rules`; counters/errors land in `out`.
void assemble_group(const std::filesystem::path& rules_dir,
                    const std::vector<std::filesystem::path>& files,
                    bool with_elf_external, chunk_result_t& out) {
  if (files.empty()) return;
  std::vector<std::string> errors;
  YR_RULES* rules =
      try_compile(rules_dir, files, errors, &out.ns_to_set, nullptr,
                  with_elf_external);
  if (rules) {
    out.rules.push_back(rules);
    out.files_loaded += files.size();
    return;
  }

  // Optimistic attempt failed: discard its error lines and classify each
  // file with its own compiler (classify uses identical inputs, so the
  // reassembly below is guaranteed to be clean).
  std::vector<std::filesystem::path> clean;
  std::vector<std::filesystem::path> flipped;
  clean.reserve(files.size());
  for (const auto& file : files) {
    std::vector<std::string> file_errors;
    std::vector<std::filesystem::path> one{file};
    YR_RULES* probe =
        try_compile(rules_dir, one, file_errors, nullptr, nullptr,
                    with_elf_external);
    bool used_mode = with_elf_external;
    if (!probe && !with_elf_external) {
      // Static analysis said "no external", but the compile disagrees:
      // try the other mode before dropping the file.
      file_errors.clear();
      probe = try_compile(rules_dir, one, file_errors, nullptr, nullptr, true);
      if (probe) used_mode = true;
    }
    if (probe) {
      yr_rules_destroy(probe);
      (used_mode == with_elf_external ? clean : flipped).push_back(file);
    } else {
      ++out.files_failed;
      out.errors.insert(out.errors.end(), file_errors.begin(), file_errors.end());
      if (file_errors.empty())
        out.errors.push_back(rule_error(file, "rule compilation failed"));
    }
  }

  if (!clean.empty()) {
    if (YR_RULES* reassembled = try_compile(rules_dir, clean, out.errors,
                                            &out.ns_to_set, nullptr,
                                            with_elf_external)) {
      out.rules.push_back(reassembled);
      out.files_loaded += clean.size();
    } else {
      out.files_failed += clean.size();
    }
  }
  if (!flipped.empty()) {
    // Files that only compile in the other external mode: assemble them
    // in that mode (group A flips to with-external; unreachable for the
    // group already compiled with the external).
    if (YR_RULES* other = try_compile(rules_dir, flipped, out.errors,
                                      &out.ns_to_set, nullptr,
                                      !with_elf_external)) {
      out.rules.push_back(other);
      out.files_loaded += flipped.size();
    } else {
      out.files_failed += flipped.size();
    }
  }
}

// One chunk of the rule set: mode-A files and mode-B files, each assembled
// independently so a per-file external mode conflict never leaks across
// groups.
void compile_chunk(const std::filesystem::path& rules_dir,
                   const std::vector<std::filesystem::path>& files,
                   const std::vector<std::filesystem::path>& files_with_external,
                   chunk_result_t& out) {
  assemble_group(rules_dir, files, false, out);
  assemble_group(rules_dir, files_with_external, true, out);
}

// Compile the whole set: chunks in parallel, results merged deterministically
// in chunk order.
std::unique_ptr<compiled_set_t> compile_rule_set(
    const std::filesystem::path& rules_dir,
    const std::vector<std::filesystem::path>& kept,
    std::uint64_t hash, std::size_t chunks) {
  auto entry = std::make_unique<compiled_set_t>();
  entry->hash = hash;
  entry->compiled_here = true;

  g_include_root = rules_dir.generic_string();
  struct root_guard_t {
    ~root_guard_t() { g_include_root.clear(); }
  } root_guard;

  const auto started = std::chrono::steady_clock::now();

  // Static per-file external mode: most files read "is__elf" nowhere and
  // land in mode A; bare references (no definition in the include closure)
  // go to mode B. Strided across the same worker layout as the compile
  // pool, so each chunk's two groups are built directly.
  std::vector<std::vector<std::filesystem::path>> parts(chunks);
  std::vector<std::vector<std::filesystem::path>> parts_with_external(chunks);
  {
    const std::string include_root = rules_dir.generic_string();
    std::vector<std::thread> pool;
    pool.reserve(chunks);
    for (std::size_t worker = 0; worker < chunks; ++worker) {
      pool.emplace_back([&, worker] {
        std::unordered_map<std::string, bool> cache;
        for (std::size_t i = worker; i < kept.size(); i += chunks) {
          if (file_needs_elf_external(kept[i], include_root, cache))
            parts_with_external[worker].push_back(kept[i]);
          else
            parts[worker].push_back(kept[i]);
        }
      });
    }
    for (std::thread& thread : pool) thread.join();
  }
  std::vector<chunk_result_t> results(chunks);

  std::atomic<std::size_t> next{0};
  std::vector<std::thread> pool;
  pool.reserve(chunks);
  for (std::size_t worker = 0; worker < chunks; ++worker) {
    pool.emplace_back([&] {
      for (;;) {
        const std::size_t index = next.fetch_add(1, std::memory_order_relaxed);
        if (index >= chunks) return;
        compile_chunk(rules_dir, parts[index], parts_with_external[index],
                      results[index]);
      }
    });
  }
  for (std::thread& thread : pool) thread.join();

  for (chunk_result_t& chunk : results) {
    entry->files_loaded += chunk.files_loaded;
    entry->files_failed += chunk.files_failed;
    entry->errors.insert(entry->errors.end(), chunk.errors.begin(),
                         chunk.errors.end());
    for (YR_RULES* rules : chunk.rules) entry->rules.push_back(rules);
    for (auto& [ns, set] : chunk.ns_to_set)
      entry->ns_to_set.emplace(std::move(ns), std::move(set));
  }
  if (entry->files_loaded > 0 && entry->files_loaded + entry->files_failed != kept.size()) {
    // Files that failed inside try_compile before the classify pass counted
    // twice; clamp the invariant for the report.
    entry->files_failed = kept.size() - entry->files_loaded;
  }
  entry->compile_seconds =
      std::chrono::duration<double>(std::chrono::steady_clock::now() - started).count();

  if (entry->rules.empty() || entry->files_loaded == 0) {
    if (entry->errors.empty())
      entry->errors.push_back("no rule file survived compilation");
    entry->files_loaded = 0;
    return entry;
  }
  LOG_DEBUG("yara: compiled {}/{} file(s) in {} chunk(s), {} with errors",
            entry->files_loaded, kept.size(), entry->rules.size(),
            entry->files_failed);

  // Best-effort disk cache: next run of this rule-set hash skips the compile.
  if (std::error_code ec; !std::filesystem::exists("logs", ec)) {
    std::filesystem::create_directories("logs", ec);
  }
  {
    // Chunk caches are tens of MB each; write them in parallel so the
    // one-time compile run does not pay a serial 75 MB write.
    std::vector<std::thread> pool;
    pool.reserve(entry->rules.size());
    for (std::size_t i = 0; i < entry->rules.size(); ++i) {
      pool.emplace_back([&, i] {
        const auto cache_path = disk_cache_path(hash, i);
        if (yr_rules_save(entry->rules[i], cache_path.string().c_str()) !=
            ERROR_SUCCESS) {
          LOG_DEBUG("yara: could not save rule cache to {}", cache_path.string());
        }
      });
    }
    for (std::thread& thread : pool) thread.join();
  }
  cache_stats_t stats;
  stats.pieces = entry->rules.size();
  stats.files_loaded = entry->files_loaded;
  stats.files_failed = entry->files_failed;
  stats.errors = entry->errors;
  write_cache_sidecar(hash, stats);
  return entry;
}

// Load a previously compiled rule set from logs/yara_rules_<hash>_c<i>.cache.
// The sidecar names the exact piece count (chunks may compile into one or
// two pieces depending on the is__elf external mode split).
std::unique_ptr<compiled_set_t> load_from_disk(
    std::uint64_t hash, std::size_t chunks,
    const std::vector<std::filesystem::path>& kept,
    const std::vector<std::filesystem::path>& all,
    const std::unordered_map<std::string, std::string>& ns_to_set) {
  std::error_code ec;
  cache_stats_t stats;
  if (!read_cache_sidecar(hash, stats)) return nullptr;
  const std::size_t count = stats.pieces;

  // All piece files must exist; a gap means a truncated save.
  for (std::size_t i = 0; i < count; ++i) {
    if (!std::filesystem::is_regular_file(disk_cache_path(hash, i), ec)) {
      LOG_DEBUG("yara: rule cache piece {} missing ({} expected), recompiling",
                i, count);
      return nullptr;
    }
  }

  // Deserialize the piece caches in parallel: each file is tens of MB and
  // yr_rules_load rebuilds the compiled automaton, so serial loading was
  // the dominant cost of a disk-cache run.
  std::vector<YR_RULES*> rules(count, nullptr);
  std::atomic<std::size_t> next_load{0};
  std::atomic<bool> failed{false};
  {
    std::vector<std::thread> pool;
    pool.reserve(count);
    for (std::size_t worker = 0; worker < count; ++worker) {
      pool.emplace_back([&] {
        for (;;) {
          const std::size_t i = next_load.fetch_add(1, std::memory_order_relaxed);
          if (i >= count) return;
          YR_RULES* loaded = nullptr;
          const auto cache_path = disk_cache_path(hash, i);
          if (yr_rules_load(cache_path.string().c_str(), &loaded) != ERROR_SUCCESS ||
              !loaded) {
            LOG_DEBUG("yara: rule cache {} failed to load, recompiling",
                      cache_path.string());
            failed.store(true, std::memory_order_relaxed);
            continue;
          }
          rules[i] = loaded;
        }
      });
    }
    for (std::thread& thread : pool) thread.join();
  }

  if (failed.load(std::memory_order_relaxed)) {
    // Corrupt or incompatible cache (e.g. libyara upgrade): drop all
    // pieces and recompile.
    for (YR_RULES* r : rules)
      if (r) yr_rules_destroy(r);
    for (std::size_t j = 0; j < count; ++j)
      std::filesystem::remove(disk_cache_path(hash, j), ec);
    std::filesystem::remove(disk_cache_errors_path(hash), ec);
    return nullptr;
  }

  auto entry = std::make_unique<compiled_set_t>();
  entry->hash = hash;
  entry->rules = std::move(rules);
  entry->compiled_here = false;
  entry->ns_to_set = ns_to_set;
  entry->files_loaded = stats.files_loaded;
  entry->files_failed = stats.files_failed;
  entry->errors = std::move(stats.errors);
  (void)chunks;
  (void)kept;
  (void)all;
  return entry;
}

// --- error log ----------------------------------------------------------------

const char* kErrorLogPath = "logs/yara_errors.log";

void write_error_log(const std::filesystem::path& rules_dir, std::uint64_t hash,
                     const std::vector<std::string>& errors) {
  std::error_code ec;
  std::filesystem::create_directories("logs", ec);
  std::ofstream out(kErrorLogPath, std::ios::trunc);
  if (!out) {
    LOG_WARN("yara: cannot write {}", kErrorLogPath);
    return;
  }
  const std::time_t now = std::time(nullptr);
  char stamp[32]{};
  std::tm tm_snapshot{};
#ifdef _WIN32
  gmtime_s(&tm_snapshot, &now);
#else
  gmtime_r(&now, &tm_snapshot);
#endif
  std::strftime(stamp, sizeof(stamp), "%Y-%m-%dT%H:%M:%SZ", &tm_snapshot);
  out << "# yara compile errors\n"
      << "# generated: " << stamp << '\n'
      << "# rules directory: " << rules_dir.generic_string() << '\n'
      << "# rule-set hash: " << hex16(hash) << '\n';
  for (const auto& line : errors) out << line << '\n';
  LOG_INFO("yara: {} compile error(s) written to {}", errors.size(), kErrorLogPath);
}

}  // namespace

// --- public entry point -------------------------------------------------------

bool scan_pe(result_t& result, const analyzer::file_info_t& info,
             const std::filesystem::path& requested_directory) {
  result = {};
  result.applicable = info.type.executable_type.find("PE") != std::string::npos;
  result.attempted = true;
  if (!result.applicable) return true;

  const std::filesystem::path default_rules_dir =
      std::filesystem::path(STATIC_ANALYZER_SOURCE_DIR) / "yara-rules";
  std::filesystem::path rules_dir = requested_directory;
  if (rules_dir.empty()) {
    const char* override_dir = std::getenv("YARA_RULES_DIR");
    std::error_code override_ec;
    if (override_dir && *override_dir &&
        std::filesystem::is_directory(override_dir, override_ec)) {
      rules_dir = std::filesystem::path(override_dir);
    } else {
      rules_dir = default_rules_dir;
    }
  }
  result.rules_directory = rules_dir.string();

  const auto started = std::chrono::steady_clock::now();
  ensure_yara_initialized();

  // The compiled rule set is shared through the cache; serialize entry so
  // concurrent scan_pe calls cannot race the cache or the shared state.
  std::lock_guard<std::mutex> lock(g_scan_mutex);

  std::size_t found = 0;
  const auto all_files = rglob_rule_files(rules_dir, found);
  result.rule_files_found = found;
  if (all_files.empty()) {
    result.errors.push_back(
        rule_error(rules_dir, "no .yar or .yara rule files found"));
    return false;
  }

  // Hygiene filter: drop trees that cannot apply to a PE target or that
  // duplicate rules compiled elsewhere in the tree.
  std::vector<std::filesystem::path> kept;
  kept.reserve(all_files.size());
  skip_stats_t skip;
  for (const auto& file : all_files) {
    const std::filesystem::path rel = rel_to_root(file, rules_dir);
    const std::string rel_lower = lower(rel.generic_string());
    const std::string name_lower = lower(rel.filename().string());
    if (is_excluded("/" + rel_lower, name_lower, skip)) continue;
    kept.push_back(file);
  }
  result.rule_files_skipped = skip.total();
  if (kept.empty()) {
    result.errors.push_back(
        rule_error(rules_dir, "every rule file was excluded by the hygiene filters"));
    return false;
  }

  const std::size_t chunks = choose_chunks(kept.size());
  result.worker_threads = chunks;
  const std::uint64_t hash =
      hash_rule_set(rules_dir.generic_string(), kept, all_files, chunks);

  // namespace -> set map for the current file list; matches are enriched
  // from it after the scan (identical across cache generations for this hash).
  std::unordered_map<std::string, std::string> ns_to_set;
  for (const auto& file : kept) {
    const std::filesystem::path rel = rel_to_root(file, rules_dir);
    const std::string set = rule_set_of(rel);
    ns_to_set.emplace(make_namespace(set, rel.generic_string()), set);
  }

  compiled_set_t* entry = nullptr;
  double load_seconds = 0.0;
  auto memory_it = g_cache.find(hash);
  if (memory_it != g_cache.end()) {
    entry = memory_it->second.get();
    result.memory_cache_hit = true;
  } else {
    const auto load_started = std::chrono::steady_clock::now();
    auto loaded = load_from_disk(hash, chunks, kept, all_files, ns_to_set);
    load_seconds =
        std::chrono::duration<double>(std::chrono::steady_clock::now() - load_started).count();
    if (loaded) {
      result.disk_cache_hit = true;
      entry = loaded.get();
      g_cache.emplace(hash, std::move(loaded));
    } else {
      auto compiled = compile_rule_set(rules_dir, kept, hash, chunks);
      if (!compiled || compiled->rules.empty()) {
        if (compiled) result.errors = std::move(compiled->errors);
        result.exit_code = ERROR_INVALID_FILE;
        return false;
      }
      if (!compiled->errors.empty())
        write_error_log(rules_dir, hash, compiled->errors);
      entry = compiled.get();
      g_cache.emplace(hash, std::move(compiled));
    }
  }
  result.compile_seconds = entry->compile_seconds;
  if (entry->errors.empty()) {
    // A previous rule-set generation may have left a stale log behind.
    std::error_code ec;
    std::filesystem::remove(kErrorLogPath, ec);
  }

  // --- scan: every chunk, in parallel, matches merged in chunk order -------
  std::vector<std::vector<rule_match_t>> chunk_matches(entry->rules.size());
  std::vector<std::string> scan_errors(entry->rules.size());
  double scan_pool_seconds = 0.0;
  {
    const auto scan_started = std::chrono::steady_clock::now();
    std::vector<std::thread> pool;
    pool.reserve(entry->rules.size());
    for (std::size_t i = 0; i < entry->rules.size(); ++i) {
      pool.emplace_back([&, i] {
        scan_sink_t sink;
        sink.matches = &chunk_matches[i];
        const int rc = yr_rules_scan_file(entry->rules[i], info.filepath.c_str(),
                                          0, scan_callback, &sink, 0);
        if (rc != ERROR_SUCCESS)
          scan_errors[i] = "YARA scan failed with error " + std::to_string(rc);
      });
    }
    for (std::thread& thread : pool) thread.join();
    scan_pool_seconds =
        std::chrono::duration<double>(std::chrono::steady_clock::now() - scan_started).count();
  }

  std::vector<rule_match_t> raw_matches;
  for (auto& part : chunk_matches)
    raw_matches.insert(raw_matches.end(),
                       std::make_move_iterator(part.begin()),
                       std::make_move_iterator(part.end()));

  // Enrich with set/quality attribution, then dedupe by (namespace, rule).
  std::unordered_set<std::string> seen;
  result.matches.reserve(raw_matches.size());
  for (auto& match : raw_matches) {
    const auto set_it = entry->ns_to_set.find(match.ns);
    const std::string set = set_it != entry->ns_to_set.end() ? set_it->second : "unknown";
    match.rule_set = set;
    const quality_t quality = quality_of(set);
    match.quality = quality.tier;
    match.weight = quality.weight;

    const std::string key = match.ns + '\x1f' + match.identifier;
    if (!seen.insert(key).second) {
      ++result.rules_deduped;
      continue;
    }
    result.matches.push_back(std::move(match));
  }
  // Stable output regardless of thread completion order.
  std::sort(result.matches.begin(), result.matches.end(),
            [](const rule_match_t& a, const rule_match_t& b) {
              if (a.rule_set != b.rule_set) return a.rule_set < b.rule_set;
              return a.identifier < b.identifier;
            });
  result.rules_matched = result.matches.size();

  result.available = true;
  result.scan_ok = true;
  for (const auto& message : scan_errors) {
    if (message.empty()) continue;
    result.scan_ok = false;
    result.errors.push_back(message);
  }
  result.exit_code = result.scan_ok ? ERROR_SUCCESS : ERROR_COULD_NOT_MAP_FILE;

  // --- bookkeeping ----------------------------------------------------------
  result.rule_files_loaded = entry->files_loaded;
  result.rule_files_failed = entry->files_failed;
  result.compile_errors = entry->errors.size();

  const std::size_t kMaxErrorSamples = 4;
  for (std::size_t i = 0; i < entry->errors.size() && i < kMaxErrorSamples; ++i)
    result.errors.push_back(entry->errors[i]);
  if (!entry->errors.empty()) {
    result.errors_log = kErrorLogPath;
    result.errors.push_back(std::to_string(entry->errors.size()) +
                            " compile error(s) - full list in " + kErrorLogPath);
  }

  if (result.rule_files_loaded == 0) {
    result.exit_code =
        result.exit_code == ERROR_SUCCESS ? ERROR_INVALID_FILE : result.exit_code;
    result.scan_ok = false;
  }

  const double total_seconds =
      std::chrono::duration<double>(std::chrono::steady_clock::now() - started).count();
  result.seconds = total_seconds;

  // One-line console summary (requirement: compile errors surface as a
  // single line pointing at logs/yara_errors.log, not 400 bullets).
  {
    std::ostringstream line;
    line << "[yara] " << result.rule_files_loaded << '/' << result.rule_files_found
         << " file(s)";
    if (result.rule_files_skipped)
      line << ", " << result.rule_files_skipped << " skipped (deprecated/"
           << "android/elf/mirror/index)";
    line << ", " << result.rules_matched << " match(es)";
    if (result.rules_deduped) line << " (" << result.rules_deduped << " duplicate dropped)";
    line << ", " << result.compile_errors << " compile error(s)";
    if (result.compile_errors) line << " -> " << kErrorLogPath;
    line << std::fixed << std::setprecision(2) << ", compile " << result.compile_seconds
         << "s [" << (result.memory_cache_hit   ? "memory cache"
                      : result.disk_cache_hit ? "disk cache"
                                              : "compiled")
         << "], load " << load_seconds << "s, scan " << scan_pool_seconds << "s ("
         << total_seconds << "s total)";
    const bool has_errors = result.compile_errors > 0;
    std::cout << console::paint(has_errors ? console::yellow : console::green,
                                line.str())
              << '\n';
    LOG_INFO("{}", line.str());
  }

  if (skip.total() > 0) {
    LOG_DEBUG(
        "yara: hygiene skips: mirror={}, deprecated={}, android={}, index={}, elf={}",
        skip.mirror, skip.deprecated, skip.android, skip.index, skip.elf);
  }
  return result.scan_ok;
}

}  // namespace yara_scanner
