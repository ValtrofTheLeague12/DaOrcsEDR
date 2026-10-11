// yara_scanner.hpp — libyara rule scanning for PE files.
#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

#include "file_analyzer.hpp"

namespace yara_scanner {

struct string_match_t {
  std::string identifier;
  std::vector<std::int64_t> offsets;
};

struct rule_match_t {
  std::string identifier;
  std::string tags;
  // Compile namespace of the matched rule: unique per rule file, built as
  // "<set>__<sanitised relative path>". Two rules with the same identifier
  // from different sets keep different namespaces.
  std::string ns;
  // Top-level rule set directory (CDI_yara, fsYara, ...) the file came from.
  std::string rule_set;
  // "curated" for vetted vendor/research packs, "community" for community
  // aggregations (higher FP rate). Weight is the scoring multiplier:
  // curated = 1.0, community = 0.5.
  std::string quality;
  double weight = 1.0;
  std::vector<string_match_t> strings;
};

struct result_t {
  bool attempted = false;
  bool applicable = false;
  bool available = false;
  bool scan_ok = false;
  int exit_code = -1;
  double seconds = 0.0;
  std::size_t rule_files_found = 0;
  std::size_t rule_files_loaded = 0;
  std::size_t rule_files_failed = 0;
  // Files excluded by the hygiene filters (deprecated/Android/ELF trees,
  // mirror copies, aggregator index files).
  std::size_t rule_files_skipped = 0;
  std::size_t rules_matched = 0;
  // Duplicate (namespace, rule) matches dropped after the scan.
  std::size_t rules_deduped = 0;
  // Total YARA compiler error messages emitted during the last compile.
  std::size_t compile_errors = 0;
  std::size_t worker_threads = 0;
  // Compile cache state: memory = reused in-process, disk = loaded from
  // logs/yara_rules_<hash>.cache, miss = compiled from source this run.
  bool memory_cache_hit = false;
  bool disk_cache_hit = false;
  double compile_seconds = 0.0;
  // logs/yara_errors.log when compile_errors > 0 ("" otherwise).
  std::string errors_log;
  std::string rules_directory;
  std::vector<rule_match_t> matches;
  // Capped summary (first few lines + a pointer to errors_log); the full
  // compiler output lives in errors_log, not here.
  std::vector<std::string> errors;
};

// The default directory is the project's yara-rules folder, or YARA_RULES_DIR.
bool scan_pe(result_t& result,
             const analyzer::file_info_t& info,
             const std::filesystem::path& rules_directory = {});

}  // namespace yara_scanner
