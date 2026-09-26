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
  std::size_t rules_matched = 0;
  std::size_t worker_threads = 0;
  std::string rules_directory;
  std::vector<rule_match_t> matches;
  std::vector<std::string> errors;
};

// The default directory is the project's yara-rules folder, or YARA_RULES_DIR.
bool scan_pe(result_t& result,
             const analyzer::file_info_t& info,
             const std::filesystem::path& rules_directory = {});

}  // namespace yara_scanner
