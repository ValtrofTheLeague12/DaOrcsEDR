#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace capa {

enum class status {
  ok,
  file_missing,
  not_found,
  launch_failed,
  timed_out,
  output_too_large,
  exit_error,
  bad_output,
  rules_missing,      // options.rules_dir was set but does not exist
};

const char* to_string(status s);

struct options {
  std::string executable = "C:/Users/The4thReich/Desktop/IAProject/capa-exec/capa.exe";
  std::string rules_dir = "C:/Users/The4thReich/Desktop/IAProject/capa-rules";
  std::string signatures_dir;
  std::string backend;
  std::string format;
  std::string os;
  std::vector<std::string> tags;          
  std::vector<std::string> extra_args;    // appended verbatim before the sample path

  
  std::chrono::seconds timeout{600};       
  std::chrono::seconds large_timeout{1800}; 

  std::size_t max_stdout_bytes = 512u * 1024u * 1024u;
  bool low_priority = true;               // run capa below normal priority

  bool include_library_rules = false;     // keep rules flagged `lib: true` in the results
  std::size_t max_addresses = 32;         // match addresses stored per capability

  // On-disk cache of the (filtered) result document. Empty = disabled.
  // The key covers the sample (path, size, mtime), the capa executable, and every
  // option above; put rule/signature versions in cache_salt when you update them.
  std::string cache_dir;
  std::string cache_salt;

  bool keep_raw_json = false;             // keep capa's raw stdout in report_t::raw_json

  // When true, analyze_file() refuses to run if rules_dir is non-empty and does
  // not point at an existing directory. Set to false to let capa try anyway.
  bool require_rules_dir = true;
};

struct attack_t {
  std::string tactic;
  std::string technique;
  std::string subtechnique;
  std::string id;
};

struct mbc_t {
  std::string objective;
  std::string behavior;       // "Allocate Memory"
  std::string method;         // "" or a method name
  std::string id;             // "C0007"
};

struct capability_t {
  std::string name;               // "allocate or change RWX memory"
  std::string namespace_path;     // "host-interaction/process/inject"
  std::string scope;              // "file", "function", "basic block", "instruction", ...
  std::string description;
  std::vector<attack_t> attack;
  std::vector<mbc_t>    mbc;
  std::size_t match_count = 0;
  std::vector<std::uint64_t> addresses;   // first options::max_addresses (static analysis)
  bool library = false;                   // a `lib: true` rule (only kept on request)
};

struct report_t {
  status      st        = status::launch_failed;
  int         exit_code = 0;
  std::string error;                
  std::string stderr_tail;         
  std::vector<std::string> warnings;

  std::string capa_version;
  std::string flavor;                
  std::string md5, sha1, sha256;
  std::string format;                
  std::string arch;                 
  std::string os;
  std::string backend;               // capa's feature extractor, e.g. VivisectFeatureExtractor

  std::size_t rules_matched = 0;     // all matched rules, libraries included
  std::size_t library_rules = 0;
  std::vector<capability_t> capabilities;   // sorted by namespace, then name

  bool        from_cache = false;
  double      seconds    = 0.0;      // wall clock (capa run, or cache read)
  std::string command_line;          // what was executed (for logs)
  std::string raw_json;              // only with options::keep_raw_json

  bool ok() const { return st == status::ok; }
};

// Runs capa on `sample` (blocking). Never throws.
report_t analyze_file(const std::string& sample, const options& opts = {});

report_t parse_json(std::string_view json_text, const options& opts = {});

std::string find_executable(const options& opts = {});

std::string describe_exit_code(int exit_code);

bool rules_dir_exists(const options& opts = {});

bool self_check(const options& opts = {}, const std::string& sample = {});

std::vector<std::string> attack_ids(const report_t& report);
std::vector<std::string> mbc_ids(const report_t& report);
std::vector<std::string> namespaces(const report_t& report);
std::vector<std::pair<std::string, std::size_t>> capabilities_by_category(const report_t& report);

}  // namespace capa