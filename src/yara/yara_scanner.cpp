// yara_scanner.cpp — libyara integration.
#include "yara_scanner.hpp"

#include <yara.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cctype>
#include <cstdlib>
#include <sstream>
#include <system_error>
#include <thread>

namespace yara_scanner {
namespace {

std::string lower(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  return value;
}

std::string rule_error(const std::filesystem::path& path, const std::string& message) {
  return path.string() + ": " + message;
}

void compiler_message(int level, const char* file_name, int line_number,
                      const YR_RULE*, const char* message, void* user_data) {
  if (!user_data || level != YARA_ERROR_LEVEL_ERROR) return;
  auto* errors = static_cast<std::vector<std::string>*>(user_data);
  std::ostringstream out;
  if (file_name) out << file_name << ':' << line_number << ": ";
  out << (message ? message : "YARA compilation error");
  errors->push_back(out.str());
}

int scan_callback(YR_SCAN_CONTEXT* context, int message, void* message_data,
                  void* user_data) {
  if (message != CALLBACK_MSG_RULE_MATCHING || !message_data || !user_data)
    return CALLBACK_CONTINUE;
  auto* result = static_cast<result_t*>(user_data);
  auto* rule = static_cast<YR_RULE*>(message_data);
  rule_match_t match;
  match.identifier = rule->identifier ? rule->identifier : "<unnamed rule>";
  match.tags = rule->tags ? rule->tags : "";

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
  result->matches.push_back(std::move(match));
  return CALLBACK_CONTINUE;
}

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
             ? read_rule_file(include_path) : nullptr;
  }
  if (calling_rule_filename && *calling_rule_filename) {
    const std::filesystem::path candidate =
        std::filesystem::path(calling_rule_filename).parent_path() / include_path;
    if (std::filesystem::is_regular_file(candidate, ec)) return read_rule_file(candidate);
  }
  return nullptr;
}

struct file_scan_t {
  std::filesystem::path path;
  result_t result;
};

void scan_one_file(const std::filesystem::path& path,
                   const std::string& target, file_scan_t& output) {
  output.path = path;
  output.result.attempted = true;
  output.result.applicable = true;
  output.result.rules_directory = path.parent_path().string();

  YR_COMPILER* compiler = nullptr;
  const int compiler_error = yr_compiler_create(&compiler);
  if (compiler_error != ERROR_SUCCESS || !compiler) {
    output.result.errors.push_back("yr_compiler_create failed with error " +
                                   std::to_string(compiler_error));
    output.result.exit_code = compiler_error;
    return;
  }
  yr_compiler_set_callback(compiler, compiler_message, &output.result.errors);
  yr_compiler_set_include_callback(compiler, resolve_include, include_free, nullptr);

  std::FILE* file = std::fopen(path.string().c_str(), "rb");
  if (!file) {
    output.result.errors.push_back(rule_error(path, "could not open rule file"));
    output.result.exit_code = ERROR_COULD_NOT_OPEN_FILE;
    yr_compiler_destroy(compiler);
    return;
  }
  const int add_error = yr_compiler_add_file(compiler, file, nullptr,
                                             path.string().c_str());
  std::fclose(file);
  if (add_error != ERROR_SUCCESS) {
    char message[512]{};
    yr_compiler_get_error_message(compiler, message, sizeof(message));
    output.result.errors.push_back(rule_error(
        path, message[0] ? message : "rule compilation failed"));
    output.result.exit_code = add_error;
    yr_compiler_destroy(compiler);
    return;
  }
  output.result.rule_files_found = 1;
  output.result.rule_files_loaded = 1;

  YR_RULES* rules = nullptr;
  const int get_rules_error = yr_compiler_get_rules(compiler, &rules);
  if (get_rules_error != ERROR_SUCCESS || !rules) {
    output.result.errors.push_back("yr_compiler_get_rules failed with error " +
                                   std::to_string(get_rules_error));
    output.result.exit_code = get_rules_error;
    yr_compiler_destroy(compiler);
    return;
  }
  output.result.available = true;
  output.result.exit_code = yr_rules_scan_file(rules, target.c_str(), 0,
                                               scan_callback, &output.result, 0);
  output.result.scan_ok = output.result.exit_code == ERROR_SUCCESS;
  output.result.rules_matched = output.result.matches.size();
  if (!output.result.scan_ok)
    output.result.errors.push_back("YARA scan failed with error " +
                                   std::to_string(output.result.exit_code));
  yr_rules_destroy(rules);
  yr_compiler_destroy(compiler);
}

}  // namespace


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
  const auto files = rglob_rule_files(rules_dir, result.rule_files_found);
  if (files.empty()) {
    result.errors.push_back(rule_error(rules_dir, "no .yar or .yara rule files found"));
    return false;
  }

  const auto started = std::chrono::steady_clock::now();
  const int init_error = yr_initialize();
  if (init_error != ERROR_SUCCESS) {
    result.errors.push_back("yr_initialize failed with error " +
                            std::to_string(init_error));
    return false;
  }

  const unsigned int hardware = std::max(1u, std::thread::hardware_concurrency());
  result.worker_threads = std::min<std::size_t>(files.size(),
                                                 std::min<unsigned int>(hardware, 8u));
  std::vector<file_scan_t> outputs(files.size());
  std::atomic<std::size_t> next{0};
  std::vector<std::thread> workers;
  workers.reserve(result.worker_threads);
  for (std::size_t worker = 0; worker < result.worker_threads; ++worker) {
    workers.emplace_back([&] {
      for (;;) {
        const std::size_t index = next.fetch_add(1, std::memory_order_relaxed);
        if (index >= files.size()) return;
        scan_one_file(files[index], info.filepath, outputs[index]);
      }
    });
  }
  for (std::thread& worker : workers) worker.join();

  for (const file_scan_t& output : outputs) {
    result.rule_files_loaded += output.result.rule_files_loaded;
    result.rule_files_failed += output.result.rule_files_failed;
    result.rules_matched += output.result.rules_matched;
    result.matches.insert(result.matches.end(), output.result.matches.begin(),
                          output.result.matches.end());
    result.errors.insert(result.errors.end(), output.result.errors.begin(),
                         output.result.errors.end());
    if (output.result.exit_code != ERROR_SUCCESS && result.exit_code == ERROR_SUCCESS)
      result.exit_code = output.result.exit_code;
    result.available = result.available || output.result.available;
    result.scan_ok = result.scan_ok || output.result.scan_ok;
  }
  if (result.rule_files_loaded == 0) {
    result.exit_code = result.exit_code == ERROR_SUCCESS ? ERROR_INVALID_FILE : result.exit_code;
    result.scan_ok = false;
  } else {
    result.exit_code = ERROR_SUCCESS;
    result.scan_ok = true;
  }
  yr_finalize();
  result.seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - started).count();
  return result.scan_ok;
}

}  // namespace yara_scanner
