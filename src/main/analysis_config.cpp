#include "analysis_config.hpp"

#include "logging.hpp"
#include "redact.hpp"

#include <yaml-cpp/yaml.h>

#include <algorithm>
#include <cstdlib>
#include <stdexcept>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace pipeline {

const std::vector<std::string>& known_analysis_keys() {
  // The analyzer's own list of what it reads. The panel offers exactly these;
  // the test suite fails if the two drift apart.
  // Order matches ENV_OPTIONS in python/panel/analysis.py, because that is the
  // order the console lists them in and a list that reorders under the operator
  // between two releases reads as the settings having changed meaning.
  static const std::vector<std::string> kKeys{
      "CTI_SKIP",               // keep the CTI phase off the network
      "ML_SKIP",                // skip the EMBER score
      "ML_EXPLAIN",             // request SHAP contributions
      "ML_THRESHOLD",           // decision threshold, 0..1
      "ML_TOP_K",               // SHAP rows carried in the report
      "CTI_CONFIG",             // JSON overlay for provider URLs
      "STATIC_ANALYZER_CURSES", // PDCurses progress screen
      "IA_ALLOW_CORE_DUMP",     // keep a dump when the process dies
      "IA_CONTINUE_ON_SIGNAL",  // Ctrl+C re-runs the phase and continues
      "TRACE_FILE",             // symbol/offset diagnostics
  };
  return kKeys;
}

namespace {

std::vector<std::filesystem::path> config_candidates() {
  // Same search shape as config/artifacts.yaml: working directory first, then
  // beside the executable, so a packaged build finds the config it shipped with.
  //
  // The exe directory is resolved here rather than borrowed from the planner's
  // pipeline_roots(): that is a private helper in an anonymous namespace, and
  // lifting it into a header would mean publishing an implementation detail for
  // the sake of one caller.
  std::filesystem::path exe;
#if defined(_WIN32)
  char buf[MAX_PATH] = {};
  const DWORD n = ::GetModuleFileNameA(nullptr, buf, MAX_PATH);
  if (n > 0 && n < MAX_PATH) exe = std::filesystem::path(buf).parent_path();
#else
  std::error_code ec;
  const std::filesystem::path self = std::filesystem::read_symlink("/proc/self/exe", ec);
  if (!ec) exe = self.parent_path();
#endif

  std::vector<std::filesystem::path> out{
      std::filesystem::current_path() / "config" / "analysis.yaml"};
  if (!exe.empty()) {
    out.push_back(exe / "config" / "analysis.yaml");
    out.push_back(exe.parent_path() / "config" / "analysis.yaml");
  }
  std::vector<std::filesystem::path> unique;
  for (const auto& p : out) {
    if (std::find(unique.begin(), unique.end(), p) == unique.end()) unique.push_back(p);
  }
  return unique;
}

}  // namespace

analysis_settings load_analysis_settings() {
  analysis_settings settings;
  std::filesystem::path path;
  for (const std::filesystem::path& candidate : config_candidates()) {
    std::error_code ec;
    if (std::filesystem::is_regular_file(candidate, ec) && !ec) {
      path = candidate;
      break;
    }
  }
  // No file is the normal case. Not an error, not a warning: a checkout without
  // one behaves exactly as it did before this existed.
  if (path.empty()) return settings;

  settings.source = path.string();
  YAML::Node root;
  try {
    root = YAML::LoadFile(path.string());
  } catch (const std::exception& e) {
    throw std::runtime_error(path.string() + ": invalid analysis config: " + e.what());
  }
  if (!root || root.IsNull()) {
    // A file of nothing but comments parses to a null node. That is a valid,
    // meaningful configuration - "no global settings" - and it is what ships by
    // default, so it must not be an error. Rejecting it would mean the stock
    // config could not be parsed at all.
    return settings;
  }
  if (!root.IsMap()) {
    throw std::runtime_error(path.string() + ": analysis config must be a YAML map");
  }

  const std::vector<std::string>& known = known_analysis_keys();
  for (const auto& entry : root) {
    if (!entry.first.IsScalar()) {
      throw std::runtime_error(path.string() + ": analysis config keys must be strings");
    }
    const std::string key = entry.first.Scalar();
    if (std::find(known.begin(), known.end(), key) == known.end()) {
      // Refused rather than ignored. An operator who mistyped ML_SKP would
      // otherwise sit there believing they had skipped the model.
      std::string suggestion;
      for (const std::string& k : known) {
        // Cheap near-miss test: one edit away is enough to name it.
        if (k.size() > 2 && key.size() > 2 &&
            (k.find(key) != std::string::npos || key.find(k) != std::string::npos)) {
          suggestion = " (did you mean '" + k + "'?)";
          break;
        }
      }
      throw std::runtime_error(path.string() + ": unknown analysis option '" + key +
                               "'" + suggestion +
                               "; config/analysis.yaml only accepts the settings the "
                               "analyzer reads");
    }
    if (!entry.second.IsScalar()) {
      throw std::runtime_error(path.string() + ": value for '" + key +
                               "' must be a scalar");
    }
    settings.settings.emplace_back(key, entry.second.Scalar());
  }

  // Anything the panel writes lands here, so a value that never reaches the
  // environment is worth a line in the log - it is the difference between "the
  // setting does not work" and "the setting was never applied".
  for (const auto& [key, value] : settings.settings) {
    if (redact::is_secret_name(key)) {
      LOG_DEBUG("analysis config: {} set", key);
    } else {
      LOG_DEBUG("analysis config: {}={}", key, redact::scrub(value));
    }
  }
  LOG_INFO("analysis settings: {} from '{}'",
           settings.settings.size(), settings.source);
  return settings;
}

void apply_analysis_settings(const analysis_settings& settings) {
  for (const auto& [key, value] : settings.settings) {
#if defined(_WIN32)
    // Both blocks, for the same reason the pipeline's apply_environment() does
    // it: SetEnvironmentVariable covers what children inherit, _putenv_s covers
    // getenv() in this process.
    SetEnvironmentVariableA(key.c_str(), value.empty() ? nullptr : value.c_str());
    _putenv_s(key.c_str(), value.c_str());
#else
    setenv(key.c_str(), value.c_str(), 1);
#endif
  }
}

}  // namespace pipeline