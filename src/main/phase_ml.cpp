#include "pipeline.hpp"

#include <algorithm>
#include <cstdlib>
#include <exception>
#include <filesystem>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <system_error>

#include "console.hpp"
#include "logging.hpp"
#include "ml_api.hpp"

namespace pipeline {

namespace {

// ML_* environment knobs. All optional; every one has a working default, so a
// plain `static-analyzer sample.exe` needs no configuration at all.
constexpr const char* kSkipEnv      = "ML_SKIP";        // "1"/"true" disables the phase
constexpr const char* kThresholdEnv = "ML_THRESHOLD";   // decision threshold, 0..1
constexpr const char* kExplainEnv   = "ML_EXPLAIN";     // "1"/"true" requests SHAP
constexpr const char* kTopKEnv      = "ML_TOP_K";       // how many SHAP rows

// Strict "1"/"true"/"0"/"false" test, so an unparseable value falls back to the
// default instead of throwing out of a phase.
bool env_flag(const char* name, bool fallback) {
    const char* v = std::getenv(name);
    if (v == nullptr || *v == '\0') return fallback;
    const std::string s(v);
    if (s == "1" || s == "true" || s == "yes") return true;
    if (s == "0" || s == "false" || s == "no")  return false;
    LOG_WARN("ml: {}='{}' is not a boolean, using {}", name, s,
             fallback ? "true" : "false");
    return fallback;
}

double env_double(const char* name, double fallback, double lo, double hi) {
    const char* v = std::getenv(name);
    if (v == nullptr || *v == '\0') return fallback;
    try {
        std::size_t used = 0;
        const double parsed = std::stod(std::string(v), &used);
        if (used != std::string(v).size()) throw std::invalid_argument("trailing");
        if (parsed < lo || parsed > hi) throw std::out_of_range("range");
        return parsed;
    } catch (const std::exception&) {
        LOG_WARN("ml: {}='{}' is not a number in [{}, {}], using {}",
                 name, v, lo, hi, fallback);
        return fallback;
    }
}

}  // namespace

// ---------------------------------------------------------------------------
// Phase 21: EMBER2024 model score
//
// One REST round trip. The analyzer sends the file path and the service runs
// thrember + LightGBM, because the C++ exporter only reproduces 512 of the
// 2,568 EMBER dimensions and a hand-built partial vector would be scored as if
// the other 2,056 were zero.
//
// Skipped, not failed, when the service is absent or ML_SKIP is set: a missing
// model must never turn a good static analysis into a failed run.
// ---------------------------------------------------------------------------
void run_ml_score(context& ctx) {
  // The applicability gate is evaluated before the phase header prints, so the
  // "[phase n/total]" plan only ever advertises work that really happens.
  std::string skip;
  if (env_flag(kSkipEnv, false)) {
    skip = "ML_SKIP is set";
  } else if (ctx.ml_api_server == nullptr) {
    skip = "scoring service not available (see the log for why)";
  } else if (ctx.failed) {
    skip = "the file could not be parsed";
  }

  phase(ctx, skip.empty(), "EMBER2024 ML score");

  if (!skip.empty()) {
    ctx.ml_skip_reason = skip;
    LOG_DEBUG("ml: phase skipped: {}", skip);
    return;
  }

  const auto started = report_clock::now();

  ml_api::score_options_t options;
  // The threshold is the single biggest lever on this model's output (see
  // ml/README.md), so it is a knob rather than a constant, and the value the
  // service actually applied is echoed back into the report.
  options.threshold = env_double(kThresholdEnv, 0.5, 0.0, 1.0);
  options.explain   = env_flag(kExplainEnv, true);
  options.top_k     = static_cast<int>(env_double(kTopKEnv, 8.0, 1.0, 50.0));

  // The service resolves a relative path against its OWN working directory
  // (ml/), not the analyzer's, so `.\sample.exe` would be looked up in the wrong
  // place and come back as "not a file". Send an absolute path.
  std::error_code ec;
  std::filesystem::path abs_path =
      std::filesystem::absolute(std::filesystem::path(ctx.info.filepath), ec);
  if (ec) {
    // Fall back to the original string rather than sending an empty path: the
    // service's own error message is more useful than a guess.
    LOG_WARN("ml: cannot resolve '{}' to an absolute path ({}); sending it as-is",
             ctx.info.filepath, ec.message());
    abs_path = std::filesystem::path(ctx.info.filepath);
  }

  // The 512 dimensions the C++ extractor reproduces (histogram, byteentropy)
  // ride along so the service can diff them against its fresh thrember vector
  // - the automated train/serve skew check. An extraction-less pipeline
  // simply sends nothing and the check is skipped.
  ml_api::analyzer_groups_t groups;
  if (ctx.full.histogram.total_bytes > 0 &&
      !extractor::has_errors(ctx.full.histogram.errors)) {
    const extractor::byte_histogram_t& h = ctx.full.histogram;
    groups.histogram.assign(h.ember_histogram, h.ember_histogram + 256);
    groups.byteentropy.assign(h.ember_byteentropy, h.ember_byteentropy + 256);
  }

  ctx.ml_score = ml_api::score_file(*ctx.ml_api_server, abs_path.string(),
                                    options, groups);

  print_ml_score_report(ctx.ml_score, ctx.ml_skip_reason);
  print_duration(elapsed_ms(started));
}

}  // namespace pipeline