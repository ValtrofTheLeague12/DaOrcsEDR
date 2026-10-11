#pragma once
// ml_api.hpp
//
// Typed client for the EMBER2024 scoring service (ml/serve.py). The analyzer
// already runs two local Python services (python/api/server.py for MalAPI), and
// the ML service is a third REST endpoint on loopback, so this is a thin
// request/response layer over local_api::local_api_server's transport rather
// than a new HTTP stack.
//
// The service vectorises with thrember and scores a LightGBM model trained on
// EMBER2024. The analyzer therefore asks it to score the FILE (POST /score)
// instead of sending a vector: the C++ exporter only reproduces the histogram
// and byteentropy groups (512 of 2,568 dimensions), so /score/vector would
// silently score a mostly-zero vector. See ml/README.md, "The analyzer cannot
// call /score/vector yet".
//
// Everything the model asserts is carried through verbatim, including the two
// fields that decide how a verdict may be read:
//   * verdict - banded (benign / inconclusive / malicious / not_applicable)
//   * is_pe   - read from the vector, not trusted from the request; the model
//               only ever saw Win64 PE images
// plus model_sha256 and the threshold actually used, so a score is always
// traceable to one model build and one decision point.

#include "local_api.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace ml_api {

// How the service should classify a score. The service is the single source of
// truth for the bands; these mirror ml/serve.py's BANDS so the analyzer can
// colour a verdict without re-deriving it.
enum class verdict { benign, inconclusive, malicious, not_applicable };

const char* to_string(verdict v);

// How alarmed a reader should be by ONE score. Derived by the analyzer rather
// than the service, because the service bands p alone (ml/serve.py BANDS) while
// this bands p against the threshold that was actually applied - the single
// biggest lever on the verdict (see phase_ml.cpp and ml/README.md).
//
// It is a reading aid over an UNCALIBRATED ranking signal: "high" means "far
// above the operating point", never "high confidence of malware". The four
// labels are deliberately coarse so they survive a threshold change: with the
// default t=0.5 they line up as
//   low       p < 0.25      (well below the operating point)
//   moderate  0.25 .. 0.75  (borderline, either side of t)
//   high      0.75 .. 0.90
//   critical  p >= 0.90
// not_applicable is carried through from the service verdict: the model only
// ever saw Win64 PE images, so a non-PE score has no threat level at all.
enum class threat_level { low, moderate, high, critical, not_applicable };

const char* to_string(threat_level lvl);

// One SHAP row from the optional `explanation` block. Named rather than a bare
// column index where the service could name it.
struct feature_evidence_t {
    int         feature_index   = 0;
    std::string group;
    std::string label;          // may be empty for an unnamed hashed bucket
    std::string evidence;       // concrete import/export names, comma-joined
    std::string direction;      // "towards malicious" | "towards benign"
    double      value           = 0.0;
    double      shap_log_odds   = 0.0;
    int         bucket_occupancy = 0;
    bool        shared_bucket   = false;
    bool        analyzer_implemented = false;
};

struct group_rollup_t {
    std::string group;
    double      shap_log_odds = 0.0;
    bool        analyzer_implemented = false;
};

// Train/serve skew check for ONE EMBER group: the analyzer ships the 512
// dimensions it reproduces itself (histogram, byteentropy) alongside the file
// path, and the service compares them element-wise against the fresh thrember
// vector it actually scored. Any divergence above tolerance means the C++
// exporter and the feature extractor the model was trained on have drifted.
struct skew_group_t {
    double max_abs_diff     = 0.0;
    long   n                = 0;
    long   first_diff_index = -1;   // global vector index, -1 when within tolerance
    bool   ok               = true;
};

struct feature_skew_t {
    bool   present   = false;   // groups were sent AND the service compared them
    bool   ok        = true;
    double tolerance = 0.0;
    // (group name, stats) for each group the service could compare.
    std::vector<std::pair<std::string, skew_group_t>> groups;
};

// The analyzer-side EMBER groups the C++ extractor reproduces (512 of 2,568
// dimensions). Either vector may be empty when that phase did not run; an
// empty set simply disables the skew check for that group.
struct analyzer_groups_t {
    std::vector<double> histogram;     // 256 dims
    std::vector<double> byteentropy;   // 256 dims

    bool any() const { return !histogram.empty() || !byteentropy.empty(); }
};

// A parsed /score response. Populated only when `ok` is true, apart from
// `error`/`detail`, which the service fills on every failure.
struct score_result_t {
    bool        ok            = false;
    std::string error;                      // service-side code, e.g. "not a file"
    std::string detail;                     // human-readable elaboration
    long        http_status   = 0;

    std::string file;
    std::string feature_source;             // "thrember" for /score
    std::uintmax_t bytes      = 0;
    double      probability  = 0.0;         // p(malicious), NOT calibrated
    ml_api::verdict verdict = ml_api::verdict::benign;
    std::string verdict_raw;                // the service's own string
    std::string verdict_note;               // set when verdict is not_applicable
    double      threshold    = 0.5;         // the threshold actually applied
    bool        is_pe        = false;

    std::string model;
    std::string model_sha256;
    long        trees   = 0;
    long        features = 0;

    // Verdict trust: true when the score must NOT be read at face value -
    // the vector did not come from a fresh thrember run, or the C++/thrember
    // feature skew check failed. `confidence_note` says why, in one line.
    bool        low_confidence  = false;
    std::string confidence_note;

    // Present only when analyzer groups were sent and the service compared
    // them (see feature_skew_t).
    feature_skew_t skew;

    // Present only when explain=true was requested.
    bool        explained = false;
    double      base_log_odds        = 0.0;
    double      prediction_log_odds  = 0.0;
    double      sum_shap             = 0.0;
    double      consistency_error    = 0.0;
    std::vector<feature_evidence_t> top_features;
    std::vector<group_rollup_t>     group_rollup;
};

// p - threshold, signed. Positive means the score sat on the malicious side of
// the operating point that produced the verdict.
double threshold_margin(const score_result_t& r);

// Bands that margin, as a fraction of the room left on its own side of the
// threshold (so a t=0.9 run and a t=0.3 run read on the same scale).
threat_level level_for(const score_result_t& r);

// Per-call knobs. `threshold` is passed to the service, which applies it; the
// analyzer does not second-guess the result.
struct score_options_t {
    double threshold = 0.5;
    bool   explain   = false;
    int    top_k     = 8;   // clamped to the service's 1..50
};

// POST /score - thrember vectorises `path`, then the model scores it.
// `path` must be a filesystem path the service process can read.
// `groups`, when non-empty, is sent as `analyzer_groups` so the service can
// run the train/serve skew check against its own thrember vector; a service
// that does not know the field simply ignores it (skew stays present=false).
score_result_t score_file(local_api::local_api_server& api,
                          const std::string& path,
                          const score_options_t& options = {},
                          const analyzer_groups_t& groups = {});

// POST /score/vector - score a vector the caller already holds. Provided for
// completeness and for callers that do hold a full 2,568-d vector; the C++
// exporter does not, so run_ml_score() uses score_file().
score_result_t score_vector(local_api::local_api_server& api,
                            const std::vector<double>& vector,
                            const score_options_t& options = {});

// GET /health - liveness plus which model is loaded.
bool service_healthy(local_api::local_api_server& api);

// GET /model - model metadata and the EMBER group offsets.
bool service_model_info(local_api::local_api_server& api,
                        std::string& model_sha256,
                        long& features);

}  // namespace ml_api