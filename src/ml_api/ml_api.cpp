// ml_api.cpp
//
// JSON in, JSON out. Every response field is read defensively: a missing key
// yields a default and leaves `ok` false with the service's own error text, so a
// service-side change degrades into "ML phase reported nothing" rather than a
// crash or a silently wrong verdict.
#include "ml_api.hpp"

#include "logging.hpp"

#include <algorithm>
#include <exception>
#include <iomanip>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

namespace ml_api {

namespace {

using nlohmann::json;

// Response bodies are small (a few KB even with top_k=50), but a runaway or
// wrong-endpoint response must not be buffered without bound.
constexpr std::size_t kMaxResponseBytes = 4u * 1024u * 1024u;

const std::vector<std::pair<std::string, std::string>> kJsonHeaders = {
    {"Content-Type", "application/json"},
    {"Accept", "application/json"},
};

verdict parse_verdict(const std::string& raw) {
    if (raw == "malicious")       return verdict::malicious;
    if (raw == "inconclusive")     return verdict::inconclusive;
    if (raw == "not_applicable")   return verdict::not_applicable;
    return verdict::benign;   // also the fallback for an unknown string
}

std::string jstr(const json& j, const char* key) {
    const auto it = j.find(key);
    return (it != j.end() && it->is_string()) ? it->get<std::string>() : std::string();
}

double jnum(const json& j, const char* key, double fallback = 0.0) {
    const auto it = j.find(key);
    return (it != j.end() && it->is_number()) ? it->get<double>() : fallback;
}

long jint(const json& j, const char* key, long fallback = 0) {
    const auto it = j.find(key);
    return (it != j.end() && it->is_number()) ? it->get<long>() : fallback;
}

bool jbool(const json& j, const char* key, bool fallback = false) {
    const auto it = j.find(key);
    return (it != j.end() && it->is_boolean()) ? it->get<bool>() : fallback;
}

// Decide whether the score may be read at face value. Two independent reasons
// to distrust it: the vector did not come from a fresh thrember run, or the
// analyzer's own EMBER groups diverged from what the service scored.
void apply_confidence(score_result_t& out) {
    std::vector<std::string> notes;
    if (out.feature_source != "thrember") {
        notes.push_back("features came from '" +
                        (out.feature_source.empty() ? std::string("unknown source")
                                                    : out.feature_source) +
                        "', not a fresh thrember vector");
    }
    if (out.skew.present && !out.skew.ok) {
        double worst = -1.0;
        std::string worst_group;
        for (const auto& [name, g] : out.skew.groups) {
            if (g.ok) continue;
            if (g.max_abs_diff > worst) {
                worst = g.max_abs_diff;
                worst_group = name;
            }
        }
        std::ostringstream msg;
        msg << std::scientific << std::setprecision(2)
            << "C++/thrember feature skew in " << worst_group
            << " (max abs diff " << worst << " > tolerance "
            << out.skew.tolerance << ")";
        notes.push_back(msg.str());
    }
    if (notes.empty()) return;
    out.low_confidence = true;
    for (std::size_t i = 0; i < notes.size(); ++i) {
        if (i) out.confidence_note += "; ";
        out.confidence_note += notes[i];
    }
}

// Turn one transport response into a score_result_t. A non-2xx status is
// expected: the service answers refusals with {"error", "detail"} and a real
// status code (404 not-a-file, 413 too-large, 422 cannot-vectorise), which is
// more informative than any message this layer could invent.
score_result_t parse_score(const cti::http_response& res) {
    score_result_t out;
    out.http_status = res.status;

    if (!res.transport_ok) {
        out.error  = "transport error";
        out.detail = res.error;
        return out;
    }

    json j = json::parse(res.body, nullptr, /*allow_exceptions=*/false);
    if (j.is_discarded() || !j.is_object()) {
        out.error  = "malformed response";
        out.detail = res.body.empty()
                         ? "empty body from the scoring service"
                         : res.body.substr(0, 200);
        return out;
    }

    // The error envelope wins over everything else: it is how the service
    // refuses a request it will not answer.
    const std::string error = jstr(j, "error");
    if (!error.empty()) {
        out.error  = error;
        out.detail = jstr(j, "detail");
        return out;
    }
    if (res.status < 200 || res.status >= 300) {
        out.error  = "unexpected status";
        out.detail = "HTTP " + std::to_string(res.status);
        return out;
    }

    // The core score fields are REQUIRED. Reading them with jnum/jstr
    // defaults would turn a 200 response that lost a field into
    // "p=0.0, verdict=benign" - a silently wrong clean verdict. Refuse instead.
    const auto prob_it = j.find("malicious_probability");
    if (prob_it == j.end() || !prob_it->is_number()) {
        out.error  = "malformed score response";
        out.detail = "missing numeric 'malicious_probability'";
        return out;
    }
    const auto verd_it = j.find("verdict");
    if (verd_it == j.end() || !verd_it->is_string()) {
        out.error  = "malformed score response";
        out.detail = "missing string 'verdict'";
        return out;
    }
    const std::string verdict_raw = verd_it->get<std::string>();
    if (verdict_raw != "benign" && verdict_raw != "inconclusive" &&
        verdict_raw != "malicious" && verdict_raw != "not_applicable") {
        out.error  = "unknown verdict";
        out.detail = verdict_raw;
        return out;
    }

    out.ok             = true;
    out.file           = jstr(j, "file");
    out.feature_source = jstr(j, "feature_source");
    out.bytes          = static_cast<std::uintmax_t>(jint(j, "bytes"));
    out.probability    = prob_it->get<double>();
    out.threshold      = jnum(j, "threshold", 0.5);
    out.is_pe          = jbool(j, "is_pe");
    out.verdict_raw    = verdict_raw;
    out.verdict        = parse_verdict(out.verdict_raw);
    out.verdict_note   = jstr(j, "verdict_note");
    out.model          = jstr(j, "model");
    out.model_sha256   = jstr(j, "model_sha256");
    out.trees          = jint(j, "trees");
    out.features       = jint(j, "features");

    // Optional train/serve skew report (see feature_skew_t).
    const auto skew_it = j.find("feature_skew");
    if (skew_it != j.end() && skew_it->is_object()) {
        out.skew.present   = true;
        out.skew.ok        = jbool(*skew_it, "ok", false);
        out.skew.tolerance = jnum(*skew_it, "tolerance");
        const auto gs = skew_it->find("groups");
        if (gs != skew_it->end() && gs->is_object()) {
            for (auto it = gs->begin(); it != gs->end(); ++it) {
                if (!it.value().is_object()) continue;
                skew_group_t g;
                g.max_abs_diff     = jnum(it.value(), "max_abs_diff");
                g.n                = jint(it.value(), "n");
                g.first_diff_index = jint(it.value(), "first_diff_index", -1);
                g.ok               = jbool(it.value(), "ok", true);
                out.skew.groups.emplace_back(it.key(), std::move(g));
            }
        }
    }
    apply_confidence(out);

    const auto ex = j.find("explanation");
    if (ex == j.end() || !ex->is_object()) return out;

    out.explained           = true;
    out.base_log_odds       = jnum(*ex, "base_log_odds");
    out.prediction_log_odds = jnum(*ex, "prediction_log_odds");
    out.sum_shap            = jnum(*ex, "sum_shap");
    out.consistency_error   = jnum(*ex, "consistency_error");

    const auto rows = ex->find("top_features");
    if (rows != ex->end() && rows->is_array()) {
        for (const json& row : *rows) {
            if (!row.is_object()) continue;
            feature_evidence_t f;
            f.feature_index        = static_cast<int>(jint(row, "feature_index"));
            f.group                = jstr(row, "group");
            f.label                = jstr(row, "label");
            f.evidence             = jstr(row, "evidence");
            f.direction            = jstr(row, "direction");
            f.value                = jnum(row, "value");
            f.shap_log_odds        = jnum(row, "shap_log_odds");
            f.bucket_occupancy     = static_cast<int>(jint(row, "bucket_occupancy"));
            f.shared_bucket        = jbool(row, "shared_bucket");
            f.analyzer_implemented = jbool(row, "analyzer_implemented");
            out.top_features.push_back(std::move(f));
        }
    }

    const auto groups = ex->find("group_rollup");
    if (groups != ex->end() && groups->is_array()) {
        for (const json& row : *groups) {
            if (!row.is_object()) continue;
            group_rollup_t g;
            g.group                = jstr(row, "group");
            g.shap_log_odds        = jnum(row, "shap_log_odds");
            g.analyzer_implemented = jbool(row, "analyzer_implemented");
            out.group_rollup.push_back(std::move(g));
        }
    }
    return out;
}

// Build a /score or /score/vector request body. nlohmann is used rather than
// string concatenation because `path` is attacker-adjacent data: a path holding
// a quote or a backslash must be escaped, not pasted into a literal.
std::string make_body(const json& fields, const score_options_t& options,
                      const analyzer_groups_t* groups = nullptr) {
    json body = fields;
    body["threshold"] = options.threshold;
    if (options.explain) {
        body["explain"] = true;
        // The service rejects anything outside 1..50, so clamp rather than let
        // it 400 on a value the caller computed carelessly.
        body["top_k"] = std::clamp(options.top_k, 1, 50);
    }
    if (groups != nullptr && groups->any()) {
        // Train/serve skew check: the service diffs these against its own
        // thrember vector at the same group offsets. 512 doubles ≈ 10 KB.
        json ag = json::object();
        if (!groups->histogram.empty())   ag["histogram"]   = groups->histogram;
        if (!groups->byteentropy.empty()) ag["byteentropy"] = groups->byteentropy;
        body["analyzer_groups"] = std::move(ag);
    }
    return body.dump();
}
}  // namespace

// -----------------------------------------------------------------------------
// to_string
// -----------------------------------------------------------------------------
const char* to_string(verdict v) {
    switch (v) {
        case verdict::benign:          return "benign";
        case verdict::inconclusive:    return "inconclusive";
        case verdict::malicious:       return "malicious";
        case verdict::not_applicable:  return "not_applicable";
    }
    return "benign";
}

// -----------------------------------------------------------------------------
// Threat level (see ml_api.hpp for why it lives here rather than in the service)
// -----------------------------------------------------------------------------
double threshold_margin(const score_result_t& r) {
    return r.probability - r.threshold;
}

const char* to_string(threat_level lvl) {
    switch (lvl) {
        case threat_level::low:             return "low";
        case threat_level::moderate:        return "moderate";
        case threat_level::high:            return "high";
        case threat_level::critical:        return "critical";
        case threat_level::not_applicable:  return "n/a";
    }
    return "n/a";
}

threat_level level_for(const score_result_t& r) {
    // A score nobody asked for, or a model that refuses to judge this file
    // type, has no threat level: inventing "low" for it would read as a
    // clean bill of health.
    if (!r.ok || r.verdict == verdict::not_applicable) {
        return threat_level::not_applicable;
    }

    const double p = std::clamp(r.probability, 0.0, 1.0);
    const double t = std::clamp(r.threshold, 0.0, 1.0);
    const double margin = p - t;

    // The room left on the side the score landed on. Normalising by it keeps
    // the bands meaningful at any threshold: at t=0.9, p=0.95 is only +0.05 in
    // absolute terms but has covered half the distance to a perfect score.
    const double span = (margin >= 0.0) ? (1.0 - t) : t;
    if (span <= 1e-9) return threat_level::moderate;  // degenerate threshold

    const double rel = margin / span;
    if (rel >=  0.80) return threat_level::critical;
    if (rel >=  0.50) return threat_level::high;
    if (rel >= -0.50) return threat_level::moderate;
    return threat_level::low;
}

// -----------------------------------------------------------------------------
// POST /score
// -----------------------------------------------------------------------------
score_result_t score_file(local_api::local_api_server& api,
                          const std::string& path,
                          const score_options_t& options,
                          const analyzer_groups_t& groups) {
    score_result_t out;
    if (!api.running()) {
        out.error  = "service not running";
        out.detail = "the ML scoring service was not started for this run";
        return out;
    }

    try {
        const std::string body =
            make_body(json{{"path", path}}, options,
                      groups.any() ? &groups : nullptr);
        const cti::http_response res =
            api.post("/score", body, kJsonHeaders, kMaxResponseBytes);
        out = parse_score(res);
    } catch (const std::exception& e) {
        LOG_ERROR("ml_api: score_file threw: {}", e.what());
        out.error  = "client error";
        out.detail = e.what();
    }
    return out;
}

// -----------------------------------------------------------------------------
// POST /score/vector
// -----------------------------------------------------------------------------
score_result_t score_vector(local_api::local_api_server& api,
                            const std::vector<double>& vector,
                            const score_options_t& options) {
    score_result_t out;
    if (!api.running()) {
        out.error  = "service not running";
        out.detail = "the ML scoring service was not started for this run";
        return out;
    }

    try {
        const std::string body = make_body(json{{"vector", vector}}, options);
        const cti::http_response res =
            api.post("/score/vector", body, kJsonHeaders, kMaxResponseBytes);
        out = parse_score(res);
    } catch (const std::exception& e) {
        LOG_ERROR("ml_api: score_vector threw: {}", e.what());
        out.error  = "client error";
        out.detail = e.what();
    }
    return out;
}

// -----------------------------------------------------------------------------
// GET /health
// -----------------------------------------------------------------------------
bool service_healthy(local_api::local_api_server& api) {
    if (!api.running()) return false;
    const cti::http_response res =
        api.get("/health", {{"Accept", "application/json"}}, 64 * 1024);
    if (!res.ok()) return false;
    try {
        const json j = json::parse(res.body, nullptr, /*allow_exceptions=*/false);
        return !j.is_discarded() && j.is_object() && jstr(j, "status") == "ok";
    } catch (const std::exception&) {
        return false;
    }
}

// -----------------------------------------------------------------------------
// GET /model
// -----------------------------------------------------------------------------
bool service_model_info(local_api::local_api_server& api,
                        std::string& model_sha256,
                        long& features) {
    if (!api.running()) return false;
    const cti::http_response res =
        api.get("/model", {{"Accept", "application/json"}}, kMaxResponseBytes);
    if (!res.ok()) return false;
    try {
        const json j = json::parse(res.body, nullptr, /*allow_exceptions=*/false);
        if (j.is_discarded() || !j.is_object()) return false;
        model_sha256 = jstr(j, "model_sha256");
        features     = jint(j, "features");
        return true;
    } catch (const std::exception&) {
        return false;
    }
}
}  // namespace ml_api