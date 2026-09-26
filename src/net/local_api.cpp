// local_api.cpp
#include "local_api.hpp"
#include "logging.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <mutex>
#include <string>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

namespace local_api {

// =============================================================================
// helpers
// =============================================================================
namespace {

// Returns true if `script` is a regular file either directly (relative to
// CWD) or joined with `working_dir`. Logs both candidates at TRACE so it is
// obvious which one matched (or that neither did).
bool script_exists(const std::string& script, const std::string& working_dir) {
    namespace fs = std::filesystem;
    std::error_code ec;

    LOG_TRACE("local_api: script_exists: trying direct path '{}'", script);
    if (fs::is_regular_file(script, ec)) {
        LOG_TRACE("local_api: script_exists: matched '{}'", script);
        return true;
    }
    LOG_TRACE("local_api: script_exists: direct path failed (ec={})",
              ec ? ec.message() : "no error");

    if (!working_dir.empty()) {
        const fs::path joined = fs::path(working_dir) / script;
        LOG_TRACE("local_api: script_exists: trying joined path '{}'",
                  joined.string());
        std::error_code ec2;
        if (fs::is_regular_file(joined, ec2)) {
            LOG_TRACE("local_api: script_exists: matched '{}'",
                      joined.string());
            return true;
        }
        LOG_TRACE("local_api: script_exists: joined path failed (ec={})",
                  ec2 ? ec2.message() : "no error");
    }

    LOG_DEBUG("local_api: script_exists: '{}' not found (working_dir='{}')",
              script, working_dir);
    return false;
}

std::string join_url(const std::string& base, const std::string& path) {
    if (path.empty()) return base;
    const bool base_slash = !base.empty() && base.back() == '/';
    const bool path_slash = path.front() == '/';
    if (base_slash && path_slash)   return base + path.substr(1);
    if (!base_slash && !path_slash) return base + "/" + path;
    return base + path;
}

// Human-readable summary of argv for logging.
std::string format_argv(const std::string& program,
                        const std::vector<std::string>& args) {
    std::string out = program;
    for (const auto& a : args) {
        out += ' ';
        if (a.find(' ') != std::string::npos) {
            out += '"';
            out += a;
            out += '"';
        } else {
            out += a;
        }
    }
    return out;
}

}  // namespace

// =============================================================================
// to_string
// =============================================================================
const char* to_string(launch_status status) {
    switch (status) {
        case launch_status::ok:              return "ok";
        case launch_status::not_found:       return "not_found";
        case launch_status::launch_failed:   return "launch_failed";
        case launch_status::already_running: return "already_running";
        case launch_status::died_early:      return "died_early";
        case launch_status::unhealthy:       return "unhealthy";
    }
    return "unknown";
}

// =============================================================================
// local_api_server
// =============================================================================
local_api_server::local_api_server() {
    LOG_TRACE("local_api: ctor this={}", static_cast<const void*>(this));
}

local_api_server::~local_api_server() {
    LOG_TRACE("local_api: dtor this={} (running={})",
              static_cast<const void*>(this),
              (child_ && child_->running()) ? "yes" : "no");
    stop();
    LOG_TRACE("local_api: dtor done this={}", static_cast<const void*>(this));
}

// -----------------------------------------------------------------------------
// start
// -----------------------------------------------------------------------------
launch_status local_api_server::start(const launch_options& options) {
    LOG_DEBUG("local_api: start: enter (python='{}', script='{}', "
              "working_dir='{}', extra_args={}, extra_env={})",
              options.python, options.script, options.working_dir,
              options.args.size(), options.extra_env.size());

    if (child_ && child_->running()) {
        LOG_WARN("local_api: start called while pid={} is still running",
                 child_->pid());
        return launch_status::already_running;
    }

    options_ = options;
    LOG_TRACE("local_api: start: options_ captured");

    // ---- 0. script existence ----------------------------------------------
    if (!script_exists(options_.script, options_.working_dir)) {
        LOG_ERROR("local_api: server script not found: '{}' (working_dir='{}')",
                  options_.script, options_.working_dir);
        return launch_status::not_found;
    }

    LOG_INFO("local_api: launching '{}' '{}' with {} extra arg(s)",
             options_.python, options_.script, options_.args.size());

    // ---- 1. HTTP client ---------------------------------------------------
    LOG_DEBUG("local_api: start: creating http_client "
              "(connect_timeout_ms={}, verify_tls={}, retries={}, "
              "retry_wait_ms={})",
              options_.connect_timeout_ms,
              options_.verify_tls ? "yes" : "no",
              options_.max_retries,
              options_.max_retry_wait_ms);

    cti::http_options hopts;
    hopts.user_agent         = "local_api/1.0";
    hopts.connect_timeout_ms = options_.connect_timeout_ms;
    hopts.verify_tls         = options_.verify_tls;
    hopts.ca_bundle          = options_.ca_bundle;
    hopts.proxy              = options_.proxy;
    hopts.max_retries        = options_.max_retries;
    hopts.max_retry_wait_ms  = options_.max_retry_wait_ms;

    http_ = cti::make_curl_client(hopts);
    if (!http_) {
        LOG_ERROR("local_api: failed to create http_client "
                  "(curl_global_init likely failed)");
        return launch_status::launch_failed;
    }
    LOG_TRACE("local_api: start: http_client ready");

    // ---- 2. subprocess ----------------------------------------------------
    proc::run_options ro;
    ro.working_dir      = options_.working_dir;
    ro.extra_env        = options_.extra_env;
    ro.low_priority     = options_.low_priority;
    ro.timeout          = std::chrono::milliseconds{0};  // server owns lifetime
    ro.max_stdout_bytes = options_.max_stdout_bytes;
    ro.max_stderr_bytes = options_.max_stderr_bytes;

    std::vector<std::string> argv;
    argv.push_back(options_.script);
    argv.insert(argv.end(), options_.args.begin(), options_.args.end());

    LOG_INFO("local_api: start: exec: {}",
             format_argv(options_.python, argv));
    LOG_TRACE("local_api: start: cwd='{}', low_priority={}, "
              "max_stdout={} B, max_stderr={} B",
              ro.working_dir.empty() ? "(inherit)" : ro.working_dir,
              ro.low_priority ? "yes" : "no",
              ro.max_stdout_bytes,
              ro.max_stderr_bytes);

    child_ = std::make_unique<proc::child>();
    const proc::launch_status st = child_->start(options_.python, argv, ro);
    LOG_TRACE("local_api: start: proc::child::start returned '{}'",
              proc::to_string(st));

    if (st != proc::launch_status::ok) {
        LOG_ERROR("local_api: failed to launch '{}' '{}': {}",
                  options_.python, options_.script, proc::to_string(st));

        const std::string err = child_->std_err();
        if (!err.empty()) {
            LOG_ERROR("local_api: child stderr: {}", err);
        } else {
            LOG_DEBUG("local_api: child produced no stderr");
        }

        const std::string out = child_->std_out();
        if (!out.empty()) {
            LOG_DEBUG("local_api: child stdout: {}", out);
        }

        // stop() snapshots pid/exit/stdout/stderr so the accessors still
        // work after the child handle is released.
        stop();
        return (st == proc::launch_status::not_found)
                   ? launch_status::not_found
                   : launch_status::launch_failed;
    }

    LOG_INFO("local_api: server launched pid={}", child_->pid());

    // ---- 3. wait for health -----------------------------------------------
    if (options_.startup_timeout.count() <= 0) {
        LOG_INFO("local_api: server ready (pid={}, no health wait)",
                 child_->pid());
        return launch_status::ok;
    }

    const unsigned total_ms =
        static_cast<unsigned>(options_.startup_timeout.count());
    const unsigned poll_ms =
        static_cast<unsigned>(options_.health_poll_interval.count());
    const std::string health_url =
        join_url(options_.base_url, options_.health_path);

    LOG_DEBUG("local_api: start: polling {} every {} ms for up to {} ms",
              health_url, poll_ms, total_ms);

    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(total_ms);

    unsigned attempt = 0;
    while (std::chrono::steady_clock::now() < deadline) {
        ++attempt;

        if (child_->wait_for_exit(0)) {
            LOG_ERROR("local_api: server pid={} exited during startup (exit={}) "
                      "after {} health attempt(s)",
                      child_->pid(), child_->exit_code(), attempt);

            const std::string err = child_->std_err();
            if (!err.empty()) {
                LOG_ERROR("local_api: server stderr: {}", err);
            } else {
                LOG_DEBUG("local_api: server produced no stderr");
            }

            const std::string out = child_->std_out();
            if (!out.empty()) {
                LOG_DEBUG("local_api: server stdout: {}", out);
            }

            // stop() snapshots the final output so main() can still read
            // std_err() after the failure.
            stop();
            return launch_status::died_early;
        }

        if (healthy()) {
            LOG_INFO("local_api: server healthy at {} (pid={}) after {} "
                     "health attempt(s)",
                     health_url, child_->pid(), attempt);
            return launch_status::ok;
        }

        LOG_TRACE("local_api: start: health attempt {} failed for {}",
                  attempt, health_url);

        std::this_thread::sleep_for(std::chrono::milliseconds(poll_ms));
    }

    LOG_ERROR("local_api: server pid={} did not become healthy within {} ms "
              "(url={}, {} attempt(s))",
              child_->pid(), total_ms, health_url, attempt);

    const std::string err = child_->std_err();
    if (!err.empty()) {
        LOG_ERROR("local_api: server stderr: {}", err);
    } else {
        LOG_DEBUG("local_api: server produced no stderr before timeout");
    }

    // Never leave an unhealthy server running: stop() kills the child and
    // snapshots its state. Without this, running() would keep returning
    // true while every request against base_url fails.
    stop();
    return launch_status::unhealthy;
}

// -----------------------------------------------------------------------------
// stop
// -----------------------------------------------------------------------------
void local_api_server::stop() {
    LOG_TRACE("local_api: stop: enter (child_={})",
              child_ ? "present" : "null");

    if (!child_) {
        LOG_TRACE("local_api: stop: nothing to stop");
        http_.reset();
        return;
    }

    if (child_->running()) {
        LOG_INFO("local_api: stopping server pid={}", child_->pid());
        child_->kill();
        LOG_INFO("local_api: server stopped (exit={})", child_->exit_code());
    } else {
        LOG_DEBUG("local_api: stop called on already-exited server (exit={})",
                  child_->exit_code());
    }

    // Snapshot the final state so accessors still work after reset.
    {
        std::lock_guard<std::mutex> lock(last_output_mtx_);
        last_std_out_   = child_->std_out();
        last_std_err_   = child_->std_err();
        last_exit_code_ = child_->exit_code();
        last_pid_       = child_->pid();

        LOG_TRACE("local_api: stop: snapshot (pid={}, exit={}, "
                  "stdout={} B, stderr={} B)",
                  last_pid_, last_exit_code_,
                  last_std_out_.size(), last_std_err_.size());
    }

    LOG_TRACE("local_api: stop: resetting child_");
    child_.reset();

    LOG_TRACE("local_api: stop: resetting http_");
    http_.reset();

    LOG_TRACE("local_api: stop: done");
}

// -----------------------------------------------------------------------------
// state accessors
// -----------------------------------------------------------------------------
bool local_api_server::running() const {
    const bool r = child_ && child_->running();
    LOG_TRACE("local_api: running() -> {}", r);
    return r;
}

std::uint64_t local_api_server::pid() const {
    if (child_) {
        const std::uint64_t p = child_->pid();
        LOG_TRACE("local_api: pid() -> {} (live)", p);
        return p;
    }
    std::lock_guard<std::mutex> lock(last_output_mtx_);
    LOG_TRACE("local_api: pid() -> {} (cached)", last_pid_);
    return last_pid_;
}

int local_api_server::exit_code() const {
    if (child_) {
        const int c = child_->exit_code();
        LOG_TRACE("local_api: exit_code() -> {} (live)", c);
        return c;
    }
    std::lock_guard<std::mutex> lock(last_output_mtx_);
    LOG_TRACE("local_api: exit_code() -> {} (cached)", last_exit_code_);
    return last_exit_code_;
}

std::string local_api_server::std_out() const {
    if (child_) {
        const std::string s = child_->std_out();
        LOG_TRACE("local_api: std_out() -> {} B (live)", s.size());
        return s;
    }
    std::lock_guard<std::mutex> lock(last_output_mtx_);
    LOG_TRACE("local_api: std_out() -> {} B (cached)", last_std_out_.size());
    return last_std_out_;
}

std::string local_api_server::std_err() const {
    if (child_) {
        const std::string s = child_->std_err();
        LOG_TRACE("local_api: std_err() -> {} B (live)", s.size());
        return s;
    }
    std::lock_guard<std::mutex> lock(last_output_mtx_);
    LOG_TRACE("local_api: std_err() -> {} B (cached)", last_std_err_.size());
    return last_std_err_;
}

// -----------------------------------------------------------------------------
// health check
// -----------------------------------------------------------------------------
bool local_api_server::healthy() {
    if (!http_) {
        LOG_TRACE("local_api: healthy(): no http client");
        return false;
    }

    cti::http_request req;
    req.method             = "GET";
    req.url                = join_url(options_.base_url, options_.health_path);
    req.timeout_ms         = options_.connect_timeout_ms;
    req.max_response_bytes = 64 * 1024;

    LOG_TRACE("local_api: health check GET {}", req.url);

    const cti::http_response res = http_->perform(req);

    if (!res.transport_ok) {
        LOG_TRACE("local_api: health check transport error: {}", res.error);
        return false;
    }
    if (res.status < 200 || res.status >= 300) {
        LOG_TRACE("local_api: health check returned status {}", res.status);
        return false;
    }

    LOG_TRACE("local_api: health check OK (status={}, {} B)",
              res.status, res.body.size());
    return true;
}

// -----------------------------------------------------------------------------
// GET
// -----------------------------------------------------------------------------
cti::http_response local_api_server::get(
    const std::string& path,
    const std::vector<std::pair<std::string, std::string>>& headers,
    std::size_t max_response_bytes) {

    if (!http_) {
        LOG_ERROR("local_api: GET {} called before start()", path);
        cti::http_response r;
        r.error = "http client not initialized";
        return r;
    }

    cti::http_request req;
    req.method             = "GET";
    req.url                = join_url(options_.base_url, path);
    req.headers            = headers;   // both sides: vector<pair<string,string>>
    req.timeout_ms         = options_.request_timeout_ms;
    req.max_response_bytes = max_response_bytes;

    LOG_DEBUG("local_api: GET {} (timeout_ms={}, max_response_bytes={}, "
              "header_count={})",
              req.url, req.timeout_ms, req.max_response_bytes,
              req.headers.size());

    for (const auto& [k, v] : req.headers) {
        LOG_TRACE("local_api: GET header: {}: {}", k, v);
    }

    const auto started = std::chrono::steady_clock::now();
    const cti::http_response res = http_->perform(req);
    const double seconds =
        std::chrono::duration<double>(std::chrono::steady_clock::now() - started)
            .count();

    if (!res.transport_ok) {
        LOG_ERROR("local_api: GET {} transport error: {} (after {:.3f}s)",
                  req.url, res.error, seconds);
    } else if (res.status < 200 || res.status >= 300) {
        LOG_WARN("local_api: GET {} returned status {} ({} B, {:.3f}s)",
                 req.url, res.status, res.body.size(), seconds);
    } else {
        LOG_DEBUG("local_api: GET {} -> {} ({} B, {:.3f}s, attempts={})",
                  req.url, res.status, res.body.size(), seconds,
                  res.attempts);
    }
    return res;
}

}  // namespace local_api