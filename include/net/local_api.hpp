#pragma once
// local_api.hpp
//
// Launch and own a local Python API server (python/api/server.py) as a
// background subprocess (proc::child from process_runner.hpp), and expose
// a simple GET helper backed by cti::http_client.

#include "cti.hpp"
#include "process_runner.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <utility>     // std::pair
#include <vector>

namespace local_api {

// -----------------------------------------------------------------------------
// Options for launching the server.
// -----------------------------------------------------------------------------
struct launch_options {
    std::string python = "py";                    // 'py' launcher ('python' may not be on PATH)
    std::string script = "python/api/server.py";
    std::vector<std::string> args;
    std::vector<std::string> extra_env;
    std::string working_dir;
    bool        low_priority = false;

    std::size_t max_stdout_bytes = 256 * 1024;
    std::size_t max_stderr_bytes = 256 * 1024;

    // HTTP wiring
    std::string base_url    = "http://127.0.0.1:60000";  // matches server.py app.run
    std::string health_path = "/health";

    std::chrono::milliseconds startup_timeout{10000};
    std::chrono::milliseconds health_poll_interval{200};

    long        request_timeout_ms = 30000;
    long        connect_timeout_ms = 5000;
    bool        verify_tls         = false;
    std::string ca_bundle;
    std::string proxy;

    // http_client retry knobs (defaults if the struct doesn't define them)
    int  max_retries       = 2;
    long max_retry_wait_ms = 5000;
};

// -----------------------------------------------------------------------------
// Launch result.
// -----------------------------------------------------------------------------
enum class launch_status {
    ok,
    not_found,
    launch_failed,
    already_running,
    died_early,
    unhealthy
};

const char* to_string(launch_status status);

// -----------------------------------------------------------------------------
// local_api_server
// -----------------------------------------------------------------------------
class local_api_server {
public:
    local_api_server();
    ~local_api_server();

    local_api_server(const local_api_server&)            = delete;
    local_api_server& operator=(const local_api_server&) = delete;
    local_api_server(local_api_server&&)                 = delete;
    local_api_server& operator=(local_api_server&&)      = delete;

    // lifecycle
    launch_status start(const launch_options& options);
    void          stop();

    bool          running() const;
    std::uint64_t pid() const;
    int           exit_code() const;
    std::string   std_out() const;
    std::string   std_err() const;

    // HTTP (GET only). Headers type matches cti::http_request::headers.
    cti::http_response get(
        const std::string& path,
        const std::vector<std::pair<std::string, std::string>>& headers = {},
        std::size_t max_response_bytes = 8 * 1024 * 1024);

    // HTTP (POST with a JSON body). Same transport and logging as get(); the
    // ML scoring service (ml/serve.py) is reached through this, so a REST call
    // out of the analyzer needs no second HTTP stack.
    //
    // `body` is sent verbatim. Callers own JSON serialisation and must set
    // Content-Type themselves - the header list is passed straight to libcurl.
    cti::http_response post(
        const std::string& path,
        const std::string& body,
        const std::vector<std::pair<std::string, std::string>>& headers = {},
        std::size_t max_response_bytes = 8 * 1024 * 1024);

    bool healthy();

    const std::string& base_url() const { return options_.base_url; }

private:
    std::unique_ptr<proc::child>      child_;
    std::unique_ptr<cti::http_client> http_;
    launch_options                    options_;

    // Cache so accessors still work after stop() releases the child handle.
    mutable std::mutex last_output_mtx_;
    std::string        last_std_out_;
    std::string        last_std_err_;
    int                last_exit_code_ = -1;
    std::uint64_t      last_pid_       = 0;
};

}  // namespace local_api