#include "podman_runner.hpp"

#include <algorithm>
#include <chrono>
#include <iterator>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "http_client.hpp"
#include "logging.hpp"
#include "process_runner.hpp"

namespace podman {

namespace {

using clock_type = std::chrono::steady_clock;

constexpr std::size_t k_max_output = 4u * 1024u * 1024u;

std::string trim(std::string value) {
  while (!value.empty() && (value.back() == '\n' || value.back() == '\r' || value.back() == ' ')) {
    value.pop_back();
  }
  std::size_t start = 0;
  while (start < value.size() && (value[start] == '\n' || value[start] == '\r' || value[start] == ' ')) {
    ++start;
  }
  return value.substr(start);
}

std::string tail(const std::string& text, std::size_t max_bytes) {
  if (text.size() <= max_bytes) return text;
  return text.substr(text.size() - max_bytes);
}

// `wsl.exe [-d <distro>] --`, then the Linux-side command. `--` matters: it
// stops wsl.exe from interpreting anything after it as its own flag.
std::vector<std::string> wsl_prefix(const options& opts) {
  std::vector<std::string> command{"wsl.exe"};
  if (!opts.wsl_distro.empty()) {
    command.push_back("-d");
    command.push_back(opts.wsl_distro);
  }
  command.push_back("--");
  return command;
}

// Podman arguments to execute inside the distro.
std::vector<std::string> podman_argv(const options& opts, std::vector<std::string> args) {
  std::vector<std::string> command = wsl_prefix(opts);
  command.push_back(opts.podman.empty() ? "podman" : opts.podman);
  command.insert(command.end(), std::make_move_iterator(args.begin()),
                 std::make_move_iterator(args.end()));
  return command;
}

std::string join(const std::vector<std::string>& argv) {
  std::string text;
  for (const std::string& part : argv) {
    if (!text.empty()) text += ' ';
    text += part;
  }
  return text;
}

proc::run_result run_podman(const options& opts, const std::vector<std::string>& args,
                            std::chrono::milliseconds timeout) {
  const std::vector<std::string> command = podman_argv(opts, args);
  proc::run_options run_opts;
  run_opts.timeout = timeout;
  run_opts.max_stdout_bytes = k_max_output;
  run_opts.max_stderr_bytes = 256u * 1024u;
  return proc::run(command.front(), std::vector<std::string>(command.begin() + 1, command.end()),
                   run_opts);
}

// A short, quotable description of a failed proc::run for error()/logs().
std::string describe(const proc::run_result& run) {
  if (run.status != proc::launch_status::ok) {
    return run.error.empty() ? proc::to_string(run.status) : run.error;
  }
  const std::string err = trim(run.std_err);
  if (!err.empty()) return err;
  return "exit code " + std::to_string(run.exit_code);
}

bool check_image_present(const options& opts) {
  const proc::run_result run =
      run_podman(opts, {"image", "inspect", opts.image}, opts.inspect_timeout);
  const bool present = run.status == proc::launch_status::ok && run.exit_code == 0;
  LOG_DEBUG("podman: image '{}' present={} ({})", opts.image, present, describe(run));
  return present;
}

bool run_build(const options& opts, std::string* error) {
  LOG_INFO("podman: building image '{}' from '{}' (this can take a while)",
           opts.image, opts.project_dir);
  const proc::run_result run =
      run_podman(opts, {"build", "-t", opts.image, opts.project_dir}, opts.build_timeout);
  if (run.status != proc::launch_status::ok || run.exit_code != 0) {
    if (error != nullptr) {
      *error = "podman build failed: " + describe(run) + "\n" + tail(trim(run.std_out), 2048);
    }
    LOG_ERROR("podman: podman build failed: {}", describe(run));
    return false;
  }
  LOG_INFO("podman: image '{}' built in {:.1f}s", opts.image, run.seconds);
  return true;
}

std::string probe_host(const options& opts) {
  // 0.0.0.0 is a bind directive, not a dialable address.
  return opts.bind_address == "0.0.0.0" ? "127.0.0.1" : opts.bind_address;
}

// Any HTTP status counts: a 404 still proves something is listening on the
// published port. Only a transport failure means "not up yet".
bool http_answers(cti::http_client* client, const options& opts) {
  if (client == nullptr) return false;
  cti::http_request request;
  request.method = "GET";
  request.url = "http://" + probe_host(opts) + ":" + std::to_string(opts.host_port) + "/";
  request.timeout_ms = 3000;
  request.max_response_bytes = 64u * 1024u;
  const cti::http_response response = client->perform(request);
  return response.transport_ok;
}

bool container_running(const options& opts) {
  const proc::run_result run = run_podman(
      opts,
      {"inspect", "--format", "{{.State.Running}}", opts.container_name},
      opts.inspect_timeout);
  return run.status == proc::launch_status::ok && trim(run.std_out) == "true";
}

}  // namespace

const char* to_string(state s) {
  switch (s) {
    case state::stopped:  return "stopped";
    case state::building: return "building";
    case state::starting: return "starting";
    case state::running:  return "running";
    case state::failed:   return "failed";
  }
  return "unknown";
}

struct runner::impl {
  options     opts;
  // Held by pointer because proc::child deletes copy AND move assignment, so a
  // stopped handle cannot be reset in place -- stop() swaps in a fresh one.
  std::unique_ptr<proc::child> process = std::make_unique<proc::child>();
  state       st  = state::stopped;
  bool        adopted = false;   // the port was already served; we own no child
  std::string err;

  ~impl() { stop(); }

  std::string url_for(const options& o) const {
    return "http://" + probe_host(o) + ":" + std::to_string(o.host_port) + "/";
  }

  void fail(std::string message) {
    st = state::failed;
    err = std::move(message);
    LOG_ERROR("podman: {}", err);
  }

  bool port_answers() {
    cti::http_options http_opts;
    http_opts.max_retries = 0;
    http_opts.connect_timeout_ms = 1000;
    http_opts.verify_tls = false;
    std::unique_ptr<cti::http_client> client = cti::make_curl_client(http_opts);
    if (client == nullptr) {
      // Without libcurl the HTTP probe is unavailable; fall back to asking
      // podman, which is weaker (the container can be up before it serves).
      LOG_DEBUG("podman: libcurl unavailable, falling back to podman inspect");
      return container_running(opts);
    }
    return http_answers(client.get(), opts);
  }

  // A container left behind by a killed CLI keeps --name and the port busy.
  // Removing it by name is safe: it is ours, or it is a name collision we want
  // to hear about.
  void remove_stale_container() {
    const proc::run_result run =
        run_podman(opts, {"rm", "-f", opts.container_name}, opts.inspect_timeout);
    if (run.status == proc::launch_status::ok && run.exit_code == 0) {
      LOG_WARN("podman: removed stale container '{}'", opts.container_name);
    }
  }

  bool wait_until_ready() {
    const auto deadline = clock_type::now() + opts.ready_timeout;
    while (clock_type::now() < deadline) {
      if (port_answers()) return true;
      if (!process->running()) {
        const int code = process->exit_code();
        fail("container exited during startup (exit code " + std::to_string(code) + "):\n" +
             tail(logs(), 2048));
        return false;
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(250));
    }
    fail("server did not answer on " + url_for(opts) + " within " +
         std::to_string(opts.ready_timeout.count() / 1000) + "s:\n" + tail(logs(), 2048));
    return false;
  }

  std::string logs() const {
    std::string text = process->std_out();
    const std::string err_text = process->std_err();
    if (!err_text.empty()) {
      if (!text.empty()) text += '\n';
      text += err_text;
    }
    return text;
  }

  bool start(const options& requested) {
    opts = requested;
    err.clear();

    if (st == state::running) {
      if (port_answers()) {
        LOG_DEBUG("podman: already running at {}", url_for(opts));
        return true;
      }
      LOG_WARN("podman: container was running but no longer answers; restarting");
      process->kill();
      st = state::stopped;
      adopted = false;
    }

    // Someone -- possibly a previous session of ours -- already holds the port.
    // Adopt it rather than tearing down something the user started by hand;
    // stop() can still reach it by container name.
    if (port_answers()) {
      LOG_WARN("podman: {} is already served by something else; not launching a second one",
               url_for(opts));
      st = state::running;
      adopted = true;
      return true;
    }

    if (opts.force_rebuild || !check_image_present(opts)) {
      if (!opts.allow_build) {
        fail("image '" + opts.image + "' is missing and allow_build is false");
        return false;
      }
      st = state::building;
      std::string build_error;
      if (!run_build(opts, &build_error)) {
        fail(build_error);
        return false;
      }
    }

    remove_stale_container();

    const std::string publish =
        opts.bind_address + ":" + std::to_string(opts.host_port) + ":" +
        std::to_string(opts.container_port);
    std::vector<std::string> args{"run", "--rm", "--name", opts.container_name,
                                  "-p", publish, opts.image};

    proc::run_options run_opts;
    run_opts.max_stdout_bytes = k_max_output;
    run_opts.max_stderr_bytes = 256u * 1024u;
    // No timeout: the container runs for as long as the caller wants it.

    const std::vector<std::string> command = podman_argv(opts, args);
    const std::string program = command.front();
    const std::vector<std::string> argv(command.begin() + 1, command.end());

    LOG_INFO("podman: starting: {}", join(command));
    st = state::starting;
    const proc::launch_status launched = process->start(program, argv, run_opts);
    if (launched != proc::launch_status::ok) {
      fail("could not launch WSL/podman: " + std::string(proc::to_string(launched)) +
           (opts.wsl_distro.empty() ? "" : " (distro '" + opts.wsl_distro + "')"));
      return false;
    }

    if (!wait_until_ready()) return false;

    adopted = false;
    st = state::running;
    LOG_INFO("podman: ready at {} (pid {})", url_for(opts), process->pid());
    return true;
  }

  bool stop() {
    if (st == state::stopped && !process->running()) return true;

    // Ask podman to stop the container first; that is what makes the
    // foreground `podman run` in the child exit on its own, and lets --rm
    // clean the container up.
    const proc::run_result run =
        run_podman(opts, {"stop", opts.container_name}, opts.stop_timeout);
    if (run.status == proc::launch_status::ok && run.exit_code == 0) {
      LOG_INFO("podman: container '{}' stopped", opts.container_name);
    } else if (!adopted) {
      LOG_DEBUG("podman: podman stop '{}' returned: {}", opts.container_name, describe(run));
    }

    // Backstop: reap the child whether or not podman answered.
    if (process->running()) {
      process->wait_for_exit(5000);
      process->kill();
    }

    process = std::make_unique<proc::child>();  // fresh handle, ready for another start()
    st = state::stopped;
    adopted = false;
    return true;
  }
};

runner::runner() : impl_(new impl()) {}
runner::~runner() { delete impl_; impl_ = nullptr; }

bool runner::start(const options& opts) { return impl_->start(opts); }
bool runner::stop() { return impl_->stop(); }
bool runner::running() const { return impl_->st == state::running; }
state runner::status() const { return impl_->st; }
const std::string& runner::error() const { return impl_->err; }
std::string runner::url() const { return impl_->url_for(impl_->opts); }
std::string runner::logs(std::size_t max_bytes) const { return tail(impl_->logs(), max_bytes); }
std::uint64_t runner::pid() const { return impl_->process->pid(); }

bool runner::image_present(const options& opts) { return check_image_present(opts); }

bool runner::build_image(const options& opts) {
  std::string error;
  return run_build(opts, &error);
}

}  // namespace podman
