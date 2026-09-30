#pragma once

// Starts and supervises a long-lived podman container from WSL.
//
//   * podman, not docker: the commands, the flags and the container naming are
//     all podman's. `localhost/<name>` is the image reference podman gives a
//     locally built image, which is where options::image points by default.
//   * everything goes through WSL, because the image and the build context
//     both live inside the distro:
//         wsl.exe [-d <distro>] -- podman run --rm --name cyberchef
//                  -p 127.0.0.1:60000:3000 localhost/cyberchef
//   * the container is long-lived, so this holds a proc::child rather than
//     calling proc::run(), which blocks until the child exits.
//   * if the image is absent it is built from options::project_dir first
//     (podman build -t <image> <project_dir>).
//   * start() is idempotent and never throws; on failure status() is
//     state::failed and error() explains why.
//
// The container runs in the foreground inside the child, so killing the child
// tears down the WSL-side process tree. stop() still asks podman to stop the
// container by name first, so podman -- not our kill -- does the orderly
// shutdown.

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace podman {

enum class state {
  stopped,     // no child, nothing on the port that we started
  building,    // `podman build` is running because the image was missing
  starting,    // container launched, waiting for the port to answer
  running,     // base_url answers HTTP
  failed,      // see error()
};

const char* to_string(state s);

struct options {
  // Empty = whatever `wsl.exe` currently uses as the default distro.
  std::string wsl_distro;

  // Path to the podman binary inside the distro. Override for a user-local
  // install or a podman-remote shim.
  std::string podman = "podman";

  // Build context inside the distro; used only when the image is missing.
  std::string project_dir = "/home/the4threich/cyber_chef/CyberChef-server";

  // `localhost/` is how podman refers to an image built locally.
  std::string image          = "localhost/cyberchef";
  std::string container_name = "cyberchef";

  // Published on the loopback only: the server has no authentication.
  std::string bind_address   = "127.0.0.1";
  int         host_port      = 60000;
  int         container_port = 3000;

  std::chrono::milliseconds inspect_timeout{30000};    // podman image inspect
  std::chrono::milliseconds build_timeout{1800000};    // podman build, 30 min
  std::chrono::milliseconds ready_timeout{180000};     // port probe deadline
  std::chrono::milliseconds stop_timeout{30000};

  // Build the image when it is absent. With this false, a missing image is an
  // error instead of a (possibly very long) build.
  bool allow_build = true;

  // Rebuild even when the image is already present.
  bool force_rebuild = false;
};

class runner {
 public:
  runner();
  ~runner();

  runner(const runner&)            = delete;
  runner& operator=(const runner&) = delete;

  // Brings the container up and waits until the published port answers.
  // Returns true when it is usable. Safe to call when already running.
  bool start(const options& opts = {});

  // Stops the container and reaps the child. Safe to call when stopped.
  bool stop();

  bool running() const;
  state status() const;

  // Human-readable reason for state::failed; empty otherwise.
  const std::string& error() const;

  // http://127.0.0.1:60000, from the options the last start() used.
  std::string url() const;

  // Tail of the container's stdout+stderr (server logs, build output).
  std::string logs(std::size_t max_bytes = 8192) const;

  // True when `podman image inspect <image>` succeeds.
  bool image_present(const options& opts = {});

  // `podman build -t <image> <project_dir>`. Blocking.
  bool build_image(const options& opts = {});

  // PID of the WSL child driving the container, 0 when stopped.
  std::uint64_t pid() const;

 private:
  struct impl;
  impl* impl_;
};

}  // namespace podman
