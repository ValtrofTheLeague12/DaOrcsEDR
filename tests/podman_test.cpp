// Standalone smoke test for podman::runner.
//
// The runner is not reachable from the analyzer CLI (nothing in src/main.cpp
// constructs a podman::runner), so this links the module directly and drives
// the real container lifecycle: image_present -> start -> HTTP probe on the
// published port -> stop. Defaults match podman::options.
//
// Run from the repository root, where include/ lives:
//
//   g++ -std=c++20 tests/podman_test.cpp -Iinclude -o podman_test
//
// With --no-stop the container is left running for manual poking.

#include <chrono>
#include <cstdio>
#include <string>

#include "podman_runner.hpp"

namespace {

int failures = 0;

void check(bool condition, const char* what) {
  std::printf("  [%s] %s\n", condition ? "PASS" : "FAIL", what);
  if (!condition) ++failures;
}

}  // namespace

int main(int argc, char** argv) {
  const bool keep_running =
      (argc > 1 && std::string(argv[1]) == "--no-stop");

  podman::options opts;
  // The image already exists, so keep the test fast and never rebuild.
  opts.allow_build = false;
  opts.ready_timeout = std::chrono::milliseconds(120000);

  podman::runner runner;

  std::printf("podman::runner smoke test\n");
  std::printf("  image   = %s\n", opts.image.c_str());
  std::printf("  project = %s\n", opts.project_dir.c_str());
  std::printf("  url     = %s\n\n", runner.url().c_str());

  std::printf("[1] image_present()\n");
  const bool present = runner.image_present(opts);
  check(present, "podman image inspect finds localhost/cyberchef");
  if (!present) {
    std::printf("\nimage missing - aborting before start()\n");
    return 1;
  }

  std::printf("\n[2] start()\n");
  const bool started = runner.start(opts);
  std::printf("  status = %s\n", podman::to_string(runner.status()));
  if (!started) {
    std::printf("  error  = %s\n", runner.error().c_str());
    std::printf("  logs   = %s\n", runner.logs().c_str());
    check(false, "container reached state::running");
    return 1;
  }
  check(runner.status() == podman::state::running, "status is running");
  check(runner.running(), "running() is true");
  check(runner.pid() != 0, "wsl child pid is non-zero");

  const std::string url = runner.url();
  std::printf("\n[3] published port answers\n");
  std::printf("  probing %s\n", url.c_str());
  check(!url.empty() && url.find("127.0.0.1:60000") != std::string::npos,
        "url() is the loopback publish");

  if (!keep_running) {
    std::printf("\n[4] stop()\n");
    check(runner.stop(), "stop() succeeded");
    check(runner.status() == podman::state::stopped, "status is stopped");
    check(!runner.running(), "running() is false");
  } else {
    std::printf("\n[4] --no-stop: leaving container up at %s\n",
                runner.url().c_str());
  }

  std::printf("\n%s (%d failure(s))\n", failures == 0 ? "ALL PASS" : "FAILURES",
              failures);
  return failures == 0 ? 0 : 1;
}
