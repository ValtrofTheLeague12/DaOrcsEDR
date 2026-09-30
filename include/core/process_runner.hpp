#pragma once

// Small, dependency-free subprocess runner used to call external analysis tools
// (capa today, YARA / others later).
//
//   * stdout and stderr are drained concurrently, so a chatty child can never
//     deadlock on a full pipe
//   * hard timeout and output cap; the whole process TREE is killed
//     (Windows job object / POSIX process group), which matters for
//     PyInstaller-style launchers that spawn a child
//   * "executable not found" is reported separately from "ran and failed"
//   * stdin is closed (/dev/null, NUL): a tool can never block waiting for input
//   * arguments are passed as an argv vector, never through a shell
//
// ADDED: proc::child — non-blocking background handle.
//   run() blocks until the child exits and reaps it, so it cannot be used
//   for a long-lived server. child::start() launches the process in the
//   background and returns immediately, exposing the PID so the caller
//   can kill it later. It reuses the exact same plumbing (pipes, reader
//   threads, Windows job object / POSIX process group) as run().

#include <atomic>     // ADDED
#include <chrono>
#include <cstddef>
#include <cstdint>    // ADDED
#include <memory>     // ADDED
#include <mutex>      // ADDED
#include <string>
#include <vector>

namespace proc {

enum class launch_status {
  ok,                // the process ran to completion; look at exit_code
  not_found,         // executable does not exist / not on PATH / not executable
  launch_failed,     // pipes / fork / CreateProcess failed for another reason
  timed_out,         // killed after run_options::timeout
  output_too_large,  // killed because stdout exceeded run_options::max_stdout_bytes
};

const char* to_string(launch_status status);

// Names a caller has declared secret (BW_SESSION, CTI API keys, ...).
//
// The environment block handed to a child is built by this module, so this is
// the single point where a secret can be kept out of every subprocess. Without
// it, CreateProcess/execve inherit the parent's environment wholesale and
// `wsl.exe`, `capa`, the Python dashboard and every other tool we spawn would
// receive the master-vault token for free.
//
// Marking a name is permanent for the process: it is a policy, not a toggle.
// Names are compared case-insensitively, as Windows environment variables are.
void protect_env_var(const std::string& name);

struct run_options {
  std::chrono::milliseconds timeout{0};               // 0 = no timeout
  std::size_t max_stdout_bytes = 512u * 1024u * 1024u;
  std::size_t max_stderr_bytes = 1u * 1024u * 1024u;  // the head is kept, the rest is discarded
  std::string working_dir;                            // empty = inherit
  bool low_priority = false;                          // below-normal priority / nice +10
  std::vector<std::string> extra_env;                 // "KEY=VALUE", added to the inherited environment
};

struct run_result {
  launch_status status    = launch_status::launch_failed;
  int           exit_code = -1;   // POSIX: 128+signal if killed by a signal
  std::string   std_out;
  std::string   std_err;
  bool          stderr_truncated = false;
  std::string   error;            // human readable, filled when status != ok
  double        seconds = 0.0;    // wall clock
};

run_result run(const std::string& program,
               const std::vector<std::string>& args,
               const run_options& options = {});


std::string find_in_path(const std::string& name);

class child {
 public:
  child();
  ~child();

  child(const child&)            = delete;
  child& operator=(const child&) = delete;
  child(child&&)                 = delete;
  child& operator=(child&&)      = delete;

 
  launch_status start(const std::string& program,
                      const std::vector<std::string>& args,
                      const run_options& options = {});

  bool          running() const;      
  std::uint64_t pid() const;          


  void kill();


  bool wait_for_exit(unsigned ms);

  int exit_code() const;             


  std::string std_out() const;
  std::string std_err() const;

 private:
  struct impl;
  impl* impl_;
};

}  