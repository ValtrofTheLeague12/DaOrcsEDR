#include "mega_runner.hpp"

#include "process_runner.hpp"

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <string>
#include <system_error>
#include <vector>

namespace mega_runner {
namespace {

// Which interpreter runs the uploader.
//
// The project venv first, for one reason: upload.py imports `seal`, which
// needs `cryptography`. That package is a declared dependency of the venv and
// only incidentally present in whatever global interpreter happens to be on the
// machine - so a bare 'py' makes evidence encryption depend on the operator's
// personal Python setup. die_runner and phase_output already resolve the venv
// this way for the same reason. MEGA_PYTHON overrides, matching DIE_PYTHON.
std::string python_command() {
#if defined(_WIN32)
  if (const char* override = std::getenv("MEGA_PYTHON");
      override != nullptr && *override != '\0') {
    return override;
  }
  // Relative: proc::run is given the working directory, so this resolves the
  // same way the analyzer's other Python phases resolve it.
  const std::filesystem::path venv = "python/.venv/Scripts/python.exe";
  std::error_code ec;
  if (std::filesystem::is_regular_file(venv, ec) && !ec) return venv.string();
  return "py";
#else
  if (const char* override = std::getenv("MEGA_PYTHON");
      override != nullptr && *override != '\0') {
    return override;
  }
  return "python3";
#endif
}

}  // namespace

result run(const options& config) {
  result out;
  if (config.artifact_name.empty() || config.source_directory.empty() ||
      config.output_root.empty() || config.uploader_script.empty()) {
    out.error = "artifact name, source directory, output root, and uploader script are required";
    return out;
  }
  if (config.artifact_name.front() == '.' ||
      config.artifact_name.find_first_of("/\\") != std::string::npos ||
      config.artifact_name.find('\0') != std::string::npos) {
    out.error = "artifact_name must be a plain file name";
    return out;
  }
  if (config.timeout_seconds < 1 || config.timeout_seconds > 86400) {
    out.error = "timeout_seconds must be between 1 and 86400";
    return out;
  }
  if (config.remote_root.empty()) {
    out.error = "remote_root must not be empty";
    return out;
  }
  // A bad recipient name would otherwise reach the uploader as a free-form
  // string and be rejected there, after the bundle was already built.
  if (config.encrypt && config.encryption_recipient != "user" &&
      config.encryption_recipient != "admin") {
    out.error = "encryption_recipient must be 'user' or 'admin', got '" +
                config.encryption_recipient + "'";
    return out;
  }
  if (!std::filesystem::is_directory(config.source_directory)) {
    out.error = "analysis export directory not found: " + config.source_directory;
    return out;
  }
  if (!std::filesystem::is_regular_file(config.uploader_script)) {
    out.error = "MEGA uploader script not found: " + config.uploader_script;
    return out;
  }

  std::vector<std::string> args{
      config.uploader_script,
      "--artifact", config.artifact_name,
      "--source", config.source_directory,
      "--out-root", config.output_root,
      "--remote-root", config.remote_root,
      "--timeout", std::to_string(config.timeout_seconds),
  };
  if (!config.upload) args.emplace_back("--no-upload");
  // Encryption is stated explicitly rather than left to the uploader's default:
  // the config value is the operator's decision and must not depend on whether
  // this particular code path remembered to pass it.
  args.emplace_back(config.encrypt ? "--encrypt" : "--no-encrypt");
  args.emplace_back("--recipient");
  args.emplace_back(config.encryption_recipient.empty() ? "user"
                                                        : config.encryption_recipient);
  if (!config.admin_public_key.empty()) {
    args.emplace_back("--admin-key");
    args.emplace_back(config.admin_public_key);
  }

  proc::run_options process;
  process.timeout = std::chrono::seconds(config.timeout_seconds + 30);
  process.max_stdout_bytes = 16u * 1024u * 1024u;
  process.working_dir = std::filesystem::current_path().string();
  const proc::run_result command = proc::run(python_command(), args, process);
  out.standard_output = command.std_out;
  out.standard_error = command.std_err;
  if (command.status != proc::launch_status::ok || command.exit_code != 0) {
    out.error = command.status == proc::launch_status::ok
                    ? "uploader exited with status " + std::to_string(command.exit_code)
                    : "could not run uploader: " + command.error;
    return out;
  }

  const std::filesystem::path bundle =
      std::filesystem::path(config.output_root) / (config.artifact_name + "_artifact");
  const std::vector<std::filesystem::path> expected{
      bundle / (config.artifact_name + "_evidence.tar.gz"),
      bundle / (config.artifact_name + "_evidence.tar.gz.sha256"),
      bundle / "manifest.json",
      bundle / "README.txt",
  };
  for (const auto& path : expected) {
    std::error_code ec;
    if (!std::filesystem::is_regular_file(path, ec) || ec) {
      out.error = "uploader completed without creating expected artifact: " + path.string();
      return out;
    }
    out.artifacts.push_back(path.string());
  }

  out.ok = true;
  out.bundle_created = true;
  out.uploaded = config.upload;
  out.encrypted = config.encrypt;
  return out;
}

}  // namespace mega_runner
