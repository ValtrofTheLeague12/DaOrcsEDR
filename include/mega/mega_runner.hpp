#pragma once

#include <string>
#include <vector>

namespace mega_runner {

struct options {
  std::string artifact_name;
  std::string source_directory;
  std::string output_root;
  std::string uploader_script;
  std::string remote_root = "/";
  int timeout_seconds = 900;
  bool upload = false;
  // Wrap the archive in a password-protected zip before it leaves the machine.
  // The uploader refuses to send the plaintext when this is set and protection
  // fails, so a broken password file can never quietly downgrade the bundle to
  // an unprotected upload.
  bool encrypt = false;
  // The password file the zip encryption reads. empty = the uploader's default
  // operator password file outside the repo (the one the panel manages).
  std::string password_file;
};

struct result {
  bool ok = false;
  bool bundle_created = false;
  bool uploaded = false;
  bool encrypted = false;
  std::string error;
  std::string standard_output;
  std::string standard_error;
  std::vector<std::string> artifacts;
};

  // Seal the analyzer's exported results and optionally upload the bundle
  // using the repository's MEGAcmd-backed uploader. No shell is used for
  // invocation.
  result run(const options& config);

}  // namespace mega_runner
