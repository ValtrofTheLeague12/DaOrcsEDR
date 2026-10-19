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
  // Seal the bundle to a public key before it leaves the machine. The uploader
  // refuses to send the plaintext when this is set and sealing fails, so a
  // broken key can never quietly downgrade the bundle to an unprotected upload.
  bool encrypt = false;
  // "user" (this machine's operator key) or "admin" (the lab's public key).
  std::string encryption_recipient = "user";
  std::string admin_public_key;   // empty = look in the default location
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

// Seal the analyzer's exported results and optionally upload the bundle using
// the repository's MEGAcmd-backed uploader. No shell is used for invocation.
result run(const options& config);

}  // namespace mega_runner
