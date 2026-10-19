#pragma once

// Secret redaction for everything the debug stack writes to disk.
//
// The registry holds secret *values* (API keys, tokens, vault passwords) that
// were found in the environment, in .env* and in the two credential files the
// repo keeps (qiling_dlls/vm_info.json, admin-terminal/vms.json). scrub()
// replaces every occurrence with "***REDACTED***", so a dump, a crash report
// or a log line can quote a whole config struct without leaking a key.
//
// Two rules keep the registry useful instead of destructive:
//   * Values are only registered when their *name* looks like a credential
//     (is_secret_name()). VM_IP and YARA_RULES_DIR are not secrets, and
//     scrubbing an IP out of an analysis dump would be worse than the leak.
//   * Only values of 8+ characters are registered, so a short token can never
//     rewrite unrelated text all over the log.
//
// Seeding happens once, single threaded, before the first phase runs. After
// that the registry is read-only and scrub() takes no lock - the crash handler
// must never block on a mutex.

#include <cstddef>
#include <filesystem>
#include <string>
#include <string_view>

namespace redact {

// Fills the registry from the environment and from the credential files.
// Idempotent; safe to call again (seed_pair can still add values).
void seed();

// Adds one name/value pair. Ignored unless is_secret_name(name) and the value
// is long enough to be worth masking.
void seed_pair(std::string_view name, std::string_view value);

// True when the name reads like it holds a credential (case-insensitive):
// *_API_KEY, *_AUTH_KEY, *_KEY, *TOKEN*, *PASSWORD*, *SESSION*, *SECRET*, ...
bool is_secret_name(std::string_view name);

// Returns text with every registered secret (and any "Bearer <token>" /
// "x-apikey: <token>" token) replaced by "***REDACTED***".
std::string scrub(std::string_view text);

// The credential files whose *contents* must never be dumped: .env, .env.*,
// vm_info.json, vms.json (basename match, case-insensitive).
bool is_denied_path(const std::filesystem::path& path);

// Metadata-only rendering of a path - "<file 'x.exe' (123 bytes, sha256=...)>"
// - or "<redacted file ...>" for a denied path. Never returns file contents.
// Intended for normal (non-crash) paths; it reads and hashes the file.
std::string file_summary(const std::filesystem::path& path);

// Registered value count (0 until seed()). For tests.
std::size_t secret_count();

}  // namespace redact
