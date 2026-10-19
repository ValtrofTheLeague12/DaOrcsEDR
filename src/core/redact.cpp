#include "redact.hpp"

#include "file_hasher.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <fstream>
#include <mutex>
#include <vector>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
extern char** environ;
#endif

namespace redact {
namespace {

using json = nlohmann::json;

constexpr const char* kMask = "***REDACTED***";
constexpr std::size_t k_min_secret_length = 8;
constexpr std::uintmax_t k_hash_limit_bytes = 64ull * 1024ull * 1024ull;

// Written during the single-threaded startup (seed/seed_pair), read afterwards
// from any thread including the crash handler - so reads take no lock. The
// vector is reserved up front so a late seed_pair never reallocates under a
// reader.
std::mutex g_seed_mtx;
std::vector<std::string> g_secrets;
bool g_files_seeded = false;

std::string lower(std::string_view text) {
  std::string out(text);
  std::transform(out.begin(), out.end(), out.begin(),
                 [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  return out;
}

void add_value_locked(std::string value) {
  while (!value.empty() && (value.front() == ' ' || value.front() == '\t' ||
                            value.front() == '\r' || value.front() == '\n')) {
    value.erase(value.begin());
  }
  while (!value.empty() && (value.back() == ' ' || value.back() == '\t' ||
                            value.back() == '\r' || value.back() == '\n')) {
    value.pop_back();
  }
  if (value.size() < k_min_secret_length) return;
  for (const std::string& known : g_secrets) {
    if (known == value) return;
  }
  g_secrets.push_back(std::move(value));
}

// "NAME=VALUE" from the raw environment block / environ entry.
void seed_env_entry(std::string_view entry) {
  const std::size_t eq = entry.find('=');
  if (eq == std::string_view::npos || eq == 0) return;
  const std::string_view name = entry.substr(0, eq);
  if (!is_secret_name(name)) return;
  add_value_locked(std::string(entry.substr(eq + 1)));
}

void seed_environment_locked() {
#if defined(_WIN32)
  if (LPSTR block = GetEnvironmentStringsA()) {
    for (LPCSTR p = block; p != nullptr && *p != '\0';) {
      const std::string entry(p);
      p += entry.size() + 1;
      seed_env_entry(entry);
    }
    FreeEnvironmentStringsA(block);
  }
#else
  if (environ != nullptr) {
    for (char** p = environ; *p != nullptr; ++p) seed_env_entry(*p);
  }
#endif
}

// Container keys that make every descendant string a secret by construction:
// {"keys":{"virustotal":"..."}} has no per-key name to gate on, so the
// containing key is what identifies the values.
bool secret_key_name(std::string_view key) {
  if (is_secret_name(key)) return true;
  const std::string key_lower = lower(key);
  return key_lower == "keys" || key_lower == "api_keys" || key_lower == "secrets" ||
         key_lower == "credentials" || key_lower == "passwords" ||
         key_lower == "tokens";
}

void walk_json(const json& node, bool inherited_secret) {
  if (node.is_object()) {
    for (auto it = node.begin(); it != node.end(); ++it) {
      const bool secret_here = inherited_secret || secret_key_name(it.key());
      if (it.value().is_string()) {
        if (secret_here) add_value_locked(it.value().get<std::string>());
      } else if (it.value().is_object() || it.value().is_array()) {
        walk_json(it.value(), secret_here);
      }
    }
  } else if (node.is_array()) {
    for (const json& item : node) walk_json(item, inherited_secret);
  }
}

// .env style: KEY=VALUE lines, '#' comments, optional surrounding quotes.
void seed_env_file(const std::filesystem::path& path) {
  std::ifstream in(path);
  if (!in) return;
  std::string line;
  while (std::getline(in, line)) {
    std::size_t first = line.find_first_not_of(" \t");
    if (first == std::string::npos) continue;
    if (line[first] == '#') continue;
    const std::size_t eq = line.find('=', first);
    if (eq == std::string::npos || eq == first) continue;
    std::string name = line.substr(first, eq - first);
    std::string value = line.substr(eq + 1);
    while (!value.empty() &&
           (value.back() == '\r' || value.back() == ' ' || value.back() == '\t')) {
      value.pop_back();
    }
    if (value.size() >= 2 && ((value.front() == '"' && value.back() == '"') ||
                              (value.front() == '\'' && value.back() == '\''))) {
      value = value.substr(1, value.size() - 2);
    }
    if (!is_secret_name(name)) continue;
    add_value_locked(std::move(value));
  }
}

void seed_json_file(const std::filesystem::path& path) {
  std::ifstream in(path);
  if (!in) return;
  try {
    json doc = json::parse(in, nullptr, false);
    if (doc.is_discarded()) return;
    walk_json(doc, false);
  } catch (...) {
    // A malformed credential file must not abort startup; it just contributes
    // fewer secrets to the registry.
  }
}

std::filesystem::path project_root() {
#if defined(STATIC_ANALYZER_SOURCE_DIR)
  return std::filesystem::path(STATIC_ANALYZER_SOURCE_DIR);
#else
  std::error_code ec;
  const auto cwd = std::filesystem::current_path(ec);
  return ec ? std::filesystem::path(".") : cwd;
#endif
}

// Case-insensitive search for `needle` in `text` starting at `from`.
std::size_t ci_find(std::string_view text, std::string_view needle, std::size_t from) {
  if (needle.empty() || text.size() < needle.size()) return std::string_view::npos;
  for (std::size_t i = from; i + needle.size() <= text.size(); ++i) {
    bool match = true;
    for (std::size_t j = 0; j < needle.size(); ++j) {
      const char a = static_cast<char>(std::tolower(static_cast<unsigned char>(text[i + j])));
      const char b = static_cast<char>(std::tolower(static_cast<unsigned char>(needle[j])));
      if (a != b) { match = false; break; }
    }
    if (match) return i;
  }
  return std::string_view::npos;
}

// Masks the token that follows a scheme/keyword: "Bearer <tok>",
// "x-apikey: <tok>". The keyword itself is kept so the log still reads well.
void mask_token_after(std::string& text, std::string_view keyword) {
  std::size_t pos = 0;
  while ((pos = ci_find(text, keyword, pos)) != std::string_view::npos) {
    std::size_t value_start = pos + keyword.size();
    while (value_start < text.size() &&
           (text[value_start] == ' ' || text[value_start] == '\t')) {
      ++value_start;
    }
    std::size_t value_end = value_start;
    while (value_end < text.size()) {
      const char c = text[value_end];
      if (c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '"' || c == '\'' ||
          c == ',' || c == '}' || c == ']' || c == ')' || c == '<' || c == '>') {
        break;
      }
      ++value_end;
    }
    if (value_end > value_start) {
      text.replace(value_start, value_end - value_start, kMask);
      pos = value_start + std::char_traits<char>::length(kMask);
    } else {
      pos = value_start;
    }
  }
}

}  // namespace

bool is_secret_name(std::string_view name) {
  const std::string name_lower = lower(name);
  // Patterns are deliberately name-shaped: *_KEY alone is not enough, because
  // CTI_KEY_NAME / CTI_KEY_TARGET hold an item name and an env-var name, not a
  // secret. ends_with("_KEY") still catches custom "<thing>_KEY" variables.
  static const char* const k_substrings[] = {
      "api_key",     "auth_key",  "token",     "password",  "passwd",
      "secret",      "session",   "private",   "credential", "apikey",
      "passphrase",
  };
  for (const char* needle : k_substrings) {
    if (name_lower.find(needle) != std::string::npos) return true;
  }
  static const char* const k_suffixes[] = {"_key", "_pwd", "_pw"};
  for (const char* suffix : k_suffixes) {
    if (name_lower.size() > std::char_traits<char>::length(suffix) &&
        name_lower.compare(name_lower.size() - std::char_traits<char>::length(suffix),
                           std::string::npos, suffix) == 0) {
      return true;
    }
  }
  return false;
}

void seed() {
  std::lock_guard<std::mutex> lock(g_seed_mtx);
  if (g_secrets.empty()) g_secrets.reserve(64);
  seed_environment_locked();
  if (!g_files_seeded) {
    g_files_seeded = true;
    const std::filesystem::path root = project_root();
    const std::filesystem::path credential_files[] = {
        root / ".env",
        root / ".env.bak",
        root / "qiling_dlls" / "vm_info.json",
        root / "admin-terminal" / "vms.json",
    };
    for (const std::filesystem::path& path : credential_files) {
      if (!std::filesystem::exists(path)) continue;
      const std::string name = lower(path.filename().string());
      if (name.rfind(".env", 0) == 0) seed_env_file(path);
      else seed_json_file(path);
    }

    // CTI_CONFIG: the documented overlay {"keys":{...}} - the one config file
    // whose *values* are API keys by schema, whatever the file is called.
    if (const char* overlay = std::getenv("CTI_CONFIG");
        overlay != nullptr && *overlay != '\0') {
      const std::filesystem::path overlay_path(overlay);
      if (std::filesystem::exists(overlay_path)) seed_json_file(overlay_path);
    }
  }
}

void seed_pair(std::string_view name, std::string_view value) {
  if (!is_secret_name(name)) return;
  std::lock_guard<std::mutex> lock(g_seed_mtx);
  if (g_secrets.empty()) g_secrets.reserve(64);
  add_value_locked(std::string(value));
}

std::string scrub(std::string_view text) {
  if (text.empty()) return {};
  std::string out(text);
  for (const std::string& secret : g_secrets) {
    if (secret.empty()) continue;
    std::size_t pos = 0;
    while ((pos = out.find(secret, pos)) != std::string::npos) {
      out.replace(pos, secret.size(), kMask);
      pos += std::char_traits<char>::length(kMask);
    }
  }
  mask_token_after(out, "bearer ");
  mask_token_after(out, "x-apikey:");
  return out;
}

bool is_denied_path(const std::filesystem::path& path) {
  const std::string name = lower(path.filename().string());
  if (name.empty()) return false;
  return name.rfind(".env", 0) == 0 || name == "vm_info.json" || name == "vms.json";
}

std::string file_summary(const std::filesystem::path& path) {
  const std::string name = path.filename().string();
  std::error_code ec;
  if (!std::filesystem::exists(path, ec) || ec) {
    return std::string("<file '") + name + "' (missing)>";
  }
  const std::uintmax_t size = std::filesystem::file_size(path, ec);
  const std::uintmax_t bytes = ec ? 0 : size;
  const bool denied = is_denied_path(path);

  std::string sha = "skipped";
  if (!ec && bytes > 0 && bytes <= k_hash_limit_bytes) {
    std::vector<std::uint8_t> data(static_cast<std::size_t>(bytes));
    std::ifstream in(path, std::ios::binary);
    if (in) {
      in.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(bytes));
      const auto got = in.gcount();
      if (got > 0) {
        file_hash_t h;
        if (hasher::hash_bytes(h, data.data(), static_cast<std::size_t>(got)) &&
            !h.hash.empty() && h.hash != "N/A") {
          sha = h.hash;
        }
      }
    }
  }

  return std::string(denied ? "<redacted file '" : "<file '") + name + "' (" +
         std::to_string(bytes) + " bytes, sha256=" + sha + ")>";
}

std::size_t secret_count() { return g_secrets.size(); }

}  // namespace redact
