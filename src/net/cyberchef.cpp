#include "cyberchef.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <nlohmann/json.hpp>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "http_client.hpp"
#include "logging.hpp"
#include "process_runner.hpp"

namespace cyberchef {
namespace {

using json = nlohmann::json;

// ---------------------------------------------------------------------------
// Suspicious indicators - matched case-insensitively against *decoded* text.
// Deliberately strong terms (launcher / LOLBin names, download cradles,
// evasion switches, shells, persistence). A bare URL is not enough on its
// own: benign XML schema URIs decode all the time. URLs are recorded on a
// flag only once an indicator has already fired.
// ---------------------------------------------------------------------------
constexpr const char* k_indicators[] = {
    // script engines / LOLBins
    "powershell", "pwsh", "cmd.exe", "wscript", "cscript", "mshta",
    "rundll32", "regsvr32", "regasm", "certutil", "bitsadmin", "msbuild",
    "installutil", "msiexec", "forfiles",
    // download cradles / remote execution
    "iex", "invoke-expression", "invoke-command", "invoke-webrequest",
    "downloadstring", "downloadfile", "net.webclient", "net.webrequest",
    "start-bitstransfer", "frombase64string",
    // evasion / payload handling
    "amsi", "-nop", "-exec", "bypass", "windowstyle", "virtualalloc",
    "writeprocessmemory", "getprocaddress", "createremotethread",
    "virtualprotect",
    // shells / post-ex
    "/bin/sh", "/bin/bash", "chmod +x", "reverse shell", "bash -i",
    "mimikatz", "meterpreter", "procdump", "lsass",
    "shell_exec", "base64_decode", "eval(", " system(", "popen(",
    "runtime.getruntime", "processbuilder",
    // persistence / host changes
    "currentversion\\run", "\\startup", "schtasks", "crontab",
    "icacls ", "net user", "net localgroup",
};

// --- small helpers ---------------------------------------------------------

std::string to_lower(std::string s) {
  for (char& c : s)
    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return s;
}

// Printable ASCII (space..~) plus tab / newline / CR.
double printable_ratio(const std::string& s) {
  if (s.empty()) return 0.0;
  std::size_t good = 0;
  for (unsigned char c : s) {
    if ((c >= 32 && c <= 126) || c == '\t' || c == '\n' || c == '\r') ++good;
  }
  return static_cast<double>(good) / static_cast<double>(s.size());
}

std::string clip(const std::string& s, std::size_t n) {
  return s.size() <= n ? s : s.substr(0, n) + "...";
}

// --- ROT family (local screen; the API re-decodes every suspect) -----------

std::string rot13(const std::string& s) {
  std::string out = s;
  for (char& c : out) {
    const unsigned char u = static_cast<unsigned char>(c);
    if (u >= 'a' && u <= 'z')
      c = static_cast<char>('a' + (u - 'a' + 13) % 26);
    else if (u >= 'A' && u <= 'Z')
      c = static_cast<char>('A' + (u - 'A' + 13) % 26);
  }
  return out;
}

std::string rot47(const std::string& s) {
  std::string out = s;
  for (char& c : out) {
    const unsigned char u = static_cast<unsigned char>(c);
    if (u >= 33 && u <= 126)
      c = static_cast<char>(33 + (u - 33 + 47) % 94);
  }
  return out;
}

// --- generalized printable ROT ---------------------------------------------
// No CyberChef op exists for an arbitrary printable-ROT amount, so this
// family is decided locally (ROT47 - the n = 47 case - stays on the /bake
// path above; a string only ever takes one of the two routes).

// Shift within 0x20..0x7E by n (mod 95). Light obfuscators and config
// blobs use amounts other than 13/47; the screen below tries them all.
std::string rot_printable(const std::string& s, unsigned n) {
  std::string out = s;
  for (char& c : out) {
    const unsigned char u = static_cast<unsigned char>(c);
    if (u >= 0x20 && u <= 0x7E)
      c = static_cast<char>(0x20 + (u - 0x20 + n) % 95);
  }
  return out;
}

// --- per-byte bit rotation --------------------------------------------------
// What CyberChef's "Rotate left/right" does with carry-through disabled:
// the bits falling off one side re-enter on the other, so - unlike a bit
// shift, which is lossy and untraceable - rotation is information-
// preserving. It still destroys printability for most inputs, which is why
// candidates are rare; the screen exists because samples do use it.
std::string rotate_bits(const std::string& s, unsigned n, bool left) {
  std::string out = s;
  for (char& c : out) {
    unsigned b = static_cast<unsigned char>(c);
    for (unsigned i = 0; i < n; ++i)
      b = left ? ((b << 1) & 0xFFu) | ((b >> 7) & 1u)
               : ((b >> 1) & 0xFFu) | ((b & 1u) << 7);
    c = static_cast<char>(b);
  }
  return out;
}

// --- single-byte XOR --------------------------------------------------------
// The classic string obfuscator: local brute force over keys 1..255, the
// winning key is then confirmed through /bake (op "XOR").

std::string xor_decode(const std::string& s, unsigned key) {
  std::string out = s;
  for (char& c : out)
    c = static_cast<char>(static_cast<unsigned char>(c) ^ key);
  return out;
}

// PowerShell's -enc shape: UTF-16LE text whose ASCII range survives as
// every other byte. If a decode is NUL-heavy, dropping the NULs recovers
// the payload - which is all an indicator match needs.
std::string maybe_utf16le_ascii(const std::string& s) {
  if (s.size() < 4) return s;
  std::size_t nuls = 0;
  for (unsigned char c : s) {
    if (c == '\0') ++nuls;
  }
  if (nuls * 10 < s.size() * 3) return s;  // under 30 %: not UTF-16LE-ish
  std::string out;
  out.reserve(s.size() - nuls);
  for (unsigned char c : s) {
    if (c != '\0') out.push_back(static_cast<char>(c));
  }
  return out;
}

// --- local base64 -----------------------------------------------------------
// Only reached when /magic declines to decode a b64-shaped string; the
// winning decode is still re-confirmed through /bake. Handles the standard
// and URL-safe alphabets and tolerates missing padding.

int b64_value(unsigned char c) {
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a' + 26;
  if (c >= '0' && c <= '9') return c - '0' + 52;
  if (c == '+' || c == '-') return 62;
  if (c == '/' || c == '_') return 63;
  return -1;
}

bool b64_decode(const std::string& s, std::string& out) {
  out.clear();
  unsigned acc = 0;
  int bits = 0;
  for (unsigned char c : s) {
    if (c == '=') break;  // padding: nothing more to decode
    const int v = b64_value(c);
    if (v < 0) return false;  // not a base64 alphabet after all
    acc = (acc << 6) | static_cast<unsigned>(v);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push_back(static_cast<char>((acc >> bits) & 0xFFu));
    }
  }
  return !out.empty();
}

// --- flag decision ---------------------------------------------------------

struct score_t {
  std::vector<std::string> indicators;
  std::vector<std::string> urls;
};

// Indicator list, built once. Pure alphanumeric words are matched on word
// boundaries ("iex" must not fire inside "OIEXN" - the brute-force screens
// produce plenty of pseudo-words); anything with punctuation stays a
// substring match.
const std::vector<std::pair<std::string, bool>>& indicator_list() {
  static const auto list = [] {
    std::vector<std::pair<std::string, bool>> v;
    for (const char* ind : k_indicators) {
      const std::string s = ind;
      const bool word = std::all_of(s.begin(), s.end(), [](unsigned char c) {
        return std::isalnum(c) != 0;
      });
      v.emplace_back(s, word);
    }
    return v;
  }();
  return list;
}

// Readable text that hits at least one strong indicator is flaggable.
// This is what keeps a benign English sentence decoded from ROT13 quiet.
// min_indicator_len lets the brute-force screens ignore short words like
// "iex" that turn up by pure chance in pseudo-text.
bool score_text(const std::string& text, score_t& out,
                std::size_t min_indicator_len = 0) {
  if (text.size() < 8 || printable_ratio(text) < 0.80) return false;

  const std::string lower = to_lower(text);
  for (const auto& entry : indicator_list()) {
    const std::string& ind = entry.first;
    if (ind.size() < min_indicator_len) continue;
    if (!entry.second) {  // punctuation form: substring match
      if (lower.find(ind) != std::string::npos) out.indicators.push_back(ind);
      continue;
    }
    std::size_t pos = lower.find(ind);
    while (pos != std::string::npos) {
      const bool ok_left =
          pos == 0 ||
          !std::isalnum(static_cast<unsigned char>(lower[pos - 1]));
      const std::size_t end = pos + ind.size();
      const bool ok_right =
          end == lower.size() ||
          !std::isalnum(static_cast<unsigned char>(lower[end]));
      if (ok_left && ok_right) {
        out.indicators.push_back(ind);
        break;
      }
      pos = lower.find(ind, pos + 1);
    }
  }
  if (out.indicators.empty()) return false;

  // URLs ride along on an already-flagged decode (max 4, bounded length).
  static constexpr const char* k_schemes[] = {"http://", "https://", "ftp://"};
  static constexpr const char* k_url_chars = "/:?#[]@!$&'()*+,;=-._~%";
  for (const char* scheme : k_schemes) {
    std::size_t pos = 0;
    while (out.urls.size() < 4 &&
           (pos = lower.find(scheme, pos)) != std::string::npos) {
      std::size_t end = pos;
      while (end < text.size() && text[end] != '\0' &&
             (std::isalnum(static_cast<unsigned char>(text[end])) ||
              std::strchr(k_url_chars, text[end]) != nullptr))
        ++end;
      if (end - pos >= 10)
        out.urls.push_back(
            text.substr(pos, std::min<std::size_t>(end - pos, 200)));
      pos = end + 1;
    }
  }
  return true;
}

// --- candidate shapes for /magic -------------------------------------------

bool looks_like_b64(const std::string& s, const options& o) {
  if (s.size() < 16 || s.size() > o.max_string_length) return false;
  bool digit = false, letter = false;
  for (char c : s) {
    if (c == '+' || c == '/' || c == '=') continue;
    if (std::isdigit(static_cast<unsigned char>(c))) { digit = true; continue; }
    if (std::isalpha(static_cast<unsigned char>(c))) { letter = true; continue; }
    return false;
  }
  return digit && letter;
}

bool looks_like_hex(const std::string& s, const options& o) {
  if (s.size() < 16 || s.size() > o.max_string_length || s.size() % 2 != 0)
    return false;
  for (char c : s) {
    if (!std::isxdigit(static_cast<unsigned char>(c))) return false;
  }
  return true;
}

bool looks_like_pct(const std::string& s, const options& o) {
  if (s.size() < 8 || s.size() > o.max_string_length) return false;
  std::size_t hits = 0;
  for (std::size_t i = 0; i + 2 < s.size(); ++i) {
    if (s[i] == '%' && std::isxdigit(static_cast<unsigned char>(s[i + 1])) &&
        std::isxdigit(static_cast<unsigned char>(s[i + 2])))
      ++hits;
  }
  return hits >= 2;
}

// --- API-hash constants (PJW / DJB2 / FNV-1a) -------------------------------
// Shellcode and loaders hide API names behind 32-bit hashes; the constants
// surface as string literals ("0x0AADF0F1", decimal) in config blobs and
// stubs. Matching is pure local math - a hash is not decodable, so nothing
// goes over HTTP.

std::uint32_t pjw_hash(const std::string& s) {
  std::uint32_t h = 0;
  for (unsigned char c : s) {
    h = (h << 4) + c;
    const std::uint32_t g = h & 0xF0000000u;
    if (g != 0) {
      h ^= g >> 24;
      h &= ~g;
    }
  }
  return h;
}

std::uint32_t djb2_hash(const std::string& s) {
  std::uint32_t h = 5381;
  for (unsigned char c : s) h = h * 33 + c;
  return h;
}

std::uint32_t fnv1a_hash(const std::string& s) {
  std::uint32_t h = 2166136261u;
  for (unsigned char c : s) h = (h ^ c) * 16777619u;
  return h;
}

struct api_hash_hit {
  const char* algo;
  const char* api;
};

const std::vector<std::string>& api_names() {
  static const std::vector<std::string> names = {
      "LoadLibraryA",   "LoadLibraryW",       "LoadLibraryExA",
      "GetProcAddress", "GetModuleHandleA",   "GetModuleHandleW",
      "GetModuleFileNameA", "VirtualAlloc",   "VirtualAllocEx",
      "VirtualProtect", "VirtualProtectEx",   "VirtualFree",
      "VirtualQuery",   "WriteProcessMemory", "ReadProcessMemory",
      "CreateRemoteThread", "CreateThread",   "OpenProcess",
      "CreateProcessA", "CreateProcessW",     "WinExec",
      "ShellExecuteA",  "ShellExecuteW",      "CreateFileA",
      "WriteFile",      "ReadFile",           "IsDebuggerPresent",
      "CheckRemoteDebuggerPresent",           "ExitProcess",
      "TerminateProcess", "MessageBoxA",      "MessageBoxW",
      "Sleep",          "GetTickCount",       "WSASocketA",
      "WSAStartup",     "socket",             "connect",
      "send",           "recv",               "gethostbyname",
      "InternetOpenA",  "InternetOpenUrlA",   "InternetReadFile",
      "URLDownloadToFileA", "WinHttpOpen",    "RegOpenKeyExA",
      "RegSetValueExA", "NtQueryInformationProcess",
  };
  return names;
}

const std::unordered_map<std::uint32_t, std::vector<api_hash_hit>>&
api_hashes() {
  static const auto table = [] {
    std::unordered_map<std::uint32_t, std::vector<api_hash_hit>> t;
    for (const std::string& name : api_names()) {
      t[pjw_hash(name)].push_back({"PJW", name.c_str()});
      t[djb2_hash(name)].push_back({"DJB2", name.c_str()});
      t[fnv1a_hash(name)].push_back({"FNV-1a", name.c_str()});
    }
    return t;
  }();
  return table;
}

// Literals seen in the wild: "0x1234ABCD" (needs the 0x prefix to stay
// specific) or plain decimal. Small numbers are ignored - an API hash
// below 0x1000 is almost certainly a coincidence.
void scan_hash_constants(const std::string& s,
                         std::vector<ioc::encoded_flag_t>& out) {
  const auto& table = api_hashes();
  for (std::size_t i = 0; i < s.size(); ++i) {
    std::string token;
    std::uint32_t value = 0;
    std::size_t j = i;
    const bool hex = s[i] == '0' && i + 1 < s.size() &&
                     (s[i + 1] == 'x' || s[i + 1] == 'X');
    if (hex) {
      j = i + 2;
      while (j < s.size() && j - i - 2 < 10 &&
             std::isxdigit(static_cast<unsigned char>(s[j])))
        ++j;
      if (j - i - 2 < 6) continue;
      token = s.substr(i, j - i);
      value = static_cast<std::uint32_t>(
          std::strtoul(token.c_str() + 2, nullptr, 16));
    } else if (std::isdigit(static_cast<unsigned char>(s[i]))) {
      while (j < s.size() && j - i < 10 &&
             std::isdigit(static_cast<unsigned char>(s[j])))
        ++j;
      if (j - i < 5) continue;
      token = s.substr(i, j - i);
      const unsigned long v = std::strtoul(token.c_str(), nullptr, 10);
      if (v > 0xFFFFFFFFul) continue;
      value = static_cast<std::uint32_t>(v);
    } else {
      continue;
    }
    if (value >= 0x1000) {
      const auto it = table.find(value);
      if (it != table.end()) {
        for (const api_hash_hit& h : it->second) {
          out.push_back(ioc::encoded_flag_t{
              std::string(h.algo) + " API hash", clip(s, 400),
              std::string(h.api) + " (" + token + ")", {to_lower(h.api)}, {}});
        }
      }
    }
    i = j - 1;
  }
}

// --- base32 / base58 / base85 shapes ----------------------------------------
// Guarded loosely on purpose: /magic does the real detection and a flag
// still requires an indicator hit on the decoded text, so a false shape
// candidate costs one request and nothing else.

bool looks_like_b32(const std::string& s, const options& o) {
  if (s.size() < 16 || s.size() > o.max_string_length) return false;
  // Wants padding or an 8-multiple length plus at least two digits - plain
  // upper-case words never match.
  if (s.back() != '=' && s.size() % 8 != 0) return false;
  std::size_t digits = 0;
  for (char c : s) {
    if (c == '=') continue;
    if (c >= '2' && c <= '7') {
      ++digits;
      continue;
    }
    if (c >= 'A' && c <= 'Z') continue;
    return false;
  }
  return digits >= 2;
}

bool looks_like_b58(const std::string& s, const options& o) {
  if (s.size() < 32 || s.size() > o.max_string_length) return false;
  bool digit = false, upper = false, lower = false;
  for (char c : s) {
    if (c >= '1' && c <= '9') {
      digit = true;
      continue;
    }
    if ((c >= 'A' && c <= 'Z') && c != 'I' && c != 'O') {
      upper = true;
      continue;
    }
    if ((c >= 'a' && c <= 'z') && c != 'l') {
      lower = true;
      continue;
    }
    return false;
  }
  // Real base58 payloads mix digits and both cases; identifier soup does not.
  return digit && upper && lower;
}

bool looks_like_b85(const std::string& s, const options& o) {
  if (s.size() < 16 || s.size() > o.max_string_length) return false;
  std::size_t punct = 0;
  bool digit = false;
  for (char c : s) {
    const unsigned char u = static_cast<unsigned char>(c);
    if (u < 0x21 || u > 0x75) return false;  // standard ASCII85 alphabet
    if (std::isdigit(u)) {
      digit = true;
      continue;
    }
    if (!std::isalnum(u)) ++punct;
  }
  return punct >= 2 && digit;  // words without punctuation/digits are not b85
}

// --- thin HTTP wrapper -----------------------------------------------------

struct api_client {
  std::unique_ptr<cti::http_client> http;
  const options* o = nullptr;
  std::size_t calls = 0;
  std::string last_error;
};

json post_json(api_client& a, const std::string& path, const json& body) {
  cti::http_request req;
  req.method = "POST";
  req.url = a.o->base_url + path;
  req.headers = {{"Content-Type", "application/json"}};
  // replace: candidate strings can contain arbitrary bytes.
  req.body = body.dump(-1, ' ', false, json::error_handler_t::replace);
  req.timeout_ms = a.o->request_timeout_ms;
  req.max_response_bytes = 8u * 1024u * 1024u;
  ++a.calls;

  const cti::http_response resp = a.http->perform(req);
  if (!resp.ok()) {
    a.last_error = resp.transport_ok
                       ? ("HTTP " + std::to_string(resp.status))
                       : resp.error;
    return json(json::value_t::discarded);
  }
  json parsed = json::parse(resp.body, nullptr, false);
  if (parsed.is_discarded()) a.last_error = "response is not valid JSON";
  return parsed;
}

// WSL eth0 addresses, for the loopback-relay fallback:
// `wsl.exe -- hostname -I`. Empty when WSL is not reachable.
std::vector<std::string> discover_wsl_ips() {
  std::vector<std::string> ips;
#ifdef _WIN32
  proc::run_options ro;
  ro.timeout = std::chrono::milliseconds(3000);
  ro.max_stdout_bytes = 4096;
  ro.max_stderr_bytes = 1024;
  const proc::run_result run =
      proc::run("wsl.exe", std::vector<std::string>{"--", "hostname", "-I"}, ro);
  if (run.status != proc::launch_status::ok || run.exit_code != 0) return ips;
  std::istringstream in(run.std_out);
  std::string token;
  while (in >> token) {
    if (token.find('.') != std::string::npos &&
        token.find_first_of("0123456789") != std::string::npos)
      ips.push_back(token);
  }
#endif
  return ips;
}

}  // namespace

scan_result_t scan(const std::vector<std::string>& strings,
                   const options& opts) {
  scan_result_t r;
  options o = opts;
  if (const char* v = std::getenv("CYBERCHEF_DISABLE");
      v != nullptr && *v != '\0' && std::string(v) != "0") {
    r.skipped = true;
    r.error = "CYBERCHEF_DISABLE is set";
    return r;
  }
  const char* env_url = std::getenv("CYBERCHEF_URL");
  const bool have_env_url = env_url != nullptr && *env_url != '\0';
  if (have_env_url) o.base_url = env_url;

  cti::http_options hop;
  hop.user_agent = "static-analyzer-cyberchef/1.0";
  hop.max_retries = 0;  // loopback: no point retrying over HTTP
  hop.connect_timeout_ms = o.connect_timeout_ms;
  api_client a{cti::make_curl_client(hop), &o, 0, {}};
  if (!a.http) {
    r.error = "libcurl could not be initialised";
    return r;
  }

  // -- health: the gate for everything else. Loopback first; if the WSL
  // relay has not registered the port (it only picks up listeners present
  // at distro boot) and no explicit URL was given, fall back to the WSL
  // eth0 address, where the container publishes on all interfaces.
  std::string port = ":60001";
  if (const std::size_t colon = o.base_url.rfind(':');
      colon != std::string::npos)
    port = o.base_url.substr(colon);
  auto probe_health = [&](const std::string& base) {
    cti::http_request hq;
    hq.method = "GET";
    hq.url = base + "/health";
    hq.timeout_ms = 1500;
    hq.max_response_bytes = 64u * 1024u;
    const cti::http_response health = a.http->perform(hq);
    if (!health.ok()) {
      r.error = health.transport_ok
                    ? ("HTTP " + std::to_string(health.status))
                    : health.error;
      return false;
    }
    return true;
  };

  bool up = probe_health(o.base_url);
  if (!up && !have_env_url) {
    for (const std::string& ip : discover_wsl_ips()) {
      const std::string base = "http://" + ip + port;
      if (base == o.base_url) continue;
      if (probe_health(base)) {
        LOG_INFO("cyberchef: loopback relay not registered, using {}", base);
        o.base_url = base;
        up = true;
        break;
      }
    }
  }
  if (!up) {
    LOG_WARN("cyberchef: {} not reachable ({})", o.base_url, r.error);
    return r;
  }
  r.error.clear();
  r.server_ok = true;

  // -- local screens -------------------------------------------------------
  // Every stage decodes locally and only sends *suspects* over HTTP. A flag
  // marks its string, so later stages (and /magic) skip it: one string
  // yields at most one flag.
  struct suspect {
    std::size_t idx;
    std::string op;     // CyberChef operation for the /bake recipe
    std::string label;  // recipe as reported (may carry the key or amount)
    json args;          // /bake args (null when the op takes none)
    bool has_args = false;
    // Brute-force decodes use 4: short words like "iex" appear in
    // pseudo-text far too easily (e.g. inside a XORed "EXCEPTION").
    std::size_t min_ind = 0;
  };
  std::vector<suspect> suspects;         // ROT13 / ROT47, confirmed via /bake
  std::vector<suspect> rotate_suspects;  // bit rotations, confirmed via /bake
  std::vector<suspect> xor_suspects;     // winning XOR keys, via /bake
  std::unordered_set<std::size_t> flagged_idx;

  // API-hash constants first: pure local math, and a numeric literal is no
  // rot/xor candidate anyway.
  for (std::size_t i = 0; i < strings.size(); ++i) {
    const std::size_t before = r.flagged.size();
    scan_hash_constants(strings[i], r.flagged);
    if (r.flagged.size() != before) flagged_idx.insert(i);
  }
  r.candidates_hash = r.flagged.size();

  // ROT family. ROT13/ROT47 are confirmed through /bake; a printable-ROT hit
  // has no server op to confirm against, so it is the flag itself (the same
  // client-side decision as the indicator match).
  std::unordered_set<std::string> seen;
  std::size_t screened = 0;
  std::size_t rot_found = 0;
  for (std::size_t i = 0;
       i < strings.size() && rot_found < o.max_rot_candidates; ++i) {
    const std::string& s = strings[i];
    if (s.size() < o.min_string_length || s.size() > o.max_string_length)
      continue;
    if (printable_ratio(s) < 0.90) continue;  // binary blobs: not text
    if (flagged_idx.count(i) != 0) continue;
    if (!seen.insert(s).second) continue;     // duplicates cost nothing extra
    ++screened;
    score_t scratch;
    if (score_text(rot13(s), scratch)) {
      suspects.push_back({i, "ROT13", "ROT13", json(), false});
      ++rot_found;
      continue;
    }
    scratch = {};
    if (score_text(rot47(s), scratch)) {
      suspects.push_back({i, "ROT47", "ROT47", json(), false});
      ++rot_found;
      continue;
    }
    if (s.size() > 256 || screened > o.max_local_screen_strings) continue;
    for (unsigned n = 1; n <= 94; ++n) {
      scratch = {};
      const std::string dec = rot_printable(s, n);
      if (!score_text(dec, scratch, 4)) continue;
      r.flagged.push_back(ioc::encoded_flag_t{
          "ROT printable +" + std::to_string(n), clip(s, 400),
          clip(dec, 1500), std::move(scratch.indicators),
          std::move(scratch.urls)});
      flagged_idx.insert(i);
      ++rot_found;
      break;
    }
  }
  r.candidates_rot = rot_found;

  // Per-byte bit rotations (ROTL / ROTR, 1..7 bits): confirmed through
  // /bake with the op args the server expects - amount, carry-through off.
  std::unordered_set<std::string> seen_rot;
  screened = 0;
  for (std::size_t i = 0;
       i < strings.size() &&
       rotate_suspects.size() < o.max_rotate_candidates; ++i) {
    const std::string& s = strings[i];
    if (s.size() < o.min_string_length || s.size() > 256) continue;
    if (printable_ratio(s) < 0.90) continue;
    if (flagged_idx.count(i) != 0) continue;
    if (!seen_rot.insert(s).second) continue;
    if (++screened > o.max_local_screen_strings) break;
    for (unsigned n = 1; n <= 7; ++n) {
      bool found = false;
      for (unsigned dir = 0; dir < 2 && !found; ++dir) {
        const bool left = dir == 0;
        score_t scratch;
        if (!score_text(rotate_bits(s, n, left), scratch, 4)) continue;
        rotate_suspects.push_back(
            {i, left ? "Rotate left" : "Rotate right",
             std::string(left ? "Rotate left " : "Rotate right ") +
                 std::to_string(n),
             json::array({n, false}), true, 4});
        found = true;
      }
      if (found) break;
    }
  }
  r.candidates_rotate = rotate_suspects.size();

  // Single-byte XOR: brute the keys locally, keep the first (and normally
  // only) key that yields readable indicator-bearing text.
  std::unordered_set<std::string> seen_xor;
  screened = 0;
  for (std::size_t i = 0;
       i < strings.size() && xor_suspects.size() < o.max_xor_candidates; ++i) {
    const std::string& s = strings[i];
    if (s.size() < o.min_string_length || s.size() > 256) continue;
    if (printable_ratio(s) < 0.90) continue;
    if (flagged_idx.count(i) != 0) continue;
    if (!seen_xor.insert(s).second) continue;
    if (++screened > o.max_local_screen_strings) break;
    const std::string lower_s = to_lower(s);
    for (unsigned key = 1; key <= 255; ++key) {
      const std::string dec = xor_decode(s, key);
      if (printable_ratio(dec) < 0.90) continue;
      if (to_lower(dec) == lower_s) continue;  // case flip only: not obfuscation
      score_t scratch;
      if (!score_text(dec, scratch, 4)) continue;
      char hx[4];
      std::snprintf(hx, sizeof(hx), "%02x", key);
      const std::string keyhex = hx;
      xor_suspects.push_back(
          {i, "XOR", "XOR 0x" + keyhex,
           json::array({json{{"option", "Hex"}, {"string", keyhex}}}), true,
           4});
      break;
    }
  }
  r.candidates_xor = xor_suspects.size();

  // -- encoding-shaped candidates for /magic ------------------------------
  std::vector<std::size_t> magic_idx;
  std::unordered_set<std::string> seen_shape;
  for (std::size_t i = 0;
       i < strings.size() && magic_idx.size() < o.max_magic_candidates; ++i) {
    const std::string& s = strings[i];
    if (s.size() < o.min_string_length || s.size() > o.max_string_length)
      continue;
    if (flagged_idx.count(i) != 0) continue;
    if (!(looks_like_b64(s, o) || looks_like_hex(s, o) ||
          looks_like_pct(s, o) || looks_like_b32(s, o) ||
          looks_like_b58(s, o) || looks_like_b85(s, o)))
      continue;
    if (!seen_shape.insert(s).second) continue;
    magic_idx.push_back(i);
  }
  r.candidates_magic = magic_idx.size();

  // -- /bake: the server re-decodes every suspect -------------------------
  const auto bake_confirm = [&](const suspect& sus) {
    if (flagged_idx.count(sus.idx) != 0) return;
    json op = json{{"op", sus.op}};
    if (sus.has_args) op["args"] = sus.args;
    json resp = post_json(a, "/bake",
                          json{{"input", strings[sus.idx]},
                               {"recipe", json::array({op})},
                               {"outputType", "string"}});
    if (resp.is_discarded() || !resp.contains("value") ||
        !resp["value"].is_string())
      return;
    const std::string decoded =
        maybe_utf16le_ascii(resp["value"].get<std::string>());
    score_t hit;
    if (!score_text(decoded, hit, sus.min_ind)) return;  // API output is truth
    r.flagged.push_back(ioc::encoded_flag_t{
        sus.label, clip(strings[sus.idx], 400), clip(decoded, 1500),
        std::move(hit.indicators), std::move(hit.urls)});
    flagged_idx.insert(sus.idx);
  };
  for (const suspect& sus : suspects) bake_confirm(sus);
  for (const suspect& sus : rotate_suspects) bake_confirm(sus);
  for (const suspect& sus : xor_suspects) bake_confirm(sus);

  // -- /magic: CyberChef's own detection for encoding shapes --------------
  for (std::size_t idx : magic_idx) {
    if (flagged_idx.count(idx) != 0) continue;
    const std::string& original = strings[idx];
    json resp = post_json(a, "/magic", json{{"input", original}});
    if (resp.is_discarded() || !resp.contains("value") ||
        !resp["value"].is_array())
      continue;
    std::size_t considered = 0;
    for (const json& sug : resp["value"]) {
      if (considered++ >= 3) break;  // top 3 suggestions are enough
      if (!sug.is_object() || !sug.contains("recipe") ||
          !sug["recipe"].is_array() || sug["recipe"].empty())
        continue;
      const json& op0 = sug["recipe"][0];
      if (!op0.is_object() || !op0.contains("op") || !op0["op"].is_string())
        continue;
      const std::string op = op0["op"].get<std::string>();
      if (op.empty() || !sug.contains("data") || !sug["data"].is_string())
        continue;
      const std::string data =
          maybe_utf16le_ascii(sug["data"].get<std::string>());
      if (data == original) continue;  // identity suggestion
      score_t hit;
      if (!score_text(data, hit)) continue;
      r.flagged.push_back(ioc::encoded_flag_t{
          op, clip(original, 400), clip(data, 1500),
          std::move(hit.indicators), std::move(hit.urls)});
      flagged_idx.insert(idx);
      break;
    }
  }

  // -- base64 fallback: /magic has no UTF-16LE story, so a b64-shaped
  // string whose local decode is NUL-heavy (PowerShell -enc) is confirmed
  // through /bake with an explicit "From Base64 + Decode text" recipe -----
  for (std::size_t idx = 0; idx < strings.size(); ++idx) {
    if (flagged_idx.count(idx) != 0) continue;
    const std::string& original = strings[idx];
    if (original.size() < o.min_string_length ||
        original.size() > o.max_string_length)
      continue;
    if (!looks_like_b64(original, o)) continue;
    std::string bytes;
    if (!b64_decode(original, bytes)) continue;
    const std::string norm = maybe_utf16le_ascii(bytes);
    score_t pre;
    if (!score_text(norm, pre)) continue;  // cheap local gate before HTTP
    const bool utf16 = norm != bytes;
    json recipe = json::array();
    recipe.push_back(json{{"op", "From Base64"}});
    if (utf16)
      recipe.push_back(json{{"op", "Decode text"},
                            {"args", json::array({"UTF-16LE (1200)"})}});
    json resp = post_json(a, "/bake",
                          json{{"input", original},
                               {"recipe", recipe},
                               {"outputType", "string"}});
    if (resp.is_discarded() || !resp.contains("value") ||
        !resp["value"].is_string())
      continue;
    const std::string decoded =
        maybe_utf16le_ascii(resp["value"].get<std::string>());
    score_t hit;
    if (!score_text(decoded, hit)) continue;  // API output is the truth
    r.flagged.push_back(ioc::encoded_flag_t{
        utf16 ? "From Base64 + Decode text" : "From Base64",
        clip(original, 400), clip(decoded, 1500),
        std::move(hit.indicators), std::move(hit.urls)});
    flagged_idx.insert(idx);
  }

  r.calls = a.calls;
  r.flags = r.flagged.size();
  LOG_INFO(
      "cyberchef: {} string(s) -> rot {}, rotate {}, xor {}, hash {}, "
      "shape {} candidate(s), {} HTTP call(s), {} flag(s)",
      strings.size(), r.candidates_rot, r.candidates_rotate, r.candidates_xor,
      r.candidates_hash, r.candidates_magic, r.calls, r.flags);
  return r;
}

}  // namespace cyberchef
