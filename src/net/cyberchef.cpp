#include "cyberchef.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <nlohmann/json.hpp>
#include <sstream>
#include <string>
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

// --- flag decision ---------------------------------------------------------

struct score_t {
  std::vector<std::string> indicators;
  std::vector<std::string> urls;
};

// Readable text that hits at least one strong indicator is flaggable.
// This is what keeps a benign English sentence decoded from ROT13 quiet.
bool score_text(const std::string& text, score_t& out) {
  if (text.size() < 8 || printable_ratio(text) < 0.80) return false;

  const std::string lower = to_lower(text);
  for (const char* ind : k_indicators) {
    if (lower.find(ind) != std::string::npos)
      out.indicators.emplace_back(ind);
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
  proc::run_options ro;
  ro.timeout = std::chrono::milliseconds(3000);
  ro.max_stdout_bytes = 4096;
  ro.max_stderr_bytes = 1024;
  const proc::run_result run =
      proc::run("wsl.exe", std::vector<std::string>{"--", "hostname", "-I"}, ro);
  std::vector<std::string> ips;
  if (run.status != proc::launch_status::ok || run.exit_code != 0) return ips;
  std::istringstream in(run.std_out);
  std::string token;
  while (in >> token) {
    if (token.find('.') != std::string::npos &&
        token.find_first_of("0123456789") != std::string::npos)
      ips.push_back(token);
  }
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

  // -- ROT suspects: decode locally, screen, confirm through /bake --------
  struct suspect {
    std::size_t idx;
    std::string recipe;
  };
  std::vector<suspect> suspects;
  std::unordered_set<std::string> seen;
  for (std::size_t i = 0;
       i < strings.size() && suspects.size() < o.max_rot_candidates; ++i) {
    const std::string& s = strings[i];
    if (s.size() < o.min_string_length || s.size() > o.max_string_length)
      continue;
    if (printable_ratio(s) < 0.90) continue;  // binary blobs: not text
    if (!seen.insert(s).second) continue;     // duplicates cost nothing extra
    score_t scratch;
    if (score_text(rot13(s), scratch)) {
      suspects.push_back({i, "ROT13"});
      continue;
    }
    scratch = {};
    if (score_text(rot47(s), scratch)) suspects.push_back({i, "ROT47"});
  }
  r.candidates_rot = suspects.size();

  // -- encoding-shaped candidates for /magic ------------------------------
  std::vector<std::size_t> magic_idx;
  std::unordered_set<std::string> seen_shape;
  for (std::size_t i = 0;
       i < strings.size() && magic_idx.size() < o.max_magic_candidates; ++i) {
    const std::string& s = strings[i];
    if (s.size() < o.min_string_length || s.size() > o.max_string_length)
      continue;
    if (!(looks_like_b64(s, o) || looks_like_hex(s, o) ||
          looks_like_pct(s, o)))
      continue;
    if (!seen_shape.insert(s).second) continue;
    magic_idx.push_back(i);
  }
  r.candidates_magic = magic_idx.size();

  // -- /bake: the server re-decodes every suspect -------------------------
  for (const suspect& sus : suspects) {
    const std::string& original = strings[sus.idx];
    json recipe = json::array();
    recipe.push_back(json{{"op", sus.recipe}});
    json resp = post_json(a, "/bake",
                          json{{"input", original},
                               {"recipe", recipe},
                               {"outputType", "string"}});
    if (resp.is_discarded() || !resp.contains("value") ||
        !resp["value"].is_string())
      continue;
    const std::string decoded = resp["value"].get<std::string>();
    score_t hit;
    if (!score_text(decoded, hit)) continue;  // API output is the truth
    r.flagged.push_back(ioc::encoded_flag_t{
        sus.recipe, clip(original, 400), clip(decoded, 1500),
        std::move(hit.indicators), std::move(hit.urls)});
  }

  // -- /magic: CyberChef's own detection for encoding shapes --------------
  for (std::size_t idx : magic_idx) {
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
      const std::string data = sug["data"].get<std::string>();
      if (data == original) continue;  // identity suggestion
      score_t hit;
      if (!score_text(data, hit)) continue;
      r.flagged.push_back(ioc::encoded_flag_t{
          op, clip(original, 400), clip(data, 1500),
          std::move(hit.indicators), std::move(hit.urls)});
      break;
    }
  }

  r.calls = a.calls;
  r.flags = r.flagged.size();
  LOG_INFO(
      "cyberchef: {} string(s) -> {} rot suspect(s), {} shape candidate(s), "
      "{} HTTP call(s), {} flag(s)",
      strings.size(), r.candidates_rot, r.candidates_magic, r.calls, r.flags);
  return r;
}

}  // namespace cyberchef
