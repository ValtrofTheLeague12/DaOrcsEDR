#include "malapi.hpp"

#include <cctype>
#include <exception>
#include <initializer_list>
#include <set>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

#include "cti.hpp"
#include "logging.hpp"
#include "report.hpp"

namespace {

// The YAML behind every route is {name, dll, description, attacks, source};
// attacks is a list, so the string-only "pick" below can never see it.
std::string join_attacks(const nlohmann::json& j) {
  if (!j.contains("attacks") || !j["attacks"].is_array()) return {};
  std::string out;
  for (const auto& a : j["attacks"]) {
    if (!a.is_string()) continue;
    if (!out.empty()) out += " · ";
    out += a.get<std::string>();
  }
  return out;
}

std::string first_string(const nlohmann::json& j,
                         std::initializer_list<const char*> keys) {
  for (const char* k : keys) {
    if (j.contains(k) && j[k].is_string()) return j[k].get<std::string>();
  }
  return {};
}

std::string ellipsis(std::string text, std::size_t limit) {
  if (text.size() <= limit) return text;
  return text.substr(0, limit - 3) + "...";
}

// Addresses are printed the way r2 and the call-site dump print them:
// 0x14000105e, not the zero-padded hex_value() form.
std::string hex_addr(std::uint64_t value) {
  std::ostringstream os;
  os << "0x" << std::hex << value;
  return os.str();
}

}  // namespace

std::optional<malapi_hit_t> query_malapi(local_api::local_api_server& api,
                                         const std::string& function_name) {
  if (!api.running()) return std::nullopt;

  const std::string path = "/malapi/" + function_name + "/";

  const std::vector<std::pair<std::string, std::string>> headers = {
      {"Accept", "application/json"},
  };

  LOG_DEBUG("malapi: GET {}{}", api.base_url(), path);

  const cti::http_response res = api.get(path, headers, 1 * 1024 * 1024);

  if (!res.transport_ok) {
    LOG_DEBUG("malapi: GET {} transport error: {}", path, res.error);
    return std::nullopt;
  }
  if (res.status < 200 || res.status >= 300) {
    LOG_DEBUG("malapi: GET {} -> HTTP {}", path, res.status);
    return std::nullopt;
  }
  if (res.body.empty()) {
    LOG_DEBUG("malapi: GET {} -> empty body", path);
    return std::nullopt;
  }

  malapi_hit_t hit;
  hit.function = function_name;
  hit.status   = res.status;
  hit.raw_json = res.body;
  return hit;
}

bool looks_like_api_name(const std::string& s) {
  if (s.size() < 4 || s.size() > 64) return false;
  if (!std::isalpha(static_cast<unsigned char>(s.front()))) return false;
  for (unsigned char c : s) {
    if (!std::isalnum(c) && c != '_') return false;
  }
  static const std::set<std::string> kNoise = {
      "true", "false", "nullptr", "void", "int", "char", "long",
      "unsigned", "static", "const", "return",
  };
  return kNoise.find(s) == kNoise.end();
}

std::string format_malapi_hit(const malapi_hit_t& hit) {
  try {
    const auto j = nlohmann::json::parse(hit.raw_json);

    const std::string desc     = first_string(j, {"description", "desc", "summary", "info"});
    const std::string attacks  = join_attacks(j);
    const std::string category = first_string(j, {"category", "type", "class", "tactic"});
    const std::string dll      = first_string(j, {"dll", "module"});
    const std::string mitre    = first_string(j, {"mitre", "attack", "technique", "attck"});
    const std::string severity = first_string(j, {"severity", "risk", "level"});

    std::ostringstream os;
    os << hit.function;
    const std::string tags = !attacks.empty() ? attacks : category;
    if (!tags.empty()) os << "  [" << tags << "]";
    if (!dll.empty())  os << "  " << dll;
    if (!severity.empty()) os << "  sev=" << severity;
    if (!mitre.empty())    os << "  " << mitre;
    if (!desc.empty()) os << "  - " << ellipsis(desc, 120);
    return os.str();
  } catch (const std::exception&) {
    std::string preview = hit.raw_json;
    for (char& c : preview) {
      if (c == '\n' || c == '\r' || c == '\t') c = ' ';
    }
    return hit.function + "  ->  " + ellipsis(preview, 160);
  }
}

void print_malapi_hit(const malapi_hit_t& hit) {
  std::string attacks;
  std::string desc;
  std::string yaml_dll;
  try {
    const auto j   = nlohmann::json::parse(hit.raw_json);
    attacks        = join_attacks(j);
    desc           = first_string(j, {"description", "desc", "summary", "info"});
    yaml_dll       = first_string(j, {"dll", "module"});
  } catch (const std::exception&) {
    // Keep the hit, just without the database fields.
  }

  // --- the hit itself ------------------------------------------------------
  std::ostringstream head;
  head << hit.function;
  if (!attacks.empty()) head << "  [" << attacks << "]";
  const std::string& dll = hit.dll.empty() ? yaml_dll : hit.dll;
  if (!dll.empty()) head << "  " << dll;
  print_bullet(head.str(), console::red);

  // --- where the import lives in this binary -------------------------------
  std::ostringstream import;
  if (!dll.empty()) import << dll << "!";
  if (hit.is_ordinal) {
    import << "#" << hit.ordinal << " (ordinal)";
  } else {
    import << hit.function << "  hint " << hit.hint;
  }
  if (hit.iat_rva != 0) {
    import << "  IAT " << hex_rva(hit.iat_rva);
  }
  if (hit.is_delay) import << "  delay-import";
  print_kv("import", import.str());

  // --- which code references it --------------------------------------------
  std::ostringstream call;
  if (!hit.call_sites.empty()) {
    const malapi_call_site_t& site = hit.call_sites.front();
    call << site.function;
    if (site.function_offset != 0) {
      call << "+" << hex_addr(site.address - site.function_offset);
    }
    call << "  @ " << hex_addr(site.address);
    if (hit.call_sites.size() > 1) {
      call << "  (+" << (hit.call_sites.size() - 1) << " more)";
    }
    print_kv("call", call.str());
  } else if (hit.sites_resolved) {
    // The reason the locations are missing altogether is reported once, at
    // section level - repeating it per hit would drown the list.
    print_kv("call", "no direct reference - reached through a computed pointer");
  }

  if (!desc.empty()) print_kv("about", ellipsis(desc, 160));
}
