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

    auto pick = [&](std::initializer_list<const char*> keys) -> std::string {
      for (const char* k : keys) {
        if (j.contains(k) && j[k].is_string()) {
          return j[k].get<std::string>();
        }
      }
      return {};
    };

    const std::string desc     = pick({"description", "desc", "summary", "info"});
    const std::string category = pick({"category", "type", "class", "tactic"});
    const std::string mitre    = pick({"mitre", "attack", "technique", "attck"});
    const std::string severity = pick({"severity", "risk", "level"});

    std::ostringstream os;
    os << hit.function;
    if (!category.empty()) os << "  [" << category << "]";
    if (!severity.empty()) os << "  sev=" << severity;
    if (!mitre.empty())    os << "  " << mitre;
    if (!desc.empty()) {
      std::string d = desc;
      if (d.size() > 120) d = d.substr(0, 117) + "...";
      os << "  - " << d;
    }
    return os.str();
  } catch (const std::exception&) {
    std::string preview = hit.raw_json;
    for (char& c : preview) {
      if (c == '\n' || c == '\r' || c == '\t') c = ' ';
    }
    if (preview.size() > 160) preview = preview.substr(0, 157) + "...";
    return hit.function + "  ->  " + preview;
  }
}
