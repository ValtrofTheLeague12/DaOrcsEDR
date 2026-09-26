#include "secret_store.hpp"

#include "http_client.hpp"

#include <nlohmann/json.hpp>

#include <cctype>
#include <cstdlib>

// secret_store.cpp
//
// Intentionally free of logging.hpp. See the header for the reasoning: the
// logging layer does not redact, so a secret must never be handed to it.

namespace secret_store {
namespace {

// bw serve binds loopback only and allowlists these host names. Enforced here
// so BW_SESSION can never be aimed at a non-loopback host by a hostile
// environment.
bool is_loopback_url(const std::string& url) {
  static const char* kPrefixes[] = {
      "http://127.0.0.1", "http://localhost", "http://[::1]",
  };
  for (const char* prefix : kPrefixes) {
    if (url.rfind(std::string(prefix), 0) == 0) return true;
  }
  return false;
}

std::string trim(const std::string& text) {
  std::size_t begin = 0;
  std::size_t end = text.size();
  const auto space = [](char c) { return std::isspace(static_cast<unsigned char>(c)) != 0; };
  while (begin < end && space(text[begin])) ++begin;
  while (end > begin && space(text[end - 1])) --end;
  return text.substr(begin, end - begin);
}

cti::http_request make_request(const std::string& url, const std::string& session) {
  cti::http_request request;
  request.method = "GET";
  request.url = url;
  request.headers.emplace_back("Authorization", "Bearer " + session);
  request.headers.emplace_back("Accept", "application/json");
  // Loopback: fail fast rather than hang if bw serve is not running.
  request.timeout_ms = 5000;
  // A vault listing is small; a wrong endpoint should not be able to stream an
  // unbounded body into memory.
  request.max_response_bytes = 8u * 1024u * 1024u;
  return request;
}

}  // namespace

result_t fetch_from_bw_serve(const std::string& item_name, const std::string& base_url) {
  result_t result;

  if (item_name.empty()) {
    result.error = "no item name given";
    return result;
  }
  if (!is_loopback_url(base_url)) {
    result.error = "refusing non-loopback base_url for bw serve";
    return result;
  }

  const char* session_env = std::getenv("BW_SESSION");
  if (session_env == nullptr || *session_env == '\0') {
    result.error = "BW_SESSION is not set - run: export BW_SESSION=$(bw unlock --raw)";
    return result;
  }
  const std::string session = session_env;

  cti::http_options options;
  options.user_agent = "static-analyzer/1.0";
  // bw serve is on loopback and speaks plain HTTP; keep connection attempts
  // short so a missing server surfaces in seconds rather than minutes.
  options.connect_timeout_ms = 2000;
  auto client = cti::make_curl_client(options);
  if (!client) {
    result.error = "libcurl could not be initialised";
    return result;
  }

  // 1. List vault items and find the one with an exact name match.
  std::string base = trim(base_url);
  while (!base.empty() && base.back() == '/') base.pop_back();

  cti::http_response list =
      client->perform(make_request(base + "/object/secure-item/vault-item", session));
  if (!list.transport_ok) {
    result.error = "bw serve unreachable: " + list.error + " (is `bw serve` running?)";
    return result;
  }
  if (list.status == 401) {
    result.error = "bw serve rejected BW_SESSION - the vault is locked or the "
                   "session expired; run: export BW_SESSION=$(bw unlock --raw)";
    return result;
  }
  if (!list.ok()) {
    result.error = "listing vault items failed with HTTP " + std::to_string(list.status);
    return result;
  }

  nlohmann::json items;
  try {
    items = nlohmann::json::parse(list.body);
  } catch (const std::exception&) {
    result.error = "could not parse the vault item list returned by bw serve";
    return result;
  }
  if (!items.is_array()) {
    result.error = "unexpected response shape from bw serve (not a list)";
    return result;
  }

  std::string item_id;
  int matches = 0;
  for (const auto& entry : items) {
    if (!entry.is_object()) continue;
    const auto name = entry.find("name");
    if (name == entry.end() || !name->is_string()) continue;
    if (name->get<std::string>() != item_name) continue;
    const auto id = entry.find("id");
    if (id != entry.end() && id->is_string()) item_id = id->get<std::string>();
    ++matches;
  }

  // Ambiguity is a failure on purpose: silently picking one of two same-named
  // items could send the wrong credential to the wrong service.
  if (matches == 0) {
    result.error = "no vault item named '" + item_name + "'";
    return result;
  }
  if (matches > 1) {
    result.error = "vault has " + std::to_string(matches) + " items named '" +
                   item_name + "'; rename them so the target is unambiguous";
    return result;
  }
  if (item_id.empty()) {
    result.error = "matched item has no id";
    return result;
  }

  // 2. Read that item's decrypted data and take login.password.
  cti::http_response data = client->perform(make_request(
      base + "/object/secure-item/vault-item/" + item_id + "/data", session));
  if (!data.transport_ok) {
    result.error = "reading item data failed: " + data.error;
    return result;
  }
  if (data.status == 401) {
    result.error = "bw serve rejected the session while reading item data";
    return result;
  }
  if (!data.ok()) {
    result.error = "reading item data failed with HTTP " + std::to_string(data.status);
    return result;
  }

  nlohmann::json parsed;
  try {
    parsed = nlohmann::json::parse(data.body);
  } catch (const std::exception&) {
    result.error = "could not parse the item data returned by bw serve";
    return result;
  }
  if (!parsed.is_object()) {
    result.error = "unexpected item data shape from bw serve";
    return result;
  }

  const auto login = parsed.find("login");
  if (login == parsed.end() || !login->is_object()) {
    result.error = "item '" + item_name + "' has no login section";
    return result;
  }
  const auto password = login->find("password");
  if (password == login->end() || !password->is_string() ||
      password->get_ref<const std::string&>().empty()) {
    result.error = "item '" + item_name + "' has an empty password field";
    return result;
  }

  result.ok = true;
  result.value = password->get<std::string>();
  return result;
}

}  // namespace secret_store
