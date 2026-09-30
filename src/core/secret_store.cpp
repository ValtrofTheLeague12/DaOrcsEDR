#include "secret_store.hpp"

#include "http_client.hpp"
#include "process_runner.hpp"

#include <nlohmann/json.hpp>

#include <cctype>
#include <cstdlib>
#include <memory>
#include <utility>

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

// Normalises a base URL: trims whitespace and drops trailing slashes so the
// request paths below never double up on '/'.
std::string normalize_base(const std::string& base_url) {
  std::string base = trim(base_url);
  while (!base.empty() && base.back() == '/') base.pop_back();
  return base;
}

std::string missing_session_error() {
  return "BW_SESSION is not set - run: export BW_SESSION=$(bw unlock --raw)";
}

// Everything the entry points need to talk to `bw serve`. open_vault()
// validates the preconditions once so the callers only deal with one error
// string; the session token stays inside this structure and never reaches a
// log line.
struct vault_client {
  std::unique_ptr<cti::http_client> http;
  std::string base;
  std::string session;
  std::string error;
  bool ok = false;
};

vault_client open_vault(const std::string& base_url) {
  vault_client vault;
  if (!is_loopback_url(base_url)) {
    vault.error = "refusing non-loopback base_url for bw serve";
    return vault;
  }

  // Read the session, then scrub it from our own environment. Everything else
  // in this program spawns children (wsl.exe, capa, the Python dashboard, ...),
  // and each of them would otherwise inherit the master-vault token through the
  // process environment.
  //
  // The token is cached in a process-local copy so that a second fetch (a retry,
  // or the legacy single-key call after the roster) still works after the
  // environment copy is gone. It lives in memory only, for the lifetime of the
  // process, and is never logged.
  static std::string cached_session;
  if (cached_session.empty()) {
    const char* session_env = std::getenv("BW_SESSION");
    if (session_env == nullptr || *session_env == '\0') {
      vault.error = missing_session_error();
      return vault;
    }
    cached_session.assign(session_env);
    cached_session.shrink_to_fit();

    // Belt and braces: proc::protect_env_var() filters the variable out of every
    // child environment this process builds; clearing it here additionally keeps
    // it out of *our* environment, where a same-user process could read it.
    proc::protect_env_var("BW_SESSION");
#if defined(_WIN32)
    _putenv_s("BW_SESSION", "");
#else
    ::unsetenv("BW_SESSION");
#endif
  }

  cti::http_options options;
  options.user_agent = "static-analyzer/1.0";
  // bw serve is on loopback and speaks plain HTTP; keep connection attempts
  // short so a missing server surfaces in seconds rather than minutes.
  options.connect_timeout_ms = 2000;
  vault.http = cti::make_curl_client(options);
  if (!vault.http) {
    vault.error = "libcurl could not be initialised";
    return vault;
  }

  vault.base = normalize_base(base_url);
  vault.session = cached_session;   // not session_env: the environment copy is already scrubbed
  vault.ok = true;
  return vault;
}

// GET /object/secure-item/vault-item once. `count` receives how many items the
// session can see.
bool list_vault_items(const vault_client& vault, nlohmann::json& items,
                      std::size_t& count, std::string& error) {
  cti::http_response list = vault.http->perform(
      make_request(vault.base + "/object/secure-item/vault-item", vault.session));
  if (!list.transport_ok) {
    error = "bw serve unreachable: " + list.error + " (is `bw serve` running?)";
    return false;
  }
  if (list.status == 401) {
    error = "bw serve rejected BW_SESSION - the vault is locked or the "
            "session expired; run: export BW_SESSION=$(bw unlock --raw)";
    return false;
  }
  if (!list.ok()) {
    error = "listing vault items failed with HTTP " + std::to_string(list.status);
    return false;
  }

  try {
    items = nlohmann::json::parse(list.body);
  } catch (const std::exception&) {
    error = "could not parse the vault item list returned by bw serve";
    return false;
  }
  if (!items.is_array()) {
    error = "unexpected response shape from bw serve (not a list)";
    return false;
  }
  count = items.size();
  return true;
}

enum class match_result { found, missing, ambiguous, broken };

// Exact-name match. Ambiguity is a failure on purpose: silently picking one of
// two same-named items could send the wrong credential to the wrong service.
match_result find_single_item(const nlohmann::json& items, const std::string& item_name,
                              std::string& item_id, std::string& error) {
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

  if (matches == 0) {
    error = "no vault item named '" + item_name + "'";
    return match_result::missing;
  }
  if (matches > 1) {
    error = "vault has " + std::to_string(matches) + " items named '" + item_name +
            "'; rename them so the target is unambiguous";
    return match_result::ambiguous;
  }
  if (item_id.empty()) {
    error = "matched item has no id";
    return match_result::broken;
  }
  return match_result::found;
}

// GET /object/secure-item/vault-item/<id>/data and take login.password.
bool read_password(const vault_client& vault, const std::string& item_id,
                   const std::string& item_name, std::string& password,
                   std::string& error) {
  cti::http_response data = vault.http->perform(make_request(
      vault.base + "/object/secure-item/vault-item/" + item_id + "/data", vault.session));
  if (!data.transport_ok) {
    error = "reading item data failed: " + data.error;
    return false;
  }
  if (data.status == 401) {
    error = "bw serve rejected the session while reading item data";
    return false;
  }
  if (!data.ok()) {
    error = "reading item data failed with HTTP " + std::to_string(data.status);
    return false;
  }

  nlohmann::json parsed;
  try {
    parsed = nlohmann::json::parse(data.body);
  } catch (const std::exception&) {
    error = "could not parse the item data returned by bw serve";
    return false;
  }
  if (!parsed.is_object()) {
    error = "unexpected item data shape from bw serve";
    return false;
  }

  const auto login = parsed.find("login");
  if (login == parsed.end() || !login->is_object()) {
    error = "item '" + item_name + "' has no login section";
    return false;
  }
  const auto password_field = login->find("password");
  if (password_field == login->end() || !password_field->is_string() ||
      password_field->get_ref<const std::string&>().empty()) {
    error = "item '" + item_name + "' has an empty password field";
    return false;
  }

  password = password_field->get<std::string>();
  return true;
}

}  // namespace

result_t fetch_from_bw_serve(const std::string& item_name, const std::string& base_url) {
  result_t result;

  if (item_name.empty()) {
    result.error = "no item name given";
    return result;
  }

  vault_client vault = open_vault(base_url);
  if (!vault.ok) {
    result.error = vault.error;
    return result;
  }

  nlohmann::json items;
  std::size_t count = 0;
  if (!list_vault_items(vault, items, count, result.error)) return result;

  std::string item_id;
  if (find_single_item(items, item_name, item_id, result.error) != match_result::found) {
    return result;   // `error` already carries the operator-facing reason
  }

  std::string password;
  if (!read_password(vault, item_id, item_name, password, result.error)) return result;

  result.ok = true;
  result.value = std::move(password);
  return result;
}

const char* to_string(item_state state) {
  switch (state) {
    case item_state::missing:   return "missing";
    case item_state::ambiguous: return "ambiguous";
    case item_state::unusable:  return "unusable";
    case item_state::present:   return "present";
  }
  return "unknown";
}

batch_result_t fetch_many_from_bw_serve(const std::vector<item_request_t>& requests,
                                        const std::string& base_url) {
  batch_result_t batch;
  batch.items.reserve(requests.size());

  // Mirrors a single failure onto every request so the caller always gets one
  // result per requested name, in request order.
  const auto fail_all = [&](const std::string& error) {
    for (const item_request_t& request : requests) {
      item_result_t item;
      item.name = request.name;
      item.target = request.target;
      item.state = item_state::unusable;
      item.error = error;
      batch.items.push_back(std::move(item));
    }
  };

  if (requests.empty()) {
    batch.error = "no item names given";
    return batch;
  }

  vault_client vault = open_vault(base_url);
  if (!vault.ok) {
    batch.error = vault.error;
    fail_all(vault.error);
    return batch;
  }

  nlohmann::json items;
  std::size_t count = 0;
  if (!list_vault_items(vault, items, count, batch.error)) {
    fail_all(batch.error);
    return batch;
  }

  batch.listing_ok  = true;
  batch.vault_items = count;

  for (const item_request_t& request : requests) {
    item_result_t item;
    item.name = request.name;
    item.target = request.target;

    if (request.name.empty()) {
      item.state = item_state::missing;
      item.error = "empty item name";
      batch.items.push_back(std::move(item));
      continue;
    }

    std::string item_id;
    const match_result match = find_single_item(items, request.name, item_id, item.error);
    if (match == match_result::missing) {
      item.state = item_state::missing;
    } else if (match == match_result::ambiguous) {
      item.state = item_state::ambiguous;
    } else if (match == match_result::broken) {
      item.state = item_state::unusable;
    } else if (request.target.empty()) {
      // Existence check only: the caller does not need the secret, so it is
      // never read into memory.
      item.state = item_state::present;
    } else {
      std::string password;
      if (!read_password(vault, item_id, request.name, password, item.error)) {
        item.state = item_state::unusable;
      } else {
        item.state = item_state::present;
        item.value_loaded = true;
        item.value = std::move(password);
      }
    }

    batch.items.push_back(std::move(item));
  }

  return batch;
}

}  // namespace secret_store
