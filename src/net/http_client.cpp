#include "http_client.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <limits>
#include <mutex>
#include <thread>

#include <curl/curl.h>

namespace cti {

namespace {

struct transfer {
  std::string body;
  std::map<std::string, std::string> headers;
  std::size_t max_bytes = 0;
  bool        too_large = false;
};

std::size_t write_body(char* data, std::size_t size, std::size_t count, void* user) {
  auto* t = static_cast<transfer*>(user);
  const std::size_t n = size * count;
  if (t->body.size() + n > t->max_bytes) {
    t->too_large = true;
    return 0;  
  }
  t->body.append(data, n);
  return n;
}

std::size_t write_header(char* data, std::size_t size, std::size_t count, void* user) {
  auto* t = static_cast<transfer*>(user);
  const std::size_t n = size * count;
  const std::string line(data, n);
  const std::size_t colon = line.find(':');
  if (colon != std::string::npos && colon > 0) {
    std::string name = line.substr(0, colon);
    std::string value = line.substr(colon + 1);
    for (char& c : name) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    while (!value.empty() && std::isspace(static_cast<unsigned char>(value.front()))) value.erase(value.begin());
    while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back()))) value.pop_back();
    t->headers[name] = value;
  }
  return n;
}

std::once_flag g_curl_once;
bool g_curl_ready = false;

class curl_http_client final : public http_client {
 public:
  explicit curl_http_client(http_options options) : options_(std::move(options)) {}

  http_response perform(const http_request& request) override {
    const auto started = std::chrono::steady_clock::now();
    http_response result;
    for (int attempt = 0; attempt <= options_.max_retries; ++attempt) {
      const auto now = std::chrono::steady_clock::now();
      if (request.deadline != std::chrono::steady_clock::time_point::max() &&
          now >= request.deadline) {
        result.transport_ok = false;
        result.error = "request deadline exceeded";
        break;
      }
      long timeout_ms = request.timeout_ms;
      if (request.deadline != std::chrono::steady_clock::time_point::max()) {
        const auto remaining =
            std::chrono::ceil<std::chrono::milliseconds>(request.deadline - now).count();
        const long bounded_remaining = static_cast<long>(
            std::min<std::int64_t>(remaining, std::numeric_limits<long>::max()));
        timeout_ms = timeout_ms > 0 ? std::min(timeout_ms, bounded_remaining)
                                    : bounded_remaining;
      }
      result = attempt_once(request, timeout_ms);
      result.attempts = attempt + 1;

      const bool retry_status = result.transport_ok && (result.status == 429 || result.status == 502 ||
                                                       result.status == 503 || result.status == 504);
      const bool retry_transport = !result.transport_ok && result.error.find("too large") == std::string::npos;
      if (attempt == options_.max_retries || !(retry_status || retry_transport)) break;

      long wait_ms = 500L << attempt;                       // 0.5 s, 1 s, 2 s ...
      const auto retry_after = result.headers.find("retry-after");
      if (retry_after != result.headers.end()) {            // seconds form only
        const long seconds = std::strtol(retry_after->second.c_str(), nullptr, 10);
        if (seconds > 0) wait_ms = std::max(wait_ms, seconds * 1000L);
      }
      wait_ms = std::min(wait_ms, options_.max_retry_wait_ms);
      if (request.deadline != std::chrono::steady_clock::time_point::max()) {
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
                                  request.deadline - std::chrono::steady_clock::now())
                                  .count();
        if (remaining <= 0) break;
        wait_ms = std::min(wait_ms, static_cast<long>(remaining));
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(wait_ms));
    }
    result.seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - started).count();
    return result;
  }

 private:
  http_response attempt_once(const http_request& request, long timeout_ms) const {
    http_response response;
    CURL* curl = curl_easy_init();
    if (curl == nullptr) {
      response.error = "curl_easy_init failed";
      return response;
    }

    transfer state;
    state.max_bytes = request.max_response_bytes;

    curl_slist* headers = nullptr;
    for (const auto& [name, value] : request.headers) {
      headers = curl_slist_append(headers, (name + ": " + value).c_str());
    }

    curl_easy_setopt(curl, CURLOPT_URL, request.url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, options_.user_agent.c_str());
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 5L);
    curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "");          // gzip / deflate / br when built in
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);                  // required when used from threads
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, timeout_ms);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, options_.connect_timeout_ms);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, options_.verify_tls ? 1L : 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, options_.verify_tls ? 2L : 0L);
    if (!options_.ca_bundle.empty()) curl_easy_setopt(curl, CURLOPT_CAINFO, options_.ca_bundle.c_str());
    if (!options_.proxy.empty()) curl_easy_setopt(curl, CURLOPT_PROXY, options_.proxy.c_str());
#if LIBCURL_VERSION_NUM >= 0x075500
    curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS_STR, "http,https");   // never follow into file:// etc.
    curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, "http,https");
#else
    curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
    curl_easy_setopt(curl, CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
#endif
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_body);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &state);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, write_header);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &state);

    if (request.method == "POST") {
      curl_easy_setopt(curl, CURLOPT_POST, 1L);
      curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(request.body.size()));
      curl_easy_setopt(curl, CURLOPT_COPYPOSTFIELDS, request.body.c_str());
    } else if (request.method == "HEAD") {
      // A HEAD probe must never expect a body: with CURLOPT_CUSTOMREQUEST libcurl
      // still waits for Content-Length bytes and reports CURLE_PARTIAL_FILE when a
      // minimal server answers headers-only (like the fake CTI server, or any
      // HEAD implementation that sends no body). CURLOPT_NOBODY makes libcurl send
      // HEAD and accept headers-only as success, which is what network_available()
      // needs from its connectivity probe.
      curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
    } else if (request.method != "GET") {
      curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, request.method.c_str());
    }

    const CURLcode code = curl_easy_perform(curl);
    if (code == CURLE_OK) {
      long status = 0;
      curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
      response.transport_ok = true;
      response.status = status;
      response.body = std::move(state.body);
      response.headers = std::move(state.headers);
    } else if (state.too_large) {
      response.error = "response too large (limit " + std::to_string(request.max_response_bytes) + " bytes)";
    } else {
      response.error = std::string(curl_easy_strerror(code));
    }
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return response;
  }

  http_options options_;
};

}  

std::unique_ptr<http_client> make_curl_client(const http_options& options) {
  std::call_once(g_curl_once, [] { g_curl_ready = curl_global_init(CURL_GLOBAL_DEFAULT) == CURLE_OK; });
  if (!g_curl_ready) return nullptr;
  return std::make_unique<curl_http_client>(options);
}

}  