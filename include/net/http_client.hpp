#pragma once

// Minimal HTTP layer for the CTI providers.
//   * http_client is an interface, so tests can inject a fake and providers never see curl
//   * curl_http_client: libcurl, TLS verification on, redirects (max 5), gzip, timeouts,
//     bounded response size, retries with exponential backoff on transport errors,
//     HTTP 429 and 5xx (honours Retry-After, capped)

#include <chrono>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace cti {

struct http_request {
  std::string method = "GET";                                    // GET | POST
  std::string url;
  std::vector<std::pair<std::string, std::string>> headers;
  std::string body;                                              // POST payload
  long        timeout_ms = 20000;
  std::size_t max_response_bytes = 128u * 1024u * 1024u;
  std::chrono::steady_clock::time_point deadline =
      std::chrono::steady_clock::time_point::max();
};

struct http_response {
  bool        transport_ok = false;    // false: DNS/connect/TLS/timeout failure (see error)
  long        status = 0;              // HTTP status when transport_ok
  std::string body;
  std::map<std::string, std::string> headers;   // lower-case names (last value wins)
  std::string error;
  int         attempts = 0;
  double      seconds = 0.0;

  bool ok() const { return transport_ok && status >= 200 && status < 300; }
};

class http_client {
 public:
  virtual ~http_client() = default;
  virtual http_response perform(const http_request& request) = 0;
};

struct http_options {
  std::string user_agent = "cti-pipeline/1.0";
  std::string proxy;                    // "" = libcurl default (environment)
  std::string ca_bundle;                // "" = system store
  bool        verify_tls = true;
  int         max_retries = 2;          // extra attempts after the first
  long        connect_timeout_ms = 8000;
  long        max_retry_wait_ms = 30000;
};

// Fails only if libcurl itself cannot be initialised (returns nullptr).
std::unique_ptr<http_client> make_curl_client(const http_options& options = {});

}  // namespace cti
