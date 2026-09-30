#pragma once

#include <optional>
#include <string>

#include "local_api.hpp"

// MalAPI is served by the local Python API (python/api/server.py) as
// GET /malapi/<function_name>/. The lookup runs against the functions the PE
// actually imports, not against heuristic guesses over raw strings.

struct malapi_hit_t {
  std::string function;
  std::string raw_json;
  long        status = 0;
};

std::optional<malapi_hit_t> query_malapi(local_api::local_api_server& api,
                                         const std::string& function_name);

// Rejects strings that cannot be an API name (too short/long, not
// [A-Za-z][A-Za-z0-9_]*, or a language keyword) so the query queue is not
// filled with ordinal junk.
bool looks_like_api_name(const std::string& s);

// One-line rendering of a hit for the terminal report.
std::string format_malapi_hit(const malapi_hit_t& hit);
