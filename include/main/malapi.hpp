#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "local_api.hpp"

// MalAPI is served by the local Python API (python/api/server.py) as
// GET /malapi/<function_name>/. The lookup runs against the functions the PE
// actually imports, not against heuristic guesses over raw strings.

// One code location that references the import: the enclosing function (as
// radare2 names it), its start offset, and the address of the reference
// itself. Addresses are VAs, the same base r2 loads the sample at.
struct malapi_call_site_t {
  std::string   function;
  std::uint64_t function_offset = 0;
  std::uint64_t address         = 0;
};

struct malapi_hit_t {
  std::string function;
  std::string raw_json;
  long        status = 0;

  // Import origin: which import this name came from (Phase 4 of the extract),
  // so the report can place the hit even when no code reference was resolved.
  std::string   dll;
  std::uint16_t hint      = 0;
  std::uint16_t ordinal   = 0;
  bool          is_ordinal = false;
  bool          is_delay   = false;
  std::uint64_t iat_rva    = 0;

  // Code that references this import, filled by the radare2 call-site
  // resolution below. Empty when radare2 is unavailable, the resolution was
  // disabled, or nothing references the slot directly - `sites_resolved`
  // separates "we looked and found nothing" from "we never looked".
  std::vector<malapi_call_site_t> call_sites;
  bool sites_resolved = false;
};

std::optional<malapi_hit_t> query_malapi(local_api::local_api_server& api,
                                         const std::string& function_name);

// Rejects strings that cannot be an API name (too short/long, not
// [A-Za-z][A-Za-z0-9_]*, or a language keyword) so the query queue is not
// filled with ordinal junk.
bool looks_like_api_name(const std::string& s);

// One-line rendering of a hit for the terminal report.
std::string format_malapi_hit(const malapi_hit_t& hit);

// Block rendering: the hit line followed by the import origin, the code that
// references it, and a short description. Uses the report vocabulary
// (print_bullet / print_kv) so the terminal and the PDCurses browser agree.
void print_malapi_hit(const malapi_hit_t& hit);
