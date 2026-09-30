#pragma once

#include <vector>

#include "extractor.hpp"

// Human-readable description for every mitigation the extractor tracks, so the
// guards phase explains what each flag actually does instead of only listing
// raw note strings.
struct guard_description_t {
  const char* name;
  bool        enabled;
  const char* description;
};

std::vector<guard_description_t> guard_descriptions(
    const extractor::guard_info_t& g);
