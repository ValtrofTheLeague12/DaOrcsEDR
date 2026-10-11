// known_pe_hashes.cpp - see include/file/known_pe_hashes.hpp.
#include "known_pe_hashes.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdlib>
#include <fstream>
#include <string>
#include <string_view>
#include <vector>

#include <nlohmann/json.hpp>

#include "logging.hpp"

namespace {
using json = nlohmann::json;

using clock_type = std::chrono::steady_clock;

double seconds_since(clock_type::time_point start) {
  return std::chrono::duration<double>(clock_type::now() - start).count();
}

// Decodes 64 hex characters into 32 bytes. Returns false for anything else -
// a truncated digest, a stray space, a non-hex byte - so a corrupt roster line
// is skipped instead of poisoning the index with a half-decoded digest.
bool hex_to_digest(std::string_view hex, std::array<std::uint8_t, 32>& out) {
  if (hex.size() != 64) return false;

  auto nibble = [](char c, int& value) {
    if (c >= '0' && c <= '9')  { value = c - '0';     return true; }
    if (c >= 'a' && c <= 'f')  { value = c - 'a' + 10; return true; }
    if (c >= 'A' && c <= 'F')  { value = c - 'A' + 10; return true; }
    return false;
  };

  for (std::size_t i = 0; i < out.size(); ++i) {
    int high = 0;
    int low  = 0;
    if (!nibble(hex[i * 2], high) || !nibble(hex[i * 2 + 1], low)) return false;
    out[i] = static_cast<std::uint8_t>((high << 4) | low);
  }
  return true;
}

std::string to_lower(std::string_view text) {
  std::string out(text);
  std::transform(out.begin(), out.end(), out.begin(),
                 [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  return out;
}

// The roster writes "split" as a single name, but accepts a list too so a
// hand-edited file that tags a hash with several splits still loads.
std::uint8_t parse_splits(const json& node) {
  if (node.is_string()) {
    const std::string name = to_lower(node.get<std::string>());
    if (name == "train")     return known_pe::split_train;
    if (name == "test")      return known_pe::split_test;
    if (name == "challenge") return known_pe::split_challenge;
    return 0;
  }
  if (node.is_array()) {
    std::uint8_t bits = 0;
    for (const auto& item : node) {
      if (!item.is_string()) continue;
      const std::string name = to_lower(item.get<std::string>());
      if (name == "train")           bits |= known_pe::split_train;
      else if (name == "test")      bits |= known_pe::split_test;
      else if (name == "challenge") bits |= known_pe::split_challenge;
    }
    return bits;
  }
  return 0;
}
}  // namespace

namespace known_pe {

std::string entry_t::split_names() const {
  std::string out;
  auto append = [&out](const char* name) {
    if (!out.empty()) out += ',';
    out += name;
  };
  if (splits & split_train)     append("train");
  if (splits & split_test)      append("test");
  if (splits & split_challenge) append("challenge");
  return out;
}

std::filesystem::path default_index_path() {
  if (const char* override_path = std::getenv("KNOWN_PE_HASHES_FILE");
      override_path != nullptr && *override_path != '\0') {
    return std::filesystem::path(override_path);
  }
#ifdef STATIC_ANALYZER_SOURCE_DIR
  return std::filesystem::path(STATIC_ANALYZER_SOURCE_DIR) /
         "data" / "known_pe_hashes.jsonl";
#else
  return {};
#endif
}

bool lookup(result_t& result,
            const std::string& sha256,
            const std::filesystem::path& index_path) {
  result = {};
  result.attempted = true;
  result.sha256 = to_lower(sha256);

  const auto started = clock_type::now();

  std::array<std::uint8_t, 32> wanted{};
  if (!hex_to_digest(result.sha256, wanted)) {
    LOG_WARN("known_pe: lookup: '{}' is not a 64-character hex SHA-256", result.sha256);
    result.errors.push_back("Sample SHA-256 is not 64 hex characters: " + result.sha256);
    result.seconds = seconds_since(started);
    return false;
  }

  const std::filesystem::path path =
      index_path.empty() ? default_index_path() : index_path;

  if (path.empty()) {
    LOG_DEBUG("known_pe: lookup: no roster path configured, skipping");
    result.errors.push_back("No known-PE roster path configured (set KNOWN_PE_HASHES_FILE)");
    result.seconds = seconds_since(started);
    return false;
  }

  result.index_path = path.string();

  std::error_code ec;
  if (!std::filesystem::is_regular_file(path, ec) || ec) {
    LOG_INFO("known_pe: lookup: no roster at '{}', skipping lookup", path.string());
    result.errors.push_back("No known-PE roster at " + path.string());
    result.seconds = seconds_since(started);
    return false;
  }

  std::ifstream input(path, std::ios::binary);
  if (!input) {
    LOG_ERROR("known_pe: lookup: cannot open roster '{}'", path.string());
    result.errors.push_back("Could not open known-PE roster: " + path.string());
    result.seconds = seconds_since(started);
    return false;
  }

  // entries is indexed by digest_ref_t::entry; digests stays sorted by digest so
  // the lookup is a binary search. Sorting after the load (rather than inserting
  // in order) keeps the read a straight sequential scan of the file.
  std::vector<known_pe::entry_t> entries;
  std::vector<known_pe::digest_ref_t> digests;
  entries.reserve(220000);
  digests.reserve(220000);

  std::string line;
  std::size_t malformed = 0;
  while (std::getline(input, line)) {
    if (!line.empty() && line.back() == '\r') line.pop_back();
    if (line.empty()) continue;

    json record;
    try {
      record = json::parse(line);
    } catch (...) {
      ++malformed;
      continue;
    }
    if (!record.is_object() || !record.contains("sha256") ||
        !record["sha256"].is_string()) {
      ++malformed;
      continue;
    }

    std::array<std::uint8_t, 32> digest{};
    if (!hex_to_digest(record["sha256"].get_ref<const std::string&>(), digest)) {
      ++malformed;
      continue;
    }

    known_pe::entry_t entry;
    if (record.contains("label")) {
      entry.malicious = record["label"].is_number_integer() &&
                        record["label"].get<std::int64_t>() != 0;
    }
    if (record.contains("family") && record["family"].is_string()) {
      entry.family = record["family"].get<std::string>();
    }
    if (record.contains("split")) entry.splits = parse_splits(record["split"]);

    digests.push_back({digest, static_cast<std::uint32_t>(entries.size())});
    entries.push_back(std::move(entry));
  }

  // Collapse digests that appear more than once. std::sort leaves equal
  // digests in an unspecified order, so without this a hand-edited roster with
  // the same hash listed under two families would report whichever entry the
  // sort happened to put first. Merging keeps every split bit and the first
  // family that was actually recorded, so the answer is stable.
  std::sort(digests.begin(), digests.end(),
            [](const known_pe::digest_ref_t& left, const known_pe::digest_ref_t& right) {
              return left.digest < right.digest;
            });

  {
    std::size_t out = 0;
    for (std::size_t i = 1; i < digests.size(); ++i) {
      if (digests[i].digest != digests[out].digest) {
        digests[++out] = digests[i];
        continue;
      }
      known_pe::entry_t& keep = entries[digests[out].entry];
      const known_pe::entry_t& extra = entries[digests[i].entry];
      keep.splits |= extra.splits;
      if (keep.family.empty()) keep.family = extra.family;
      keep.malicious = keep.malicious || extra.malicious;
    }
    digests.resize(digests.empty() ? 0 : out + 1);
  }

  result.available = true;
  // Distinct digests, not parsed lines: the dedupe pass above may have merged
  // repeats, and "how many hashes are in this roster" is the useful number.
  result.entries_loaded = digests.size();
  result.lines_skipped = malformed;

  if (malformed > 0) {
    LOG_WARN("known_pe: lookup: skipped {} malformed roster line(s) in '{}'",
             malformed, path.string());
    result.errors.push_back("Skipped " + std::to_string(malformed) +
                            " malformed roster line(s)");
  }

  const auto it = std::lower_bound(
      digests.begin(), digests.end(), wanted,
      [](const known_pe::digest_ref_t& left, const std::array<std::uint8_t, 32>& right) {
        return left.digest < right;
      });

  if (it != digests.end() && it->digest == wanted) {
    result.matched = true;
    result.entry = entries[it->entry];
    LOG_INFO("known_pe: lookup: '{}' is a known PE (family='{}', split='{}')",
             result.sha256, result.entry.family, result.entry.split_names());
  } else {
    LOG_DEBUG("known_pe: lookup: '{}' is not in the known-PE roster", result.sha256);
  }

  LOG_DEBUG("known_pe: lookup: {} entries from '{}' in {:.3f}s",
            result.entries_loaded, path.string(), seconds_since(started));

  result.seconds = seconds_since(started);
  return result.matched;
}

}  // namespace known_pe