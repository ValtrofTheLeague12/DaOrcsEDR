// known_pe_hashes.hpp - lookup of a sample's SHA-256 against the roster of known
// PE files shipped in data/known_pe_hashes.jsonl (the EMBER2024 Win64 corpus).
//
// The point is to answer "have we already seen this exact PE?" before the
// analysis spends its time on it, and to say which EMBER split and family the
// sample belongs to when it does match. It is a corpus membership check, NOT a
// verdict: a match says the file is in the reference set, the label says what
// the corpus recorded about it, and neither is a fresh judgement about the file
// in front of us.
//
// The index is optional. A missing or unreadable roster is not an analysis
// error - it degrades to "no lookup performed" so a checkout without the data
// file still analyzes samples exactly as before.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace known_pe {

// The four EMBER2024 subsets the roster is drawn from, as bits so a hash that
// somehow appears in more than one split keeps all of them.
enum split_bit : std::uint8_t {
  split_train     = 1u << 0,
  split_test      = 1u << 1,
  split_challenge = 1u << 2,
};

struct entry_t {
  bool        malicious = false;   // EMBER label: 1 = malicious, 0 = benign
  std::string family;              // empty when the corpus recorded none
  std::uint8_t splits = 0;         // bitwise OR of split_bit values

  // "train", "test", "challenge", or "train,test" for a hash present in
  // several. Always non-empty for a hash that actually matched.
  std::string split_names() const;
};

// One raw 32-byte digest plus the index of its entry in the entry table. Kept
// as bytes rather than hex text so the roster costs ~8 MB instead of ~20 MB,
// and so a lookup compares digests directly instead of normalizing strings.
struct digest_ref_t {
  std::array<std::uint8_t, 32> digest{};
  std::uint32_t entry = 0;
};

struct result_t {
  bool attempted = false;          // a lookup was requested
  bool available = false;          // the roster was found and parsed
  bool matched = false;            // this sample's SHA-256 is in the roster

  std::string sha256;              // normalised (lower-case) digest that was looked up
  std::string index_path;          // roster that was used, empty when none was
  entry_t entry;                   // meaningful only when matched

  std::size_t entries_loaded = 0;  // distinct hashes in the roster
  std::size_t lines_skipped = 0;   // malformed or non-hex lines ignored
  double seconds = 0.0;

  std::vector<std::string> errors;
};

// Where the roster lives when the caller does not say: $KNOWN_PE_HASHES_FILE if
// set, otherwise data/known_pe_hashes.jsonl under the source tree. Returns an
// empty path when neither can be determined, which lookup() reports as a skip.
std::filesystem::path default_index_path();

// Looks `sha256` up in the roster at `index_path` (default_index_path() when
// empty). `sha256` is matched case-insensitively; a digest that is not 64 hex
// characters cannot match and is reported as an error rather than a miss.
//
// The roster is read on every call. That is deliberate: the analyzer handles a
// single sample per process, so caching one roster across calls would buy
// nothing, and re-reading keeps the result self-contained.
bool lookup(result_t& result,
            const std::string& sha256,
            const std::filesystem::path& index_path = {});

}  // namespace known_pe