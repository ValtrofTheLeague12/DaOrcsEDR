#include "file_hasher.hpp"
#include "console.hpp"
#include "file_analyzer.hpp"
#include "logging.hpp"

#include <tlsh/tlsh.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <openssl/sha.h>
#include <sstream>

namespace {
constexpr const char* MAIN_ALGO  = "sha256";
constexpr const char* FUZZY_ALGO = "tlsh";

constexpr std::size_t kChunkSize = 4096;

using clock_type = std::chrono::steady_clock;

double seconds_since(clock_type::time_point start) {
  return std::chrono::duration<double>(clock_type::now() - start).count();
}

const char* hash_error_name(hash_error error) {
  switch (error) {
    case hash_error::none: return "none";
    case hash_error::invalid_path: return "invalid_path";
    case hash_error::empty_file: return "empty_file";
    case hash_error::read_failed: return "read_failed";
    case hash_error::hash_init_failed: return "hash_init_failed";
    case hash_error::hash_update_failed: return "hash_update_failed";
    case hash_error::hash_final_failed: return "hash_final_failed";
    case hash_error::invalid_fuzzy_hash: return "invalid_fuzzy_hash";
    case hash_error::fuzzy_hash_failed: return "fuzzy_hash_failed";
  }
  return "unknown";
}

void add_hash_error(hash_error_t& errors, hash_error error, const std::string& detail) {
  errors.flags = errors.flags | error;
  const std::string message =
      std::string("[") + hash_error_name(error) + "] " + detail;
  LOG_ERROR("hasher: {}", message);
  errors.messages.push_back(message);
  if (!errors.details.empty()) {
    errors.details += '\n';
  }
  errors.details += detail;
}
}  // namespace

namespace hasher {

bool hash_file_with_openssl(file_hash_t& instance, analyzer::file_info_t& info) {
  LOG_DEBUG("hasher: hash_file_with_openssl: '{}' (size={})",
            info.filepath, info.size);
  const auto started = clock_type::now();

  instance = {};
  instance.algo_used = MAIN_ALGO;

  if (!std::filesystem::exists(info.filepath) || info.size == 0) {
    LOG_WARN("hasher: hash_file_with_openssl: invalid path or empty file '{}'",
             info.filepath);
    add_hash_error(instance.errors, hash_error::invalid_path,
                   "Invalid file path or empty file: " + info.filepath);
    instance.hash = "N/A";
    return false;
  }

  std::ifstream binary(info.filepath, std::ios::binary);
  if (!binary) {
    LOG_ERROR("hasher: hash_file_with_openssl: cannot open '{}'", info.filepath);
    add_hash_error(instance.errors, hash_error::read_failed,
                   "Could not open file for hashing: " + info.filepath);
    instance.hash = "N/A";
    return false;
  }

  console::success("Recovering File Hash using OpenSSL : " +
                  std::string(OPENSSL_FULL_VERSION_STR));
  console::success("Digest size: " + std::to_string(SHA256_DIGEST_LENGTH));

  LOG_TRACE("hasher: hash_file_with_openssl: OpenSSL version={}, digest_len={}",
            OPENSSL_FULL_VERSION_STR, SHA256_DIGEST_LENGTH);

  SHA256_CTX sha256_context{};
  if (SHA256_Init(&sha256_context) != 1) {
    LOG_ERROR("hasher: hash_file_with_openssl: SHA256_Init failed for '{}'",
              info.filepath);
    add_hash_error(instance.errors, hash_error::hash_init_failed,
                   "OpenSSL SHA256 context initialization failed.");
    instance.hash = "N/A";
    return false;
  }

  std::array<unsigned char, kChunkSize> buffer{};
  unsigned char digest[SHA256_DIGEST_LENGTH]{};
  std::uint64_t total_read = 0;
  std::size_t chunk_count = 0;

  while (binary.good()) {
    binary.read(reinterpret_cast<char*>(buffer.data()),
                static_cast<std::streamsize>(buffer.size()));
    const std::streamsize bytes_read = binary.gcount();
    if (bytes_read <= 0) {
      break;
    }
    if (SHA256_Update(&sha256_context, buffer.data(),
                      static_cast<std::size_t>(bytes_read)) != 1) {
      LOG_ERROR("hasher: hash_file_with_openssl: SHA256_Update failed for '{}' "
                "after {} bytes", info.filepath, total_read);
      add_hash_error(instance.errors, hash_error::hash_update_failed,
                     "OpenSSL SHA256 update failed.");
      instance.hash = "N/A";
      return false;
    }
    total_read += static_cast<std::uint64_t>(bytes_read);
    ++chunk_count;
  }

  if (binary.bad()) {
    LOG_ERROR("hasher: hash_file_with_openssl: stream error reading '{}' "
              "after {} bytes", info.filepath, total_read);
    add_hash_error(instance.errors, hash_error::read_failed,
                   "Error while reading file for hashing.");
    instance.hash = "N/A";
    return false;
  }

  if (SHA256_Final(digest, &sha256_context) != 1) {
    LOG_ERROR("hasher: hash_file_with_openssl: SHA256_Final failed for '{}'",
              info.filepath);
    add_hash_error(instance.errors, hash_error::hash_final_failed,
                   "OpenSSL SHA256 finalization failed.");
    instance.hash = "N/A";
    return false;
  }

  std::ostringstream hash_stream;
  hash_stream << std::hex << std::setfill('0');
  for (unsigned char byte : digest) {
    hash_stream << std::setw(2) << static_cast<unsigned int>(byte);
  }

  instance.hash = hash_stream.str();

  LOG_DEBUG("hasher: hash_file_with_openssl: '{}' hashed in {:.3f}s "
            "({} chunks, {} bytes)",
            info.filepath, seconds_since(started), chunk_count, total_read);
  LOG_INFO("SHA256 of '{}': {}", info.filename, instance.hash);
  return true;
}

bool hash_file(file_hash_t& instance, analyzer::file_info_t& info) {
  LOG_TRACE("hasher: hash_file: '{}'", info.filepath);
  return hash_file_with_openssl(instance, info);
}

bool hash_bytes(file_hash_t& instance,
                const std::uint8_t* data,
                std::size_t size) {
  LOG_TRACE("hasher: hash_bytes: size={}", size);

  instance = {};
  instance.algo_used = MAIN_ALGO;

  if (data == nullptr || size == 0) {
    LOG_WARN("hasher: hash_bytes: null data or zero size");
    add_hash_error(instance.errors, hash_error::empty_file,
                   "Empty byte buffer for hashing");
    instance.hash = "N/A";
    return false;
  }

  unsigned char digest[SHA256_DIGEST_LENGTH]{};
  SHA256_CTX ctx{};
  if (SHA256_Init(&ctx) != 1) {
    LOG_ERROR("hasher: hash_bytes: SHA256_Init failed");
    add_hash_error(instance.errors, hash_error::hash_init_failed,
                   "SHA256 context init failed for byte buffer.");
    instance.hash = "N/A";
    return false;
  }
  if (SHA256_Update(&ctx, data, size) != 1) {
    LOG_ERROR("hasher: hash_bytes: SHA256_Update failed (size={})", size);
    add_hash_error(instance.errors, hash_error::hash_update_failed,
                   "SHA256 update failed for byte buffer.");
    instance.hash = "N/A";
    return false;
  }
  if (SHA256_Final(digest, &ctx) != 1) {
    LOG_ERROR("hasher: hash_bytes: SHA256_Final failed");
    add_hash_error(instance.errors, hash_error::hash_final_failed,
                   "SHA256 final failed for byte buffer.");
    instance.hash = "N/A";
    return false;
  }

  std::ostringstream stream;
  stream << std::hex << std::setfill('0');
  for (unsigned char b : digest) {
    stream << std::setw(2) << static_cast<unsigned int>(b);
  }
  instance.hash = stream.str();

  LOG_TRACE("hasher: hash_bytes: {} -> {}", size, instance.hash);
  return true;
}

bool fuzzy_hash_file(fuzzy_hash_t& instance, analyzer::file_info_t& info) {
  LOG_DEBUG("hasher: fuzzy_hash_file: '{}' (size={})",
            info.filepath, info.size);
  const auto started = clock_type::now();

  instance = {};
  instance.fuzzy_algo_used = FUZZY_ALGO;

  if (not std::filesystem::exists(info.filepath) || info.size == 0) {
    LOG_WARN("hasher: fuzzy_hash_file: invalid path or empty file '{}'",
             info.filepath);
    add_hash_error(instance.errors, hash_error::invalid_path,
                   "Invalid file path or empty file: " + info.filepath);
    instance.fuzzy_hash = "N/A";
    return false;
  }

  std::ifstream input(info.filepath, std::ios::binary);
  if (!input) {
    LOG_ERROR("hasher: fuzzy_hash_file: cannot open '{}'", info.filepath);
    add_hash_error(instance.errors, hash_error::read_failed,
                   "Could not open file for fuzzy hashing: " + info.filepath);
    instance.fuzzy_hash = "N/A";
    return false;
  }

  Tlsh tlsh;
  std::array<unsigned char, kChunkSize> buffer{};
  std::uint64_t total_read = 0;
  std::size_t chunk_count = 0;

  while (input.good()) {
    input.read(reinterpret_cast<char*>(buffer.data()),
               static_cast<std::streamsize>(buffer.size()));
    const std::streamsize bytes_read = input.gcount();
    if (bytes_read <= 0) {
      break;
    }
    tlsh.update(buffer.data(), static_cast<unsigned int>(bytes_read));
    total_read += static_cast<std::uint64_t>(bytes_read);
    ++chunk_count;
  }

  if (input.bad()) {
    LOG_ERROR("hasher: fuzzy_hash_file: stream error reading '{}' after {} bytes",
              info.filepath, total_read);
    add_hash_error(instance.errors, hash_error::read_failed,
                   "Error while reading file for fuzzy hashing.");
    instance.fuzzy_hash = "N/A";
    return false;
  }

  tlsh.final();
  const char* hash = tlsh.getHash(0);
  if (hash == nullptr) {
    LOG_WARN("hasher: fuzzy_hash_file: TLSH returned null for '{}' "
             "(file may be too small or too uniform)",
             info.filepath);
    add_hash_error(instance.errors, hash_error::fuzzy_hash_failed,
                   "TrendLSH fuzzy hash generation failed.");
    instance.fuzzy_hash = "N/A";
    return false;
  }

  instance.fuzzy_hash = std::string(hash);

  LOG_DEBUG("hasher: fuzzy_hash_file: '{}' hashed in {:.3f}s "
            "({} chunks, {} bytes)",
            info.filepath, seconds_since(started), chunk_count, total_read);
  LOG_INFO("TLSH fuzzy hash of '{}': {}", info.filename, instance.fuzzy_hash);
  return true;
}

bool fuzzy_hash_bytes(fuzzy_hash_t& instance,
                      const std::uint8_t* data,
                      std::size_t size) {
  LOG_TRACE("hasher: fuzzy_hash_bytes: size={}", size);

  instance = {};
  instance.fuzzy_algo_used = FUZZY_ALGO;

  if (data == nullptr || size == 0) {
    LOG_WARN("hasher: fuzzy_hash_bytes: null data or zero size");
    add_hash_error(instance.errors, hash_error::invalid_fuzzy_hash,
                   "Empty byte buffer for fuzzy hashing");
    instance.fuzzy_hash = "N/A";
    return false;
  }

  Tlsh tlsh;
  tlsh.update(data, static_cast<unsigned int>(size));
  tlsh.final();

  const char* h = tlsh.getHash(0);
  if (h == nullptr) {
    LOG_WARN("hasher: fuzzy_hash_bytes: TLSH returned null (size={})", size);
    add_hash_error(instance.errors, hash_error::fuzzy_hash_failed,
                   "TLSH byte-buffer hashing failed.");
    instance.fuzzy_hash = "N/A";
    return false;
  }

  instance.fuzzy_hash = std::string(h);
  LOG_TRACE("hasher: fuzzy_hash_bytes: {} -> {}", size, instance.fuzzy_hash);
  return true;
}

std::string fuzzy_hash(analyzer::file_info_t& info) {
  LOG_DEBUG("hasher: fuzzy_hash: '{}'", info.filepath);
  fuzzy_hash_t instance{};
  if (!fuzzy_hash_file(instance, info)) {
    LOG_WARN("hasher: fuzzy_hash: failed for '{}', returning 'N/A'",
             info.filepath);
    return "N/A";
  }
  return instance.fuzzy_hash;
}

bool match_hashes(const std::string& hash1, const std::string& hash2) {
  const bool equal = hash1 == hash2;
  LOG_TRACE("hasher: match_hashes: equal={} ('{}' vs '{}')",
            equal, hash1, hash2);
  return equal;
}

double fuzzy_similarity_ratio(const fuzzy_hash_t& left, const fuzzy_hash_t& right) {
  LOG_TRACE("hasher: fuzzy_similarity_ratio: comparing two hashes");

  if (left.fuzzy_hash.empty() || right.fuzzy_hash.empty()) {
    LOG_DEBUG("hasher: fuzzy_similarity_ratio: one or both hashes empty "
              "(left_len={}, right_len={})",
              left.fuzzy_hash.size(), right.fuzzy_hash.size());
    console::info("Similarity: 0.00%");
    return 0.0;
  }

  Tlsh left_hash;
  Tlsh right_hash;
  if (left_hash.fromTlshStr(left.fuzzy_hash.c_str()) != 0 ||
      right_hash.fromTlshStr(right.fuzzy_hash.c_str()) != 0) {
    LOG_WARN("hasher: fuzzy_similarity_ratio: fromTlshStr failed "
             "(left='{}', right='{}')",
             left.fuzzy_hash, right.fuzzy_hash);
    console::info("Similarity: 0.00%");
    return 0.0;
  }

  const int diff = left_hash.totalDiff(&right_hash, true);
  const double similarity = 100.0 - std::min(100.0, static_cast<double>(diff) / 10.0);

  console::info("Similarity: " +
               std::to_string(similarity).substr(0, std::to_string(similarity).find('.') + 3) + "%");

  LOG_DEBUG("hasher: fuzzy_similarity_ratio: diff={}, similarity={:.2f}%",
            diff, similarity);
  return similarity;
}

bool match_fuzzy_hash(const fuzzy_hash_t& left, const fuzzy_hash_t& right) {
  const double similarity = fuzzy_similarity_ratio(left, right);
  const bool match = similarity >= 80.0;
  LOG_DEBUG("hasher: match_fuzzy_hash: similarity={:.2f}%, match={}",
            similarity, match);
  return match;
}

bool has_hash_errors(const file_hash_t& instance) {
  return instance.errors.flags != hash_error::none;
}

bool has_fuzzy_hash_errors(const fuzzy_hash_t& instance) {
  return instance.errors.flags != hash_error::none;
}

std::vector<std::string> get_hash_error_messages(const file_hash_t& instance) {
  return instance.errors.messages;
}

std::vector<std::string> get_fuzzy_hash_error_messages(const fuzzy_hash_t& instance) {
  return instance.errors.messages;
}
  }