#ifndef FILE_HASHER_HPP
#define FILE_HASHER_HPP

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

#define OPENSSL_API_COMPAT 0x10100000L
#include <openssl/sha.h>

#include "file_analyzer.hpp"

enum class hash_error : std::uint32_t {
  none = 0,
  invalid_path = 1u << 0,
  empty_file = 1u << 1,
  read_failed = 1u << 2,
  hash_init_failed = 1u << 3,
  hash_update_failed = 1u << 4,
  hash_final_failed = 1u << 5,
  invalid_fuzzy_hash = 1u << 6,
  fuzzy_hash_failed = 1u << 7,
};

inline hash_error operator|(hash_error left, hash_error right) {
  return static_cast<hash_error>(static_cast<std::uint32_t>(left) |
                                 static_cast<std::uint32_t>(right));
}

inline bool has_hash_error(hash_error flags, hash_error error) {
  return (static_cast<std::uint32_t>(flags) &
          static_cast<std::uint32_t>(error)) != 0;
}

struct hash_error_t {
  hash_error flags = hash_error::none;
  std::string details;
  std::vector<std::string> messages;
};

struct file_hash_t {
  std::string hash;
  std::string algo_used;
  hash_error_t errors;
};

struct fuzzy_hash_t {
  std::string fuzzy_hash;
  std::string fuzzy_algo_used;
  hash_error_t errors;
};

namespace hasher {

bool hash_file_with_openssl(file_hash_t& instance, analyzer::file_info_t& info);
bool hash_file(file_hash_t& instance, analyzer::file_info_t& info);

bool hash_bytes(file_hash_t& instance,
                const std::uint8_t* data,
                std::size_t size);

// PGP word-list rendering of a hex digest (e.g. the SHA-256 above): the
// first `bytes` bytes, each as its even/odd-list word, "-"-joined so it can
// be read aloud. Returns "" when the input holds no valid hex bytes.
std::string human_words(const std::string& sha256_hex, std::size_t bytes = 8);

bool fuzzy_hash_file(fuzzy_hash_t& instance, analyzer::file_info_t& info);

bool fuzzy_hash_bytes(fuzzy_hash_t& instance,
                      const std::uint8_t* data,
                      std::size_t size);

std::string fuzzy_hash(analyzer::file_info_t& info);
bool match_hashes(const std::string& hash1, const std::string& hash2);
double fuzzy_similarity_ratio(const fuzzy_hash_t& left, const fuzzy_hash_t& right);
bool match_fuzzy_hash(const fuzzy_hash_t& left, const fuzzy_hash_t& right);
bool has_hash_errors(const file_hash_t& instance);
bool has_fuzzy_hash_errors(const fuzzy_hash_t& instance);
std::vector<std::string> get_hash_error_messages(const file_hash_t& instance);
std::vector<std::string> get_fuzzy_hash_error_messages(const fuzzy_hash_t& instance);

}  

#endif