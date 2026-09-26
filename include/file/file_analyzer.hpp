#ifndef FILE_ANALYZER_HPP
#define FILE_ANALYZER_HPP

#include <cstdint>
#include <string>
#include <vector>

namespace analyzer {

enum class file_error : std::uint32_t {
  none = 0,
  invalid_path = 1u << 0,
  empty_file = 1u << 1,
  read_failed = 1u << 2,
  magic_failed = 1u << 3,
  parse_failed = 1u << 4,
};

inline file_error operator|(file_error left, file_error right) {
  return static_cast<file_error>(static_cast<std::uint32_t>(left) |
                                 static_cast<std::uint32_t>(right));
}

inline bool has_error(file_error flags, file_error error) {
  return (static_cast<std::uint32_t>(flags) &
          static_cast<std::uint32_t>(error)) != 0;
}

struct error_type_t {
  file_error flags = file_error::none;
  std::string details;
  std::vector<std::string> messages;
};

struct file_type_t {
  bool is_executable = false;
  std::string executable_type;
};

struct file_info_t {
  std::string filepath;
  std::size_t size = 0;
  std::string file_magic;
  std::string filename;
  std::string extension;
  std::vector<std::uint8_t> binary_magic;
  std::string header_signature;
  file_type_t type;
  error_type_t errors;
};

file_info_t get_file_info(const std::string& path);
bool has_errors(const file_info_t& info);
std::vector<std::string> get_error_messages(const file_info_t& info);

}

#endif
