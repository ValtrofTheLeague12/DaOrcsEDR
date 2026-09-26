#include "file_analyzer.hpp"
#include "logging.hpp"
#include <LIEF/LIEF.hpp>
#include <magic.h>
#include <algorithm>
#include <array>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <memory>

#define MAGIC_DATABASE "C:/msys64/ucrt64/share/misc/magic.mgc"

namespace {
constexpr std::array<std::uint8_t, 4> ELF_HEADER = {0x7F, 0x45, 0x4C, 0x46};
constexpr std::array<std::uint8_t, 2> PE_HEADER = {0x4D, 0x5A};
constexpr std::array<std::uint8_t, 4> MACHO_HEADER = {0xFE, 0xED, 0xFA, 0xCE};
constexpr std::array<std::uint8_t, 4> MACHO_REVERSE_HEADER = {0xCE, 0xFA, 0xED, 0xFE};

template <std::size_t N>
bool starts_with(const std::vector<std::uint8_t>& bytes,
                 const std::array<std::uint8_t, N>& signature) {
  return bytes.size() >= N &&
         std::equal(signature.begin(), signature.end(), bytes.begin());
 }
}  

namespace analyzer {
namespace {

using clock_type = std::chrono::steady_clock;

double seconds_since(clock_type::time_point start) {
  return std::chrono::duration<double>(clock_type::now() - start).count();
}

const char* error_name(file_error error) {
  switch (error) {
    case file_error::invalid_path: return "invalid_path";
    case file_error::empty_file: return "empty_file";
    case file_error::read_failed: return "read_failed";
    case file_error::magic_failed: return "magic_failed";
    case file_error::parse_failed: return "parse_failed";
    case file_error::none: return "none";
  }
  return "unknown";
}

void add_error(file_info_t& info, file_error error, const std::string& detail) {
  info.errors.flags = info.errors.flags | error;
  const std::string message =
      std::string("[") + error_name(error) + "] " + detail;
  LOG_ERROR("analyzer: {}", message);
  info.errors.messages.push_back(message);
  if (!info.errors.details.empty()) {
    info.errors.details += '\n';
  }
  info.errors.details += detail;
}

bool check_file(const std::string& path, file_info_t& info) {
  LOG_TRACE("analyzer: check_file: path='{}'", path);

  const std::filesystem::path path_object(path);
  std::error_code error;
  info.filename = path_object.filename().string();
  info.extension = path_object.extension().string();

  LOG_TRACE("analyzer: check_file: filename='{}', extension='{}'",
            info.filename, info.extension);

  const bool regular = std::filesystem::is_regular_file(path, error);
  if (error) {
    LOG_DEBUG("analyzer: check_file: is_regular_file error: {}", error.message());
  }

  info.size = error ? 0 : std::filesystem::file_size(path, error);

  if (error || !regular) {
    LOG_WARN("analyzer: check_file: '{}' is not a regular file (regular={}, "
             "error='{}')", path, regular, error.message());
    add_error(info, file_error::invalid_path, "Invalid or non-regular file: " + path);
    return false;
  }
  if (info.size == 0) {
    LOG_WARN("analyzer: check_file: '{}' is empty", path);
    add_error(info, file_error::empty_file, "File is empty: " + path);
    return false;
  }

  LOG_DEBUG("analyzer: check_file: '{}' ok (regular=true, size={})",
            path, info.size);
  return true;
}

void read_magic_bytes(const std::string& path, file_info_t& info) {
  LOG_TRACE("analyzer: read_magic_bytes: opening '{}'", path);

  std::ifstream input(path, std::ios::binary);
  if (!input) {
    LOG_ERROR("analyzer: read_magic_bytes: could not open '{}'", path);
    add_error(info, file_error::read_failed, "Could not open file: " + path);
    return;
  }

  constexpr std::size_t magic_header_size = 16;
  info.binary_magic.resize(magic_header_size);
  input.read(reinterpret_cast<char*>(info.binary_magic.data()),
             static_cast<std::streamsize>(info.binary_magic.size()));
  info.binary_magic.resize(static_cast<std::size_t>(input.gcount()));

  LOG_TRACE("analyzer: read_magic_bytes: read {} magic bytes from '{}'",
            info.binary_magic.size(), path);

  if (starts_with(info.binary_magic, ELF_HEADER)) {
    info.header_signature = "ELF signature at offset 0: 7F 45 4C 46";
    LOG_DEBUG("analyzer: read_magic_bytes: '{}' has ELF magic", path);
  } else if (starts_with(info.binary_magic, PE_HEADER)) {
    info.header_signature = "PE signature at offset 0: 4D 5A (MZ)";
    LOG_DEBUG("analyzer: read_magic_bytes: '{}' has PE (MZ) magic", path);
  } else if (starts_with(info.binary_magic, MACHO_HEADER) ||
             starts_with(info.binary_magic, MACHO_REVERSE_HEADER)) {
    info.header_signature = "Mach-O signature at offset 0";
    LOG_DEBUG("analyzer: read_magic_bytes: '{}' has Mach-O magic", path);
  } else {
    info.header_signature = "Unknown executable signature at offset 0";
    LOG_DEBUG("analyzer: read_magic_bytes: '{}' has unknown magic "
              "(first byte = 0x{:02x})",
              path, info.binary_magic.empty() ? 0u : info.binary_magic.front());
  }
}

void detect_executable(const std::string& path, file_info_t& info) {
  LOG_TRACE("analyzer: detect_executable: parsing '{}' with LIEF", path);
  const auto started = clock_type::now();

  try {
    std::unique_ptr<LIEF::Binary> binary = LIEF::Parser::parse(path);
    if (!binary) {
      LOG_DEBUG("analyzer: detect_executable: LIEF returned null for '{}'", path);
      add_error(info, file_error::parse_failed, "LIEF could not parse the file");
      return;
    }
    info.type.is_executable = true;
    info.type.executable_type = LIEF::to_string(binary->format());

    LOG_DEBUG("analyzer: detect_executable: '{}' parsed as '{}' in {:.3f}s",
              path, info.type.executable_type, seconds_since(started));
  } catch (const std::exception& exception) {
    LOG_DEBUG("analyzer: detect_executable: exception parsing '{}': {}",
              path, exception.what());
    add_error(info, file_error::parse_failed, exception.what());
  }
}

void detect_file_magic(const std::string& path, file_info_t& info) {
  LOG_TRACE("analyzer: detect_file_magic: identifying '{}' with libmagic", path);

  magic_t magic = magic_open(MAGIC_MIME_TYPE | MAGIC_ERROR);
  if (magic == nullptr) {
    LOG_ERROR("analyzer: detect_file_magic: magic_open failed");
    add_error(info, file_error::magic_failed, "Could not initialize libmagic");
    return;
  }
  if (magic_load(magic, MAGIC_DATABASE) != 0) {
    const char* error = magic_error(magic);
    LOG_ERROR("analyzer: detect_file_magic: magic_load('{}') failed: {}",
              MAGIC_DATABASE, error == nullptr ? "(no detail)" : error);
    add_error(info, file_error::magic_failed,
              error == nullptr ? "Could not load magic database" : error);
    magic_close(magic);
    return;
  }

  const char* detected = magic_file(magic, path.c_str());
  if (detected == nullptr) {
    const char* error = magic_error(magic);
    LOG_WARN("analyzer: detect_file_magic: magic_file('{}') failed: {}",
             path, error == nullptr ? "(no detail)" : error);
    add_error(info, file_error::magic_failed,
              error == nullptr ? "Could not identify file" : error);
  } else {
    info.file_magic = detected;
    LOG_DEBUG("analyzer: detect_file_magic: '{}' -> '{}'", path, info.file_magic);
  }
  magic_close(magic);
}

}  

file_info_t get_file_info(const std::string& path) {
  LOG_INFO("analyzer: get_file_info: analyzing file '{}'", path);
  const auto started = clock_type::now();

  file_info_t info{};
  info.filepath = path;

  if (!check_file(path, info)) {
    LOG_WARN("analyzer: get_file_info: '{}' rejected during validation "
             "(errors={})", path, info.errors.messages.size());
    return info;
  }

  read_magic_bytes(path, info);
  detect_file_magic(path, info);
  detect_executable(path, info);

  LOG_INFO("analyzer: get_file_info: '{}' done in {:.3f}s — {} bytes, "
           "format '{}', magic '{}', header '{}', errors={}",
           info.filename, seconds_since(started), info.size,
           info.type.executable_type, info.file_magic,
           info.header_signature, info.errors.messages.size());

  if (has_errors(info)) {
    LOG_DEBUG("analyzer: get_file_info: '{}' completed with {} error message(s)",
              path, info.errors.messages.size());
  }
  return info;
}

bool has_errors(const file_info_t& info) {
  return info.errors.flags != file_error::none;
}

std::vector<std::string> get_error_messages(const file_info_t& info) {
  return info.errors.messages;
}

}