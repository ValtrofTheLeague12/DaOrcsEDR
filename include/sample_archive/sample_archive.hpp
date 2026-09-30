#pragma once

// sample_archive library: zstd compress / decompress for sample STORAGE and
// TRANSFER.
//
// This library only moves bytes around; it does not make anything executable.
// A zstd-compressed PE has no MZ header, no section table and no entry point,
// so it cannot be run or analyzed as a binary - decompress it first if you
// need to feed it to static_analyzer. It exists to keep samples small in an
// evidence store, a mail attachment, or a transfer to another analysis host.

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>

namespace sample_archive {

constexpr int kLevel = 19;  // best ratio; offline storage path, CPU is fine

struct result_t {
    bool ok = false;
    std::string error;
    std::uint64_t in_bytes = 0;
    std::uint64_t out_bytes = 0;
};

struct info_t {
    bool ok = false;
    std::string error;
    std::uint64_t compressed = 0;
    std::uint64_t produced = 0;  // bytes that would be written
    std::uint64_t frames = 0;
    std::uint64_t trailing = 0;  // non-frame bytes after the last frame
    bool checksum = false;       // xxhash64 checksum trailer present
};

// Not named file_size(): argument-dependent lookup would make every call
// ambiguous with std::filesystem::file_size.
std::optional<std::uint64_t> size_on_disk(const std::filesystem::path& p);

std::string human_size(std::uint64_t bytes);

// Writes to a sibling ".partial" file and renames on success, so a corrupt
// source or a crash can never leave a half-written sample behind.
result_t compress(const std::filesystem::path& in, const std::filesystem::path& out);
result_t decompress(const std::filesystem::path& in, const std::filesystem::path& out);

// Dry run: walks the frames with a streaming decoder and reports what
// decompress would produce, without writing anything.
info_t inspect(const std::filesystem::path& in);

}  // namespace sample_archive
