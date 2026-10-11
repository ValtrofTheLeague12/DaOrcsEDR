#pragma once

#include <string>
#include <vector>
#include <filesystem>
#include <chrono>
#include <optional>
#include <zlib.h>

namespace compressor {

struct ArtifactMetadata {
    std::string artifact_name;
    std::string original_path;
    std::uint64_t original_size;
    std::uint64_t compressed_size;
    std::string detected_on_host;
    std::string detected_by_user;
    std::chrono::system_clock::time_point detection_timestamp;
    std::chrono::system_clock::time_point file_modification_time;
    std::string file_hash_sha256;
    std::string file_hash_md5;
    std::string architecture;
    std::string file_type;
    std::vector<std::string> tags;
    std::string notes;
};

struct CompressionResult {
    bool success;
    std::string compressed_path;
    std::string readme_path;
    std::uint64_t original_size;
    std::uint64_t compressed_size;
    double compression_ratio;
    std::string error_message;
};

class ZlibCompressor {
public:
    explicit ZlibCompressor(int compression_level = Z_DEFAULT_COMPRESSION);
    ~ZlibCompressor() = default;

    CompressionResult compress_file(
        const std::filesystem::path& input_path,
        const std::filesystem::path& output_dir,
        const ArtifactMetadata& metadata
    );

    static bool decompress_file(
        const std::filesystem::path& compressed_path,
        const std::filesystem::path& output_path
    );

    static std::optional<ArtifactMetadata> read_readme_metadata(
        const std::filesystem::path& readme_path
    );

private:
    int compression_level_;

    bool compress_data(
        const std::vector<std::uint8_t>& input,
        std::vector<std::uint8_t>& output
    );

    std::string generate_readme_content(const ArtifactMetadata& metadata) const;
    std::string format_timestamp(const std::chrono::system_clock::time_point& tp) const;
    std::string get_hostname() const;
    std::string get_current_user() const;
};

} // namespace compressor