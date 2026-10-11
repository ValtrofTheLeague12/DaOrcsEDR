#include "core/compressor.hpp"

#include <zlib.h>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <array>
#include <chrono>
#include <ctime>
#include <random>
#include <openssl/sha.h>
#include <openssl/md5.h>

#ifdef _WIN32
#include <windows.h>
#include <lmcons.h>
#else
#include <unistd.h>
#include <pwd.h>
#include <sys/utsname.h>
#endif

namespace compressor {

namespace {

long long days_from_civil(int y, unsigned m, unsigned d) {
    y -= m <= 2;
    const int era = (y >= 0 ? y : y - 399) / 400;
    const unsigned yoe = static_cast<unsigned>(y - era * 400);
    const unsigned doy = (153u * (m > 2 ? m - 3 : m + 9) + 2) / 5 + d - 1;
    const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return static_cast<long long>(era) * 146097 + static_cast<long long>(doe) - 719468;
}

std::chrono::system_clock::time_point parse_iso8601_utc(const std::string& value) {
    std::tm tm{};
    std::istringstream ss(value);
    ss >> std::get_time(&tm, "%Y-%m-%dT%H:%M:%S");
    if (ss.fail()) {
        return {};
    }
    const long long days = days_from_civil(
        tm.tm_year + 1900,
        static_cast<unsigned>(tm.tm_mon + 1),
        static_cast<unsigned>(tm.tm_mday)
    );
    const long long seconds = days * 86400LL
        + static_cast<long long>(tm.tm_hour) * 3600
        + static_cast<long long>(tm.tm_min) * 60
        + tm.tm_sec;
    return std::chrono::system_clock::time_point{std::chrono::seconds{seconds}};
}

}

ZlibCompressor::ZlibCompressor(int compression_level)
    : compression_level_(compression_level) {}

bool ZlibCompressor::compress_data(
    const std::vector<std::uint8_t>& input,
    std::vector<std::uint8_t>& output
) {
    z_stream strm{};
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    strm.avail_in = static_cast<uInt>(input.size());
    strm.next_in = const_cast<Bytef*>(input.data());

    if (deflateInit(&strm, compression_level_) != Z_OK) {
        return false;
    }

    const size_t chunk_size = 16384;
    std::vector<std::uint8_t> out_buffer(chunk_size);
    int ret;

    do {
        strm.avail_out = static_cast<uInt>(chunk_size);
        strm.next_out = out_buffer.data();

        ret = deflate(&strm, Z_FINISH);

        size_t have = chunk_size - strm.avail_out;
        output.insert(output.end(), out_buffer.begin(), out_buffer.begin() + have);
    } while (ret == Z_OK);

    deflateEnd(&strm);
    return ret == Z_STREAM_END;
}

CompressionResult ZlibCompressor::compress_file(
    const std::filesystem::path& input_path,
    const std::filesystem::path& output_dir,
    const ArtifactMetadata& metadata
) {
    CompressionResult result;
    result.success = false;
    result.original_size = 0;
    result.compressed_size = 0;
    result.compression_ratio = 0.0;

    if (!std::filesystem::exists(input_path)) {
        result.error_message = "Input file does not exist: " + input_path.string();
        return result;
    }

    std::error_code ec;
    std::filesystem::create_directories(output_dir, ec);
    if (ec) {
        result.error_message = "Failed to create output directory: " + ec.message();
        return result;
    }

    std::ifstream input_file(input_path, std::ios::binary);
    if (!input_file) {
        result.error_message = "Failed to open input file: " + input_path.string();
        return result;
    }

    input_file.seekg(0, std::ios::end);
    std::uint64_t file_size = input_file.tellg();
    input_file.seekg(0, std::ios::beg);

    std::vector<std::uint8_t> input_data(file_size);
    input_file.read(reinterpret_cast<char*>(input_data.data()), file_size);
    input_file.close();

    if (static_cast<std::uint64_t>(input_file.gcount()) != file_size) {
        result.error_message = "Failed to read entire file";
        return result;
    }

    std::vector<std::uint8_t> compressed_data;
    compressed_data.reserve(file_size);

    if (!compress_data(input_data, compressed_data)) {
        result.error_message = "Compression failed";
        return result;
    }

    std::string base_name = input_path.stem().string();
    std::filesystem::path compressed_path = output_dir / (base_name + ".zlib");
    std::filesystem::path readme_path = output_dir / (base_name + ".README.md");

    std::ofstream compressed_file(compressed_path, std::ios::binary);
    if (!compressed_file) {
        result.error_message = "Failed to create compressed file: " + compressed_path.string();
        return result;
    }
    compressed_file.write(
        reinterpret_cast<const char*>(compressed_data.data()),
        compressed_data.size()
    );
    compressed_file.close();

    ArtifactMetadata enriched_metadata = metadata;
    if (enriched_metadata.artifact_name.empty()) {
        enriched_metadata.artifact_name = input_path.filename().string();
    }
    if (enriched_metadata.original_path.empty()) {
        enriched_metadata.original_path = input_path.string();
    }
    enriched_metadata.original_size = file_size;
    enriched_metadata.compressed_size = compressed_data.size();
    enriched_metadata.detection_timestamp = std::chrono::system_clock::now();
    auto ftime = std::filesystem::last_write_time(input_path);
    auto sctp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
        ftime - std::filesystem::file_time_type::clock::now()
        + std::chrono::system_clock::now()
    );
    enriched_metadata.file_modification_time = sctp;

    if (enriched_metadata.detected_on_host.empty()) {
        enriched_metadata.detected_on_host = get_hostname();
    }
    if (enriched_metadata.detected_by_user.empty()) {
        enriched_metadata.detected_by_user = get_current_user();
    }

    std::string readme_content = generate_readme_content(enriched_metadata);
    std::ofstream readme_file(readme_path);
    if (!readme_file) {
        result.error_message = "Failed to create README file: " + readme_path.string();
        return result;
    }
    readme_file << readme_content;
    readme_file.close();

    result.success = true;
    result.compressed_path = compressed_path.string();
    result.readme_path = readme_path.string();
    result.original_size = file_size;
    result.compressed_size = compressed_data.size();
    result.compression_ratio = file_size > 0
        ? static_cast<double>(compressed_data.size()) / file_size
        : 0.0;

    return result;
}

bool ZlibCompressor::decompress_file(
    const std::filesystem::path& compressed_path,
    const std::filesystem::path& output_path
) {
    std::ifstream input_file(compressed_path, std::ios::binary);
    if (!input_file) {
        return false;
    }

    input_file.seekg(0, std::ios::end);
    std::uint64_t compressed_size = input_file.tellg();
    input_file.seekg(0, std::ios::beg);

    std::vector<std::uint8_t> compressed_data(compressed_size);
    input_file.read(reinterpret_cast<char*>(compressed_data.data()), compressed_size);
    input_file.close();

    z_stream strm{};
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    strm.avail_in = static_cast<uInt>(compressed_data.size());
    strm.next_in = compressed_data.data();

    if (inflateInit(&strm) != Z_OK) {
        return false;
    }

    const size_t chunk_size = 16384;
    std::vector<std::uint8_t> out_buffer(chunk_size);
    std::ofstream output_file(output_path, std::ios::binary);
    if (!output_file) {
        inflateEnd(&strm);
        return false;
    }

    int ret;
    do {
        strm.avail_out = static_cast<uInt>(chunk_size);
        strm.next_out = out_buffer.data();

        ret = inflate(&strm, Z_NO_FLUSH);

        size_t have = chunk_size - strm.avail_out;
        output_file.write(
            reinterpret_cast<const char*>(out_buffer.data()),
            have
        );
    } while (ret == Z_OK);

    output_file.close();
    inflateEnd(&strm);

    return ret == Z_STREAM_END;
}

std::optional<ArtifactMetadata> ZlibCompressor::read_readme_metadata(
    const std::filesystem::path& readme_path
) {
    std::ifstream file(readme_path);
    if (!file) {
        return std::nullopt;
    }

    ArtifactMetadata metadata;
    std::string line;
    std::string current_section;

    while (std::getline(file, line)) {
        if (line.rfind("## ", 0) == 0) {
            current_section = line.substr(3);
            continue;
        }

        if (line.rfind("- ", 0) == 0) {
            std::string key_value = line.substr(2);
            size_t colon_pos = key_value.find(':');
            if (colon_pos != std::string::npos) {
                std::string key = key_value.substr(0, colon_pos);
                std::string value = key_value.substr(colon_pos + 1);
                while (!value.empty() && value[0] == ' ') {
                    value.erase(0, 1);
                }

                if (key == "Artifact Name") metadata.artifact_name = value;
                else if (key == "Original Path") metadata.original_path = value;
                else if (key == "Original Size") metadata.original_size = std::stoull(value);
                else if (key == "Compressed Size") metadata.compressed_size = std::stoull(value);
                else if (key == "Detected On Host") metadata.detected_on_host = value;
                else if (key == "Detected By User") metadata.detected_by_user = value;
                else if (key == "Detection Timestamp") {
                    metadata.detection_timestamp = parse_iso8601_utc(value);
                }
                else if (key == "File Modification Time") {
                    metadata.file_modification_time = parse_iso8601_utc(value);
                }
                else if (key == "SHA256") metadata.file_hash_sha256 = value;
                else if (key == "MD5") metadata.file_hash_md5 = value;
                else if (key == "Architecture") metadata.architecture = value;
                else if (key == "File Type") metadata.file_type = value;
                else if (key == "Tags") {
                    std::istringstream ss(value);
                    std::string tag;
                    while (std::getline(ss, tag, ',')) {
                        while (!tag.empty() && tag[0] == ' ') tag.erase(0, 1);
                        metadata.tags.push_back(tag);
                    }
                }
                else if (key == "Notes") metadata.notes = value;
            }
        }
    }

    return metadata;
}

std::string ZlibCompressor::generate_readme_content(
    const ArtifactMetadata& metadata
) const {
    std::ostringstream oss;

    oss << "# Artifact Analysis Report\n\n";
    oss << "## Metadata\n\n";
    oss << "- **Artifact Name**: " << metadata.artifact_name << "\n";
    oss << "- **Original Path**: " << metadata.original_path << "\n";
    oss << "- **Original Size**: " << metadata.original_size << " bytes ("
        << std::fixed << std::setprecision(2)
        << static_cast<double>(metadata.original_size) / (1024 * 1024) << " MB)\n";
    oss << "- **Compressed Size**: " << metadata.compressed_size << " bytes ("
        << std::fixed << std::setprecision(2)
        << static_cast<double>(metadata.compressed_size) / (1024 * 1024) << " MB)\n";
    if (metadata.original_size > 0) {
        double ratio = static_cast<double>(metadata.compressed_size) / metadata.original_size * 100.0;
        oss << "- **Compression Ratio**: " << std::fixed << std::setprecision(2) << ratio << "%\n";
    }
    oss << "- **Detected On Host**: " << metadata.detected_on_host << "\n";
    oss << "- **Detected By User**: " << metadata.detected_by_user << "\n";
    oss << "- **Detection Timestamp**: " << format_timestamp(metadata.detection_timestamp) << "\n";
    oss << "- **File Modification Time**: " << format_timestamp(metadata.file_modification_time) << "\n";

    if (!metadata.file_hash_sha256.empty()) {
        oss << "- **SHA256**: " << metadata.file_hash_sha256 << "\n";
    }
    if (!metadata.file_hash_md5.empty()) {
        oss << "- **MD5**: " << metadata.file_hash_md5 << "\n";
    }
    if (!metadata.architecture.empty()) {
        oss << "- **Architecture**: " << metadata.architecture << "\n";
    }
    if (!metadata.file_type.empty()) {
        oss << "- **File Type**: " << metadata.file_type << "\n";
    }
    if (!metadata.tags.empty()) {
        oss << "- **Tags**: ";
        for (size_t i = 0; i < metadata.tags.size(); ++i) {
            if (i > 0) oss << ", ";
            oss << metadata.tags[i];
        }
        oss << "\n";
    }
    if (!metadata.notes.empty()) {
        oss << "- **Notes**: " << metadata.notes << "\n";
    }

    oss << "\n## Compression Details\n\n";
    oss << "- **Algorithm**: zlib (DEFLATE)\n";
    oss << "- **Compression Level**: " << compression_level_ << "\n";
    oss << "- **Container Format**: Raw zlib stream (RFC 1950)\n\n";

    oss << "---\n";
    oss << "*Generated by StaticAnalyzer Compressor Module*\n";

    return oss.str();
}

std::string ZlibCompressor::format_timestamp(
    const std::chrono::system_clock::time_point& tp
) const {
    auto time_t = std::chrono::system_clock::to_time_t(tp);
    std::tm tm = *std::gmtime(&time_t);
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
    return oss.str();
}

std::string ZlibCompressor::get_hostname() const {
#ifdef _WIN32
    char buffer[256];
    DWORD size = sizeof(buffer);
    if (GetComputerNameA(buffer, &size)) {
        return std::string(buffer);
    }
    return "unknown-host";
#else
    char buffer[256];
    if (gethostname(buffer, sizeof(buffer)) == 0) {
        return std::string(buffer);
    }
    return "unknown-host";
#endif
}

std::string ZlibCompressor::get_current_user() const {
#ifdef _WIN32
    char buffer[UNLEN + 1];
    DWORD size = sizeof(buffer);
    if (GetUserNameA(buffer, &size)) {
        return std::string(buffer);
    }
    return "unknown-user";
#else
    struct passwd* pw = getpwuid(getuid());
    if (pw) {
        return std::string(pw->pw_name);
    }
    return "unknown-user";
#endif
}

} // namespace compressor