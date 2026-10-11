#include "phase_compression.hpp"

#include "core/compressor.hpp"
#include "logging.hpp"
#include "console.hpp"

#include <filesystem>

namespace pipeline {

void run_compression(context& ctx, const std::string& output_dir, int compression_level) {
    // Only compress if we have an executable format (PE, ELF, or Mach-O)
    if (!ctx.is_pe && !ctx.is_elf && !ctx.is_macho) {
        LOG_DEBUG("compression: not an executable format, skipping");
        return;
    }

    if (ctx.failed) {
        LOG_DEBUG("compression: analysis failed, skipping");
        return;
    }

    phase(ctx, true, "artifact compression");

    const auto started = report_clock::now();

    // Determine output directory
    std::filesystem::path out_dir = output_dir;
    if (out_dir.is_relative()) {
        out_dir = std::filesystem::path(ctx.path).parent_path() / out_dir;
    }
    std::error_code ec;
    std::filesystem::create_directories(out_dir, ec);
    if (ec) {
        LOG_ERROR("compression: failed to create output directory '{}': {}",
                  out_dir.string(), ec.message());
        return;
    }

    // Build metadata from context
    compressor::ArtifactMetadata metadata;
    metadata.artifact_name = ctx.info.filename;
    metadata.original_path = ctx.path;
    metadata.architecture = ctx.info.type.executable_type.empty() ? "unknown" : ctx.info.type.executable_type;
    metadata.file_type = ctx.info.file_magic;

    // Add tags based on format
    if (ctx.is_pe) metadata.tags.push_back("pe");
    if (ctx.is_elf) metadata.tags.push_back("elf");
    if (ctx.is_macho) metadata.tags.push_back("macho");
    if (!ctx.info.type.executable_type.empty()) metadata.tags.push_back(ctx.info.type.executable_type);

    // Add notes from analysis if available
    std::string notes;
    if (!ctx.capa_report.capabilities.empty()) {
        notes += "capa capabilities: " + std::to_string(ctx.capa_report.capabilities.size()) + "; ";
    }
    if (!ctx.ioc_results.ips.empty()) {
        notes += "IPs: " + std::to_string(ctx.ioc_results.ips.size()) + "; ";
    }
    if (!ctx.malapi_hits.empty()) {
        notes += "MalAPI hits: " + std::to_string(ctx.malapi_hits.size()) + "; ";
    }
    if (ctx.known_pe_match.matched) {
        notes += "Known PE: ";
        notes += ctx.known_pe_match.entry.malicious ? "malicious" : "benign";
        notes += "; ";
    }
    metadata.notes = notes;

    // Get hostname and user
    metadata.detected_on_host = ctx.info.type.executable_type.empty() ? "unknown" : ctx.info.type.executable_type;
    // Note: In a real deployment, you'd get the actual hostname/user from the system

    // Create compressor
    compressor::ZlibCompressor compressor(compression_level);

    // Compress the file
    auto result = compressor.compress_file(
        ctx.path,
        out_dir,
        metadata
    );

    if (result.success) {
        LOG_INFO("compression: {} -> {} ({:.1f}%)",
                 result.original_size, result.compressed_size,
                 result.compression_ratio * 100.0);
        print_kv_colored("Compressed", result.compressed_path, console::green);
        print_kv("README", result.readme_path);
        print_kv("Ratio", std::to_string(result.compression_ratio * 100.0) + "%");
    } else {
        LOG_ERROR("compression: failed: {}", result.error_message);
        print_kv_colored("Compression", "FAILED", console::red);
        print_kv("Error", result.error_message);
    }

    print_duration(elapsed_ms(started));
}

}  // namespace pipeline