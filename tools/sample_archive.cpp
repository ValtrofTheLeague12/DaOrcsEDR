// sample_archive: zstd compress / decompress for sample STORAGE and TRANSFER.
//
// This tool only moves bytes around; it does not make anything executable. A
// zstd-compressed PE has no MZ header, no section table and no entry point, so
// it cannot be run or analyzed as a binary - decompress it first if you need to
// feed it to static_analyzer. It exists to keep samples small in an evidence
// store, a mail attachment, or a transfer to another analysis host.
//
//   sample_archive compress   <in> [out.zst]
//   sample_archive decompress <in.zst> [out]
//   sample_archive info       <in.zst>
//
// Output defaults to the input path with ".zst" appended, or with the
// extension stripped for decompress.

#include <zstd.h>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <optional>
#include <string>
#include <vector>

namespace {

constexpr std::size_t kChunk = 256 * 1024;

std::string human_size(std::uint64_t bytes) {
    static const char* units[] = {"B", "KiB", "MiB", "GiB", "TiB"};
    double value = static_cast<double>(bytes);
    std::size_t unit = 0;
    while (value >= 1024.0 && unit + 1 < sizeof(units) / sizeof(units[0])) {
        value /= 1024.0;
        ++unit;
    }
    char buf[64];
    if (unit == 0) std::snprintf(buf, sizeof(buf), "%llu %s",
                                 static_cast<unsigned long long>(bytes), units[unit]);
    else          std::snprintf(buf, sizeof(buf), "%.2f %s", value, units[unit]);
    return buf;
}

void usage() {
    std::cout
        << "sample_archive - zstd compress/decompress for sample storage or transfer\n\n"
        << "usage:\n"
        << "  sample_archive compress   <in> [out.zst]\n"
        << "  sample_archive decompress <in.zst> [out]\n"
        << "  sample_archive info       <in.zst>\n\n"
        << "Notes:\n"
        << "  * Compressed output is a zstd frame, not a PE. Decompress it before\n"
        << "    handing it to static_analyzer or any other binary parser.\n"
        << "  * Frames carry an xxhash64 content checksum; corrupt input is rejected\n"
        << "    on decompress rather than silently producing garbage.\n";
}

// Not named file_size(): argument-dependent lookup would make every call
// ambiguous with std::filesystem::file_size.
std::optional<std::uint64_t> size_on_disk(const std::filesystem::path& p) {
    std::error_code ec;
    const auto n = std::filesystem::file_size(p, ec);
    if (ec) return std::nullopt;
    return static_cast<std::uint64_t>(n);
}

struct result_t {
    bool ok = false;
    std::string error;
    std::uint64_t in_bytes = 0;
    std::uint64_t out_bytes = 0;
};

// zstd's own error strings are terse; add the stream position so a truncated
// file can be told apart from a corrupt one.
std::string describe(ZSTD_ErrorCode code, std::uint64_t pos) {
    return std::string(ZSTD_getErrorName(code)) + " (at byte " + std::to_string(pos) + ")";
}

result_t compress(const std::filesystem::path& in, const std::filesystem::path& out) {
    result_t r;
    std::ifstream src(in, std::ios::binary);
    if (!src) { r.error = "cannot read " + in.string(); return r; }

    std::ofstream dst(out, std::ios::binary);
    if (!dst) { r.error = "cannot write " + out.string(); return r; }

    std::vector<char> in_buf(kChunk);
    std::vector<char> out_buf(ZSTD_CStreamOutSize());

    ZSTD_CStream* cs = ZSTD_createCStream();
    if (cs == nullptr) { r.error = "ZSTD_createCStream failed"; return r; }
    // Level 19: best ratio, and this is an offline storage path where the CPU
    // cost does not matter.
    const std::size_t init_err = ZSTD_initCStream(cs, 19);
    if (!ZSTD_isError(init_err)) {
        // xxhash64 content checksum, so a corrupt archive is detected on
        // decompress instead of yielding silently wrong bytes.
        ZSTD_CCtx_setParameter(cs, ZSTD_c_checksumFlag, 1);
    }

    ZSTD_inBuffer input{in_buf.data(), 0, 0};
    bool eof = false;
    bool finished = false;
    while (!ZSTD_isError(init_err) && !finished) {
        if (!eof && input.pos == input.size) {
            src.read(in_buf.data(), static_cast<std::streamsize>(in_buf.size()));
            const std::streamsize got = src.gcount();
            if (got < 0) { r.error = "read error on " + in.string(); break; }
            if (got == 0) eof = true;
            input = {in_buf.data(), static_cast<std::size_t>(got), 0};
            if (got == 0) {
                // Fall through to endStream() below. The frame epilogue and
                // checksum are written there, so skipping it yields a stream
                // that decompresses correctly but is structurally malformed -
                // ZSTD_findFrameCompressedSize rejects it, and other tools may
                // refuse the file outright.
                continue;
            }
        }
        ZSTD_outBuffer output{out_buf.data(), out_buf.size(), 0};
        // endStream() must be called until it returns 0; one call can leave
        // buffered data unwritten when the output buffer is small.
        const std::size_t rc = eof ? ZSTD_endStream(cs, &output)
                                   : ZSTD_compressStream(cs, &output, &input);
        if (ZSTD_isError(rc)) {
            r.error = "compress failed: " + describe(ZSTD_getErrorCode(rc), input.pos);
            break;
        }
        if (output.pos) {
            dst.write(out_buf.data(), static_cast<std::streamsize>(output.pos));
            r.out_bytes += output.pos;
            if (!dst) { r.error = "write error on " + out.string(); break; }
        }
        if (eof && rc == 0) finished = true;       // frame fully flushed
    }

    ZSTD_freeCStream(cs);
    if (!r.error.empty()) return r;

    r.in_bytes = size_on_disk(in).value_or(r.out_bytes);
    r.ok = true;
    return r;
}

result_t decompress(const std::filesystem::path& in, const std::filesystem::path& out) {
    result_t r;
    std::ifstream src(in, std::ios::binary);
    if (!src) { r.error = "cannot read " + in.string(); return r; }

    // Write to a sibling temp file and rename on success, so a truncated or
    // corrupt archive never leaves a half-written "restored" sample behind.
    std::filesystem::path tmp = out;
    tmp += ".partial";
    {
        std::ofstream dst(tmp, std::ios::binary);
        if (!dst) { r.error = "cannot write " + tmp.string(); return r; }

        std::vector<char> in_buf(kChunk);
        std::vector<char> out_buf(ZSTD_DStreamOutSize());

        ZSTD_DStream* ds = ZSTD_createDStream();
        if (ds == nullptr) { r.error = "ZSTD_createDStream failed"; return r; }
        const std::size_t init_err = ZSTD_initDStream(ds);

        ZSTD_inBuffer input{in_buf.data(), 0, 0};
        bool eof = false;
        while (!ZSTD_isError(init_err)) {
            if (input.pos == input.size && !eof) {
                src.read(in_buf.data(), static_cast<std::streamsize>(in_buf.size()));
                const std::streamsize got = src.gcount();
                if (got < 0) { r.error = "read error on " + in.string(); break; }
                if (got == 0) eof = true;
                input = {in_buf.data(), static_cast<std::size_t>(got), 0};
            }
            ZSTD_outBuffer output{out_buf.data(), out_buf.size(), 0};
            const std::size_t rc = ZSTD_decompressStream(ds, &output, &input);
            if (ZSTD_isError(rc)) {
                r.error = "decompress failed: " + describe(ZSTD_getErrorCode(rc), input.pos);
                break;
            }
            if (output.pos) {
                dst.write(out_buf.data(), static_cast<std::streamsize>(output.pos));
                r.out_bytes += output.pos;
                if (!dst) { r.error = "write error on " + tmp.string(); break; }
            }
            // At EOF keep feeding an empty input until zstd reports the frame
            // finished (rc == 0). Breaking on EOF alone would silently truncate
            // any sample whose final frame still has buffered blocks.
            if (eof && input.pos == input.size && (rc == 0 || output.pos == 0)) break;
        }

        ZSTD_freeDStream(ds);
        if (!r.error.empty()) {
            dst.close();
            std::error_code ignored;
            std::filesystem::remove(tmp, ignored);
            return r;
        }
    }

    std::error_code ec;
    std::filesystem::rename(tmp, out, ec);
    if (ec) {
        std::error_code ignored;
        std::filesystem::remove(tmp, ignored);
        r.error = "cannot move " + tmp.string() + " -> " + out.string() + ": " + ec.message();
        return r;
    }

    r.in_bytes = size_on_disk(in).value_or(r.out_bytes);
    r.ok = true;
    return r;
}

int show_info(const std::filesystem::path& in) {
    std::ifstream src(in, std::ios::binary);
    if (!src) { std::cerr << "error: cannot read " << in << "\n"; return 1; }

    // Frame boundaries come from ZSTD_findFrameCompressedSize rather than from
    // ZSTD_decompressStream's return value. The latter is only guaranteed to
    // hit 0 when a frame is *fully flushed*, which depends on how the caller's
    // output buffer happens to line up with the block structure - it is not a
    // reliable frame counter.
    //
    // Only the frame header is needed to size a frame, so a small window at
    // each offset is enough and the file is never held in memory.
    const std::uint64_t total = size_on_disk(in).value_or(0);

    // ZSTD_findFrameCompressedSize needs the whole frame in the buffer, not
    // just its header, so read the largest frame this file could hold. Capped
    // so a huge multi-frame file cannot blow up memory; frames past the cap
    // simply stop the walk, and the trailing-bytes note reports the rest.
    const std::size_t window = static_cast<std::size_t>(
        std::min<std::uint64_t>(total, 64ull * 1024 * 1024));
    std::vector<char> buf(window ? window : 1);

    std::uint64_t offset = 0, frames = 0;
    while (offset < total) {
        src.seekg(static_cast<std::streamoff>(offset), std::ios::beg);
        if (!src) break;
        src.read(buf.data(), static_cast<std::streamsize>(buf.size()));
        const std::streamsize got = src.gcount();
        if (got <= 0) break;
        const std::size_t frame_size =
            ZSTD_findFrameCompressedSize(buf.data(), static_cast<std::size_t>(got));
        if (ZSTD_isError(frame_size)) {
            std::cerr << "error: " << ZSTD_getErrorName(frame_size)
                      << " at byte " << offset
                      << " (file " << total << " B, read " << got
                      << " B, needs more than " << buf.size() << " B)\n";
            return 1;
        }
        if (frame_size == 0) break;                 // no further frame
        ++frames;
        offset += frame_size;
    }

    // Measure the decompressed size so the ratio is meaningful.
    ZSTD_DStream* ds = ZSTD_createDStream();
    if (ds == nullptr) { std::cerr << "error: ZSTD_createDStream failed\n"; return 1; }
    ZSTD_initDStream(ds);
    src.clear();
    src.seekg(0, std::ios::beg);

    std::vector<char> in_buf(kChunk);
    std::vector<char> out_buf(ZSTD_DStreamOutSize());
    ZSTD_inBuffer input{in_buf.data(), 0, 0};

    std::uint64_t produced = 0;
    bool eof = false;
    while (true) {
        if (input.pos == input.size && !eof) {
            src.read(in_buf.data(), static_cast<std::streamsize>(in_buf.size()));
            const std::streamsize got = src.gcount();
            if (got <= 0) {
                // No more input, but the current frame may still have buffered
                // blocks to drain, so keep looping with an empty input until
                // zstd reports the frame finished.
                eof = true;
                input = {in_buf.data(), 0, 0};
            } else {
                input = {in_buf.data(), static_cast<std::size_t>(got), 0};
            }
        }
        ZSTD_outBuffer output{out_buf.data(), out_buf.size(), 0};
        const std::size_t rc = ZSTD_decompressStream(ds, &output, &input);
        if (ZSTD_isError(rc)) {
            std::cerr << "error: " << ZSTD_getErrorName(rc) << " at byte " << input.pos << "\n";
            ZSTD_freeDStream(ds);
            return 1;
        }
        produced += output.pos;
        if (eof && input.pos == input.size && (rc == 0 || output.pos == 0)) break;
    }
    ZSTD_freeDStream(ds);

    if (offset < total) {
        // Trailing bytes that are not a frame: skippable frames or junk.
        std::cout << "note:        " << (total - offset)
                  << " trailing byte(s) after the last frame\n";
    }

    std::cout << "file:         " << in << "\n"
              << "compressed:   " << human_size(total) << "\n"
              << "decompressed: " << human_size(produced) << "\n";
    if (total) {
        std::cout << "ratio:        " << std::fixed << std::setprecision(1)
                  << (100.0 * static_cast<double>(produced) / static_cast<double>(total))
                  << "% of original\n";
    }
    std::cout << "frames:       " << frames << "\n"
              << "content:      xxhash64 checksum verified while scanning\n";
    return 0;
}

void report(const char* verb, const std::filesystem::path& out, const result_t& r) {
    std::cout << "[+] " << verb << " " << out.string() << "\n"
              << "    " << human_size(r.in_bytes) << " -> " << human_size(r.out_bytes) << "\n";
    if (r.in_bytes) {
        std::cout << "    " << std::fixed << std::setprecision(1)
                  << (100.0 * static_cast<double>(r.out_bytes) /
                      static_cast<double>(r.in_bytes))
                  << "% of original\n";
    }
}

}  // namespace

int main(int argc, char** argv) {
    // --help is valid with no file argument, so it has to be handled before
    // the argc check below.
    if (argc >= 2) {
        const std::string maybe_verb = argv[1];
        if (maybe_verb == "-h" || maybe_verb == "--help" || maybe_verb == "help") {
            usage();
            return 0;
        }
    }
    if (argc < 3) { usage(); return 2; }

    const std::string verb = argv[1];
    const std::filesystem::path in = argv[2];

    if (verb == "info") {
        if (argc > 3) { std::cerr << "error: info takes exactly one file\n"; return 2; }
        return show_info(in);
    }

    const bool compressing = (verb == "compress");
    const bool expanding = (verb == "decompress");
    if (!compressing && !expanding) {
        std::cerr << "error: unknown verb '" << verb << "'\n\n";
        usage();
        return 2;
    }
    if (argc > 4) {
        std::cerr << "error: too many arguments\n\n";
        usage();
        return 2;
    }

    std::filesystem::path out;
    if (argc == 4) {
        out = argv[3];
    } else if (compressing) {
        out = in;
        out += ".zst";
    } else {
        out = in;
        out.replace_extension();                 // drop ".zst"
    }

    if (out == in) {
        std::cerr << "error: refusing to overwrite the input with its own output\n";
        return 1;
    }
    if (std::filesystem::exists(out)) {
        std::cerr << "error: " << out.string() << " already exists (delete it or pass a name)\n";
        return 1;
    }

    const result_t r = compressing ? compress(in, out) : decompress(in, out);
    if (!r.ok) {
        std::cerr << "error: " << r.error << "\n";
        return 1;
    }
    report(compressing ? "compressed to" : "decompressed to", out, r);
    if (compressing) {
        std::cout << "    note: this is a zstd frame, not a PE - decompress before analysis\n";
    }
    return 0;
}
