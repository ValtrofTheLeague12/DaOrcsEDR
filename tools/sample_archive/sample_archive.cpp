// sample_archive library: zstd compress / decompress for sample STORAGE and
// TRANSFER (ported from tools/sample_archive.cpp, keeping its verified
// streaming logic and both bug fixes: ZSTD_getErrorName(size_t) error
// reporting, and rejecting truncated frames instead of silently accepting a
// partial restore).
//
// Only moves bytes around; never makes anything executable. See
// include/sample_archive/sample_archive.hpp for the API contract.

#include "sample_archive/sample_archive.hpp"

#include "sample_archive/archive_log.hpp"

#include <zstd.h>

#include <algorithm>
#include <cstdio>
#include <fstream>
#include <vector>

namespace sample_archive {

namespace {

constexpr std::size_t kChunk = 256 * 1024;

std::filesystem::path temp_sibling(const std::filesystem::path& out) {
    std::filesystem::path tmp = out;
    tmp += ".partial";
    return tmp;
}

// On any failure path that has already created the staged temp file, drop it
// so an aborted run never leaves a ".partial" lying next to the archive.
void discard(const std::filesystem::path& tmp) {
    std::error_code ignored;
    std::filesystem::remove(tmp, ignored);
}

// zstd wants the raw size_t result here: ZSTD_getErrorName(size_t) decodes
// the error from the result itself. Converting through ZSTD_getErrorCode()
// first mis-reports real failures (e.g. a checksum mismatch came out as
// "No error detected").
std::string describe(std::size_t rc, std::uint64_t pos) {
    return std::string(ZSTD_getErrorName(rc)) + " (at byte " + std::to_string(pos) + ")";
}

}  // namespace

std::optional<std::uint64_t> size_on_disk(const std::filesystem::path& p) {
    std::error_code ec;
    const auto n = std::filesystem::file_size(p, ec);
    if (ec) return std::nullopt;
    return static_cast<std::uint64_t>(n);
}

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
    else           std::snprintf(buf, sizeof(buf), "%.2f %s", value, units[unit]);
    return buf;
}

result_t compress(const std::filesystem::path& in, const std::filesystem::path& out) {
    result_t r;
    std::ifstream src(in, std::ios::binary);
    if (!src) { r.error = "cannot read " + in.string(); return r; }

    // Staged write + rename on success, so a failure can never leave a
    // half-written sample behind that looks like a real one.
    const std::filesystem::path tmp = temp_sibling(out);
    std::ofstream dst(tmp, std::ios::binary | std::ios::trunc);
    if (!dst) { r.error = "cannot write " + tmp.string(); return r; }

    std::vector<char> in_buf(kChunk);
    std::vector<char> out_buf(ZSTD_CStreamOutSize());

    ZSTD_CStream* cs = ZSTD_createCStream();
    if (cs == nullptr) {
        r.error = "ZSTD_createCStream failed";
        dst.close();
        discard(tmp);
        return r;
    }
    // Level 19: best ratio, and this is an offline storage path where the CPU
    // cost does not matter.
    const std::size_t init_err = ZSTD_initCStream(cs, kLevel);
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
            r.error = "compress failed: " + describe(rc, input.pos);
            break;
        }
        if (output.pos) {
            dst.write(out_buf.data(), static_cast<std::streamsize>(output.pos));
            r.out_bytes += output.pos;
            if (!dst) { r.error = "write error on " + tmp.string(); break; }
        }
        if (eof && rc == 0) finished = true;       // frame fully flushed
        archive_log::debug("compress: out=" + std::to_string(r.out_bytes) +
                           (eof ? " (flushing)" : ""));
    }

    ZSTD_freeCStream(cs);
    dst.close();
    if (!r.error.empty()) {
        discard(tmp);
        return r;
    }

    std::error_code ec;
    std::filesystem::rename(tmp, out, ec);
    if (ec) {
        discard(tmp);
        r.error = "cannot move " + tmp.string() + " -> " + out.string() + ": " + ec.message();
        return r;
    }

    r.in_bytes = size_on_disk(in).value_or(r.out_bytes);
    r.ok = true;
    archive_log::info("compressed " + in.string() + " -> " + out.string() + " (" +
                      std::to_string(r.in_bytes) + " -> " + std::to_string(r.out_bytes) + ")");
    return r;
}

result_t decompress(const std::filesystem::path& in, const std::filesystem::path& out) {
    result_t r;
    std::ifstream src(in, std::ios::binary);
    if (!src) { r.error = "cannot read " + in.string(); return r; }

    // Write to a sibling temp file and rename on success, so a truncated or
    // corrupt archive never leaves a half-written "restored" sample behind.
    const std::filesystem::path tmp = temp_sibling(out);
    {
        std::ofstream dst(tmp, std::ios::binary | std::ios::trunc);
        if (!dst) { r.error = "cannot write " + tmp.string(); return r; }

        std::vector<char> in_buf(kChunk);
        std::vector<char> out_buf(ZSTD_DStreamOutSize());

        ZSTD_DStream* ds = ZSTD_createDStream();
        if (ds == nullptr) {
            r.error = "ZSTD_createDStream failed";
            dst.close();
            discard(tmp);
            return r;
        }
        const std::size_t init_err = ZSTD_initDStream(ds);

        ZSTD_inBuffer input{in_buf.data(), 0, 0};
        bool eof = false;
        bool frame_done = false;
        std::uint64_t total_in = 0;
        while (!ZSTD_isError(init_err)) {
            if (input.pos == input.size && !eof) {
                total_in += static_cast<std::uint64_t>(input.size);
                src.read(in_buf.data(), static_cast<std::streamsize>(in_buf.size()));
                const std::streamsize got = src.gcount();
                if (got < 0) { r.error = "read error on " + in.string(); break; }
                if (got == 0) eof = true;
                input = {in_buf.data(), static_cast<std::size_t>(got), 0};
            }
            ZSTD_outBuffer output{out_buf.data(), out_buf.size(), 0};
            const std::size_t rc = ZSTD_decompressStream(ds, &output, &input);
            if (ZSTD_isError(rc)) {
                r.error = "decompress failed: " + describe(rc, input.pos);
                break;
            }
            if (rc == 0) frame_done = true;
            archive_log::debug("decompress: out=" + std::to_string(r.out_bytes) +
                               (eof ? " (draining)" : ""));
            if (output.pos) {
                dst.write(out_buf.data(), static_cast<std::streamsize>(output.pos));
                r.out_bytes += output.pos;
                if (!dst) { r.error = "write error on " + tmp.string(); break; }
            }
            // rc == 0 means the current frame is fully decoded. At EOF with no
            // output left to flush the stream is done; a nonzero rc here means
            // the frame is incomplete, i.e. truncated input, so fail instead
            // of silently accepting a partial sample.
            if (eof && input.pos == input.size && output.pos == 0) {
                if (!frame_done) {
                    r.error = "decompress failed: truncated input (frame incomplete "
                              "at byte " + std::to_string(total_in) + ")";
                }
                break;
            }
        }

        ZSTD_freeDStream(ds);
        dst.close();
        if (!r.error.empty()) {
            discard(tmp);
            return r;
        }
    }

    std::error_code ec;
    std::filesystem::rename(tmp, out, ec);
    if (ec) {
        discard(tmp);
        r.error = "cannot move " + tmp.string() + " -> " + out.string() + ": " + ec.message();
        return r;
    }

    r.in_bytes = size_on_disk(in).value_or(r.out_bytes);
    r.ok = true;
    archive_log::info("decompressed " + in.string() + " -> " + out.string() + " (" +
                      std::to_string(r.in_bytes) + " -> " + std::to_string(r.out_bytes) + ")");
    return r;
}

info_t inspect(const std::filesystem::path& in) {
    info_t i;
    std::ifstream src(in, std::ios::binary);
    if (!src) { i.error = "cannot read " + in.string(); return i; }

    // Frame boundaries come from ZSTD_findFrameCompressedSize rather than from
    // ZSTD_decompressStream's return value. The latter is only guaranteed to
    // hit 0 when a frame is *fully flushed*, which depends on how the caller's
    // output buffer happens to line up with the block structure - it is not a
    // reliable frame counter.
    //
    // Only the frame header is needed to size a frame, so a small window at
    // each offset is enough and the file is never held in memory.
    i.compressed = size_on_disk(in).value_or(0);
    const std::uint64_t total = i.compressed;

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
            i.error = "Unknown frame descriptor at byte " + std::to_string(offset) + " (file " +
                      std::to_string(total) + " B, read " + std::to_string(got) +
                      " B, needs more than " + std::to_string(buf.size()) + " B)";
            return i;
        }
        if (frame_size == 0) break;                 // no further frame
        ++frames;
        offset += frame_size;
    }

    // Measure the decompressed size so the ratio is meaningful.
    ZSTD_DStream* ds = ZSTD_createDStream();
    if (ds == nullptr) { i.error = "ZSTD_createDStream failed"; return i; }
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
            i.error = std::string(ZSTD_getErrorName(rc)) + " at byte " + std::to_string(input.pos);
            ZSTD_freeDStream(ds);
            return i;
        }
        produced += output.pos;
        if (eof && input.pos == input.size && (rc == 0 || output.pos == 0)) break;
    }
    ZSTD_freeDStream(ds);

    i.trailing = total - offset;
    i.produced = produced;
    i.frames = frames;
    i.checksum = true;  // verified implicitly: a mismatch fails the scan above
    i.ok = true;
    archive_log::debug("inspect: frames=" + std::to_string(frames) +
                       " produced=" + std::to_string(produced));
    return i;
}

}  // namespace sample_archive



