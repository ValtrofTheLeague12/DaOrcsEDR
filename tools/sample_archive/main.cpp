// sample_archive tool driver: thin CLI over the sample_archive library.
//
//   sample_archive [--verbose] compress   <in> [out.zst]
//   sample_archive [--verbose] decompress <in.zst> [out]
//   sample_archive [--verbose] info       <in.zst>
//
// Output defaults to the input path with ".zst" appended, or with the
// extension stripped for decompress.

#include "sample_archive/archive_log.hpp"
#include "sample_archive/sample_archive.hpp"

#include <filesystem>
#include <iomanip>
#include <iostream>
#include <string>

namespace {

void usage() {
    std::cout
        << "sample_archive - zstd compress/decompress for sample storage or transfer\n\n"
        << "usage:\n"
        << "  sample_archive [--verbose] compress   <in> [out.zst]\n"
        << "  sample_archive [--verbose] decompress <in.zst> [out]\n"
        << "  sample_archive [--verbose] info       <in.zst>\n\n"
        << "Notes:\n"
        << "  * Compressed output is a zstd frame, not a PE. Decompress it before\n"
        << "    handing it to static_analyzer or any other binary parser.\n"
        << "  * Frames carry an xxhash64 content checksum; corrupt input is rejected\n"
        << "    on decompress rather than silently producing garbage.\n";
}

void report(const char* verb, const std::filesystem::path& out,
            const sample_archive::result_t& r) {
    std::cout << "[+] " << verb << " " << out.string() << "\n"
              << "    " << sample_archive::human_size(r.in_bytes) << " -> "
              << sample_archive::human_size(r.out_bytes) << "\n";
    if (r.in_bytes) {
        std::cout << "    " << std::fixed << std::setprecision(1)
                  << (100.0 * static_cast<double>(r.out_bytes) /
                      static_cast<double>(r.in_bytes))
                  << "% of original\n";
    }
}

int show_info(const std::filesystem::path& in) {
    const sample_archive::info_t i = sample_archive::inspect(in);
    if (!i.ok) {
        std::cerr << "error: " << i.error << "\n";
        return 1;
    }
    std::cout << "file:         " << in << "\n"
              << "compressed:   " << sample_archive::human_size(i.compressed) << "\n"
              << "decompressed: " << sample_archive::human_size(i.produced) << "\n";
    if (i.compressed) {
        std::cout << "ratio:        " << std::fixed << std::setprecision(1)
                  << (100.0 * static_cast<double>(i.produced) /
                      static_cast<double>(i.compressed))
                  << "% of original\n";
    }
    std::cout << "frames:       " << i.frames << "\n"
              << "content:      xxhash64 checksum verified while scanning\n";
    if (i.trailing) {
        std::cout << "note:         " << i.trailing << " trailing byte(s) after the last frame\n";
    }
    return 0;
}

}  // namespace

int main(int argc, char** argv) {
    // --help is valid with no file argument, so it has to be handled before
    // the argc check below.
    int arg = 1;
    if (arg < argc) {
        const std::string first = argv[arg];
        if (first == "-h" || first == "--help" || first == "help") {
            usage();
            return 0;
        }
        if (first == "--verbose" || first == "-v") {
            archive_log::set_verbose(true);
            ++arg;
        }
    }
    if (arg < argc) {
        const std::string maybe_verb = argv[arg];
        if (maybe_verb == "-h" || maybe_verb == "--help" || maybe_verb == "help") {
            usage();
            return 0;
        }
    }
    if (argc - arg < 2) { usage(); return 2; }

    const std::string verb = argv[arg];
    const std::filesystem::path in = argv[arg + 1];

    if (verb == "info") {
        if (argc - arg > 2) { std::cerr << "error: info takes exactly one file\n"; return 2; }
        return show_info(in);
    }

    const bool compressing = (verb == "compress");
    const bool expanding = (verb == "decompress");
    if (!compressing && !expanding) {
        std::cerr << "error: unknown verb '" << verb << "'\n\n";
        usage();
        return 2;
    }
    if (argc - arg > 3) {
        std::cerr << "error: too many arguments\n\n";
        usage();
        return 2;
    }

    std::filesystem::path out;
    if (argc - arg == 3) {
        out = argv[arg + 2];
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

    const sample_archive::result_t r =
        compressing ? sample_archive::compress(in, out) : sample_archive::decompress(in, out);
    if (!r.ok) {
        // Plain "error: ..." on stderr is the CLI's stable contract (scripts
        // grep for it); archive_log already carries the verbose progress
        // stream, so the reason is only printed once.
        std::cerr << "error: " << r.error << "\n";
        return 1;
    }
    report(compressing ? "compressed to" : "decompressed to", out, r);
    if (compressing) {
        std::cout << "    note: this is a zstd frame, not a PE - decompress before analysis\n";
    }
    archive_log::info(std::string(compressing ? "compress" : "decompress") + " ok: " +
                      in.string() + " -> " + out.string());
    return 0;
}
