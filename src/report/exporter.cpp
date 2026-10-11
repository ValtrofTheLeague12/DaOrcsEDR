// exporter.cpp

#include "exporter.hpp"

#include "logging.hpp"
#include "console.hpp"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <set>
#include <sstream>

namespace exporter {

namespace fs = std::filesystem;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

namespace {

template <typename E>
inline bool flags_set(E e) noexcept {
    return static_cast<std::uint32_t>(e) != 0;
}

class scoped_timer {
public:
    scoped_timer(std::string name, const char* file, int line)
        : name_(std::move(name)), file_(file), line_(line),
          start_(std::chrono::steady_clock::now()) {}

    ~scoped_timer() {
        const auto end = std::chrono::steady_clock::now();
        const double ms =
            std::chrono::duration<double, std::milli>(end - start_).count();
        logging::debug(file_, line_, "exporter: '{}' took {:.3f} ms", name_, ms);
    }

    scoped_timer(const scoped_timer&) = delete;
    scoped_timer& operator=(const scoped_timer&) = delete;

private:
    std::string name_;
    const char* file_;
    int line_;
    std::chrono::steady_clock::time_point start_;
};

constexpr std::uint32_t kSoftExtractorErrors =
    static_cast<std::uint32_t>(extractor::extractor_error::no_signature)       |
    static_cast<std::uint32_t>(extractor::extractor_error::no_debug_symbols)   |
    static_cast<std::uint32_t>(extractor::extractor_error::no_strings)         |
    static_cast<std::uint32_t>(extractor::extractor_error::no_code_section)    |
    static_cast<std::uint32_t>(extractor::extractor_error::no_guards)          |
    static_cast<std::uint32_t>(extractor::extractor_error::hexdump_read_failed) |
    static_cast<std::uint32_t>(extractor::extractor_error::cminer_not_found) |
    static_cast<std::uint32_t>(extractor::extractor_error::cminer_failed)    |
    static_cast<std::uint32_t>(extractor::extractor_error::cminer_timeout);

void print_export_line(const char* artifact, const fs::path& path, bool ok) {
    if (ok) {
        std::cout << console::paint(console::green, "[+] ")
                  << console::paint(console::green, artifact)
                  << ": " << path.string() << "\n";
    } else {
        std::cout << console::paint(console::red, "[-] ")
                  << console::paint(console::red, artifact)
                  << ": export failed\n";
    }
}

}  // namespace

#define EXPORTER_TRY(label, ...)                                            \
    try {                                                                   \
        __VA_ARGS__                                                         \
    } catch (const std::exception& e) {                                     \
        LOG_ERROR("exporter: " label " threw: {}", e.what());               \
        std::cout << console::paint(console::red, "[-] ")                   \
                  << console::paint(console::red, label)                    \
                  << ": " << e.what() << "\n";                              \
        return {};                                                          \
    } catch (...) {                                                         \
        LOG_ERROR("exporter: " label " threw unknown exception");           \
        std::cout << console::paint(console::red, "[-] ")                   \
                  << console::paint(console::red, label)                    \
                  << ": unknown exception\n";                               \
        return {};                                                          \
    }

// ---------------------------------------------------------------------------
// artifact_stem / sanitize_stem / make_stem
// ---------------------------------------------------------------------------

std::string artifact_stem(std::string_view stem, std::string_view artifact) {
    LOG_TRACE("exporter: artifact_stem: stem='{}', artifact='{}'", stem, artifact);
    std::string out;
    out.reserve(stem.size() + artifact.size() + 1);
    out += stem;
    out += '_';
    out += artifact;
    return out;
}

// ---------------------------------------------------------------------------
// dir:: per-run path helpers
//
// One run = one directory: exports/<stem>_analysis/<category>/<stem>_<x>.json.
// The category directories used to be shared across every sample ever
// analyzed; rooting them per stem means a run never reads (or overwrites)
// another sample's artifacts.
// ---------------------------------------------------------------------------

namespace dir {

std::filesystem::path run_root(const std::string& stem) {
    LOG_TRACE("exporter: dir::run_root: stem='{}'", stem);
    return std::filesystem::path(root) / (stem + "_analysis");
}

std::filesystem::path run(const std::string& stem, std::string_view category) {
    return run_root(stem) / std::string(category);
}

std::filesystem::path artifact(const std::string& stem,
                               std::string_view category,
                               std::string_view artifact_name) {
    return run(stem, category) / (artifact_stem(stem, artifact_name) + ".json");
}

} // namespace dir

std::string sanitize_stem(const std::string& raw) {
    LOG_TRACE("exporter: sanitize_stem: raw='{}' ({} chars)", raw, raw.size());
    std::string out;
    out.reserve(raw.size());
    std::size_t replaced = 0;
    for (char c : raw) {
        const unsigned char uc = static_cast<unsigned char>(c);
        if (uc < 0x20 || uc == 0x7F) { out.push_back('_'); ++replaced; continue; }
        switch (c) {
            case '/': case '\\': case ':': case '*':
            case '?': case '"':  case '<': case '>':
            case '|':
                out.push_back('_');
                ++replaced;
                break;
            default:
                out.push_back(c);
                break;
        }
    }
    if (out == "." || out == "..") {
        LOG_DEBUG("exporter: sanitize_stem: reserved name '{}' -> 'sample'", raw);
        out = "sample";
    }
    constexpr std::size_t kMaxStem = 200;
    if (out.size() > kMaxStem) {
        LOG_DEBUG("exporter: sanitize_stem: truncating from {} to {} chars",
                  out.size(), kMaxStem);
        out.resize(kMaxStem);
    }
    if (out.empty()) {
        LOG_DEBUG("exporter: sanitize_stem: empty result for '{}' -> 'sample'", raw);
        out = "sample";
    }
    LOG_TRACE("exporter: sanitize_stem -> '{}' ({} char(s) replaced)", out, replaced);
    return out;
}

std::string make_stem(const analyzer::file_info_t& info,
                      const file_hash_t& sha256) {
    LOG_TRACE("exporter: make_stem: filename='{}', filepath='{}', sha256_len={}",
              info.filename, info.filepath, sha256.hash.size());
    auto strip_ext = [](std::string s) -> std::string {
        const std::size_t dot = s.find_last_of('.');
        if (dot != std::string::npos && dot > 0) s.resize(dot);
        return s;
    };
    if (!info.filename.empty()) {
        const std::string stem = sanitize_stem(strip_ext(info.filename));
        LOG_DEBUG("exporter: make_stem: using filename stem='{}'", stem);
        return stem;
    }
    if (sha256.hash.size() >= 16) {
        const std::string stem = sha256.hash.substr(0, 16);
        LOG_DEBUG("exporter: make_stem: using sha256 prefix stem='{}'", stem);
        return stem;
    }
    if (!info.filepath.empty()) {
        const std::string stem = sanitize_stem(
            strip_ext(fs::path(info.filepath).filename().string()));
        LOG_DEBUG("exporter: make_stem: using filepath stem='{}'", stem);
        return stem;
    }
    LOG_WARN("exporter: make_stem: no filename/sha256/filepath, falling back to 'sample'");
    return "sample";
}

// ---------------------------------------------------------------------------
// to_json(file_info_t)
// ---------------------------------------------------------------------------

json to_json(const analyzer::file_info_t& info) {
    LOG_TRACE("exporter: to_json(file_info_t): filepath='{}', size={}, magic_bytes={}",
              info.filepath, info.size, info.binary_magic.size());

    json magic_bytes = json::array();
    for (auto b : info.binary_magic) magic_bytes.push_back(static_cast<std::uint32_t>(b));

    std::string magic_hex;
    static constexpr char kHex[] = "0123456789abcdef";
    for (std::size_t i = 0; i < info.binary_magic.size(); ++i) {
        if (i) magic_hex.push_back(' ');
        const std::uint8_t b = info.binary_magic[i];
        magic_hex.push_back(kHex[b >> 4]);
        magic_hex.push_back(kHex[b & 0x0F]);
    }

    char size_human[32];
    if (info.size < 1024ull)
        std::snprintf(size_human, sizeof(size_human), "%llu B",
                      static_cast<unsigned long long>(info.size));
    else if (info.size < 1024ull * 1024ull)
        std::snprintf(size_human, sizeof(size_human), "%.1f KiB",
                      static_cast<double>(info.size) / 1024.0);
    else
        std::snprintf(size_human, sizeof(size_human), "%.1f MiB",
                      static_cast<double>(info.size) / (1024.0 * 1024.0));

    if (flags_set(info.errors.flags)) {
        LOG_DEBUG("exporter: to_json(file_info_t): errors.flags={}, messages={}",
                  static_cast<std::uint32_t>(info.errors.flags),
                  info.errors.messages.size());
    }

    return json{
        {"filepath",         info.filepath},
        {"filename",         info.filename},
        {"extension",        info.extension},
        {"size",             info.size},
        {"size_human",       size_human},
        {"file_magic",       info.file_magic},
        {"header_signature", info.header_signature},
        {"format",           info.type.executable_type},
        {"is_executable",    info.type.is_executable},
        {"binary_magic",     std::move(magic_bytes)},
        {"binary_magic_hex", std::move(magic_hex)},
        {"errors", {
            {"flags",    static_cast<std::uint32_t>(info.errors.flags)},
            {"messages", info.errors.messages},
            {"details",  info.errors.details},
        }},
    };
}

// ---------------------------------------------------------------------------
// to_json(hashes)
// ---------------------------------------------------------------------------

json to_json(const file_hash_t& sha256, const fuzzy_hash_t& tlsh) {
    LOG_TRACE("exporter: to_json(hashes): sha256_len={}, tlsh_len={}",
              sha256.hash.size(), tlsh.fuzzy_hash.size());

    auto short_of = [](const std::string& s, std::size_t n) {
        if (s.size() <= n) return s;
        return s.substr(0, n) + "...";
    };

    // Read-aloud rendering of the digest (PGP word list), exported next to
    // the hex so a human can compare it without transcribing 64 characters.
    const std::string words = hasher::human_words(sha256.hash);

    json algorithms = json::array();
    if (!sha256.hash.empty()) {
        algorithms.push_back({
            {"name",      sha256.algo_used.empty() ? "sha256" : sha256.algo_used},
            {"value",     sha256.hash},
            {"short",     short_of(sha256.hash, 16)},
            {"words",     words},
            {"size_bits", 256},
        });
    } else {
        LOG_WARN("exporter: to_json(hashes): sha256 hash is empty");
    }
    if (!tlsh.fuzzy_hash.empty()) {
        algorithms.push_back({
            {"name",      tlsh.fuzzy_algo_used.empty() ? "tlsh" : tlsh.fuzzy_algo_used},
            {"value",     tlsh.fuzzy_hash},
            {"short",     short_of(tlsh.fuzzy_hash, 16)},
            {"size_bits", 280},
        });
    } else {
        LOG_WARN("exporter: to_json(hashes): tlsh hash is empty");
    }

    if (flags_set(sha256.errors.flags) || flags_set(tlsh.errors.flags)) {
        LOG_DEBUG("exporter: to_json(hashes): sha256 errors.flags={}, tlsh errors.flags={}",
                  static_cast<std::uint32_t>(sha256.errors.flags),
                  static_cast<std::uint32_t>(tlsh.errors.flags));
    }

    return json{
        {"sha256",       sha256.hash},
        {"sha256_short", short_of(sha256.hash, 16)},
        {"sha256_words", words},
        {"sha256_algo",  sha256.algo_used},
        {"tlsh",         tlsh.fuzzy_hash},
        {"tlsh_short",   short_of(tlsh.fuzzy_hash, 16)},
        {"tlsh_algo",    tlsh.fuzzy_algo_used},
        {"algorithms",   std::move(algorithms)},
        {"errors", {
            {"sha256", {
                {"flags",    static_cast<std::uint32_t>(sha256.errors.flags)},
                {"messages", sha256.errors.messages},
                {"details",  sha256.errors.details},
            }},
            {"tlsh", {
                {"flags",    static_cast<std::uint32_t>(tlsh.errors.flags)},
                {"messages", tlsh.errors.messages},
                {"details",  tlsh.errors.details},
            }},
        }},
    };
}

// ---------------------------------------------------------------------------
// to_json(ioc)
// ---------------------------------------------------------------------------

json to_json(const ioc::ioc_results_t& r) {
    LOG_TRACE("exporter: to_json(ioc): urls={}, domains={}, ips={}, emails={}, "
              "hashes={}, family_hits={}, string_indicators={}",
              r.num_urls, r.num_domains, r.num_ips, r.num_emails,
              r.hashes.size(), r.family_hits.size(), r.string_hits.size());

    json pie_labels = json::array();
    json pie_values = json::array();
    auto add_slice = [&](const char* label, std::size_t count) {
        if (count == 0) return;
        pie_labels.push_back(label);
        pie_values.push_back(count);
    };
    add_slice("urls",    r.num_urls);
    add_slice("domains", r.num_domains);
    add_slice("ips",     r.num_ips);
    add_slice("emails",  r.num_emails);
    add_slice("md5",     r.num_md5);
    add_slice("sha1",    r.num_sha1);
    add_slice("sha256",  r.num_sha256);
    add_slice("sha512",  r.num_sha512);

    json hashes_detailed = json::array();
    for (const auto& h : r.hashes) {
        const char* type = "unknown";
        switch (h.size()) {
            case 32:  type = "md5";    break;
            case 40:  type = "sha1";   break;
            case 64:  type = "sha256"; break;
            case 128: type = "sha512"; break;
            default: break;
        }
        hashes_detailed.push_back({
            {"value",  h},
            {"type",   type},
            {"length", h.size()},
        });
    }

    json family_hits = json::array();
    for (const auto& h : r.family_hits) {
        family_hits.push_back({
            {"keyword",        std::string(h.keyword)},
            {"classification", std::string(h.classification)},
            {"in_string",      h.matched_string},
        });
    }

    // CyberChef encoded-string flags: the candidate, the recipe that
    // decoded it, what came out, and why that was flagged.
    auto clip_text = [](const std::string& s, std::size_t n) {
        return s.size() <= n ? s : s.substr(0, n) + "...";
    };
    json encoded_flags = json::array();
    for (const auto& f : r.encoded_flags) {
        encoded_flags.push_back({
            {"recipe",     f.recipe},
            {"original",   clip_text(f.original, 400)},
            {"decoded",    clip_text(f.decoded, 1500)},
            {"indicators", f.indicators},
            {"urls",       f.urls},
        });
    }
    add_slice("encoded", r.encoded_flags.size());

    // EMBER-style string indicators (thrember StringExtractor table): pattern
    // name, source group, match count and a few evidence strings per hit.
    json string_indicators = json::array();
    for (const auto& h : r.string_hits) {
        string_indicators.push_back({
            {"name",    h.name},
            {"group",   h.group},
            {"count",   h.count},
            {"samples", h.samples},
        });
    }

    if (ioc::has_errors(r.errors)) {
        LOG_WARN("exporter: to_json(ioc): extraction errors present "
                 "(flags={}, messages={})",
                 static_cast<std::uint32_t>(r.errors.flags),
                 r.errors.messages.size());
    }

    return json{
        {"summary", {
            {"urls",      r.num_urls},
            {"domains",   r.num_domains},
            {"ips",       r.num_ips},
            {"emails",    r.num_emails},
            {"md5",       r.num_md5},
            {"sha1",      r.num_sha1},
            {"sha256",    r.num_sha256},
            {"sha512",    r.num_sha512},
            {"hash_tags", r.num_hash_tags},
            {"encoded",   r.encoded_flags.size()},
            {"string_indicators", r.string_hits.size()},
        }},
        {"pie_data", {
            {"labels", pie_labels},
            {"values", pie_values},
        }},
        {"urls",        r.urls},
        {"domains",     r.domains},
        {"ips",         r.ips},
        {"dns",         r.dns_results},
        {"emails",      r.emails},
        {"hashes",      std::move(hashes_detailed)},
        {"hash_tags",   r.num_hash_tags},
        {"family_hits", std::move(family_hits)},
        {"encoded_flags", std::move(encoded_flags)},
        {"string_indicators", std::move(string_indicators)},
        {"errors", {
            {"has_errors", ioc::has_errors(r.errors)},
            {"flags",      static_cast<std::uint32_t>(r.errors.flags)},
            {"messages",   r.errors.messages},
            {"details",    r.errors.details},
        }},
    };
}

// ---------------------------------------------------------------------------
// to_json(capa::report_t)
// ---------------------------------------------------------------------------

json to_json(const capa::report_t& r) {
    LOG_TRACE("exporter: to_json(capa::report_t): status={}, capabilities={}, "
              "rules_matched={}, library_rules={}",
              capa::to_string(r.st), r.capabilities.size(),
              r.rules_matched, r.library_rules);

    json capabilities = json::array();
    for (const auto& cap : r.capabilities) {
        json attack = json::array();
        for (const auto& a : cap.attack) {
            attack.push_back({
                {"tactic",       a.tactic},
                {"technique",    a.technique},
                {"subtechnique", a.subtechnique},
                {"id",           a.id},
            });
        }
        json mbc = json::array();
        for (const auto& m : cap.mbc) {
            mbc.push_back({
                {"objective", m.objective},
                {"behavior",  m.behavior},
                {"method",    m.method},
                {"id",        m.id},
            });
        }
        json addresses = json::array();
        for (std::uint64_t addr : cap.addresses) addresses.push_back(addr);

        capabilities.push_back({
            {"name",        cap.name},
            {"namespace",   cap.namespace_path},
            {"description", cap.description},
            {"scope",       cap.scope},
            {"library",     cap.library},
            {"match_count", cap.match_count},
            {"attack",      std::move(attack)},
            {"mbc",         std::move(mbc)},
            {"addresses",   std::move(addresses)},
        });
    }

    json attack_ids = json::array();
    for (const auto& id : capa::attack_ids(r)) attack_ids.push_back(id);
    const std::vector<std::string> mbc_id_list = capa::mbc_ids(r);
    json mbc_ids = json::array();
    json mbc_details = json::object();
    {
      // Enrich the bare MBC ids with the local catalog entry (name, kind,
      // objective, description, URL, ATT&CK cross-links, detection-rule
      // count) so consumers of capa.json - the dashboard above all - can
      // render them without shipping the STIX bundle themselves. A missing
      // catalog leaves the object empty; the ids above stay authoritative.
      const std::set<std::string> wanted(mbc_id_list.begin(), mbc_id_list.end());
      const auto details = cti::mbc_details_for(wanted);
      for (const auto& id : mbc_id_list) mbc_ids.push_back(id);
      for (const auto& [id, d] : details) {
        json objectives = json::array();
        for (const auto& o : d.objectives) objectives.push_back(o);
        json attack = json::array();
        for (const auto& t : d.attack_ids) attack.push_back(t);
        mbc_details[id] = {
            {"kind",            d.kind},
            {"name",            d.name},
            {"description",     d.description},
            {"url",             d.url},
            {"parent",          d.parent},
            {"objectives",      std::move(objectives)},
            {"attack_ids",      std::move(attack)},
            {"detection_rules", d.detection_rules},
        };
      }
    }
    json warnings = json::array();
    for (const auto& w : r.warnings) warnings.push_back(w);

    if (r.st != capa::status::ok) {
        LOG_DEBUG("exporter: to_json(capa::report_t): non-ok status='{}', error='{}'",
                  capa::to_string(r.st), r.error);
    }

    return json{
        {"status",        capa::to_string(r.st)},
        {"error",         r.error},
        {"from_cache",    r.from_cache},
        {"seconds",       r.seconds},
        {"exit_code",     r.exit_code},
        {"command_line",  r.command_line},
        {"stderr_tail",   r.stderr_tail},
        {"warnings",      std::move(warnings)},
        {"capa", {
            {"version",   r.capa_version},
            {"flavor",    r.flavor},
            {"format",    r.format},
            {"arch",      r.arch},
            {"os",        r.os},
            {"backend",   r.backend},
        }},
        {"sample", {
            {"md5",    r.md5},
            {"sha1",   r.sha1},
            {"sha256", r.sha256},
        }},
        {"counts", {
            {"rules_matched",   r.rules_matched},
            {"library_rules",   r.library_rules},
            {"capabilities",    r.capabilities.size()},
            {"attack_ids",      attack_ids.size()},
            {"mbc_ids",         mbc_ids.size()},
        }},
        {"capabilities", std::move(capabilities)},
        {"attack_ids",   std::move(attack_ids)},
        {"mbc_ids",      std::move(mbc_ids)},
        {"mbc_details",  std::move(mbc_details)},
    };
}

// ---------------------------------------------------------------------------
// to_json(iat_result_t)
// ---------------------------------------------------------------------------
json to_json(const extractor::iat_result_t& r) {
    LOG_TRACE("exporter: to_json(iat_result_t): entries={}, dlls={}, "
              "named={}, ordinal={}, delay={}",
              r.entries.size(), r.dll_count, r.named_import_count,
              r.ordinal_import_count, r.delay_import_count);

    json entries = json::array();
    for (const auto& e : r.entries) {
        entries.push_back({
            {"dll",          e.dll},
            {"name",         e.name},
            {"hint",         e.hint},
            {"ordinal",      e.ordinal},
            {"is_ordinal",   e.is_ordinal},
            {"is_delay",     e.is_delay},
            {"iat_rva",      e.iat_rva},
            {"iat_value",    e.iat_value},
            {"int_rva",      e.int_rva},
            {"ilt_rva",      e.ilt_rva},
            {"iat_base",     e.iat_base},
            {"timestamp",    e.timestamp},
            {"forwarder",    e.forwarder},
        });
    }

    if (flags_set(r.errors.flags)) {
        LOG_DEBUG("exporter: to_json(iat_result_t): errors.flags={}",
                  static_cast<std::uint32_t>(r.errors.flags));
    }

    return json{
        {"summary", {
            {"dll_count",            r.dll_count},
            {"named_import_count",   r.named_import_count},
            {"ordinal_import_count", r.ordinal_import_count},
            {"delay_dll_count",      r.delay_dll_count},
            {"delay_import_count",   r.delay_import_count},
            {"total_entries",        r.entries.size()},
            {"truncated",            r.truncated},
        }},
        {"iat_range", {
            {"lowest_rva",  r.iat_lowest_rva},
            {"highest_rva", r.iat_highest_rva},
        }},
        {"entries", std::move(entries)},
        {"errors", {
            {"flags",      static_cast<std::uint32_t>(r.errors.flags)},
            {"has_errors", flags_set(r.errors.flags)},
            {"messages",   r.errors.messages},
            {"details",    r.errors.details},
        }},
    };
}

// ---------------------------------------------------------------------------
// to_json(got_result_t)
// ---------------------------------------------------------------------------

json to_json(const extractor::got_result_t& r) {
    LOG_TRACE("exporter: to_json(got_result_t): format='{}', entries={}, "
              "slots={}, named={}, plt={}, lazy={}",
              r.format, r.entries.size(), r.slot_count,
              r.named_count, r.plt_count, r.lazy_count);

    json entries = json::array();
    for (const auto& e : r.entries) {
        entries.push_back({
            {"name",              e.name},
            {"library",           e.library},
            {"binding",           e.binding},
            {"slot_address",      e.slot_address},
            {"slot_offset",       e.slot_offset},
            {"initial_value",     e.initial_value},
            {"plt_stub_address",  e.plt_stub_address},
            {"stub_address",      e.stub_address},
            {"reloc_address",     e.reloc_address},
            {"reloc_addend",      e.reloc_addend},
            {"reloc_type",        e.reloc_type},
            {"is_lazy",           e.is_lazy},
            {"is_weak",           e.is_weak},
        });
    }

    json sections = json::array();
    for (const auto& s : r.sections) sections.push_back(s);

    if (flags_set(r.errors.flags)) {
        LOG_DEBUG("exporter: to_json(got_result_t): errors.flags={}",
                  static_cast<std::uint32_t>(r.errors.flags));
    }

    return json{
        {"format",       r.format},
        {"architecture", r.architecture},
        {"counts", {
            {"slots",   r.slot_count},
            {"named",   r.named_count},
            {"plt",     r.plt_count},
            {"lazy",    r.lazy_count},
            {"entries", r.entries.size()},
        }},
        {"slot_range", {
            {"lowest",  r.got_lowest_slot},
            {"highest", r.got_highest_slot},
        }},
        {"sections",  std::move(sections)},
        {"truncated", r.truncated},
        {"entries",   std::move(entries)},
        {"errors", {
            {"flags",      static_cast<std::uint32_t>(r.errors.flags)},
            {"has_errors", flags_set(r.errors.flags)},
            {"messages",   r.errors.messages},
            {"details",    r.errors.details},
        }},
    };
}

// ---------------------------------------------------------------------------
// to_json(r2::bulk_result_t)
// ---------------------------------------------------------------------------

json to_json(const r2::bulk_result_t& r) {
    LOG_TRACE("exporter: to_json(r2::bulk_result_t): status={}, files={}, "
              "functions={}, errors={}",
              r2::to_string(r.st), r.files.size(),
              r.functions.size(), r.errors.size());

    json out;
    out["status"]  = r2::to_string(r.st);
    out["seconds"] = r.seconds;

    json files = json::array();
    files.get_ref<json::array_t&>().reserve(r.files.size());
    for (const auto& f : r.files) {
        files.push_back({
            {"path",  f.path},
            {"bytes", f.bytes},
            {"kind",  f.kind},
        });
        LOG_DEBUG("exporter: to_json(r2): file kind='{}' bytes={} path='{}'",
                  f.kind, f.bytes, f.path);
    }
    out["files"] = std::move(files);

    json funcs = json::array();
    funcs.get_ref<json::array_t&>().reserve(r.functions.size());
    for (const auto& f : r.functions) {
        funcs.push_back({
            {"name",    f.name},
            {"offset",  f.offset},
            {"size",    f.size},
            {"blocks",  f.blocks},
            {"is_pure", f.is_pure},
        });
    }
    out["functions"] = std::move(funcs);

    json nop_sections = json::array();
    for (const auto& section : r.section_nop_stats) {
        nop_sections.push_back({
            {"section",      section.section},
            {"instructions", section.instructions},
            {"nop_count",    section.nop_count},
            {"nop_percent",  section.nop_percent()},
        });
    }
    out["nop_stats"] = {
        {"total",           r.nop_total},
        {"by_section",      std::move(nop_sections)},
    };

    json errors = json::array();
    for (const auto& [kind, message] : r.errors) {
        errors.push_back({{"kind", kind}, {"message", message}});
        LOG_DEBUG("exporter: to_json(r2): error kind='{}': {}", kind, message);
    }
    out["errors"] = std::move(errors);

    out["counts"] = {
        {"files",     r.files.size()},
        {"functions", r.functions.size()},
        {"nops",      r.nop_total},
        {"errors",    r.errors.size()},
    };

    return out;
}

// ---------------------------------------------------------------------------
// to_json(r2::xref_asm_result_t)
// ---------------------------------------------------------------------------

json to_json(const r2::xref_asm_result_t& r) {
    LOG_TRACE("exporter: to_json(r2::xref_asm_result_t): status={}, "
              "slots={}, xrefs={}, functions={}",
              r2::to_string(r.st), r.slots_input,
              r.xrefs_found, r.functions_dumped);

    json errors = json::array();
    if (!r.error.empty()) errors.push_back(r.error);

    return json{
        {"status",           r2::to_string(r.st)},
        {"error",            r.error},
        {"seconds",          r.seconds},
        {"path",             r.path},
        {"bytes",            r.bytes},
        {"slots_input",      r.slots_input},
        {"slots_with_xrefs", r.slots_with_xrefs},
        {"xrefs_found",      r.xrefs_found},
        {"functions_dumped", r.functions_dumped},
        {"command_line",     r.command_line},
        {"stderr_tail",      r.stderr_tail},
        {"errors",           std::move(errors)},
    };
}

// ---------------------------------------------------------------------------
// Extraction serialization helpers
// ---------------------------------------------------------------------------

namespace {

json serialize_common_errors(const extractor::error_type_t& e) {
    if (flags_set(e.flags)) {
        LOG_DEBUG("exporter: serialize_common_errors: flags={}, messages={}",
                  static_cast<std::uint32_t>(e.flags), e.messages.size());
    }
    return json{
        {"flags",    static_cast<std::uint32_t>(e.flags)},
        {"messages", e.messages},
        {"details",  e.details},
    };
}

json serialize_strings_summary(const extractor::strings_result_t& s) {
    LOG_TRACE("exporter: serialize_strings_summary: count={}, errors.flags={}",
              s.strings.size(),
              static_cast<std::uint32_t>(s.errors.flags));
    return json{
        {"count",  s.strings.size()},
        {"errors", serialize_common_errors(s.errors)},
    };
}

json serialize_byte_histogram(const extractor::byte_histogram_t& h) {
    LOG_TRACE("exporter: serialize_byte_histogram: total={}, entropy={:.3f}",
              h.total_bytes, h.entropy);

    json bins = json::array(), counts = json::array(), frequencies = json::array();
    json ember_hist = json::array(), ember_be = json::array();
    for (std::size_t i = 0; i < 256; ++i) {
        bins.push_back(static_cast<std::uint32_t>(i));
        counts.push_back(h.counts[i]);
        frequencies.push_back(h.frequencies[i]);
        ember_hist.push_back(h.ember_histogram[i]);
        ember_be.push_back(h.ember_byteentropy[i]);
    }

    struct byte_entry { std::uint32_t byte; std::uint64_t count; double freq; };
    std::vector<byte_entry> top;
    for (std::size_t i = 0; i < 256; ++i) {
        if (h.counts[i] == 0) continue;
        top.push_back({static_cast<std::uint32_t>(i), h.counts[i], h.frequencies[i]});
    }
    std::sort(top.begin(), top.end(),
              [](const byte_entry& a, const byte_entry& b) { return a.count > b.count; });
    if (top.size() > 10) top.resize(10);

    json top_json = json::array();
    for (const auto& e : top) {
        char buf[8];
        std::snprintf(buf, sizeof(buf), "0x%02x", e.byte);
        top_json.push_back({{"byte", buf}, {"value", e.byte}, {"count", e.count}, {"percent", e.freq * 100.0}});
    }

    char most_buf[8], least_buf[8];
    std::snprintf(most_buf, sizeof(most_buf), "0x%02x", h.most_common_byte);
    std::snprintf(least_buf, sizeof(least_buf), "0x%02x", h.least_common_byte);

    return json{
        {"total_bytes",      h.total_bytes},
        {"entropy",          h.entropy},
        {"chi2",             h.chi2},
        {"mean",             h.mean},
        {"stddev",           h.stddev},
        {"nonzero_bins",     h.nonzero_bins},
        {"zero_bytes",       h.zero_bytes},
        {"most_common_byte", {{"byte", most_buf}, {"value", h.most_common_byte}, {"count", h.counts[h.most_common_byte]}}},
        {"least_common_byte", {{"byte", least_buf}, {"value", h.least_common_byte}, {"count", h.counts[h.least_common_byte]}}},
        {"histogram", {
            {"bins",        std::move(bins)},
            {"counts",      std::move(counts)},
            {"frequencies", std::move(frequencies)},
        }},
        // EMBER2024 thrember ML vectors: ByteHistogram (dim 256) and
        // ByteEntropyHistogram (dim 256, window=2048, step=1024). Drop-in
        // for thrember.process_raw_features output.
        {"ember_histogram",   std::move(ember_hist)},
        {"ember_byteentropy", std::move(ember_be)},
        {"top_10", std::move(top_json)},
        {"errors", serialize_common_errors(h.errors)},
    };
}

json serialize_packing(const extractor::packer_detection_t& p) {
    LOG_TRACE("exporter: serialize_packing: packed={}, reasons={}",
              p.packed, p.reasons.size());

    json reasons = json::array();
    for (const auto& reason : p.reasons) {
        std::string category = "other";
        if (reason.find("RWX") != std::string::npos)               category = "rwx";
        else if (reason.find("packer name") != std::string::npos)  category = "packer_name";
        else if (reason.find("high entropy") != std::string::npos) category = "high_entropy";
        else if (reason.find("imports") != std::string::npos)      category = "empty_imports";
        reasons.push_back({{"category", category}, {"text", reason}});
    }
    return json{
        {"packed",       p.packed},
        {"reason_count", reasons.size()},
        {"reasons",      std::move(reasons)},
        {"errors",       serialize_common_errors(p.errors)},
    };
}

json serialize_opcodes(const extractor::opcode_stats_t& o) {
    LOG_TRACE("exporter: serialize_opcodes: architecture='{}', total={}",
              o.architecture, o.total_instructions);

    json bins = json::array(), counts = json::array(), frequencies = json::array();
    for (std::size_t i = 0; i < 256; ++i) {
        bins.push_back(static_cast<std::uint32_t>(i));
        counts.push_back(o.counts[i]);
        frequencies.push_back(o.frequencies[i]);
    }

    struct op_entry { std::uint32_t opcode; std::uint32_t count; double freq; };
    std::vector<op_entry> top;
    for (std::size_t i = 0; i < 256; ++i) {
        if (o.counts[i] == 0) continue;
        top.push_back({static_cast<std::uint32_t>(i), o.counts[i], o.frequencies[i]});
    }
    std::sort(top.begin(), top.end(),
              [](const op_entry& a, const op_entry& b) { return a.count > b.count; });
    if (top.size() > 10) top.resize(10);

    json top_json = json::array();
    for (const auto& e : top) {
        char buf[8];
        std::snprintf(buf, sizeof(buf), "0x%02x", e.opcode);
        top_json.push_back({{"opcode", buf}, {"count", e.count}, {"percent", e.freq * 100.0}});
    }

    return json{
        {"architecture", o.architecture},
        {"total",        o.total_instructions},
        {"histogram", {
            {"bins",        std::move(bins)},
            {"counts",      std::move(counts)},
            {"frequencies", std::move(frequencies)},
        }},
        {"top_10", std::move(top_json)},
        {"errors", serialize_common_errors(o.errors)},
    };
}

json serialize_signature(const extractor::signature_info_t& s) {
    LOG_TRACE("exporter: serialize_signature: is_signed={}, has_signature={}, "
              "is_valid={}, num_signatures={}",
              s.is_signed, s.has_signature, s.is_valid, s.num_signatures);

    std::string indicator = "unsigned";
    if (s.is_signed)          indicator = "signed";
    else if (s.has_signature) indicator = "present_unknown";
    return json{
        {"indicator",      indicator},
        {"is_signed",      s.is_signed},
        {"has_signature",  s.has_signature},
        {"is_valid",       s.is_valid},
        {"num_signatures", s.num_signatures},
        {"format",         s.format},
        {"signer",         s.signer},
        {"issuer",         s.issuer},
        {"digest",         s.digest_algorithm},
        {"details",        s.details},
        {"errors",         serialize_common_errors(s.errors)},
    };
}

json serialize_debug(const extractor::debug_symbols_t& d) {
    LOG_TRACE("exporter: serialize_debug: format='{}', has_symbols={}, "
              "stripped={}, symbol_count={}",
              d.format, d.has_debug_symbols, d.stripped, d.symbols.size());

    return json{
        {"format",         d.format},
        {"has_symbols",    d.has_debug_symbols},
        {"has_sections",   d.has_debug_sections},
        {"stripped",       d.stripped},
        {"pdb_filename",   d.pdb_filename},
        {"pdb_guid",       d.pdb_guid},
        {"pdb_age",        d.pdb_age},
        {"pdb_timestamp",  d.pdb_timestamp},
        {"debug_sections", d.debug_sections},
        {"symbol_count",   d.symbols.size()},
        {"errors",         serialize_common_errors(d.errors)},
    };
}

json serialize_guards(const extractor::guard_info_t& g) {
    LOG_TRACE("exporter: serialize_guards: format='{}', mitigations={}/{}",
              g.format, g.mitigations_enabled, g.mitigations_checked);

    if (g.format == "PE") {
        return json{
            {"format",          "PE"},
            {"raw",             g.dll_characteristics_raw},
            {"aslr",            g.has_aslr},
            {"dep",             g.has_dep},
            {"nx",              g.has_nx},
            {"high_entropy_va", g.has_high_entropy_va},
            {"force_integrity", g.has_force_integrity},
            {"seh",             g.has_seh},
            {"isolation",       g.has_isolation},
            {"no_bind",         g.has_no_bind},
            {"wdm_driver",      g.has_wdm_driver},
            {"guard_cf",        g.has_guard_cf},
            {"cet_compat",      g.has_cet_compat},
            {"cet_strict",      g.cet_strict_mode},
            {"cet_relaxed_ip",  g.cet_set_context_ip_validation_relaxed},
            {"cet_dyn_apis",    g.cet_dynamic_apis_allow_in_proc},
            {"notes",           g.notes},
            {"errors",          serialize_common_errors(g.errors)},
        };
    }
    if (g.format == "ELF") {
        return json{
            {"format", "ELF"},
            {"raw",    g.x86_features_raw},
            {"shstk",  g.has_shstk},
            {"ibt",    g.has_ibt},
            {"notes",  g.notes},
            {"errors", serialize_common_errors(g.errors)},
        };
    }
    LOG_DEBUG("exporter: serialize_guards: unknown format '{}'", g.format);
    return json{
        {"format", g.format.empty() ? "Unknown" : g.format},
        {"notes",  g.notes},
        {"errors", serialize_common_errors(g.errors)},
    };
}

}  // namespace

// ---------------------------------------------------------------------------
// to_json(hexdump_result_t)
// ---------------------------------------------------------------------------

// The bytes go out as a real JSON array of numbers rather than as formatted
// text. That is what the dashboard's hexdump view consumes, and it means the
// browser does not have to parse an offset/hex/ASCII table back into the
// numbers it started from.
json to_json(const extractor::hexdump_result_t& r) {
    LOG_TRACE("exporter: to_json(hexdump_result_t): attempted={}, available={}, bytes={}",
              r.attempted, r.available, r.bytes.size());
    return json{
        {"attempted",     r.attempted},
        {"available",     r.available},
        {"base",          r.base},
        {"total_bytes",   r.total_bytes},
        {"bytes",         r.bytes},
        {"bytes_per_row", r.bytes_per_row},
        {"truncated",     r.truncated},
        {"seconds",       r.seconds},
        {"errors",        serialize_common_errors(r.errors)},
    };
}

// ---------------------------------------------------------------------------
// to_json(cminer_result_t)
// ---------------------------------------------------------------------------

json to_json(const extractor::cminer_result_t& r) {
    LOG_TRACE("exporter: to_json(cminer_result_t): applicable={}, available={}, caves={}",
              r.applicable, r.available, r.caves.size());
    json caves = json::array();
    for (const extractor::cminer_cave_t& cave : r.caves) {
        caves.push_back({
            {"section",       cave.section},
            {"size",          cave.size},
            {"start_address", cave.start_address},
            {"end_address",   cave.end_address},
            {"file_offset",   cave.file_offset},
        });
    }
    return json{
        {"attempted",          r.attempted},
        {"available",          r.available},
        {"applicable",         r.applicable},
        {"exit_code",          r.exit_code},
        {"seconds",            r.seconds},
        {"minimum_cave_size",  r.minimum_cave_size},
        {"cave_count",         r.caves.size()},
        {"total_cave_bytes",   r.total_cave_bytes},
        {"largest_cave_bytes", r.largest_cave_bytes},
        {"command",            r.command},
        {"caves",              std::move(caves)},
        {"stderr_tail",        r.stderr_tail},
        {"errors",             serialize_common_errors(r.errors)},
    };
}

// ---------------------------------------------------------------------------
// to_json(yara_scanner::result_t)
// ---------------------------------------------------------------------------

json to_json(const yara_scanner::result_t& r) {
    json matches = json::array();
    for (const yara_scanner::rule_match_t& rule : r.matches) {
        json strings = json::array();
        for (const yara_scanner::string_match_t& string : rule.strings) {
            strings.push_back({
                {"identifier", string.identifier},
                {"offsets", string.offsets},
            });
        }
        matches.push_back({
            {"identifier", rule.identifier},
            {"tags", rule.tags},
            {"namespace", rule.ns},
            {"rule_set", rule.rule_set},
            {"quality", rule.quality},
            {"weight", rule.weight},
            {"strings", std::move(strings)},
        });
    }
    return json{
        {"attempted", r.attempted},
        {"applicable", r.applicable},
        {"available", r.available},
        {"scan_ok", r.scan_ok},
        {"exit_code", r.exit_code},
        {"seconds", r.seconds},
        {"rule_files_found", r.rule_files_found},
        {"rule_files_loaded", r.rule_files_loaded},
        {"rule_files_failed", r.rule_files_failed},
        {"rule_files_skipped", r.rule_files_skipped},
        {"rules_directory", r.rules_directory},
        {"rules_matched", r.rules_matched},
        {"rules_deduped", r.rules_deduped},
        {"compile_errors", r.compile_errors},
        {"memory_cache_hit", r.memory_cache_hit},
        {"disk_cache_hit", r.disk_cache_hit},
        {"compile_seconds", r.compile_seconds},
        {"errors_log", r.errors_log},
        {"worker_threads", r.worker_threads},
        {"matches", std::move(matches)},
        {"errors", r.errors},
    };
}

// ---------------------------------------------------------------------------
// to_json(extraction_result_t)
// ---------------------------------------------------------------------------

json to_json(const extractor::extraction_result_t& r) {
    // elf_impl() fills elf.got while the dedicated GOT stage fills the
    // top-level got with the SAME entries (extractor.cpp) — so never add
    // both. Prefer the stage output, fall back to the legacy embedded copy.
    const std::size_t num_got = !r.got.entries.empty()
        ? r.got.entries.size() : r.elf.got.entries.size();
    LOG_TRACE("exporter: to_json(extraction_result_t): sections={}, strings={}, "
              "instructions={}, packed={}, signed={}, iat={}, got={}",
              r.sections.sections.size(), r.strings.strings.size(),
              r.opcodes.total_instructions, r.packer.packed, r.signature.is_signed,
              r.pe.iat.entries.size(),
              num_got);

    const bool is_pe  = !r.pe.machine.empty();
    const bool is_elf = !r.elf.machine.empty();

    std::string format = "Unknown";
    if (is_pe)       format = "PE";
    else if (is_elf) format = "ELF";

    LOG_DEBUG("exporter: to_json(extraction_result_t): format={}, is_pe={}, is_elf={}",
              format, is_pe, is_elf);

    const std::string& machine = is_pe ? r.pe.machine : r.elf.machine;
    const std::uint64_t entry  = is_pe ? r.pe.entrypoint : r.elf.entrypoint;

    char ep_hex[32];
    std::snprintf(ep_hex, sizeof(ep_hex), "0x%llx",
                  static_cast<unsigned long long>(entry));

    json summary = {
        {"format",             format},
        {"machine",            machine},
        {"entrypoint",         ep_hex},
        {"num_sections",       r.sections.sections.size()},
        {"num_strings",        r.strings.strings.size()},
        {"total_instructions", r.opcodes.total_instructions},
        {"is_packed",          r.packer.packed},
        {"is_signed",          r.signature.is_signed},
        {"has_debug",          r.debug_symbols.has_debug_symbols},
        {"stripped",           r.debug_symbols.stripped},
        {"num_iat_entries",    r.pe.iat.entries.size()},
        {"num_got_entries",    num_got},
    };

    json section_labels  = json::array();
    json section_entropy = json::array();
    json section_size    = json::array();
    json section_chi2    = json::array();
    json section_details = json::array();
    json section_flags   = json::array();

    const auto& sec_list = r.sections.sections;
    for (const auto& s : sec_list) {
        section_labels.push_back(s.name);
        section_entropy.push_back(s.entropy);
        section_size.push_back(s.size);
        section_chi2.push_back(s.chi2);
        section_details.push_back({
            {"name",            s.name},
            {"virtual_address", s.virtual_address},
            {"size",            s.size},
            {"entropy",         s.entropy},
            {"chi2",            s.chi2},
            {"sha256",          s.sha256.hash},
            {"tlsh",            s.tlsh.fuzzy_hash},
        });
    }

    for (const auto& s : r.pe.sections) {
        section_flags.push_back({
            {"name",            s.name},
            {"characteristics", s.characteristics},
            {"virtual_size",    s.virtual_size},
            {"raw_size",        s.raw_size},
            {"raw_offset",      s.raw_offset},
            {"raw_end",         s.raw_end},
        });
    }

    json sections_json = {
        {"count",  sec_list.size()},
        {"labels", section_labels},
        {"entropy", {{"labels", section_labels}, {"values", section_entropy}}},
        {"size",    {{"labels", section_labels}, {"values", section_size}}},
        {"chi2",    {{"labels", section_labels}, {"values", section_chi2}}},
        {"details",  std::move(section_details)},
        {"pe_flags", std::move(section_flags)},
        {"errors",   serialize_common_errors(r.sections.errors)},
    };

    json pipeline_errors = json::array();
    for (const auto& stage : extractor::recover_errors(r)) {
        LOG_DEBUG("exporter: pipeline error in stage '{}': {} message(s)",
                  stage.stage, stage.messages.size());
        pipeline_errors.push_back({
            {"stage",    stage.stage},
            {"messages", stage.messages},
        });
    }

    const std::uint32_t all_flags = static_cast<std::uint32_t>(r.errors.flags);
    const std::uint32_t hard_flags = all_flags & ~kSoftExtractorErrors;
    const std::uint32_t soft_flags = all_flags &  kSoftExtractorErrors;

    if (hard_flags != 0) {
        LOG_WARN("exporter: to_json(extraction_result_t): hard errors "
                 "(flags={}, soft={}, count={})",
                 hard_flags, soft_flags, r.errors.messages.size());
    } else if (soft_flags != 0) {
        LOG_DEBUG("exporter: to_json(extraction_result_t): soft errors only "
                  "(flags={}, count={})",
                  soft_flags, r.errors.messages.size());
    }

    return json{
        {"summary",         std::move(summary)},
        {"guards",          serialize_guards(r.guards)},
        {"sections",        std::move(sections_json)},
        {"byte_histogram",  serialize_byte_histogram(r.histogram)},
        {"opcodes",         serialize_opcodes(r.opcodes)},
        {"packing",         serialize_packing(r.packer)},
        {"signature",       serialize_signature(r.signature)},
        {"debug",           serialize_debug(r.debug_symbols)},
        {"strings_summary", serialize_strings_summary(r.strings)},
        {"iat",             to_json(r.pe.iat)},
        {"hexdump",         to_json(r.hexdump)},
        {"cminer",          to_json(r.cminer)},
        {"yara",             to_json(r.yara)},
        {"got",             to_json(r.elf.got.entries.empty() ? r.got : r.elf.got)},
        {"pipeline_errors", std::move(pipeline_errors)},
        {"raw", {
            {"sha256", r.sha256.hash},
            {"tlsh",   r.tlsh.fuzzy_hash},
            {"elf", {
                {"machine",    r.elf.machine},
                {"file_type",  r.elf.file_type},
                {"entrypoint", r.elf.entrypoint},
            }},
            {"pe", {
                {"machine",         r.pe.machine},
                {"characteristics", r.pe.characteristics},
                {"entrypoint",      r.pe.entrypoint},
                {"overlay_size",    r.pe.overlay_size},
                {"file_size",       r.pe.file_size},
                {"last_section_end", r.pe.last_section_end},
                {"computed_overlay_start", r.pe.computed_overlay_start},
                {"computed_overlay_end", r.pe.computed_overlay_end},
                {"computed_overlay_size", r.pe.computed_overlay_size},
                {"has_computed_overlay", r.pe.has_computed_overlay},
                {"overlay_size_matches", r.pe.overlay_size_matches},
                {"security_directory", {
                    {"present", r.pe.security_directory.present},
                    {"file_offset", r.pe.security_directory.file_offset},
                    {"size", r.pe.security_directory.size},
                    {"end_offset", r.pe.security_directory.end_offset},
                    {"within_file", r.pe.security_directory.within_file},
                    {"overlaps_section", r.pe.security_directory.overlaps_section},
                    {"inside_section_overlay", r.pe.security_directory.inside_section_overlay},
                    {"valid_range", r.pe.security_directory.valid_range},
                    {"certificate_count", r.pe.security_directory.certificate_count},
                    {"warnings", r.pe.security_directory.warnings},
                }},
                {"overlay_after_security_start", r.pe.overlay_after_security_start},
                {"overlay_after_security_end", r.pe.overlay_after_security_end},
                {"overlay_after_security_size", r.pe.overlay_after_security_size},
                {"has_overlay_after_security", r.pe.has_overlay_after_security},
                {"overlay", {
                    {"present",          r.pe.overlay.present},
                    {"offset",           r.pe.overlay.offset},
                    {"size",             r.pe.overlay.size},
                    {"truncated",        r.pe.overlay.truncated},
                    {"retained_bytes",   r.pe.overlay.data.size()},
                    {"magic_hex",        r.pe.overlay.magic_hex},
                    {"magic_ascii",      r.pe.overlay.magic_ascii},
                    {"sha256",           r.pe.overlay.sha256},
                    {"entropy",          r.pe.overlay.entropy},
                    {"chi2",             r.pe.overlay.chi2},
                    {"format_count",     r.pe.overlay.signatures.size()},
                    {"formats", [&] {
                        json formats = json::array();
                        for (const auto& sig : r.pe.overlay.signatures) {
                            formats.push_back({
                                {"format",           sig.format},
                                {"description",      sig.description},
                                {"offset",           sig.offset},
                                {"relative_offset",  sig.relative_offset},
                                {"size",             sig.size},
                                {"confidence",       sig.confidence},
                            });
                        }
                        return formats;
                    }()},
                }},
                {"export_table", {
                    {"present", r.pe.export_table.present},
                    {"name", r.pe.export_table.name},
                    {"timestamp", r.pe.export_table.timestamp},
                    {"major_version", r.pe.export_table.major_version},
                    {"minor_version", r.pe.export_table.minor_version},
                    {"ordinal_base", r.pe.export_table.ordinal_base},
                    {"address_table_rva", r.pe.export_table.export_addr_table_rva},
                    {"address_table_count", r.pe.export_table.export_addr_table_count},
                    {"name_table_rva", r.pe.export_table.names_addr_table_rva},
                    {"name_table_count", r.pe.export_table.names_addr_table_count},
                    {"ordinal_table_rva", r.pe.export_table.ordinal_addr_table_rva},
                    {"named_count", r.pe.export_table.named_count},
                    {"forwarded_count", r.pe.export_table.forwarded_count},
                    {"external_count", r.pe.export_table.external_count},
                    {"entries", [&] {
                        json entries = json::array();
                        for (const auto& entry : r.pe.export_table.entries) {
                            entries.push_back({
                                {"name", entry.name},
                                {"ordinal", entry.ordinal},
                                {"rva", entry.rva},
                                {"address", entry.address},
                                {"function_rva", entry.function_rva},
                                {"is_extern", entry.is_extern},
                                {"is_forwarded", entry.is_forwarded},
                                {"forwarder_library", entry.forwarder_library},
                                {"forwarder_function", entry.forwarder_function},
                            });
                        }
                        return entries;
                    }()},
                }},
        }},
        }},
        {"errors", serialize_common_errors(r.errors)},
    };
}

// ---------------------------------------------------------------------------
// File writing
// ---------------------------------------------------------------------------

namespace {

fs::path write_json_file(const fs::path& target_dir,
                         const std::string& stem,
                         const json& payload) {
    LOG_TRACE("exporter: write_json_file: dir='{}', stem='{}'",
              target_dir.string(), stem);

    std::error_code ec;
    fs::create_directories(target_dir, ec);
    if (ec) {
        LOG_ERROR("export: cannot create directory '{}' (error: {})",
                  target_dir.string(), ec.message());
        return {};
    }

    const fs::path file = target_dir / (stem + ".json");

    std::ofstream out(file, std::ios::binary | std::ios::trunc);
    if (!out) {
        LOG_ERROR("export: cannot open '{}' for writing", file.string());
        return {};
    }

    scoped_timer timer("write_json_file(" + stem + ")", __FILE__, __LINE__);

    std::string serialized;
    try {
        serialized = payload.dump(2, ' ', false, json::error_handler_t::replace);
    } catch (const std::exception& e) {
        LOG_ERROR("export: JSON dump failed for '{}': {}", file.string(), e.what());
        return {};
    }

    out << serialized;
    if (!out) {
        LOG_ERROR("export: failed while writing '{}'", file.string());
        return {};
    }
    out.close();
    if (out.fail()) {
        LOG_ERROR("export: error closing '{}'", file.string());
        return {};
    }

    LOG_INFO("export: wrote '{}' ({} bytes)", file.string(), serialized.size());
    return file;
}

// Non-JSON writers: same atomic-write shape, plain text payload.
fs::path write_text_file(const fs::path& target_dir,
                         const std::string& stem,
                         const std::string& extension,
                         const std::string& text) {
    LOG_TRACE("exporter: write_text_file: dir='{}', stem='{}', ext='{}', bytes={}",
              target_dir.string(), stem, extension, text.size());

    std::error_code ec;
    fs::create_directories(target_dir, ec);
    if (ec) {
        LOG_ERROR("export: cannot create directory '{}' (error: {})",
                  target_dir.string(), ec.message());
        return {};
    }

    const fs::path file = target_dir / (stem + extension);

    std::ofstream out(file, std::ios::binary | std::ios::trunc);
    if (!out) {
        LOG_ERROR("export: cannot open '{}' for writing", file.string());
        return {};
    }

    scoped_timer timer("write_text_file(" + stem + extension + ")", __FILE__, __LINE__);

    out.write(text.data(), static_cast<std::streamsize>(text.size()));
    if (!out) {
        LOG_ERROR("export: failed while writing '{}'", file.string());
        return {};
    }
    out.close();
    if (out.fail()) {
        LOG_ERROR("export: error closing '{}'", file.string());
        return {};
    }

    LOG_INFO("export: wrote '{}' ({} bytes)", file.string(), text.size());
    return file;
}

// Raw binary writer: used for extracted overlay payloads. Same shape as
// write_text_file() but takes an explicit byte buffer.
fs::path write_binary_file(const fs::path& target_dir,
                          const std::string& stem,
                          const std::string& extension,
                          const std::vector<std::uint8_t>& data) {
    std::error_code ec;
    fs::create_directories(target_dir, ec);
    if (ec) {
        LOG_ERROR("export: cannot create directory '{}' (error: {})",
                  target_dir.string(), ec.message());
        return {};
    }

    const fs::path file = target_dir / (stem + extension);

    std::ofstream out(file, std::ios::binary | std::ios::trunc);
    if (!out) {
        LOG_ERROR("export: cannot open '{}' for writing", file.string());
        return {};
    }

    if (!data.empty()) {
        out.write(reinterpret_cast<const char*>(data.data()),
                  static_cast<std::streamsize>(data.size()));
    }
    if (!out) {
        LOG_ERROR("export: failed while writing '{}'", file.string());
        return {};
    }
    out.close();
    if (out.fail()) {
        LOG_ERROR("export: error closing '{}'", file.string());
        return {};
    }

    LOG_INFO("export: wrote '{}' ({} bytes)", file.string(), data.size());
    return file;
}

}  // namespace

// ---------------------------------------------------------------------------
// Public writers
// ---------------------------------------------------------------------------

std::filesystem::path write_fileinfo_json(const std::string& stem,
                                          const analyzer::file_info_t& info) {
    LOG_DEBUG("exporter: write_fileinfo_json: stem='{}', filepath='{}'",
              stem, info.filepath);
    EXPORTER_TRY("write_fileinfo_json", {
        const auto path = write_json_file(dir::run(stem, "fileinfo"),
                                          artifact_stem(stem, "fileinfo"),
                                          to_json(info));
        print_export_line("fileinfo", path, !path.empty());
        return path;
    })
}

std::filesystem::path write_hash_json(const std::string& stem,
                                       const file_hash_t& sha256,
                                       const fuzzy_hash_t& tlsh) {
    LOG_DEBUG("exporter: write_hash_json: stem='{}', sha256_len={}, tlsh_len={}",
              stem, sha256.hash.size(), tlsh.fuzzy_hash.size());
    EXPORTER_TRY("write_hash_json", {
        const auto path = write_json_file(dir::run(stem, "hash"),
                                          artifact_stem(stem, "hash"),
                                          to_json(sha256, tlsh));
        print_export_line("hash", path, !path.empty());
        return path;
    })
}

std::filesystem::path write_ioc_json(const std::string& stem,
                                     const ioc::ioc_results_t& r) {
    LOG_DEBUG("exporter: write_ioc_json: stem='{}', urls={}, domains={}, ips={}",
              stem, r.num_urls, r.num_domains, r.num_ips);
    EXPORTER_TRY("write_ioc_json", {
        const auto path = write_json_file(dir::run(stem, "ioc"),
                                          artifact_stem(stem, "ioc"),
                                          to_json(r));
        print_export_line("ioc", path, !path.empty());
        return path;
    })
}

std::filesystem::path write_strings_json(const std::string& stem,
                                         const extractor::strings_result_t& r) {
    LOG_DEBUG("exporter: write_strings_json: stem='{}', strings={}, truncated={}",
              stem, r.strings.size(), r.truncated);
    EXPORTER_TRY("write_strings_json", {
        json out;
        out["count"]       = r.strings.size();
        out["ascii_count"] = r.ascii_count;
        out["utf16_count"] = r.utf16_count;
        out["truncated"]   = r.truncated;
        json arr = json::array();
        for (const auto& entry : r.strings) {
            arr.push_back({{"offset",  entry.offset},
                           {"value",   entry.value},
                           {"section", entry.section},
                           {"encoding", entry.encoding}});
        }
        out["strings"] = std::move(arr);
        const auto path = write_json_file(dir::run(stem, "strings"),
                                          artifact_stem(stem, "strings"),
                                          out);
        print_export_line("strings", path, !path.empty());
        return path;
    })
}

std::filesystem::path write_malapi_json(const std::string& stem,
                                        const json& hits) {
    const auto n = hits.is_array() ? hits.size() : 0;
    LOG_DEBUG("exporter: write_malapi_json: stem='{}', hits={}", stem, n);
    EXPORTER_TRY("write_malapi_json", {
        const auto path = write_json_file(dir::run(stem, "malapi"),
                                          artifact_stem(stem, "malapi"),
                                          hits);
        print_export_line("malapi", path, !path.empty());
        return path;
    })
}

std::filesystem::path write_extraction_json(const std::string& stem,
                                             const extractor::extraction_result_t& r) {
    LOG_DEBUG("exporter: write_extraction_json: stem='{}', sections={}, strings={}",
              stem, r.sections.sections.size(), r.strings.strings.size());
    EXPORTER_TRY("write_extraction_json", {
        const auto path = write_json_file(dir::run(stem, "extraction"),
                                          artifact_stem(stem, "extraction"),
                                          to_json(r));
        print_export_line("extraction", path, !path.empty());
        return path;
    })
}

std::filesystem::path write_capa_json(const std::string& stem,
                                      const capa::report_t& r) {
    LOG_DEBUG("exporter: write_capa_json: stem='{}', status={}, capabilities={}",
              stem, capa::to_string(r.st), r.capabilities.size());
    EXPORTER_TRY("write_capa_json", {
        const auto path = write_json_file(dir::run(stem, "capa"),
                                          artifact_stem(stem, "capa"),
                                          to_json(r));
        print_export_line("capa", path, !path.empty());
        return path;
    })
}

std::filesystem::path write_iat_json(const std::string& stem,
                                     const extractor::iat_result_t& r) {
    LOG_DEBUG("exporter: write_iat_json: stem='{}', entries={}, dlls={}",
              stem, r.entries.size(), r.dll_count);
    EXPORTER_TRY("write_iat_json", {
        const auto path = write_json_file(dir::run(stem, "iat"),
                                          artifact_stem(stem, "iat"),
                                          to_json(r));
        print_export_line("iat", path, !path.empty());
        return path;
    })
}

// ---------------------------------------------------------------------------
// to_json(pe_export_table_t) — EAT
// ---------------------------------------------------------------------------
// Dedicated Export Address Table export
// (`exports/<stem>_analysis/eat/<stem>_eat.json`).
// Previously the EAT only lived inside the big extraction JSON
// (`raw.pe.export_table`), so a consumer that wanted exports had to parse the
// whole extraction blob. Same shape as the extraction-side serialization so
// the two stay in step, plus an entry_count and a flat `exports` name list
// for grepping.
json to_json(const extractor::pe_export_table_t& r) {
    LOG_TRACE("exporter: to_json(pe_export_table_t): present={}, entries={}",
              r.present, r.entries.size());
    json entries = json::array();
    json names = json::array();
    for (const auto& e : r.entries) {
        const bool forwarded = !e.forwarder_library.empty();
        const std::string kind =
            forwarded ? "forwarded" : (e.is_extern ? "external" : "normal");
        entries.push_back({
            {"name", e.name},
            {"rva", e.rva},
            {"ordinal", e.ordinal},
            {"forwarded", forwarded},
            {"forwarder_library", e.forwarder_library},
            {"forwarder_function", e.forwarder_function},
            {"extern", e.is_extern},
            {"kind", kind},
        });
        if (!e.name.empty()) names.push_back(e.name);
    }
    return json{
        {"present", r.present},
        {"name", r.name},
        {"timestamp", r.timestamp},
        {"major_version", r.major_version},
        {"minor_version", r.minor_version},
        {"ordinal_base", r.ordinal_base},
        {"address_table_rva", r.export_addr_table_rva},
        {"address_table_count", r.export_addr_table_count},
        {"name_table_rva", r.names_addr_table_rva},
        {"name_table_count", r.names_addr_table_count},
        {"ordinal_table_rva", r.ordinal_addr_table_rva},
        {"named_count", r.named_count},
        {"forwarded_count", r.forwarded_count},
        {"external_count", r.external_count},
        {"entry_count", r.entries.size()},
        {"entries", std::move(entries)},
        {"exports", std::move(names)},
        // pe_export_table_t carries no errors field: EAT parse failures are
        // absorbed into the enclosing pe_sections_t.errors, so report an
        // empty error object here to keep the schema stable.
        {"errors", serialize_common_errors(extractor::error_type_t{})},
    };
}

// ---------------------------------------------------------------------------
// write_eat_json
// ---------------------------------------------------------------------------
// Writes the PE Export Address Table to exports/<stem>_analysis/eat/<stem>_eat.json.
//
// Note the raw/pe naming: the IAT file is named `<stem>_iat.json`, so the EAT
// file is `<stem>_eat.json` (not `_export_table.json`).
std::filesystem::path write_eat_json(const std::string& stem,
                                     const extractor::pe_export_table_t& r) {
    LOG_DEBUG("exporter: write_eat_json: stem='{}', present={}, entries={}",
              stem, r.present, r.entries.size());
    EXPORTER_TRY("write_eat_json", {
        const auto path = write_json_file(dir::run(stem, "eat"),
                                          artifact_stem(stem, "eat"),
                                          to_json(r));
        print_export_line("eat", path, !path.empty());
        return path;
    });
    return {};
}


std::filesystem::path write_got_json(const std::string& stem,
                                     const extractor::got_result_t& r) {
    LOG_DEBUG("exporter: write_got_json: stem='{}', format='{}', entries={}",
              stem, r.format, r.entries.size());
    EXPORTER_TRY("write_got_json", {
        const auto path = write_json_file(dir::run(stem, "got"),
                                          artifact_stem(stem, "got"),
                                          to_json(r));
        print_export_line("got", path, !path.empty());
        return path;
    })
}

std::filesystem::path write_radare2_json(const std::string& stem,
                                         const r2::bulk_result_t& r) {
    LOG_DEBUG("exporter: write_radare2_json: stem='{}', status={}, files={}, functions={}",
              stem, r2::to_string(r.st), r.files.size(), r.functions.size());
    EXPORTER_TRY("write_radare2_json", {
        const auto path = write_json_file(dir::run(stem, "radare2"),
                                          artifact_stem(stem, "radare2"),
                                          to_json(r));
        print_export_line("radare2", path, !path.empty());
        return path;
    })
}

std::filesystem::path write_xref_asm_json(const std::string& stem,
                                          const r2::xref_asm_result_t& r) {
    LOG_DEBUG("exporter: write_xref_asm_json: stem='{}', status={}, "
              "slots={}, xrefs={}, functions={}",
              stem, r2::to_string(r.st), r.slots_input,
              r.xrefs_found, r.functions_dumped);
    EXPORTER_TRY("write_xref_asm_json", {
        const auto path = write_json_file(dir::run(stem, "radare2"),
                                          artifact_stem(stem, "iat_calls"),
                                          to_json(r));
        print_export_line("iat_calls", path, !path.empty());
        return path;
    })
}

std::filesystem::path write_asm_text(const std::string& stem,
                                     const std::string& text) {
    LOG_DEBUG("exporter: write_asm_text: stem='{}', bytes={}", stem, text.size());
    EXPORTER_TRY("write_asm_text", {
        const auto path = write_text_file(fs::path(dir::run(stem, "radare2")),
                                          artifact_stem(stem, "functions"),
                                          ".asm", text);
        print_export_line("asm", path, !path.empty());
        return path;
    })
}

std::filesystem::path write_overlay_bin(const std::string& stem,
                                        const extractor::pe_overlay_t& overlay) {
    // No overlay means no artifact at all: this keeps the export list stable
    // for the common (unsigned, unpacked) case.
    if (!overlay.present || overlay.data.empty()) {
        LOG_DEBUG("exporter: write_overlay_bin: stem='{}', no overlay present",
                  stem);
        return {};
    }
    LOG_DEBUG("exporter: write_overlay_bin: stem='{}', offset={}, size={}, "
              "retained={}, formats={}",
              stem, overlay.offset, overlay.size, overlay.data.size(),
              overlay.signatures.size());
    EXPORTER_TRY("write_overlay_bin", {
        const auto path = write_binary_file(fs::path(dir::run(stem, "extraction")),
                                            artifact_stem(stem, "overlay"),
                                            ".bin", overlay.data);
        print_export_line("overlay", path, !path.empty());
        return path;
    })
}

// ---------------------------------------------------------------------------
// write_all
// ---------------------------------------------------------------------------

namespace {

write_result_t write_all_impl(const std::string& stem,
                              const analyzer::file_info_t& info,
                              const file_hash_t& sha256,
                              const fuzzy_hash_t& tlsh,
                              const ioc::ioc_results_t& iocs,
                              const extractor::extraction_result_t& extraction,
                              const capa::report_t* capa_report,
                              const extractor::iat_result_t* iat,
                              const extractor::got_result_t* got,
                              const r2::bulk_result_t* radare2,
                              const r2::xref_asm_result_t* xref_asm,
                              const std::string* asm_text) {
    // The overlay dump is conditional on the PE carrying overlay bytes, but that
    // is already known from `extraction` before a single byte is written, so it
    // can be part of the up-front plan rather than a surprise extra.
    const bool overlay_expected =
        extraction.pe.overlay.present && !extraction.pe.overlay.data.empty();

    const std::size_t expected =
        4 + (capa_report ? 1 : 0) + (iat ? 1 : 0) + (got ? 1 : 0)
          + (radare2 ? 1 : 0) + (xref_asm ? 1 : 0) + (asm_text ? 1 : 0)
          + (overlay_expected ? 1 : 0);

    // Hand the true total back to the caller so it never has to re-derive it.
    write_result_t out;
    out.expected = expected;

    LOG_INFO("exporter: write_all: starting export for stem='{}' "
             "(filepath='{}', capa={}, iat={}, got={}, radare2={}, iat_calls={}, asm_text={})",
             stem, info.filepath,
             capa_report != nullptr, iat != nullptr,
             got != nullptr, radare2 != nullptr, xref_asm != nullptr,
             asm_text != nullptr);

    std::cout << "\n" << console::paint(console::cyan,
        "== exporter: writing " + std::to_string(expected) +
        " artifacts for '" + stem + "' ==") << "\n";

    scoped_timer timer("write_all(" + stem + ")", __FILE__, __LINE__);

    LOG_DEBUG("exporter: write_all: [1/{}] fileinfo", expected);
    out.fileinfo = write_fileinfo_json(stem, info);

    LOG_DEBUG("exporter: write_all: [2/{}] hash", expected);
    out.hash = write_hash_json(stem, sha256, tlsh);

    LOG_DEBUG("exporter: write_all: [3/{}] ioc", expected);
    out.ioc = write_ioc_json(stem, iocs);

    LOG_DEBUG("exporter: write_all: [4/{}] extraction", expected);
    out.extraction = write_extraction_json(stem, extraction);

    if (capa_report != nullptr) {
        LOG_DEBUG("exporter: write_all: [5/{}] capa", expected);
        out.capa = write_capa_json(stem, *capa_report);
    } else {
        LOG_DEBUG("exporter: write_all: skipping capa (not provided)");
    }

    if (iat != nullptr) {
        LOG_DEBUG("exporter: write_all: iat");
        out.iat = write_iat_json(stem, *iat);
    } else {
        LOG_DEBUG("exporter: write_all: skipping iat (not provided)");
    }

    if (got != nullptr) {
        LOG_DEBUG("exporter: write_all: got");
        out.got = write_got_json(stem, *got);
    } else {
        LOG_DEBUG("exporter: write_all: skipping got (not provided)");
    }

    if (radare2 != nullptr) {
        LOG_DEBUG("exporter: write_all: radare2 (files={}, functions={})",
                  radare2->files.size(), radare2->functions.size());
        out.radare2 = write_radare2_json(stem, *radare2);
    } else {
        LOG_DEBUG("exporter: write_all: skipping radare2 (not provided)");
    }

    if (xref_asm != nullptr) {
        LOG_DEBUG("exporter: write_all: iat_calls (slots={}, xrefs={}, functions={})",
                  xref_asm->slots_input, xref_asm->xrefs_found,
                  xref_asm->functions_dumped);
        out.iat_calls = write_xref_asm_json(stem, *xref_asm);
    } else {
        LOG_DEBUG("exporter: write_all: skipping iat_calls (not provided)");
    }

    if (asm_text != nullptr) {
        LOG_DEBUG("exporter: write_all: asm_text ({} bytes)", asm_text->size());
        out.asm_text = write_asm_text(stem, *asm_text);
    } else {
        LOG_DEBUG("exporter: write_all: skipping asm_text (not provided)");
    }

    // Optional: only emitted when the PE actually has overlay bytes. Its
    // presence is already accounted for in `expected` above, so a PE with an
    // overlay no longer trips the caller's "export files failed" check.
    if (overlay_expected) {
        LOG_DEBUG("exporter: write_all: overlay (offset={}, size={}, formats={})",
                  extraction.pe.overlay.offset, extraction.pe.overlay.size,
                  extraction.pe.overlay.signatures.size());
        out.overlay = write_overlay_bin(stem, extraction.pe.overlay);
    } else {
        LOG_DEBUG("exporter: write_all: skipping overlay (no overlay present)");
    }

    bool ok = !out.fileinfo.empty() && !out.hash.empty() &&
              !out.ioc.empty() && !out.extraction.empty();

    auto check = [&ok](const char* name, const fs::path& path) {
        if (path.empty()) {
            LOG_WARN("exporter: write_all: artifact '{}' was not written", name);
            ok = false;
        } else {
            LOG_DEBUG("exporter: write_all: artifact '{}' ok ({})",
                      name, path.string());
        }
    };
    check("fileinfo",   out.fileinfo);
    check("hash",       out.hash);
    check("ioc",        out.ioc);
    check("extraction", out.extraction);
    if (capa_report != nullptr) check("capa",       out.capa);
    if (iat != nullptr)         check("iat",        out.iat);
    if (got != nullptr)         check("got",        out.got);
    if (radare2 != nullptr)     check("radare2",    out.radare2);
    if (xref_asm != nullptr)    check("iat_calls",  out.iat_calls);
    if (asm_text != nullptr)    check("asm_text",   out.asm_text);

    std::uintmax_t total_bytes = 0;
    for (const auto& p : out.paths()) {
        std::error_code ec;
        const auto sz = fs::file_size(p, ec);
        if (!ec) total_bytes += sz;
    }

    if (ok) {
        // Report the real written/promised pair instead of "expected/expected",
        // which claimed success even when a stage silently produced nothing.
        const std::size_t written = out.paths().size();
        LOG_INFO("exporter: write_all: {}/{} artifacts written for stem='{}' "
                 "(total {} bytes)",
                 written, out.expected, stem, total_bytes);
        std::cout << console::paint(console::green,
            "[+] exporter: " + std::to_string(written) + "/" +
            std::to_string(out.expected) + " artifacts written for '" + stem + "'")
                  << "\n";
    } else {
        LOG_ERROR("exporter: write_all: partial failure for stem='{}' — "
                  "fileinfo={}, hash={}, ioc={}, extraction={}, "
                  "capa={}, iat={}, got={}, radare2={}, iat_calls={}, asm_text={}",
                  stem,
                  out.fileinfo.empty()   ? "FAILED" : "ok",
                  out.hash.empty()       ? "FAILED" : "ok",
                  out.ioc.empty()        ? "FAILED" : "ok",
                  out.extraction.empty() ? "FAILED" : "ok",
                  out.capa.empty()       ? (capa_report ? "FAILED" : "n/a") : "ok",
                  out.iat.empty()        ? (iat         ? "FAILED" : "n/a") : "ok",
                  out.got.empty()        ? (got         ? "FAILED" : "n/a") : "ok",
                  out.radare2.empty()    ? (radare2     ? "FAILED" : "n/a") : "ok",
                  out.iat_calls.empty()  ? (xref_asm    ? "FAILED" : "n/a") : "ok",
                  out.asm_text.empty()   ? (asm_text    ? "FAILED" : "n/a") : "ok");
        std::cout << console::paint(console::red,
            "[-] exporter: partial failure for '" + stem + "'") << "\n";
    }

    return out;
}

}  // namespace

write_result_t write_all(const std::string& stem,
                         const analyzer::file_info_t& info,
                         const file_hash_t& sha256,
                         const fuzzy_hash_t& tlsh,
                         const ioc::ioc_results_t& iocs,
                         const extractor::extraction_result_t& extraction) {
    return write_all_impl(stem, info, sha256, tlsh, iocs, extraction,
                          nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
}

write_result_t write_all(const std::string& stem,
                         const analyzer::file_info_t& info,
                         const file_hash_t& sha256,
                         const fuzzy_hash_t& tlsh,
                         const ioc::ioc_results_t& iocs,
                         const extractor::extraction_result_t& extraction,
                         const capa::report_t& capa_report) {
    return write_all_impl(stem, info, sha256, tlsh, iocs, extraction,
                          &capa_report, nullptr, nullptr, nullptr, nullptr, nullptr);
}

write_result_t write_all(const std::string& stem,
                         const analyzer::file_info_t& info,
                         const file_hash_t& sha256,
                         const fuzzy_hash_t& tlsh,
                         const ioc::ioc_results_t& iocs,
                         const extractor::extraction_result_t& extraction,
                         const capa::report_t& capa_report,
                         const extractor::iat_result_t& iat,
                         const extractor::got_result_t& got) {
    return write_all_impl(stem, info, sha256, tlsh, iocs, extraction,
                          &capa_report, &iat, &got, nullptr, nullptr, nullptr);
}

write_result_t write_all(const std::string& stem,
                         const analyzer::file_info_t& info,
                         const file_hash_t& sha256,
                         const fuzzy_hash_t& tlsh,
                         const ioc::ioc_results_t& iocs,
                         const extractor::extraction_result_t& extraction,
                         const capa::report_t& capa_report,
                         const extractor::iat_result_t& iat,
                         const extractor::got_result_t& got,
                         const r2::bulk_result_t& radare2) {
    return write_all_impl(stem, info, sha256, tlsh, iocs, extraction,
                          &capa_report, &iat, &got, &radare2, nullptr, nullptr);
}

write_result_t write_all(const std::string& stem,
                         const analyzer::file_info_t& info,
                         const file_hash_t& sha256,
                         const fuzzy_hash_t& tlsh,
                         const ioc::ioc_results_t& iocs,
                         const extractor::extraction_result_t& extraction,
                         const capa::report_t& capa_report,
                         const extractor::iat_result_t& iat,
                         const extractor::got_result_t& got,
                         const r2::bulk_result_t& radare2,
                         const r2::xref_asm_result_t& xref_asm) {
    return write_all_impl(stem, info, sha256, tlsh, iocs, extraction,
                          &capa_report, &iat, &got, &radare2, &xref_asm, nullptr);
}

write_result_t write_all(const std::string& stem,
                         const analyzer::file_info_t& info,
                         const file_hash_t& sha256,
                         const fuzzy_hash_t& tlsh,
                         const ioc::ioc_results_t& iocs,
                         const extractor::extraction_result_t& extraction,
                         const capa::report_t& capa_report,
                         const extractor::iat_result_t& iat,
                         const extractor::got_result_t& got,
                         const r2::bulk_result_t& radare2,
                         const r2::xref_asm_result_t& xref_asm,
                         const std::string& asm_text) {
    return write_all_impl(stem, info, sha256, tlsh, iocs, extraction,
                          &capa_report, &iat, &got, &radare2, &xref_asm, &asm_text);
}

// ---------------------------------------------------------------------------
// Summaries
// ---------------------------------------------------------------------------

namespace {

std::size_t count_records(const json& doc) {
    if (doc.is_object()) return doc.size();
    if (doc.is_array())  return doc.size();
    return 0;
}

std::string format_timestamp(std::filesystem::file_time_type t) {
    if (t == std::filesystem::file_time_type{}) return "(unknown)";
    using namespace std::chrono;
    const auto sys_now  = system_clock::now();
    const auto file_now = std::filesystem::file_time_type::clock::now();
    const auto sys_tp   = sys_now + (t - file_now);
    const std::time_t tt = system_clock::to_time_t(sys_tp);
    std::tm tm_buf{};
#if defined(_WIN32)
    localtime_s(&tm_buf, &tt);
#else
    localtime_r(&tt, &tm_buf);
#endif
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm_buf);
    return buf;
}

std::string format_bytes(std::uintmax_t bytes) {
    char buf[32];
    if (bytes < 1024ull)
        std::snprintf(buf, sizeof(buf), "%llu B",
                      static_cast<unsigned long long>(bytes));
    else if (bytes < 1024ull * 1024ull)
        std::snprintf(buf, sizeof(buf), "%.1f KiB",
                      static_cast<double>(bytes) / 1024.0);
    else
        std::snprintf(buf, sizeof(buf), "%.1f MiB",
                      static_cast<double>(bytes) / (1024.0 * 1024.0));
    return buf;
}

}  // namespace


export_file_info_t inspect_file(const fs::path& path) {
    LOG_TRACE("exporter: inspect_file: '{}'", path.string());
    export_file_info_t info;
    info.path = path;
    std::error_code ec;
    info.exists = fs::exists(path, ec);
    if (!info.exists || ec) {
        LOG_DEBUG("exporter: inspect_file: '{}' does not exist", path.string());
        return info;
    }
    info.size_bytes = fs::file_size(path, ec);
    if (ec) info.size_bytes = 0;
    info.last_write = fs::last_write_time(path, ec);
    try {
        std::ifstream in(path, std::ios::binary);
        if (!in) { info.parse_error = "cannot open for reading"; return info; }
        const json doc = json::parse(in, nullptr, false);
        if (doc.is_discarded()) { info.parse_error = "invalid JSON"; return info; }
        info.record_count = count_records(doc);
        info.parse_ok = true;
        LOG_TRACE("exporter: inspect_file: '{}' records={}, size={}",
                  path.string(), info.record_count, info.size_bytes);
    } catch (const std::exception& e) {
        info.parse_error = e.what();
        LOG_WARN("exporter: inspect_file: exception on '{}': {}",
                 path.string(), e.what());
    }
    return info;
}

export_file_info_t inspect_artifact(const fs::path& path) {
    LOG_TRACE("exporter: inspect_artifact: '{}'", path.string());
    export_file_info_t info;
    info.path = path;

    std::error_code ec;
    info.exists = fs::exists(path, ec);
    if (!info.exists || ec) {
        LOG_DEBUG("exporter: inspect_artifact: '{}' does not exist", path.string());
        return info;
    }

    info.size_bytes = fs::file_size(path, ec);
    if (ec) {
        info.size_bytes = 0;
        LOG_WARN("exporter: inspect_artifact: could not stat '{}': {}",
                 path.string(), ec.message());
    }

    info.last_write = fs::last_write_time(path, ec);

    info.parse_ok = info.size_bytes > 0;
    info.record_count = 1;   // one file counts as one entry in the summary
    if (!info.parse_ok) info.parse_error = "empty file";
    return info;
}

export_summary_t summarize_exports(const write_result_t& result) {
    LOG_DEBUG("exporter: summarize_exports: inspecting {} path(s)",
              result.paths().size());
    return summarize_export_paths(result.paths());
}

export_summary_t summarize_export_paths(
    const std::vector<std::filesystem::path>& paths) {
    export_summary_t summary;
    summary.files.reserve(paths.size());
    for (const auto& path : paths) {
        export_file_info_t info = inspect_file(path);
        summary.total_bytes   += info.size_bytes;
        summary.total_records += info.record_count;
        if (info.exists && info.parse_ok) ++summary.parsed_files;
        else                              ++summary.missing_files;
        summary.files.push_back(std::move(info));
    }
    LOG_INFO("exporter: summarize: files={}, parsed={}, missing={}, "
             "total_bytes={}, total_records={}",
             summary.files.size(), summary.parsed_files, summary.missing_files,
             summary.total_bytes, summary.total_records);
    return summary;
}

export_summary_t summarize_artifacts(
    const std::vector<std::filesystem::path>& paths) {
    export_summary_t summary;
    summary.files.reserve(paths.size());
    for (const auto& path : paths) {
        export_file_info_t info = inspect_artifact(path);
        summary.total_bytes   += info.size_bytes;
        summary.total_records += info.record_count;
        if (info.exists && info.parse_ok) ++summary.parsed_files;
        else                              ++summary.missing_files;
        summary.files.push_back(std::move(info));
    }
    LOG_INFO("exporter: summarize_artifacts: files={}, present={}, missing={}, "
             "total_bytes={}",
             summary.files.size(), summary.parsed_files, summary.missing_files,
             summary.total_bytes);
    return summary;
}

void print_export_summary(const export_summary_t& summary) {
    std::cout << '\n'
              << console::paint(console::cyan, "  -- export summary") << '\n';

    for (const auto& f : summary.files) {
        std::ostringstream line;
        line << "    " << std::left << std::setw(34) << f.path.filename().string();
        if (!f.exists) {
            std::cout << line.str()
                      << console::paint(console::red, "MISSING") << '\n';
            continue;
        }
        line << std::right << std::setw(10) << format_bytes(f.size_bytes)
             << "  " << std::setw(6) << f.record_count << " records"
             << "  " << format_timestamp(f.last_write);
        std::cout << line.str() << '\n';
        if (!f.parse_ok && !f.parse_error.empty()) {
            std::cout << console::paint(console::yellow,
                                        "        (!) " + f.parse_error) << '\n';
        }
    }

    std::cout << '\n';
    std::ostringstream total;
    total << "    total: " << summary.files.size() << " files, "
          << summary.parsed_files << " parsed, "
          << summary.missing_files << " missing, "
          << format_bytes(summary.total_bytes) << ", "
          << summary.total_records << " records";
    std::cout << console::paint(console::grey, total.str()) << '\n';
}

// ===========================================================================
// ml_export.cpp
// ===========================================================================

// The probability is stored under its own key and never collapsed into a
// "malicious": true boolean. The service's verdict is banded and can be
// not_applicable, and a consumer that reads a boolean off a 0.99 score for a
// non-PE file would be wrong - that combination is exactly the artefact the
// service refuses to call a detection. `probability_is_calibrated` is written as
// a literal false so the field cannot be quietly reinterpreted later.
json to_json(const ml_api::score_result_t& r) {
    json out = {
        {"ok", r.ok},
        {"file", r.file},
        {"bytes", r.bytes},
        {"feature_source", r.feature_source},
        {"malicious_probability", r.probability},
        {"probability_is_calibrated", false},
        {"verdict", r.verdict_raw},
        {"threshold", r.threshold},
        {"is_pe", r.is_pe},
        {"model", r.model},
        {"model_sha256", r.model_sha256},
        {"trees", r.trees},
        {"features", r.features},
        {"http_status", r.http_status},
    };
    if (!r.verdict_note.empty()) out["verdict_note"] = r.verdict_note;
    // Trust markers: a consumer that switches on `verdict` must be able to
    // see, without parsing prose, that this score was not built from a fresh
    // thrember vector or failed the train/serve skew check.
    out["low_confidence"] = r.low_confidence;
    if (!r.confidence_note.empty()) out["confidence_note"] = r.confidence_note;
    if (r.skew.present) {
        json groups = json::object();
        for (const auto& [name, g] : r.skew.groups) {
            groups[name] = {
                {"max_abs_diff", g.max_abs_diff},
                {"n", g.n},
                {"first_diff_index", g.first_diff_index},
                {"ok", g.ok},
            };
        }
        out["feature_skew"] = {
            {"ok", r.skew.ok},
            {"tolerance", r.skew.tolerance},
            {"groups", std::move(groups)},
        };
    }
    if (!r.ok) {
        out["error"]  = r.error;
        out["detail"] = r.detail;
        return out;
    }
    // Derived by ml_api::level_for(), not re-implemented by any consumer: the
    // console report, the dashboard and this file must band the same number the
    // same way, or a reader comparing them sees two different threats.
    out["threat_level"]     = ml_api::to_string(ml_api::level_for(r));
    out["threshold_margin"] = ml_api::threshold_margin(r);
    if (!r.explained) return out;

    json features = json::array();
    for (const ml_api::feature_evidence_t& f : r.top_features) {
        features.push_back({
            {"feature_index", f.feature_index},
            {"group", f.group},
            {"label", f.label},
            {"evidence", f.evidence},
            {"value", f.value},
            {"shap_log_odds", f.shap_log_odds},
            {"direction", f.direction},
            // Retained because a shared bucket's SHAP is the sum over every name
            // hashing into it; without these two a reader would attribute one
            // bucket's whole contribution to a single import.
            {"bucket_occupancy", f.bucket_occupancy},
            {"shared_bucket", f.shared_bucket},
            {"analyzer_implemented", f.analyzer_implemented},
        });
    }
    json groups = json::array();
    for (const ml_api::group_rollup_t& g : r.group_rollup) {
        groups.push_back({
            {"group", g.group},
            {"shap_log_odds", g.shap_log_odds},
            {"analyzer_implemented", g.analyzer_implemented},
        });
    }
    out["explanation"] = {
        {"space", "log-odds (binary objective)"},
        {"base_log_odds", r.base_log_odds},
        {"prediction_log_odds", r.prediction_log_odds},
        {"sum_shap", r.sum_shap},
        // base + sum(SHAP) must reproduce prediction_log_odds; a non-zero value
        // would mean the attribution is approximate rather than exact.
        {"consistency_error", r.consistency_error},
        {"top_features", std::move(features)},
        {"group_rollup", std::move(groups)},
    };
    return out;
}

// Writes the model verdict to exports/<stem>_analysis/ml/<stem>_ml.json. Written even when the
// score failed, so a refused request (non-vectorisable file, oversized sample)
// leaves a record of why rather than no file at all.
std::filesystem::path write_ml_json(const std::string& stem,
                                    const ml_api::score_result_t& score) {
    LOG_DEBUG("exporter: write_ml_json: stem='{}', ok={}, verdict='{}'",
              stem, score.ok, score.verdict_raw);
    EXPORTER_TRY("write_ml_json", {
        const auto path = write_json_file(dir::run(stem, "ml"), artifact_stem(stem, "ml"),
                                          to_json(score));
        print_export_line("ml", path, !path.empty());
        return path;
    })
}

json to_json(const known_pe::result_t& r) {
    json out = {
        {"sha256", r.sha256},
        {"roster", r.index_path},
        {"roster_entries", r.entries_loaded},
        {"roster_lines_skipped", r.lines_skipped},
        {"matched", r.matched},
        {"lookup_seconds", r.seconds},
    };
    if (r.matched) {
        out["label"]    = r.entry.malicious ? 1 : 0;
        out["verdict"]  = r.entry.malicious ? "malicious" : "benign";
        out["family"]   = r.entry.family;
        out["split"]    = r.entry.split_names();
    }
    if (!r.errors.empty()) out["errors"] = r.errors;
    return out;
}

// Only a lookup that actually read a roster produces a file. `attempted`
// distinguishes "the caller never asked" from "the caller asked and there was
// no roster", and neither should leave an artifact behind - a file recording
// "matched: false" would read as a real negative finding.
std::filesystem::path write_known_pe_json(const std::string& stem,
                                          const known_pe::result_t& match) {
    LOG_DEBUG("exporter: write_known_pe_json: stem='{}', matched={}, available={}",
              stem, match.matched, match.available);
    if (!match.attempted || !match.available) {
        LOG_DEBUG("exporter: write_known_pe_json: no roster lookup to record, skipping");
        return {};
    }
    EXPORTER_TRY("write_known_pe_json", {
        const auto path = write_json_file(dir::run(stem, "known_pe"),
                                          artifact_stem(stem, "known_pe"),
                                          to_json(match));
        print_export_line("known_pe", path, !path.empty());
        return path;
    })
}

// ===========================================================================
// cti_export.cpp
// ===========================================================================

namespace {
}  // namespace

// Writes the full CTI report (artifacts, verdicts, families, ATT&CK, providers,
// warnings — everything the pipeline found) to exports/<stem>_analysis/cti/<stem>_cti.json.
std::filesystem::path write_cti_json(const std::string& stem, const cti::report& r) {
  LOG_DEBUG("exporter: write_cti_json: stem='{}', items={}, warnings={}",
            stem, r.items.size(), r.warnings.size());
  EXPORTER_TRY("write_cti_json", {
    // cti::to_json() hands back JSON *text*, while write_json_file()
    // serializes a json *value*: passing the text straight through made
    // nlohmann wrap it in a JSON string, so <stem>_cti.json on disk was one
    // giant quoted blob (every consumer had to json.loads() it twice).
    const std::string text = cti::to_json(r);
    const json doc = json::parse(text, nullptr, false);
    if (doc.is_discarded()) {
      LOG_ERROR("export: cti::to_json() produced unparseable JSON ({} bytes)", text.size());
      std::cout << console::paint(console::red, "[-] ") << console::paint(console::red, "cti")
                << ": internal JSON was not parseable\n";
      return {};
    }
    const auto path = write_json_file(dir::run(stem, "cti"), artifact_stem(stem, "cti"), doc);
    print_export_line("cti", path, !path.empty());
    return path;
  })
}

// ---------------------------------------------------------------------------
// STIX 2.1 bundle + ATT&CK Navigator layer
// ---------------------------------------------------------------------------

namespace {

// ATT&CK v19 renamed the "defense-evasion" tactic (TA0005) to "stealth" and
// added "defense-impairment" (TA0112).  The knowledge feed already speaks the
// new names, but every capa rule still tags the tactic the old way
// ("Defense Evasion::..."), so the legacy spelling is folded onto "stealth"
// rather than dropped.
std::string navigator_tactic(const std::string& raw) {
    std::string key;
    key.reserve(raw.size() + 4);
    for (char c : raw) {
        const unsigned char u = static_cast<unsigned char>(c);
        if (c == '&') { key += "and"; continue; }
        if (std::isalnum(u)) key += static_cast<char>(std::tolower(u));
        else                 key += '-';
    }

    std::string out;                       // collapse runs of '-', trim ends
    bool pending_dash = false;
    for (char c : key) {
        if (c == '-') { pending_dash = true; continue; }
        if (pending_dash && !out.empty()) out += '-';
        pending_dash = false;
        out += c;
    }

    static const std::map<std::string, std::string> aliases = {
        {"c2", "command-and-control"},
        {"c2-command-and-control", "command-and-control"},
        {"command-and-control-c2", "command-and-control"},
        {"recon", "reconnaissance"},
        // ATT&CK <= v18 name for TA0005, still what every capa rule tags.
        {"defense-evasion", "stealth"},
        {"defense-evasion-and-privilege-escalation", "stealth"},
    };
    if (const auto it = aliases.find(out); it != aliases.end()) out = it->second;

    static const std::set<std::string> known = {
        "reconnaissance", "resource-development", "initial-access", "execution",
        "persistence", "privilege-escalation", "stealth", "defense-impairment",
        "credential-access", "discovery", "lateral-movement", "collection",
        "command-and-control", "exfiltration", "impact",
    };
    return known.count(out) != 0 ? out : std::string{};
}

}  // namespace

std::filesystem::path write_stix_bundle(const std::string& stem,
                                        const cti::report& r,
                                        const cti::stix_options& options) {
  LOG_DEBUG("exporter: write_stix_bundle: stem='{}', items={}, producer='{}'",
            stem, r.items.size(), options.producer);
  EXPORTER_TRY("write_stix_bundle", {
    // Same trap as write_cti_json(): cti::to_stix_bundle() returns JSON
    // *text*, and handing that text to write_json_file() would store it as one
    // quoted blob instead of a document.
    const std::string text = cti::to_stix_bundle(r, options);
    const json doc = json::parse(text, nullptr, false);
    if (doc.is_discarded()) {
      LOG_ERROR("export: cti::to_stix_bundle() produced unparseable JSON ({} bytes)",
                text.size());
      std::cout << console::paint(console::red, "[-] ")
                << console::paint(console::red, "stix")
                << ": internal JSON was not parseable\n";
      return {};
    }
    const auto path = write_json_file(dir::run(stem, "stix"), artifact_stem(stem, "stix21"), doc);
    print_export_line("stix", path, !path.empty());
    return path;
  })
}

std::filesystem::path write_navigator_layer(const std::string& stem,
                                            const capa::report_t& capa_report,
                                            const cti::report& report,
                                            const std::string& attack_version) {
  LOG_DEBUG("exporter: write_navigator_layer: stem='{}', capabilities={}, report items={}",
            stem, capa_report.capabilities.size(), report.items.size());
  EXPORTER_TRY("write_navigator_layer", {
    struct tech_info {
      std::string name;                       // display name: knowledge > capa > id
      std::string url;
      std::vector<std::string> platforms;
      std::vector<std::string> tactics;       // ALL tactics of the technique
      std::vector<std::string> capabilities;  // distinct capa capability names
      bool from_capa = false;
      bool from_cti = false;
      bool knowledge_tactics = false;         // tactics came from ATT&CK knowledge
    };
    std::map<std::string, tech_info> techs;   // keyed by upper-case technique id

    const auto join_with = [](const std::vector<std::string>& parts, const char* sep) {
      std::string out;
      for (std::size_t i = 0; i < parts.size(); ++i) {
        if (i) out += sep;
        out += parts[i];
      }
      return out;
    };

    // 1) capa: the capability names (the procedure text in the comment), a
    //    tactic fallback for when no ATT&CK knowledge is available, and the
    //    display name. capa matches a technique once per capability, so the
    //    capability list is deduped here.
    for (const capa::capability_t& cap : capa_report.capabilities) {
      for (const capa::attack_t& att : cap.attack) {
        if (att.id.empty()) continue;
        const std::string id = cti::to_upper(att.id);
        tech_info& t = techs[id];
        t.from_capa = true;
        if (t.name.empty()) {
          std::string display = att.technique;
          if (!att.subtechnique.empty())
            display += display.empty() ? att.subtechnique : ": " + att.subtechnique;
          t.name = display.empty() ? id : display;
        }
        if (!cap.name.empty() &&
            std::find(t.capabilities.begin(), t.capabilities.end(), cap.name) ==
                t.capabilities.end())
          t.capabilities.push_back(cap.name);
        if (!t.knowledge_tactics) {
          const std::string tactic = navigator_tactic(att.tactic);
          if (!tactic.empty() &&
              std::find(t.tactics.begin(), t.tactics.end(), tactic) == t.tactics.end())
            t.tactics.push_back(tactic);
        }
      }
    }

    // 2) the (enriched) CTI report: the real technique name and - the point of
    //    this rewrite - EVERY ATT&CK tactic the technique belongs to, not just
    //    the one capa's rule tagged. Also picks up techniques capa never hit.
    for (const cti::enrichment& e : report.items) {
      if (e.skipped || e.art.type != cti::artifact_type::technique) continue;
      const std::string id = cti::to_upper(e.art.value);
      if (id.empty()) continue;
      tech_info& t = techs[id];
      t.from_cti = true;
      const auto it = e.knowledge.find("mitre_attack");
      if (it == e.knowledge.end() || !it->is_object()) continue;
      const json& k = *it;
      if (k.contains("name") && k["name"].is_string() && !k["name"].get<std::string>().empty())
        t.name = k["name"].get<std::string>();
      if (k.contains("url") && k["url"].is_string() && !k["url"].get<std::string>().empty())
        t.url = k["url"].get<std::string>();
      if (k.contains("platforms") && k["platforms"].is_array()) {
        t.platforms.clear();
        for (const json& p : k["platforms"])
          if (p.is_string()) t.platforms.push_back(p.get<std::string>());
      }
      if (k.contains("tactic_shortnames") && k["tactic_shortnames"].is_array()) {
        std::vector<std::string> known;
        for (const json& raw : k["tactic_shortnames"]) {
          if (!raw.is_string()) continue;
          const std::string tactic = navigator_tactic(raw.get<std::string>());
          if (!tactic.empty() &&
              std::find(known.begin(), known.end(), tactic) == known.end())
            known.push_back(tactic);
        }
        if (!known.empty()) {
          t.tactics = std::move(known);   // knowledge wins over the capa fallback
          t.knowledge_tactics = true;
        }
      }
    }

    for (auto& entry : techs)
      if (entry.second.name.empty()) entry.second.name = entry.first;

    if (techs.empty()) {
      LOG_DEBUG("exporter: write_navigator_layer: no techniques observed");
      return {};
    }

    // One entry per (technique, tactic): each technique is expanded across
    // ALL of its ATT&CK tactics. A sub-technique is only reachable in the
    // Navigator below its parent cell, so parents of matched sub-techniques
    // get showSubtechniques - observed parents carry the flag on their own
    // entries, unobserved parents are synthesised further down with score 0.
    std::set<std::string> parents;
    for (const auto& entry : techs) {
      const auto dot = entry.first.find('.');
      if (dot != std::string::npos) parents.insert(entry.first.substr(0, dot));
    }

    json techniques = json::array();
    std::set<std::pair<std::string, std::string>> emitted;   // (id, tactic)
    std::size_t unassigned = 0;
    int max_score = 1;

    auto push = [&](const std::string& id, const std::string& tactic, int score,
                    std::string comment, json metadata, bool expand) {
      if (!emitted.emplace(id, tactic).second) return;
      json entry = {{"techniqueID", id}, {"enabled", true}, {"score", score},
                    {"comment", std::move(comment)}, {"metadata", std::move(metadata)}};
      if (tactic.empty()) ++unassigned;
      else                 entry["tactic"] = tactic;
      if (expand)          entry["showSubtechniques"] = true;
      techniques.push_back(std::move(entry));
    };

    for (const auto& entry : techs) {
      const std::string& id = entry.first;
      const tech_info& t = entry.second;
      const int score = static_cast<int>(std::max<std::size_t>(1, t.capabilities.size()));
      max_score = std::max(max_score, score);

      // comment = procedure detail: the capa capabilities that matched here.
      std::string comment = t.name;
      if (!t.capabilities.empty())
        comment += " - matched by capa: " + join_with(t.capabilities, "; ");
      else
        comment += " - observed in this sample (no capa capability matched)";

      json metadata = json::array();
      metadata.push_back({{"name", "source"},
                          {"value", t.from_capa && t.from_cti ? "capa + CTI"
                                                             : (t.from_capa ? "capa" : "CTI")}});
      if (!t.capabilities.empty())
        metadata.push_back({{"name", "capabilities"},
                            {"value", std::to_string(t.capabilities.size())}});
      if (!t.platforms.empty())
        metadata.push_back({{"name", "platforms"}, {"value", join_with(t.platforms, ", ")}});
      if (!t.url.empty())
        metadata.push_back({{"name", "attack_url"}, {"value", t.url}});

      const bool expand = parents.count(id) != 0;
      if (t.tactics.empty()) {
        push(id, "", score, comment, metadata, expand);
      } else {
        for (const std::string& tactic : t.tactics)
          push(id, tactic, score, comment, metadata, expand);
      }
    }

    // Synthesised parents: not observed themselves, present only so the matched
    // sub-technique underneath them renders (score 0 = not scored, honest).
    for (const auto& entry : techs) {
      const std::string& child = entry.first;
      const auto dot = child.find('.');
      if (dot == std::string::npos) continue;
      const std::string parent_id = child.substr(0, dot);
      if (techs.count(parent_id) != 0) continue;
      const std::string comment = parent_id + " - parent of matched sub-technique " + child;
      json metadata = json::array();
      metadata.push_back({{"name", "source"}, {"value", "sub-technique expansion"}});
      if (entry.second.tactics.empty()) {
        push(parent_id, "", 0, comment, metadata, true);
      } else {
        for (const std::string& tactic : entry.second.tactics)
          push(parent_id, tactic, 0, comment, metadata, true);
      }
    }

    const json layer = {
      {"name", stem},
      {"versions", {
        // v19 is the oldest release whose matrix uses "stealth" and
        // "defense-impairment"; declaring 14 would hide every such column.
        {"attack",    attack_version.empty() ? std::string("19") : attack_version},
        {"navigator", "4.9.0"},
        {"layer",     "4.5"},
      }},
      {"domain", "enterprise-attack"},
      {"description", "Techniques observed during static analysis of " + stem +
                      ", each mapped to ALL of its ATT&CK tactics. Score = number of "
                      "matching capa capabilities (1 = observed once or via CTI)."},
      {"techniques", std::move(techniques)},
      {"gradient", {
        {"colors", json::array({"#ffffff", "#ffd166", "#ff9f43", "#ff4d5e"})},
        {"minValue", 0},
        {"maxValue", std::max(3, max_score)},
      }},
      {"legendItems", json::array({
        json{{"label", "score = matching capa capabilities"}, {"color", "#ff9f43"}},
        json{{"label", "parent expanded for a matched sub-technique"}, {"color", "#ffffff"}},
      })},
      {"sorting", 3},
      {"layout", {{"layout", "side"}, {"showID", true}, {"showName", true}}},
      {"hideDisabled", true},
    };

    if (unassigned != 0) {
      LOG_WARN("export: navigator layer: {} technique(s) had no usable tactic",
               unassigned);
    }

    const auto path = write_json_file(dir::run(stem, "stix"), artifact_stem(stem, "navigator"), layer);
    print_export_line("navigator", path, !path.empty());
    return path;
  })
}

}  // namespace exporter