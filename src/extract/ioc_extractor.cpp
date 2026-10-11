#include "ioc_extractor.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <iostream>
#include <memory>
#include <optional>
#include <random>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

#include "console.hpp"
#include "logging.hpp"

namespace ioc {

// ---------------------------------------------------------------------------
// Small ASCII helpers (locale independent)
// ---------------------------------------------------------------------------
namespace {

using clock_type = std::chrono::steady_clock;

double seconds_since(clock_type::time_point start) {
    return std::chrono::duration<double>(clock_type::now() - start).count();
}

inline bool is_digit(char c) { return c >= '0' && c <= '9'; }
inline bool is_alpha_lc(char c) { return c >= 'a' && c <= 'z'; }
inline bool is_alnum_lc(char c) { return is_digit(c) || is_alpha_lc(c); }
inline char to_lc(char c) { return (c >= 'A' && c <= 'Z') ? static_cast<char>(c + 32) : c; }

void to_lower_into(std::string_view s, std::string& out) {
    out.resize(s.size());
    for (std::size_t i = 0; i < s.size(); ++i) out[i] = to_lc(s[i]);
}

std::string to_lower(std::string_view s) {
    std::string out;
    to_lower_into(s, out);
    return out;
}

// Keyword match with word boundaries. Plain substring matching flagged
// "rat" in "operator", "c2" in hex strings, "mask" in "bitmask", etc.
//   * keywords <= 3 chars ("rat", "c2", "rig", "url"): both neighbours must be
//     non-alphanumeric
//   * longer keywords: both neighbours must be non-letters (so "emotet_x.exe" and
//     "trickbot2" still match, "operation" does not match "rat")
// `lower` must already be lower-cased.
bool contains_keyword(const std::string& lower, std::string_view keyword) {
    const bool strict = keyword.size() <= 3;
    std::size_t pos = 0;
    while ((pos = lower.find(keyword, pos)) != std::string::npos) {
        const std::size_t end = pos + keyword.size();
        const char before = pos == 0 ? ' ' : lower[pos - 1];
        const char after = end >= lower.size() ? ' ' : lower[end];
        const bool ok = strict ? (!is_alnum_lc(before) && !is_alnum_lc(after))
                               : (!is_alpha_lc(before) && !is_alpha_lc(after));
        if (ok) return true;
        ++pos;
    }
    return false;
}

// Real TLDs only (ccTLDs + the gTLDs that show up in malware/phishing).
// Without this every "kernel32.dll" / "System.Windows.Forms" is a "domain".
// Deliberately absent: "zip" and "mov" (valid TLDs but far more often file names).
const std::unordered_set<std::string_view>& known_tlds() {
    static const std::unordered_set<std::string_view> tlds = [] {
        constexpr std::string_view list =
            "ac ad ae af ag ai al am ao aq ar as at au aw ax az ba bb bd be bf bg bh bi bj bm "
            "bn bo br bs bt bw by bz ca cc cd cf cg ch ci ck cl cm cn co cr cu cv cw cx cy cz "
            "de dj dk dm do dz ec ee eg er es et eu fi fj fk fm fo fr ga gd ge gf gg gh gi gl "
            "gm gn gp gq gr gs gt gu gw gy hk hm hn hr ht hu id ie il im in io iq ir is it je "
            "jm jo jp ke kg kh ki km kn kp kr kw ky kz la lb lc li lk lr ls lt lu lv ly ma mc "
            "md me mg mh mk ml mm mn mo mp mq mr ms mt mu mv mw mx my mz na nc ne nf ng ni nl "
            "no np nr nu nz om pa pe pf pg ph pk pl pm pn pr ps pt pw py qa re ro rs ru rw sa "
            "sb sc sd se sg sh si sk sl sm sn so sr ss st su sv sx sy sz tc td tf tg th tj tk "
            "tl tm tn to tr tt tv tw tz ua ug uk us uy uz va vc ve vg vi vn vu wf ws ye yt za "
            "zm zw "
            "com net org info biz edu gov mil int mobi name pro asia tel jobs travel museum "
            "aero coop cat xxx arpa onion app dev cloud tech online site store shop xyz top "
            "club icu cyou cfd buzz work live life fun link click world today space website "
            "press vip ltd email support agency network digital solutions services systems "
            "center company group news media page blog wiki host download";
        std::unordered_set<std::string_view> out;
        std::size_t i = 0;
        while (i < list.size()) {
            std::size_t j = list.find(' ', i);
            if (j == std::string_view::npos) j = list.size();
            if (j > i) out.insert(list.substr(i, j - i));
            i = j + 1;
        }
        return out;
    }();
    return tlds;
}

// TLDs that double as extremely common file extensions or short code tokens.
// A bare "word.tld" match against one of these is far more often a filename
// (README.md, utils.py, handler.sh, libssl.so, main.rs, helper.la, model.ai)
// or a decompiled namespace/member chain (System.IO, Console.In, Convert.To)
// than an actual domain. Full URLs, hosts with a real subdomain, or hosts
// followed by a path/port still get through -- see is_plausible_domain().
const std::unordered_set<std::string_view>& ambiguous_tlds() {
    static const std::unordered_set<std::string_view> tlds = {
        "md",  // Markdown
        "py",  // Python
        "sh",  // shell script
        "pl",  // Perl
        "so",  // Linux shared object
        "ai",  // Adobe Illustrator
        "ml",  // OCaml source
        "rs",  // Rust source
        "gs",  // Google Apps Script
        "la",  // libtool archive
        "cc",  // C/C++ source (also a common ccTLD)
        "tv", "im", "to", "in", "id", "is", "st", "gg",
        "io", // very common as a bare 2-segment code/member chain too
    };
    return tlds;
}

// gTLDs that are also common English words, code tokens or ISA suffixes:
// a bare "word.tld" pair is far more often an instruction-table entry
// (i32.store, cmp.click, f64.live) than an actual domain. These get the
// same context requirement as ambiguous_tlds.
const std::unordered_set<std::string_view>& wordlike_tlds() {
    static const std::unordered_set<std::string_view> tlds = {
        "store", "shop", "top", "club", "work", "live", "life", "fun",
        "link", "click", "world", "today", "space", "website", "press",
        "vip", "ltd", "email", "support", "agency", "network", "digital",
        "solutions", "services", "systems", "center", "company", "group",
        "news", "media", "page", "blog", "wiki", "host", "download",
        "online", "site", "app", "dev", "cloud", "tech",
    };
    return tlds;
}

// A bare "label.tld" needs corroborating context (subdomain / path / port /
// scheme) when the TLD is a 2-letter ccTLD (cmp.af, shra.ph, and.ge all
// collide with instruction suffixes), an ambiguous extension, or a wordlike
// gTLD. Real C2 hosts found in binary strings virtually always appear inside
// a URL, with a port, or with a real subdomain.
bool tld_requires_context(std::string_view tld) {
    return tld.size() == 2 ||
           ambiguous_tlds().count(tld) != 0 ||
           wordlike_tlds().count(tld) != 0;
}

// Extensions that commonly show up as the *second* extension on a
// "double extension" file: utils.py.bak, README.md.orig, handler.so.1
// (the trailing "1" isn't alphabetic so it's naturally excluded by
// IOC_TLD's [a-z]{2,24} and never reaches this check).
bool is_trailing_file_extension(std::string_view lower_ext) {
    static const std::unordered_set<std::string_view> exts = {
        "dll", "exe", "sys", "ocx", "drv", "cpl", "scr", "bat", "cmd", "ps1",
        "vbs", "jar", "class", "pdb", "config", "resources", "mui", "manifest",
        "bak", "old", "orig", "tmp", "log", "dat", "bin", "obj", "lib",
        "deb", "rpm", "msi", "cab", "iso", "vhd", "apk", "ipa", "a", "o",
    };
    return exts.count(lower_ext) != 0;
}

// `text` is the ORIGINAL scan buffer; `pos`/`len` locate the raw regex match
// inside it, so we can look at what precedes and follows the match itself
// (subdomain depth, trailing double-extension, leading scheme/www.) instead
// of judging the candidate domain in isolation.
bool is_plausible_domain(std::string_view text, std::size_t pos, std::size_t len) {
    std::string_view domain = text.substr(pos, len);
    if (domain.size() > 253) return false;

    const std::string lower = to_lower(domain);
    const std::size_t dot = lower.rfind('.');
    if (dot == std::string::npos) return false;
    const std::string_view tld = std::string_view(lower).substr(dot + 1);

    const bool is_xn = tld.size() >= 4 && tld.substr(0, 4) == "xn--";
    if (!is_xn && known_tlds().count(tld) == 0) return false;

    // Double-extension guard: "utils.py.bak", "README.md.orig" -> reject if
    // what immediately follows the match is another dotted, letters-only,
    // known non-TLD file extension. Real domains are essentially never
    // followed by ".dll" / ".bak" / ".config" etc. with no separator.
    {
        const std::size_t after = pos + len;
        if (after < text.size() && text[after] == '.') {
            std::size_t ext_start = after + 1;
            std::size_t ext_end = ext_start;
            while (ext_end < text.size() && is_alpha_lc(to_lc(text[ext_end]))) ++ext_end;
            if (ext_end > ext_start) {
                const std::string ext = to_lower(text.substr(ext_start, ext_end - ext_start));
                if (is_trailing_file_extension(ext)) return false;
            }
        }
    }

    // Context-required TLDs (ambiguous extension, wordlike gTLD, or any
    // 2-letter ccTLD): only accept when there's real corroborating context --
    // a subdomain made of normal-length labels, a following path or port, or
    // a preceding scheme/www. A bare "SLD.tld" with nothing else around it is
    // more often README.md / utils.py / System.IO / cmp.af / i32.store than an
    // actual domain. For context-free 3+ label matches every non-TLD label
    // must be at least 3 chars, so ISA-table chains like "precrq.qb.ph" and
    // "amoadd.d.aq" are rejected while "mail.update.ph" still passes.
    if (!is_xn && tld_requires_context(tld)) {
        const std::size_t dots = static_cast<std::size_t>(
            std::count(lower.begin(), lower.end(), '.'));
        const bool has_subdomain = dots >= 2;

        const std::size_t after = pos + len;
        const bool followed_by_path_or_port =
            after < text.size() && (text[after] == '/' || text[after] == ':');

        bool preceded_by_scheme_or_www = false;
        if (pos > 0) {
            const std::string before = to_lower(text.substr(0, pos));
            preceded_by_scheme_or_www =
                (before.size() >= 4 && before.compare(before.size() - 4, 4, "www.") == 0) ||
                before.find("://") != std::string::npos;
        }

        const bool has_context =
            followed_by_path_or_port || preceded_by_scheme_or_www;

        if (!has_subdomain && !has_context) {
            return false;
        }

        if (has_subdomain && !has_context) {
            // Every label except the TLD must be >= 3 chars.
            std::size_t start = 0;
            while (start < lower.size()) {
                std::size_t end = lower.find('.', start);
                if (end == std::string::npos) end = lower.size();
                const bool is_tld_label = (end == lower.size());
                if (!is_tld_label && end - start < 3) return false;
                start = end + 1;
            }
        }
    }

    return true;
}

// Drops IPv4 "hits" that are really version strings / reserved space, plus
// private and special-use ranges (RFC 1918, loopback, link-local, CGNAT,
// multicast) which are not actionable external indicators. Documentation
// ranges (TEST-NET-1..3) are deliberately kept: they are rare in real
// binaries and are used as C2 stand-ins by the detection fixtures.
bool is_plausible_ip(std::string_view text, std::size_t pos, std::size_t len) {
    // part of a longer dotted number, e.g. 1.2.3.4.5
    if (pos >= 2 && text[pos - 1] == '.' && is_digit(text[pos - 2])) return false;
    const std::size_t end = pos + len;
    if (end + 1 < text.size() && text[end] == '.' && is_digit(text[end + 1])) return false;

    unsigned octets[4] = {0, 0, 0, 0};
    int part = 0;
    for (std::size_t i = pos; i < end; ++i) {
        if (text[i] == '.') { ++part; continue; }
        if (part < 4) octets[part] = octets[part] * 10 + static_cast<unsigned>(text[i] - '0');
    }

    const unsigned o0 = octets[0], o1 = octets[1], o2 = octets[2];
    if (o0 == 0) return false;                                 // 0.0.0.0/8 "this network"
    if (o0 == 10) return false;                                // 10.0.0.0/8 private
    if (o0 == 127) return false;                               // loopback
    if (o0 == 169 && o1 == 254) return false;                  // link-local
    if (o0 == 172 && o1 >= 16 && o1 <= 31) return false;       // 172.16.0.0/12 private
    if (o0 == 192 && o1 == 168) return false;                  // 192.168.0.0/16 private
    if (o0 == 192 && o1 == 0 && o2 == 0) return false;         // 192.0.0.0/24 IETF
    if (o0 == 100 && o1 >= 64 && o1 <= 127) return false;      // 100.64.0.0/10 CGNAT
    if (o0 >= 224) return false;                               // multicast / reserved
    return true;
}

bool is_trivial_hash(std::string_view h) {
    return std::all_of(h.begin(), h.end(), [&](char c) { return c == h.front(); });
}

// "hxxps://..." -> "https://..." and strip trailing punctuation picked up from prose.
std::string finalize_url(std::string url) {
    if (url.size() >= 4 && (url[1] == 'x' || url[1] == 'X') && (url[2] == 'x' || url[2] == 'X')) {
        url[1] = 't';
        url[2] = 't';
    }
    constexpr std::string_view trailing = ".,;:!?)]}'\"";
    while (!url.empty() && trailing.find(url.back()) != std::string_view::npos) url.pop_back();
    return url;
}

}  // namespace

const std::vector<std::string>& userAgents() {
    static const std::vector<std::string> ua = {
        "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.99 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.99 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.99 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_1) AppleWebKit/602.2.14 (KHTML, like Gecko) Version/10.0.1 Safari/602.2.14",
        "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.98 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.98 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36",
        "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.99 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:50.0) Gecko/20100101 Firefox/50.0",
    };
    return ua;
}

std::vector<Header> HEADERS() {
    static thread_local std::mt19937 rng{std::random_device{}()};
    const auto& ua = userAgents();
    std::uniform_int_distribution<std::size_t> dist(0, ua.size() - 1);
    const std::size_t picked = dist(rng);
    LOG_TRACE("ioc: HEADERS: picked UA index {}", picked);
    return {
        {"User-Agent", ua[picked]},
        {"Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"},
    };
}

const char* error_name(extractor_error error) {
    switch (error) {
        case extractor_error::none:               return "none";
        case extractor_error::invalid_input:      return "invalid_input";
        case extractor_error::empty_input:        return "empty_input";
        case extractor_error::regex_compile_fail: return "regex_compile_fail";
        case extractor_error::regex_match_fail:   return "regex_match_fail";
        case extractor_error::no_matches:         return "no_matches";
        case extractor_error::no_strings:         return "no_strings";
        case extractor_error::unknown:            return "unknown";
    }
    return "unknown";
}

void add_error(error_type_t& errors, extractor_error error, const std::string& detail) {
    LOG_TRACE("ioc: add_error: {} — {}", error_name(error), detail);
    errors.flags |= error;
    errors.messages.push_back(std::string("[") + error_name(error) + "] " + detail);
    if (!errors.details.empty()) {
        errors.details += '\n';
    }
    errors.details += detail;
}

bool has_errors(const error_type_t& errors) {
    return errors.flags != extractor_error::none;
}

std::vector<std::string> get_error_messages(const error_type_t& errors) {
    return errors.messages;
}

// NOTE: family names that were tagged with the wrong class in the original table
// were corrected (agenttesla, formbook, pony -> INFO_STEALER; gandcrab,
// globeimposter, bandarchore -> RANSOMWARE; ramnit, gootkit -> TROJAN;
// sweetorange -> EXPLOIT_KIT).
const std::vector<keyword_entry>& commonKeywordClassification() {
    static const std::vector<keyword_entry> k = {
        {"adwind", TROJAN}, {"adylkuzz", TROJAN}, {"afraid", RANSOMWARE},
        {"afriad", EXPLOIT_KIT}, {"agenttesla", INFO_STEALER}, {"angler", EXPLOIT_KIT},
        {"alphacrypt", RANSOMWARE}, {"andromeda", TROJAN}, {"arescrypt", RANSOMWARE},
        {"asprox", WORM},
        {"backoff", TROJAN}, {"badrabbit", RANSOMWARE}, {"bandarchore", RANSOMWARE},
        {"bamital", TROJAN}, {"banjori", TROJAN}, {"bebloh", TROJAN}, {"bedep", TROJAN},
        {"beebone", VIRUS}, {"blackenergy", APT}, {"brobot", TROJAN},
        {"caphaw", TROJAN}, {"carbanak", APT}, {"cerber", RANSOMWARE},
        {"conficker", WORM}, {"corebot", TROJAN}, {"cryptodefense", RANSOMWARE},
        {"cryptolocker", RANSOMWARE}, {"cryptowall", RANSOMWARE}, {"cryptxxx", RANSOMWARE},
        {"chthonic", TROJAN}, {"crypmic", RANSOMWARE}, {"cryptmic", RANSOMWARE},
        {"darkleech", CRIMEWARE}, {"dexter", VIRUS}, {"dircrypt", RANSOMWARE},
        {"dridex", TROJAN}, {"dyre", TROJAN},
        {"eitest", TROJAN}, {"emotet", TROJAN}, {"explosive", APT},
        {"fiesta", EXPLOIT_KIT}, {"fobber", INFO_STEALER}, {"formbook", INFO_STEALER},
        {"gameoverzeus", TROJAN}, {"zeus", TROJAN}, {"gandcrab", RANSOMWARE},
        {"geodo", TROJAN}, {"goodman", EXPLOIT_KIT}, {"gootkit", TROJAN},
        {"globeimposter", RANSOMWARE},
        {"hailstorm", TROJAN}, {"hancitor", TROJAN}, {"havex", TROJAN}, {"hesperbot", TROJAN},
        {"icedid", TROJAN}, {"infinity", EXPLOIT_KIT},
        {"jbitfrost", TROJAN}, {"jigsaw", TROJAN},
        {"kaixin", EXPLOIT_KIT}, {"kelihos", TROJAN}, {"kraken", TROJAN}, {"kuluoz", TROJAN},
        {"locky", RANSOMWARE}, {"locki", RANSOMWARE},
        {"magnitude", EXPLOIT_KIT}, {"magnitudeek", EXPLOIT_KIT}, {"mask", TROJAN},
        {"matsnu", BACKDOOR}, {"mirai", WORM}, {"murofet", TROJAN},
        {"nebula", EXPLOIT_KIT}, {"necurs", TROJAN}, {"neutrino", EXPLOIT_KIT},
        {"neurtrino", EXPLOIT_KIT}, {"njrat", TROJAN}, {"nuclear", EXPLOIT_KIT},
        {"nyetya", RANSOMWARE},
        {"odin", RANSOMWARE},
        {"padcrypt", RANSOMWARE}, {"pandabanker", TROJAN}, {"petya", RANSOMWARE},
        {"pony", INFO_STEALER}, {"pseudolocker", RANSOMWARE}, {"pushdo", TROJAN}, {"pykspa", WORM},
        {"qadars", TROJAN}, {"qakbot", TROJAN}, {"qbot", TROJAN},
        {"ramdo", TROJAN}, {"ramnit", TROJAN}, {"ranbyus", TROJAN}, {"reign", APT},
        {"rig", EXPLOIT_KIT}, {"rigek", EXPLOIT_KIT}, {"rovnix", TROJAN}, {"rulan", DROPPER},
        {"seamless", EXPLOIT_KIT}, {"shiotob", TROJAN}, {"sisron", TROJAN},
        {"smokeloader", TROJAN}, {"sofacy", APT}, {"sundown", EXPLOIT_KIT},
        {"suppobox", TROJAN}, {"sweetorange", EXPLOIT_KIT}, {"symmi", TROJAN},
        {"tempedreve", WORM}, {"terdot", TROJAN}, {"terror", EXPLOIT_KIT},
        {"teslacrypt", RANSOMWARE}, {"tinba", TROJAN}, {"torrentlocker", RANSOMWARE},
        {"trickbot", TROJAN},
        {"upatre", TROJAN}, {"ursnif", TROJAN},
        {"vawtrak", TROJAN},
        {"wannacry", RANSOMWARE}, {"webcryptominer", TROJAN}, {"wirelurker", MOBILE_TROJAN},
        {"xagent", TROJAN}, {"xpiro", TROJAN},
        {"zbot", TROJAN}, {"zepto", RANSOMWARE},
        {"cryptominer", CRYPTOMINING}, {"phishing", PHISHING}, {"url", URL_C},
        {"domain", DOMAIN_C}, {"control panel", INFRASTRUCTURE}, {"exploitkit", MALWARE},
        {"gate", INFRASTRUCTURE}, {"malware", MALWARE}, {"spyware", SPYWARE},
        {"adware", ADWARE}, {"ransomware", RANSOMWARE}, {"botnet", INFRASTRUCTURE},
        {"rat", TROJAN}, {"maldoc", MALWARE},
        {"email", EMAIL_C}, {"powershell", MALWARE}, {"trojan", TROJAN},
        {"compromised", TROJAN}, {"open directory", INFRASTRUCTURE},
        {"opendirectory", INFRASTRUCTURE},
    };
    return k;
}

// Classification of the FIRST keyword found in `s` (word-boundary match).
// extract_all() does not use this: it needs the matching entry, see below.
std::optional<std::string_view> classify_keyword(std::string_view s) {
    const std::string lower = to_lower(s);
    for (const auto& entry : commonKeywordClassification()) {
        if (contains_keyword(lower, entry.keyword)) {
            LOG_TRACE("ioc: classify_keyword: matched '{}' in '{}'",
                      entry.keyword, s);
            return entry.classification;
        }
    }
    return std::nullopt;
}

const std::vector<std::pair<std::string_view, std::string_view>>& commonDefangs() {
    static const std::vector<std::pair<std::string_view, std::string_view>> d = {
        {".]]", "."}, {"[[.", "."}, {"[.", "."}, {".]", "."},
        {"[:", ":"},  {":]", ":"},  {"[@", "@"}, {"@]", "@"},
        {"[dot]", "."}, {"(dot)", "."}, {"(.)", "."},
        {"[at]", "@"},  {"(at)", "@"},  {"[://]", "://"},
    };
    return d;
}

const std::vector<std::pair<char, char>>& commonUriDefangs() {
    static const std::vector<std::pair<char, char>> d = {
        {'x', 't'}, {'X', 't'}, {'T', 't'},
    };
    return d;
}

const std::vector<std::string_view>& commonRemoveChars() {
    static const std::vector<std::string_view> c = {
        "&lt;", "&gt;", "<", ">", ",", "\n", "\t",
    };
    return c;
}

// ---------------------------------------------------------------------------
// Regexes (RE2 syntax)
//
// Every pattern that has to work on arbitrary text is case-insensitive and
// uses greedy "(label\.)+TLD" instead of the old
//   [a-z0-9\-]{1,61} | [a-z0-9\-]{1,30}\.[a-z]{2,}
// alternation: RE2 is leftmost-first, so the short first branch always won and
// "sub.example.com" was reported as "sub.example".
// ---------------------------------------------------------------------------
#define IOC_LABEL R"re([a-z0-9](?:[a-z0-9\-_]{0,61}[a-z0-9])?)re"
#define IOC_TLD   R"re((?:xn--[a-z0-9\-]{1,59}|[a-z]{2,24}))re"

const std::string_view DOMAIN_RE_RE2 =
    R"re((?i)\b(?:)re" IOC_LABEL R"re(\.)+)re" IOC_TLD R"re(\b)re";

const std::string_view DOMAIN_PORT_RE_RE2 =
    R"re((?i)\b(?:)re" IOC_LABEL R"re(\.)+)re" IOC_TLD R"re(\b(?::[0-9]{1,5})?)re";

// No leading zeros; 0-255 per octet.
const std::string_view IP_RE_RE2 =
    R"re(\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\b)re";

const std::string_view URI_RE =
    R"((?:.\w+://)?(?:[\w.\-]+(?:\.[\w.\-]+)+[\w\-._~:/?#\[\]@!$&'()*+,;=.]+))";

// http / https / hxxp / hxxps (any case), domain or IPv4 host, optional port and
// path. The path stops at whitespace, quotes and brackets instead of `.*`
// (which used to swallow the rest of the line).
const std::string_view URL_RE =
    R"re((?i)\bh(?:tt|xx)ps?://(?:(?:)re" IOC_LABEL R"re(\.)+)re" IOC_TLD
    R"re(|(?:[0-9]{1,3}\.){3}[0-9]{1,3})(?::[0-9]{1,5})?(?:/[^\s"'<>\\^`{|}\x00-\x1f]*)?)re";

const std::string_view URL_POT_RE =
    R"([a-z0-9]+(?:[-.]{1}[a-z0-9]+)*\.[a-z]{2,5}(?::[0-9]{1,5})?(?:/.*)?)";

const std::string_view HASH_TAG_RE = R"(#(\w+))";

// Two capture groups: local part, host.
const std::string_view EMAIL_RE =
    R"re((?i)([a-z0-9_.+\-]+)@((?:)re" IOC_LABEL R"re(\.)+[a-z]{2,24})\b)re";

const std::string_view MD5_RE    = R"(\b([a-fA-F\d]{32})\b)";
const std::string_view SHA1_RE   = R"(\b([a-fA-F\d]{40})\b)";
const std::string_view SHA256_RE = R"(\b([a-fA-F\d]{64})\b)";
const std::string_view SHA512_RE = R"(\b([a-fA-F\d]{128})\b)";

#undef IOC_LABEL
#undef IOC_TLD

Regexes::Regexes()
    : opts(RE2::Quiet),
      domain    (DOMAIN_RE_RE2,      opts),
      domainPort(DOMAIN_PORT_RE_RE2, opts),
      ip        (IP_RE_RE2,          opts),
      uri       (URI_RE,             opts),
      url       (URL_RE,             opts),
      urlPot    (URL_POT_RE,         opts),
      hashTag   (HASH_TAG_RE,        opts),
      email     (EMAIL_RE,           opts),
      md5       (MD5_RE,             opts),
      sha1      (SHA1_RE,            opts),
      sha256    (SHA256_RE,          opts),
      sha512    (SHA512_RE,          opts) {}

const Regexes& regexes() {
    static const Regexes r;
    return r;
}

std::unique_ptr<RE2> rexCompile(std::string_view pattern) {
    LOG_TRACE("ioc: rexCompile: compiling pattern (size={})", pattern.size());
    RE2::Options opts(RE2::Quiet);
    auto re = std::make_unique<RE2>(pattern, opts);
    if (!re->ok()) {
        LOG_WARN("ioc: rexCompile: pattern failed to compile: {}", re->error());
        return nullptr;
    }
    return re;
}

std::string replaceAll(std::string s, std::string_view from, std::string_view to) {
    if (from.empty()) return s;
    std::size_t pos = 0;
    while ((pos = s.find(from, pos)) != std::string::npos) {
        s.replace(pos, from.size(), to);
        pos += to.size();
    }
    return s;
}

std::string cleanString(std::string s) {
    for (auto c : commonRemoveChars()) {
        s = replaceAll(std::move(s), c, "");
    }
    return s;
}

std::string refang(std::string s) {
    for (const auto& [from, to] : commonDefangs()) {
        s = replaceAll(std::move(s), from, to);
    }
    return s;
}

namespace {

struct span_t {
    std::size_t pos;
    std::size_t len;
};

// RE2::FindAndConsume(&in, re, &match) returns false when `re` has fewer
// capture groups than arguments -- so with the group-less patterns above the old
// findAll() never returned a single match. Match() with an explicit submatch
// has no such restriction.
void findAllSpans(const RE2& re, std::string_view text, std::vector<span_t>& out) {
    const re2::StringPiece input(text.data(), text.size());
    re2::StringPiece match;
    std::size_t pos = 0;
    while (pos <= text.size() &&
           re.Match(input, pos, text.size(), RE2::UNANCHORED, &match, 1)) {
        const std::size_t start = static_cast<std::size_t>(match.data() - input.data());
        out.push_back({start, match.size()});
        pos = start + match.size();
        if (match.empty()) ++pos;  // never loop on an empty match
    }
}

}  // namespace

void findAll(const RE2& re, std::string_view text,
             std::vector<std::string>& out) {
    std::vector<span_t> spans;
    findAllSpans(re, text, spans);
    for (const auto& s : spans) out.emplace_back(text.substr(s.pos, s.len));
}

void findAllGroup1(const RE2& re, std::string_view text,
                   std::vector<std::string>& out) {
    re2::StringPiece input(text.data(), text.size());
    std::string capture;
    while (RE2::FindAndConsume(&input, re, &capture)) {
        out.push_back(std::move(capture));
    }
}

void findAllGroup12(const RE2& re, std::string_view text,
                    std::vector<std::pair<std::string, std::string>>& out) {
    re2::StringPiece input(text.data(), text.size());
    std::string g1, g2;
    while (RE2::FindAndConsume(&input, re, &g1, &g2)) {
        out.emplace_back(std::move(g1), std::move(g2));
    }
}

std::size_t countMatches(const RE2& re, std::string_view text) {
    std::vector<span_t> spans;
    findAllSpans(re, text, spans);
    return spans.size();
}

namespace {

// ---------------------------------------------------------------------------
// EMBER-style string indicators
//
// Verbatim port of thrember's StringExtractor pattern table (EMBER2024,
// src/thrember/features.py, groups "IOC strings" .. "Miscellaneous strings").
// The table doubles as the string-block contract for the ML feature work, so
// upstream quirks are preserved on purpose:
//   * "email_addr" carries the MAC-address pattern (upstream copy/paste bug)
//   * "registry_key" matches KHEY_/KHLM (upstream typos of HKEY_/HKLM)
//   * bare words ("file", "enum", ...) have no \b, so "file" also matches
//     inside "profile" -- exactly what the EMBER2024 dataset was built with
// Entries whose pattern is a plain literal are matched with a substring scan
// (case-insensitive ones against a lower-cased copy of the batch); the rest go
// through RE2. Most entries are bare words, so this keeps the scan cheap.
// ---------------------------------------------------------------------------

struct string_indicator_def_t {
    std::string_view name;
    std::string_view group;
    std::string_view pattern;  // RE2 source, translated from thrember's Python
    bool             ci;       // thrember compiled it with re.IGNORECASE
    std::string_view literal;  // non-empty: plain needle, searched without RE2
};

const std::vector<string_indicator_def_t>& string_indicator_defs() {
    static const std::vector<string_indicator_def_t> defs = {
        // --- IOC strings ---
        {"url", "IOC strings",
         R"re(\b(?:http|https|ftp)://[a-zA-Z0-9\-._~:?#\[\]@!$&'()*+,;=]+)re", false, {}},
        {"ipv4_addr", "IOC strings",
         R"re(\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b)re", false, {}},
        {"ipv6_addr", "IOC strings",
         R"re(\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b|\b(?:[A-Fa-f0-9]{1,4}:){1,7}:\b|\b:[A-Fa-f0-9]{1,4}(?::[A-Fa-f0-9]{1,4}){1,6}\b)re", false, {}},
        {"mac_addr", "IOC strings",
         R"re(\b(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})\b)re", false, {}},
        {"email_addr", "IOC strings",
         R"re(\b(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})\b)re", false, {}},
        {"btc_wallet", "IOC strings",
         R"re([13][a-km-zA-HJ-NP-Z1-9]{25,34})re", false, {}},

        // --- Windows strings ---
        {"file_path", "Windows strings", R"re(\bC:/)re", false, {}},
        {"dos_msg", "Windows strings", R"(!This program )", false, "!This program "},
        {"registry_key", "Windows strings", R"re(\b(?:KHEY_|KHLM|HKCU))re", false, {}},

        // --- Linux strings ---
        {"/dev/", "Linux strings", R"(/dev/)", false, "/dev/"},
        {"/proc/", "Linux strings", R"(/proc/)", false, "/proc/"},
        {"/bin/", "Linux strings", R"(/bin/)", false, "/bin/"},
        {"/usr/", "Linux strings", R"(/usr/)", false, "/usr/"},
        {"/tmp/", "Linux strings", R"(/tmp/)", false, "/tmp/"},

        // --- PDF strings ---
        {"/URI", "PDF strings", R"(/URI)", false, "/URI"},
        {"/FlateDecode", "PDF strings", R"(/FlateDecode)", false, "/FlateDecode"},
        {"/EmbeddedFile", "PDF strings", R"(/EmbeddedFile)", false, "/EmbeddedFile"},

        // --- HTML and JS strings ---
        {"html", "HTML and JS strings", R"(html)", true, "html"},
        {"javascript", "HTML and JS strings", R"(javascript)", true, "javascript"},
        {"<script", "HTML and JS strings", R"(<script)", true, "<script"},
        {".click(", "HTML and JS strings", R"re(.click)re", true, {}},
        {"onlick", "HTML and JS strings", R"(onclick)", true, "onclick"},

        // --- Powershell strings ---
        {"powershell", "Powershell strings", R"(powershell)", true, "powershell"},
        {"Invoke-Expression", "Powershell strings", R"(Invoke-Expression)", false, "Invoke-Expression"},
        {"Invoke-Command", "Powershell strings", R"(Invoke-Command)", false, "Invoke-Command"},
        {"Start-process", "Powershell strings", R"(Start-process)", false, "Start-process"},

        // --- Network strings ---
        {"get", "Network strings", R"(GET /)", true, "GET /"},
        {"post", "Network strings", R"(POST /)", true, "POST /"},
        {"http", "Network strings", R"(HTTP/)", true, "HTTP/"},
        {"http://", "Network strings", R"(http://)", true, "http://"},
        {"https://", "Network strings", R"(https://)", true, "https://"},
        {"ftp", "Network strings", R"(ftp:)", true, "ftp:"},
        {"useragent", "Network strings", R"(User-Agent)", true, "User-Agent"},
        {"cookie", "Network strings", R"(cookie)", true, "cookie"},
        {"internet", "Network strings", R"(internet)", true, "internet"},
        {"download", "Network strings", R"(download)", true, "download"},
        {"connect", "Network strings", R"(connect)", true, "connect"},

        // --- Cryptography and encoding strings ---
        {"base64", "Cryptography and encoding strings", R"(base64)", true, "base64"},
        {"base64string", "Cryptography and encoding strings",
         R"(ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/)", false,
         "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"},
        {"crypt", "Cryptography and encoding strings", R"(crypt)", false, "crypt"},
        {"encode", "Cryptography and encoding strings", R"(encode)", true, "encode"},
        {"decode", "Cryptography and encoding strings", R"(decode)", true, "decode"},

        // --- Miscellaneous strings ---
        {"cache", "Miscellaneous strings", R"(cache)", true, "cache"},
        {"certificate", "Miscellaneous strings", R"(certificate)", true, "certificate"},
        {"clipboard", "Miscellaneous strings", R"(clipboard)", true, "clipboard"},
        {"command", "Miscellaneous strings", R"(command)", true, "command"},
        {"create", "Miscellaneous strings", R"(create)", true, "create"},
        {"debug", "Miscellaneous strings", R"(debug)", true, "debug"},
        {"delete", "Miscellaneous strings", R"(delete)", true, "delete"},
        {"desktop", "Miscellaneous strings", R"(desktop)", true, "desktop"},
        {"directory", "Miscellaneous strings", R"(directory)", true, "directory"},
        {"disk", "Miscellaneous strings", R"(disk)", true, "disk"},
        {"environment", "Miscellaneous strings", R"(environment)", true, "environment"},
        {"enum", "Miscellaneous strings", R"(enum)", true, "enum"},
        {"exit", "Miscellaneous strings", R"(exit)", true, "exit"},
        {"file", "Miscellaneous strings", R"(file)", true, "file"},
        {"hostname", "Miscellaneous strings", R"(hostname)", true, "hostname"},
        {"install", "Miscellaneous strings", R"(install)", true, "install"},
        {"hidden", "Miscellaneous strings", R"(hidden)", true, "hidden"},
        {"keyboard", "Miscellaneous strings", R"(keyboard)", true, "keyboard"},
        {"memory", "Miscellaneous strings", R"(memory)", true, "memory"},
        {"module", "Miscellaneous strings", R"(module)", true, "module"},
        {"mutex", "Miscellaneous strings", R"(mutex)", true, "mutex"},
        {"password", "Miscellaneous strings", R"(password)", true, "password"},
        {"privilege", "Miscellaneous strings", R"(privilege)", true, "privilege"},
        {"process", "Miscellaneous strings", R"(process)", true, "process"},
        {"remote", "Miscellaneous strings", R"(remote)", true, "remote"},
        {"resource", "Miscellaneous strings", R"(resource)", true, "resource"},
        {"security", "Miscellaneous strings", R"(security)", true, "security"},
        {"service", "Miscellaneous strings", R"(service)", true, "service"},
        {"shell", "Miscellaneous strings", R"(shell)", true, "shell"},
        {"snapshot", "Miscellaneous strings", R"(snapshot)", true, "snapshot"},
        {"system", "Miscellaneous strings", R"(system)", true, "system"},
        {"thread", "Miscellaneous strings", R"(thread)", true, "thread"},
        {"token", "Miscellaneous strings", R"(token)", true, "token"},
        {"wallet", "Miscellaneous strings", R"(wallet)", true, "wallet"},
        {"window", "Miscellaneous strings", R"(window)", true, "window"},
    };
    return defs;
}

// One compiled entry per table row, in table order: the RE2 (compiled even for
// literal rows, so a bad pattern is reported instead of silently skipped) and
// the effective literal needle (lower-cased when ci). This RE2 build deletes
// copy and move, so the compiled pattern lives behind a unique_ptr and is
// built once, in the row's own constructor path.
struct compiled_string_indicator_t {
    const string_indicator_def_t* def = nullptr;
    std::unique_ptr<RE2> re;
    std::string needle;
};

const std::vector<compiled_string_indicator_t>& compiled_string_indicators() {
    static const std::vector<compiled_string_indicator_t> compiled = [] {
        const auto& defs = string_indicator_defs();
        std::vector<compiled_string_indicator_t> out;
        out.reserve(defs.size());
        RE2::Options opts(RE2::Quiet);
        for (const auto& def : defs) {
            std::string pattern(def.pattern);
            if (def.ci) pattern = "(?i)" + pattern;
            compiled_string_indicator_t entry;
            entry.def = &def;
            entry.re  = std::make_unique<RE2>(pattern, opts);
            if (!def.literal.empty()) {
                entry.needle = def.ci ? to_lower(def.literal)
                                      : std::string(def.literal);
            }
            out.push_back(std::move(entry));
        }
        return out;
    }();
    return compiled;
}

constexpr std::size_t kMaxStringIndicatorSamples   = 4;
constexpr std::size_t kMaxStringIndicatorSampleLen = 160;

// Evidence kept per fired pattern, bounded so a packed binary with 500k strings
// cannot blow up the report. The scan buffer is the newline-joined string list,
// so the sample is the whole string around the match (clipped): what an analyst
// wants to see, not the matched token.
void add_indicator_sample(string_indicator_hit_t& hit, const std::string& text,
                          std::size_t pos, std::size_t len) {
    if (hit.samples.size() >= kMaxStringIndicatorSamples) return;
    std::size_t begin = text.rfind('\n', pos);
    begin = (begin == std::string::npos) ? 0 : begin + 1;
    std::size_t end = text.find('\n', pos + len);
    if (end == std::string::npos) end = text.size();
    std::string sample = text.substr(begin, end - begin);
    if (sample.size() > kMaxStringIndicatorSampleLen) {
        sample.resize(kMaxStringIndicatorSampleLen);
        sample += "...";
    }
    for (const auto& existing : hit.samples) {
        if (existing == sample) return;  // the same string matched again
    }
    hit.samples.push_back(std::move(sample));
}

}  // namespace

namespace {

constexpr std::size_t kBatchTargetBytes    = 64 * 1024;
constexpr std::size_t kSingleStringThreshold = 8 * 1024;
constexpr std::size_t kMaxLocalB64Flags    = 20;
constexpr std::size_t kMaxLocalXorFlags    = 20;

bool needs_refang(const std::string& s) {
    return s.find_first_of("[](") != std::string::npos;
}

// Long base64 runs are candidates for embedded payloads / config blobs.
const RE2& base64_candidate_re() {
    static const RE2 re(R"([A-Za-z0-9+/]{32,}={0,2})", RE2::Quiet);
    return re;
}

bool base64_decode(std::string_view in, std::string& out) {
    static const std::string_view kAlphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    static const auto rev = [] {
        std::array<int, 256> r{};
        r.fill(-1);
        for (int i = 0; i < 64; ++i) r[static_cast<unsigned char>(kAlphabet[static_cast<std::size_t>(i)])] = i;
        return r;
    }();
    out.clear();
    out.reserve(in.size() * 3 / 4);
    int val = 0;
    int valb = -8;
    for (unsigned char c : in) {
        if (c == '=') break;
        const int d = rev[c];
        if (d < 0) return false;
        val = (val << 6) + d;
        valb += 6;
        if (valb >= 0) {
            out.push_back(static_cast<char>((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return !out.empty();
}

double shannon_entropy(std::string_view s) {
    if (s.empty()) return 0.0;
    std::size_t counts[256] = {};
    for (unsigned char c : s) ++counts[c];
    double ent = 0.0;
    const double n = static_cast<double>(s.size());
    for (std::size_t c : counts) {
        if (c == 0) continue;
        const double p = static_cast<double>(c) / n;
        ent -= p * std::log2(p);
    }
    return ent;
}

// Single-byte XOR crib-drag: returns true and fills `key`/`decoded`/`crib`
// for the first key byte that exposes one of the tracked plaintext cribs.
// Only called on fully-printable, high-entropy strings (see extract_all).
bool xor_crib_find(std::string_view s, int& key_out, std::string& decoded_out,
                   std::string& crib_out) {
    static constexpr std::string_view cribs[] = {
        "http://", "https://", "This program", "cmd.exe", "powershell",
        "MZ",
    };
    std::string decoded;
    decoded.reserve(s.size());
    for (int key = 1; key < 256; ++key) {
        decoded.clear();
        for (unsigned char c : s) {
            decoded.push_back(static_cast<char>(c ^ static_cast<unsigned char>(key)));
        }
        for (const std::string_view crib : cribs) {
            const std::size_t hit = decoded.find(crib);
            if (hit == std::string::npos) continue;
            key_out = key;
            decoded_out = decoded;
            crib_out = std::string(crib);
            return true;
        }
    }
    return false;
}

} // namespace

ioc_results_t extract_all(const std::vector<std::string>& strings) {
    LOG_INFO("ioc: extract_all: starting with {} input string(s)", strings.size());
    const auto started = clock_type::now();

    ioc_results_t r;

    if (strings.empty()) {
        LOG_WARN("ioc: extract_all: empty input");
        add_error(r.errors, extractor_error::empty_input,
                  "No strings provided for IOC extraction");
        return r;
    }

    const auto& re = regexes();

    // RE2::Quiet hides compile errors, so check every pattern (not just 3 of 12).
    {
        struct named { const char* name; const RE2* re; };
        const named all[] = {
            {"domain", &re.domain}, {"domainPort", &re.domainPort}, {"ip", &re.ip},
            {"uri", &re.uri}, {"url", &re.url}, {"urlPot", &re.urlPot},
            {"hashTag", &re.hashTag}, {"email", &re.email}, {"md5", &re.md5},
            {"sha1", &re.sha1}, {"sha256", &re.sha256}, {"sha512", &re.sha512},
        };
        bool failed = false;
        for (const auto& n : all) {
            if (!n.re->ok()) {
                failed = true;
                LOG_ERROR("ioc: extract_all: regex '{}' failed to compile: {}",
                          n.name, n.re->error());
                add_error(r.errors, extractor_error::regex_compile_fail,
                          std::string("regex '") + n.name + "' failed to compile: " + n.re->error());
            }
        }
        for (const auto& c : compiled_string_indicators()) {
            if (c.re->ok()) continue;
            failed = true;
            LOG_ERROR("ioc: extract_all: string indicator '{}' failed to compile: {}",
                      c.def->name, c.re->error());
            add_error(r.errors, extractor_error::regex_compile_fail,
                      "string indicator '" + std::string(c.def->name) +
                          "' failed to compile: " + c.re->error());
        }
        if (failed) return r;
        LOG_TRACE("ioc: extract_all: all {} regexes compiled OK", sizeof(all) / sizeof(all[0]));
    }

    std::unordered_set<std::string> seen_urls, seen_domains, seen_ips,
                                    seen_emails, seen_hashes, seen_keywords;

    // EMBER-style string indicators: one accumulator per table entry, kept in
    // table order so the report is stable. Only non-zero entries are promoted
    // to r.string_hits at the end.
    const auto& indicator_defs = string_indicator_defs();
    const auto& indicator_compiled = compiled_string_indicators();
    std::vector<string_indicator_hit_t> indicator_hits;
    indicator_hits.reserve(indicator_defs.size());
    for (const auto& def : indicator_defs) {
        indicator_hits.push_back({std::string(def.name), std::string(def.group), 0, {}});
    }

    std::size_t batch_count = 0;
    std::size_t refang_count = 0;
    std::size_t single_scan_count = 0;
    std::size_t hashtag_suppressed = 0;
    std::vector<encoded_flag_t> local_b64_flags;
    std::vector<std::string> hashtag_candidates;
    std::unordered_set<std::string> bare_identifiers;

    // "#word" matches C preprocessor directives (#include, #pragma), resource
    // IDs (#101), LLVM machine-function names (#ATOMIC_SWAP_I32) and printf
    // fragments in every compiler-produced binary. Keep only social-style
    // tags: alpha-start, no digits, no underscores, >= 4 chars, not a
    // preprocessor keyword. Candidates surviving these rules are checked
    // against bare identifiers after the scan: a tag whose body also appears
    // as a plain identifier in the binary is a symbol reference, not a
    // hashtag (see the post-scan filter in extract_all).
    const auto is_noise_hashtag = [&](const std::string& tag) -> bool {
        if (tag.size() < 4) return true;
        if (!is_alpha_lc(tag.front())) return true;
        if (std::any_of(tag.begin(), tag.end(),
                        [](unsigned char c) { return is_digit(c) != 0; })) {
            return true;
        }
        if (tag.find('_') != std::string::npos) return true;
        static const std::unordered_set<std::string_view> noise = {
            "include", "define", "pragma", "ifdef", "ifndef", "endif",
            "else", "elif", "undef", "error", "warning", "line",
            "region", "endregion", "import", "using", "module", "alignas",
        };
        const std::string lower_tag = to_lower(tag);
        return noise.count(lower_tag) != 0;
    };

    auto scan_batch = [&](const std::string& buf) {
        if (buf.empty()) return;
        ++batch_count;
        LOG_TRACE("ioc: scan_batch: scanning {} bytes", buf.size());

        {
            std::vector<std::string> tmp;
            findAll(re.url, buf, tmp);
            for (auto& u : tmp) {
                std::string url = finalize_url(std::move(u));
                if (seen_urls.insert(url).second) r.urls.push_back(std::move(url));
            }
        }
        {
            // Uses spans (not findAll) so is_plausible_domain can inspect the
            // characters surrounding the match -- needed to tell a real
            // domain apart from a filename / code identifier that happens to
            // end in a valid TLD (see is_plausible_domain / ambiguous_tlds).
            std::vector<span_t> spans;
            findAllSpans(re.domain, buf, spans);
            for (const auto& s : spans) {
                if (!is_plausible_domain(buf, s.pos, s.len)) continue;
                std::string lower = to_lower(buf.substr(s.pos, s.len));
                if (seen_domains.insert(lower).second) {
                    r.domains.push_back(std::move(lower));
                }
            }
        }
        {
            std::vector<span_t> spans;
            findAllSpans(re.ip, buf, spans);
            for (const auto& s : spans) {
                if (!is_plausible_ip(buf, s.pos, s.len)) continue;
                std::string ip = buf.substr(s.pos, s.len);
                if (seen_ips.insert(ip).second) r.ips.push_back(std::move(ip));
            }
        }
        {
            std::vector<std::pair<std::string, std::string>> parts;
            findAllGroup12(re.email, buf, parts);
            for (auto& [user, host] : parts) {
                std::string full = to_lower(user + "@" + host);
                if (!is_plausible_domain(host, 0, host.size())) continue;
                if (seen_emails.insert(full).second) {
                    r.emails.push_back(std::move(full));
                }
            }
        }
        {
            auto collect = [&](const RE2& regex) {
                std::vector<std::string> tmp;
                findAllGroup1(regex, buf, tmp);
                for (auto& h : tmp) {
                    std::string lower = to_lower(h);  
                    if (is_trivial_hash(lower)) continue;
                    if (seen_hashes.insert(lower).second) {
                        r.hashes.push_back(std::move(lower));
                    }
                }
            };
            collect(re.sha512);
            collect(re.sha256);
            collect(re.sha1);
            collect(re.md5);
        }
        {
            std::vector<std::string> tmp;
            findAllGroup1(re.hashTag, buf, tmp);
            for (auto& tag : tmp) {
                if (is_noise_hashtag(tag)) {
                    ++hashtag_suppressed;
                    continue;
                }
                hashtag_candidates.push_back(std::move(tag));
            }
        }

        // Local base64 candidates: long base64 runs whose decode is mostly
        // printable are embedded payloads / config blobs worth flagging
        // without any network round-trip (CyberChef scan may add more later).
        if (local_b64_flags.size() < kMaxLocalB64Flags) {
            std::vector<span_t> spans;
            findAllSpans(base64_candidate_re(), buf, spans);
            for (const auto& sp : spans) {
                if (local_b64_flags.size() >= kMaxLocalB64Flags) break;
                const std::string_view cand = buf.substr(sp.pos, sp.len);
                std::string decoded;
                if (!base64_decode(cand, decoded)) continue;
                if (decoded.size() < 24) continue;
                std::size_t printable = 0;
                for (unsigned char c : decoded) {
                    if (c >= 0x20 && c < 0x7f) ++printable;
                }
                if (printable * 10 < decoded.size() * 6) continue;  // < 60% printable
                encoded_flag_t flag;
                flag.recipe = "local-base64";
                flag.original = std::string(cand.substr(0, 96));
                flag.decoded = decoded.substr(0, 160);
                flag.indicators = {"high-printable-decode"};
                findAll(re.url, decoded, flag.urls);
                local_b64_flags.push_back(std::move(flag));
            }
        }

        // EMBER-style string indicators (see string_indicator_defs). Literal
        // entries skip RE2 entirely: case-insensitive ones search a lower-cased
        // copy of the batch (built once, on demand), case-sensitive ones search
        // the batch itself.
        {
            std::string lower_batch;
            bool lower_ready = false;
            auto lowered = [&]() -> const std::string& {
                if (!lower_ready) {
                    to_lower_into(buf, lower_batch);
                    lower_ready = true;
                }
                return lower_batch;
            };

            for (std::size_t i = 0; i < indicator_compiled.size(); ++i) {
                const compiled_string_indicator_t& entry = indicator_compiled[i];
                string_indicator_hit_t& hit = indicator_hits[i];

                if (!entry.needle.empty()) {
                    const std::string& hay = entry.def->ci ? lowered() : buf;
                    const std::string_view hay_view(hay);
                    const std::string_view needle(entry.needle);
                    std::size_t pos = hay_view.find(needle);
                    while (pos != std::string_view::npos) {
                        ++hit.count;
                        add_indicator_sample(hit, buf, pos, needle.size());
                        pos = hay_view.find(needle, pos + needle.size());
                    }
                    continue;
                }

                std::vector<span_t> spans;
                findAllSpans(*entry.re, buf, spans);
                for (const auto& s : spans) {
                    ++hit.count;
                    add_indicator_sample(hit, buf, s.pos, s.len);
                }
            }
        }
    };

    // Reports EVERY keyword that matches a string, with the keyword that actually
    // matched. The old code returned the first keyword's *class* and then looked
    // up the first table entry of that class, so "trickbot" was reported as
    // keyword=adwind.
    std::string lower_buf;
    auto classify_one = [&](const std::string& s) {
        to_lower_into(s, lower_buf);
        for (const auto& entry : commonKeywordClassification()) {
            if (!contains_keyword(lower_buf, entry.keyword)) continue;
            std::string key = std::string(entry.keyword) + "\x1f" + s;
            if (seen_keywords.insert(std::move(key)).second) {
                r.family_hits.push_back({entry.keyword, entry.classification, s});
                LOG_DEBUG("ioc: classify_one: family hit keyword='{}', class='{}'",
                          entry.keyword, entry.classification);
            }
        }
    };

    std::string              batch;
    std::vector<std::string> batch_strings;
    batch.reserve(kBatchTargetBytes + 512);

    auto flush = [&]() {
        if (batch.empty()) return;
        LOG_TRACE("ioc: flush: batch of {} bytes / {} strings",
                  batch.size(), batch_strings.size());
        scan_batch(batch);
        for (const auto& s : batch_strings) classify_one(s);
        batch.clear();
        batch_strings.clear();
    };

    std::size_t processed = 0;
    std::size_t skipped_empty = 0;
    std::size_t skipped_low_printable = 0;
    std::size_t local_xor_flags = 0;

    for (const auto& s : strings) {
        if (s.empty()) {
            ++skipped_empty;
            continue;
        }

        // Drop low-printable-ratio fragments: binary blobs that slipped
        // through the strings extractor carry no extractable IOCs and only
        // slow the regex scan down.
        {
            std::size_t printable = 0;
            for (unsigned char c : s) {
                if ((c >= 0x20 && c < 0x7f) || c == '\n' || c == '\t' || c == '\r') {
                    ++printable;
                }
            }
            if (printable * 10 < s.size() * 7) {  // < 70% printable
                ++skipped_low_printable;
                continue;
            }
        }
        ++processed;

        // Bare identifier index for the post-scan hashtag filter: a "#tag"
        // whose body also occurs as a plain identifier in the binary is a
        // symbol reference (LLVM function name, macro), not a social tag.
        if (s.size() >= 4 && s.size() <= 48 && is_alpha_lc(s.front())) {
            bool ident = true;
            for (unsigned char c : s) {
                if (!(is_alpha_lc(c) || is_digit(c) || c == '_')) {
                    ident = false;
                    break;
                }
            }
            if (ident) bare_identifiers.insert(to_lower(s));
        }

        // Entropy-gated single-byte XOR candidates: fully printable strings
        // with high Shannon entropy often store a XOR'd payload/URL. Crib for
        // known plaintexts; capped per run to bound worst-case cost.
        if (local_xor_flags < kMaxLocalXorFlags &&
            s.size() >= 32 && s.size() <= 4096 &&
            shannon_entropy(s) >= 6.0) {
            bool all_printable = true;
            for (unsigned char c : s) {
                if (c < 0x20 || c >= 0x7f) { all_printable = false; break; }
            }
            if (all_printable) {
                int key = 0;
                std::string decoded;
                std::string crib;
                if (xor_crib_find(s, key, decoded, crib)) {
                    ++local_xor_flags;
                    encoded_flag_t flag;
                    char key_hex[8];
                    std::snprintf(key_hex, sizeof(key_hex), "0x%02X", key);
                    flag.recipe = std::string("local-xor1(") + key_hex + ")";
                    flag.original = s.substr(0, 96);
                    flag.decoded = decoded.substr(0, 160);
                    flag.indicators = {crib};
                    findAll(re.url, decoded, flag.urls);
                    r.encoded_flags.push_back(std::move(flag));
                }
            }
        }

        const bool did_refang = needs_refang(s);
        if (did_refang) ++refang_count;
        const std::string scanned = did_refang ? refang(s) : s;

        if (scanned.size() > kSingleStringThreshold) {
            ++single_scan_count;
            flush();
            scan_batch(scanned);
            classify_one(s);
            continue;
        }

        if (batch.size() + scanned.size() + 1 > kBatchTargetBytes && !batch.empty()) {
            flush();
        }

        batch += scanned;
        batch += '\n';
        batch_strings.push_back(s);
    }
    flush();

    if (processed == 0) {
        LOG_WARN("ioc: extract_all: all {} strings were empty", strings.size());
        add_error(r.errors, extractor_error::empty_input,
                  "All provided strings were empty");
        return r;
    }

    for (auto& flag : local_b64_flags) {
        r.encoded_flags.push_back(std::move(flag));
    }

    // Post-scan hashtag filter: candidates whose body appears as a bare
    // identifier anywhere in the binary are symbol references, not social
    // tags (e.g. "; #ReadTB" next to LLVM's bare "ReadTB" symbols).
    {
        std::unordered_set<std::string> counted;
        for (auto& tag : hashtag_candidates) {
            if (bare_identifiers.count(to_lower(tag)) != 0) {
                ++hashtag_suppressed;
                continue;
            }
            if (counted.insert(to_lower(tag)).second) {
                ++r.num_hash_tags;
            }
        }
    }

    // Minimum two distinct hits per family keyword: one string containing a
    // family name (or worse, a generic term like "virus") is weak static
    // evidence; two independent strings are what a real family trace looks
    // like. Suppressed singles are counted and logged, never silently lost.
    std::size_t family_suppressed = 0;
    {
        std::unordered_map<std::string_view, std::size_t> counts;
        for (const auto& h : r.family_hits) ++counts[h.keyword];
        std::vector<ioc_results_t::family_hit> kept;
        kept.reserve(r.family_hits.size());
        for (const auto& h : r.family_hits) {
            if (counts[h.keyword] >= 2) kept.push_back(h);
            else ++family_suppressed;
        }
        r.family_hits = std::move(kept);
    }

    r.num_urls    = r.urls.size();
    r.num_domains = r.domains.size();
    r.num_ips     = r.ips.size();
    r.num_emails  = r.emails.size();

    for (const auto& h : r.hashes) {
        switch (h.size()) {
            case 32:  r.num_md5++;    break;
            case 40:  r.num_sha1++;   break;
            case 64:  r.num_sha256++; break;
            case 128: r.num_sha512++; break;
            default: break;
        }
    }

    for (auto& hit : indicator_hits) {
        if (hit.count == 0) continue;
        r.string_hits.push_back(std::move(hit));
    }
    LOG_DEBUG("ioc: extract_all: {} of {} string-indicator pattern(s) fired",
              r.string_hits.size(), indicator_compiled.size());

    const std::size_t total_iocs =
        r.num_urls + r.num_domains + r.num_ips +
        r.num_emails + r.hashes.size();

    if (total_iocs == 0 && r.family_hits.empty()) {
        LOG_WARN("ioc: extract_all: no IOCs found in {} processed string(s)",
                 processed);
        add_error(r.errors, extractor_error::no_matches,
                  "No IOCS has been found...");
    }

    LOG_INFO("ioc: extract_all: done in {:.3f}s — strings={} (empty={}, "
             "low-printable={}, refanged={}, single-scan={}), batches={}, "
             "urls={}, domains={}, ips={}, emails={}, hashes={} (md5={}, "
             "sha1={}, sha256={}, sha512={}), hashtags={} (suppressed={}), "
             "family_hits={} (suppressed_singles={}), "
             "encoded_flags={} (base64={}, xor={}), errors={}",
             seconds_since(started), processed, skipped_empty,
             skipped_low_printable, refang_count,
             single_scan_count, batch_count,
             r.num_urls, r.num_domains, r.num_ips, r.num_emails,
             r.hashes.size(), r.num_md5, r.num_sha1, r.num_sha256, r.num_sha512,
             r.num_hash_tags, hashtag_suppressed,
             r.family_hits.size(), family_suppressed,
             r.encoded_flags.size(), local_b64_flags.size(), local_xor_flags,
             r.errors.messages.size());

    return r;
}

bool has_errors(const ioc_results_t& result) {
    return has_errors(result.errors);
}

std::vector<std::string> get_error_messages(const ioc_results_t& result) {
    return get_error_messages(result.errors);
}

namespace {

constexpr std::size_t kMaxPrintPerCategory = 20;

void print_header(const char* label, std::size_t count) {
    std::string line = "[*] ";
    line += label;
    line += " (";
    line += std::to_string(count);
    line += ")";
    std::cout << console::paint(console::cyan, line) << "\n";
}

void print_values(const std::vector<std::string>& values, std::string_view color) {
    if (values.empty()) {
        std::cout << "    (none)\n";
        return;
    }
    std::size_t shown = 0;
    for (const auto& v : values) {
        if (shown++ >= kMaxPrintPerCategory) {
            std::string more = "    ... and "
                             + std::to_string(values.size() - kMaxPrintPerCategory)
                             + " more";
            std::cout << console::paint(console::yellow, more) << "\n";
            break;
        }
        std::cout << "    " << console::paint(color, v) << "\n";
    }
}

} 

void print_ioc_results(const ioc_results_t& r) {
    LOG_TRACE("ioc: print_ioc_results: printing {} urls, {} domains, {} ips, "
              "{} emails, {} hashes, {} family hits",
              r.num_urls, r.num_domains, r.num_ips, r.num_emails,
              r.hashes.size(), r.family_hits.size());

    std::cout << "\n";
    std::cout << console::paint(console::cyan, "=== IOC Extraction ===\n");

    if (has_errors(r.errors)) {
        for (const auto& msg : r.errors.messages) {
            std::cout << console::paint(console::yellow, "[-] " + msg) << "\n";
        }
        if (has_error(r.errors.flags, extractor_error::empty_input) ||
            has_error(r.errors.flags, extractor_error::no_matches)) {
            return;
        }
    }

    print_header("URLs", r.num_urls);
    print_values(r.urls, console::green);

    print_header("Domains", r.num_domains);
    print_values(r.domains, console::green);

    print_header("IPs", r.num_ips);
    print_values(r.ips, console::green);

    print_header("Emails", r.num_emails);
    print_values(r.emails, console::green);

    print_header("Hashes", r.hashes.size());
    if (r.num_md5 || r.num_sha1 || r.num_sha256 || r.num_sha512) {
        std::string breakdown = "    MD5: " + std::to_string(r.num_md5)
                              + "  SHA1: " + std::to_string(r.num_sha1)
                              + "  SHA256: " + std::to_string(r.num_sha256)
                              + "  SHA512: " + std::to_string(r.num_sha512);
        std::cout << console::paint(console::yellow, breakdown) << "\n";
    }
    print_values(r.hashes, console::green);

    if (r.num_hash_tags > 0) {
        print_header("Hash tags", r.num_hash_tags);
    }

    if (!r.family_hits.empty()) {
        print_header("Family matches", r.family_hits.size());
        std::size_t shown = 0;
        for (const auto& hit : r.family_hits) {
            if (shown++ >= kMaxPrintPerCategory) {
                std::cout << console::paint(console::yellow,
                    "    ... and " + std::to_string(r.family_hits.size() - kMaxPrintPerCategory) + " more") << "\n";
                break;
            }
            std::string line = "    ["
                             + std::string(hit.classification)
                             + "] keyword="
                             + std::string(hit.keyword);
            std::cout << console::paint(console::red, line) << "\n";
            std::cout << "        in: " << hit.matched_string << "\n";
        }
    }

    if (!r.string_hits.empty()) {
        print_header("String indicators", r.string_hits.size());
        std::size_t shown = 0;
        for (const auto& hit : r.string_hits) {
            if (shown++ >= kMaxPrintPerCategory) {
                std::cout << console::paint(console::yellow,
                    "    ... and " + std::to_string(r.string_hits.size() - kMaxPrintPerCategory) + " more") << "\n";
                break;
            }
            std::string line = "    [" + hit.group + "] " + hit.name
                             + " x" + std::to_string(hit.count);
            std::cout << console::paint(console::yellow, line) << "\n";
            if (!hit.samples.empty()) {
                std::cout << "        e.g. " << hit.samples.front() << "\n";
            }
        }
    }
}

std::string ioc_results_to_json(const ioc_results_t& r) {
    LOG_TRACE("ioc: ioc_results_to_json: serializing results");

    using json = nlohmann::json;
    json j;
    j["urls"]      = r.urls;
    j["domains"]   = r.domains;
    j["ips"]       = r.ips;
    j["emails"]    = r.emails;
    j["hashes"]    = r.hashes;
    j["hash_tags"] = r.num_hash_tags;
    j["counts"] = {
        {"urls",    r.num_urls},
        {"domains", r.num_domains},
        {"ips",     r.num_ips},
        {"emails",  r.num_emails},
        {"md5",     r.num_md5},
        {"sha1",    r.num_sha1},
        {"sha256",  r.num_sha256},
        {"sha512",  r.num_sha512},
    };
    j["family_hits"] = json::array();
    for (const auto& h : r.family_hits) {
        j["family_hits"].push_back({
            {"keyword",        std::string(h.keyword)},
            {"classification", std::string(h.classification)},
            {"in_string",      h.matched_string},
        });
    }
    j["string_indicators"] = json::array();
    for (const auto& h : r.string_hits) {
        j["string_indicators"].push_back({
            {"name",    h.name},
            {"group",   h.group},
            {"count",   h.count},
            {"samples", h.samples},
        });
    }
    j["errors"] = {
        {"has_errors", has_errors(r.errors)},
        {"flags",      static_cast<std::uint32_t>(r.errors.flags)},
        {"messages",   r.errors.messages},
        {"details",    r.errors.details},
    };
    return j.dump(2, ' ', false, json::error_handler_t::replace);
}

}