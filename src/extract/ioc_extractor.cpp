#include "ioc_extractor.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <memory>
#include <optional>
#include <random>
#include <string>
#include <string_view>
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

// `domain` must be lower-case.
bool is_plausible_domain(std::string_view domain) {
    if (domain.size() > 253) return false;
    const std::size_t dot = domain.rfind('.');
    if (dot == std::string_view::npos) return false;
    const std::string_view tld = domain.substr(dot + 1);
    if (tld.size() >= 4 && tld.substr(0, 4) == "xn--") return true;
    return known_tlds().count(tld) != 0;
}

// Drops IPv4 "hits" that are really version strings / reserved space.
bool is_plausible_ip(std::string_view text, std::size_t pos, std::size_t len) {
    // part of a longer dotted number, e.g. 1.2.3.4.5
    if (pos >= 2 && text[pos - 1] == '.' && is_digit(text[pos - 2])) return false;
    const std::size_t end = pos + len;
    if (end + 1 < text.size() && text[end] == '.' && is_digit(text[end + 1])) return false;

    unsigned first = 0;
    for (std::size_t i = pos; i < end && text[i] != '.'; ++i) first = first * 10 + (text[i] - '0');
    return first != 0 && first < 224;  // 0/8 and multicast/reserved/broadcast
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
        {"pony", INFO_STEALER}, {"pseudo", RANSOMWARE}, {"pushdo", TROJAN}, {"pykspa", WORM},
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
        {"rat", TROJAN}, {"c2", INFRASTRUCTURE}, {"maldoc", MALWARE},
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

constexpr std::size_t kBatchTargetBytes    = 64 * 1024;
constexpr std::size_t kSingleStringThreshold = 8 * 1024;

bool needs_refang(const std::string& s) {
    return s.find_first_of("[](") != std::string::npos;
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
        if (failed) return r;
        LOG_TRACE("ioc: extract_all: all {} regexes compiled OK", sizeof(all) / sizeof(all[0]));
    }

    std::unordered_set<std::string> seen_urls, seen_domains, seen_ips,
                                    seen_emails, seen_hashes, seen_keywords;

    std::size_t batch_count = 0;
    std::size_t refang_count = 0;
    std::size_t single_scan_count = 0;

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
            std::vector<std::string> tmp;
            findAll(re.domain, buf, tmp);
            for (auto& d : tmp) {
                std::string lower = to_lower(d);
                if (is_plausible_domain(lower) && seen_domains.insert(lower).second) {
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
                if (!is_plausible_domain(to_lower(host))) continue;
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
            r.num_hash_tags += tmp.size();
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

    for (const auto& s : strings) {
        if (s.empty()) {
            ++skipped_empty;
            continue;
        }
        ++processed;

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

    const std::size_t total_iocs =
        r.num_urls + r.num_domains + r.num_ips +
        r.num_emails + r.hashes.size();

    if (total_iocs == 0 && r.family_hits.empty()) {
        LOG_WARN("ioc: extract_all: no IOCs found in {} processed string(s)",
                 processed);
        add_error(r.errors, extractor_error::no_matches,
                  "No IOCs or family keywords found across " +
                  std::to_string(processed) + " strings");
    }

    LOG_INFO("ioc: extract_all: done in {:.3f}s — strings={} (empty={}, "
             "refanged={}, single-scan={}), batches={}, "
             "urls={}, domains={}, ips={}, emails={}, hashes={} (md5={}, "
             "sha1={}, sha256={}, sha512={}), hashtags={}, family_hits={}, "
             "errors={}",
             seconds_since(started), processed, skipped_empty, refang_count,
             single_scan_count, batch_count,
             r.num_urls, r.num_domains, r.num_ips, r.num_emails,
             r.hashes.size(), r.num_md5, r.num_sha1, r.num_sha256, r.num_sha512,
             r.num_hash_tags, r.family_hits.size(), r.errors.messages.size());

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
    j["errors"] = {
        {"has_errors", has_errors(r.errors)},
        {"flags",      static_cast<std::uint32_t>(r.errors.flags)},
        {"messages",   r.errors.messages},
        {"details",    r.errors.details},
    };
    return j.dump(2, ' ', false, json::error_handler_t::replace);
}

}