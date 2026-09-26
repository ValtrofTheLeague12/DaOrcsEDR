#pragma once

#include <re2/re2.h>
#include <nlohmann/json.hpp>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace ioc {

// ---------------------------------------------------------------------------
// Keyword classes (see commonKeywordClassification)
// ---------------------------------------------------------------------------
inline constexpr std::string_view TROJAN         = "trojan";
inline constexpr std::string_view BACKDOOR       = "backdoor";
inline constexpr std::string_view DROPPER        = "dropper";
inline constexpr std::string_view RANSOMWARE     = "ransomware";
inline constexpr std::string_view EXPLOIT_KIT    = "exploitkit";
inline constexpr std::string_view WORM           = "worm";
inline constexpr std::string_view VIRUS          = "virus";
inline constexpr std::string_view APT            = "apt";
inline constexpr std::string_view CRIMEWARE      = "crimeware";
inline constexpr std::string_view INFO_STEALER   = "infostealer";
inline constexpr std::string_view MOBILE_TROJAN  = "mobile_trojan";
inline constexpr std::string_view CRYPTOMINING   = "cryptomining";
inline constexpr std::string_view PHISHING       = "phishing";
inline constexpr std::string_view MALWARE        = "malware";
inline constexpr std::string_view SPYWARE        = "spyware";
inline constexpr std::string_view ADWARE         = "adware";
inline constexpr std::string_view INFRASTRUCTURE = "infrastructure";
inline constexpr std::string_view EMAIL_C        = "email";
inline constexpr std::string_view URL_C          = "url";
inline constexpr std::string_view DOMAIN_C       = "domain";
inline constexpr std::string_view DOMAIN_PORT_C  = "domain_port";

enum class extractor_error : std::uint32_t {
    none               = 0,
    invalid_input      = 1u << 0,  // reserved, not raised yet
    empty_input        = 1u << 1,  // no strings, or every string was empty
    regex_compile_fail = 1u << 2,  // one message per failing pattern, with RE2's error text
    regex_match_fail   = 1u << 3,  // reserved, not raised yet
    no_matches         = 1u << 4,  // no IOC and no family keyword found
    no_strings         = 1u << 5,  // reserved, not raised yet
    unknown            = 1u << 6,
};

inline constexpr extractor_error operator|(extractor_error a, extractor_error b) {
    return static_cast<extractor_error>(
        static_cast<std::uint32_t>(a) | static_cast<std::uint32_t>(b));
}

inline constexpr extractor_error operator&(extractor_error a, extractor_error b) {
    return static_cast<extractor_error>(
        static_cast<std::uint32_t>(a) & static_cast<std::uint32_t>(b));
}

inline extractor_error& operator|=(extractor_error& a, extractor_error b) {
    a = a | b;
    return a;
}

inline constexpr bool has_error(extractor_error flags, extractor_error e) {
    return (static_cast<std::uint32_t>(flags) &
            static_cast<std::uint32_t>(e)) != 0;
}

struct error_type_t {
    extractor_error          flags = extractor_error::none;
    std::vector<std::string> messages;  // "[error_name] detail", one per add_error()
    std::string              details;   // the details, newline separated
};

const char* error_name(extractor_error error);
void add_error(error_type_t& errors, extractor_error error, const std::string& detail);
bool has_errors(const error_type_t& errors);
std::vector<std::string> get_error_messages(const error_type_t& errors);

struct Header {
    std::string name;
    std::string value;
};

const std::vector<std::string>& userAgents();
std::vector<Header> HEADERS();


struct keyword_entry {
    std::string_view keyword;         
    std::string_view classification;  
};

const std::vector<keyword_entry>& commonKeywordClassification();
std::optional<std::string_view> classify_keyword(std::string_view s);
const std::vector<std::pair<std::string_view, std::string_view>>& commonDefangs();
const std::vector<std::pair<char, char>>& commonUriDefangs();
const std::vector<std::string_view>& commonRemoveChars();
extern const std::string_view DOMAIN_RE_RE2;
extern const std::string_view DOMAIN_PORT_RE_RE2;
extern const std::string_view IP_RE_RE2;
extern const std::string_view URI_RE;
extern const std::string_view URL_RE;
extern const std::string_view URL_POT_RE;
extern const std::string_view HASH_TAG_RE;
extern const std::string_view EMAIL_RE;
extern const std::string_view MD5_RE;
extern const std::string_view SHA1_RE;
extern const std::string_view SHA256_RE;
extern const std::string_view SHA512_RE;


struct Regexes {
    RE2::Options opts;
    RE2 domain;
    RE2 domainPort;
    RE2 ip;
    RE2 uri;
    RE2 url;
    RE2 urlPot;
    RE2 hashTag;
    RE2 email;
    RE2 md5;
    RE2 sha1;
    RE2 sha256;
    RE2 sha512;

    Regexes();
};

const Regexes& regexes();
std::unique_ptr<RE2> rexCompile(std::string_view pattern);

std::string replaceAll(std::string s, std::string_view from, std::string_view to);
std::string cleanString(std::string s);  
std::string refang(std::string s);       

void findAll(const RE2& re, std::string_view text, std::vector<std::string>& out);

void findAllGroup1(const RE2& re, std::string_view text, std::vector<std::string>& out);
void findAllGroup12(const RE2& re, std::string_view text,
                    std::vector<std::pair<std::string, std::string>>& out);
std::size_t countMatches(const RE2& re, std::string_view text);


struct ioc_results_t {
    error_type_t errors{};

    std::size_t num_urls      = 0;
    std::size_t num_domains   = 0;
    std::size_t num_ips       = 0;
    std::size_t num_emails    = 0;
    std::size_t num_md5       = 0;
    std::size_t num_sha1      = 0;
    std::size_t num_sha256    = 0;
    std::size_t num_sha512    = 0;
    std::size_t num_hash_tags = 0;

    std::vector<std::string> urls;
    std::vector<std::string> domains;
    std::vector<std::string> ips;
    std::vector<std::string> emails;
    std::vector<std::string> hashes;


    struct family_hit {
        std::string_view keyword;        
        std::string_view classification;
        std::string      matched_string; 
    };
    std::vector<family_hit> family_hits;
    // DNS lookups performed after IOC extraction, serialized by the exporter.
    std::vector<nlohmann::json> dns_results;
};


ioc_results_t extract_all(const std::vector<std::string>& strings);

bool has_errors(const ioc_results_t& result);
std::vector<std::string> get_error_messages(const ioc_results_t& result);

void print_ioc_results(const ioc_results_t& results);
std::string ioc_results_to_json(const ioc_results_t& results);

}