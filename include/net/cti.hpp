#pragma once

// cti: threat-intelligence collection & enrichment pipeline.
// Single consolidated header (see cti.cpp for the implementation).
// Originally split across cti_types/cti_util/http_client/cti_config/
// cti_knowledge/cti_providers/cti_pipeline/cti_export(/cti_collect).

#include <cstdint>
#include <set>
#include <string>
#include <vector>
#include <nlohmann/json.hpp>
#include <chrono>
#include <filesystem>
#include <mutex>
#include <optional>
#include <string_view>
#include <map>
#include <memory>
#include <utility>
#include <cstddef>
#include <unordered_map>
#include <functional>
#include <iosfwd>

#include "http_client.hpp"

#ifdef CTI_WITH_COLLECT
#include "extractor.hpp"
#include "ioc_extractor.hpp"
#endif

namespace cti {

// ===========================================================================
// cti_types.hpp
// ===========================================================================
using json = nlohmann::json;

enum class artifact_type { unknown, ip, domain, url, email, md5, sha1, sha256, sha512, cve, technique };

enum class verdict { unknown, benign, suspicious, malicious };

const char* to_string(artifact_type type);
const char* to_string(verdict value);
bool is_hash(artifact_type type);
bool parse_artifact_type(const std::string& text, artifact_type& out);

struct artifact {
  artifact_type type = artifact_type::unknown;
  std::string   value;                    // normalised, see normalize_artifact()
  std::set<std::string> sources;          // "ioc_extractor", "capa", "user", "derived", ...
  std::set<std::string> tags;             // caller supplied context
  std::string   derived_from;             // "domain:evil.example" when the pipeline created it

  std::string key() const { return std::string(to_string(type)) + ":" + value; }
};

struct finding {
  std::string provider;                   // "abuseipdb", "threatfox", "cisa_kev", ...
  verdict     outcome    = verdict::unknown;
  int         confidence = 0;             // 0..100: how sure the provider is about `outcome`
  double      weight     = 1.0;           // trust in this provider (set by the provider)
  std::string summary;                    // one line, human readable
  std::vector<std::string> tags;
  std::vector<std::string> families;      // malware families named by the provider
  std::vector<std::string> references;    // URLs
  json        data;                       // provider specific details (kept small)
  bool        from_cache = false;
};

struct provider_error {
  std::string provider;
  std::string message;
  long        http_status = 0;
  bool        retryable   = false;        // rate limit / timeout / 5xx: worth retrying later
};

// Everything learned about the network side of an artifact.
struct network_context {
  std::vector<std::string> resolved_ips;      // domain -> A/AAAA
  std::vector<std::string> hostnames;         // ip -> PTR, InternetDB hostnames
  std::vector<std::string> nameservers;
  std::vector<std::string> mail_servers;
  std::vector<std::string> txt_records;
  std::vector<std::string> subdomains;        // certificate transparency
  std::vector<int>         open_ports;
  std::vector<std::string> cpes;
  std::vector<std::string> vulns;             // CVE ids reported for an IP
  std::string asn, asn_name, prefix, country, org;
  std::string registrar, domain_created, domain_expires;
  // IP network details, derived from the IP and the provider-reported prefix when available.
  std::string ip_version, ip_class, cidr, subnet_mask, network_address, broadcast_address;
  int         address_bits = -1;            // 32 for IPv4, 128 for IPv6
  int         prefix_bits = -1;             // CIDR prefix length
  int         domain_age_days = -1;           // -1 = unknown
  bool        nxdomain = false;

  void merge(const network_context& other);
  bool empty() const;
};

struct enrichment {
  artifact art;
  std::vector<finding>        findings;
  std::vector<provider_error> errors;
  network_context             net;

  verdict     outcome = verdict::unknown;     // aggregated
  int         score   = 0;                    // 0..100 aggregated risk
  std::string reason;                         // why (top contributing providers)
  bool        skipped = false;
  std::string skip_reason;                    // "private address", "invalid", ...

  std::vector<std::string> families;          // union over findings
  std::vector<std::string> tags;
  json        knowledge;                      // CVE (KEV/EPSS/NVD) and technique (MITRE) details
};

// ===========================================================================
// cti_util.hpp
// ===========================================================================
// ---------------------------------------------------------------------------
// strings
// ---------------------------------------------------------------------------
std::string trim(std::string text);
std::string to_lower(std::string text);
std::string to_upper(std::string text);
bool        starts_with(std::string_view text, std::string_view prefix);
std::string env_or(const char* name, const std::string& fallback = "");
std::string url_encode(const std::string& text);          // RFC 3986 unreserved kept
std::string base64url(const std::string& bytes);          // no padding (VirusTotal URL ids)
std::string fnv_hex(const std::string& text);             // 16 hex chars, cache keys / STIX ids

// ---------------------------------------------------------------------------
// artifacts
// ---------------------------------------------------------------------------
// "hxxps://evil[.]com" -> "https://evil.com", "user[at]host(dot)tld" -> "user@host.tld"
std::string refang(std::string text);

// Cleans, validates and classifies a raw string. With `hint` the value must be valid for
// that type. Returns nullopt for anything that is not a well-formed artifact.
// Normal forms: hashes/domains/e-mails lower-case, CVE and technique ids upper-case,
// URLs with lower-case scheme and host and no fragment, IPs canonical.
std::optional<artifact> normalize_artifact(const std::string& raw,
                                           artifact_type hint = artifact_type::unknown);

std::string url_host(const std::string& url);              // "" when it has none
std::string email_domain(const std::string& email);

enum class ip_scope {
  global, private_range, loopback, link_local, multicast, carrier_grade_nat,
  documentation, unspecified, reserved, invalid
};
ip_scope    classify_ip(const std::string& ip);            // IPv4 and IPv6
bool        is_public_ip(const std::string& ip);
bool        is_ipv4(const std::string& text);
bool        is_ipv6(const std::string& text);
const char* to_string(ip_scope scope);
// 1.2.3.4 -> "4.3.2.1.in-addr.arpa"; IPv6 -> nibble form ".ip6.arpa"; "" when invalid
std::string reverse_dns_name(const std::string& ip);

// Builds deterministic IP network metadata from the address and an optional
// provider prefix such as "45.33.32.0/19".
network_context ip_network_context(const std::string& ip,
                                   const std::string& provider_prefix = {});

// "4.3.2.1" / nibbles only, without the arpa suffix (Team Cymru lookups)
std::string reverse_labels(const std::string& ip);

// ---------------------------------------------------------------------------
// time
// ---------------------------------------------------------------------------
std::int64_t now_epoch();
std::string  iso8601(std::int64_t epoch, bool millis = false);     // 2026-09-20T12:00:00Z
std::optional<std::int64_t> parse_iso8601(const std::string& text);   // also "2026-09-20"

// ---------------------------------------------------------------------------
// concurrency helpers
// ---------------------------------------------------------------------------
// Token bucket: `per_minute` sustained, `burst` immediate. acquire() blocks until allowed.
class rate_limiter {
 public:
  explicit rate_limiter(double per_minute = 60.0, int burst = 1);
  void acquire();
  // Like acquire(), but gives up (returns false, nothing consumed) if the wait would end after
  // `deadline`.
  bool acquire_until(std::chrono::steady_clock::time_point deadline);
  void set_rate(double per_minute, int burst);

 private:
  std::mutex mutex_;
  double     per_second_;
  double     capacity_;
  double     tokens_;
  std::chrono::steady_clock::time_point last_;
};

// One JSON file per (namespace, key) with a fetch timestamp. Safe for concurrent use
// (atomic rename). A disabled cache (empty directory) never stores or returns anything.
class file_cache {
 public:
  explicit file_cache(std::filesystem::path directory = {});
  bool enabled() const { return !dir_.empty(); }
  std::optional<json> get(const std::string& ns, const std::string& key, std::int64_t ttl_seconds) const;
  void put(const std::string& ns, const std::string& key, const json& value) const;
  const std::filesystem::path& directory() const { return dir_; }

 private:
  std::filesystem::path path_for(const std::string& ns, const std::string& key) const;
  std::filesystem::path dir_;
};

// ===========================================================================
// cti_config.hpp
// ===========================================================================
// API keys. Providers without a key are skipped (and listed in report::warnings), except
// the ones that work anonymously (Shodan InternetDB, RDAP, DNS-over-HTTPS, crt.sh, CIRCL
// hashlookup, EPSS, NVD, GreyNoise community).
struct api_keys {
  std::string abuseipdb;    // ABUSEIPDB_API_KEY   https://www.abuseipdb.com/account/api   (free)
  std::string otx;          // OTX_API_KEY         https://otx.alienvault.com               (free)
  std::string virustotal;   // VT_API_KEY          https://www.virustotal.com               (free, 4 req/min)
  std::string abusech;      // ABUSECH_AUTH_KEY    https://auth.abuse.ch  ThreatFox, URLhaus, MalwareBazaar (free)
  std::string greynoise;    // GREYNOISE_API_KEY   optional, raises community limits
  std::string nvd;          // NVD_API_KEY         optional, raises the NVD rate limit
};

// Base URLs. Overridable so the pipeline can be pointed at a proxy or a test server.
struct endpoints {
  std::string shodan_internetdb = "https://internetdb.shodan.io";
  std::string abuseipdb         = "https://api.abuseipdb.com/api/v2";
  std::string otx               = "https://otx.alienvault.com/api/v1";
  std::string threatfox         = "https://threatfox-api.abuse.ch/api/v1/";
  std::string urlhaus           = "https://urlhaus-api.abuse.ch/v1";
  std::string malwarebazaar     = "https://mb-api.abuse.ch/api/v1/";
  std::string virustotal        = "https://www.virustotal.com/api/v3";
  std::string greynoise         = "https://api.greynoise.io/v3/community";
  std::string circl_hashlookup  = "https://hashlookup.circl.lu";
  std::string rdap              = "https://rdap.org";
  std::string doh               = "https://cloudflare-dns.com/dns-query";
  std::string crtsh             = "https://crt.sh";
  std::string epss              = "https://api.first.org/data/v1/epss";
  std::string nvd               = "https://services.nvd.nist.gov/rest/json/cves/2.0";
  std::string cisa_kev          = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
  std::string attack_stix       = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json";
};

struct config {
  api_keys  keys;
  endpoints urls;
  http_options http;

  std::string cache_dir = "cti-cache";            // "" disables all caching (also the knowledge files)
  std::int64_t ttl_positive_hours = 24;           // provider answers
  std::int64_t ttl_negative_hours = 6;            // "not found" answers
  std::int64_t attack_max_age_hours = 24 * 7;     // re-download ATT&CK weekly
  std::int64_t kev_max_age_hours = 24;            // re-download KEV daily

  std::int64_t provider_budget_seconds = 600;     // stop querying after this long (0 = unlimited)

  bool offline = false;                           // never touch the network: cache only
  bool load_knowledge = true;                     // ATT&CK + KEV
  bool skip_non_public_ips = true;                // private / loopback / reserved are not looked up

  int         derived_rounds = 2;                 // DNS -> IPs -> ..., IP -> CVEs, OTX -> techniques
  std::size_t max_derived_artifacts = 200;
  std::size_t max_artifacts = 5000;
  std::size_t max_derived_per_artifact = 10;

  std::vector<std::string> dns_record_types = {"A", "AAAA", "NS", "MX", "TXT"};
  std::set<std::string> disabled_providers;       // by provider name, e.g. "crtsh"

  // Reads the *_API_KEY variables listed above.
  static config from_environment();
  // Overlays a JSON file: {"keys":{...},"endpoints":{...},"cache_dir":"...","offline":false,
  // "disabled_providers":["crtsh"],"dns_record_types":["A","NS"], ...}. Unknown keys are ignored.
  bool merge_json_file(const std::string& path, std::string& error);
  bool merge_json_text(const std::string& text, std::string& error);
};

// ===========================================================================
// cti_knowledge.hpp
// ===========================================================================
// ---------------------------------------------------------------------------
// MITRE ATT&CK
// ---------------------------------------------------------------------------
struct attack_group {
  std::string id;        // "G0007"
  std::string name;      // "APT28"
};

struct attack_software {
  std::string id;        // "S0002"
  std::string name;      // "Mimikatz"
  std::string type;      // "tool" | "malware"
};

struct attack_tactic {
  std::string id;        // "TA0005"
  std::string shortname; // "defense-evasion"
  std::string name;      // "Defense Evasion"
};

struct attack_technique {
  std::string id;        // "T1055" / "T1055.012"
  std::string name;
  std::string url;
  std::string parent_id; // for sub-techniques
  bool        is_subtechnique = false;
  std::vector<std::string>     tactics;     // tactic shortnames, kill-chain ordered
  std::vector<std::string>     platforms;
  std::vector<attack_group>    groups;
  std::vector<attack_software> software;
  std::size_t                  mitigation_count = 0;
};

class attack_db {
 public:
  // Parses an ATT&CK STIX bundle. Revoked / deprecated objects are ignored.
  bool load_json_text(std::string_view text, std::string& error);
  bool load_file(const std::string& path, std::string& error);

  const attack_technique* technique(const std::string& id) const;     // case-insensitive
  std::string tactic_name(const std::string& shortname) const;        // "" when unknown
  const attack_tactic* tactic(const std::string& shortname) const;
  const std::vector<attack_tactic>& tactics() const { return tactics_; }   // kill-chain order

  std::size_t technique_count() const { return techniques_.size(); }
  std::size_t group_count() const { return group_count_; }
  const std::string& version() const { return version_; }
  bool loaded() const { return !techniques_.empty(); }

 private:
  std::unordered_map<std::string, attack_technique> techniques_;
  std::vector<attack_tactic> tactics_;
  std::size_t group_count_ = 0;
  std::string version_;
};

// ---------------------------------------------------------------------------
// CISA KEV
// ---------------------------------------------------------------------------
struct kev_entry {
  std::string cve;
  std::string vendor, product, name;
  std::string date_added, due_date;
  std::string description, required_action, notes;
  bool        ransomware_use = false;           // knownRansomwareCampaignUse == "Known"
  std::vector<std::string> cwes;
};

class kev_db {
 public:
  bool load_json_text(std::string_view text, std::string& error);
  bool load_file(const std::string& path, std::string& error);

  const kev_entry* find(const std::string& cve) const;                // case-insensitive
  std::size_t size() const { return entries_.size(); }
  const std::string& catalog_version() const { return catalog_version_; }
  const std::string& date_released() const { return date_released_; }
  bool loaded() const { return !entries_.empty(); }

 private:
  std::unordered_map<std::string, kev_entry> entries_;
  std::string catalog_version_, date_released_;
};

// ---------------------------------------------------------------------------
// Download helper: makes sure `path` holds a copy of `url` no older than `max_age`.
//   * fresh file on disk           -> nothing to do
//   * offline                      -> uses whatever is on disk
//   * download fails, stale copy   -> keeps the stale copy and reports it in `warning`
// Returns false only when there is no usable file at all (see `error`).
// ---------------------------------------------------------------------------
bool refresh_file(http_client& http, const std::string& url, const std::string& path,
                  std::chrono::seconds max_age, bool offline, std::string& warning,
                  std::string& error);

// ===========================================================================
// cti_providers.hpp
// ===========================================================================
struct provider_context {
  http_client&      http;
  const file_cache& cache;
  const config&     cfg;
  bool              offline = false;
  const attack_db*  attack = nullptr;
  const kev_db*     kev = nullptr;
  // Time budget (config::provider_budget_seconds). A provider must not wait on its rate limiter
  // past it: it reports an error starting with "budget:" instead.
  std::chrono::steady_clock::time_point deadline = std::chrono::steady_clock::time_point::max();
};

struct query_result {
  std::vector<finding>        findings;
  std::vector<provider_error> errors;
  network_context             net;
  std::vector<artifact>       derived;      // new artifacts worth looking up (IPs from DNS, CVEs, ...)
  json                        knowledge;    // merged into enrichment::knowledge[provider name]
};

class provider {
 public:
  virtual ~provider() = default;

  virtual std::string name() const = 0;
  virtual bool supports(artifact_type type) const = 0;
  virtual bool configured() const { return true; }              // false: API key missing
  virtual std::string requirement() const { return {}; }        // e.g. "ABUSEIPDB_API_KEY"
  virtual int concurrency() const { return 2; }                 // worker threads for this provider
  virtual query_result query(const artifact& art, provider_context& ctx) = 0;
};

// Builds every provider (minus config::disabled_providers).
std::vector<std::unique_ptr<provider>> make_default_providers(const config& cfg);

// ===========================================================================
// cti_pipeline.hpp
// ===========================================================================
struct progress_info {
  int         round = 0;          // 0 = the collected artifacts, 1.. = follow-up rounds
  std::size_t done = 0;
  std::size_t total = 0;          // tasks in this round
  std::string provider;
  std::string artifact;           // "ip:1.2.3.4"
};
using progress_callback = std::function<void(const progress_info&)>;

struct provider_stat {
  std::string provider;
  std::size_t queries = 0;
  std::size_t answers = 0;        // queries that produced at least one finding
  std::size_t malicious = 0;
  std::size_t suspicious = 0;
  std::size_t cache_hits = 0;
  std::size_t errors = 0;
  std::size_t offline_misses = 0; // offline mode: nothing cached
};

struct family_summary {
  std::string name;
  std::vector<std::string> artifacts;     // artifact keys
  std::vector<std::string> providers;
};

struct tactic_coverage {
  std::string shortname, name;
  std::vector<std::string> techniques;    // "T1055.012 Process Hollowing"
};

struct group_match {
  std::string id, name;
  std::size_t techniques_matched = 0;
  std::vector<std::string> techniques;
};

struct shared_host {
  std::string ip;
  std::vector<std::string> domains;
  std::string asn, asn_name;
};

struct asn_cluster {
  std::string asn, asn_name;
  std::vector<std::string> ips;
};

struct report {
  std::string generated_at;
  double      seconds = 0.0;
  std::vector<enrichment> items;

  std::map<std::string, std::size_t> counts_by_type;
  std::map<std::string, std::size_t> counts_by_verdict;

  std::vector<family_summary>  families;          // most widespread first
  std::vector<tactic_coverage> attack_matrix;     // kill-chain order
  std::vector<group_match>     likely_groups;     // groups sharing the most techniques
  std::vector<shared_host>     shared_hosting;    // IPs behind >= 2 of the collected domains
  std::vector<asn_cluster>     asn_clusters;      // ASNs with >= 2 collected IPs
  std::vector<std::string>     kev_cves;          // CVEs in the CISA KEV catalog
  std::vector<provider_stat>   provider_stats;
  std::vector<std::string>     warnings;          // skipped providers, knowledge problems, ...

  std::string attack_version;
  std::string kev_version;
  json        sample;                             // caller supplied metadata about the sample

  const enrichment* find(const std::string& key) const;       // "ip:1.2.3.4"
  std::size_t error_count() const;
};

class pipeline {
 public:
  // `http` defaults to a libcurl client built from config::http.
  explicit pipeline(config cfg, std::unique_ptr<http_client> http = nullptr);
  ~pipeline();
  pipeline(const pipeline&) = delete;
  pipeline& operator=(const pipeline&) = delete;

  // Adds one artifact. The value is refanged / validated / normalised; duplicates are merged
  // (sources and tags accumulate). Returns false for values that are not artifacts.
  bool add(artifact art);
  bool add_raw(const std::string& raw, const std::string& source,
               artifact_type hint = artifact_type::unknown);
  std::size_t add_all(const std::vector<std::string>& raws, const std::string& source);

  std::size_t size() const { return items_.size(); }
  json& sample() { return sample_; }                          // copied into report::sample
  const config& configuration() const { return cfg_; }
  const std::vector<std::string>& warnings() const { return warnings_; }

  // Best-effort connectivity check. Uses HEAD so it does not download a large response.
  // Returns false for explicit offline mode, unavailable HTTP clients, DNS/connect/TLS
  // failures, and probe exceptions.
  bool network_available() const;

  // Loads ATT&CK + KEV now (run() does it otherwise). Problems become warnings.
  // Network/filesystem errors are handled as warnings; a missing connection must not
  // throw out of this method.
  bool load_knowledge();
  const attack_db& attack() const { return attack_; }
  const kev_db& kev() const { return kev_; }

  // Runs the pipeline. Network failures are reported in report::warnings and the
  // remaining local/cached analysis completes; transport errors do not throw.
  report run(const progress_callback& progress = nullptr);

 private:
  bool load_knowledge_impl();
  bool add_internal(artifact art, bool derived);
  void expand_static();
  void run_round(int round, const progress_callback& progress, std::vector<artifact>& new_derived);
  void finalize(report& out);

  config cfg_;
  std::unique_ptr<http_client> http_;
  file_cache cache_;
  std::vector<std::unique_ptr<provider>> providers_;
  attack_db attack_;
  kev_db kev_;
  bool knowledge_loaded_ = false;

  std::vector<enrichment> items_;
  std::map<std::string, std::size_t> index_;
  std::vector<std::set<std::string>> done_;             // providers already run per item
  std::map<std::string, provider_stat> stats_;
  std::vector<std::string> warnings_;
  std::size_t derived_count_ = 0;
  std::set<std::string> budget_warned_;
  std::chrono::steady_clock::time_point run_started_ = std::chrono::steady_clock::now();
  json sample_ = json::object();
};

// ===========================================================================
// cti_export.hpp
// ===========================================================================
struct json_export_options {
  int  indent = 2;                     // -1 = compact
  bool include_finding_data = true;    // provider specific details of every finding
  bool only_flagged = false;           // only suspicious / malicious artifacts (+ CVEs and techniques)
};

// Complete machine readable report (artifacts with findings, correlations, statistics).
std::string to_json(const report& r, const json_export_options& options = {});

struct stix_options {
  int  min_score = 30;                 // indicators are created for artifacts scoring at least this
  bool include_all = false;            // also benign / unknown artifacts
  bool include_techniques = true;      // attack-pattern objects for ATT&CK techniques
  std::string producer = "cti-pipeline";
};

// STIX 2.1 bundle: identity, indicators (malicious / suspicious IOCs), malware families,
// vulnerabilities (CVEs), attack patterns (ATT&CK) and the relationships between them, plus a
// report object referencing everything. Ids are deterministic (same input -> same ids).
std::string to_stix_bundle(const report& r, const stix_options& options = {});

// Human readable summary for a terminal.
void print_summary(const report& r, std::ostream& out, std::size_t max_items = 15);

#ifdef CTI_WITH_COLLECT
// ===========================================================================
// cti_collect.hpp
// ===========================================================================
// URLs, domains, IPs, e-mails and hashes of an ioc::extract_all() result; keyword family hits
// are recorded in pipeline::sample()["ioc_family_hints"]. Returns the number of NEW artifacts.
std::size_t collect_from_ioc(pipeline& p, const ioc::ioc_results_t& iocs,
                             const std::string& source = "ioc_extractor");

// Runs ioc::extract_all() on raw strings, plus a scan for CVE identifiers, then collects.
std::size_t collect_from_strings(pipeline& p, const std::vector<std::string>& strings,
                                 const std::string& source = "strings");

// Everything the extractor produced: IOCs from the strings, ATT&CK technique ids from capa
// (source "capa"), and sample metadata (packer verdict, imphash, capa capabilities) stored in
// pipeline::sample().
std::size_t collect_from_extraction(pipeline& p, const extractor::extraction_result_t& result,
                                    const std::string& source = "extractor");

// The sample's own hashes (hex strings from your hasher). Empty values are ignored.
std::size_t add_file_hashes(pipeline& p, const std::string& sha256, const std::string& md5 = "",
                            const std::string& sha1 = "");
#endif  // CTI_WITH_COLLECT

}  // namespace cti
