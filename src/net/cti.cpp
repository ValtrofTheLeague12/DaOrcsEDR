#include "cti.hpp"

#include "console.hpp"
#include "logging.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <exception>
#include <fstream>
#include <iterator>
#include <thread>
#include <chrono>
#include <mutex>
#include <filesystem>
#include <set>
#include <unordered_set>
#include <atomic>
#include <cmath>
#include <sstream>
#include <unordered_map>
#include <iomanip>
#include <iostream>


namespace cti {

// ===========================================================================
// cti_util.cpp
// ===========================================================================
// ===========================================================================
// enums / model helpers
// ===========================================================================
const char* to_string(artifact_type type) {
  switch (type) {
    case artifact_type::ip:        return "ip";
    case artifact_type::domain:    return "domain";
    case artifact_type::url:       return "url";
    case artifact_type::email:     return "email";
    case artifact_type::md5:       return "md5";
    case artifact_type::sha1:      return "sha1";
    case artifact_type::sha256:    return "sha256";
    case artifact_type::sha512:    return "sha512";
    case artifact_type::cve:       return "cve";
    case artifact_type::technique: return "technique";
    case artifact_type::unknown:   break;
  }
  return "unknown";
}

const char* to_string(verdict value) {
  switch (value) {
    case verdict::benign:     return "benign";
    case verdict::suspicious: return "suspicious";
    case verdict::malicious:  return "malicious";
    case verdict::unknown:    break;
  }
  return "unknown";
}

bool is_hash(artifact_type type) {
  return type == artifact_type::md5 || type == artifact_type::sha1 ||
         type == artifact_type::sha256 || type == artifact_type::sha512;
}

bool parse_artifact_type(const std::string& text, artifact_type& out) {
  static const artifact_type all[] = {artifact_type::ip,     artifact_type::domain, artifact_type::url,
                                      artifact_type::email,  artifact_type::md5,    artifact_type::sha1,
                                      artifact_type::sha256, artifact_type::sha512, artifact_type::cve,
                                      artifact_type::technique};
  const std::string lowered = to_lower(text);
  for (artifact_type type : all) {
    if (lowered == to_string(type)) {
      out = type;
      return true;
    }
  }
  return false;
}

namespace {

void merge_list(std::vector<std::string>& into, const std::vector<std::string>& from) {
  for (const std::string& item : from) {
    if (std::find(into.begin(), into.end(), item) == into.end()) into.push_back(item);
  }
}

}  // namespace

void network_context::merge(const network_context& o) {
  merge_list(resolved_ips, o.resolved_ips);
  merge_list(hostnames, o.hostnames);
  merge_list(nameservers, o.nameservers);
  merge_list(mail_servers, o.mail_servers);
  merge_list(txt_records, o.txt_records);
  merge_list(subdomains, o.subdomains);
  merge_list(cpes, o.cpes);
  merge_list(vulns, o.vulns);
  for (int port : o.open_ports) {
    if (std::find(open_ports.begin(), open_ports.end(), port) == open_ports.end()) open_ports.push_back(port);
  }
  auto fill = [](std::string& dst, const std::string& src) {
    if (dst.empty()) dst = src;
  };
  fill(asn, o.asn);
  fill(asn_name, o.asn_name);
  fill(prefix, o.prefix);
  fill(country, o.country);
  fill(org, o.org);
  fill(registrar, o.registrar);
  fill(domain_created, o.domain_created);
  fill(domain_expires, o.domain_expires);
  fill(ip_version, o.ip_version);
  fill(ip_class, o.ip_class);
  fill(cidr, o.cidr);
  fill(subnet_mask, o.subnet_mask);
  fill(network_address, o.network_address);
  fill(broadcast_address, o.broadcast_address);
  if (address_bits < 0) address_bits = o.address_bits;
  if (prefix_bits < 0) prefix_bits = o.prefix_bits;
  if (domain_age_days < 0) domain_age_days = o.domain_age_days;
  nxdomain = nxdomain || o.nxdomain;
}

bool network_context::empty() const {
  return resolved_ips.empty() && hostnames.empty() && nameservers.empty() && mail_servers.empty() &&
         txt_records.empty() && subdomains.empty() && open_ports.empty() && cpes.empty() &&
         vulns.empty() && asn.empty() && asn_name.empty() && prefix.empty() && country.empty() &&
         org.empty() && registrar.empty() && domain_created.empty() && domain_expires.empty() &&
         ip_version.empty() && ip_class.empty() && cidr.empty() && subnet_mask.empty() &&
         network_address.empty() && broadcast_address.empty() && address_bits < 0 && prefix_bits < 0 &&
         domain_age_days < 0 && !nxdomain;
}

// ===========================================================================
// strings
// ===========================================================================
std::string trim(std::string text) {
  const auto is_space = [](unsigned char c) { return std::isspace(c) != 0; };
  text.erase(text.begin(), std::find_if_not(text.begin(), text.end(), is_space));
  text.erase(std::find_if_not(text.rbegin(), text.rend(), is_space).base(), text.end());
  return text;
}

std::string to_lower(std::string text) {
  for (char& c : text) c = (c >= 'A' && c <= 'Z') ? static_cast<char>(c + 32) : c;
  return text;
}

std::string to_upper(std::string text) {
  for (char& c : text) c = (c >= 'a' && c <= 'z') ? static_cast<char>(c - 32) : c;
  return text;
}

bool starts_with(std::string_view text, std::string_view prefix) {
  return text.size() >= prefix.size() && text.compare(0, prefix.size(), prefix) == 0;
}

std::string env_or(const char* name, const std::string& fallback) {
  const char* value = std::getenv(name);
  return (value != nullptr && *value != '\0') ? std::string(value) : fallback;
}

std::string url_encode(const std::string& text) {
  static const char* hex = "0123456789ABCDEF";
  std::string out;
  for (unsigned char c : text) {
    if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
      out.push_back(static_cast<char>(c));
    } else {
      out.push_back('%');
      out.push_back(hex[c >> 4]);
      out.push_back(hex[c & 15]);
    }
  }
  return out;
}

std::string base64url(const std::string& bytes) {
  static const char* table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  std::string out;
  std::size_t i = 0;
  while (i + 2 < bytes.size()) {
    const std::uint32_t v = (static_cast<unsigned char>(bytes[i]) << 16) |
                            (static_cast<unsigned char>(bytes[i + 1]) << 8) |
                            static_cast<unsigned char>(bytes[i + 2]);
    out += table[(v >> 18) & 63];
    out += table[(v >> 12) & 63];
    out += table[(v >> 6) & 63];
    out += table[v & 63];
    i += 3;
  }
  if (i + 1 == bytes.size()) {
    const std::uint32_t v = static_cast<unsigned char>(bytes[i]) << 16;
    out += table[(v >> 18) & 63];
    out += table[(v >> 12) & 63];
  } else if (i + 2 == bytes.size()) {
    const std::uint32_t v = (static_cast<unsigned char>(bytes[i]) << 16) |
                            (static_cast<unsigned char>(bytes[i + 1]) << 8);
    out += table[(v >> 18) & 63];
    out += table[(v >> 12) & 63];
    out += table[(v >> 6) & 63];
  }
  return out;  // no '=' padding
}

std::string fnv_hex(const std::string& text) {
  std::uint64_t hash = 1469598103934665603ull;
  for (unsigned char c : text) {
    hash ^= c;
    hash *= 1099511628211ull;
  }
  char buffer[20];
  std::snprintf(buffer, sizeof(buffer), "%016llx", static_cast<unsigned long long>(hash));
  return buffer;
}

// ===========================================================================
// IP handling
// ===========================================================================
namespace {

bool parse_ipv4(const std::string& text, std::array<int, 4>& out) {
  std::size_t pos = 0;
  for (int i = 0; i < 4; ++i) {
    const std::size_t start = pos;
    int value = 0;
    while (pos < text.size() && text[pos] >= '0' && text[pos] <= '9') {
      value = value * 10 + (text[pos] - '0');
      if (value > 255 || pos - start > 3) return false;
      ++pos;
    }
    const std::size_t digits = pos - start;
    if (digits == 0 || (digits > 1 && text[start] == '0')) return false;  // no leading zeros
    out[static_cast<std::size_t>(i)] = value;
    if (i < 3) {
      if (pos >= text.size() || text[pos] != '.') return false;
      ++pos;
    }
  }
  return pos == text.size();
}

bool parse_ipv6(std::string text, std::array<std::uint8_t, 16>& out) {
  const std::size_t zone = text.find('%');
  if (zone != std::string::npos) text.erase(zone);
  if (text.size() < 2 || text.find(':') == std::string::npos) return false;

  std::vector<std::uint16_t> head, tail;
  std::vector<std::uint16_t>* current = &head;
  bool compressed = false;
  std::size_t i = 0;
  if (text.compare(0, 2, "::") == 0) {
    compressed = true;
    current = &tail;
    i = 2;
  } else if (text[0] == ':') {
    return false;
  }
  while (i < text.size()) {
    std::size_t end = text.find(':', i);
    const std::string group = text.substr(i, end == std::string::npos ? std::string::npos : end - i);
    if (group.empty()) return false;
    if (group.find('.') != std::string::npos) {   // embedded IPv4 in the last 32 bits
      std::array<int, 4> v4{};
      if (end != std::string::npos || !parse_ipv4(group, v4)) return false;
      current->push_back(static_cast<std::uint16_t>((v4[0] << 8) | v4[1]));
      current->push_back(static_cast<std::uint16_t>((v4[2] << 8) | v4[3]));
      break;
    }
    if (group.size() > 4) return false;
    unsigned value = 0;
    for (char c : group) {
      if (!std::isxdigit(static_cast<unsigned char>(c))) return false;
      value = value * 16 + static_cast<unsigned>(std::isdigit(static_cast<unsigned char>(c)) ? c - '0' : (std::tolower(c) - 'a' + 10));
    }
    current->push_back(static_cast<std::uint16_t>(value));
    if (end == std::string::npos) break;
    i = end + 1;
    if (i < text.size() && text[i] == ':') {   // "::" in the middle
      if (compressed) return false;
      compressed = true;
      current = &tail;
      ++i;
    } else if (i == text.size()) {
      return false;  // trailing single ':'
    }
  }
  const std::size_t total = head.size() + tail.size();
  if (compressed ? total > 7 : total != 8) return false;
  std::array<std::uint16_t, 8> groups{};
  for (std::size_t k = 0; k < head.size(); ++k) groups[k] = head[k];
  for (std::size_t k = 0; k < tail.size(); ++k) groups[8 - tail.size() + k] = tail[k];
  for (std::size_t k = 0; k < 8; ++k) {
    out[k * 2] = static_cast<std::uint8_t>(groups[k] >> 8);
    out[k * 2 + 1] = static_cast<std::uint8_t>(groups[k] & 0xff);
  }
  return true;
}

ip_scope classify_v4(const std::array<int, 4>& b) {
  if (b[0] == 0) return (b[1] == 0 && b[2] == 0 && b[3] == 0) ? ip_scope::unspecified : ip_scope::reserved;
  if (b[0] == 10) return ip_scope::private_range;
  if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return ip_scope::private_range;
  if (b[0] == 192 && b[1] == 168) return ip_scope::private_range;
  if (b[0] == 127) return ip_scope::loopback;
  if (b[0] == 169 && b[1] == 254) return ip_scope::link_local;
  if (b[0] == 100 && b[1] >= 64 && b[1] <= 127) return ip_scope::carrier_grade_nat;
  if (b[0] == 192 && b[1] == 0 && b[2] == 2) return ip_scope::documentation;
  if (b[0] == 198 && b[1] == 51 && b[2] == 100) return ip_scope::documentation;
  if (b[0] == 203 && b[1] == 0 && b[2] == 113) return ip_scope::documentation;
  if (b[0] == 192 && b[1] == 0 && b[2] == 0) return ip_scope::reserved;
  if (b[0] == 198 && (b[1] == 18 || b[1] == 19)) return ip_scope::reserved;
  if (b[0] >= 224 && b[0] <= 239) return ip_scope::multicast;
  if (b[0] >= 240) return ip_scope::reserved;
  return ip_scope::global;
}

}  // namespace

bool is_ipv4(const std::string& text) {
  std::array<int, 4> b{};
  return parse_ipv4(text, b);
}

bool is_ipv6(const std::string& text) {
  std::array<std::uint8_t, 16> b{};
  return parse_ipv6(text, b);
}

ip_scope classify_ip(const std::string& ip) {
  std::array<int, 4> v4{};
  if (parse_ipv4(ip, v4)) return classify_v4(v4);

  std::array<std::uint8_t, 16> b{};
  if (!parse_ipv6(ip, b)) return ip_scope::invalid;

  bool all_zero_prefix = true;
  for (std::size_t i = 0; i < 15; ++i) all_zero_prefix = all_zero_prefix && b[i] == 0;
  if (all_zero_prefix && b[15] == 0) return ip_scope::unspecified;
  if (all_zero_prefix && b[15] == 1) return ip_scope::loopback;

  bool mapped = true;   // ::ffff:a.b.c.d
  for (std::size_t i = 0; i < 10; ++i) mapped = mapped && b[i] == 0;
  if (mapped && b[10] == 0xff && b[11] == 0xff) {
    return classify_v4({b[12], b[13], b[14], b[15]});
  }
  if (b[0] == 0xfe && (b[1] & 0xc0) == 0x80) return ip_scope::link_local;
  if ((b[0] & 0xfe) == 0xfc) return ip_scope::private_range;
  if (b[0] == 0xff) return ip_scope::multicast;
  if (b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0d && b[3] == 0xb8) return ip_scope::documentation;
  if ((b[0] & 0xe0) == 0x20) return ip_scope::global;  // 2000::/3
  return ip_scope::reserved;
}

bool is_public_ip(const std::string& ip) { return classify_ip(ip) == ip_scope::global; }

const char* to_string(ip_scope scope) {
  switch (scope) {
    case ip_scope::global:            return "global";
    case ip_scope::private_range:     return "private range";
    case ip_scope::loopback:          return "loopback";
    case ip_scope::link_local:        return "link-local";
    case ip_scope::multicast:         return "multicast";
    case ip_scope::carrier_grade_nat: return "carrier-grade NAT";
    case ip_scope::documentation:     return "documentation range";
    case ip_scope::unspecified:       return "unspecified";
    case ip_scope::reserved:          return "reserved";
    case ip_scope::invalid:           break;
  }
  return "invalid";
}

std::string reverse_labels(const std::string& ip) {
  std::array<int, 4> v4{};
  if (parse_ipv4(ip, v4)) {
    return std::to_string(v4[3]) + "." + std::to_string(v4[2]) + "." + std::to_string(v4[1]) + "." +
           std::to_string(v4[0]);
  }
  std::array<std::uint8_t, 16> b{};
  if (!parse_ipv6(ip, b)) return {};
  static const char* hex = "0123456789abcdef";
  std::string out;
  for (int i = 15; i >= 0; --i) {
    const std::uint8_t byte = b[static_cast<std::size_t>(i)];
    out += hex[byte & 15];
    out += '.';
    out += hex[byte >> 4];
    if (i > 0) out += '.';
  }
  return out;
}

std::string format_ipv4(const std::array<int, 4>& b) {
  return std::to_string(b[0]) + "." + std::to_string(b[1]) + "." + std::to_string(b[2]) + "." + std::to_string(b[3]);
}

std::string format_ipv6(const std::array<std::uint8_t, 16>& b) {
  static const char* hex = "0123456789abcdef";
  std::array<unsigned, 8> groups{};
  for (std::size_t i = 0; i < groups.size(); ++i) {
    groups[i] = (static_cast<unsigned>(b[i * 2]) << 8) | b[i * 2 + 1];
  }

  std::size_t best_start = groups.size();
  std::size_t best_length = 0;
  for (std::size_t i = 0; i < groups.size();) {
    if (groups[i] != 0) { ++i; continue; }
    std::size_t start = i;
    while (i < groups.size() && groups[i] == 0) ++i;
    if (i - start > best_length) {
      best_start = start;
      best_length = i - start;
    }
  }

  std::string out;
  auto append_group = [&out](unsigned group) {
    if (group >= 16) out += hex[group >> 4];
    out += hex[group & 15];
  };
  if (best_length < 2) {
    for (std::size_t i = 0; i < groups.size(); ++i) {
      if (i != 0) out += ':';
      append_group(groups[i]);
    }
    return out;
  }

  for (std::size_t i = 0; i < best_start; ++i) {
    if (i != 0) out += ':';
    append_group(groups[i]);
  }
  out += "::";
  for (std::size_t i = best_start + best_length; i < groups.size(); ++i) {
    append_group(groups[i]);
    if (i + 1 != groups.size()) out += ':';
  }
  return out;
}

void populate_ip_info(network_context& net, const std::string& ip) {
  std::array<int, 4> ip4{};
  const bool v4 = parse_ipv4(ip, ip4);
  std::array<std::uint8_t, 16> ip6{};
  const bool v6 = !v4 && parse_ipv6(ip, ip6);
  if (!v4 && !v6) return;

  net.ip_version = v4 ? "IPv4" : "IPv6";
  net.address_bits = v4 ? 32 : 128;
  net.ip_class = v4 ? (ip4[0] <= 126 ? "A" : ip4[0] <= 191 ? "B" : ip4[0] <= 223 ? "C" :
                       ip4[0] <= 239 ? "D" : "E") : "IPv6";

  int bits = v4 ? 32 : 128;
  const std::size_t slash = net.prefix.find('/');
  if (slash != std::string::npos) {
    const std::string length = net.prefix.substr(slash + 1);
    if (!length.empty() && length.size() <= 3) {
      int parsed = 0;
      bool valid = true;
      for (char c : length) {
        if (c < '0' || c > '9') { valid = false; break; }
        parsed = parsed * 10 + c - '0';
      }
      if (valid && parsed >= 0 && parsed <= bits) bits = parsed;
    }
  }
  net.prefix_bits = bits;

  if (v4) {
    std::array<int, 4> network{};
    std::array<int, 4> broadcast{};
    const std::uint32_t mask = bits == 0 ? 0u : (0xffffffffu << (32 - bits));
    const std::uint32_t value = (static_cast<std::uint32_t>(ip4[0]) << 24) |
                                (static_cast<std::uint32_t>(ip4[1]) << 16) |
                                (static_cast<std::uint32_t>(ip4[2]) << 8) | ip4[3];
    const std::uint32_t network_value = value & mask;
    const std::uint32_t broadcast_value = value | ~mask;
    network = {static_cast<int>((network_value >> 24) & 255), static_cast<int>((network_value >> 16) & 255),
               static_cast<int>((network_value >> 8) & 255), static_cast<int>(network_value & 255)};
    broadcast = {static_cast<int>((broadcast_value >> 24) & 255), static_cast<int>((broadcast_value >> 16) & 255),
                 static_cast<int>((broadcast_value >> 8) & 255), static_cast<int>(broadcast_value & 255)};
    net.network_address = format_ipv4(network);
    net.broadcast_address = format_ipv4(broadcast);
    net.subnet_mask = format_ipv4({static_cast<int>((mask >> 24) & 255), static_cast<int>((mask >> 16) & 255),
                                   static_cast<int>((mask >> 8) & 255), static_cast<int>(mask & 255)});
    net.cidr = net.network_address + "/" + std::to_string(bits);
  } else {
    std::array<std::uint8_t, 16> network{};
    std::array<std::uint8_t, 16> mask{};
    for (int bit = 0; bit < 128; ++bit) {
      if (bit < bits) mask[static_cast<std::size_t>(bit / 8)] |= static_cast<std::uint8_t>(0x80u >> (bit % 8));
    }
    for (std::size_t i = 0; i < ip6.size(); ++i) network[i] = ip6[i] & mask[i];
    net.network_address = format_ipv6(network);
    net.subnet_mask = format_ipv6(mask);
    net.cidr = net.network_address + "/" + std::to_string(bits);
  }
}

network_context ip_network_context(const std::string& ip,
                                   const std::string& provider_prefix) {
  network_context net;
  net.prefix = provider_prefix;
  populate_ip_info(net, ip);
  return net;
}

std::string reverse_dns_name(const std::string& ip) {
  const std::string labels = reverse_labels(ip);
  if (labels.empty()) return {};
  return labels + (is_ipv4(ip) ? ".in-addr.arpa" : ".ip6.arpa");
}

// ===========================================================================
// artifact normalisation
// ===========================================================================
std::string refang(std::string text) {
  static const std::pair<const char*, const char*> replacements[] = {
      {"[://]", "://"}, {"[:]", ":"}, {"[.]", "."}, {"(.)", "."}, {"{.}", "."}, {"[dot]", "."},
      {"(dot)", "."},   {"[at]", "@"}, {"(at)", "@"}, {"[@]", "@"}, {".]", "."}, {"[.", "."},
  };
  for (const auto& [from, to] : replacements) {
    const std::string needle = from;
    std::size_t pos = 0;
    while ((pos = text.find(needle, pos)) != std::string::npos) {
      text.replace(pos, needle.size(), to);
      pos += std::string(to).size();
    }
  }
  // hxxp / hXXps / fxp -> real schemes (case-insensitive, scheme position only)
  const std::string lowered = to_lower(text);
  if (starts_with(lowered, "hxxp")) text.replace(0, 4, "http");
  else if (starts_with(lowered, "fxp")) text.replace(0, 3, "ftp");
  return text;
}

namespace {

bool is_hex_string(const std::string& text) {
  return !text.empty() && std::all_of(text.begin(), text.end(), [](unsigned char c) { return std::isxdigit(c) != 0; });
}

bool is_valid_domain(const std::string& domain) {
  if (domain.empty() || domain.size() > 253) return false;
  std::size_t labels = 0;
  std::size_t start = 0;
  std::string last;
  while (start <= domain.size()) {
    std::size_t end = domain.find('.', start);
    if (end == std::string::npos) end = domain.size();
    const std::string label = domain.substr(start, end - start);
    if (label.empty() || label.size() > 63 || label.front() == '-' || label.back() == '-') return false;
    for (unsigned char c : label) {
      if (!(std::isalnum(c) || c == '-' || c == '_')) return false;
    }
    last = label;
    ++labels;
    start = end + 1;
  }
  if (labels < 2) return false;
  if (starts_with(last, "xn--")) return true;
  return last.size() >= 2 && last.size() <= 24 &&
         std::all_of(last.begin(), last.end(), [](unsigned char c) { return std::isalpha(c) != 0; });
}

bool is_cve_id(const std::string& text) {   // CVE-YYYY-NNNN[N...]
  if (text.size() < 13 || text.size() > 16 || to_upper(text.substr(0, 4)) != "CVE-") return false;
  if (text[8] != '-') return false;
  for (std::size_t i = 4; i < text.size(); ++i) {
    if (i == 8) continue;
    if (!std::isdigit(static_cast<unsigned char>(text[i]))) return false;
  }
  return true;
}

bool is_technique_id(const std::string& text) {   // T1234 or T1234.567
  if (text.size() != 5 && text.size() != 9) return false;
  if (to_upper(text.substr(0, 1)) != "T") return false;
  for (std::size_t i = 1; i < 5; ++i) if (!std::isdigit(static_cast<unsigned char>(text[i]))) return false;
  if (text.size() == 9) {
    if (text[5] != '.') return false;
    for (std::size_t i = 6; i < 9; ++i) if (!std::isdigit(static_cast<unsigned char>(text[i]))) return false;
  }
  return true;
}

bool split_url(const std::string& url, std::string& scheme, std::string& host, std::string& rest,
               std::string& userinfo_and_port_prefix) {
  const std::size_t sep = url.find("://");
  if (sep == std::string::npos || sep == 0) return false;
  scheme = to_lower(url.substr(0, sep));
  for (unsigned char c : scheme) {
    if (!(std::isalnum(c) || c == '+' || c == '-' || c == '.')) return false;
  }
  const std::size_t auth_start = sep + 3;
  std::size_t auth_end = url.find_first_of("/?#", auth_start);
  if (auth_end == std::string::npos) auth_end = url.size();
  std::string authority = url.substr(auth_start, auth_end - auth_start);
  rest = url.substr(auth_end);
  const std::size_t hash_pos = rest.find('#');   // fragments are never sent to a server
  if (hash_pos != std::string::npos) rest.erase(hash_pos);

  userinfo_and_port_prefix.clear();
  const std::size_t at = authority.rfind('@');
  if (at != std::string::npos) {
    userinfo_and_port_prefix = authority.substr(0, at + 1);
    authority.erase(0, at + 1);
  }
  std::string port;
  if (!authority.empty() && authority.front() == '[') {          // [v6]:port
    const std::size_t close = authority.find(']');
    if (close == std::string::npos) return false;
    host = authority.substr(1, close - 1);
    port = authority.substr(close + 1);
  } else {
    const std::size_t colon = authority.rfind(':');
    if (colon != std::string::npos) {
      host = authority.substr(0, colon);
      port = authority.substr(colon);
    } else {
      host = authority;
    }
  }
  if (!port.empty()) {
    if (port[0] != ':' || port.size() > 6) return false;
    for (std::size_t i = 1; i < port.size(); ++i) if (!std::isdigit(static_cast<unsigned char>(port[i]))) return false;
    rest = port + rest;    // keep the port with the path, host itself stays clean
  }
  host = to_lower(host);
  return !host.empty();
}

}  // namespace

std::string url_host(const std::string& url) {
  std::string scheme, host, rest, prefix;
  return split_url(url, scheme, host, rest, prefix) ? host : std::string();
}

std::string email_domain(const std::string& email) {
  const std::size_t at = email.rfind('@');
  return at == std::string::npos ? std::string() : to_lower(email.substr(at + 1));
}

std::optional<artifact> normalize_artifact(const std::string& raw, artifact_type hint) {
  std::string text = trim(refang(trim(raw)));
  // surrounding quotes / angle brackets / trailing sentence punctuation
  while (!text.empty() && std::string("\"'<>`").find(text.front()) != std::string::npos) text.erase(text.begin());
  while (!text.empty() && std::string("\"'<>`,;:!?").find(text.back()) != std::string::npos) text.pop_back();
  if (text.empty() || text.size() > 4096) return std::nullopt;

  artifact result;
  auto finish = [&](artifact_type type, std::string value) -> std::optional<artifact> {
    if (hint != artifact_type::unknown && hint != type) return std::nullopt;
    result.type = type;
    result.value = std::move(value);
    return result;
  };

  if (text.find("://") != std::string::npos) {
    while (!text.empty() && std::string(".)]}").find(text.back()) != std::string::npos) text.pop_back();
    std::string scheme, host, rest, prefix;
    if (!split_url(text, scheme, host, rest, prefix)) return std::nullopt;
    const bool host_ok = is_ipv4(host) || is_ipv6(host) || is_valid_domain(host) || host == "localhost";
    if (!host_ok) return std::nullopt;
    const std::string shown_host = is_ipv6(host) ? "[" + host + "]" : host;
    return finish(artifact_type::url, scheme + "://" + prefix + shown_host + rest);
  }

  while (!text.empty() && std::string(".)]}").find(text.back()) != std::string::npos && text.find('@') == std::string::npos)
    text.pop_back();
  if (text.empty()) return std::nullopt;

  if (is_cve_id(text)) return finish(artifact_type::cve, to_upper(text));
  if (is_technique_id(text)) return finish(artifact_type::technique, to_upper(text));

  if (is_hex_string(text)) {
    switch (text.size()) {
      case 32:  return finish(artifact_type::md5, to_lower(text));
      case 40:  return finish(artifact_type::sha1, to_lower(text));
      case 64:  return finish(artifact_type::sha256, to_lower(text));
      case 128: return finish(artifact_type::sha512, to_lower(text));
      default: break;
    }
  }

  if (is_ipv4(text)) return finish(artifact_type::ip, text);
  if (is_ipv6(text)) return finish(artifact_type::ip, to_lower(text));

  const std::size_t at = text.find('@');
  if (at != std::string::npos) {
    if (at == 0 || text.find('@', at + 1) != std::string::npos) return std::nullopt;
    const std::string local = to_lower(text.substr(0, at));
    const std::string domain = to_lower(text.substr(at + 1));
    if (!is_valid_domain(domain)) return std::nullopt;
    for (unsigned char c : local) {
      if (!(std::isalnum(c) || std::string("._%+-").find(static_cast<char>(c)) != std::string::npos)) return std::nullopt;
    }
    return finish(artifact_type::email, local + "@" + domain);
  }

  std::string domain = to_lower(text);
  if (!domain.empty() && domain.back() == '.') domain.pop_back();
  if (is_valid_domain(domain)) return finish(artifact_type::domain, domain);
  return std::nullopt;
}

// ===========================================================================
// time
// ===========================================================================
namespace {

// Howard Hinnant's civil-date algorithms: no dependency on timegm()/_mkgmtime.
std::int64_t days_from_civil(std::int64_t y, unsigned m, unsigned d) {
  y -= m <= 2;
  const std::int64_t era = (y >= 0 ? y : y - 399) / 400;
  const unsigned yoe = static_cast<unsigned>(y - era * 400);
  const unsigned doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
  const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
  return era * 146097 + static_cast<std::int64_t>(doe) - 719468;
}

}  // namespace

std::int64_t now_epoch() {
  return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}

std::string iso8601(std::int64_t epoch, bool millis) {
  const std::time_t t = static_cast<std::time_t>(epoch);
  std::tm tm_value{};
#if defined(_WIN32)
  gmtime_s(&tm_value, &t);
#else
  gmtime_r(&t, &tm_value);
#endif
  char buffer[40];
  std::strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%S", &tm_value);
  return std::string(buffer) + (millis ? ".000Z" : "Z");
}

std::optional<std::int64_t> parse_iso8601(const std::string& text) {
  int y = 0, mo = 0, d = 0, h = 0, mi = 0;
  double s = 0;
  char tz[8] = {};
  const int n = std::sscanf(text.c_str(), "%d-%d-%dT%d:%d:%lf%7s", &y, &mo, &d, &h, &mi, &s, tz);
  if (n < 3 || y < 1970 || mo < 1 || mo > 12 || d < 1 || d > 31) return std::nullopt;
  if (n < 6) { h = mi = 0; s = 0; }
  std::int64_t epoch = days_from_civil(y, static_cast<unsigned>(mo), static_cast<unsigned>(d)) * 86400 +
                       h * 3600 + mi * 60 + static_cast<std::int64_t>(s);
  if (n >= 7 && (tz[0] == '+' || tz[0] == '-')) {   // +hh:mm offset
    int oh = 0, om = 0;
    if (std::sscanf(tz + 1, "%d:%d", &oh, &om) >= 1) {
      const std::int64_t offset = oh * 3600 + om * 60;
      epoch += tz[0] == '+' ? -offset : offset;
    }
  }
  return epoch;
}

// ===========================================================================
// rate limiter
// ===========================================================================
rate_limiter::rate_limiter(double per_minute, int burst) { set_rate(per_minute, burst); }

void rate_limiter::set_rate(double per_minute, int burst) {
  std::lock_guard<std::mutex> lock(mutex_);
  per_second_ = per_minute > 0 ? per_minute / 60.0 : 0.0;
  capacity_ = std::max(1, burst);
  tokens_ = capacity_;
  last_ = std::chrono::steady_clock::now();
}

void rate_limiter::acquire() { acquire_until(std::chrono::steady_clock::time_point::max()); }

bool rate_limiter::acquire_until(std::chrono::steady_clock::time_point deadline) {
  for (;;) {
    std::chrono::milliseconds wait{0};
    {
      std::lock_guard<std::mutex> lock(mutex_);
      if (per_second_ <= 0.0) return true;   // unlimited
      const auto now = std::chrono::steady_clock::now();
      tokens_ = std::min(capacity_, tokens_ + std::chrono::duration<double>(now - last_).count() * per_second_);
      last_ = now;
      if (tokens_ >= 1.0) {
        tokens_ -= 1.0;
        return true;
      }
      wait = std::chrono::milliseconds(static_cast<long long>((1.0 - tokens_) / per_second_ * 1000.0) + 1);
      if (deadline != std::chrono::steady_clock::time_point::max() && deadline - now < wait) return false;
    }
    std::this_thread::sleep_for(wait);
  }
}

// ===========================================================================
// file cache
// ===========================================================================
namespace fs = std::filesystem;

file_cache::file_cache(fs::path directory) : dir_(std::move(directory)) {}

fs::path file_cache::path_for(const std::string& ns, const std::string& key) const {
  const std::string hash = fnv_hex(ns + "\x1f" + key);
  return dir_ / ns / hash.substr(0, 2) / (hash + ".json");
}

std::optional<json> file_cache::get(const std::string& ns, const std::string& key, std::int64_t ttl_seconds) const {
  if (!enabled()) return std::nullopt;
  std::ifstream in(path_for(ns, key), std::ios::binary);
  if (!in) return std::nullopt;
  json envelope = json::parse(in, nullptr, false);
  if (envelope.is_discarded() || !envelope.is_object() || !envelope.contains("t") || !envelope.contains("v") ||
      !envelope.contains("k") || envelope["k"] != key) {   // "k" guards against hash collisions
    return std::nullopt;
  }
  const std::int64_t fetched = envelope["t"].is_number_integer() ? envelope["t"].get<std::int64_t>() : 0;
  if (ttl_seconds >= 0 && now_epoch() - fetched > ttl_seconds) return std::nullopt;
  return envelope["v"];
}

void file_cache::put(const std::string& ns, const std::string& key, const json& value) const {
  if (!enabled()) return;
  try {
    const fs::path target = path_for(ns, key);
    fs::create_directories(target.parent_path());
    const fs::path tmp = target.string() + "." + fnv_hex(std::to_string(now_epoch()) + key) + ".tmp";
    {
      std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
      if (!out) return;
      out << json{{"t", now_epoch()}, {"k", key}, {"v", value}}.dump();
    }
    std::error_code ec;
    fs::rename(tmp, target, ec);   // atomic replace
    if (ec) fs::remove(tmp, ec);
  } catch (const std::exception&) {
    // A cache that cannot be written is only a missed optimisation.
  }
}

config config::from_environment() {
  config cfg;
  cfg.keys.abuseipdb  = env_or("ABUSEIPDB_API_KEY");
  cfg.keys.otx        = env_or("OTX_API_KEY");
  cfg.keys.virustotal = env_or("VT_API_KEY", env_or("VIRUSTOTAL_API_KEY"));
  cfg.keys.abusech    = env_or("ABUSECH_AUTH_KEY", env_or("ABUSECH_API_KEY"));
  cfg.keys.greynoise  = env_or("GREYNOISE_API_KEY");
  cfg.keys.nvd        = env_or("NVD_API_KEY");
  cfg.http.proxy      = env_or("CTI_PROXY");
  cfg.cache_dir       = env_or("CTI_CACHE_DIR", cfg.cache_dir);
  return cfg;
}

namespace {

void set_string(const json& object, const char* key, std::string& target) {
  const auto it = object.find(key);
  if (it != object.end() && it->is_string()) target = it->get<std::string>();
}

void set_bool(const json& object, const char* key, bool& target) {
  const auto it = object.find(key);
  if (it != object.end() && it->is_boolean()) target = it->get<bool>();
}

template <class Int>
void set_int(const json& object, const char* key, Int& target) {
  const auto it = object.find(key);
  if (it != object.end() && it->is_number_integer() && it->get<long long>() >= 0) {
    target = static_cast<Int>(it->get<long long>());
  }
}

}  // namespace

bool config::merge_json_text(const std::string& text, std::string& error) {
  const json doc = json::parse(text, nullptr, /*allow_exceptions=*/false);
  if (doc.is_discarded() || !doc.is_object()) {
    error = "configuration is not a JSON object";
    return false;
  }
  if (const auto k = doc.find("keys"); k != doc.end() && k->is_object()) {
    set_string(*k, "abuseipdb", keys.abuseipdb);
    set_string(*k, "otx", keys.otx);
    set_string(*k, "virustotal", keys.virustotal);
    set_string(*k, "abusech", keys.abusech);
    set_string(*k, "greynoise", keys.greynoise);
    set_string(*k, "nvd", keys.nvd);
  }
  if (const auto e = doc.find("endpoints"); e != doc.end() && e->is_object()) {
    set_string(*e, "shodan_internetdb", urls.shodan_internetdb);
    set_string(*e, "abuseipdb", urls.abuseipdb);
    set_string(*e, "otx", urls.otx);
    set_string(*e, "threatfox", urls.threatfox);
    set_string(*e, "urlhaus", urls.urlhaus);
    set_string(*e, "malwarebazaar", urls.malwarebazaar);
    set_string(*e, "virustotal", urls.virustotal);
    set_string(*e, "greynoise", urls.greynoise);
    set_string(*e, "circl_hashlookup", urls.circl_hashlookup);
    set_string(*e, "rdap", urls.rdap);
    set_string(*e, "doh", urls.doh);
    set_string(*e, "crtsh", urls.crtsh);
    set_string(*e, "epss", urls.epss);
    set_string(*e, "nvd", urls.nvd);
    set_string(*e, "cisa_kev", urls.cisa_kev);
    set_string(*e, "attack_stix", urls.attack_stix);
  }
  if (const auto h = doc.find("http"); h != doc.end() && h->is_object()) {
    set_string(*h, "user_agent", http.user_agent);
    set_string(*h, "proxy", http.proxy);
    set_string(*h, "ca_bundle", http.ca_bundle);
    set_bool(*h, "verify_tls", http.verify_tls);
    set_int(*h, "max_retries", http.max_retries);
  }
  set_string(doc, "cache_dir", cache_dir);
  set_int(doc, "ttl_positive_hours", ttl_positive_hours);
  set_int(doc, "ttl_negative_hours", ttl_negative_hours);
  set_int(doc, "attack_max_age_hours", attack_max_age_hours);
  set_int(doc, "kev_max_age_hours", kev_max_age_hours);
  set_int(doc, "provider_budget_seconds", provider_budget_seconds);
  set_bool(doc, "offline", offline);
  set_bool(doc, "load_knowledge", load_knowledge);
  set_bool(doc, "skip_non_public_ips", skip_non_public_ips);
  set_int(doc, "derived_rounds", derived_rounds);
  set_int(doc, "max_derived_artifacts", max_derived_artifacts);
  set_int(doc, "max_artifacts", max_artifacts);
  set_int(doc, "max_derived_per_artifact", max_derived_per_artifact);
  if (const auto d = doc.find("disabled_providers"); d != doc.end() && d->is_array()) {
    for (const json& name : *d) if (name.is_string()) disabled_providers.insert(name.get<std::string>());
  }
  if (const auto d = doc.find("dns_record_types"); d != doc.end() && d->is_array()) {
    dns_record_types.clear();
    for (const json& name : *d) if (name.is_string()) dns_record_types.push_back(to_upper(name.get<std::string>()));
  }
  return true;
}

bool config::merge_json_file(const std::string& path, std::string& error) {
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    error = "cannot read " + path;
    return false;
  }
  const std::string text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
  return merge_json_text(text, error);
}

// ===========================================================================
// cti_knowledge.cpp
// ===========================================================================
namespace fs = std::filesystem;

namespace {

// Keys that are never used. Dropping them WHILE parsing keeps the ~45 MB ATT&CK bundle small
// in memory.
//
// "description" is deliberately NOT dropped any more. ATT&CK v19 moved detection guidance
// into x-mitre-analytic objects, so the description is now the only place the detection
// prose exists - dropping it left every analytic blank. The whole bundle's descriptions are
// ~6 MB of the ~53 MB file (the 21k relationship objects are the bulk), which is an
// acceptable price for the guidance the tactic view exists to show. The other keys below
// are metadata no consumer reads.
bool keep_attack_value(int, json::parse_event_t event, json& parsed) {
  if (event != json::parse_event_t::key) return true;
  static const std::set<std::string> dropped = {
      "x_mitre_detection", "x_mitre_data_sources", "x_mitre_contributors",
      "x_mitre_modified_by_ref", "object_marking_refs", "created_by_ref", "created", "modified",
      "x_mitre_attack_spec_version", "x_mitre_domains", "x_mitre_defense_bypassed",
      "x_mitre_permissions_required", "x_mitre_effective_permissions", "x_mitre_system_requirements",
      "x_mitre_impact_type", "x_mitre_remote_support", "x_mitre_tactic_type", "x_mitre_aliases",
      "x_mitre_first_seen_citation", "x_mitre_last_seen_citation"};
  return dropped.count(parsed.get_ref<const std::string&>()) == 0;
}

std::string str_of(const json& object, const char* key) {
  if (!object.is_object()) return {};
  const auto it = object.find(key);
  return (it != object.end() && it->is_string()) ? it->get<std::string>() : std::string();
}

bool flag_of(const json& object, const char* key) {
  if (!object.is_object()) return false;
  const auto it = object.find(key);
  return it != object.end() && it->is_boolean() && it->get<bool>();
}

// external_id / url of the "mitre-attack" reference
bool mitre_reference(const json& object, std::string& id, std::string& url) {
  const auto it = object.find("external_references");
  if (it == object.end() || !it->is_array()) return false;
  for (const json& ref : *it) {
    if (str_of(ref, "source_name") == "mitre-attack" && !str_of(ref, "external_id").empty()) {
      id = str_of(ref, "external_id");
      url = str_of(ref, "url");
      return true;
    }
  }
  return false;
}

// ATT&CK v19 renamed the "defense-evasion" tactic (TA0005) to "stealth" and
// added a 15th tactic, "defense-impairment" (TA0112).  The legacy spelling is
// kept in the list so an older cached feed still ranks sensibly; consumers
// (the Navigator layer) fold it onto the current name.
const std::vector<std::string>& kill_chain_order() {
  static const std::vector<std::string> order = {
      "reconnaissance", "resource-development", "initial-access", "execution", "persistence",
      "privilege-escalation", "stealth", "defense-evasion", "credential-access", "discovery",
      "lateral-movement", "collection", "command-and-control", "exfiltration", "impact",
      "defense-impairment"};
  return order;
}

std::size_t tactic_rank(const std::string& shortname) {
  const auto& order = kill_chain_order();
  const auto it = std::find(order.begin(), order.end(), shortname);
  return static_cast<std::size_t>(it - order.begin());
}

bool read_file(const std::string& path, std::string& out) {
  std::ifstream in(path, std::ios::binary);
  if (!in) return false;
  out.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
  return true;
}

}  // namespace

// ===========================================================================
// ATT&CK
// ===========================================================================
bool attack_db::load_file(const std::string& path, std::string& error) {
  std::string text;
  if (!read_file(path, text)) {
    error = "cannot read " + path;
    return false;
  }
  return load_json_text(text, error);
}

bool attack_db::load_json_text(std::string_view text, std::string& error) {
  json doc = json::parse(text.begin(), text.end(), keep_attack_value, /*allow_exceptions=*/false);
  if (doc.is_discarded() || !doc.is_object() || !doc.contains("objects") || !doc["objects"].is_array()) {
    error = "not a STIX bundle (no 'objects' array)";
    return false;
  }

  techniques_.clear();
  tactics_.clear();
  group_count_ = 0;
  version_.clear();

  std::unordered_map<std::string, std::string> technique_of;          // STIX id -> T-id
  std::unordered_map<std::string, attack_group> group_of;             // STIX id -> group
  std::unordered_map<std::string, attack_software> software_of;
  std::unordered_set<std::string> mitigations;
  // ATT&CK v19 moved detection guidance off the technique: attack-pattern objects
  // no longer carry x_mitre_detection, so it is reached through
  // `detects` -> x-mitre-detection-strategy -> x_mitre_analytic_refs -> analytic.
  std::unordered_map<std::string, attack_detection> detection_of;     // STIX id -> strategy
  std::unordered_map<std::string, attack_analytic>   analytic_of;     // STIX id -> analytic
  std::vector<std::pair<std::string, std::string>>   strategy_order;  // insertion order

  const json& objects = doc["objects"];
  for (const json& object : objects) {
    if (!object.is_object() || flag_of(object, "revoked") || flag_of(object, "x_mitre_deprecated")) continue;
    const std::string type = str_of(object, "type");
    const std::string stix_id = str_of(object, "id");
    std::string ext_id, url;

    if (type == "attack-pattern" && mitre_reference(object, ext_id, url)) {
      attack_technique tech;
      tech.id = ext_id;
      tech.name = str_of(object, "name");
      tech.url = url;
      tech.description = str_of(object, "description");
      tech.is_subtechnique = flag_of(object, "x_mitre_is_subtechnique");
      if (tech.is_subtechnique && ext_id.find('.') != std::string::npos) tech.parent_id = ext_id.substr(0, ext_id.find('.'));
      if (const auto phases = object.find("kill_chain_phases"); phases != object.end() && phases->is_array()) {
        for (const json& phase : *phases) {
          if (str_of(phase, "kill_chain_name") == "mitre-attack") tech.tactics.push_back(str_of(phase, "phase_name"));
        }
        std::sort(tech.tactics.begin(), tech.tactics.end(),
                  [](const std::string& a, const std::string& b) { return tactic_rank(a) < tactic_rank(b); });
      }
      if (const auto platforms = object.find("x_mitre_platforms"); platforms != object.end() && platforms->is_array()) {
        for (const json& p : *platforms) if (p.is_string()) tech.platforms.push_back(p.get<std::string>());
      }
      technique_of[stix_id] = ext_id;
      techniques_[ext_id] = std::move(tech);
    } else if (type == "x-mitre-tactic" && mitre_reference(object, ext_id, url)) {
      tactics_.push_back({ext_id, str_of(object, "x_mitre_shortname"), str_of(object, "name")});
    } else if (type == "intrusion-set" && mitre_reference(object, ext_id, url)) {
      group_of[stix_id] = {ext_id, str_of(object, "name")};
    } else if ((type == "malware" || type == "tool") && mitre_reference(object, ext_id, url)) {
      software_of[stix_id] = {ext_id, str_of(object, "name"), type};
    } else if (type == "course-of-action") {
      mitigations.insert(stix_id);
    } else if (type == "x-mitre-collection" && version_.empty()) {
      version_ = str_of(object, "x_mitre_version");
    } else if (type == "x-mitre-detection-strategy") {
      // The analytics are resolved in the relationship pass below, once every
      // analytic in the bundle has been seen.
      attack_detection det;
      mitre_reference(object, det.id, url);
      det.name = str_of(object, "name");
      detection_of[stix_id] = std::move(det);
      strategy_order.emplace_back(stix_id, str_of(object, "name"));
    } else if (type == "x-mitre-analytic") {
      attack_analytic an;
      mitre_reference(object, an.id, url);
      an.name = str_of(object, "name");
      an.description = str_of(object, "description");
      if (const auto platforms = object.find("x_mitre_platforms"); platforms != object.end() && platforms->is_array()) {
        for (const json& p : *platforms) if (p.is_string()) an.platforms.push_back(p.get<std::string>());
      }
      analytic_of[stix_id] = std::move(an);
    }
  }
  group_count_ = group_of.size();

  // Second pass: resolve each strategy's analytic references. Kept separate from
  // the object pass because a strategy may name an analytic defined later in the
  // bundle, and a single pass would drop it.
  for (const json& object : objects) {
    if (!object.is_object() || str_of(object, "type") != "x-mitre-detection-strategy") continue;
    if (flag_of(object, "revoked") || flag_of(object, "x_mitre_deprecated")) continue;
    const auto it = detection_of.find(str_of(object, "id"));
    if (it == detection_of.end()) continue;
    const auto refs = object.find("x_mitre_analytic_refs");
    if (refs == object.end() || !refs->is_array()) continue;
    for (const json& ref : *refs) {
      if (!ref.is_string()) continue;
      const auto a = analytic_of.find(ref.get<std::string>());
      if (a != analytic_of.end()) it->second.analytics.push_back(a->second);
    }
  }

  for (const json& object : objects) {
    if (!object.is_object() || str_of(object, "type") != "relationship" || flag_of(object, "revoked")) continue;
    const std::string kind = str_of(object, "relationship_type");
    const std::string source = str_of(object, "source_ref");
    const auto target = technique_of.find(str_of(object, "target_ref"));

    if (kind == "detects") {
      // detection-strategy --detects--> attack-pattern. Handled before the shared
      // technique lookup below because here `source_ref` is a strategy rather than
      // a group or software object, and the target still has to resolve.
      if (target == technique_of.end()) continue;
      const auto d = detection_of.find(source);
      if (d == detection_of.end() || d->second.id.empty()) continue;
      attack_technique& tech = techniques_[target->second];
      const auto same = [&](const attack_detection& x) { return x.id == d->second.id; };
      if (std::none_of(tech.detections.begin(), tech.detections.end(), same))
        tech.detections.push_back(d->second);
      continue;
    }

    if (target == technique_of.end()) continue;
    attack_technique& tech = techniques_[target->second];

    if (kind == "uses") {
      if (const auto g = group_of.find(source); g != group_of.end()) {
        const auto same = [&](const attack_group& x) { return x.id == g->second.id; };
        if (std::none_of(tech.groups.begin(), tech.groups.end(), same)) tech.groups.push_back(g->second);
      } else if (const auto s = software_of.find(source); s != software_of.end()) {
        const auto same = [&](const attack_software& x) { return x.id == s->second.id; };
        if (std::none_of(tech.software.begin(), tech.software.end(), same)) tech.software.push_back(s->second);
      }
    } else if (kind == "mitigates" && mitigations.count(source) != 0) {
      ++tech.mitigation_count;
    }
  }

  // Parent -> child ids. Everything above walks edges INTO a technique, so
  // nothing recorded the reverse direction: without this a parent technique looks
  // childless even though 475 sub-techniques hang off 101 parents.
  for (const auto& [id, tech] : techniques_) {
    if (tech.parent_id.empty()) continue;
    const auto p = techniques_.find(tech.parent_id);
    if (p == techniques_.end()) continue;
    if (std::find(p->second.subtechniques.begin(), p->second.subtechniques.end(), id) ==
        p->second.subtechniques.end())
      p->second.subtechniques.push_back(id);
  }

  // Deterministic ordering so two runs over the same sample emit identical JSON.
  for (auto& entry : techniques_) {
    std::sort(entry.second.subtechniques.begin(), entry.second.subtechniques.end());
    std::sort(entry.second.software.begin(), entry.second.software.end(),
              [](const attack_software& a, const attack_software& b) {
                if (a.type != b.type) return a.type == "tool";   // tools before malware
                return a.id < b.id;
              });
    std::sort(entry.second.detections.begin(), entry.second.detections.end(),
              [](const attack_detection& a, const attack_detection& b) { return a.name < b.name; });
  }

  std::sort(tactics_.begin(), tactics_.end(), [](const attack_tactic& a, const attack_tactic& b) {
    return tactic_rank(a.shortname) < tactic_rank(b.shortname);
  });

  if (techniques_.empty()) {
    error = "bundle contains no ATT&CK techniques";
    return false;
  }
  return true;
}

const attack_technique* attack_db::technique(const std::string& id) const {
  const auto it = techniques_.find(to_upper(id));
  return it == techniques_.end() ? nullptr : &it->second;
}

const attack_tactic* attack_db::tactic(const std::string& shortname) const {
  for (const attack_tactic& t : tactics_) {
    if (t.shortname == shortname) return &t;
  }
  return nullptr;
}

std::string attack_db::tactic_name(const std::string& shortname) const {
  const attack_tactic* t = tactic(shortname);
  return t != nullptr ? t->name : std::string();
}

// ===========================================================================
// attack_details_for: description / detection / platforms for a few techniques
// ===========================================================================
namespace {

// Pass 1 keeps only the small keys needed to tell WHICH objects are the wanted
// techniques (identity, references, name, phases, platforms). Everything big -
// description and x_mitre_detection above all - is dropped while parsing, the
// same way attack_db does it, so the 54 MB bundle stays a few MB in memory.
// The callback filters at EVERY depth, so the keys nested inside the kept
// arrays (external_references, kill_chain_phases) must be listed too - or the
// arrays survive as shells of empty objects and mitre_reference() finds
// nothing.
bool keep_detail_brief_value(int, json::parse_event_t event, json& parsed) {
  if (event != json::parse_event_t::key) return true;
  static const std::set<std::string> kept = {
      "type", "id", "objects", "external_references", "source_name", "external_id", "url",
      "name", "kill_chain_phases", "kill_chain_name", "phase_name",
      "x_mitre_platforms", "x_mitre_is_subtechnique", "revoked", "x_mitre_deprecated"};
  return kept.count(parsed.get_ref<const std::string&>()) != 0;
}

// Pass 2 state: which STIX ids (from pass 1) may keep their description.
struct detail_scan {
  const std::map<std::string, std::string>* stix_to_tid = nullptr;   // STIX id -> T-id
  bool id_pending = false; // last depth-3 key was "id"
  std::string current_id;  // STIX id of the object being parsed
};

}  // namespace

std::map<std::string, attack_detail> attack_details_for(const std::set<std::string>& wanted_ids,
                                                        const std::string& bundle_path) {
  std::map<std::string, attack_detail> out;
  if (wanted_ids.empty()) return out;

  // Resolve the cache exactly like pipeline::load_knowledge_impl() does:
  // $CTI_CACHE_DIR (default cti-cache)/knowledge/enterprise-attack.json, with
  // an empty base meaning "caching disabled" -> the temp-dir fallback. A full
  // file path may also be passed in directly.
  fs::path path;
  if (!bundle_path.empty()) path = bundle_path;
  else {
    const std::string base = env_or("CTI_CACHE_DIR", "cti-cache");
    path = base.empty() ? fs::temp_directory_path() / "cti-knowledge" / "enterprise-attack.json"
                        : fs::path(base) / "knowledge" / "enterprise-attack.json";
  }
  std::string text;
  if (!read_file(path.string(), text) || text.empty()) return out;

  std::set<std::string> want;
  for (const std::string& id : wanted_ids) want.insert(to_upper(id));

  // ---- pass 1: identity + structure, no descriptions -----------------------
  const json brief = json::parse(text.begin(), text.end(), keep_detail_brief_value,
                                 /*allow_exceptions=*/false);
  if (brief.is_discarded() || !brief.is_object() || !brief.contains("objects") ||
      !brief["objects"].is_array())
    return out;

  std::map<std::string, std::string> stix_to_tid;   // STIX id -> wanted T-id
  for (const json& object : brief["objects"]) {
    if (!object.is_object() || flag_of(object, "revoked") || flag_of(object, "x_mitre_deprecated"))
      continue;
    if (str_of(object, "type") != "attack-pattern") continue;
    std::string ext_id, url;
    if (!mitre_reference(object, ext_id, url)) continue;
    ext_id = to_upper(ext_id);
    if (want.count(ext_id) == 0 || out.count(ext_id) != 0) continue;   // first occurrence wins

    attack_detail d;
    d.name = str_of(object, "name");
    d.url = url;
    d.is_subtechnique = flag_of(object, "x_mitre_is_subtechnique");
    if (const auto phases = object.find("kill_chain_phases");
        phases != object.end() && phases->is_array()) {
      for (const json& phase : *phases) {
        if (str_of(phase, "kill_chain_name") != "mitre-attack") continue;
        std::string shortname = str_of(phase, "phase_name");
        if (!shortname.empty()) d.tactic_shortnames.push_back(std::move(shortname));
      }
      std::sort(d.tactic_shortnames.begin(), d.tactic_shortnames.end(),
                [](const std::string& a, const std::string& b) {
                  return tactic_rank(a) < tactic_rank(b);
                });
    }
    if (const auto platforms = object.find("x_mitre_platforms");
        platforms != object.end() && platforms->is_array()) {
      for (const json& p : *platforms)
        if (p.is_string()) d.platforms.push_back(p.get<std::string>());
    }
    const std::string stix_id = str_of(object, "id");
    if (!stix_id.empty()) stix_to_tid[stix_id] = ext_id;
    out.emplace(ext_id, std::move(d));
  }
  if (stix_to_tid.empty()) return out;

  // ---- pass 2: descriptions / detection for the wanted objects only --------
  // The callback keeps type/id/objects everywhere, plus description and
  // x_mitre_detection - and those two only while parsing an object whose STIX
  // id pass 1 mapped to a wanted technique. MITRE serialises "id" before
  // "description", so the decision can be made per key; a bundle that ever
  // reversed the order would only lose that one detail (callers fill absent
  // keys, so nothing breaks).
  //
  // Key depth comes from the callback itself (ref_stack.size()): for a bundle
  // the stack is [root-object, objects-array, current-object], so keys OF an
  // object in the top-level "objects" array arrive at depth 3. Tracking depth
  // by counting object_start/object_end events would be wrong - nlohmann skips
  // the object_end callback for containers it decided not to store.
  constexpr int k_object_keys = 3;
  detail_scan scan;
  scan.stix_to_tid = &stix_to_tid;
  const json texts = json::parse(
      text.begin(), text.end(),
      [&scan, k_object_keys](int depth, json::parse_event_t event, json& parsed) -> bool {
        if (event == json::parse_event_t::key) {
          const std::string& key = parsed.get_ref<const std::string&>();
          if (key == "description" || key == "x_mitre_detection")
            return depth == k_object_keys && scan.stix_to_tid->count(scan.current_id) != 0;
          if (depth == k_object_keys && key == "id") scan.id_pending = true;
          return key == "type" || key == "id" || key == "objects";
        }
        if (event == json::parse_event_t::value && scan.id_pending) {
          // the value of a depth-3 "id" key: the STIX id of the current object
          scan.id_pending = false;
          if (parsed.is_string()) scan.current_id = parsed.get<std::string>();
        }
        return true;   // objects and arrays are structure, keep them
      },
      /*allow_exceptions=*/false);
  if (texts.is_discarded() || !texts.is_object() || !texts.contains("objects") ||
      !texts["objects"].is_array())
    return out;

  for (const json& object : texts["objects"]) {
    if (!object.is_object()) continue;
    const auto map_it = stix_to_tid.find(str_of(object, "id"));
    if (map_it == stix_to_tid.end()) continue;
    attack_detail& d = out[map_it->second];
    if (d.description.empty()) d.description = str_of(object, "description");
    if (d.detection.empty())   d.detection   = str_of(object, "x_mitre_detection");
  }
  return out;
}

// ===========================================================================
// mbc_details_for: name / objective / description for a few MBC ids
// ---------------------------------------------------------------------------
// The Malware Behavior Catalog ships in-repo as a STIX 2.1 bundle
// (mbc-stix2.1/mbc/mbc.json, ~2.5 MB: malware-behavior, malware-method and
// malware-objective objects). This turns the bare MBC ids capa tags onto its
// matches (C0007, B0032, E1056, ...) into the catalog entry behind them, so
// the terminal, the exported capa.json and the dashboard can show
// "C0007 Virtual Memory Operations" instead of a cryptic code. Offline by
// construction - a missing bundle is an empty result, never an error.
// ===========================================================================
namespace {

// Candidate locations, in order: explicit argument, $MBC_BUNDLE, the
// knowledge cache (mirroring enterprise-attack.json), then the vendored STIX
// tree that ships in the repo. Empty return means "bundle not found".
fs::path resolve_mbc_bundle(const std::string& bundle_path) {
  if (!bundle_path.empty()) return bundle_path;
  if (const std::string env = env_or("MBC_BUNDLE", ""); !env.empty()) return env;
  const std::string base = env_or("CTI_CACHE_DIR", "cti-cache");
  if (!base.empty()) {
    const fs::path cached = fs::path(base) / "knowledge" / "mbc.json";
    std::error_code ec;
    if (fs::exists(cached, ec) && !ec) return cached;
  }
  for (const char* candidate : {"mbc-stix2.1/mbc/mbc.json"}) {
    std::error_code ec;
    if (fs::exists(candidate, ec) && !ec) return candidate;
  }
  return {};
}

// T-ids embedded in MBC prose ("See ATT&CK: **Input Capture ([T1056](...))**").
// A tiny fixed-shape scanner rather than <regex>: it runs once per process on
// a few KB of description text, and the boundary check keeps ids inside longer
// tokens ("STIX1056") from matching.
std::vector<std::string> scrape_attack_ids(std::string_view text) {
  std::vector<std::string> out;
  const auto is_digit = [](char c) { return c >= '0' && c <= '9'; };
  const auto is_alnum = [](char c) {
    return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
  };
  for (std::size_t i = 0;; ++i) {
    if (i + 4 >= text.size()) break;
    if (text[i] != 'T') continue;
    if (!is_digit(text[i + 1]) || !is_digit(text[i + 2]) ||
        !is_digit(text[i + 3]) || !is_digit(text[i + 4]))
      continue;
    if (i > 0 && is_alnum(text[i - 1])) continue;   // part of a longer token
    std::size_t len = 5;
    if (i + 8 < text.size() && text[i + 5] == '.' && is_digit(text[i + 6]) &&
        is_digit(text[i + 7]) && is_digit(text[i + 8]))
      len = 9;
    out.emplace_back(text.substr(i, len));
    i += len - 1;
  }
  return out;
}

// Builds the full upper-case-id -> detail index from the bundle. Behaviors
// overwrite (their entries carry objectives directly); methods only fill gaps
// and inherit objectives through behavior_ref, so a stray id collision keeps
// the behavior entry.
std::map<std::string, mbc_detail> build_mbc_index(const fs::path& path) {
  std::map<std::string, mbc_detail> index;
  std::string text;
  if (!read_file(path.string(), text) || text.empty()) {
    LOG_WARN("mbc: build_mbc_index: cannot read '{}'", path.string());
    return index;
  }
  const json doc = json::parse(text.begin(), text.end(), nullptr, /*allow_exceptions=*/false);
  if (doc.is_discarded() || !doc.is_object() || !doc.contains("objects") ||
      !doc["objects"].is_array()) {
    LOG_WARN("mbc: build_mbc_index: '{}' is not a STIX bundle", path.string());
    return index;
  }
  const json& objects = doc["objects"];

  // Pass 1a: objectives (STIX id -> "Execution"). Must complete before
  // behaviors are read - objective_refs are STIX ids resolved by name here.
  std::map<std::string, std::string> objective_names;
  for (const json& object : objects) {
    if (!object.is_object() || str_of(object, "type") != "malware-objective") continue;
    const std::string stix_id = str_of(object, "id");
    const std::string name = str_of(object, "name");
    if (!stix_id.empty() && !name.empty()) objective_names[stix_id] = name;
  }

  // Pass 1b: behaviors' STIX id -> objective names / external id / name, so
  // methods (parsed in pass 2) can inherit through behavior_ref.
  std::map<std::string, std::vector<std::string>> behavior_objectives;
  std::map<std::string, std::string> behavior_ids;    // STIX id -> "B0012"
  std::map<std::string, std::string> behavior_names;  // STIX id -> name
  for (const json& object : objects) {
    if (!object.is_object() || str_of(object, "type") != "malware-behavior") continue;
    const std::string stix_id = str_of(object, "id");
    if (stix_id.empty()) continue;
    behavior_names[stix_id] = str_of(object, "name");
    const auto defn = object.find("obj_defn");
    if (defn != object.end() && defn->is_object())
      behavior_ids[stix_id] = str_of(*defn, "external_id");
    if (const auto refs = object.find("objective_refs");
        refs != object.end() && refs->is_array()) {
      for (const json& ref : *refs) {
        if (!ref.is_string()) continue;
        const auto it = objective_names.find(ref.get<std::string>());
        if (it != objective_names.end()) behavior_objectives[stix_id].push_back(it->second);
      }
    }
  }

  // Pass 2: behaviors, then methods.
  for (int pass = 0; pass < 2; ++pass) {
    const char* want = pass == 0 ? "malware-behavior" : "malware-method";
    for (const json& object : objects) {
      if (!object.is_object() || str_of(object, "type") != want) continue;
      const auto defn = object.find("obj_defn");
      if (defn == object.end() || !defn->is_object()) continue;
      const std::string ext_id = str_of(*defn, "external_id");
      if (ext_id.empty()) continue;

      mbc_detail d;
      d.id = to_upper(ext_id);
      d.kind = pass == 0 ? "behavior" : "method";
      d.name = str_of(object, "name");
      d.description = str_of(*defn, "description");
      d.url = str_of(*defn, "url");

      const std::string stix_id = str_of(object, "id");
      if (pass == 0) {
        d.objectives = behavior_objectives[stix_id];
      } else if (const auto ref = object.find("behavior_ref");
                 ref != object.end() && ref->is_string()) {
        const std::string parent = ref->get<std::string>();
        d.objectives = behavior_objectives[parent];
        const auto pid = behavior_ids.find(parent);
        if (pid != behavior_ids.end() && !pid->second.empty()) {
          d.parent = pid->second;
          const auto pname = behavior_names.find(parent);
          if (pname != behavior_names.end() && !pname->second.empty())
            d.parent += " " + pname->second;
          // methods carry no obj_defn.url of their own - reuse the parent
          // behavior's mbc-markdown page so the dashboard chip stays linkable.
          if (d.url.empty()) {
            const auto found = index.find(to_upper(pid->second));
            if (found != index.end()) d.url = found->second.url;
          }
        }
      }
      if (const auto rules = object.find("detection_rules");
          rules != object.end() && rules->is_array())
        d.detection_rules = rules->size();

      d.attack_ids = scrape_attack_ids(d.description);
      std::sort(d.attack_ids.begin(), d.attack_ids.end());
      d.attack_ids.erase(std::unique(d.attack_ids.begin(), d.attack_ids.end()),
                         d.attack_ids.end());

      if (pass == 0) index[d.id] = std::move(d);        // behaviors win collisions
      else          index.try_emplace(d.id, std::move(d));
    }
  }
  LOG_DEBUG("mbc: build_mbc_index: indexed {} entr(y|ies) from '{}'",
            index.size(), path.string());
  return index;
}

}  // namespace

std::map<std::string, mbc_detail> mbc_details_for(const std::set<std::string>& wanted_ids,
                                                  const std::string& bundle_path) {
  std::map<std::string, mbc_detail> out;
  if (wanted_ids.empty()) return out;

  // The catalog is small enough to index fully; the index is built once per
  // process. An explicit bundle_path bypasses the shared cache so a caller
  // (tests, one-off tools) can point at a fixture without poisoning it.
  static std::map<std::string, mbc_detail> index;
  static bool loaded = false;

  const std::map<std::string, mbc_detail>* source = nullptr;
  std::map<std::string, mbc_detail> scratch;
  if (!bundle_path.empty()) {
    scratch = build_mbc_index(resolve_mbc_bundle(bundle_path));
    source = &scratch;
  } else {
    if (!loaded) {
      const fs::path path = resolve_mbc_bundle(bundle_path);
      if (!path.empty()) index = build_mbc_index(path);
      else LOG_DEBUG("mbc: mbc_details_for: no MBC bundle found (set $MBC_BUNDLE)");
      loaded = true;
    }
    source = &index;
  }

  for (const std::string& raw : wanted_ids) {
    const auto it = source->find(to_upper(raw));
    if (it != source->end()) out.emplace(it->first, it->second);
  }
  LOG_TRACE("mbc: mbc_details_for: {} wanted, {} resolved", wanted_ids.size(), out.size());
  return out;
}

// ===========================================================================
// CISA KEV
// ===========================================================================
bool kev_db::load_file(const std::string& path, std::string& error) {
  std::string text;
  if (!read_file(path, text)) {
    error = "cannot read " + path;
    return false;
  }
  return load_json_text(text, error);
}

bool kev_db::load_json_text(std::string_view text, std::string& error) {
  const json doc = json::parse(text.begin(), text.end(), nullptr, /*allow_exceptions=*/false);
  if (doc.is_discarded() || !doc.is_object() || !doc.contains("vulnerabilities") ||
      !doc["vulnerabilities"].is_array()) {
    error = "not a CISA KEV catalog (no 'vulnerabilities' array)";
    return false;
  }
  entries_.clear();
  catalog_version_ = str_of(doc, "catalogVersion");
  date_released_ = str_of(doc, "dateReleased");

  for (const json& v : doc["vulnerabilities"]) {
    kev_entry entry;
    entry.cve = to_upper(str_of(v, "cveID"));
    if (entry.cve.empty()) continue;
    entry.vendor = str_of(v, "vendorProject");
    entry.product = str_of(v, "product");
    entry.name = str_of(v, "vulnerabilityName");
    entry.date_added = str_of(v, "dateAdded");
    entry.due_date = str_of(v, "dueDate");
    entry.description = str_of(v, "shortDescription");
    entry.required_action = str_of(v, "requiredAction");
    entry.notes = str_of(v, "notes");
    entry.ransomware_use = str_of(v, "knownRansomwareCampaignUse") == "Known";
    if (const auto cwes = v.find("cwes"); cwes != v.end() && cwes->is_array()) {
      for (const json& c : *cwes) if (c.is_string()) entry.cwes.push_back(c.get<std::string>());
    }
    entries_[entry.cve] = std::move(entry);
  }
  if (entries_.empty()) {
    error = "KEV catalog is empty";
    return false;
  }
  return true;
}

const kev_entry* kev_db::find(const std::string& cve) const {
  const auto it = entries_.find(to_upper(cve));
  return it == entries_.end() ? nullptr : &it->second;
}

// ===========================================================================
// downloads
// ===========================================================================
bool refresh_file(http_client& http, const std::string& url, const std::string& path,
                  std::chrono::seconds max_age, bool offline, std::string& warning, std::string& error,
                  std::chrono::steady_clock::time_point deadline) {
  std::error_code ec;
  const bool have = fs::exists(path, ec) && fs::file_size(path, ec) > 0;
  if (have) {
    const auto modified = fs::last_write_time(path, ec);
    if (!ec) {
      const auto age = std::chrono::duration_cast<std::chrono::seconds>(fs::file_time_type::clock::now() - modified);
      if (age <= max_age) return true;
    }
  }
  if (offline) {
    if (have) {
      warning = "offline: using the cached copy of " + url;
      return true;
    }
    error = "offline and no cached copy of " + url;
    return false;
  }

  http_request request;
  request.url = url;
  request.timeout_ms = 180000;
  request.max_response_bytes = 256u * 1024u * 1024u;
  request.deadline = deadline;
  request.headers.push_back({"Accept", "application/json"});
  std::string problem;
  http_response response;
  try {
    response = http.perform(request);
    if (!response.transport_ok) problem = "download failed: " + response.error;
    else if (!response.ok()) problem = "download failed: HTTP " + std::to_string(response.status);
    else if (response.body.empty()) problem = "download failed: empty response";
  } catch (const std::exception& ex) {
    problem = "download failed: " + std::string(ex.what());
  } catch (...) {
    problem = "download failed: unknown transport error";
  }

  if (problem.empty()) {
    fs::create_directories(fs::path(path).parent_path(), ec);
    const std::string tmp = path + ".tmp";
    {
      std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
      out.write(response.body.data(), static_cast<std::streamsize>(response.body.size()));
      if (!out) problem = "cannot write " + tmp;
    }
    if (problem.empty()) {
      fs::rename(tmp, path, ec);
      if (ec) problem = "cannot replace " + path + ": " + ec.message();
    }
  }
  if (problem.empty()) return true;
  if (have) {
    warning = problem + " (" + url + "); using the stale cached copy";
    return true;
  }
  error = problem + " (" + url + ")";
  return false;
}

// ===========================================================================
// cti_providers.cpp
// ===========================================================================
namespace {

// ===========================================================================
// JSON access helpers (never throw, never index a missing key)
// ===========================================================================
const json* jget(const json& object, const char* key) {
  if (!object.is_object()) return nullptr;
  const auto it = object.find(key);
  return it == object.end() ? nullptr : &*it;
}

std::string jstr(const json& object, const char* key) {
  const json* v = jget(object, key);
  if (v == nullptr) return {};
  if (v->is_string()) return v->get<std::string>();
  if (v->is_number_integer()) return std::to_string(v->get<long long>());
  if (v->is_number_float()) {
    std::ostringstream s;
    s << v->get<double>();
    return s.str();
  }
  return {};
}

double jnum(const json& object, const char* key, double fallback = 0.0) {
  const json* v = jget(object, key);
  if (v == nullptr) return fallback;
  if (v->is_number()) return v->get<double>();
  if (v->is_string()) {                       // several APIs return numbers as strings
    char* end = nullptr;
    const std::string s = v->get<std::string>();
    const double d = std::strtod(s.c_str(), &end);
    return end != s.c_str() ? d : fallback;
  }
  return fallback;
}

long long jint(const json& object, const char* key, long long fallback = 0) {
  return static_cast<long long>(jnum(object, key, static_cast<double>(fallback)));
}

bool jbool(const json& object, const char* key) {
  const json* v = jget(object, key);
  return v != nullptr && v->is_boolean() && v->get<bool>();
}

std::vector<std::string> jstrings(const json& array) {
  std::vector<std::string> out;
  if (!array.is_array()) return out;
  for (const json& item : array) if (item.is_string()) out.push_back(item.get<std::string>());
  return out;
}

void add_unique(std::vector<std::string>& list, const std::string& value) {
  if (!value.empty() && std::find(list.begin(), list.end(), value) == list.end()) list.push_back(value);
}

std::string join(const std::vector<std::string>& items, const std::string& sep, std::size_t max = 0) {
  std::string out;
  std::size_t n = 0;
  for (const std::string& item : items) {
    if (max != 0 && n >= max) {
      out += sep + "...";
      break;
    }
    out += (n++ == 0 ? "" : sep) + item;
  }
  return out;
}

int clamp_int(double value, int lo = 0, int hi = 100) {
  return static_cast<int>(std::max<double>(lo, std::min<double>(hi, std::round(value))));
}

// Path segment for services that take a raw URL in the path (OTX): only the characters that
// would change the meaning of the request are escaped.
std::string escape_raw_url(const std::string& url) {
  std::string out;
  for (char c : url) {
    switch (c) {
      case ' ': out += "%20"; break;
      case '?': out += "%3F"; break;
      case '#': out += "%23"; break;
      case '%': out += "%25"; break;
      default:  out += c;
    }
  }
  return out;
}

// example.co.uk -> example.co.uk, a.b.example.com -> example.com (heuristic, no PSL)
std::string registrable_domain(const std::string& domain) {
  std::vector<std::string> labels;
  std::size_t start = 0;
  while (start <= domain.size()) {
    std::size_t end = domain.find('.', start);
    if (end == std::string::npos) end = domain.size();
    labels.push_back(domain.substr(start, end - start));
    start = end + 1;
  }
  if (labels.size() <= 2) return domain;
  static const std::set<std::string> second_level = {"co", "com", "org", "net", "gov", "edu", "ac", "or", "ne", "go"};
  const std::string& tld = labels.back();
  const std::string& sld = labels[labels.size() - 2];
  const std::size_t keep = (tld.size() == 2 && second_level.count(sld) != 0) ? 3 : 2;
  std::string out;
  for (std::size_t i = labels.size() - keep; i < labels.size(); ++i) out += (out.empty() ? "" : ".") + labels[i];
  return out;
}

artifact derived_artifact(artifact_type type, const std::string& value, const artifact& parent) {
  artifact a;
  a.type = type;
  a.value = value;
  a.sources.insert("derived");
  a.derived_from = parent.key();
  return a;
}

// ===========================================================================
// base class: caching, rate limiting, error classification
// ===========================================================================
struct fetched {
  bool        ok = false;             // 2xx with a JSON body
  bool        not_found = false;      // 404: the service does not know the artifact
  long        status = 0;
  json        body;
  std::string error;
  bool        retryable = false;
  bool        from_cache = false;
};

class base_provider : public provider {
 public:
  base_provider(std::string name, double per_minute, int burst, int concurrency, double weight)
      : name_(std::move(name)), limiter_(per_minute, burst), concurrency_(concurrency), weight_(weight) {}

  std::string name() const override { return name_; }
  int concurrency() const override { return concurrency_; }

 protected:
  static std::vector<std::pair<std::string, std::string>> json_headers() {
    return {{"Accept", "application/json"}};
  }

  fetched fetch(provider_context& ctx, const http_request& request) {
    const std::string key = request.method + " " + request.url + "\n" + request.body;
    if (auto cached = ctx.cache.get(name_, key, -1)) {
      if (cached->is_object() && jint(*cached, "exp") > now_epoch()) {
        fetched f;
        f.status = jint(*cached, "s");
        f.ok = f.status >= 200 && f.status < 300;
        f.not_found = f.status == 404;
        if (const json* body = jget(*cached, "b")) f.body = *body;
        f.from_cache = true;
        return f;
      }
    }
    fetched f;
    if (ctx.offline) {
      f.error = "offline: no cached answer";
      return f;
    }
    // Circuit breaker: after several consecutive failures (network down, bad API key, endless
    // 429s) stop hammering the service for the rest of this run instead of waiting on retries.
    if (failures_.load() >= kCircuitThreshold) {
      f.error = "provider unavailable: stopped after " + std::to_string(kCircuitThreshold) + " consecutive failures";
      return f;
    }

    // A rate limiter protects a service that is answering; if the last request never got an
    // answer at all (connection refused, DNS failure, timeout) waiting adds nothing.
    if (!last_failure_transport_.load() && !limiter_.acquire_until(ctx.deadline)) {
      f.error = "budget: time budget exhausted while waiting for the " + name_ + " rate limit";
      return f;
    }
    http_request bounded_request = request;
    bounded_request.deadline = std::min(bounded_request.deadline, ctx.deadline);
    const http_response response = ctx.http.perform(bounded_request);
    if (ctx.deadline != std::chrono::steady_clock::time_point::max() &&
        std::chrono::steady_clock::now() >= ctx.deadline) {
      f.error = "budget: time budget exhausted during the " + name_ + " request";
      return f;
    }
    if (!response.transport_ok) {
      f.error = "request failed: " + response.error;
      f.retryable = true;
      last_failure_transport_.store(true);
      // "could not connect / resolve" means the service or the network is down: trip twice as fast
      const std::string lowered = to_lower(response.error);
      failures_ += (lowered.find("connect") != std::string::npos || lowered.find("resolve") != std::string::npos) ? 2 : 1;
      return f;
    }
    last_failure_transport_.store(false);
    f.status = response.status;

    if (response.ok()) {
      f.body = json::parse(response.body, nullptr, /*allow_exceptions=*/false);
      if (f.body.is_discarded()) {
        f.body = json();
        f.error = "invalid JSON in the response";
        return f;
      }
      f.ok = true;
    } else if (response.status == 404) {
      f.not_found = true;
      const json parsed = json::parse(response.body, nullptr, false);
      if (!parsed.is_discarded()) f.body = parsed;
    } else if (response.status == 401 || response.status == 403) {
      f.error = status_note(response.status);
      if (f.error.empty())
        f.error = "authentication failed (HTTP " + std::to_string(response.status) + "): check the " + name_ + " API key";
    } else if (response.status == 429) {
      f.error = "rate limited (HTTP 429)";
      f.retryable = true;
    } else {
      f.error = "HTTP " + std::to_string(response.status);
      f.retryable = response.status >= 500;
    }

    if (f.ok || f.not_found) failures_.store(0);
    else ++failures_;

    if (f.ok || f.not_found) {
      const std::int64_t ttl_hours = f.not_found ? ctx.cfg.ttl_negative_hours : ctx.cfg.ttl_positive_hours;
      ctx.cache.put(name_, key, json{{"s", f.status}, {"b", f.body}, {"exp", now_epoch() + ttl_hours * 3600}});
    }
    return f;
  }

  // Records a transport / auth / rate-limit problem (a 404 is not a problem).
  void note(query_result& result, const fetched& f) const {
    if (f.ok || f.not_found) return;
    result.errors.push_back({name_, f.error.empty() ? "unknown error" : f.error, f.status, f.retryable});
  }

  // Most services signal "bad credentials" with 401/403 and "too many requests" with 429.
  // A provider whose service splits them differently can word its own status codes here;
  // an empty string means "use the generic wording".
  virtual std::string status_note(long status) const {
    (void)status;
    return {};
  }

  finding make_finding(const fetched& f) const {
    finding fd;
    fd.provider = name_;
    fd.weight = weight_;
    fd.from_cache = f.from_cache;
    return fd;
  }

  static constexpr int kCircuitThreshold = 4;
  std::string name_;
  rate_limiter limiter_;
  int concurrency_;
  double weight_;
  std::atomic<int> failures_{0};
  std::atomic<bool> last_failure_transport_{false};
};

// ===========================================================================
// IP: Shodan InternetDB (no key)
// ===========================================================================
class internetdb_provider final : public base_provider {
 public:
  explicit internetdb_provider(const config& cfg)
      : base_provider("shodan_internetdb", 60, 5, 2, 0.5), url_(cfg.urls.shodan_internetdb) {}
  bool supports(artifact_type t) const override { return t == artifact_type::ip; }

  query_result query(const artifact& art, provider_context& ctx) override {
    query_result r;
    http_request req;
    req.url = url_ + "/" + url_encode(art.value);
    req.headers = json_headers();
    const fetched f = fetch(ctx, req);
    note(r, f);
    if (!f.ok) return r;

    finding fd = make_finding(f);
    for (const json& p : f.body.value("ports", json::array())) if (p.is_number_integer()) r.net.open_ports.push_back(p.get<int>());
    r.net.cpes = jstrings(f.body.value("cpes", json::array()));
    r.net.hostnames = jstrings(f.body.value("hostnames", json::array()));
    r.net.vulns = jstrings(f.body.value("vulns", json::array()));
    fd.tags = jstrings(f.body.value("tags", json::array()));

    bool bad = false;
    for (const std::string& tag : fd.tags) bad = bad || tag == "malware" || tag == "compromised" || tag == "cryptomining";
    if (bad) {
      fd.outcome = verdict::suspicious;
      fd.confidence = 55;
    }
    fd.summary = std::to_string(r.net.open_ports.size()) + " open port(s)" +
                 (r.net.vulns.empty() ? "" : ", " + std::to_string(r.net.vulns.size()) + " known CVE(s)") +
                 (fd.tags.empty() ? "" : ", tags: " + join(fd.tags, ", "));
    fd.data = {{"ports", r.net.open_ports}, {"cpes", r.net.cpes}, {"vulns", r.net.vulns}};
    fd.references.push_back("https://www.shodan.io/host/" + art.value);

    std::size_t added = 0;
    for (const std::string& cve : r.net.vulns) {
      if (added++ >= ctx.cfg.max_derived_per_artifact) break;
      if (auto norm = normalize_artifact(cve, artifact_type::cve)) r.derived.push_back(derived_artifact(artifact_type::cve, norm->value, art));
    }
    r.findings.push_back(std::move(fd));
    return r;
  }

 private:
  std::string url_;
};

// ===========================================================================
// IP: AbuseIPDB
// ===========================================================================
class abuseipdb_provider final : public base_provider {
 public:
  explicit abuseipdb_provider(const config& cfg)
      : base_provider("abuseipdb", 30, 10, 2, 0.9), url_(cfg.urls.abuseipdb), key_(cfg.keys.abuseipdb) {}
  bool supports(artifact_type t) const override { return t == artifact_type::ip; }
  bool configured() const override { return !key_.empty(); }
  std::string requirement() const override { return "ABUSEIPDB_API_KEY"; }

  query_result query(const artifact& art, provider_context& ctx) override {
    query_result r;
    http_request req;
    req.url = url_ + "/check?maxAgeInDays=90&ipAddress=" + url_encode(art.value);
    req.headers = json_headers();
    req.headers.push_back({"Key", key_});
    const fetched f = fetch(ctx, req);
    note(r, f);
    if (!f.ok) return r;

    const json data = f.body.value("data", json::object());
    finding fd = make_finding(f);
    const int score = static_cast<int>(jint(data, "abuseConfidenceScore"));
    const long long reports = jint(data, "totalReports");
    if (jbool(data, "isWhitelisted")) {
      fd.outcome = verdict::benign;
      fd.confidence = 60;
    } else if (score >= 75) {
      fd.outcome = verdict::malicious;
      fd.confidence = score;
    } else if (score >= 25) {
      fd.outcome = verdict::suspicious;
      fd.confidence = score;
    }
    if (jbool(data, "isTor")) fd.tags.push_back("tor");
    const std::string usage = jstr(data, "usageType");
    if (!usage.empty()) fd.tags.push_back(usage);
    fd.summary = "abuse confidence " + std::to_string(score) + "% (" + std::to_string(reports) + " reports from " +
                 std::to_string(jint(data, "numDistinctUsers")) + " users" +
                 (jstr(data, "lastReportedAt").empty() ? "" : ", last " + jstr(data, "lastReportedAt")) + ")";
    fd.data = {{"abuse_confidence", score}, {"total_reports", reports}, {"isp", jstr(data, "isp")}, {"usage_type", usage}};
    fd.references.push_back("https://www.abuseipdb.com/check/" + art.value);
    r.net.country = jstr(data, "countryCode");
    r.net.org = jstr(data, "isp");
    r.net.hostnames = jstrings(data.value("hostnames", json::array()));
    r.findings.push_back(std::move(fd));
    return r;
  }

 private:
  std::string url_, key_;
};

// ===========================================================================
// IP: GreyNoise Community API
// ===========================================================================
// Keyless by design: the Community endpoint answers without credentials, so
// this provider is never skipped for a missing GREYNOISE_API_KEY - the key is
// optional and only raises the quota.
//
// That quota is small and measured per day / week, not per minute (see
// docs.greynoise.io "Using the GreyNoise Community API": 10 IP lookups per day
// unauthenticated, 50 per week for a free-tier key). The keyless rate is
// therefore one lookup every five minutes: a 10-minute run spends at most two
// and the rest of the day still works, instead of one sample eating the whole
// allowance. A paid key answers far more often, hence the higher keyed rate.
class greynoise_provider final : public base_provider {
 public:
  explicit greynoise_provider(const config& cfg)
      : base_provider("greynoise",
                      cfg.keys.greynoise.empty() ? 0.2 : 20,
                      cfg.keys.greynoise.empty() ? 1 : 5,
                      1, 0.8),
        url_(cfg.urls.greynoise), key_(cfg.keys.greynoise) {}
  bool supports(artifact_type t) const override { return t == artifact_type::ip; }

  query_result query(const artifact& art, provider_context& ctx) override {
    query_result r;
    http_request req;
    req.url = url_ + "/" + url_encode(art.value);
    req.headers = json_headers();
    if (!key_.empty()) req.headers.push_back({"key", key_});
    const fetched f = fetch(ctx, req);
    note(r, f);
    if (f.not_found) {
      finding fd = make_finding(f);
      fd.summary = "not observed scanning the internet";
      r.findings.push_back(std::move(fd));
      return r;
    }
    if (!f.ok) return r;

    finding fd = make_finding(f);
    const std::string cls = jstr(f.body, "classification");
    const bool noise = jbool(f.body, "noise"), riot = jbool(f.body, "riot");
    if (cls == "malicious") {
      fd.outcome = verdict::malicious;
      fd.confidence = 80;
    } else if (riot || cls == "benign") {
      fd.outcome = verdict::benign;
      fd.confidence = riot ? 75 : 60;
    } else if (noise) {
      fd.outcome = verdict::suspicious;
      fd.confidence = 30;
    }
    if (noise) fd.tags.push_back("internet-scanner");
    if (riot) fd.tags.push_back("common-business-service");
    fd.summary = "classification " + (cls.empty() ? std::string("unknown") : cls) +
                 (jstr(f.body, "name").empty() ? "" : " (" + jstr(f.body, "name") + ")") +
                 (jstr(f.body, "last_seen").empty() ? "" : ", last seen " + jstr(f.body, "last_seen"));
    fd.data = {{"noise", noise}, {"riot", riot}, {"classification", cls}, {"name", jstr(f.body, "name")}};
    if (!jstr(f.body, "link").empty()) fd.references.push_back(jstr(f.body, "link"));
    r.findings.push_back(std::move(fd));
    return r;
  }

 private:
  std::string url_, key_;
};

// ===========================================================================
// IP / domain / URL / hash / CVE: AlienVault OTX
// ===========================================================================
class otx_provider final : public base_provider {
 public:
  explicit otx_provider(const config& cfg)
      : base_provider("otx", 60, 5, 2, 0.5), url_(cfg.urls.otx), key_(cfg.keys.otx) {}
  bool supports(artifact_type t) const override {
    return t == artifact_type::ip || t == artifact_type::domain || t == artifact_type::url ||
           is_hash(t) || t == artifact_type::cve;
  }
  bool configured() const override { return !key_.empty(); }
  std::string requirement() const override { return "OTX_API_KEY"; }

  query_result query(const artifact& art, provider_context& ctx) override {
    query_result r;
    std::string path;
    switch (art.type) {
      case artifact_type::ip:     path = std::string("/indicators/") + (is_ipv6(art.value) ? "IPv6/" : "IPv4/") + art.value; break;
      case artifact_type::domain: path = "/indicators/domain/" + art.value; break;
      case artifact_type::url:    path = "/indicators/url/" + escape_raw_url(art.value); break;
      case artifact_type::cve:    path = "/indicators/cve/" + art.value; break;
      default:                    path = "/indicators/file/" + art.value; break;
    }
    http_request req;
    req.url = url_ + path + "/general";
    req.headers = json_headers();
    req.headers.push_back({"X-OTX-API-KEY", key_});
    const fetched f = fetch(ctx, req);
    note(r, f);
    if (!f.ok) return r;

    finding fd = make_finding(f);
    const json pulse_info = f.body.value("pulse_info", json::object());
    const long long count = jint(pulse_info, "count");
    std::vector<std::string> names;
    if (const json* pulses = jget(pulse_info, "pulses"); pulses != nullptr && pulses->is_array()) {
      for (const json& pulse : *pulses) {
        if (names.size() < 5 && !jstr(pulse, "name").empty()) names.push_back(jstr(pulse, "name"));
        for (const std::string& tag : jstrings(pulse.value("tags", json::array()))) if (fd.tags.size() < 12) add_unique(fd.tags, tag);
        if (const json* families = jget(pulse, "malware_families"); families != nullptr && families->is_array()) {
          for (const json& fam : *families) add_unique(fd.families, jstr(fam, "display_name").empty() ? jstr(fam, "id") : jstr(fam, "display_name"));
        }
        if (const json* attack = jget(pulse, "attack_ids"); attack != nullptr && attack->is_array()) {
          for (const json& a : *attack) {
            if (r.derived.size() >= ctx.cfg.max_derived_per_artifact * 3) break;
            if (auto norm = normalize_artifact(jstr(a, "id"), artifact_type::technique)) {
              const bool dup = std::any_of(r.derived.begin(), r.derived.end(), [&](const artifact& d) { return d.value == norm->value; });
              if (!dup) r.derived.push_back(derived_artifact(artifact_type::technique, norm->value, art));
            }
          }
        }
      }
    }
    if (count >= 20) {
      fd.outcome = verdict::malicious;
      fd.confidence = 65;
    } else if (count >= 1) {
      fd.outcome = verdict::suspicious;
      fd.confidence = clamp_int(30 + std::min<long long>(count, 10) * 3);
    } else if (const json* validation = jget(f.body, "validation"); validation != nullptr && validation->is_array() && !validation->empty()) {
      fd.outcome = verdict::benign;   // OTX whitelists (popular / well known domains)
      fd.confidence = 50;
      fd.tags.push_back("otx-validated");
    }
    if (art.type == artifact_type::ip) {
      const std::string asn = jstr(f.body, "asn");   // "AS15169 Google LLC"
      const std::size_t sp = asn.find(' ');
      r.net.asn = sp == std::string::npos ? asn : asn.substr(0, sp);
      if (sp != std::string::npos) r.net.asn_name = asn.substr(sp + 1);
      r.net.country = jstr(f.body, "country_code");
    }
    fd.summary = std::to_string(count) + " OTX pulse(s)" + (names.empty() ? "" : ": " + join(names, "; "));
    fd.data = {{"pulse_count", count}, {"pulses", names}};
    fd.references.push_back("https://otx.alienvault.com/indicator/" + std::string(art.type == artifact_type::ip ? "ip" : art.type == artifact_type::domain ? "domain" : art.type == artifact_type::url ? "url" : art.type == artifact_type::cve ? "cve" : "file") + "/" + art.value);
    r.findings.push_back(std::move(fd));
    return r;
  }

 private:
  std::string url_, key_;
};

// ===========================================================================
// abuse.ch: ThreatFox
// ===========================================================================
class threatfox_provider final : public base_provider {
 public:
  explicit threatfox_provider(const config& cfg)
      : base_provider("threatfox", 60, 5, 2, 1.0), url_(cfg.urls.threatfox), key_(cfg.keys.abusech) {}
  bool supports(artifact_type t) const override {
    return t == artifact_type::ip || t == artifact_type::domain || t == artifact_type::url ||
           t == artifact_type::md5 || t == artifact_type::sha256;
  }
  bool configured() const override { return !key_.empty(); }
  std::string requirement() const override { return "ABUSECH_AUTH_KEY"; }

  query_result query(const artifact& art, provider_context& ctx) override {
    query_result r;
    http_request req;
    req.method = "POST";
    req.url = url_;
    req.headers = json_headers();
    req.headers.push_back({"Auth-Key", key_});
    req.headers.push_back({"Content-Type", "application/json"});
    req.body = json{{"query", "search_ioc"}, {"search_term", art.value}, {"exact_match", art.type != artifact_type::ip}}.dump();
    const fetched f = fetch(ctx, req);
    note(r, f);
    if (!f.ok) return r;

    const std::string status = jstr(f.body, "query_status");
    if (status != "ok") {                       // "no_result" | "illegal_search_term" | ...
      if (status != "no_result" && !status.empty()) r.errors.push_back({name_, "query_status " + status, f.status, false});
      return r;
    }
    finding fd = make_finding(f);
    int best = 0;
    std::size_t hits = 0;
    std::vector<std::string> types;
    if (const json* data = jget(f.body, "data"); data != nullptr && data->is_array()) {
      for (const json& entry : *data) {
        const std::string ioc = jstr(entry, "ioc");
        if (art.type == artifact_type::ip && !(ioc == art.value || starts_with(ioc, art.value + ":"))) continue;  // "1.2.3.44" is not "1.2.3.4"
        ++hits;
        best = std::max(best, static_cast<int>(jint(entry, "confidence_level")));
        const std::string malware = jstr(entry, "malware_printable");
        if (!malware.empty() && malware != "Unknown malware") add_unique(fd.families, malware);
        add_unique(types, jstr(entry, "threat_type"));
        for (const std::string& tag : jstrings(entry.value("tags", json::array()))) add_unique(fd.tags, tag);
        if (!jstr(entry, "reference").empty() && fd.references.size() < 3) fd.references.push_back(jstr(entry, "reference"));
        if (!jstr(entry, "id").empty() && fd.references.size() < 4) fd.references.push_back("https://threatfox.abuse.ch/ioc/" + jstr(entry, "id") + "/");
      }
    }
    if (hits == 0) return r;
    fd.outcome = verdict::malicious;
    fd.confidence = clamp_int(best > 0 ? best : 75);
    fd.summary = std::to_string(hits) + " ThreatFox IOC(s)" + (fd.families.empty() ? "" : ", family " + join(fd.families, "/")) +
                 (types.empty() ? "" : ", " + join(types, "/"));
    fd.data = {{"hits", hits}, {"threat_types", types}};
    r.findings.push_back(std::move(fd));
    return r;
  }

 private:
  std::string url_, key_;
};

// ===========================================================================
// abuse.ch: URLhaus (URL / host / payload hash)
// ===========================================================================
class urlhaus_provider final : public base_provider {
 public:
  explicit urlhaus_provider(const config& cfg)
      : base_provider("urlhaus", 60, 5, 2, 1.0), url_(cfg.urls.urlhaus), key_(cfg.keys.abusech) {}
  bool supports(artifact_type t) const override {
    return t == artifact_type::url || t == artifact_type::domain || t == artifact_type::ip ||
           t == artifact_type::md5 || t == artifact_type::sha256;
  }
  bool configured() const override { return !key_.empty(); }
  std::string requirement() const override { return "ABUSECH_AUTH_KEY"; }

  query_result query(const artifact& art, provider_context& ctx) override {
    query_result r;
    std::string endpoint, field;
    switch (art.type) {
      case artifact_type::url:    endpoint = "/url/"; field = "url"; break;
      case artifact_type::md5:    endpoint = "/payload/"; field = "md5_hash"; break;
      case artifact_type::sha256: endpoint = "/payload/"; field = "sha256_hash"; break;
      default:                    endpoint = "/host/"; field = "host"; break;
    }
    http_request req;
    req.method = "POST";
    req.url = url_ + endpoint;
    req.headers = json_headers();
    req.headers.push_back({"Auth-Key", key_});
    req.headers.push_back({"Content-Type", "application/x-www-form-urlencoded"});
    req.body = field + "=" + url_encode(art.value);
    const fetched f = fetch(ctx, req);
    note(r, f);
    if (!f.ok) return r;

    const std::string status = jstr(f.body, "query_status");
    if (status != "ok") {                                // "no_results" | "invalid_url" | ...
      if (status != "no_results" && !status.empty()) r.errors.push_back({name_, "query_status " + status, f.status, false});
      return r;
    }
    finding fd = make_finding(f);
    fd.outcome = verdict::malicious;
    for (const std::string& tag : jstrings(f.body.value("tags", json::array()))) add_unique(fd.tags, tag);
    if (!jstr(f.body, "urlhaus_reference").empty()) fd.references.push_back(jstr(f.body, "urlhaus_reference"));

    if (art.type == artifact_type::url) {
      const std::string state = jstr(f.body, "url_status");
      fd.confidence = state == "online" ? 95 : 75;
      fd.summary = "listed in URLhaus (" + (state.empty() ? std::string("unknown") : state) + ", threat " +
                   (jstr(f.body, "threat").empty() ? std::string("n/a") : jstr(f.body, "threat")) + ")";
      if (const json* payloads = jget(f.body, "payloads"); payloads != nullptr && payloads->is_array()) {
        for (const json& p : *payloads) add_unique(fd.families, jstr(p, "signature"));
      }
      fd.data = {{"url_status", state}, {"threat", jstr(f.body, "threat")}, {"date_added", jstr(f.body, "date_added")}};
    } else if (is_hash(art.type)) {
      fd.confidence = 90;
      add_unique(fd.families, jstr(f.body, "signature"));
      fd.summary = "payload served by " + jstr(f.body, "url_count") + " URLhaus URL(s), type " + jstr(f.body, "file_type");
      fd.data = {{"file_type", jstr(f.body, "file_type")}, {"first_seen", jstr(f.body, "firstseen")}};
    } else {
      const long long urls = jint(f.body, "url_count");
      bool online = false;
      if (const json* list = jget(f.body, "urls"); list != nullptr && list->is_array()) {
        for (const json& u : *list) online = online || jstr(u, "url_status") == "online";
      }
      const json blacklists = f.body.value("blacklists", json::object());
      const std::string dbl = jstr(blacklists, "spamhaus_dbl"), surbl = jstr(blacklists, "surbl");
      if (urls == 0) {
        if (dbl.empty() || dbl == "not listed") return r;   // listed host without URLs is still a hit
      }
      fd.confidence = online ? 90 : (urls > 0 ? 70 : 50);
      fd.summary = "host serves " + std::to_string(urls) + " URLhaus URL(s)" + (online ? ", some online" : "") +
                   (dbl.empty() || dbl == "not listed" ? "" : ", Spamhaus DBL " + dbl);
      fd.data = {{"url_count", urls}, {"online", online}, {"spamhaus_dbl", dbl}, {"surbl", surbl}};
    }
    r.findings.push_back(std::move(fd));
    return r;
  }

 private:
  std::string url_, key_;
};

// ===========================================================================
// abuse.ch: MalwareBazaar (hash)
// ===========================================================================
class malwarebazaar_provider final : public base_provider {
 public:
  explicit malwarebazaar_provider(const config& cfg)
      : base_provider("malwarebazaar", 60, 5, 2, 1.0), url_(cfg.urls.malwarebazaar), key_(cfg.keys.abusech) {}
  bool supports(artifact_type t) const override {
    return t == artifact_type::md5 || t == artifact_type::sha1 || t == artifact_type::sha256;
  }
  bool configured() const override { return !key_.empty(); }
  std::string requirement() const override { return "ABUSECH_AUTH_KEY"; }

  query_result query(const artifact& art, provider_context& ctx) override {
    query_result r;
    http_request req;
    req.method = "POST";
    req.url = url_;
    req.headers = json_headers();
    req.headers.push_back({"Auth-Key", key_});
    req.headers.push_back({"Content-Type", "application/x-www-form-urlencoded"});
    req.body = "query=get_info&hash=" + url_encode(art.value);
    const fetched f = fetch(ctx, req);
    note(r, f);
    if (!f.ok) return r;

    const std::string status = jstr(f.body, "query_status");
    if (status != "ok") {                                // "hash_not_found" | "illegal_hash" | ...
      if (status != "hash_not_found" && !status.empty()) r.errors.push_back({name_, "query_status " + status, f.status, false});
      return r;
    }
    const json* data = jget(f.body, "data");
    if (data == nullptr || !data->is_array() || data->empty()) return r;
    const json& sample = (*data)[0];

    finding fd = make_finding(f);
    fd.outcome = verdict::malicious;
    fd.confidence = 95;
    add_unique(fd.families, jstr(sample, "signature"));
    fd.tags = jstrings(sample.value("tags", json::array()));
    const std::string name = jstr(sample, "file_name"), type = jstr(sample, "file_type");
    fd.summary = "known malware sample" + (fd.families.empty() ? std::string() : " (" + fd.families[0] + ")") +
                 (type.empty() ? "" : ", " + type) + (jstr(sample, "first_seen").empty() ? "" : ", first seen " + jstr(sample, "first_seen"));
    fd.data = {{"file_name", name}, {"file_type", type}, {"sha256", jstr(sample, "sha256_hash")},
               {"delivery_method", jstr(sample, "delivery_method")}};
    fd.references.push_back("https://bazaar.abuse.ch/sample/" + jstr(sample, "sha256_hash") + "/");
    r.findings.push_back(std::move(fd));
    return r;
  }

 private:
  std::string url_, key_;
};

// ===========================================================================
// IP / domain / URL / hash: VirusTotal v3
// ===========================================================================
class virustotal_provider final : public base_provider {
 public:
  explicit virustotal_provider(const config& cfg)
      : base_provider("virustotal", 4, 1, 1, 0.9), url_(cfg.urls.virustotal), key_(cfg.keys.virustotal) {}
  bool supports(artifact_type t) const override {
    return t == artifact_type::ip || t == artifact_type::domain || t == artifact_type::url || is_hash(t);
  }
  bool configured() const override { return !key_.empty(); }
  std::string requirement() const override { return "VT_API_KEY"; }

  query_result query(const artifact& art, provider_context& ctx) override {
    query_result r;
    std::string path, gui;
    switch (art.type) {
      case artifact_type::ip:     path = "/ip_addresses/" + art.value; gui = "ip-address/" + art.value; break;
      case artifact_type::domain: path = "/domains/" + art.value; gui = "domain/" + art.value; break;
      case artifact_type::url:    path = "/urls/" + base64url(art.value); gui = "url/" + base64url(art.value); break;
      default:                    path = "/files/" + art.value; gui = "file/" + art.value; break;
    }
    http_request req;
    req.url = url_ + path;
    req.headers = json_headers();
    req.headers.push_back({"x-apikey", key_});
    const fetched f = fetch(ctx, req);
    note(r, f);
    finding fd = make_finding(f);
    if (f.not_found) {
      fd.summary = "not previously analysed by VirusTotal";
      r.findings.push_back(std::move(fd));
      return r;
    }
    if (!f.ok) return r;

    const json data = f.body.value("data", json::object());
    const json attrs = data.value("attributes", json::object());
    const json stats = attrs.value("last_analysis_stats", json::object());
    const long long mal = jint(stats, "malicious"), sus = jint(stats, "suspicious"),
                    harmless = jint(stats, "harmless"), undetected = jint(stats, "undetected");
    const long long total = mal + sus + harmless + undetected + jint(stats, "timeout");

    if (mal >= 10)      { fd.outcome = verdict::malicious;  fd.confidence = 95; }
    else if (mal >= 5)  { fd.outcome = verdict::malicious;  fd.confidence = 80; }
    else if (mal >= 2)  { fd.outcome = verdict::suspicious; fd.confidence = 60; }
    else if (mal == 1)  { fd.outcome = verdict::suspicious; fd.confidence = 30; }
    else if (sus > 0)   { fd.outcome = verdict::suspicious; fd.confidence = 25; }
    else if (harmless >= 30) { fd.outcome = verdict::benign; fd.confidence = 40; }   // clean on 30+ engines
    else if (harmless >= 5)  { fd.outcome = verdict::benign; fd.confidence = 30; }

    fd.tags = jstrings(attrs.value("tags", json::array()));
    if (const json* pt = jget(attrs, "popular_threat_classification"); pt != nullptr) {
      if (const json* names = jget(*pt, "popular_threat_name"); names != nullptr && names->is_array()) {
        for (const json& n : *names) add_unique(fd.families, jstr(n, "value"));
      }
      const std::string label = jstr(*pt, "suggested_threat_label");
      if (!label.empty()) fd.tags.push_back(label);
    }
    if (art.type == artifact_type::ip) {
      r.net.asn = jstr(attrs, "asn").empty() ? "" : "AS" + jstr(attrs, "asn");
      r.net.asn_name = jstr(attrs, "as_owner");
      r.net.country = jstr(attrs, "country");
    } else if (art.type == artifact_type::domain) {
      r.net.registrar = jstr(attrs, "registrar");
    }
    fd.summary = std::to_string(mal) + "/" + std::to_string(total) + " engines flag it malicious" +
                 (sus > 0 ? ", " + std::to_string(sus) + " suspicious" : "") +
                 (jstr(attrs, "meaningful_name").empty() ? "" : " (" + jstr(attrs, "meaningful_name") + ")");
    fd.data = {{"malicious", mal}, {"suspicious", sus}, {"harmless", harmless}, {"undetected", undetected},
               {"reputation", jint(attrs, "reputation")}};
    fd.references.push_back("https://www.virustotal.com/gui/" + gui);
    r.findings.push_back(std::move(fd));
    return r;
  }

 private:
  std::string url_, key_;
};

// ===========================================================================
// hash: CIRCL hashlookup (known-good software, NSRL)
// ===========================================================================
class circl_provider final : public base_provider {
 public:
  explicit circl_provider(const config& cfg)
      : base_provider("circl_hashlookup", 60, 5, 2, 0.6), url_(cfg.urls.circl_hashlookup) {}
  bool supports(artifact_type t) const override {
    return t == artifact_type::md5 || t == artifact_type::sha1 || t == artifact_type::sha256;
  }

  query_result query(const artifact& art, provider_context& ctx) override {
    query_result r;
    http_request req;
    req.url = url_ + "/lookup/" + to_string(art.type) + "/" + art.value;
    req.headers = json_headers();
    const fetched f = fetch(ctx, req);
    note(r, f);
    if (!f.ok) return r;                                  // 404 = unknown file: no opinion

    finding fd = make_finding(f);
    const double trust = jnum(f.body, "hashlookup:trust", 50.0);
    fd.outcome = verdict::benign;
    fd.confidence = clamp_int(trust, 40, 90);
    const std::string file = jstr(f.body, "FileName"), source = jstr(f.body, "source");
    if (!source.empty()) fd.tags.push_back(source);
    fd.tags.push_back("known-file");
    fd.summary = "known file in hashlookup" + (source.empty() ? std::string() : " (" + source + ")") + (file.empty() ? "" : ": " + file);
    fd.data = {{"file_name", file}, {"source", source}, {"trust", trust}};
    r.findings.push_back(std::move(fd));
    return r;
  }

 private:
  std::string url_;
};

// ===========================================================================
// IP / domain: RDAP (ownership, registration age)
// ===========================================================================
class rdap_provider final : public base_provider {
 public:
  explicit rdap_provider(const config& cfg)
      : base_provider("rdap", 30, 5, 2, 0.5), url_(cfg.urls.rdap) {}
  bool supports(artifact_type t) const override { return t == artifact_type::ip || t == artifact_type::domain; }

  query_result query(const artifact& art, provider_context& ctx) override {
    query_result r;
    const std::string target = art.type == artifact_type::ip ? art.value : registrable_domain(art.value);
    http_request req;
    req.url = url_ + (art.type == artifact_type::ip ? "/ip/" : "/domain/") + url_encode(target);
    req.headers = {{"Accept", "application/rdap+json, application/json"}};
    const fetched f = fetch(ctx, req);
    note(r, f);
    if (!f.ok) return r;

    finding fd = make_finding(f);
    if (art.type == artifact_type::ip) {
      r.net.org = jstr(f.body, "name");
      r.net.country = jstr(f.body, "country");
      if (const json* cidrs = jget(f.body, "cidr0_cidrs"); cidrs != nullptr && cidrs->is_array() && !cidrs->empty()) {
        const json& c = (*cidrs)[0];
        const std::string base = !jstr(c, "v4prefix").empty() ? jstr(c, "v4prefix") : jstr(c, "v6prefix");
        if (!base.empty()) r.net.prefix = base + "/" + jstr(c, "length");
      }
      fd.summary = "network " + r.net.org + (r.net.country.empty() ? "" : " (" + r.net.country + ")") + ", " +
                   jstr(f.body, "startAddress") + " - " + jstr(f.body, "endAddress");
      fd.data = {{"name", r.net.org}, {"handle", jstr(f.body, "handle")}, {"type", jstr(f.body, "type")}};
      r.findings.push_back(std::move(fd));
      return r;
    }

    // domain
    if (const json* events = jget(f.body, "events"); events != nullptr && events->is_array()) {
      for (const json& e : *events) {
        const std::string action = jstr(e, "eventAction"), date = jstr(e, "eventDate");
        if (action == "registration" && r.net.domain_created.empty()) r.net.domain_created = date;
        if (action == "expiration" && r.net.domain_expires.empty()) r.net.domain_expires = date;
      }
    }
    if (const json* ns = jget(f.body, "nameservers"); ns != nullptr && ns->is_array()) {
      for (const json& n : *ns) add_unique(r.net.nameservers, to_lower(jstr(n, "ldhName")));
    }
    if (const json* entities = jget(f.body, "entities"); entities != nullptr && entities->is_array()) {
      for (const json& e : *entities) {
        const std::vector<std::string> roles = jstrings(e.value("roles", json::array()));
        if (std::find(roles.begin(), roles.end(), "registrar") == roles.end()) continue;
        const json* vcard = jget(e, "vcardArray");
        if (vcard != nullptr && vcard->is_array() && vcard->size() > 1 && (*vcard)[1].is_array()) {
          for (const json& prop : (*vcard)[1]) {
            if (prop.is_array() && prop.size() > 3 && prop[0] == "fn" && prop[3].is_string()) r.net.registrar = prop[3].get<std::string>();
          }
        }
      }
    }
    if (const auto created = parse_iso8601(r.net.domain_created)) {
      r.net.domain_age_days = static_cast<int>((now_epoch() - *created) / 86400);
    }
    const int age = r.net.domain_age_days;
    if (age >= 0 && age < 7)       { fd.outcome = verdict::suspicious; fd.confidence = 55; }
    else if (age >= 0 && age < 30) { fd.outcome = verdict::suspicious; fd.confidence = 40; }
    else if (age >= 0 && age < 90) { fd.outcome = verdict::suspicious; fd.confidence = 20; }
    if (fd.outcome == verdict::suspicious) fd.tags.push_back("newly-registered");
    fd.summary = "registered " + (r.net.domain_created.empty() ? std::string("(date unknown)") : r.net.domain_created) +
                 (age >= 0 ? " (" + std::to_string(age) + " days ago)" : "") +
                 (r.net.registrar.empty() ? "" : ", registrar " + r.net.registrar);
    fd.data = {{"created", r.net.domain_created}, {"expires", r.net.domain_expires}, {"age_days", age},
               {"registrar", r.net.registrar}, {"registrable_domain", target}};
    r.findings.push_back(std::move(fd));
    return r;
  }

 private:
  std::string url_;
};

// ===========================================================================
// domain / IP: DNS over HTTPS (records, PTR, Team Cymru ASN)
// ===========================================================================
class dns_provider final : public base_provider {
 public:
  explicit dns_provider(const config& cfg)
      : base_provider("dns", 120, 10, 4, 0.3), url_(cfg.urls.doh), types_(cfg.dns_record_types) {}
  bool supports(artifact_type t) const override { return t == artifact_type::domain || t == artifact_type::ip; }

  query_result query(const artifact& art, provider_context& ctx) override {
    query_result r;
    finding fd = make_finding(fetched{});
    if (art.type == artifact_type::domain) query_domain(art, ctx, r, fd);
    else query_ip(art, ctx, r, fd);
    if (!fd.summary.empty()) r.findings.push_back(std::move(fd));
    return r;
  }

 private:
  struct answer { int type = 0; std::string data; };
  struct lookup { bool ok = false; int status = -1; std::vector<answer> answers; bool from_cache = false; };

  lookup resolve(provider_context& ctx, query_result& r, const std::string& name, const std::string& type) {
    http_request req;
    req.url = url_ + "?name=" + url_encode(name) + "&type=" + type;
    req.headers = {{"Accept", "application/dns-json"}};
    const fetched f = fetch(ctx, req);
    note(r, f);
    lookup out;
    if (!f.ok) return out;
    out.ok = true;
    out.from_cache = f.from_cache;
    out.status = static_cast<int>(jint(f.body, "Status", -1));
    if (const json* answers = jget(f.body, "Answer"); answers != nullptr && answers->is_array()) {
      for (const json& a : *answers) out.answers.push_back({static_cast<int>(jint(a, "type")), jstr(a, "data")});
    }
    return out;
  }

  static std::string strip_dot(std::string s) {
    if (!s.empty() && s.back() == '.') s.pop_back();
    return to_lower(s);
  }
  static std::string unquote(std::string s) {
    s = trim(s);
    s.erase(std::remove(s.begin(), s.end(), '"'), s.end());
    return s;
  }

  void query_domain(const artifact& art, provider_context& ctx, query_result& r, finding& fd) {
    std::vector<std::string> summary;
    for (const std::string& type : types_) {
      const lookup l = resolve(ctx, r, art.value, type);
      if (!l.ok) continue;
      fd.from_cache = fd.from_cache || l.from_cache;
      if (l.status == 3 && type == types_.front()) {         // NXDOMAIN
        r.net.nxdomain = true;
        fd.tags.push_back("nxdomain");
        fd.summary = "does not resolve (NXDOMAIN)";
        return;
      }
      for (const answer& a : l.answers) {
        if (a.type == 1 || a.type == 28) add_unique(r.net.resolved_ips, a.data);
        else if (a.type == 2) add_unique(r.net.nameservers, strip_dot(a.data));
        else if (a.type == 15) {                              // "10 mail.example.com."
          const std::size_t sp = a.data.find(' ');
          add_unique(r.net.mail_servers, strip_dot(sp == std::string::npos ? a.data : a.data.substr(sp + 1)));
        } else if (a.type == 16 && r.net.txt_records.size() < 10) add_unique(r.net.txt_records, unquote(a.data));
      }
    }
    std::size_t added = 0;
    for (const std::string& ip : r.net.resolved_ips) {
      if (added >= ctx.cfg.max_derived_per_artifact) break;
      if (!is_public_ip(ip)) continue;
      r.derived.push_back(derived_artifact(artifact_type::ip, is_ipv6(ip) ? to_lower(ip) : ip, art));
      ++added;
    }
    fd.summary = std::to_string(r.net.resolved_ips.size()) + " address(es), " + std::to_string(r.net.nameservers.size()) +
                 " nameserver(s), " + std::to_string(r.net.mail_servers.size()) + " mail server(s)";
    fd.data = {{"resolved_ips", r.net.resolved_ips}, {"nameservers", r.net.nameservers}, {"mx", r.net.mail_servers}};
  }

  void query_ip(const artifact& art, provider_context& ctx, query_result& r, finding& fd) {
    const std::string ptr_name = reverse_dns_name(art.value);
    if (ptr_name.empty()) return;
    const lookup ptr = resolve(ctx, r, ptr_name, "PTR");
    for (const answer& a : ptr.answers) if (a.type == 12) add_unique(r.net.hostnames, strip_dot(a.data));

    // Team Cymru IP-to-ASN mapping over DNS: "15169 | 8.8.8.0/24 | US | arin | 1992-12-01"
    const std::string origin = reverse_labels(art.value) + (is_ipv4(art.value) ? ".origin.asn.cymru.com" : ".origin6.asn.cymru.com");
    const lookup origin_lookup = resolve(ctx, r, origin, "TXT");
    std::string asn_number;
    if (!origin_lookup.answers.empty()) {
      const std::vector<std::string> parts = split_bar(unquote(origin_lookup.answers[0].data));
      if (parts.size() >= 3) {
        const std::size_t sp = parts[0].find(' ');
        asn_number = sp == std::string::npos ? parts[0] : parts[0].substr(0, sp);
        r.net.asn = "AS" + asn_number;
        r.net.prefix = parts[1];
        r.net.country = parts[2];
      }
    }
    if (!asn_number.empty()) {
      const lookup name_lookup = resolve(ctx, r, "AS" + asn_number + ".asn.cymru.com", "TXT");
      if (!name_lookup.answers.empty()) {
        const std::vector<std::string> parts = split_bar(unquote(name_lookup.answers[0].data));
        if (parts.size() >= 5) r.net.asn_name = parts[4];
      }
    }
    fd.summary = (r.net.hostnames.empty() ? std::string("no PTR record") : "PTR " + join(r.net.hostnames, ", ", 3)) +
                 (r.net.asn.empty() ? "" : ", " + r.net.asn + " " + r.net.asn_name + " (" + r.net.prefix + ")");
    fd.data = {{"ptr", r.net.hostnames}, {"asn", r.net.asn}, {"as_name", r.net.asn_name}, {"prefix", r.net.prefix}};
  }

  static std::vector<std::string> split_bar(const std::string& text) {
    std::vector<std::string> out;
    std::size_t start = 0;
    while (start <= text.size()) {
      std::size_t end = text.find('|', start);
      if (end == std::string::npos) end = text.size();
      out.push_back(trim(text.substr(start, end - start)));
      start = end + 1;
    }
    return out;
  }

  std::string url_;
  std::vector<std::string> types_;
};

// ===========================================================================
// domain: certificate transparency (crt.sh)
// ===========================================================================
class crtsh_provider final : public base_provider {
 public:
  explicit crtsh_provider(const config& cfg)
      : base_provider("crtsh", 6, 2, 1, 0.3), url_(cfg.urls.crtsh) {}
  bool supports(artifact_type t) const override { return t == artifact_type::domain; }

  query_result query(const artifact& art, provider_context& ctx) override {
    query_result r;
    http_request req;
    req.url = url_ + "/?output=json&q=%25." + url_encode(art.value);
    req.headers = json_headers();
    req.timeout_ms = 45000;
    const fetched f = fetch(ctx, req);
    note(r, f);
    if (!f.ok || !f.body.is_array()) return r;

    std::set<std::string> names;
    std::string newest;
    for (const json& cert : f.body) {
      std::istringstream lines(jstr(cert, "name_value"));
      std::string line;
      while (std::getline(lines, line)) {
        line = to_lower(trim(line));
        if (starts_with(line, "*.")) line.erase(0, 2);
        if (line == art.value || (line.size() > art.value.size() && line.compare(line.size() - art.value.size() - 1, std::string::npos, "." + art.value) == 0)) {
          if (names.size() < 300) names.insert(line);
        }
      }
      newest = std::max(newest, jstr(cert, "not_before"));
    }
    finding fd = make_finding(f);
    r.net.subdomains.assign(names.begin(), names.end());
    fd.summary = std::to_string(f.body.size()) + " certificate(s), " + std::to_string(names.size()) + " distinct name(s)" +
                 (newest.empty() ? "" : ", newest issued " + newest);
    fd.data = {{"certificates", f.body.size()}, {"names", r.net.subdomains.size()}, {"newest_not_before", newest}};
    r.findings.push_back(std::move(fd));
    return r;
  }

 private:
  std::string url_;
};

// ===========================================================================
// CVE: CISA KEV (local catalog), EPSS, NVD
// ===========================================================================
class kev_provider final : public provider {
 public:
  std::string name() const override { return "cisa_kev"; }
  bool supports(artifact_type t) const override { return t == artifact_type::cve; }
  int concurrency() const override { return 1; }

  query_result query(const artifact& art, provider_context& ctx) override {
    query_result r;
    if (ctx.kev == nullptr || !ctx.kev->loaded()) {
      r.errors.push_back({name(), "CISA KEV catalog not loaded", 0, false});
      return r;
    }
    const kev_entry* entry = ctx.kev->find(art.value);
    if (entry == nullptr) return r;               // not exploited in the wild (per CISA)

    finding fd;
    fd.provider = name();
    fd.outcome = verdict::malicious;
    fd.confidence = 95;
    fd.weight = 1.0;
    fd.tags = {"cisa-kev", "exploited-in-the-wild"};
    if (entry->ransomware_use) fd.tags.push_back("ransomware");
    fd.summary = "actively exploited (CISA KEV): " + entry->name + ", added " + entry->date_added +
                 ", remediation due " + entry->due_date + (entry->ransomware_use ? ", used in ransomware campaigns" : "");
    fd.references.push_back("https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
    json k = {{"vendor", entry->vendor}, {"product", entry->product}, {"name", entry->name},
              {"date_added", entry->date_added}, {"due_date", entry->due_date},
              {"required_action", entry->required_action}, {"ransomware", entry->ransomware_use},
              {"cwes", entry->cwes}, {"description", entry->description}};
    fd.data = k;
    r.knowledge = k;
    r.findings.push_back(std::move(fd));
    return r;
  }
};

class epss_provider final : public base_provider {
 public:
  explicit epss_provider(const config& cfg) : base_provider("epss", 60, 5, 2, 0.5), url_(cfg.urls.epss) {}
  bool supports(artifact_type t) const override { return t == artifact_type::cve; }

  query_result query(const artifact& art, provider_context& ctx) override {
    query_result r;
    http_request req;
    req.url = url_ + "?cve=" + url_encode(art.value);
    req.headers = json_headers();
    const fetched f = fetch(ctx, req);
    note(r, f);
    if (!f.ok) return r;
    const json* data = jget(f.body, "data");
    if (data == nullptr || !data->is_array() || data->empty()) return r;
    const json& row = (*data)[0];
    const double epss = jnum(row, "epss"), percentile = jnum(row, "percentile");

    finding fd = make_finding(f);
    if (epss >= 0.5) {
      fd.outcome = verdict::suspicious;
      fd.confidence = clamp_int(epss * 100.0);
    }
    fd.summary = "EPSS " + std::to_string(static_cast<int>(std::round(epss * 100))) + "% exploitation probability (percentile " +
                 std::to_string(static_cast<int>(std::round(percentile * 100))) + ")";
    fd.data = {{"epss", epss}, {"percentile", percentile}, {"date", jstr(row, "date")}};
    r.knowledge = fd.data;
    r.findings.push_back(std::move(fd));
    return r;
  }

 private:
  std::string url_;
};

// ===========================================================================
// CVE: NVD public API
// ===========================================================================
// Keyless by design: the public NVD API answers without credentials, so this
// provider always runs and a blank NVD_API_KEY is not a missing key. The key is
// optional and only lifts the published limit (5 requests / 30 s anonymous, 50
// with one); the per-minute rates below stay under both in either case.
//
// Two NVD quirks the generic status handling gets wrong:
//   * Throttling is answered with 403 (not 429), so status_note() spells that out
//     instead of blaming the credentials.
//   * An invalid apiKey is answered with a 404 and an empty body - the reason only
//     appears in a response header - which without the check below would look
//     exactly like "this CVE is not in NVD".
class nvd_provider final : public base_provider {
 public:
  explicit nvd_provider(const config& cfg)
      : base_provider("nvd", cfg.keys.nvd.empty() ? 8 : 80, 3, 1, 0.3), url_(cfg.urls.nvd), key_(cfg.keys.nvd) {}
  bool supports(artifact_type t) const override { return t == artifact_type::cve; }

  query_result query(const artifact& art, provider_context& ctx) override {
    query_result r;
    http_request req;
    req.url = url_ + "?cveId=" + url_encode(art.value);
    req.headers = json_headers();
    if (!key_.empty()) req.headers.push_back({"apiKey", key_});
    const fetched f = fetch(ctx, req);
    note(r, f);
    if (f.not_found && !key_.empty() && f.body.is_null()) {
      r.errors.push_back({name(),
                          "HTTP 404 with an empty body while NVD_API_KEY is set - NVD answers an invalid key "
                          "with 404, so this may be a key problem rather than a missing CVE",
                          f.status, false});
    }
    if (!f.ok) return r;
    const json* list = jget(f.body, "vulnerabilities");
    if (list == nullptr || !list->is_array() || list->empty()) return r;
    const json cve = (*list)[0].value("cve", json::object());

    std::string description;
    if (const json* descs = jget(cve, "descriptions"); descs != nullptr && descs->is_array()) {
      for (const json& d : *descs) if (jstr(d, "lang") == "en") { description = jstr(d, "value"); break; }
    }
    double score = -1;
    std::string severity, vector;
    const json metrics = cve.value("metrics", json::object());
    for (const char* key : {"cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"}) {
      const json* m = jget(metrics, key);
      if (m == nullptr || !m->is_array() || m->empty()) continue;
      const json data = (*m)[0].value("cvssData", json::object());
      score = jnum(data, "baseScore", -1);
      severity = jstr(data, "baseSeverity").empty() ? jstr((*m)[0], "baseSeverity") : jstr(data, "baseSeverity");
      vector = jstr(data, "vectorString");
      break;
    }
    std::vector<std::string> cwes;
    if (const json* weaknesses = jget(cve, "weaknesses"); weaknesses != nullptr && weaknesses->is_array()) {
      for (const json& w : *weaknesses) {
        if (const json* d = jget(w, "description"); d != nullptr && d->is_array()) {
          for (const json& x : *d) add_unique(cwes, jstr(x, "value"));
        }
      }
    }
    finding fd = make_finding(f);
    fd.summary = (score >= 0 ? "CVSS " + std::to_string(score).substr(0, 4) + " " + severity + ": " : std::string()) +
                 (description.size() > 160 ? description.substr(0, 157) + "..." : description);
    fd.data = {{"cvss", score}, {"severity", severity}, {"vector", vector}, {"published", jstr(cve, "published")},
               {"last_modified", jstr(cve, "lastModified")}, {"cwes", cwes}, {"description", description},
               {"in_cisa_kev", !jstr(cve, "cisaExploitAdd").empty()}};
    r.knowledge = fd.data;
    fd.references.push_back("https://nvd.nist.gov/vuln/detail/" + art.value);
    r.findings.push_back(std::move(fd));
    return r;
  }

 protected:
  std::string status_note(long status) const override {
    if (status == 403)
      return "rate limited (HTTP 403): the NVD public API blocks clients that exceed its limit "
             "(5 requests / 30 s without an API key, 50 with one)";
    return {};
  }

 private:
  std::string url_, key_;
};

// ===========================================================================
// ATT&CK technique: MITRE (local database)
// ===========================================================================
class mitre_provider final : public provider {
 public:
  std::string name() const override { return "mitre_attack"; }
  bool supports(artifact_type t) const override { return t == artifact_type::technique; }
  int concurrency() const override { return 1; }

  query_result query(const artifact& art, provider_context& ctx) override {
    query_result r;
    if (ctx.attack == nullptr || !ctx.attack->loaded()) {
      r.errors.push_back({name(), "MITRE ATT&CK data not loaded", 0, false});
      return r;
    }
    const attack_technique* t = ctx.attack->technique(art.value);
    finding fd;
    fd.provider = name();
    fd.weight = 0.0;                                  // context only, never changes a verdict
    if (t == nullptr) {
      fd.summary = art.value + " is not in the loaded ATT&CK version";
      r.findings.push_back(std::move(fd));
      return r;
    }
    std::vector<std::string> tactic_names;
    for (const std::string& shortname : t->tactics) {
      const std::string n = ctx.attack->tactic_name(shortname);
      tactic_names.push_back(n.empty() ? shortname : n);
    }
    json groups = json::array(), software = json::array();
    for (std::size_t i = 0; i < t->groups.size() && i < 30; ++i) groups.push_back({{"id", t->groups[i].id}, {"name", t->groups[i].name}});
    for (std::size_t i = 0; i < t->software.size() && i < 30; ++i) software.push_back({{"id", t->software[i].id}, {"name", t->software[i].name}, {"type", t->software[i].type}});

    fd.summary = t->id + " " + t->name + " [" + join(tactic_names, ", ") + "], used by " + std::to_string(t->groups.size()) +
                 " group(s) and " + std::to_string(t->software.size()) + " software";
    fd.tags = t->tactics;
    fd.references.push_back(t->url);
    r.knowledge = {{"id", t->id}, {"name", t->name}, {"url", t->url}, {"tactics", tactic_names}, {"tactic_shortnames", t->tactics},
                   {"platforms", t->platforms}, {"subtechnique", t->is_subtechnique}, {"parent", t->parent_id},
                   {"mitigations", t->mitigation_count}, {"group_count", t->groups.size()}, {"groups", groups},
                   {"software_count", t->software.size()}, {"software", software}};
    fd.data = {{"tactics", tactic_names}, {"groups", t->groups.size()}, {"software", t->software.size()}};
    r.findings.push_back(std::move(fd));
    return r;
  }
};

}  // namespace

std::vector<std::unique_ptr<provider>> make_default_providers(const config& cfg) {
  std::vector<std::unique_ptr<provider>> all;
  all.push_back(std::make_unique<dns_provider>(cfg));
  all.push_back(std::make_unique<rdap_provider>(cfg));
  all.push_back(std::make_unique<internetdb_provider>(cfg));
  all.push_back(std::make_unique<abuseipdb_provider>(cfg));
  all.push_back(std::make_unique<greynoise_provider>(cfg));
  all.push_back(std::make_unique<otx_provider>(cfg));
  all.push_back(std::make_unique<threatfox_provider>(cfg));
  all.push_back(std::make_unique<urlhaus_provider>(cfg));
  all.push_back(std::make_unique<malwarebazaar_provider>(cfg));
  all.push_back(std::make_unique<virustotal_provider>(cfg));
  all.push_back(std::make_unique<circl_provider>(cfg));
  all.push_back(std::make_unique<crtsh_provider>(cfg));
  all.push_back(std::make_unique<kev_provider>());
  all.push_back(std::make_unique<epss_provider>(cfg));
  all.push_back(std::make_unique<nvd_provider>(cfg));
  all.push_back(std::make_unique<mitre_provider>());

  all.erase(std::remove_if(all.begin(), all.end(),
                           [&](const std::unique_ptr<provider>& p) { return cfg.disabled_providers.count(p->name()) != 0; }),
            all.end());
  return all;
}

// ===========================================================================
// cti_pipeline.cpp
// ===========================================================================
namespace fs = std::filesystem;

namespace {

// Used when libcurl cannot be initialised: every request fails cleanly instead of crashing.
class failing_http_client final : public http_client {
 public:
  http_response perform(const http_request&) override {
    http_response r;
    r.error = "no HTTP client available";
    return r;
  }
};

bool internal_name(const std::string& domain) {
  static const char* suffixes[] = {".local", ".localdomain", ".internal", ".lan", ".home.arpa", ".intranet", ".corp"};
  if (domain == "localhost") return true;
  for (const char* s : suffixes) {
    const std::string suffix = s;
    if (domain.size() > suffix.size() && domain.compare(domain.size() - suffix.size(), suffix.size(), suffix) == 0) return true;
  }
  return false;
}

int priority_of(const artifact& a) {
  int rank = 6;
  switch (a.type) {
    case artifact_type::sha256: case artifact_type::sha1: case artifact_type::md5: case artifact_type::sha512: rank = 0; break;
    case artifact_type::url: rank = 1; break;
    case artifact_type::domain: rank = 2; break;
    case artifact_type::ip: rank = 3; break;
    case artifact_type::email: rank = 4; break;
    case artifact_type::cve: rank = 5; break;
    default: break;
  }
  return rank + (a.derived_from.empty() ? 0 : 10);
}

std::string family_key(std::string name) {
  name = to_lower(std::move(name));
  name.erase(std::remove_if(name.begin(), name.end(), [](char c) { return c == ' ' || c == '_' || c == '-' || c == '.'; }), name.end());
  return name;
}

void add_unique_pl(std::vector<std::string>& list, const std::string& value) {
  if (!value.empty() && std::find(list.begin(), list.end(), value) == list.end()) list.push_back(value);
}

// ---------------------------------------------------------------------------
// scoring: noisy-OR over the findings, weighted by provider trust
//   malicious finding   p = confidence * weight
//   suspicious finding  p = confidence * weight * 0.6
//   score = 1 - prod(1 - p)         >= 70 malicious, >= 30 suspicious
//   a strong benign finding (known-good file, RIOT service, whitelisted) wins over "suspicious"
// ---------------------------------------------------------------------------
void score_item(enrichment& e) {
  double miss = 1.0;
  double benign = 0.0;
  struct contribution { std::string provider; double p; };
  std::vector<contribution> contributions;

  for (const finding& f : e.findings) {
    const double c = std::max(0, std::min(100, f.confidence)) / 100.0;
    double p = 0.0;
    if (f.outcome == verdict::malicious) p = c * f.weight;
    else if (f.outcome == verdict::suspicious) p = c * f.weight * 0.6;
    else if (f.outcome == verdict::benign) benign = std::max(benign, c * std::max(f.weight, 0.3));
    if (p > 0.0) {
      miss *= (1.0 - p);
      contributions.push_back({f.provider, p});
    }
    for (const std::string& fam : f.families) {          // "AgentTesla" == "agenttesla"
      const bool known = std::any_of(e.families.begin(), e.families.end(), [&](const std::string& x) { return family_key(x) == family_key(fam); });
      if (!known && !fam.empty()) e.families.push_back(fam);
    }
    for (const std::string& tag : f.tags) if (e.tags.size() < 15) add_unique_pl(e.tags, tag);
  }
  for (const std::string& tag : e.art.tags) if (e.tags.size() < 20) add_unique_pl(e.tags, tag);

  e.score = static_cast<int>(std::round((1.0 - miss) * 100.0));
  if (e.score >= 70) e.outcome = verdict::malicious;
  else if (e.score >= 30) e.outcome = verdict::suspicious;
  else if (benign >= 0.3) e.outcome = verdict::benign;
  else e.outcome = verdict::unknown;
  if (e.outcome == verdict::suspicious && benign * 100.0 >= e.score + 10) e.outcome = verdict::benign;

  std::sort(contributions.begin(), contributions.end(), [](const contribution& a, const contribution& b) { return a.p > b.p; });
  e.reason.clear();
  for (std::size_t i = 0; i < contributions.size() && i < 3; ++i) {
    e.reason += (i == 0 ? "" : ", ") + contributions[i].provider + " (" + std::to_string(static_cast<int>(std::round(contributions[i].p * 100))) + ")";
  }
  if (e.outcome == verdict::benign) {
    for (const finding& f : e.findings) {
      if (f.outcome == verdict::benign) { e.reason = f.provider + ": " + f.summary; break; }
    }
  }
  if (e.reason.empty() && e.outcome == verdict::unknown) e.reason = e.findings.empty() ? "no provider had data" : "no provider flagged it";
}

}  // namespace

// ===========================================================================
// report helpers
// ===========================================================================
const enrichment* report::find(const std::string& key) const {
  for (const enrichment& e : items) if (e.art.key() == key) return &e;
  return nullptr;
}

std::size_t report::error_count() const {
  std::size_t n = 0;
  for (const enrichment& e : items) n += e.errors.size();
  return n;
}

// ===========================================================================
// pipeline
// ===========================================================================
pipeline::pipeline(config cfg, std::unique_ptr<http_client> http)
    : cfg_(std::move(cfg)),
      http_(std::move(http)),
      cache_(cfg_.cache_dir.empty() ? fs::path() : fs::path(cfg_.cache_dir) / "responses") {
  if (!http_) {
    try {
      http_ = make_curl_client(cfg_.http);
    } catch (const std::exception& ex) {
      warnings_.push_back("HTTP client creation failed: " + std::string(ex.what()));
    } catch (...) {
      warnings_.push_back("HTTP client creation failed: unknown error");
    }
  }
  if (!http_) {
    // A disconnected machine (or a libcurl initialisation failure) must not make
    // pipeline construction fail. All later network calls will return a normal
    // transport error and be recorded as CTI warnings.
    http_ = std::make_unique<failing_http_client>();
    if (warnings_.empty() || warnings_.back().find("HTTP client creation failed:") != 0) {
      warnings_.push_back("no internet connection or HTTP client unavailable: network providers will fail");
    }
  }
  providers_ = make_default_providers(cfg_);
}

pipeline::~pipeline() = default;

bool pipeline::network_available() const {
  if (!http_ || cfg_.offline) return false;

  try {
    http_request request;
    request.method = "HEAD";
    request.url = cfg_.urls.attack_stix;
    request.timeout_ms = 5000;
    request.max_response_bytes = 1;
    request.deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    const http_response response = http_->perform(request);
    return response.transport_ok;
  } catch (...) {
    return false;
  }
}

bool pipeline::add_internal(artifact art, bool derived) {
  const auto norm = normalize_artifact(art.value, art.type);
  if (!norm) return false;
  art.value = norm->value;
  art.type = norm->type;

  const std::string key = art.key();
  if (const auto it = index_.find(key); it != index_.end()) {
    artifact& existing = items_[it->second].art;
    existing.sources.insert(art.sources.begin(), art.sources.end());
    existing.tags.insert(art.tags.begin(), art.tags.end());
    return true;
  }
  if (derived) {
    if (derived_count_ >= cfg_.max_derived_artifacts) return false;
    ++derived_count_;
  } else if (items_.size() - derived_count_ >= cfg_.max_artifacts) {
    static const std::string message = "artifact limit reached (config.max_artifacts): the remaining ones were ignored";
    if (std::find(warnings_.begin(), warnings_.end(), message) == warnings_.end()) warnings_.push_back(message);
    return false;
  }

  enrichment e;
  e.art = std::move(art);
  items_.push_back(std::move(e));
  done_.emplace_back();
  index_[key] = items_.size() - 1;
  return true;
}

bool pipeline::add(artifact art) { return add_internal(std::move(art), false); }

bool pipeline::add_raw(const std::string& raw, const std::string& source, artifact_type hint) {
  artifact a;
  a.type = hint;
  a.value = raw;
  a.sources.insert(source.empty() ? "user" : source);
  return add_internal(std::move(a), false);
}

std::size_t pipeline::add_all(const std::vector<std::string>& raws, const std::string& source) {
  std::size_t added = 0;
  for (const std::string& raw : raws) added += add_raw(raw, source) ? 1 : 0;
  return added;
}

// ---------------------------------------------------------------------------
// knowledge bases
// ---------------------------------------------------------------------------
bool pipeline::load_knowledge() {
  try {
    return load_knowledge_impl();
  } catch (const std::exception& ex) {
    warnings_.push_back("CTI knowledge loading failed: " + std::string(ex.what()));
  } catch (...) {
    warnings_.push_back("CTI knowledge loading failed: unknown error");
  }
  return attack_.loaded() || kev_.loaded();
}

bool pipeline::load_knowledge_impl() {
  if (knowledge_loaded_) return attack_.loaded() || kev_.loaded();
  knowledge_loaded_ = true;
  if (!cfg_.load_knowledge) return false;

  const fs::path dir = (cfg_.cache_dir.empty() ? fs::temp_directory_path() / "cti-knowledge" : fs::path(cfg_.cache_dir) / "knowledge");
  std::string warning, error;
  const auto deadline = cfg_.provider_budget_seconds > 0
                            ? run_started_ + std::chrono::seconds(cfg_.provider_budget_seconds)
                            : std::chrono::steady_clock::time_point::max();

  const std::string attack_path = (dir / "enterprise-attack.json").string();
  if (refresh_file(*http_, cfg_.urls.attack_stix, attack_path,
                   std::chrono::hours(cfg_.attack_max_age_hours), cfg_.offline,
                   warning, error, deadline)) {
    if (std::chrono::steady_clock::now() >= deadline) {
      warnings_.push_back("MITRE ATT&CK: time budget exhausted before loading the knowledge bundle");
      return attack_.loaded() || kev_.loaded();
    }
    if (!warning.empty()) warnings_.push_back("MITRE ATT&CK: " + warning);
    if (!attack_.load_file(attack_path, error)) warnings_.push_back("MITRE ATT&CK: " + error);
  } else {
    warnings_.push_back("MITRE ATT&CK unavailable: " + error);
  }

  warning.clear();
  error.clear();
  const std::string kev_path = (dir / "known_exploited_vulnerabilities.json").string();
  if (std::chrono::steady_clock::now() >= deadline) {
    warnings_.push_back("CISA KEV unavailable: CTI time budget exhausted before download");
    return attack_.loaded() || kev_.loaded();
  }
  if (refresh_file(*http_, cfg_.urls.cisa_kev, kev_path,
                   std::chrono::hours(cfg_.kev_max_age_hours), cfg_.offline,
                   warning, error, deadline)) {
    if (std::chrono::steady_clock::now() >= deadline) {
      warnings_.push_back("CISA KEV: time budget exhausted before loading the knowledge bundle");
      return attack_.loaded() || kev_.loaded();
    }
    if (!warning.empty()) warnings_.push_back("CISA KEV: " + warning);
    if (!kev_.load_file(kev_path, error)) warnings_.push_back("CISA KEV: " + error);
  } else {
    warnings_.push_back("CISA KEV unavailable: " + error);
  }
  return attack_.loaded() || kev_.loaded();
}

// ---------------------------------------------------------------------------
// artifact expansion
// ---------------------------------------------------------------------------
void pipeline::expand_static() {
  const std::size_t count = items_.size();
  for (std::size_t i = 0; i < count; ++i) {
    const artifact base = items_[i].art;
    artifact d;
    d.sources.insert("derived");
    d.derived_from = base.key();
    if (base.type == artifact_type::email) {
      d.value = email_domain(base.value);
      d.type = artifact_type::domain;
    } else if (base.type == artifact_type::url) {
      d.value = url_host(base.value);
      if (!d.value.empty() && d.value.front() == '[') d.value = d.value.substr(1, d.value.size() - 2);
      d.type = artifact_type::unknown;               // domain or IP: auto-detected
    } else {
      continue;
    }
    if (!d.value.empty()) add_internal(std::move(d), true);
  }
}

// ---------------------------------------------------------------------------
// one round of provider queries
// ---------------------------------------------------------------------------
void pipeline::run_round(int round, const progress_callback& progress, std::vector<artifact>& new_derived) {
  provider_context ctx{*http_, cache_, cfg_, cfg_.offline, &attack_, &kev_};
  if (cfg_.provider_budget_seconds > 0) ctx.deadline = run_started_ + std::chrono::seconds(cfg_.provider_budget_seconds);

  struct job {
    provider* p = nullptr;
    std::vector<std::size_t> indices;
    std::atomic<std::size_t> next{0};
    std::atomic<bool> expired{false};
  };
  std::vector<std::unique_ptr<job>> jobs;
  std::size_t total = 0;

  for (const auto& p : providers_) {
    if (!p->configured()) {
      const std::string message = "provider '" + p->name() + "' skipped: set " + p->requirement();
      if (std::find(warnings_.begin(), warnings_.end(), message) == warnings_.end()) warnings_.push_back(message);
      continue;
    }
    auto j = std::make_unique<job>();
    j->p = p.get();
    for (std::size_t i = 0; i < items_.size(); ++i) {
      if (items_[i].skipped || !p->supports(items_[i].art.type) || done_[i].count(p->name()) != 0) continue;
      j->indices.push_back(i);
    }
    if (j->indices.empty()) continue;
    // Most valuable lookups first (matters for slow, rate limited providers such as VirusTotal
    // and for the time budget): hashes, URLs, domains, IPs; collected artifacts before derived ones.
    std::stable_sort(j->indices.begin(), j->indices.end(), [this](std::size_t a, std::size_t b) {
      return priority_of(items_[a].art) < priority_of(items_[b].art);
    });
    total += j->indices.size();
    jobs.push_back(std::move(j));
  }
  if (jobs.empty()) return;

  std::mutex mutex;
  std::size_t finished = 0;
  const bool has_deadline = cfg_.provider_budget_seconds > 0;
  const auto deadline = run_started_ + std::chrono::seconds(cfg_.provider_budget_seconds);

  auto worker = [&](job* j) {
    for (;;) {
      if (has_deadline && std::chrono::steady_clock::now() > deadline) {
        j->expired.store(true);
        return;
      }
      const std::size_t k = j->next.fetch_add(1);
      if (k >= j->indices.size()) return;
      const std::size_t index = j->indices[k];

      artifact art;
      {
        std::lock_guard<std::mutex> lock(mutex);
        art = items_[index].art;
      }
      query_result result;
      try {
        result = j->p->query(art, ctx);
      } catch (const std::exception& ex) {
        result.errors.push_back({j->p->name(), std::string("exception: ") + ex.what(), 0, false});
      } catch (...) {
        result.errors.push_back({j->p->name(), "unknown exception", 0, false});
      }

      std::lock_guard<std::mutex> lock(mutex);
      const bool out_of_budget = std::any_of(result.errors.begin(), result.errors.end(),
                                             [](const provider_error& err) { return starts_with(err.message, "budget:"); });
      if (out_of_budget) {           // not queried: stays pending, the provider stops for this run
        j->expired.store(true);
        return;
      }
      enrichment& e = items_[index];
      provider_stat& stat = stats_[j->p->name()];
      stat.provider = j->p->name();
      ++stat.queries;
      if (!result.findings.empty()) ++stat.answers;
      for (finding& f : result.findings) {
        if (f.from_cache) ++stat.cache_hits;
        if (f.outcome == verdict::malicious) ++stat.malicious;
        if (f.outcome == verdict::suspicious) ++stat.suspicious;
        e.findings.push_back(std::move(f));
      }
      for (provider_error& err : result.errors) {
        if (starts_with(err.message, "offline:")) {       // offline mode: a cache miss is not a failure
          ++stat.offline_misses;
          continue;
        }
        ++stat.errors;
        e.errors.push_back(std::move(err));
      }
      e.net.merge(result.net);
      if (!result.knowledge.is_null()) e.knowledge[j->p->name()] = std::move(result.knowledge);
      for (artifact& d : result.derived) new_derived.push_back(std::move(d));
      done_[index].insert(j->p->name());
      ++finished;
      if (progress) progress({round, finished, total, j->p->name(), art.key()});
    }
  };

  std::vector<std::thread> threads;
  for (const auto& j : jobs) {
    const std::size_t n = std::min<std::size_t>(std::max(1, j->p->concurrency()), j->indices.size());
    for (std::size_t i = 0; i < n; ++i) threads.emplace_back(worker, j.get());
  }
  for (std::thread& t : threads) t.join();

  for (const auto& j : jobs) {
    if (!j->expired.load()) continue;
    std::size_t pending = 0;
    for (std::size_t i : j->indices) pending += done_[i].count(j->p->name()) == 0 ? 1 : 0;
    if (pending == 0) continue;
    if (!budget_warned_.insert(j->p->name()).second) continue;      // one warning per provider
    warnings_.push_back("provider '" + j->p->name() + "' stopped: time budget of " +
                        std::to_string(cfg_.provider_budget_seconds) + " s exhausted (" +
                        std::to_string(pending) + "+ artifact(s) not queried)");
  }
}

// ---------------------------------------------------------------------------
// run
// ---------------------------------------------------------------------------
report pipeline::run(const progress_callback& progress) {
  const auto started = std::chrono::steady_clock::now();
  run_started_ = started;
  try {
    load_knowledge();
  } catch (const std::exception& ex) {
    warnings_.push_back("CTI knowledge loading failed: " + std::string(ex.what()));
  } catch (...) {
    warnings_.push_back("CTI knowledge loading failed: unknown error");
  }
  expand_static();

  // Hashes of empty input: they identify "no data", not a file (e.g. an empty string constant).
  static const std::set<std::string> empty_hashes = {
      "d41d8cd98f00b204e9800998ecf8427e", "da39a3ee5e6b4b0d3255bfef95601890afd80709",
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"};
  auto mark_skipped = [this]() {
    for (enrichment& e : items_) {
      if (e.skipped) continue;
      if (is_hash(e.art.type) && empty_hashes.count(e.art.value) != 0) {
        e.skipped = true;
        e.skip_reason = "hash of an empty input";
        continue;
      }
      if (e.art.type == artifact_type::ip && cfg_.skip_non_public_ips && !is_public_ip(e.art.value)) {
        e.skipped = true;
        e.skip_reason = std::string("non-public address (") + to_string(classify_ip(e.art.value)) + ")";
      } else if (e.art.type == artifact_type::domain && internal_name(e.art.value)) {
        e.skipped = true;
        e.skip_reason = "internal / non-routable name";
      }
    }
  };

  for (int round = 0; round <= std::max(0, cfg_.derived_rounds); ++round) {
    mark_skipped();
    std::vector<artifact> new_derived;
    run_round(round, progress, new_derived);

    std::size_t before = items_.size();
    for (artifact& d : new_derived) add_internal(std::move(d), true);
    if (items_.size() == before) break;            // nothing new to follow up
  }
  mark_skipped();

  report out;
  finalize(out);
  out.seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - started).count();
  return out;
}

// ---------------------------------------------------------------------------
// ATT&CK tactic matrix
// ---------------------------------------------------------------------------
// Resolves the knowledge cache the same way attack_details_for() does:
// $CTI_CACHE_DIR (default cti-cache)/knowledge/enterprise-attack.json, with an
// empty base meaning "caching disabled" -> the temp-dir fallback.
static fs::path knowledge_bundle_path(const std::string& bundle_path) {
  if (!bundle_path.empty()) return fs::path(bundle_path);
  const std::string base = env_or("CTI_CACHE_DIR", "cti-cache");
  return base.empty() ? fs::temp_directory_path() / "cti-knowledge" / "enterprise-attack.json"
                      : fs::path(base) / "knowledge" / "enterprise-attack.json";
}

const attack_db& shared_attack_db() {
  // Function-local static: thread-safe initialisation, and the bundle is parsed
  // on first use only. A second load would cost another ~50 MB of peak memory.
  static attack_db db;
  static bool attempted = false;
  if (!attempted) {
    attempted = true;
    std::string error;
    if (!db.load_file(knowledge_bundle_path("").string(), error))
      LOG_DEBUG("cti: shared ATT&CK db unavailable: {}", error);
  }
  return db;
}

// Builds the per-tactic view from a set of observed technique ids.
//
// Deliberately a free function over plain ids rather than a pipeline member: the
// matrix needs ATT&CK knowledge (local cache) and the observed techniques,
// neither of which involves a provider. The export phase therefore calls this
// directly with capa's technique ids, so the tactic view is populated on an
// offline run and under CTI_SKIP=1 instead of only when the CTI phase ran.
//
// `hits` is how many capa capabilities matched each technique; it decides the
// order within a tactic so the strongest evidence leads.
std::vector<tactic_coverage> build_attack_matrix(const attack_db& attack,
                                                 const std::vector<std::string>& technique_ids,
                                                 const std::map<std::string, std::size_t>& hits) {
  std::map<std::string, tactic_coverage> matrix;

  const auto lookup_hits = [&](const std::string& id) {
    const auto it = hits.find(to_upper(id));
    return it == hits.end() ? std::size_t{1} : it->second;
  };

  for (const std::string& raw_id : technique_ids) {
    const std::string wanted = to_upper(raw_id);
    if (wanted.empty()) continue;
    const attack_technique* t = attack.technique(wanted);
    if (t == nullptr) {
      // ATT&CK does not know this id (a stale cache, or a rule naming a
      // technique that was never published). Still worth showing, but there is
      // nothing to expand, so it lands in one bucket instead of a real tactic.
      tactic_coverage& c = matrix["unknown"];
      c.shortname = "unknown";
      c.name = "Unknown tactic";
      tactic_procedure p;
      p.id = wanted;
      p.name = "not in the loaded ATT&CK version";
      p.capability_hits = lookup_hits(wanted);
      c.procedures.push_back(std::move(p));
      continue;
    }
    // Everything attached here comes from the local ATT&CK cache, so it is
    // available offline and under CTI_SKIP=1.
    tactic_procedure p;
    p.id = t->id;
    p.name = t->name;
    p.url = t->url;
    p.parent_id = t->parent_id;
    p.is_subtechnique = t->is_subtechnique;
    p.platforms = t->platforms;
    p.software = t->software;
    p.groups = t->groups;
    p.detections = t->detections;
    p.subtechniques = t->subtechniques;
    p.mitigation_count = t->mitigation_count;
    p.description = t->description;
    p.capability_hits = lookup_hits(t->id);

    if (t->tactics.empty()) {
      tactic_coverage& c = matrix["unknown"];
      c.shortname = "unknown";
      c.name = "Unknown tactic";
      c.procedures.push_back(std::move(p));
      continue;
    }
    for (const std::string& shortname : t->tactics) {
      tactic_coverage& c = matrix[shortname];
      c.shortname = shortname;
      c.name = attack.tactic_name(shortname).empty() ? shortname : attack.tactic_name(shortname);
      c.procedures.push_back(p);   // one copy per tactic; a technique can sit under several
    }
  }

  // Strongest evidence first, then by id so two runs over the same sample emit
  // identical output. Duplicates collapse because a technique is seeded once
  // but may be listed under the same tactic twice by two sources.
  for (auto& [key, cov] : matrix) {
    std::sort(cov.procedures.begin(), cov.procedures.end(),
              [](const tactic_procedure& a, const tactic_procedure& b) {
                if (a.capability_hits != b.capability_hits) return a.capability_hits > b.capability_hits;
                return a.id < b.id;
              });
    cov.procedures.erase(std::unique(cov.procedures.begin(), cov.procedures.end(),
                                     [](const tactic_procedure& a, const tactic_procedure& b) {
                                       return a.id == b.id;
                                     }),
                         cov.procedures.end());
  }

  // Kill-chain order, with the unattributed bucket last.
  std::vector<tactic_coverage> out;
  for (const attack_tactic& tactic : attack.tactics())
    if (const auto it = matrix.find(tactic.shortname); it != matrix.end())
      out.push_back(std::move(it->second));
  if (const auto it = matrix.find("unknown"); it != matrix.end()) out.push_back(std::move(it->second));
  return out;
}

// Groups sharing the most observed techniques: the attribution candidates.
std::vector<group_match> build_likely_groups(const attack_db& attack,
                                             const std::vector<std::string>& technique_ids) {
  std::map<std::string, group_match> groups;
  for (const std::string& raw_id : technique_ids) {
    const attack_technique* t = attack.technique(raw_id);
    if (t == nullptr) continue;
    for (const attack_group& g : t->groups) {
      group_match& m = groups[g.id];
      m.id = g.id;
      m.name = g.name;
      ++m.techniques_matched;
      if (std::find(m.techniques.begin(), m.techniques.end(), t->id) == m.techniques.end())
        m.techniques.push_back(t->id);
    }
  }
  std::vector<group_match> out;
  for (auto& [id, m] : groups)
    if (m.techniques_matched >= 2) out.push_back(std::move(m));
  std::sort(out.begin(), out.end(), [](const group_match& a, const group_match& b) {
    return a.techniques_matched != b.techniques_matched ? a.techniques_matched > b.techniques_matched
                                                        : a.name < b.name;
  });
  return out;
}

#ifdef CTI_WITH_COLLECT
// How many capa capabilities matched each technique, used to rank within a tactic.
std::map<std::string, std::size_t> capa_hit_counts(const capa::report_t& capa_report) {
  std::map<std::string, std::size_t> hits;
  for (const capa::capability_t& cap : capa_report.capabilities)
    for (const capa::attack_t& att : cap.attack)
      if (!att.id.empty()) ++hits[to_upper(att.id)];
  return hits;
}
#endif  // CTI_WITH_COLLECT

// ---------------------------------------------------------------------------
// scoring + correlation
// ---------------------------------------------------------------------------
void pipeline::finalize(report& out) {
  for (enrichment& e : items_) score_item(e);

  // Infrastructure inherits suspicion: a domain that resolves to a malicious IP, a URL served
  // from a malicious host, an e-mail sent from a malicious domain. Only artifacts that are not
  // already malicious (or known good) are touched, and only from directly observed verdicts.
  {
    std::vector<std::pair<std::size_t, finding>> inherited;
    auto lookup = [this](const std::string& key) -> const enrichment* {
      const auto it = index_.find(key);
      return it == index_.end() ? nullptr : &items_[it->second];
    };
    for (std::size_t i = 0; i < items_.size(); ++i) {
      const enrichment& e = items_[i];
      if (e.skipped || e.outcome == verdict::malicious || e.outcome == verdict::benign) continue;
      std::string why;
      int confidence = 0;
      if (e.art.type == artifact_type::domain) {
        for (const std::string& ip : e.net.resolved_ips) {
          const enrichment* host = lookup("ip:" + ip);
          if (host != nullptr && host->outcome == verdict::malicious) {
            why = "resolves to malicious IP " + ip;
            confidence = 60;
            break;
          }
        }
      } else if (e.art.type == artifact_type::url) {
        std::string host = url_host(e.art.value);
        if (host.size() > 2 && host.front() == '[') host = host.substr(1, host.size() - 2);
        for (const char* type : {"domain:", "ip:"}) {
          const enrichment* item = lookup(type + host);
          if (item != nullptr && item->outcome == verdict::malicious) {
            why = "served from malicious host " + host;
            confidence = 70;
            break;
          }
        }
      } else if (e.art.type == artifact_type::email) {
        const enrichment* item = lookup("domain:" + email_domain(e.art.value));
        if (item != nullptr && item->outcome == verdict::malicious) {
          why = "sender domain " + item->art.value + " is malicious";
          confidence = 75;
        }
      }
      if (why.empty()) continue;
      const bool duplicate = std::any_of(e.findings.begin(), e.findings.end(), [&](const finding& f) { return f.provider == "correlation" && f.summary == why; });
      if (duplicate) continue;
      finding f;
      f.provider = "correlation";
      f.outcome = verdict::suspicious;
      f.confidence = confidence;
      f.weight = 0.8;
      f.summary = why;
      f.tags = {"inherited-suspicion"};
      inherited.emplace_back(i, std::move(f));
    }
    for (auto& [index, f] : inherited) {
      items_[index].findings.push_back(std::move(f));
      score_item(items_[index]);
    }
  }
  // Enrich every IP artifact with deterministic network metadata. If a provider supplied
  // a prefix, use its CIDR length; otherwise use the host route (/32 or /128).
  for (enrichment& e : items_) {
    if (e.art.type == artifact_type::ip) populate_ip_info(e.net, e.art.value);
  }

  out.items = items_;
  out.generated_at = iso8601(now_epoch());
  out.sample = sample_;
  out.attack_version = attack_.version();
  out.kev_version = kev_.catalog_version();
  out.warnings = warnings_;

  // --- counts
  for (const enrichment& e : items_) {
    ++out.counts_by_type[to_string(e.art.type)];
    ++out.counts_by_verdict[e.skipped ? "skipped" : to_string(e.outcome)];
  }

  // --- provider statistics
  for (const auto& [name, stat] : stats_) if (stat.queries > 0) out.provider_stats.push_back(stat);

  // --- malware families across artifacts
  std::map<std::string, family_summary> families;
  for (const enrichment& e : items_) {
    for (const finding& f : e.findings) {
      for (const std::string& fam : f.families) {
        if (fam.empty()) continue;
        family_summary& fs_entry = families[family_key(fam)];
        if (fs_entry.name.empty()) fs_entry.name = fam;
        add_unique_pl(fs_entry.artifacts, e.art.key());
        add_unique_pl(fs_entry.providers, f.provider);
      }
    }
  }
  for (auto& [key, fam] : families) out.families.push_back(std::move(fam));
  std::sort(out.families.begin(), out.families.end(), [](const family_summary& a, const family_summary& b) {
    return a.artifacts.size() != b.artifacts.size() ? a.artifacts.size() > b.artifacts.size() : a.name < b.name;
  });

  // --- ATT&CK matrix and the groups that share the most techniques.
  // Shared with the export phase so an offline run gets the same view: see
  // build_attack_matrix() for why this is not pipeline-only.
  {
    std::vector<std::string> technique_ids;
    for (const enrichment& e : items_)
      if (e.art.type == artifact_type::technique && !e.skipped)
        technique_ids.push_back(e.art.value);
    out.attack_matrix = build_attack_matrix(attack_, technique_ids, {});
    out.likely_groups = build_likely_groups(attack_, technique_ids);
    if (out.likely_groups.size() > 8) out.likely_groups.resize(8);
  }

  // --- shared infrastructure
  std::map<std::string, std::vector<std::string>> domains_by_ip;
  std::map<std::string, const enrichment*> ip_items;
  for (const enrichment& e : items_) {
    if (e.art.type == artifact_type::ip) ip_items[e.art.value] = &e;
    if (e.art.type != artifact_type::domain) continue;
    for (const std::string& ip : e.net.resolved_ips) add_unique_pl(domains_by_ip[ip], e.art.value);
  }
  for (auto& [ip, domains] : domains_by_ip) {
    if (domains.size() < 2) continue;
    shared_host h;
    h.ip = ip;
    h.domains = domains;
    if (const auto it = ip_items.find(ip); it != ip_items.end()) {
      h.asn = it->second->net.asn;
      h.asn_name = it->second->net.asn_name;
    }
    out.shared_hosting.push_back(std::move(h));
  }
  std::map<std::string, asn_cluster> clusters;
  for (const auto& [ip, e] : ip_items) {
    if (e->net.asn.empty()) continue;
    asn_cluster& c = clusters[e->net.asn];
    c.asn = e->net.asn;
    if (c.asn_name.empty()) c.asn_name = e->net.asn_name;
    c.ips.push_back(ip);
  }
  for (auto& [asn, c] : clusters) if (c.ips.size() >= 2) out.asn_clusters.push_back(std::move(c));

  // --- CISA KEV hits
  for (const enrichment& e : items_) {
    if (e.art.type != artifact_type::cve) continue;
    for (const finding& f : e.findings) {
      if (f.provider == "cisa_kev") add_unique_pl(out.kev_cves, e.art.value);
    }
  }

  std::size_t skipped = 0;
  for (const enrichment& e : items_) skipped += e.skipped ? 1 : 0;
  if (skipped > 0) out.warnings.push_back(std::to_string(skipped) + " artifact(s) skipped (private / internal)");
}

// ===========================================================================
// cti_export.cpp
// ===========================================================================
namespace {

json network_json(const network_context& n) {
  json j = json::object();
  auto put = [&j](const char* key, const std::vector<std::string>& v) { if (!v.empty()) j[key] = v; };
  auto text = [&j](const char* key, const std::string& v) { if (!v.empty()) j[key] = v; };
  put("resolved_ips", n.resolved_ips);
  put("hostnames", n.hostnames);
  put("nameservers", n.nameservers);
  put("mail_servers", n.mail_servers);
  put("txt_records", n.txt_records);
  put("subdomains", n.subdomains);
  put("cpes", n.cpes);
  put("vulns", n.vulns);
  if (!n.open_ports.empty()) j["open_ports"] = n.open_ports;
  text("asn", n.asn);
  text("asn_name", n.asn_name);
  text("prefix", n.prefix);
  text("country", n.country);
  text("org", n.org);
  text("registrar", n.registrar);
  text("domain_created", n.domain_created);
  text("domain_expires", n.domain_expires);
  text("ip_version", n.ip_version);
  text("ip_class", n.ip_class);
  text("cidr", n.cidr);
  text("subnet_mask", n.subnet_mask);
  text("network_address", n.network_address);
  text("broadcast_address", n.broadcast_address);
  if (n.address_bits >= 0) j["address_bits"] = n.address_bits;
  if (n.prefix_bits >= 0) j["prefix_bits"] = n.prefix_bits;
  if (n.domain_age_days >= 0) j["domain_age_days"] = n.domain_age_days;
  if (n.nxdomain) j["nxdomain"] = true;
  return j;
}

bool flagged(const enrichment& e) {
  return e.outcome == verdict::suspicious || e.outcome == verdict::malicious ||
         e.art.type == artifact_type::cve || e.art.type == artifact_type::technique;
}

}  // namespace

// ===========================================================================
// JSON
// ===========================================================================
std::string to_json(const report& r, const json_export_options& options) {
  json j;
  j["generated_at"] = r.generated_at;
  j["seconds"] = r.seconds;
  j["versions"] = {{"mitre_attack", r.attack_version}, {"cisa_kev_catalog", r.kev_version}};
  j["summary"] = {{"artifacts", r.items.size()}, {"by_type", r.counts_by_type}, {"by_verdict", r.counts_by_verdict},
                  {"provider_errors", r.error_count()}};
  j["sample"] = r.sample;

  json artifacts = json::array();
  for (const enrichment& e : r.items) {
    if (options.only_flagged && !flagged(e)) continue;
    json findings = json::array();
    for (const finding& f : e.findings) {
      json item = {{"provider", f.provider}, {"verdict", to_string(f.outcome)}, {"confidence", f.confidence},
                   {"weight", f.weight}, {"summary", f.summary}, {"tags", f.tags}, {"families", f.families},
                   {"references", f.references}, {"from_cache", f.from_cache}};
      if (options.include_finding_data && !f.data.is_null()) item["data"] = f.data;
      findings.push_back(std::move(item));
    }
    json errors = json::array();
    for (const provider_error& err : e.errors) {
      errors.push_back({{"provider", err.provider}, {"message", err.message}, {"http_status", err.http_status},
                        {"retryable", err.retryable}});
    }
    json item = {{"type", to_string(e.art.type)}, {"value", e.art.value},
                 {"sources", e.art.sources}, {"tags", e.tags}, {"verdict", to_string(e.outcome)},
                 {"score", e.score}, {"reason", e.reason}, {"families", e.families}};
    if (!e.art.derived_from.empty()) item["derived_from"] = e.art.derived_from;
    if (e.skipped) { item["skipped"] = true; item["skip_reason"] = e.skip_reason; }
    const json net = network_json(e.net);
    if (!net.empty()) item["network"] = net;
    if (!e.knowledge.is_null() && !e.knowledge.empty()) item["knowledge"] = e.knowledge;
    item["findings"] = std::move(findings);
    if (!errors.empty()) item["errors"] = std::move(errors);
    artifacts.push_back(std::move(item));
  }
  j["artifacts"] = std::move(artifacts);

  json families = json::array();
  for (const family_summary& f : r.families) families.push_back({{"name", f.name}, {"artifacts", f.artifacts}, {"providers", f.providers}});
  json matrix = json::array();
  for (const tactic_coverage& t : r.attack_matrix) {
    json procedures = json::array();
    for (const tactic_procedure& p : t.procedures) {
      json tools = json::array(), malware = json::array();
      for (const attack_software& s : p.software) {
        const json entry = {{"id", s.id}, {"name", s.name}};
        if (s.type == "tool") tools.push_back(entry);
        else                    malware.push_back(entry);
      }
      json procs = json::array();
      for (const attack_group& g : p.groups) procs.push_back({{"id", g.id}, {"name", g.name}});
      json detections = json::array();
      for (const attack_detection& d : p.detections) {
        json analytics = json::array();
        for (const attack_analytic& a : d.analytics) {
          analytics.push_back({{"id", a.id}, {"name", a.name}, {"platforms", a.platforms},
                               {"description", a.description}});
        }
        detections.push_back({{"id", d.id}, {"name", d.name}, {"analytics", analytics}});
      }
      json entry = {
          {"id", p.id},
          {"name", p.name},
          {"url", p.url},
          {"is_subtechnique", p.is_subtechnique},
          {"parent", p.parent_id},
          {"platforms", p.platforms},
          {"tools", tools},
          {"malware", malware},
          {"groups", procs},
          {"detections", detections},
          {"subtechniques", p.subtechniques},
          {"mitigations", p.mitigation_count},
          {"capability_hits", p.capability_hits},
      };
      if (!p.description.empty()) entry["description"] = p.description;
      procedures.push_back(std::move(entry));
    }
    matrix.push_back({{"tactic", t.shortname}, {"name", t.name}, {"procedures", procedures}});
  }
  json groups = json::array();
  for (const group_match& g : r.likely_groups) groups.push_back({{"id", g.id}, {"name", g.name}, {"techniques_matched", g.techniques_matched}, {"techniques", g.techniques}});
  json shared = json::array();
  for (const shared_host& h : r.shared_hosting) shared.push_back({{"ip", h.ip}, {"domains", h.domains}, {"asn", h.asn}, {"asn_name", h.asn_name}});
  json clusters = json::array();
  for (const asn_cluster& c : r.asn_clusters) clusters.push_back({{"asn", c.asn}, {"asn_name", c.asn_name}, {"ips", c.ips}});
  j["correlation"] = {{"malware_families", families}, {"attack_matrix", matrix}, {"likely_groups", groups},
                      {"shared_hosting", shared}, {"asn_clusters", clusters}, {"cisa_kev", r.kev_cves}};

  json stats = json::array();
  for (const provider_stat& s : r.provider_stats) {
    stats.push_back({{"provider", s.provider}, {"queries", s.queries}, {"answers", s.answers}, {"malicious", s.malicious},
                     {"suspicious", s.suspicious}, {"cache_hits", s.cache_hits}, {"errors", s.errors},
                     {"offline_misses", s.offline_misses}});
  }
  j["providers"] = std::move(stats);
  j["warnings"] = r.warnings;
  return j.dump(options.indent, ' ', false, json::error_handler_t::replace);
}

// ===========================================================================
// STIX 2.1
// ===========================================================================
namespace {

// Deterministic UUID (version 5 layout) from a seed: re-running on the same data gives the
// same ids, so downstream platforms de-duplicate instead of duplicating.
std::string stix_id(const std::string& type, const std::string& seed) {
  std::string hex = fnv_hex(type + "|" + seed) + fnv_hex(seed + "|" + type + "#2");
  hex[12] = '5';
  hex[16] = "89ab"[(hex[16] >= 'a' ? hex[16] - 'a' + 10 : hex[16] - '0') & 3];
  return type + "--" + hex.substr(0, 8) + "-" + hex.substr(8, 4) + "-" + hex.substr(12, 4) + "-" +
         hex.substr(16, 4) + "-" + hex.substr(20, 12);
}

std::string pattern_escape(const std::string& value) {
  std::string out;
  for (char c : value) {
    if (c == '\\' || c == '\'') out += '\\';
    out += c;
  }
  return out;
}

bool stix_pattern(const artifact& a, std::string& pattern) {
  const std::string v = pattern_escape(a.value);
  switch (a.type) {
    case artifact_type::ip:     pattern = std::string("[") + (is_ipv6(a.value) ? "ipv6-addr" : "ipv4-addr") + ":value = '" + v + "']"; return true;
    case artifact_type::domain: pattern = "[domain-name:value = '" + v + "']"; return true;
    case artifact_type::url:    pattern = "[url:value = '" + v + "']"; return true;
    case artifact_type::email:  pattern = "[email-addr:value = '" + v + "']"; return true;
    case artifact_type::md5:    pattern = "[file:hashes.MD5 = '" + v + "']"; return true;
    case artifact_type::sha1:   pattern = "[file:hashes.'SHA-1' = '" + v + "']"; return true;
    case artifact_type::sha256: pattern = "[file:hashes.'SHA-256' = '" + v + "']"; return true;
    case artifact_type::sha512: pattern = "[file:hashes.'SHA-512' = '" + v + "']"; return true;
    default: return false;
  }
}

}  // namespace

namespace {

// ATT&CK software/group objects, plus the `uses` edges tying them to the
// techniques observed in this sample.
//
// to_stix_bundle() used to emit only identity / attack-pattern / indicator /
// vulnerability, so the ATT&CK software and intrusion sets the analyzer already
// resolves (attack_software, attack_group, group_match) never reached the bundle
// at all. A consumer importing the bundle therefore saw a set of unrelated
// techniques with nothing saying which tools are known to use them, which group
// is a candidate, or what any of it means.
//
// Three STIX shapes are produced here, keyed by ATT&CK id so two runs over the
// same sample emit byte-identical bundles:
//   tool          -- ATT&CK `tool`,        "Mimikatz"
//   malware       -- ATT&CK `malware`,     "gh0st RAT"   (is_family, per S-id)
//   intrusion-set -- ATT&CK `group`,       "Mustang Panda"
// and, for each technique that references them, `uses` relationships in the
// direction ATT&CK itself uses: tool/malware --uses--> attack-pattern, and
// attack-pattern --used-by--> intrusion-set.
//
// Descriptions come from the ATT&CK bundle where the object graph carries them
// (tactic_procedure::description for the technique is not needed here); the
// software/group structs deliberately keep memory small by dropping them, so a
// short fallback naming the ATT&CK id is written instead of an empty field. A
// consumer can always resolve the full text from the external_references URL.
struct attack_graph {
  // Emitters supplied by the caller.
  std::function<void(json)> emit;
  std::function<json(const std::string&, const std::string&)> base;
  std::string identity_id;
  // Set by the caller so a throw inside this struct can name the step. Purely
  // diagnostic; nothing here reads it for control flow.
  std::string* stage = nullptr;
  void mark(const std::string& what) { if (stage) *stage = what; }

  std::map<std::string, std::string> software_ids;   // "S0002" -> stix id
  std::map<std::string, std::string> group_ids;      // "G0007" -> stix id
  // Tally kept here rather than inferred later: ATT&CK numbers tools and malware
  // in the same S-series ("S0002" is Mimikatz, a tool; "S0032" is gh0st RAT,
  // malware), so the id cannot tell them apart.
  std::size_t tool_count = 0;
  std::size_t malware_count = 0;

  void relationship(const std::string& type, const std::string& source,
                    const std::string& target) {
    // base() takes a finished STIX id, not a seed -- every other caller wraps its
    // seed in stix_id(). Without the wrap, object["id"] was a bare string rather
    // than an id and emit()'s push_back threw "cannot use push_back() with
    // string", which write_stix_bundle swallowed into a missing bundle.
    json rel = base("relationship",
                    stix_id("relationship", source + "|" + type + "|" + target));
    rel["created_by_ref"] = identity_id;
    rel["relationship_type"] = type;
    rel["source_ref"] = source;
    rel["target_ref"] = target;
    emit(std::move(rel));
  }

  // One ATT&CK software entry: `tool` or `malware`, depending on how ATT&CK
  // classified it. `evidence` records why we believe it is present, so the
  // relationship is not mistaken for an observation of the tool itself.
  const std::string& software(const attack_software& s, const std::string& technique) {
    const std::string kind = s.type == "tool" ? "tool" : "malware";
    const std::string key = s.id.empty() ? to_lower(s.name) : s.id;
    const auto cached = software_ids.find(key);
    if (cached != software_ids.end()) return cached->second;

    const std::string id = stix_id(kind, key);
    json o = base(kind, id);
    o["created_by_ref"] = identity_id;
    o["name"] = s.name;
    if (kind == "malware") {
      // ATT&CK models malware as families/types; `is_family` is what tells a
      // consumer this is a class of malware rather than one sample.
      o["is_family"] = true;
    }
    o["description"] =
        "ATT&CK " + std::string(kind) + " " + (s.id.empty() ? std::string(s.name) : s.id) +
        ", recorded as using " + technique + " in this sample. The mapping is " +
        "ATT&CK's, not this tool's detection: it means " + s.name +
        " is known to employ this technique, not that " + s.name +
        " was found on the host.";
    // Triple braces, matching every other external_references in this file.
    // json::array({json{...}}) is ambiguous: with a single braced argument the
    // initializer-list ctor can take the object's pairs as the array elements.
    o["external_references"] = json::array({json{
        {"source_name", "mitre-attack"},
        {"external_id", s.id},
        {"url", "https://attack.mitre.org/software/" + s.id}}});
    emit(std::move(o));
    if (kind == "tool") ++tool_count; else ++malware_count;
    return software_ids.emplace(key, id).first->second;
  }

  const std::string& intrusion_set(const attack_group& g) {
    const std::string key = g.id.empty() ? to_lower(g.name) : g.id;
    const auto cached = group_ids.find(key);
    if (cached != group_ids.end()) return cached->second;

    const std::string id = stix_id("intrusion-set", key);
    json o = base("intrusion-set", id);
    o["created_by_ref"] = identity_id;
    o["name"] = g.name;
    o["description"] =
        "ATT&CK intrusion set " + (g.id.empty() ? std::string(g.name) : g.id) +
        ", recorded in MITRE ATT&CK as using the techniques observed in this "
        "sample. Presence here is an ATT&CK catalogue relationship, not "
        "evidence that this group operated on the host; treat it as a starting "
        "point for review, never as attribution.";
    o["external_references"] = json::array({json{
        {"source_name", "mitre-attack"},
        {"external_id", g.id},
        {"url", "https://attack.mitre.org/groups/" + g.id}}});
    emit(std::move(o));
    return group_ids.emplace(key, id).first->second;
  }

  // Walk one technique's ATT&CK relationships and emit the resulting subgraph.
  void for_procedure(const tactic_procedure& p) {
    if (p.id.empty()) return;
    const std::string technique_id = stix_id("attack-pattern", p.id);
    // Resolve the ids into locals first. software()/intrusion_set() hand back a
    // reference into their own map, and each of those maps is mutated by the
    // calls that follow (a later software() can rehash/rebalance the node, and
    // group_ids is a separate container but the relationship helper may insert
    // more entries). Holding the reference across another insert is what turned
    // a dangling-reference read into a string landing in the objects array.
    for (const attack_software& s : p.software) {
      if (s.id.empty() && s.name.empty()) continue;
      mark("software:" + s.id + "/" + s.type);
      const std::string software_id = software(s, p.id);   // copy, not a reference
      mark("rel:uses:" + software_id);
      relationship("uses", software_id, technique_id);
    }
    for (const attack_group& g : p.groups) {
      if (g.id.empty() && g.name.empty()) continue;
      mark("group:" + g.id);
      const std::string group_id = intrusion_set(g);       // copy, not a reference
      mark("rel:used-by:" + group_id);
      relationship("used-by", technique_id, group_id);
    }
  }
};

}  // namespace

std::string to_stix_bundle(const report& r, const stix_options& options) {
  // Which section was being built when something threw. Declared outside the
  // try so the catch below can name it, and reported there so a malformed
  // enrichment costs one artifact rather than the whole bundle.
  std::string stage = "setup";
  try {
  const std::string now = iso8601(now_epoch(), true);
  const std::string identity_id = stix_id("identity", options.producer);

  json objects = json::array();
  std::vector<std::string> refs;                    // everything the report object references
  std::set<std::string> emitted;                    // avoid duplicate ids
  auto emit = [&](json object) {
    // Guard: every emitted value must be a STIX *object*. `objects` is an array,
    // so push_back of anything else throws type_error.308 ("cannot use push_back()
    // with <type>"), which EXPORTER_TRY swallows into a silently missing bundle.
    if (!object.is_object()) {
      std::cout << console::paint(console::red, "[-] stix: non-object emit: ")
                << object.type_name() << " " << object.dump() << '\n';
      return;
    }
    const std::string id = object["id"].get<std::string>();
    stage = "emit " + id;
    if (!emitted.insert(id).second) return;
    // Second guard, on the container rather than the element. `objects` is only
    // ever json::array() here, so this cannot fire today - it exists so that a
    // future refactor that reassigns `objects` degrades to a logged skip instead
    // of aborting the whole bundle through the catch below.
    if (!objects.is_array()) {
      std::cout << console::paint(console::red, "[-] stix: objects is not an array: ")
                << objects.type_name() << '\n';
      return;
    }
    try {
      objects.push_back(std::move(object));
    } catch (const std::exception& e) {
      LOG_ERROR("stix: emit('{}') failed: {}", id, e.what());
      std::cout << console::paint(console::red, "[-] stix: emit failed for ")
                << id << ": " << e.what() << '\n';
      return;
    }
    if (id != identity_id) refs.push_back(id);
  };
  auto base = [&](const std::string& type, const std::string& id) {
    return json{{"type", type}, {"spec_version", "2.1"}, {"id", id}, {"created", now}, {"modified", now}};
  };

  json identity = base("identity", identity_id);
  identity["name"] = options.producer;
  identity["identity_class"] = "system";
  emit(std::move(identity));

  std::map<std::string, std::string> malware_ids;       // family key -> id
  auto malware_for = [&](const std::string& family) {
    const std::string key = to_lower(family);
    const auto it = malware_ids.find(key);
    if (it != malware_ids.end()) return it->second;
    const std::string id = stix_id("malware", key);
    json m = base("malware", id);
    m["created_by_ref"] = identity_id;
    m["name"] = family;
    m["is_family"] = true;
    // Without this the family is a bare label in the graph: a consumer sees a
    // node named e.g. "Emotet" with nothing to read. Say what the name means and
    // where it came from, and state plainly that a provider naming a family is
    // not the same as attributing the sample to it.
    m["description"] =
        "Malware family named '" + family + "' by threat-intelligence providers "
        "while analysing this sample's indicators. Provider attribution is "
        "similarity-based and can be wrong or deliberately spoofed; treat the "
        "family name as a lead for triage, not a confirmed identification.";
    emit(std::move(m));
    malware_ids[key] = id;
    return id;
  };

  for (const enrichment& e : r.items) {
    if (e.skipped) continue;
    stage = std::string("item:") + to_string(e.art.type);
    // One malformed enrichment must cost one artifact, not the whole bundle.
    // The outer catch used to swallow the first bad item and drop every
    // technique, tool and group along with it, which is why a bundle could be
    // missing wholesale with no hint which artifact caused it.
    try {
    const std::string seed = e.art.key();

    if (e.art.type == artifact_type::technique) {
      if (!options.include_techniques) continue;
      json ap = base("attack-pattern", stix_id("attack-pattern", e.art.value));
      ap["created_by_ref"] = identity_id;
      std::string name = e.art.value;
      // MITRE spells a sub-technique URL with a slash: T1497/001, not T1497.001.
      // Only the ID is rewritten - replacing every '.' would also mangle the
      // dots in the "attack.mitre.org" host.
      std::string url_id = e.art.value;
      std::replace(url_id.begin(), url_id.end(), '.', '/');
      std::string url = "https://attack.mitre.org/techniques/" + url_id;
      json phases = json::array();
      json platforms = json::array();
      std::string description, detection;
      bool is_subtechnique = false;
      if (const auto it = e.knowledge.find("mitre_attack"); it != e.knowledge.end() && it->is_object()) {
        const json& k = *it;
        if (k.contains("name") && k["name"].is_string() && !k["name"].get<std::string>().empty())
          name = k["name"].get<std::string>();
        if (k.contains("url") && k["url"].is_string() && !k["url"].get<std::string>().empty())
          url = k["url"].get<std::string>();
        if (k.contains("tactic_shortnames") && k["tactic_shortnames"].is_array()) {
          for (const json& t : k["tactic_shortnames"])
            if (t.is_string())
              phases.push_back({{"kill_chain_name", "mitre-attack"}, {"phase_name", t.get<std::string>()}});
        }
        if (k.contains("description") && k["description"].is_string())
          description = k["description"].get<std::string>();
        if (k.contains("detection") && k["detection"].is_string())
          detection = k["detection"].get<std::string>();
        if (k.contains("platforms") && k["platforms"].is_array()) {
          for (const json& p : k["platforms"])
            if (p.is_string()) platforms.push_back(p.get<std::string>());
        }
        if (k.contains("subtechnique") && k["subtechnique"].is_boolean())
          is_subtechnique = k["subtechnique"].get<bool>();
      }
      ap["name"] = name;
      ap["external_references"] = json::array({{{"source_name", "mitre-attack"}, {"external_id", e.art.value}, {"url", url}}});
      if (!phases.empty()) ap["kill_chain_phases"] = phases;
      if (description.empty()) {
        // No ATT&CK text was ever resolved (knowledge cache never fetched):
        // still ship a usable sentence instead of an empty field, and say where
        // the technique came from.
        description = "ATT&CK technique " + e.art.value +
                      (name != e.art.value ? " (" + name + ")" : "") +
                      " observed in this sample. See " + url + ".";
      }
      ap["description"] = description;
      if (!detection.empty()) ap["x_mitre_detection"] = detection;
      if (!platforms.empty()) ap["x_mitre_platforms"] = platforms;
      if (is_subtechnique || e.art.value.find('.') != std::string::npos)
        ap["x_mitre_is_subtechnique"] = true;
      emit(std::move(ap));
      continue;
    }

    if (e.art.type == artifact_type::cve) {
      const bool kev = std::find(r.kev_cves.begin(), r.kev_cves.end(), e.art.value) != r.kev_cves.end();
      if (!options.include_all && !kev && e.score < options.min_score) continue;
      json v = base("vulnerability", stix_id("vulnerability", e.art.value));
      v["created_by_ref"] = identity_id;
      v["name"] = e.art.value;
      v["external_references"] = json::array({{{"source_name", "cve"}, {"external_id", e.art.value}}});
      std::string description;
      if (const auto it = e.knowledge.find("nvd"); it != e.knowledge.end() && it->contains("description") && (*it)["description"].is_string()) {
        description = (*it)["description"].get<std::string>();
      } else if (const auto k = e.knowledge.find("cisa_kev"); k != e.knowledge.end() && k->contains("description") && (*k)["description"].is_string()) {
        description = (*k)["description"].get<std::string>();
      }
      if (!description.empty()) v["description"] = description;
      if (kev) v["labels"] = json::array({"cisa-known-exploited"});
      emit(std::move(v));
      continue;
    }

    std::string pattern;
    if (!stix_pattern(e.art, pattern)) continue;
    if (!options.include_all && e.score < options.min_score) continue;
    if (!options.include_all && e.outcome != verdict::malicious && e.outcome != verdict::suspicious) continue;

    const std::string indicator_id = stix_id("indicator", seed);
    json ind = base("indicator", indicator_id);
    ind["created_by_ref"] = identity_id;
    ind["name"] = std::string(to_string(e.outcome)) + " " + to_string(e.art.type) + ": " + (e.art.value.size() > 80 ? e.art.value.substr(0, 77) + "..." : e.art.value);
    ind["description"] = e.reason.empty() ? std::string("collected by ") + options.producer : "risk score " + std::to_string(e.score) + "; " + e.reason;
    ind["pattern"] = pattern;
    ind["pattern_type"] = "stix";
    ind["pattern_version"] = "2.1";
    ind["valid_from"] = now;
    ind["indicator_types"] = json::array({e.outcome == verdict::malicious ? "malicious-activity" : (e.outcome == verdict::suspicious ? "anomalous-activity" : "benign")});
    ind["confidence"] = e.score;
    if (!e.tags.empty()) ind["labels"] = e.tags;
    json refs_json = json::array();
    for (const finding& f : e.findings) {
      for (const std::string& url : f.references) {
        if (refs_json.size() < 6 && starts_with(url, "http")) refs_json.push_back({{"source_name", f.provider}, {"url", url}});
      }
    }
    if (!refs_json.empty()) ind["external_references"] = refs_json;
    emit(std::move(ind));

    for (const std::string& family : e.families) {
      const std::string malware_id = malware_for(family);
      json rel = base("relationship", stix_id("relationship", indicator_id + "|indicates|" + malware_id));
      rel["created_by_ref"] = identity_id;
      rel["relationship_type"] = "indicates";
      rel["source_ref"] = indicator_id;
      rel["target_ref"] = malware_id;
      emit(std::move(rel));
    }
    } catch (const std::exception& ex) {
      std::cout << console::paint(console::red, "[-] stix: artifact skipped: ")
                << e.art.value << " (" << ex.what() << ")\n";
      LOG_WARN("stix: artifact '{}' skipped while building the bundle: {}",
               e.art.value, ex.what());
    }
  }

  // The ATT&CK object graph: software (tool/malware), intrusion sets, and the
  // `uses` / `used-by` relationships between them and the techniques observed.
  // Wired to the same emit/base closures so ids dedupe against everything else
  // and every object lands in the report's object_refs exactly once.
  stage = "graph:setup";
  attack_graph graph;
  graph.emit = emit;
  graph.base = base;
  graph.identity_id = identity_id;
  graph.stage = &stage;
  // Only the techniques this run actually observed carry software/group edges --
  // walk the same attack_matrix the Navigator layer and the console summary use,
  // so the STIX graph and the rest of the report cannot disagree.
  for (const tactic_coverage& t : r.attack_matrix)
    for (const tactic_procedure& p : t.procedures) {
      stage = "graph:" + p.id;
      // Same isolation as the enrichment loop: one bad technique subgraph must
      // not cost the tool/group objects for every other technique.
      try {
        graph.for_procedure(p);
      } catch (const std::exception& ex) {
        std::cout << console::paint(console::red, "[-] stix: subgraph skipped: ")
                  << p.id << " (" << ex.what() << ")\n";
        LOG_WARN("stix: subgraph for '{}' skipped: {}", p.id, ex.what());
      }
    }

  json bundle = {{"type", "bundle"}, {"id", stix_id("bundle", r.generated_at + "|" + std::to_string(objects.size()))}};
  if (!refs.empty()) {
    json report_object = base("report", stix_id("report", r.generated_at + "|" + options.producer));
    report_object["created_by_ref"] = identity_id;
    report_object["name"] = "CTI pipeline report " + r.generated_at;
    report_object["description"] = std::to_string(r.items.size()) + " artifact(s) analysed; " +
        std::to_string(r.counts_by_verdict.count("malicious") ? r.counts_by_verdict.at("malicious") : 0) + " malicious, " +
        std::to_string(r.counts_by_verdict.count("suspicious") ? r.counts_by_verdict.at("suspicious") : 0) + " suspicious.";
    // Summarise the ATT&CK graph so a consumer that only reads the report object
    // still learns what the subgraph contains. Counts, not a verdict: which
    // tools and groups are listed is a property of the ATT&CK catalogue and the
    // techniques matched, not a claim about this sample.
    //
    // Built in a std::string and assigned once, NEVER with `json_string +=`:
    // nlohmann's operator+= on a json value forwards to push_back(), which
    // throws type_error.308 ("cannot use push_back() with string") when the
    // target already holds a string. That throw fired inside this block only
    // when software/group ids existed, aborting the bundle exactly when the
    // tool and intrusion-set objects were about to be counted - the STIX
    // exporter then silently produced no file at all.
    std::string description =
        std::to_string(r.items.size()) + " artifact(s) analysed; " +
        std::to_string(r.counts_by_verdict.count("malicious") ? r.counts_by_verdict.at("malicious") : 0) + " malicious, " +
        std::to_string(r.counts_by_verdict.count("suspicious") ? r.counts_by_verdict.at("suspicious") : 0) + " suspicious.";
    if (!graph.software_ids.empty() || !graph.group_ids.empty()) {
      description += " ATT&CK graph: " +
          std::to_string(graph.group_ids.size()) + " intrusion set(s), " +
          std::to_string(graph.tool_count) + " tool(s) and " +
          std::to_string(graph.malware_count) +
          " malware entit(ies) linked to the observed techniques.";
    }
    report_object["description"] = std::move(description);
    report_object["published"] = now;
    report_object["report_types"] = json::array({"threat-report"});
    report_object["object_refs"] = refs;
    // Same reasoning as emit(): going through the shared path keeps ids deduped
    // and, more importantly, means a failure here costs one report object rather
    // than the whole bundle.
    emit(std::move(report_object));
  }
  stage = "report-object";
  bundle["objects"] = std::move(objects);
  stage = "dump";
  return bundle.dump(2, ' ', false, json::error_handler_t::replace);
  } catch (const std::exception& e) {
    std::cout << console::paint(console::red, "[-] stix bundle aborted at stage '")
              << stage << "': " << e.what() << '\n';
    throw;
  }
}

// ===========================================================================
// console summary
// ===========================================================================
void print_summary(const report& r, std::ostream& out, std::size_t max_items) {
  using console::paint;

  // This block used to be written as plain text with "--- Title ---" rules at
  // column 0. Neither the terminal palette nor the PDCurses colouriser knew that
  // shape, so the whole CTI report landed in the results browser as one grey
  // wall - including the [MAL ...] findings, which are the entire point of the
  // phase. It now speaks the same vocabulary as the rest of the report
  // (print_section / print_kv / print_bullet in main.cpp): "  -- Title" headings
  // and "    Key:  value" lines, painted with the console palette.
  const auto section = [&out](const std::string& title) {
    out << '\n' << paint(console::cyan, "  -- " + title) << '\n';
  };
  const auto kv_raw = [&out](const std::string& key, const std::string& value) {
    std::ostringstream line;
    line << "    " << std::left << std::setw(22) << (key + ":");
    out << line.str() << value << '\n';
  };
  const auto bullet = [&out](const std::string& text,
                             std::string_view color = console::grey) {
    out << paint(console::grey, "      * ") << paint(color, text) << '\n';
  };
  const auto counts = [](const std::map<std::string, std::size_t>& m) {
    std::string s;
    for (const auto& [k, v] : m) s += (s.empty() ? "" : ", ") + k + " " + std::to_string(v);
    return s.empty() ? std::string("none") : s;
  };
  const auto pad = [](std::size_t value, int width) {
    std::ostringstream o;
    o << std::right << std::setw(width) << value;
    return o.str();
  };

  {
    std::ostringstream head;
    head << "=== CTI report  (" << r.generated_at << ", " << std::fixed
         << std::setprecision(1) << r.seconds << " s) ===";
    out << '\n' << paint(console::cyan, head.str()) << '\n';
  }
  kv_raw("Artifacts", std::to_string(r.items.size()) + "  (" + counts(r.counts_by_type) + ")");
  {
    // Severity order, not the map's alphabetical one: the question this block
    // has to answer first is "was anything malicious?", not "how much was benign?".
    static constexpr const char* kOrder[] = {"malicious", "suspicious", "benign", "unknown"};
    static constexpr std::string_view kColors[] = {console::red, console::yellow,
                                                   console::green, console::grey};
    std::string verdicts;
    std::set<std::string> emitted;
    for (std::size_t i = 0; i < std::size(kOrder); ++i) {
      const auto it = r.counts_by_verdict.find(kOrder[i]);
      if (it == r.counts_by_verdict.end()) continue;
      emitted.insert(it->first);
      if (!verdicts.empty()) verdicts += ", ";
      verdicts += paint(kColors[i], it->first + " " + std::to_string(it->second));
    }
    // Anything a future verdict name introduces that the order list does not
    // know about still gets reported rather than silently dropped.
    for (const auto& [name, n] : r.counts_by_verdict) {
      if (emitted.count(name) != 0) continue;
      if (!verdicts.empty()) verdicts += ", ";
      verdicts += paint(console::grey, name + " " + std::to_string(n));
    }
    kv_raw("Verdicts", verdicts.empty() ? std::string("none") : verdicts);
  }
  if (!r.attack_version.empty() || !r.kev_version.empty()) {
    kv_raw("Knowledge", "ATT&CK " + (r.attack_version.empty() ? std::string("n/a") : r.attack_version) +
                        ", CISA KEV " + (r.kev_version.empty() ? std::string("n/a") : r.kev_version));
  }

  std::vector<const enrichment*> flagged_items;
  for (const enrichment& e : r.items) {
    if (!e.skipped && (e.outcome == verdict::malicious || e.outcome == verdict::suspicious) &&
        e.art.type != artifact_type::technique) flagged_items.push_back(&e);
  }
  std::sort(flagged_items.begin(), flagged_items.end(), [](const enrichment* a, const enrichment* b) { return a->score > b->score; });
  section("Malicious / suspicious (" + std::to_string(flagged_items.size()) + ")");
  std::size_t shown = 0;
  for (const enrichment* e : flagged_items) {
    if (shown++ >= max_items) {
      bullet("... and " + std::to_string(flagged_items.size() - max_items) + " more "
             "(the full list is in the CTI JSON export)");
      break;
    }
    const bool malicious = e->outcome == verdict::malicious;
    std::ostringstream tag;
    tag << (malicious ? "[MAL " : "[SUS ") << std::setw(3) << e->score << "] ";
    out << "    " << paint(malicious ? console::red : console::yellow, tag.str())
        << paint(console::green, e->art.key()) << '\n';

    // `reason` is only the aggregation arithmetic ("virustotal (67), abuseipdb
    // (100)"), which tells the reader nothing about why. The human-readable
    // explanation already exists on every finding and was never printed, so
    // surface the strongest few. KEV / EPSS / CVSS significance comes along for
    // free: those are finding summaries too.
    std::vector<const finding*> ranked;
    ranked.reserve(e->findings.size());
    for (const finding& f : e->findings) {
      if (!f.summary.empty()) ranked.push_back(&f);
    }
    std::sort(ranked.begin(), ranked.end(), [](const finding* a, const finding* b) {
      return a->confidence * a->weight > b->confidence * b->weight;
    });
    std::size_t shown_findings = 0;
    for (const finding* f : ranked) {
      if (shown_findings++ >= 3) break;
      std::ostringstream lead;
      lead << std::left << std::setw(16) << f->provider
           << " (conf " << std::setw(3) << f->confidence << ")";
      out << "        " << paint(console::cyan, lead.str()) << ' '
          << paint(console::grey, f->summary) << '\n';
    }
    if (shown_findings == 0 && !e->reason.empty()) {
      out << "        " << paint(console::grey, e->reason) << '\n';
    }
    if (!e->families.empty()) {
      std::string families;
      for (std::size_t i = 0; i < e->families.size() && i < 4; ++i) {
        families += (i ? ", " : "") + e->families[i];
      }
      if (e->families.size() > 4) families += ", ...";
      out << "        " << paint(console::grey, "families: ") << paint(console::red, families) << '\n';
    }
    if (!e->art.derived_from.empty()) {
      out << "        " << paint(console::grey, "found via " + e->art.derived_from) << '\n';
    }
  }
  if (flagged_items.empty()) bullet("none");

  // Artifacts the pipeline never queried (private addresses, invalid names,
  // empty-input hashes). They were reported nowhere before, which made a scan
  // of an internal host look like a provider outage.
  std::vector<const enrichment*> skipped_items;
  for (const enrichment& e : r.items) {
    if (e.skipped) skipped_items.push_back(&e);
  }
  if (!skipped_items.empty()) {
    section("Skipped (" + std::to_string(skipped_items.size()) + ")");
    std::size_t shown_skipped = 0;
    for (const enrichment* e : skipped_items) {
      if (shown_skipped++ >= max_items) {
        bullet("... and " + std::to_string(skipped_items.size() - max_items) + " more");
        break;
      }
      bullet(e->art.key() + (e->skip_reason.empty() ? "" : "  (" + e->skip_reason + ")"));
    }
  }

  if (!r.families.empty()) {
    section("Malware families");
    std::size_t shown_families = 0;
    for (const family_summary& f : r.families) {
      if (shown_families++ >= max_items) break;
      bullet(f.name + ": " + std::to_string(f.artifacts.size()) + " artifact(s), via " +
                 std::to_string(f.providers.size()) + " provider(s)",
             console::red);
    }
  }
  if (!r.kev_cves.empty()) {
    section("CISA KEV (actively exploited)");
    for (const std::string& cve : r.kev_cves) {
      const enrichment* e = r.find("cve:" + cve);
      out << "    " << paint(console::red, cve)
          << (e != nullptr && !e->art.derived_from.empty()
                  ? paint(console::grey, "  <- " + e->art.derived_from) : std::string())
          << '\n';
    }
  }
  if (!r.attack_matrix.empty()) {
    section("MITRE ATT&CK");
    for (const tactic_coverage& t : r.attack_matrix) {
      bullet(paint(console::cyan, t.name) +
                 "  " + paint(console::grey, "(" + std::to_string(t.procedures.size()) + " technique(s))"),
             console::cyan);
      // Top procedures per tactic. Ten is the most that stays readable in a
      // terminal; the full list is always in the JSON and the dashboard.
      std::size_t shown = 0;
      for (const tactic_procedure& p : t.procedures) {
        if (shown++ >= 10) {
          bullet(paint(console::grey, "    ... " + std::to_string(t.procedures.size() - 10) +
                                   " more (in the CTI JSON)"),
                 console::grey);
          break;
        }
        std::string head = "    " + paint(console::white, p.id) + " " + p.name;
        if (p.capability_hits > 1)
          head += paint(console::yellow, "  [" + std::to_string(p.capability_hits) + " capa hits]");
        out << head << '\n';

        // Tooling first: this is what an analyst hunts for. Capped so one
        // widely-used technique (T1106 native API) cannot flood the report.
        std::size_t tool_shown = 0, mal_shown = 0;
        for (const attack_software& s : p.software) {
          const bool is_tool = (s.type == "tool");
          if (is_tool ? tool_shown >= 4 : mal_shown >= 2) continue;
          (is_tool ? tool_shown : mal_shown)++;
          const std::size_t total = static_cast<std::size_t>(
              std::count_if(p.software.begin(), p.software.end(),
                            [&](const attack_software& x) { return (x.type == "tool") == is_tool; }));
          out << "      " << paint(is_tool ? console::green : console::red,
                                   is_tool ? "tool    " : "malware ") << "  "
              << s.name << paint(console::grey, "  (" + s.id + ")")
              << ((is_tool ? tool_shown : mal_shown) >= (is_tool ? 4u : 2u) && total > 0
                      ? paint(console::grey, "  +" + std::to_string(total - (is_tool ? 4u : 2u)) + " more")
                      : "")
              << '\n';
        }
        if (tool_shown == 0 && mal_shown == 0)
          out << "      " << paint(console::grey, "tool     no known tooling in ATT&CK") << '\n';

        // Groups: attribution rather than capability, so one line, capped.
        if (!p.groups.empty()) {
          std::string g;
          for (std::size_t i = 0; i < p.groups.size() && i < 3; ++i) {
            if (i) g += ", ";
            g += p.groups[i].name;
          }
          if (p.groups.size() > 3) g += " +" + std::to_string(p.groups.size() - 3) + " more";
          out << "      " << paint(console::yellow, "group    ") << "  " << g << '\n';
        }

        // Detection guidance: the analytic prose is the actionable part.
        for (const attack_detection& d : p.detections) {
          if (d.analytics.empty()) continue;
          for (const attack_analytic& a : d.analytics) {
            if (a.description.empty()) continue;
            std::string text = a.description;
            if (text.size() > 220) text = text.substr(0, 217) + "...";
            out << "      " << paint(console::blue, "detect   ") << "  " << text << '\n';
          }
        }
      }
    }
    for (const group_match& g : r.likely_groups) {
      bullet("possible group: " + g.name + " (" + g.id + ") shares " +
                 std::to_string(g.techniques_matched) + " technique(s)",
             console::yellow);
    }
  }
  if (!r.shared_hosting.empty() || !r.asn_clusters.empty()) {
    section("Infrastructure");
    for (const shared_host& h : r.shared_hosting) {
      std::string line = h.ip + (h.asn.empty() ? "" : " (" + h.asn + " " + h.asn_name + ")") + " hosts:";
      for (const std::string& d : h.domains) line += " " + d;
      bullet(line);
    }
    for (const asn_cluster& c : r.asn_clusters) {
      bullet(c.asn + " " + c.asn_name + ": " + std::to_string(c.ips.size()) + " IPs");
    }
  }

  if (!r.provider_stats.empty()) {
    section("Providers");
    for (const provider_stat& s : r.provider_stats) {
      out << "    " << std::left << std::setw(18) << s.provider << std::right
          << " queries " << std::setw(3) << s.queries
          << "  answers " << std::setw(3) << s.answers
          << "  mal " << paint(s.malicious == 0 ? console::grey : console::red,
                               pad(s.malicious, 3))
          << "  sus " << paint(s.suspicious == 0 ? console::grey : console::yellow,
                               pad(s.suspicious, 3))
          << "  cache " << std::setw(3) << s.cache_hits
          << "  errors " << s.errors << '\n';
    }
  }
  if (!r.warnings.empty()) {
    section("Warnings");
    for (const std::string& w : r.warnings) bullet(w, console::yellow);
  }
  if (r.error_count() > 0) {
    section("Provider errors (first 10)");
    std::size_t n = 0;
    for (const enrichment& e : r.items) {
      for (const provider_error& err : e.errors) {
        if (n++ >= 10) break;
        bullet(e.art.key() + "  [" + err.provider + "] " + err.message, console::red);
      }
    }
  }
  out << std::flush;
}

#ifdef CTI_WITH_COLLECT
// ===========================================================================
// cti_collect.cpp
// ===========================================================================
namespace {

std::size_t add_batch(pipeline& p, const std::vector<std::string>& values, const std::string& source,
                      artifact_type hint) {
  std::size_t added = 0;
  for (const std::string& v : values) {
    const std::size_t before = p.size();
    p.add_raw(v, source, hint);
    added += p.size() > before ? 1 : 0;
  }
  return added;
}

// "CVE-YYYY-NNNN[N..]" occurrences inside a string (ioc_extractor does not look for them)
void find_cves(const std::string& text, std::vector<std::string>& out) {
  std::size_t pos = 0;
  while ((pos = text.find_first_of("Cc", pos)) != std::string::npos) {
    if (pos + 13 <= text.size() && to_upper(text.substr(pos, 4)) == "CVE-") {
      std::size_t i = pos + 4;
      std::size_t year = 0, num = 0;
      while (i < text.size() && std::isdigit(static_cast<unsigned char>(text[i])) && year < 4) { ++i; ++year; }
      if (year == 4 && i < text.size() && text[i] == '-') {
        ++i;
        while (i < text.size() && std::isdigit(static_cast<unsigned char>(text[i])) && num < 7) { ++i; ++num; }
        if (num >= 4) out.push_back(text.substr(pos, i - pos));
      }
      pos = i;
    } else {
      ++pos;
    }
  }
}

}  // namespace

std::size_t collect_from_ioc(pipeline& p, const ioc::ioc_results_t& iocs, const std::string& source) {
  std::size_t added = 0;
  added += add_batch(p, iocs.urls, source, artifact_type::url);
  added += add_batch(p, iocs.domains, source, artifact_type::domain);
  added += add_batch(p, iocs.ips, source, artifact_type::ip);
  added += add_batch(p, iocs.emails, source, artifact_type::email);
  added += add_batch(p, iocs.hashes, source, artifact_type::unknown);   // md5 / sha1 / sha256 / sha512 by length

  if (!iocs.family_hits.empty()) {
    json hints = json::array();
    for (const auto& hit : iocs.family_hits) {
      hints.push_back({{"keyword", std::string(hit.keyword)}, {"classification", std::string(hit.classification)},
                       {"matched_string", hit.matched_string.substr(0, 200)}});
    }
    p.sample()["ioc_family_hints"] = std::move(hints);
  }
  return added;
}

std::size_t collect_from_strings(pipeline& p, const std::vector<std::string>& strings, const std::string& source) {
  std::size_t added = 0;
  if (!strings.empty()) added += collect_from_ioc(p, ioc::extract_all(strings), source);

  std::vector<std::string> cves;
  for (const std::string& s : strings) find_cves(s, cves);
  added += add_batch(p, cves, source, artifact_type::cve);
  return added;
}

std::size_t collect_from_extraction(pipeline& p, const extractor::extraction_result_t& result,
                                    const std::string& source) {
  std::vector<std::string> strings;
  strings.reserve(result.strings.strings.size());
  for (const extractor::string_entry_t& s : result.strings.strings) strings.push_back(s.value);
  std::size_t added = collect_from_strings(p, strings, source + ".strings");

  // capa: ATT&CK techniques the sample implements
  if (result.capa.attempted) {
    added += add_batch(p, result.capa.attack_ids, "capa", artifact_type::technique);
    json caps = json::array();
    for (const auto& c : result.capa.capabilities) {
      if (caps.size() >= 60) break;
      caps.push_back({{"name", c.name}, {"namespace", c.namespace_path}});
    }
    p.sample()["capa"] = {{"version", result.capa.version}, {"capability_count", result.capa.capabilities.size()},
                          {"capabilities", caps}, {"mbc_ids", result.capa.mbc_ids}};
  }

  json meta = json::object();
  meta["packed"] = result.packer.packed;
  meta["packer_score"] = result.packer.score;
  if (!result.packer.suspected_packer.empty()) meta["suspected_packer"] = result.packer.suspected_packer;
  if (!result.pe.imphash.empty()) meta["imphash"] = result.pe.imphash;
  if (!result.pe.machine.empty()) meta["pe_machine"] = result.pe.machine;
  if (!result.elf.machine.empty()) meta["elf_machine"] = result.elf.machine;
  if (result.pe.timestamp != 0) meta["pe_timestamp"] = iso8601(result.pe.timestamp);
  meta["mitigations"] = {{"enabled", result.guards.mitigations_enabled}, {"checked", result.guards.mitigations_checked}};
  p.sample()["extractor"] = std::move(meta);
  return added;
}

std::size_t add_file_hashes(pipeline& p, const std::string& sha256, const std::string& md5, const std::string& sha1) {
  std::size_t added = 0;
  for (const std::string* h : {&sha256, &sha1, &md5}) {
    if (h->empty()) continue;
    const std::size_t before = p.size();
    p.add_raw(*h, "sample", artifact_type::unknown);
    added += p.size() > before ? 1 : 0;
  }
  return added;
}
#endif  // CTI_WITH_COLLECT

}  // namespace cti
