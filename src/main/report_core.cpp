#include "report.hpp"

#include <cctype>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <utility>

// ---------------------------------------------------------------------------
// Report vocabulary
// ---------------------------------------------------------------------------
// Every function here writes to std::cout rather than to a stream parameter:
// the PDCurses front-end captures output by swapping std::cout's rdbuf, so
// anything written anywhere else - std::printf included - bypasses the capture
// and leaks to the real terminal, out of order with the rest of the report.

namespace {

constexpr std::size_t kRuleWidth = 72;
constexpr int         kLabelPad  = 22;

}  // namespace

double elapsed_ms(report_clock::time_point start) {
  return std::chrono::duration<double, std::milli>(report_clock::now() - start).count();
}

// ---------------------------------------------------------------------------
// Format detection
// ---------------------------------------------------------------------------

file_format detect_format(const analyzer::file_info_t& info) {
  const std::string& t = info.type.executable_type;
  // LIEF::to_string(Binary::FORMAT) emits upper-case names - "PE", "ELF",
  // "MACHO" - so these tests have to be case-insensitive. They previously were
  // not, and searched for "MachO"/"Mach-O", which no LIEF build ever returns:
  // every Mach-O was classified Unknown and got no format-specific analysis.
  auto contains_ci = [&t](const char* needle) {
    const std::size_t n = std::char_traits<char>::length(needle);
    if (t.size() < n) return false;
    for (std::size_t i = 0; i + n <= t.size(); ++i) {
      std::size_t k = 0;
      for (; k < n; ++k) {
        const char a = static_cast<char>(std::toupper(static_cast<unsigned char>(t[i + k])));
        const char b = static_cast<char>(std::toupper(static_cast<unsigned char>(needle[k])));
        if (a != b) break;
      }
      if (k == n) return true;
    }
    return false;
  };
  if (contains_ci("PE"))        return file_format::pe;
  if (contains_ci("ELF"))       return file_format::elf;
  if (contains_ci("MACHO"))     return file_format::macho;
  return file_format::unknown;
}

const char* format_name(file_format f) {
  switch (f) {
    case file_format::pe:    return "PE";
    case file_format::elf:   return "ELF";
    case file_format::macho: return "Mach-O";
    default:                 return "Unknown";
  }
}

// ---------------------------------------------------------------------------
// Core vocabulary
// ---------------------------------------------------------------------------

void print_banner(const std::string& title) {
  std::cout << '\n'
            << console::paint(console::cyan, std::string(kRuleWidth, '=')) << '\n'
            << console::paint(console::cyan, title) << '\n'
            << console::paint(console::cyan, std::string(kRuleWidth, '=')) << '\n';
}

void print_section(const std::string& text) {
  std::cout << '\n' << console::paint(console::cyan, "  -- " + text) << '\n';
}

void print_kv(const std::string& key, const std::string& value) {
  std::ostringstream os;
  os << "    " << std::left << std::setw(kLabelPad) << (key + ":") << value;
  std::cout << os.str() << '\n';
}

void print_kv_colored(const std::string& key,
                      const std::string& value,
                      std::string_view color) {
  std::ostringstream os;
  os << "    " << std::left << std::setw(kLabelPad) << (key + ":");
  std::cout << os.str() << console::paint(color, value) << '\n';
}

void print_bullet(const std::string& text, std::string_view color) {
  std::cout << console::paint(color, "      * ") << text << '\n';
}

void print_warn(const std::string& text) {
  console::info(console::paint(console::yellow, "[!] ") + text);
}

void print_ip_network_info(const std::string& ip, const cti::network_context& net) {
  if (net.ip_version.empty() || net.cidr.empty()) {
    print_bullet(ip + "  (invalid or unsupported IP format)");
    return;
  }
  std::ostringstream os;
  os << ip << "  " << net.ip_version << "  class=" << net.ip_class
     << "  address_bits=" << net.address_bits
     << "  prefix_bits=" << net.prefix_bits
     << "  CIDR=" << net.cidr
     << "  mask=" << net.subnet_mask
     << "  network=" << net.network_address;
  if (!net.broadcast_address.empty()) os << "  broadcast=" << net.broadcast_address;
  print_bullet(os.str(), console::green);
}

void print_duration(double ms) {
  std::ostringstream os;
  os << std::fixed << std::setprecision(1) << ms << " ms";
  std::cout << console::paint(console::grey, "    (" + os.str() + ")") << '\n';
}

std::string hex_rva(std::uint64_t value) {
  std::ostringstream os;
  os << "0x" << std::hex << std::setw(8) << std::setfill('0') << value;
  return os.str();
}

std::string hex_value(std::uint64_t value) {
  std::ostringstream os;
  os << "0x" << std::hex << std::setw(16) << std::setfill('0') << value;
  return os.str();
}

std::string env_or_empty(const char* name) {
  const char* v = std::getenv(name);
  return v ? std::string(v) : std::string();
}

// ---------------------------------------------------------------------------
// CTI_BW_KEYS roster
// ---------------------------------------------------------------------------
// Comma-separated "VaultItem=ENV_TARGET" entries, e.g.
//
//     CTI_BW_KEYS=VirusTotal=VT_API_KEY,AbuseIPDB
//
// A bare "VaultItem" (no '=') is an existence check - the password of such an
// item is never read. Whitespace around items and targets is ignored. Returns
// false and sets `error` on an empty name, a dangling '=', or a duplicate
// item/target: applying one item twice, or two items to the same variable,
// would make the report lie about what the pipeline actually received.
bool parse_vault_key_list(const std::string& text,
                          std::vector<secret_store::item_request_t>& out,
                          std::string& error) {
  const auto trim_token = [](const std::string& token) {
    std::size_t begin = 0;
    std::size_t end = token.size();
    const auto space = [](char c) { return std::isspace(static_cast<unsigned char>(c)) != 0; };
    while (begin < end && space(token[begin])) ++begin;
    while (end > begin && space(token[end - 1])) --end;
    return token.substr(begin, end - begin);
  };

  std::size_t start = 0;
  while (start < text.size()) {
    const std::size_t comma = text.find(',', start);
    const std::string token = trim_token(
        text.substr(start, (comma == std::string::npos) ? std::string::npos : comma - start));
    start = (comma == std::string::npos) ? text.size() : comma + 1;
    if (token.empty()) continue;   // tolerates a trailing comma

    secret_store::item_request_t request;
    const std::size_t eq = token.find('=');
    if (eq == std::string::npos) {
      request.name = token;
    } else {
      request.name   = trim_token(token.substr(0, eq));
      request.target = trim_token(token.substr(eq + 1));
      if (request.name.empty()) {
        error = "'" + token + "' has no item name before '='";
        return false;
      }
      if (request.target.empty()) {
        error = "'" + token + "' has no target after '='";
        return false;
      }
    }

    for (const secret_store::item_request_t& existing : out) {
      if (existing.name == request.name) {
        error = "duplicate vault item '" + request.name + "'";
        return false;
      }
      if (!request.target.empty() && existing.target == request.target) {
        error = "duplicate target '" + request.target + "'";
        return false;
      }
    }

    out.push_back(std::move(request));
  }

  return true;
}
