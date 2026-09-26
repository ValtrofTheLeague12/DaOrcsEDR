// trace.cpp — full file with radare2 + IAT/GOT call-site integration

#include "trace.hpp"
#include "logging.hpp"
#include "file_analyzer.hpp"
#include "file_hasher.hpp"
#include "console.hpp"
#include "curses_ui.hpp"
#include "extractor.hpp"
#include "ioc_extractor.hpp"
#include "exporter.hpp"
#include "capa_runner.hpp"
#include "radare2_runner.hpp"
#include "local_api.hpp"
#include "visualizer.hpp"

#include <cctype>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

void trace_process_start() __attribute__((constructor, no_instrument_function));
void trace_process_stop()  __attribute__((destructor,  no_instrument_function));

void trace_process_start() {
  trace_enable();
  const std::string memory = PrintMemoryInfo();
  trace_write_text("[memory] process startup\n");
  trace_write_text(memory);
}

void trace_process_stop() {
  const std::string memory = PrintMemoryInfo();
  trace_write_text("[memory] process shutdown\n");
  trace_write_text(memory);
  trace_disable();
}

namespace {

enum class file_format { unknown, pe, elf, macho };

file_format detect_format(const analyzer::file_info_t& info) {
  const std::string& t = info.type.executable_type;
  if (t.find("PE")     != std::string::npos) return file_format::pe;
  if (t.find("ELF")    != std::string::npos) return file_format::elf;
  if (t.find("MachO")  != std::string::npos) return file_format::macho;
  if (t.find("Mach-O") != std::string::npos) return file_format::macho;
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

constexpr std::size_t kRuleWidth = 72;
constexpr int         kLabelPad  = 22;

curses_ui::session* g_curses_session = nullptr;

void print_banner(const std::string& title) {
  std::cout << '\n'
            << console::paint(console::cyan, std::string(kRuleWidth, '=')) << '\n'
            << console::paint(console::cyan, title) << '\n'
            << console::paint(console::cyan, std::string(kRuleWidth, '=')) << '\n';
}

void print_phase(int n, int total, const std::string& label) {
  if (g_curses_session != nullptr) {
    g_curses_session->phase(static_cast<std::size_t>(n), label);
  }
  std::ostringstream os;
  os << "[phase " << n << "/" << total << "] " << label;
  std::cout << '\n' << console::paint(console::yellow, os.str()) << '\n';
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

void print_bullet(const std::string& text,
                  std::string_view color = console::grey) {
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
// IAT rendering
// ---------------------------------------------------------------------------

void print_iat_report(const extractor::iat_result_t& r) {
  if (r.entries.empty() && r.dll_count == 0 && r.delay_dll_count == 0) {
    console::info("no import table entries");
    return;
  }

  print_section("import table summary");
  std::ostringstream counts;
  counts << r.dll_count << " DLLs"
         << "  |  " << r.named_import_count << " by name"
         << "  |  " << r.ordinal_import_count << " by ordinal";
  if (r.delay_dll_count > 0) {
    counts << "  |  " << r.delay_dll_count << " delay DLLs"
           << "  |  " << r.delay_import_count << " delay imports";
  }
  print_kv_colored("Entries", counts.str(), console::green);
  print_kv("Total entries", std::to_string(r.entries.size()));
  if (r.iat_lowest_rva != 0 || r.iat_highest_rva != 0) {
    print_kv("IAT range",
             hex_rva(r.iat_lowest_rva) + " .. " + hex_rva(r.iat_highest_rva));
  }
  if (r.truncated)
    print_kv_colored("Truncated", "yes (max entries reached)", console::yellow);

  struct dll_group {
    std::uint64_t iat_base = 0;
    std::uint64_t ilt_base = 0;
    std::uint32_t timestamp = 0;
    std::uint32_t forwarder = 0;
    std::vector<const extractor::iat_entry_t*> regular;
    std::vector<const extractor::iat_entry_t*> delay;
  };
  std::map<std::string, dll_group> groups;
  for (const auto& e : r.entries) {
    auto& g = groups[e.dll];
    if (g.iat_base == 0 && e.iat_base != 0) g.iat_base = e.iat_base;
    if (g.ilt_base == 0 && e.ilt_rva != 0) g.ilt_base = e.ilt_rva;
    if (g.timestamp == 0 && e.timestamp != 0) g.timestamp = e.timestamp;
    if (g.forwarder == 0 && e.forwarder != 0) g.forwarder = e.forwarder;
    if (e.is_delay) g.delay.push_back(&e);
    else            g.regular.push_back(&e);
  }

  constexpr std::size_t kMaxEntriesPerDll = 40;

  for (const auto& [dll, g] : groups) {
    print_section("DLL: " + dll);
    std::ostringstream head;
    head << "iat_base=" << hex_rva(g.iat_base)
         << "  int_base=" << hex_rva(g.ilt_base);
    if (g.timestamp != 0) head << "  bound_ts=" << std::hex << g.timestamp << std::dec;
    if (g.forwarder != 0) head << "  fwd=0x" << std::hex << g.forwarder << std::dec;
    print_kv("Descriptor", head.str());

    if (!g.regular.empty()) {
      print_bullet("regular imports (" + std::to_string(g.regular.size()) + ")",
                   console::grey);
      std::size_t shown = 0;
      for (const auto* e : g.regular) {
        if (shown++ >= kMaxEntriesPerDll) break;
        std::ostringstream line;
        line << "IAT=" << hex_rva(e->iat_rva)
             << "  val=" << hex_value(e->iat_value)
             << "  INT=" << hex_rva(e->int_rva) << "  ";
        if (e->is_ordinal || e->name.empty())
          line << "#" << e->ordinal << "  (ordinal)";
        else {
          line << e->name;
          if (e->hint != 0) line << "  hint=" << e->hint;
        }
        print_bullet(line.str());
      }
      if (g.regular.size() > shown)
        print_bullet("... and " + std::to_string(g.regular.size() - shown) + " more");
    }

    if (!g.delay.empty()) {
      print_bullet("delay-loaded imports (" + std::to_string(g.delay.size()) + ")",
                   console::yellow);
      std::size_t shown = 0;
      for (const auto* e : g.delay) {
        if (shown++ >= kMaxEntriesPerDll) break;
        std::ostringstream line;
        line << "val=" << hex_value(e->iat_value) << "  ";
        if (e->is_ordinal || e->name.empty())
          line << "#" << e->ordinal << "  (ordinal)";
        else {
          line << e->name;
          if (e->hint != 0) line << "  hint=" << e->hint;
        }
        print_bullet(line.str(), console::yellow);
      }
      if (g.delay.size() > shown)
        print_bullet("... and " + std::to_string(g.delay.size() - shown) + " more");
    }
  }
}



void print_got_report(const extractor::got_result_t& r) {
  if (r.entries.empty()) { console::info("no GOT entries"); return; }

  print_section("GOT summary (" + r.format + " / " + r.architecture + ")");
  std::ostringstream counts;
  counts << r.slot_count << " slots"
         << "  |  " << r.named_count << " named"
         << "  |  " << r.plt_count << " PLT/stub";
  if (r.lazy_count > 0) counts << "  |  " << r.lazy_count << " lazy";
  print_kv_colored("Entries", counts.str(), console::green);
  if (r.got_lowest_slot != 0 || r.got_highest_slot != 0) {
    print_kv("Slot range",
             hex_rva(r.got_lowest_slot) + " .. " + hex_rva(r.got_highest_slot));
  }
  if (!r.sections.empty()) {
    std::string secs;
    for (const auto& s : r.sections) {
      if (!secs.empty()) secs += ", ";
      secs += s;
    }
    print_kv("Sections", secs);
  }
  if (r.truncated) print_kv_colored("Truncated", "yes", console::yellow);

  constexpr std::size_t kMaxShown = 40;
  std::size_t shown = 0;
  for (const auto& e : r.entries) {
    if (shown++ >= kMaxShown) break;
    std::ostringstream line;
    line << "slot=" << hex_value(e.slot_address);
    if (e.plt_stub_address) line << "  plt=" << hex_value(e.plt_stub_address);
    if (e.stub_address)     line << "  stub=" << hex_value(e.stub_address);
    if (!e.reloc_type.empty()) line << "  " << e.reloc_type;
    line << "  ";
    if (e.name.empty()) line << "(anonymous)";
    else                line << e.name;
    if (!e.library.empty()) line << "  <" << e.library << ">";
    if (e.is_lazy) line << "  [lazy]";
    if (e.is_weak) line << "  [weak]";
    print_bullet(line.str());
  }
  if (r.entries.size() > shown)
    print_bullet("... and " + std::to_string(r.entries.size() - shown) + " more");
}

// ---------------------------------------------------------------------------
// Capa rendering
// ---------------------------------------------------------------------------

void print_capa_report(const capa::report_t& r) {
  if (!r.ok()) {
    console::error(std::string("capa failed: ") + capa::to_string(r.st));
    if (!r.error.empty())       console::error("  reason: " + r.error);
    if (!r.stderr_tail.empty()) console::error("  stderr: " + r.stderr_tail);
    for (const auto& w : r.warnings) print_warn("  warning: " + w);
    return;
  }

  print_section("capa summary");
  print_kv("Version",    r.capa_version);
  print_kv("Flavor",     r.flavor);
  print_kv("Format",     r.format);
  print_kv("Arch",       r.arch);
  print_kv("OS",         r.os);
  print_kv("Extractor",  r.backend);
  print_kv("From cache", r.from_cache ? "yes" : "no");
  print_kv("Duration",   std::to_string(r.seconds) + "s");

  std::ostringstream counts;
  counts << r.rules_matched << " matched"
         << "  |  " << r.library_rules << " library"
         << "  |  " << r.capabilities.size() << " capabilities";
  print_kv_colored("Rules", counts.str(), console::green);

  if (r.capabilities.empty()) return;

  print_section("capabilities by category");
  for (const auto& [category, count] : capa::capabilities_by_category(r)) {
    std::ostringstream os;
    os << std::left << std::setw(30) << category << "  " << count;
    print_bullet(os.str());
  }

  print_section("capabilities (first 25)");
  constexpr std::size_t kMax = 25;
  std::size_t shown = 0;
  for (const auto& cap : r.capabilities) {
    if (shown++ >= kMax) break;
    std::string line = "[" + cap.namespace_path + "] " + cap.name;
    if (cap.library) line += "  (lib)";
    std::ostringstream tail;
    tail << "  x" << cap.match_count;
    if (!cap.scope.empty()) tail << "  scope=" << cap.scope;
    print_bullet(line + tail.str());
  }
  if (r.capabilities.size() > shown)
    print_bullet("... and " + std::to_string(r.capabilities.size() - shown) + " more");

  const auto att = capa::attack_ids(r);
  const auto mbc = capa::mbc_ids(r);
  if (!att.empty() || !mbc.empty()) {
    print_section("mappings");
    if (!att.empty()) {
      std::string line;
      for (const auto& id : att) { if (!line.empty()) line += ", "; line += id; }
      print_kv("ATT&CK", line);
    }
    if (!mbc.empty()) {
      std::string line;
      for (const auto& id : mbc) { if (!line.empty()) line += ", "; line += id; }
      print_kv("MBC", line);
    }
  }
}

// ---------------------------------------------------------------------------
// Radare2 rendering
// ---------------------------------------------------------------------------

void print_radare2_report(const r2::bulk_result_t& r) {
  const bool has_output = !r.files.empty() || !r.functions.empty();
  const bool okish = (r.st == r2::status::ok) || (r.st == r2::status::partial);
  if (!has_output && !okish) {
    console::error(std::string("radare2: ") + r2::to_string(r.st));
    for (const auto& [kind, msg] : r.errors) {
      console::error("  " + kind + ": " + msg);
    }
    return;
  }

  print_section("radare2 summary");
  {
    std::string_view color = console::green;
    if (r.st == r2::status::partial)       color = console::yellow;
    else if (r.st != r2::status::ok)       color = console::red;
    print_kv_colored("Status", r2::to_string(r.st), color);
  }
  print_kv("Duration", std::to_string(r.seconds) + "s");

  std::size_t core_files = 0;
  std::size_t section_files = 0;
  for (const auto& f : r.files) {
    if (f.kind.rfind("section:", 0) == 0) ++section_files;
    else                                   ++core_files;
  }

  std::ostringstream counts;
  counts << r.files.size() << " file(s)"
         << " (" << core_files << " core, " << section_files << " per-section)"
         << "  |  " << r.functions.size() << " function(s)";
  if (!r.errors.empty())
    counts << "  |  " << r.errors.size() << " error(s)";
  print_kv_colored("Artifacts", counts.str(), console::green);

  if (!r.files.empty()) {
    print_section("generated artifacts");
    for (const auto& f : r.files) {
      std::ostringstream os;
      os << std::left << std::setw(22) << ("[" + f.kind + "]")
         << "  " << f.path
         << "  (" << f.bytes << " bytes)";
      print_bullet(os.str());
    }
  }

  if (!r.section_nop_stats.empty()) {
    print_section("NOP statistics by section");
    for (const auto& section : r.section_nop_stats) {
      std::ostringstream os;
      os << std::left << std::setw(24) << section.section
         << "  NOPs " << std::setw(6) << section.nop_count
         << " / " << std::setw(8) << section.instructions
         << "  (" << std::fixed << std::setprecision(2) << section.nop_percent() << "%)";
      print_bullet(os.str());
    }
  }

  if (!r.functions.empty()) {
    print_section("functions (first 25)");
    constexpr std::size_t kMax = 25;
    std::size_t shown = 0;
    for (const auto& f : r.functions) {
      if (shown++ >= kMax) break;
      std::ostringstream os;
      os << "0x" << std::hex << std::setw(8) << std::setfill('0') << f.offset
         << std::dec << std::setfill(' ')
         << "  " << std::left << std::setw(40) << f.name
         << "  size=" << std::setw(6) << f.size
         << "  blocks=" << f.blocks;
      if (f.is_pure) os << "  [pure]";
      print_bullet(os.str());
    }
    if (r.functions.size() > shown) {
      print_bullet("... and " + std::to_string(r.functions.size() - shown) + " more");
    }
  }

  if (!r.errors.empty()) {
    print_section("radare2 warnings");
    for (const auto& [kind, msg] : r.errors) {
      print_bullet("[" + kind + "] " + msg, console::yellow);
    }
  }
}

// ---------------------------------------------------------------------------
// Graphviz rendering
// ---------------------------------------------------------------------------

void print_render_report(const std::string& format,
                         std::size_t rendered_ok,
                         std::size_t rendered_attempted,
                         const std::vector<std::pair<std::string, std::string>>& errors) {
  print_section("graphviz rendering");
  print_kv("Format", format);
  std::ostringstream counts;
  counts << rendered_ok << " / " << rendered_attempted << " rendered";
  std::string_view color = (errors.empty() && rendered_ok == rendered_attempted)
                               ? console::green
                               : (rendered_ok == 0 ? console::red : console::yellow);
  print_kv_colored("Graphs", counts.str(), color);

  if (!errors.empty()) {
    print_section("render warnings");
    for (const auto& [section, msg] : errors) {
      print_bullet("[" + section + "] " + msg, console::yellow);
    }
  }
}

// ---------------------------------------------------------------------------
// IAT/GOT call-site rendering
// ---------------------------------------------------------------------------

void print_xref_asm_report(const r2::xref_asm_result_t& r) {
  const bool okish = (r.st == r2::status::ok) || (r.st == r2::status::partial);
  if (!okish) {
    if (r.st == r2::status::bad_output && r.xrefs_found == 0) {
      console::info("no call sites found for the supplied IAT/GOT slots");
      return;
    }
    console::error(std::string("iat/got call-site asm: ") + r2::to_string(r.st));
    if (!r.error.empty()) console::error("  " + r.error);
    for (const auto& [k, v] : r.errors) console::error("  [" + k + "] " + v);
    return;
  }

  print_section("IAT/GOT call-site assembly");
  {
    std::string_view color =
        (r.st == r2::status::ok) ? console::green : console::yellow;
    print_kv_colored("Status", r2::to_string(r.st), color);
  }
  print_kv("Slots queried",   std::to_string(r.slots_input));
  print_kv("Slots w/ xrefs",  std::to_string(r.slots_with_xrefs));
  print_kv_colored("Call sites", std::to_string(r.xrefs_found), console::green);
  print_kv_colored("Functions",  std::to_string(r.functions_dumped), console::green);
  if (r.instructions_total > 0) {
    print_kv("Instructions", std::to_string(r.instructions_total));
  }
  if (r.functions_truncated > 0) {
    print_kv_colored("Truncated", std::to_string(r.functions_truncated) + " function(s)",
                     console::yellow);
  }
  if (!r.path.empty())      print_kv("Output", r.path);
  if (r.bytes > 0)          print_kv("Size", std::to_string(r.bytes) + " bytes");
  if (!r.json_path.empty()) print_kv("Raw JSON", r.json_path);

  if (!r.errors.empty()) {
    print_section("IAT/GOT call-site warnings");
    for (const auto& [k, v] : r.errors) {
      print_bullet("[" + k + "] " + v, console::yellow);
    }
  }
}

// ---------------------------------------------------------------------------
// Helpers for the xref target collection
// ---------------------------------------------------------------------------

bool collect_xref_targets(const analyzer::file_info_t& info,
                          bool is_pe, bool is_elf, bool is_macho,
                          std::uint64_t pe_image_base,
                          std::vector<std::uint64_t>& out) {
  out.clear();

  if (is_pe) {
    extractor::iat_result_t iat{};
    if (!extractor::extract_iat(iat, info)) return false;

    std::uint64_t image_base = pe_image_base;
    if (image_base == 0) {
      image_base = 0x140000000ull;
      print_warn("PE image base not reported by rabin2; assuming 0x140000000");
    }
    LOG_INFO("r2: xref targets: using PE image base {}", hex_value(image_base));

    for (const auto& e : iat.entries) {
      if (e.iat_rva == 0) continue;
      out.push_back(image_base + e.iat_rva);
    }
    return !out.empty();
  }

  if (is_elf || is_macho) {
    extractor::got_result_t got{};
    if (!extractor::extract_got(got, info)) return false;
    for (const auto& e : got.entries) {
      if (e.slot_address == 0) continue;
      out.push_back(e.slot_address);
    }
    return !out.empty();
  }

  return false;
}

// ---------------------------------------------------------------------------
// MalAPI lookup (GET /malapi/<function_name>/)
// ---------------------------------------------------------------------------

struct malapi_hit_t {
  std::string function;
  std::string raw_json;
  long        status = 0;
};

std::optional<malapi_hit_t> query_malapi(local_api::local_api_server& api,
                                         const std::string& function_name) {
  if (!api.running()) return std::nullopt;

  const std::string path = "/malapi/" + function_name + "/";

  const std::vector<std::pair<std::string, std::string>> headers = {
      {"Accept", "application/json"},
  };

  LOG_DEBUG("malapi: GET {}{}", api.base_url(), path);

  const cti::http_response res = api.get(path, headers, 1 * 1024 * 1024);

  if (!res.transport_ok) {
    LOG_DEBUG("malapi: GET {} transport error: {}", path, res.error);
    return std::nullopt;
  }
  if (res.status < 200 || res.status >= 300) {
    LOG_DEBUG("malapi: GET {} -> HTTP {}", path, res.status);
    return std::nullopt;
  }
  if (res.body.empty()) {
    LOG_DEBUG("malapi: GET {} -> empty body", path);
    return std::nullopt;
  }

  malapi_hit_t hit;
  hit.function = function_name;
  hit.status   = res.status;
  hit.raw_json = res.body;
  return hit;
}

bool looks_like_api_name(const std::string& s) {
  if (s.size() < 4 || s.size() > 64) return false;
  if (!std::isalpha(static_cast<unsigned char>(s.front()))) return false;
  for (unsigned char c : s) {
    if (!std::isalnum(c) && c != '_') return false;
  }
  static const std::set<std::string> kNoise = {
      "true", "false", "nullptr", "void", "int", "char", "long",
      "unsigned", "static", "const", "return",
  };
  return kNoise.find(s) == kNoise.end();
}

std::string format_malapi_hit(const malapi_hit_t& hit) {
  try {
    const auto j = nlohmann::json::parse(hit.raw_json);

    auto pick = [&](std::initializer_list<const char*> keys) -> std::string {
      for (const char* k : keys) {
        if (j.contains(k) && j[k].is_string()) {
          return j[k].get<std::string>();
        }
      }
      return {};
    };

    const std::string desc     = pick({"description", "desc", "summary", "info"});
    const std::string category = pick({"category", "type", "class", "tactic"});
    const std::string mitre    = pick({"mitre", "attack", "technique", "attck"});
    const std::string severity = pick({"severity", "risk", "level"});

    std::ostringstream os;
    os << hit.function;
    if (!category.empty()) os << "  [" << category << "]";
    if (!severity.empty()) os << "  sev=" << severity;
    if (!mitre.empty())    os << "  " << mitre;
    if (!desc.empty()) {
      std::string d = desc;
      if (d.size() > 120) d = d.substr(0, 117) + "...";
      os << "  - " << d;
    }
    return os.str();
  } catch (const std::exception&) {
    std::string preview = hit.raw_json;
    for (char& c : preview) {
      if (c == '\n' || c == '\r' || c == '\t') c = ' ';
    }
    if (preview.size() > 160) preview = preview.substr(0, 157) + "...";
    return hit.function + "  ->  " + preview;
  }
}

// Phase-1 PE trailer report: section boundaries, the Authenticode Security
// Directory range, and the extracted overlay with its detected formats.
void print_pe_overlay_report(const extractor::pe_sections_t& result) {
  print_section("PE section end / overlay");
  std::ostringstream os;
  os << "file_size=" << result.file_size
     << "  last_section_end=" << result.last_section_end;
  print_kv("Section boundary", os.str());
  print_kv_colored("Overlay detected",
                   result.has_computed_overlay ? "yes" : "no",
                   result.has_computed_overlay ? console::yellow : console::white);
  if (result.has_computed_overlay) {
    std::ostringstream range;
    range << result.computed_overlay_size << " bytes  start=0x" << std::hex
          << result.computed_overlay_start << "  end=0x" << result.computed_overlay_end;
    print_kv("Overlay range", range.str());
    print_kv("LIEF overlay match", result.overlay_size_matches ? "yes" : "no");
  }

  const auto& sec = result.security_directory;
  print_section("PE Security Directory");
  if (!sec.present) {
    console::info("no Authenticode Security Directory present");
  } else {
    std::ostringstream cert;
    cert << "offset=0x" << std::hex << sec.file_offset << "  size=" << std::dec
         << sec.size << "  end=0x" << std::hex << sec.end_offset;
    print_kv("Certificate range", cert.str());
    print_kv("Range valid", sec.valid_range ? "yes" : "no");
    print_kv("Overlaps section", sec.overlaps_section ? "yes" : "no");
    print_kv("Inside section overlay", sec.inside_section_overlay ? "yes" : "no");
    print_kv("Certificate entries", std::to_string(sec.certificate_count));
    for (const std::string& warning : sec.warnings) print_warn(warning);
  }
  if (result.has_overlay_after_security) {
    std::ostringstream after;
    after << result.overlay_after_security_size << " bytes  start=0x" << std::hex
          << result.overlay_after_security_start;
    print_kv("Data after signature", after.str());
  }

  print_section("PE overlay extraction");
  const auto& overlay = result.overlay;
  if (!overlay.present) {
    console::info("no overlay bytes available to extract or identify");
    return;
  }

  std::ostringstream head;
  head << "offset=0x" << std::hex << overlay.offset << "  size=" << std::dec
       << overlay.size << "  retained=" << overlay.data.size();
  print_kv("Overlay data", head.str());
  print_kv("Magic", overlay.magic_hex + "  [" + overlay.magic_ascii + "]");
  console::print_entropy_and_chi2(overlay.entropy, overlay.chi2);
  if (!overlay.sha256.empty()) print_kv("Overlay SHA-256", overlay.sha256);
  if (overlay.truncated) {
    print_warn("overlay exceeds the retention limit; scan used a bounded prefix");
  }

  if (overlay.signatures.empty()) {
    console::info("no known file format identified inside the overlay");
    return;
  }
  print_kv("Formats identified", std::to_string(overlay.signatures.size()));
  print_section("Overlay formats");
  for (const auto& sig : overlay.signatures) {
    std::ostringstream line;
    line << sig.format << "  " << sig.description
         << "  offset=0x" << std::hex << sig.offset
         << " (+" << std::dec << sig.relative_offset << ")"
         << "  size=" << sig.size
         << "  confidence=" << std::fixed << std::setprecision(2) << sig.confidence;
    print_bullet(line.str());
  }
}

// Human-readable description for every mitigation the extractor tracks, so the
// guards phase explains what each flag actually does instead of only listing
// raw note strings.
struct guard_description_t {
  const char* name;
  bool        enabled;
  const char* description;
};

std::vector<guard_description_t> guard_descriptions(
    const extractor::guard_info_t& g) {
  std::vector<guard_description_t> out;
  auto add = [&](const char* name, bool enabled, const char* description) {
    out.push_back({name, enabled, description});
  };

  if (g.format == "PE") {
    add("ASLR", g.has_aslr,
        "randomizes the image load address to block fixed-address exploits");
    add("High-entropy ASLR", g.has_high_entropy_va,
        "uses the full 64-bit address space, making brute force impractical");
    add("DEP/NX", g.has_nx,
        "marks data pages non-executable to stop shellcode in data regions");
    add("Force integrity", g.has_force_integrity,
        "requires a valid code signature at load time (anti-tamper)");
    add("Isolation aware", g.has_isolation,
        "enables side-channel isolation checks for Spectre-class mitigations");
    add("SEH", !g.has_no_bind,
        "uses Structured Exception Handling instead of bind-based exception tables");
    add("No bind", g.has_no_bind,
        "omits bind-based image binding; older exception model");
    add("Control Flow Guard", g.has_guard_cf,
        "validates indirect call targets against a known-function bitmap");
    add("CET shadow stack", g.has_cet_compat,
        "Intel CET hardware shadow stack for return-address protection");
    add("CET strict mode", g.cet_strict_mode,
        "enables strict CET shadow-stack enforcement");
    add("CET relax IP validation", g.cet_set_context_ip_validation_relaxed,
        "relaxes CET IP validation for compatibility (weakens the guarantee)");
    add("CET dynamic APIs in-process", g.cet_dynamic_apis_allow_in_proc,
        "allows dynamic APIs to run inside the guarded process");
    add("WDM driver", g.has_wdm_driver,
        "marks the image as a WDM driver, changing loader behaviour");
  } else if (g.format == "ELF") {
    add("PIE", g.has_pie,
        "Position Independent Executable: ASLR works with the image base");
    add("RELRO", g.has_relro,
        "makes the GOT read-only after relocations to stop GOT overwrites");
    add("Full RELRO", g.has_full_relro,
        "RELRO covering the entire GOT, not just parts of it");
    add("Stack canary", g.has_stack_canary,
        "stack cookie detects buffer overflows before a function returns");
    add("SafeSEH", g.has_safe_seh,
        "validates Structured Exception Handler addresses against a known table");
    add("FORTIFY_SOURCE", g.has_fortify,
        "compile-time bounds checking for common C library functions");
    add("RPATH/RUNPATH", g.has_rpath,
        "search-path entries baked into the binary (can redirect libraries)");
    add("Executable stack", g.executable_stack,
        "stack is executable: enables classic stack shellcode execution");
    add("SHSTK", g.has_shstk,
        "hardware shadow stack (CET) return-address protection");
    add("IBT", g.has_ibt || g.has_bti,
        "indirect branch tracking: only indirect branches to valid targets run");
    add("PAC", g.has_pac,
        "pointer authentication codes protect return addresses and pointers");
  }
  add("Stack cookie", g.has_stack_cookie,
      "canary value on the stack to detect stack smashing");
  return out;
}

// ---------------------------------------------------------------------------
// xxd hex dump rendering
// ---------------------------------------------------------------------------

// xxd emits: "<offset>: <hex bytes...> |<ascii>|". Colorize the three zones so
// the dump is readable in both the plain terminal and the PDCurses browser.
void print_xxd_line(const std::string& line) {
  const std::size_t colon = line.find(':');
  if (colon == std::string::npos) {
    print_bullet(line, console::grey);
    return;
  }

  std::cout << console::paint(console::cyan, "      * ")
            << console::paint(console::yellow, line.substr(0, colon + 1));

  // Locate the "|...|" ASCII column so the hex and text zones can be styled
  // separately even when a line contains extra pipes.
  const std::size_t last_pipe = line.rfind('|');
  const std::size_t first_pipe = line.find('|', colon + 1);
  if (first_pipe == std::string::npos || last_pipe == first_pipe) {
    std::cout << console::paint(console::green, line.substr(colon + 1)) << '\n';
    return;
  }

  std::cout << console::paint(console::green, line.substr(colon + 1, first_pipe - colon - 1))
            << console::paint(console::cyan, "|")
            << console::paint(console::white, line.substr(first_pipe + 1, last_pipe - first_pipe - 1))
            << console::paint(console::cyan, "|")
            << console::paint(console::grey, line.substr(last_pipe + 1))
            << '\n';
}

// ---------------------------------------------------------------------------
// cminer output rendering
// ---------------------------------------------------------------------------

// Cminer emits ANSI-colored text of its own. Re-emit the meaningful lines with
// our palette instead of letting the raw escape codes through.
void print_cminer_raw(const std::string& output) {
  if (output.empty()) return;
  print_section("Cminer raw output");
  std::istringstream stream(output);
  std::string line;
  std::size_t shown = 0;
  constexpr std::size_t kMaxLines = 40;
  while (shown < kMaxLines && std::getline(stream, line)) {
    // Drop Cminer's own escape sequences, then colour by content.
    std::string clean;
    for (std::size_t i = 0; i < line.size();) {
      if (line[i] == '\x1b' && i + 1 < line.size() && line[i + 1] == '[') {
        i += 2;
        while (i < line.size() && !std::isalpha(static_cast<unsigned char>(line[i]))) ++i;
        if (i < line.size()) ++i;
        continue;
      }
      if (line[i] != '\r') clean.push_back(line[i]);
      ++i;
    }
    while (!clean.empty() && std::isspace(static_cast<unsigned char>(clean.back())))
      clean.pop_back();
    if (clean.empty()) continue;

    const bool is_heading = clean.find("Cave") != std::string::npos ||
                            clean.find("Usage") != std::string::npos ||
                            clean.find("Cminer") != std::string::npos;
    const bool is_cave = clean.find("Section:") != std::string::npos ||
                         clean.find("Cave Size:") != std::string::npos;
    const std::string_view color = is_heading ? console::cyan
                                   : is_cave  ? console::green
                                              : console::grey;
    print_bullet(clean, color);
    ++shown;
  }
  if (shown >= kMaxLines) {
    print_bullet("... output truncated (full text is in the extraction JSON)",
                 console::grey);
  }
}

}  // namespace

// ---------------------------------------------------------------------------

int main(int argc, char** argv) {
  using clock = std::chrono::steady_clock;
  auto elapsed_ms = [](clock::time_point start) {
    return std::chrono::duration<double, std::milli>(clock::now() - start).count();
  };

  console::enable_utf8_output();
  logging::init();
  trace_enable();

  const std::string path = argc > 1 ? argv[1] : "a.exe";
  // Pre-detection placeholder; rescaled by set_total() once the format is known.
  constexpr int kAllPhases = 22;
  curses_ui::session curses_session;
  g_curses_session = &curses_session;
  const bool curses_started = curses_session.begin(
      path, static_cast<std::size_t>(kAllPhases));
  if (!curses_started) {
    const char* mode = std::getenv("STATIC_ANALYZER_CURSES");
    std::cerr << "[curses] UI not active (STATIC_ANALYZER_CURSES="
              << (mode ? mode : "<unset>") << ").\n";
  }

  // -------- Local Python API server ------------------------------------------
  // server.py (auto-generated) binds 127.0.0.1:60000 (hard-coded in app.run;
  // 8080 is taken by the Oracle listener, 5000 by a stale instance) and
  // opens yaml/malapi/<Name>.yaml relative to its CWD, so it must be
  // launched from python/ — the directory that contains the yaml/ tree.
  local_api::local_api_server api;
  {
    local_api::launch_options api_opts;
    api_opts.python          = "py";                      // 'py' launcher ('python' is not on PATH)
    api_opts.script          = "api/server.py";           // relative to working_dir
    api_opts.working_dir     = "python";                  // contains yaml/malapi/
    api_opts.extra_env       = {"PYTHONUNBUFFERED=1"};
    api_opts.base_url        = "http://127.0.0.1:60000";  // matches app.run(port=60000)
    api_opts.health_path     = "/health";
    api_opts.startup_timeout = std::chrono::milliseconds{10000};

    LOG_INFO("trace: starting local API server: '{} {}' (cwd='{}', poll={}{})",
             api_opts.python, api_opts.script, api_opts.working_dir,
             api_opts.base_url, api_opts.health_path);

    const auto st = api.start(api_opts);

    if (st != local_api::launch_status::ok) {
      LOG_ERROR("trace: local_api start failed: {}", local_api::to_string(st));

      const std::string err = api.std_err();
      if (!err.empty()) {
        LOG_ERROR("trace: local_api stderr:\n{}", err);
      } else {
        LOG_ERROR("trace: local_api produced no stderr. If the status above "
                  "is 'not_found', the interpreter or script path is wrong. "
                  "If it is 'died_early', the script crashed before it could "
                  "bind — run 'cd python && py api/server.py' by hand to "
                  "see the traceback.");
      }
    } else {
      LOG_INFO("trace: local API server ready pid={}", api.pid());
    }
  }

  print_banner("static analyzer");
  print_kv("Input",  path);
  print_kv("Run ID", logging::current_run_id());

  analyzer::file_info_t info = analyzer::get_file_info(path);
  const bool failed = analyzer::has_errors(info);

  print_section("file");
  print_kv("Name",  info.filename);
  print_kv("Magic", info.file_magic);
  print_kv_colored("Executable",
                   info.type.is_executable ? "yes" : "no",
                   info.type.is_executable ? console::green : console::yellow);

  console::print_magic_header(info);
  console::print_magic_offset(info);

  if (failed) {
    print_kv_colored("Status", "ANALYSIS FAILED", console::red);
    console::print_available_fields(info);
    for (const auto& error : analyzer::get_error_messages(info)) console::error(error);
    if (!info.errors.details.empty()) console::error("Details: " + info.errors.details);
  } else {
    print_kv_colored("Status", "ok", console::green);
  }

  const file_format fmt = detect_format(info);
  const bool is_pe    = (fmt == file_format::pe);
  const bool is_elf   = (fmt == file_format::elf);
  const bool is_macho = (fmt == file_format::macho);

  print_kv("Format", format_name(fmt));

  // -------- Format-aware phase plan ----------------------------------------
  // The PDCurses results screen turns every printed "[phase n/total]" header
  // into its own section, so a header emitted for a stage that cannot run would
  // advertise work that never happened (an ELF listing "IAT / Import Table
  // (PE)", a PE listing "GOT / PLT (ELF, Mach-O)"). Only the stages that
  // concern this binary are numbered and counted, which also makes the
  // progress bar reflect real work instead of the fixed 22-stage pipeline.
  //
  //   PE / ELF / Mach-O : phase 1 renders the format-specific section table, so
  //                       the generic LIEF view (phase 2) is a duplicate.
  //   PE                : import table (4) and MalAPI (5).
  //   ELF / Mach-O      : GOT / PLT (6).
  const int kSkippedGenericSections = (is_pe || is_elf || is_macho) ? 1 : 0;
  const int kSkippedPeOnly = is_pe ? 0 : 2;                 // IAT + MalAPI
  const int kSkippedGotOnly = (is_elf || is_macho) ? 0 : 1;  // GOT / PLT
  const int kTotalPhases = kAllPhases - kSkippedGenericSections
                         - kSkippedPeOnly - kSkippedGotOnly;
  curses_session.set_total(static_cast<std::size_t>(kTotalPhases));

  // Numbers the next stage that applies. Stages that do not apply advance
  // nothing and print nothing.
  int phase_no = 0;
  const auto phase = [&](bool applies, const std::string& label) {
    if (!applies) return;
    print_phase(++phase_no, kTotalPhases, label);
  };

  // -------- Hashes --------
  file_hash_t file_hash{};
  if (hasher::hash_file(file_hash, info)) {
    print_kv("SHA-256", file_hash.hash);
  } else {
    print_kv_colored("SHA-256", "failed", console::red);
    for (const auto& message : hasher::get_hash_error_messages(file_hash))
      console::error(message);
  }

  fuzzy_hash_t fuzzy_hash{};
  if (hasher::fuzzy_hash_file(fuzzy_hash, info)) {
    print_kv("TLSH", fuzzy_hash.fuzzy_hash);
  } else {
    print_kv_colored("TLSH", "failed", console::red);
    for (const auto& message : hasher::get_fuzzy_hash_error_messages(fuzzy_hash))
      console::error(message);
  }

  // -------- Phase 1: sections --------
  phase(true, is_pe ? "PE sections"
                 : is_elf ? "ELF sections"
                 : is_macho ? "Mach-O sections"
                 : "sections");
  {
    const auto started = clock::now();
    if (is_pe) {
      extractor::pe_sections_t result{};
      if (extractor::extract_pe_sections(result, info)) {
        print_section("PE: " + result.machine + "  " + result.characteristics);
        std::ostringstream ep;
        ep << "0x" << std::hex << result.entrypoint;
        print_kv("Entrypoint", ep.str());
        for (const auto& section : result.sections) {
          std::cout << "      " << std::left << std::setw(10) << section.name
                    << "  va=0x" << std::hex << section.virtual_address
                    << std::dec
                    << "  vsize=" << section.virtual_size
                    << "  raw=" << section.raw_size << '\n';
          console::print_entropy_and_chi2(section.entropy, section.chi2);
        }
        print_pe_overlay_report(result);
      } else {
        for (const auto& message : extractor::get_error_messages(result))
          console::error(message);
      }
    } else if (is_elf) {
      extractor::elf_sections_t result{};
      if (extractor::extract_elf_sections(result, info)) {
        print_section("ELF: " + result.machine + "  " + result.file_type);
        std::ostringstream ep;
        ep << "0x" << std::hex << result.entrypoint;
        print_kv("Entrypoint", ep.str());
        if (!result.interpreter.empty()) print_kv("Interpreter", result.interpreter);
        for (const auto& section : result.sections) {
          std::cout << "      " << std::left << std::setw(10) << section.name
                    << "  va=0x" << std::hex << section.virtual_address
                    << std::dec
                    << "  size=" << section.size
                    << "  type=" << section.type
                    << "  flags=" << section.flags << '\n';
          console::print_entropy_and_chi2(section.entropy, section.chi2);
        }
      } else {
        for (const auto& message : extractor::get_error_messages(result))
          console::error(message);
      }
    } else if (is_macho) {
      extractor::sections_result_t result{};
      if (extractor::extract_sections(result, info)) {
        print_section("Mach-O: " + std::to_string(result.sections.size()) + " sections");
        for (const auto& section : result.sections) {
          std::cout << "      " << std::left << std::setw(10) << section.name
                    << "  va=0x" << std::hex << section.virtual_address
                    << std::dec
                    << "  size=" << section.size
                    << "  H=" << section.entropy << '\n';
          console::print_entropy_and_chi2(section.entropy, section.chi2);
        }
      } else {
        for (const auto& message : extractor::get_error_messages(result))
          console::error(message);
      }
    } else {
      console::info("no format-specific section view for " + std::string(format_name(fmt)));
    }
    print_duration(elapsed_ms(started));
  }

  // -------- Phase 2: format-agnostic section table --------
  // Phase 1 already renders a format-specific section table (PE / ELF / Mach-O)
  // including flags and permissions. Re-printing the same sections through the
  // generic LIEF view only produced a duplicate, so it is skipped for the three
  // formats that have a dedicated view and kept for everything else.
  phase(!(is_pe || is_elf || is_macho), "generic sections");
  {
    const auto started = clock::now();
    if (!(is_pe || is_elf || is_macho)) {
      extractor::sections_result_t result{};
      if (extractor::extract_sections(result, info)) {
        print_section("Sections: " + std::to_string(result.sections.size()));
        for (const auto& section : result.sections) {
          std::cout << "      " << std::left << std::setw(10) << section.name
                    << "  va=0x" << std::hex << section.virtual_address
                    << std::dec
                    << "  size=" << section.size
                    << "  H=" << std::fixed << std::setprecision(4) << section.entropy
                    << "  chi2=" << std::setprecision(0) << section.chi2 << '\n';
        }
      } else {
        for (const auto& message : extractor::get_error_messages(result))
          console::error(message);
      }
    }
    print_duration(elapsed_ms(started));
  }

  // -------- Phase 3: strings + IOC --------
  phase(true, "strings + IOC");
  std::vector<std::string> strings_for_ioc{};
  ioc::ioc_results_t ioc_results{};
  {
    const auto started = clock::now();
    extractor::strings_result_t result{};
    if (extractor::extract_strings(result, info, 6)) {
      print_kv_colored("Strings found",
                       std::to_string(result.strings.size()),
                       console::green);
      constexpr std::size_t kMaxShown = 10;
      std::size_t shown = 0;
      for (const auto& entry : result.strings) {
        if (shown >= kMaxShown) break;
        std::ostringstream os;
        os << "[" << std::setw(8) << std::dec << entry.offset << "] " << entry.value;
        print_bullet(os.str());
        ++shown;
      }
      if (result.strings.size() > shown)
        print_bullet("... and " + std::to_string(result.strings.size() - shown) + " more");

      // Move (not copy) the values into the IOC/MalAPI working set: the
      // preview above is already printed, so keeping a second full copy of
      // every extracted string is pure overhead. Halves peak memory here.
      strings_for_ioc.reserve(result.strings.size());
      for (auto& entry : result.strings)
        strings_for_ioc.push_back(std::move(entry.value));
    } else {
      for (const auto& message : extractor::get_error_messages(result))
        console::error(message);
    }
    print_duration(elapsed_ms(started));
  }

  if (!strings_for_ioc.empty()) {
    const auto started = clock::now();
    ioc_results = ioc::extract_all(strings_for_ioc);
    if (ioc::has_errors(ioc_results)) {
      console::error("IOC extraction had errors");
      for (const auto& msg : ioc::get_error_messages(ioc_results)) console::error(msg);
    } else {
      print_section("IOC extraction");
      ioc::print_ioc_results(ioc_results);
      if (!ioc_results.ips.empty()) {
        print_section("IP network information");
        for (const std::string& ip : ioc_results.ips) {
          print_ip_network_info(ip, cti::ip_network_context(ip));
        }
      }
    }
    print_duration(elapsed_ms(started));
  } else {
    print_warn("no candidate strings available for IOC extraction");
  }

  // IOC extraction was the last consumer of the extracted strings — release
  // them before the memory-heavy capa / radare2 phases.
  strings_for_ioc.clear();
  strings_for_ioc.shrink_to_fit();

  // -------- Phases 4-5: IAT (PE) + MalAPI lookup ------------------------------
  // The MalAPI database is queried with the functions actually imported
  // from DLLs (IAT names) instead of heuristic guesses over raw strings.
  std::vector<malapi_hit_t> malapi_hits{};  // structured hits for the dashboard
  {
    // -------- Phase 4: IAT (PE) --------
    phase(is_pe, "import table (PE)");
    extractor::iat_result_t iat_result{};
    {
      const auto started = clock::now();
      if (is_pe) {
        if (extractor::extract_iat(iat_result, info)) print_iat_report(iat_result);
        else {
          for (const auto& message : extractor::get_error_messages(iat_result))
            console::error(message);
        }
      }
      print_duration(elapsed_ms(started));
    }

    // -------- Phase 5: MalAPI lookup over imported functions --------
    phase(is_pe, "MalAPI lookup (imported functions)");
    {
      const auto started = clock::now();

      if (!api.running()) {
        console::info("local API server not running; skipping MalAPI lookups");
      } else if (is_pe) {
        constexpr std::size_t kMaxQueries = 500;

        std::set<std::string> seen;
        std::vector<std::string> queue;
        queue.reserve(std::min<std::size_t>(kMaxQueries, iat_result.entries.size()));

        for (const auto& entry : iat_result.entries) {
          if (queue.size() >= kMaxQueries) break;
          if (entry.name.empty()) continue;  // ordinal-only import
          if (!looks_like_api_name(entry.name)) continue;
          if (!seen.insert(entry.name).second) continue;
          queue.push_back(entry.name);
        }

        LOG_INFO("malapi: querying {} imported function name(s)", queue.size());
        print_kv("Candidates", std::to_string(queue.size()));

        // Show which imported functions are actually being looked up. Without
        // this the phase reported only a count, so it was impossible to tell
        // what was queried when a hit or a miss mattered.
        if (!queue.empty()) {
          print_section("MalAPI lookup candidates");
          constexpr std::size_t kMaxShown = 60;
          std::size_t shown = 0;
          for (const std::string& name : queue) {
            if (shown >= kMaxShown) break;
            print_bullet(name, console::cyan);
            ++shown;
          }
          if (shown < queue.size()) {
            print_bullet("... and " + std::to_string(queue.size() - shown) +
                         " more candidate(s)", console::grey);
          }
        }

        std::vector<std::string> hits;
        hits.reserve(queue.size());

        for (const std::string& name : queue) {
          const auto hit = query_malapi(api, name);
          if (!hit) continue;
          hits.push_back(format_malapi_hit(*hit));
          malapi_hits.push_back(*hit);   // structured, for the dashboard
        }

        if (hits.empty()) {
          console::info("no MalAPI matches among the imported functions");
        } else {
          print_section("MalAPI matches (" + std::to_string(hits.size()) + ")");
          for (const std::string& line : hits) {
            print_bullet(line, console::red);
          }
        }
      }

      print_duration(elapsed_ms(started));
    }
  }  // iat_result released here — before the memory-heavy phases

  // -------- Phase 6: GOT (ELF / Mach-O) --------
  phase(is_elf || is_macho, "GOT / PLT (ELF, Mach-O)");
  {
    // Scoped to the phase: the exporter re-reads GOT data from `full`, so
    // this copy does not need to live until the end of main().
    extractor::got_result_t got_result{};
    const auto started = clock::now();
    if (is_elf || is_macho) {
      if (extractor::extract_got(got_result, info)) print_got_report(got_result);
      else {
        for (const auto& message : extractor::get_error_messages(got_result))
          console::error(message);
      }
    }
    print_duration(elapsed_ms(started));
  }

  // -------- Phase 7: packer --------
  phase(true, "packer detection");
  {
    const auto started = clock::now();
    extractor::packer_detection_t result{};
    if (extractor::detect_if_packed(result, info)) {
      if (result.packed) {
        print_kv_colored("Verdict", "SUSPICIOUS (packed)", console::red);
        for (const auto& reason : result.reasons) print_bullet(reason, console::red);
      } else {
        print_kv_colored("Verdict", "clean (no packer indicators)", console::green);
      }
    } else {
      for (const auto& message : extractor::get_error_messages(result))
        console::error(message);
    }
    print_duration(elapsed_ms(started));
  }

  // -------- Phase 8: opcodes --------
  phase(true, "opcode statistics");
  {
    const auto started = clock::now();
    extractor::opcode_stats_t result{};
    if (extractor::generate_opcode_stats(result, info)) {
      print_kv("Architecture", result.architecture);
      print_kv("Instructions", std::to_string(result.total_instructions));
      print_section("top opcode bytes");
      std::size_t top = 0;
      for (std::size_t i = 0; i < 256 && top < 10; ++i) {
        if (result.counts[i] == 0) continue;
        std::ostringstream os;
        os << "0x" << std::hex << std::setw(2) << std::setfill('0') << i
           << std::dec << std::setfill(' ')
           << "  x" << std::setw(6) << result.counts[i]
           << "  (" << std::fixed << std::setprecision(3)
           << result.frequencies[i] * 100.0 << "%)";
        print_bullet(os.str());
        ++top;
      }
    } else {
      for (const auto& message : extractor::get_error_messages(result))
        console::error(message);
    }
    print_duration(elapsed_ms(started));
  }

  // -------- Phase 9: debug symbols --------
  phase(true, "debug symbols");
  {
    const auto started = clock::now();
    extractor::debug_symbols_t result{};
    if (extractor::extract_debug_symbols(result, info)) {
      print_kv("Format",  result.format);
      print_kv("Symbols", std::to_string(result.symbols.size()));
      print_kv_colored("Stripped",
                       result.stripped ? "yes" : "no",
                       result.stripped ? console::yellow : console::green);
      if (!result.pdb_filename.empty()) print_kv("PDB", result.pdb_filename);
      if (!result.debug_sections.empty()) {
        std::string secs;
        for (const auto& s : result.debug_sections) {
          if (!secs.empty()) secs += ", ";
          secs += s;
        }
        print_kv("Debug sections", secs);
      }
    } else {
      const auto errs = extractor::get_error_messages(result);
      if (errs.empty()) {
        console::info("no debug symbols present");
      } else {
        console::error("debug symbol extraction failed");
        for (const auto& m : errs) console::error("  " + m);
      }
    }
    print_duration(elapsed_ms(started));
  }

  // -------- Phase 10: signature --------
  phase(true, "signature check");
  {
    const auto started = clock::now();
    extractor::signature_info_t result{};
    if (extractor::extract_signature_info(result, info)) {
      print_kv("Format",     result.format);
      print_kv("Signatures", std::to_string(result.num_signatures));
      if (!result.signer.empty()) print_kv("Signer", result.signer);
      if (!result.issuer.empty()) print_kv("Issuer", result.issuer);
      if (!result.verification.empty())
        print_kv_colored("Verification", result.verification,
                         result.is_valid ? console::green : console::yellow);
      for (const auto& d : result.details) console::success(d);
    } else {
      console::info("not signed (" + result.format + ")");
    }
    print_duration(elapsed_ms(started));
  }

  // -------- Phase 11: capa --------
  phase(true, "capa");
  capa::report_t capa_report;
  {
    const auto started = clock::now();
    capa::options capa_opts;
    capa_opts.executable            = "capa";
    capa_opts.cache_dir             = "cache/capa";
    capa_opts.cache_salt            = "v1";
    capa_opts.include_library_rules = false;
    capa_opts.max_addresses         = 32;
    capa_opts.max_stdout_bytes      = 64u * 1024u * 1024u;
    capa_opts.low_priority          = true;
    capa_opts.timeout               = std::chrono::seconds(300);

    capa_report = capa::analyze_file(info.filepath, capa_opts);
    print_capa_report(capa_report);
    print_duration(elapsed_ms(started));
  }

  r2::options r2_opts;
  r2_opts.executable            = "r2";
  r2_opts.rabin2                = "rabin2";
  r2_opts.use_wsl               = true;
  r2_opts.quiet                 = true;
  r2_opts.analysis              = true;
  r2_opts.timeout               = std::chrono::milliseconds(180000);
  r2_opts.pin_analysis_config   = true;
  r2_opts.anal_timeout_ms       = 120000;

  if (!r2::find_executable(r2_opts).empty()) {
    r2_opts.r2_version = r2::version(r2_opts);
  }
  if (!r2::find_rabin2(r2_opts).empty()) {
    r2_opts.rabin2_version = r2::rabin2_version(r2_opts);
  }

  const std::string stem    = exporter::make_stem(info, file_hash);
  const std::string out_dir = std::string(exporter::dir::radare2);

  // -------- Phase 12: radare2 graphs --------
  phase(true, "radare2 disassembly");
  r2::bulk_result_t r2_result{};
  {
    const auto started = clock::now();
    r2_result = r2::extract_all(info.filepath, out_dir, stem, r2_opts);
    print_radare2_report(r2_result);
    print_duration(elapsed_ms(started));
  }

  // -------- Phase 13: graphviz rendering --------
  std::size_t rendered_ok = 0;
  std::size_t rendered_attempted = 0;
  std::string render_format;
  {
    render_format = env_or_empty("R2_RENDER");
    if (!render_format.empty()) {
      phase(true, "graphviz rendering");

      const auto started = clock::now();
      std::string dot_exe = env_or_empty("R2_DOT_EXE");
      if (dot_exe.empty()) dot_exe = r2::default_dot();

      r2::section_dot_result_t dot_view;
      for (const auto& f : r2_result.files) {
        const bool is_dot =
            f.path.size() >= 4 &&
            f.path.compare(f.path.size() - 4, 4, ".dot") == 0;
        if (!is_dot) continue;

        r2::section_dot_file_t entry;
        entry.section = f.kind;
        entry.path    = f.path;
        entry.bytes   = f.bytes;
        entry.empty   = (f.bytes == 0);
        dot_view.files.push_back(std::move(entry));
      }
      dot_view.sections_considered = dot_view.files.size();

      if (dot_view.files.empty()) {
        console::info("no .dot files to render");
      } else if (dot_exe.empty()) {
        print_warn("graphviz 'dot' not found; skipping render "
                   "(install Graphviz or set R2_DOT_EXE)");
      } else {
        const auto errors =
            r2::render_section_dots(dot_view, dot_exe, render_format);
        rendered_attempted = dot_view.files.size();
        rendered_ok = rendered_attempted - errors.size();
        print_render_report(render_format, rendered_ok, rendered_attempted, errors);
      }
      print_duration(elapsed_ms(started));
    }
  }

  // -------- Phase 14: IAT/GOT call-site assembly --------
  phase(true, "IAT/GOT call-site assembly");
  r2::xref_asm_result_t xref_result{};
  bool xref_skipped = false;
  {
    const auto started = clock::now();

    std::uint64_t pe_image_base = 0;
    if (is_pe) {
      r2::result_t meta = r2::analyze_file(info.filepath, r2_opts);
      if (meta.st == r2::status::ok) pe_image_base = meta.info.baddr;
    }

    std::vector<std::uint64_t> targets;
    const bool have_targets = collect_xref_targets(
        info, is_pe, is_elf, is_macho, pe_image_base, targets);

    if (!have_targets || targets.empty()) {
      console::info("no IAT/GOT targets to disassemble");
      xref_skipped = true;
    } else {
      r2::xref_asm_options dump;
      dump.max_slots               = 2000;
      dump.max_functions           = 500;
      dump.dedup_functions         = true;
      dump.include_addresses       = true;
      dump.include_function_header = true;

      xref_result = r2::dump_xref_calls(info.filepath, out_dir, stem,
                                        targets, r2_opts, dump);
      print_xref_asm_report(xref_result);
    }

    print_duration(elapsed_ms(started));
  }

  // -------- Phase 15: compilation guards --------
  phase(true, "compilation guards");
  {
    const auto started = clock::now();
    extractor::guard_info_t result{};
    if (extractor::extract_guard_info(result, info)) {
      print_kv("Format", result.format);
      if (result.format == "PE") {
        std::ostringstream dc;
        dc << "0x" << std::hex << result.dll_characteristics_raw;
        print_kv("DllCharacteristics", dc.str());
      } else if (result.format == "ELF") {
        std::ostringstream xf;
        xf << "0x" << std::hex << result.x86_features_raw;
        print_kv("x86 features", xf.str());
      }
      if (result.notes.empty()) {
        print_kv_colored("Guards",
                         "none set - suspicious for modern software",
                         console::red);
      } else {
        print_section("active mitigations");
        for (const auto& note : result.notes) print_bullet(note, console::green);
      }

      // Explain what each mitigation actually does, and flag the risky ones.
      const auto descriptions = guard_descriptions(result);
      if (!descriptions.empty()) {
        print_kv("Mitigations",
                 std::to_string(result.mitigations_enabled) + " of " +
                     std::to_string(result.mitigations_checked) + " checked");
        print_section("compilation guard details");
        std::ostringstream head;
        head << std::left << std::setw(26) << "Guard" << std::setw(6) << "State"
             << "What it does";
        print_bullet(head.str(), console::cyan);
        for (const auto& guard : descriptions) {
          const bool risky = std::strcmp(guard.name, "Executable stack") == 0 ||
                             std::strcmp(guard.name, "No bind") == 0 ||
                             std::strcmp(guard.name, "CET relax IP validation") == 0 ||
                             std::strcmp(guard.name, "Force integrity") == 0;
          const std::string state = guard.enabled ? "on" : "off";
          const std::string_view color = guard.enabled
                                             ? (risky ? console::yellow : console::green)
                                             : console::grey;
          std::ostringstream row;
          row << std::left << std::setw(26) << guard.name
              << std::setw(6) << state << guard.description;
          print_bullet(row.str(), color);
        }
      }
    } else {
      console::info("no compilation guards extracted (" + result.format + ")");
    }
    print_duration(elapsed_ms(started));
  }

  // -------- Full pipeline --------
  extractor::extraction_result_t full{};
  extractor::analyze(full, info);

  // -------- Phase 16: xxd hex dump --------
  // The extractor already runs `wsl xxd` and stores the output; surface it as a
  // real report section so it is visible in the terminal and in the PDCurses
  // results browser (it is also exported inside the extraction JSON).
  phase(true, "xxd hex dump");
  {
    const auto started = clock::now();
    const auto& xxd = full.xxd;
    print_section("Xxd");
    if (!xxd.attempted) {
      console::info("xxd was not attempted for this file");
    } else if (!xxd.available) {
      print_warn("xxd unavailable: WSL or the xxd binary could not be used");
      if (!xxd.command.empty()) print_kv("Command", xxd.command);
      if (!xxd.stderr_tail.empty()) print_kv("Stderr", xxd.stderr_tail);
    } else {
      print_kv("Command", xxd.command);
      std::ostringstream meta;
      meta << "exit=" << xxd.exit_code << "  seconds=" << std::fixed
           << std::setprecision(3) << xxd.seconds
           << "  bytes=" << xxd.output.size();
      print_kv("Dump", meta.str());
      print_section("Hex dump");
      std::istringstream stream(xxd.output);
      std::string line;
      std::size_t shown = 0;
      constexpr std::size_t kMaxLines = 80;   // 0x500 bytes by default
      while (shown < kMaxLines && std::getline(stream, line)) {
        print_xxd_line(line);
        ++shown;
      }
      if (shown < std::count_if(xxd.output.begin(), xxd.output.end(),
                                 [](char c) { return c == '\n'; })) {
        print_bullet("... more dump lines follow "
                     "(the full dump is in the extraction JSON)",
                     console::grey);
      }
    }
    print_duration(elapsed_ms(started));
  }

  // -------- Phase 17: cminer code caves --------
  phase(true, "cminer code caves");
  {
    const auto started = clock::now();
    const auto& caves = full.cminer;
    print_section("Cminer");
    if (!caves.attempted) {
      console::info("cminer was not attempted for this file");
    } else if (!caves.applicable) {
      console::info("cminer only analyzes PE files; skipped");
    } else if (!caves.available) {
      print_warn("cminer unavailable: WSL or the Cminer binary could not be used");
      if (!caves.command.empty()) print_kv("Command", caves.command);
      if (!caves.stderr_tail.empty()) print_kv("Stderr", caves.stderr_tail);
    } else {
      print_kv("Command", caves.command);
      std::ostringstream meta;
      meta << "exit=" << caves.exit_code << "  seconds=" << std::fixed
           << std::setprecision(3) << caves.seconds
           << "  min_cave_size=" << caves.minimum_cave_size;
      print_kv("Scan", meta.str());
      print_kv("Caves found", std::to_string(caves.caves.size()));
      print_kv("Total cave bytes", std::to_string(caves.total_cave_bytes));
      print_kv("Largest cave", std::to_string(caves.largest_cave_bytes));
      if (caves.caves.empty()) {
        console::info("no code caves at or above the minimum size");
      } else {
        print_section("Code caves");
        std::ostringstream head;
        head << std::left << std::setw(18) << "Section" << std::right
             << std::setw(8) << "Size" << std::setw(14) << "Start"
             << std::setw(14) << "End" << std::setw(12) << "FileOff";
        print_bullet(head.str(), console::cyan);
        constexpr std::size_t kMaxCaves = 20;
        std::size_t shown = 0;
        for (const auto& cave : caves.caves) {
          if (shown >= kMaxCaves) break;
          std::ostringstream row;
          row << std::left << std::setw(18) << cave.section << std::right
              << std::setw(8) << cave.size
              << "  0x" << std::hex << std::setw(10) << cave.start_address
              << "  0x" << std::setw(10) << cave.end_address
              << "  0x" << std::setw(8) << cave.file_offset << std::dec;
          print_bullet(row.str());
          ++shown;
        }
        if (shown < caves.caves.size()) {
          print_bullet("... and " + std::to_string(caves.caves.size() - shown) +
                       " more (all caves are in the extraction JSON)");
        }
      }
      // The raw tool output is kept alongside the parsed table.
      print_cminer_raw(caves.output);
    }
    print_duration(elapsed_ms(started));
  }

  // -------- Phase 18: pipeline error recovery --------
  phase(true, "pipeline error recovery");
  {
    const auto started = clock::now();
    const auto errors = extractor::recover_errors(full);
    if (errors.empty()) console::success("no pipeline errors");
    else {
      console::print_tree_header("stage errors");
      console::print_tree_stages(errors);
    }
    print_duration(elapsed_ms(started));
  }

  // CTI phase state — declared here so phases 17 and 18b can both see it.
  cti::report cti_report{};
  bool cti_ok = false;

  // -------- Phase 17: CTI threat-intel pipeline (env API keys) --------
  {
    const auto started = clock::now();
    phase(true, "CTI threat intel");

    // Keys come from environment (no header configuration / no CLI flags).
    // Providers without a key are skipped and listed in the report warnings.
    const auto cti_cfg = cti::config::from_environment();

    // Allow the smoke / CI run (no keys, no network) to skip this phase
    // without hanging: the phase is a no-op when CTI_SKIP is set.
    const bool cti_skip = [] {
      const char* v = std::getenv("CTI_SKIP");
      return v && (std::string(v) == "1" || std::string(v) == "true");
    }();

    if (cti_skip) {
      console::info("CTI phase skipped (CTI_SKIP=1) — API keys not wired in this environment");
    } else {
      cti::pipeline pipe(cti_cfg);
      if (!pipe.network_available()) {
        console::info("No internet connection found — skipping CTI phase.");
      } else {

      // Seed the pipeline from the artifacts already extracted in this run.
      cti::collect_from_ioc(pipe, ioc_results);
      cti::collect_from_extraction(pipe, full);

      // The file hasher exposes a single unified hash member; feed whichever
      // hash the hasher produced (md5/sha1 are left empty and ignored).
      cti::add_file_hashes(pipe, file_hash.hash, "", "");

      // Progress: one line per completed (source, artifact) query. The source
      // name is the provider that answered, which is what makes the trace
      // readable — a bare round/task counter says nothing about where the
      // intelligence came from. A header is printed whenever the pipeline
      // moves to the next round (the callback fires per task, possibly from
      // several worker threads at once, hence the lock).
      std::mutex cti_progress_mtx;
      int        cti_progress_round = -1;

      cti_report = pipe.run([&](const cti::progress_info& info) {
        std::lock_guard<std::mutex> lock(cti_progress_mtx);

        if (info.round != cti_progress_round) {
          cti_progress_round = info.round;
          std::ostringstream head;
          head << "cti round " << (info.round + 1) << ": "
               << (info.round == 0 ? "artifacts collected in this scan"
                                   : "artifacts derived from earlier answers")
               << " (" << info.total << " query task(s))";
          console::info(head.str());
        }

        std::ostringstream os;
        os << std::left << std::setw(18) << info.provider
           << ' ' << std::left << std::setw(46) << info.artifact
           << " [" << info.done << '/' << info.total << ']';
        console::info(os.str());
      });

      std::vector<const cti::enrichment*> cti_ips;
      for (const cti::enrichment& item : cti_report.items) {
        if (item.art.type == cti::artifact_type::ip) cti_ips.push_back(&item);
      }
      if (!cti_ips.empty()) {
        print_section("CTI IP network information");
        for (const cti::enrichment* item : cti_ips) {
          print_ip_network_info(item->art.value, item->net);
        }
      }

      if (cti_report.items.empty() && cti_report.warnings.empty()) {
        console::info("CTI pipeline produced no artifacts (no keys / no results for this sample)");
      } else {
        cti::print_summary(cti_report, std::cout);
      }

      cti_ok = !cti_report.items.empty();
      if (cti_ok) console::success("CTI: " + std::to_string(cti_report.items.size()) +
                                   " artifact(s), " + std::to_string(cti_report.counts_by_verdict.size()) +
                                   " verdict categories");
      else       console::info("CTI: no artifacts collected for this sample");
      }
    }

    print_duration(elapsed_ms(started));
  }

  // -------- Phase 18: export --------
  phase(true, "export");
  {
    const auto started = clock::now();

    const extractor::iat_result_t& iat = full.pe.iat;
    const extractor::got_result_t& got =
        full.elf.got.entries.empty() ? full.got : full.elf.got;

    const auto paths = exporter::write_all(
        stem, info, file_hash, fuzzy_hash, ioc_results, full,
        capa_report, iat, got, r2_result);

    std::size_t expected_artifacts = 4 + 1 + 1;
    if (is_pe)              expected_artifacts += 1;
    if (!paths.got.empty()) expected_artifacts += 1;

    if (paths.paths().size() == expected_artifacts) {
      console::success("exported " + std::to_string(expected_artifacts) +
                       " report files under exports/");
      for (const auto& p : paths.paths()) print_bullet(p.string(), console::green);
    } else {
      console::error("some export files failed to write (expected " +
                     std::to_string(expected_artifacts) +
                     ", got " + std::to_string(paths.paths().size()) + ")");
      for (const auto& p : paths.paths()) print_bullet(p.string());
    }

    const auto summary = exporter::summarize_exports(paths);
    exporter::print_export_summary(summary);
    print_duration(elapsed_ms(started));
  }

  // ---------- Phase 18b: CTI JSON export ----------
  {
    if (!cti_report.items.empty()) {
      const auto cti_path = exporter::write_cti_json(stem, cti_report);
      if (!cti_path.empty()) {
        console::success("CTI report written to " + cti_path.string());
      }
    }
  }

  // Structured MalAPI hits for the dashboard (exports/malapi/<stem>_malapi.json).
  if (!malapi_hits.empty()) {
    nlohmann::json marr = nlohmann::json::array();
    for (const auto& h : malapi_hits) {
      nlohmann::json mh = {{"function", h.function}, {"status", h.status}};
      try {
        mh["data"] = nlohmann::json::parse(h.raw_json);
      } catch (const std::exception&) {
        mh["raw"] = h.raw_json;
      }
      marr.push_back(std::move(mh));
    }
    exporter::write_malapi_json(stem, marr);
  }
  {
    std::vector<malapi_hit_t> empty;
    std::swap(malapi_hits, empty);
  }

  // -------- Phase 19: dashboard (HTML) --------
  {
    const auto started = clock::now();
    phase(true, "dashboard");

    // Collect the artifacts the dashboard consumes. The .dot graphs and the
    // enriched assembly JSON are produced by the radare2 runner.
    std::string asm_json, callgraph_dot, section_dot;
    for (const auto& f : r2_result.files) {
      if (f.kind == "asm_json")          asm_json      = f.path;
      else if (f.kind == "callgraph")    callgraph_dot = f.path;
      else if (f.kind.rfind("section:", 0) == 0 && section_dot.empty())
        section_dot = f.path;
    }

    visualizer::options vopts;
    vopts.output_name   = stem;
    vopts.fileinfo      = (exporter::dir::fileinfo   + ("/" + stem + "_fileinfo.json"));
    vopts.hash          = (exporter::dir::hash       + ("/" + stem + "_hash.json"));
    vopts.ioc           = (exporter::dir::ioc        + ("/" + stem + "_ioc.json"));
    vopts.extraction    = (exporter::dir::extraction + ("/" + stem + "_extraction.json"));
    vopts.capa          = (exporter::dir::capa       + ("/" + stem + "_capa.json"));
    vopts.iat           = (exporter::dir::iat        + ("/" + stem + "_iat.json"));
    vopts.got           = (exporter::dir::got        + ("/" + stem + "_got.json"));
    vopts.radare2       = (exporter::dir::radare2    + ("/" + stem + "_radare2.json"));
    vopts.malapi        = (exporter::dir::malapi     + ("/" + stem + "_malapi.json"));
    vopts.cti           = (exporter::dir::cti        + ("/" + stem + "_cti.json"));
    vopts.files_root    = exporter::dir::root;
    vopts.asm_json      = asm_json;
    vopts.callgraph_dot = callgraph_dot;
    vopts.section_dot   = section_dot;

    const auto vr = visualizer::render(vopts);
    if (vr.ok) {
      if (g_curses_session != nullptr) g_curses_session->set_dashboard_path(vr.html_path);
      print_kv_colored("Dashboard", vr.html_path, console::green);
    } else {
      print_warn("dashboard not generated: " + vr.error);
    }
    print_duration(elapsed_ms(started));
  }

  // The exporter was the last consumer of the IOC results — release them
  // before the sanity phase and shutdown.
  {
    ioc::ioc_results_t empty{};
    std::swap(ioc_results, empty);
  }

  // -------- Phase 20: sanity --------
  phase(true, "sanity: invalid input");
  {
    const auto started = clock::now();
    bool hash_failed = false;
    bool fuzzy_failed = false;
    {
      file_hash_t invalid_hash{};
      analyzer::file_info_t invalid_info{};
      invalid_info.filepath = "definitely_missing_hash_target.bin";
      hash_failed = !hasher::hash_file(invalid_hash, invalid_info);
    }
    {
      fuzzy_hash_t invalid_fuzzy_hash{};
      analyzer::file_info_t invalid_info{};
      invalid_info.filepath = "definitely_missing_fuzzy_target.bin";
      fuzzy_failed = !hasher::fuzzy_hash_file(invalid_fuzzy_hash, invalid_info);
    }
    if (hash_failed && fuzzy_failed) console::success("invalid inputs correctly rejected");
    else console::error("one or more invalid inputs were accepted");
    print_duration(elapsed_ms(started));
  }

  // -------- Summary --------
  print_banner("summary");
  print_kv("File",    info.filename);
  print_kv("Format",  format_name(fmt));
  print_kv("SHA-256", file_hash.hash.empty() ? "(failed)" : file_hash.hash);
  print_kv("Capa",
           capa_report.ok()
               ? (std::to_string(capa_report.capabilities.size()) + " capabilities")
               : std::string("failed: ") + capa::to_string(capa_report.st));

  {
    std::size_t core = 0, sections = 0;
    for (const auto& f : r2_result.files) {
      if (f.kind.rfind("section:", 0) == 0) ++sections;
      else                                   ++core;
    }
    std::ostringstream os;
    if (r2_result.st == r2::status::ok || r2_result.st == r2::status::partial) {
      os << core << " core file(s), " << sections << " section file(s), "
         << r2_result.functions.size() << " function(s)";
      if (r2_result.st == r2::status::partial) {
        os << " (" << r2_result.errors.size() << " error(s))";
      }
      print_kv("Radare2", os.str());
    } else {
      print_kv_colored("Radare2",
                       std::string("failed: ") + r2::to_string(r2_result.st),
                       console::red);
    }
  }

  if (!render_format.empty() && rendered_attempted > 0) {
    std::ostringstream os;
    os << rendered_ok << " / " << rendered_attempted
       << " graph(s) rendered (" << render_format << ")";
    print_kv_colored("Graphviz", os.str(),
                     rendered_ok == rendered_attempted ? console::green : console::yellow);
  }

  if (xref_skipped) {
    print_kv("IAT/GOT calls", "skipped (no IAT/GOT targets)");
  } else if (xref_result.st == r2::status::ok ||
             xref_result.st == r2::status::partial) {
    std::ostringstream os;
    os << xref_result.xrefs_found << " call site(s) -> "
       << xref_result.functions_dumped << " function(s)";
    if (xref_result.st == r2::status::partial) {
      os << " (" << xref_result.errors.size() << " error(s))";
    }
    print_kv("IAT/GOT calls", os.str());
  } else if (xref_result.st == r2::status::bad_output) {
    print_kv("IAT/GOT calls", "no call sites found");
  } else {
    print_kv_colored("IAT/GOT calls",
                     std::string("failed: ") + r2::to_string(xref_result.st),
                     console::red);
  }

  if (is_pe) {
    print_kv("IAT", std::to_string(full.pe.iat.entries.size()) + " entries");
  }
  {
    const auto& g = full.elf.got.entries.empty() ? full.got : full.elf.got;
    if (!g.entries.empty()) {
      print_kv("GOT", std::to_string(g.entries.size()) + " entries");
    }
  }

  // Release the full extraction bundle — the largest single allocation in
  // the pipeline — before shutdown. Nothing below reads `full` anymore.
  {
    extractor::extraction_result_t empty{};
    std::swap(full, empty);
  }

  // -------- Result and shutdown --------------------------------------------
  int rc = EXIT_SUCCESS;
  if (failed) {
    print_kv_colored("Result", "FAILED", console::red);
    rc = EXIT_FAILURE;
  } else if (!capa_report.ok()) {
    print_kv_colored("Result", "capa failed", console::red);
    rc = EXIT_FAILURE;
  } else if (r2_result.st == r2::status::not_found ||
             r2_result.st == r2::status::launch_failed ||
             r2_result.st == r2::status::timed_out) {
    print_kv_colored("Result",
                     std::string("radare2 ") + r2::to_string(r2_result.st),
                     console::red);
    rc = EXIT_FAILURE;
  } else {
    print_kv_colored("Result", "success", console::green);
  }

  g_curses_session = nullptr;
  curses_session.complete(rc == EXIT_SUCCESS);

  api.stop();
  if (api.exit_code() != 0) {
    LOG_DEBUG("trace: local API server exited with code {}", api.exit_code());
  }

  return rc;
}
