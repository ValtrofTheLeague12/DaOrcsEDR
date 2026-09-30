#include "report.hpp"

#include <iomanip>
#include <sstream>
#include <string>
#include <string_view>

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
