#include "report.hpp"

#include <algorithm>
#include <cctype>
#include <iomanip>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>

// ---------------------------------------------------------------------------
// Hexdump rendering
// ---------------------------------------------------------------------------

// Renders one row of a hexdump straight from the bytes, in the classic
// "offset  hex bytes  |ascii|" shape. Building the row here rather than
// re-parsing a formatted dump means the zones are known by construction, so
// they can be colored without having to rediscover where one ends and the next
// begins (the old xxd-text parser had to hunt for the pipes, and got it wrong
// whenever a byte happened to render as '|').
void print_hexdump_row(std::uint64_t address,
                       const std::uint8_t* data,
                       std::size_t count,
                       std::size_t bytes_per_row) {
  if (count == 0) return;
  if (bytes_per_row == 0) bytes_per_row = 16;

  std::ostringstream addr_os;
  addr_os << std::hex << std::setfill('0') << std::setw(8) << address;
  std::cout << console::paint(console::cyan, "      * ")
            << console::paint(console::yellow, addr_os.str())
            << "  ";

  // Two groups of eight, separated by the extra space the classic layout uses.
  for (std::size_t i = 0; i < count; ++i) {
    if (i == 8) std::cout << ' ';
    std::ostringstream byte_os;
    byte_os << std::hex << std::setfill('0') << std::setw(2)
            << static_cast<unsigned>(data[i]);
    std::cout << console::paint(console::green, byte_os.str()) << ' ';
  }

  // Pad a short final row so the ASCII column stays aligned with the rows above.
  for (std::size_t i = count; i < bytes_per_row; ++i) {
    std::cout << (i == 8 ? "   " : "  ");
  }

  std::cout << console::paint(console::cyan, "|");
  std::string ascii;
  ascii.reserve(count);
  for (std::size_t i = 0; i < count; ++i) {
    const unsigned char c = data[i];
    ascii += (c >= 0x20 && c <= 0x7e) ? static_cast<char>(c) : '.';
  }
  std::cout << console::paint(console::white, ascii)
            << console::paint(console::cyan, "|") << '\n';
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

// ---------------------------------------------------------------------------
// YARA report
// ---------------------------------------------------------------------------
// The rule scan runs inside the extraction pipeline, so these results were only
// ever reaching the extraction JSON and the dashboard. The terminal and the
// PDCurses results browser showed nothing at all, which made the single most
// security-relevant finding invisible in the primary UI.
void print_yara_report(const yara_scanner::result_t& r) {
  print_section("YARA");
  if (!r.attempted) {
    console::info("YARA was not attempted for this file");
    return;
  }
  if (!r.applicable) {
    console::info("YARA rule scanning only applies to PE files");
    return;
  }
  if (!r.available) {
    print_warn("YARA unavailable: libyara or the rules directory could not be used");
    if (!r.rules_directory.empty()) print_kv("Rules dir", r.rules_directory);
    for (const auto& message : r.errors) print_bullet(message, console::red);
    return;
  }

  // Whether anything matched is the most important fact in this section, so it
  // leads. It used to be printed only after the load/scan bookkeeping, and
  // uncoloured - the one line in the block that has to jump out did not.
  if (r.matches.empty()) {
    print_kv_colored("Matches", "no matches", console::green);
  } else {
    print_kv_colored("Matches",
                     std::to_string(r.rules_matched) + " rule(s) matched",
                     console::red);
  }

  std::ostringstream load;
  load << r.rule_files_loaded << " / " << r.rule_files_found;
  print_kv_colored("Rules loaded", load.str(),
                   r.rule_files_failed == 0 ? console::green : console::yellow);
  if (r.rule_files_failed > 0) {
    print_kv_colored("Rule files failed", std::to_string(r.rule_files_failed),
                     console::red);
  }
  print_kv("Workers", std::to_string(r.worker_threads));
  if (!r.rules_directory.empty()) print_kv("Rules dir", r.rules_directory);
  std::ostringstream scan;
  scan << "exit=" << r.exit_code << "  seconds=" << std::fixed
       << std::setprecision(3) << r.seconds;
  print_kv_colored("Scan", scan.str(), r.scan_ok ? console::green : console::yellow);
  for (const auto& message : r.errors) print_bullet(message, console::yellow);

  if (r.matches.empty()) return;

  // Tags are how a rule pack says what it found ("malware", "apt", "pe"), but
  // most packs put the same few words on nearly every rule. Counted once here,
  // they read as a summary; repeated as a bullet under all 60 rule headers they
  // were just noise, which is where they ended up before.
  std::map<std::string, std::size_t> tag_counts;
  for (const auto& match : r.matches) {
    std::istringstream tag_stream(match.tags);
    std::string tag;
    while (tag_stream >> tag) ++tag_counts[tag];
  }
  if (!tag_counts.empty()) {
    std::vector<std::pair<std::string, std::size_t>> tags(tag_counts.begin(),
                                                          tag_counts.end());
    std::sort(tags.begin(), tags.end(), [](const auto& a, const auto& b) {
      return a.second != b.second ? a.second > b.second : a.first < b.first;
    });
    std::ostringstream line;
    for (std::size_t i = 0; i < tags.size(); ++i) {
      line << (i ? ", " : "") << tags[i].first << " (" << tags[i].second << ")";
    }
    print_kv_colored("Tags", line.str(), console::cyan);
  }

  // Some rule packs match hundreds of rules on a packed binary; the full set is
  // in the extraction JSON.
  constexpr std::size_t kMaxRules = 60;
  std::size_t shown = 0;
  for (const auto& match : r.matches) {
    if (shown >= kMaxRules) {
      print_bullet("... more rules matched (full list is in the extraction JSON)",
                   console::grey);
      break;
    }
    // Tags ride on the rule header instead of taking a bullet line each, so a
    // rule's own tags stay visible without pushing its strings off the screen.
    std::string title = "Rule: " + (match.identifier.empty() ? "(unnamed)" : match.identifier);
    if (!match.tags.empty()) {
      std::istringstream tag_stream(match.tags);
      std::string tag;
      std::string joined;
      while (tag_stream >> tag) joined += (joined.empty() ? "" : ", ") + tag;
      title += "  [" + joined + "]";
    }
    print_section(title);

    std::size_t offsets = 0;
    for (const auto& s : match.strings) offsets += s.offsets.size();
    std::ostringstream shape;
    shape << match.strings.size() << " string(s), " << offsets << " offset(s)";
    print_kv_colored("Strings", shape.str(),
                     offsets == 0 ? console::grey : console::green);

    for (const auto& s : match.strings) {
      std::ostringstream offsets_text;
      std::size_t emitted = 0;
      for (const auto off : s.offsets) {
        if (emitted >= 12) { offsets_text << " ..."; break; }
        if (emitted) offsets_text << ", ";
        offsets_text << "0x" << std::hex << off << std::dec;
        ++emitted;
      }
      print_kv(s.identifier, offsets_text.str());
    }
    ++shown;
  }
}
