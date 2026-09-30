#include "curses_ui.hpp"

#include "console.hpp"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <mutex>
#include <sstream>
#include <streambuf>
#include <thread>
#include <vector>

#include <pdcurses.h>

#ifdef _WIN32
  #include <io.h>
  #include <windows.h>
#else
  #include <sys/ioctl.h>
  #include <unistd.h>
#endif

namespace curses_ui {

namespace {

bool terminal_available() {
  const char* mode = std::getenv("STATIC_ANALYZER_CURSES");
  if (mode != nullptr && std::string(mode) == "1") return true;
  if (mode != nullptr && std::string(mode) == "0") return false;
#ifdef _WIN32
  return _isatty(_fileno(stdout)) != 0;
#else
  return isatty(fileno(stdout)) != 0;
#endif
}

std::string strip_ansi(std::string text) {
  std::string clean;
  clean.reserve(text.size());
  bool escape = false;
  for (const char ch : text) {
    if (escape) {
      if (ch == 'm') escape = false;
      continue;
    }
    if (ch == '\x1b') {
      escape = true;
      continue;
    }
    clean.push_back(ch);
  }
  return clean;
}

std::vector<std::string> result_lines(const std::string& text) {
  std::vector<std::string> lines;
  std::string current;
  for (const char ch : strip_ansi(text)) {
    if (ch == '\n') {
      if (!current.empty() && current.back() == '\r') current.pop_back();
      lines.push_back(current);
      current.clear();
    } else {
      current.push_back(ch);
    }
  }
  if (!current.empty()) lines.push_back(current);
  return lines;
}
struct result_section_t {
  std::string title;
  std::vector<std::string> lines;
};

struct export_file_t {
  std::string path;
  std::uintmax_t size = 0;
  bool text = false;
};

bool starts_with(const std::string& text, const std::string& prefix);

std::string capitalize_title(std::string title) {
  bool capitalize_next = true;
  for (char& ch : title) {
    if (capitalize_next && std::isalpha(static_cast<unsigned char>(ch))) {
      ch = static_cast<char>(std::toupper(static_cast<unsigned char>(ch)));
      capitalize_next = false;
    } else if (std::isspace(static_cast<unsigned char>(ch)) ||
               ch == '/' || ch == '-' || ch == '(') {
      capitalize_next = true;
    }
  }
  return title;
}

std::vector<result_section_t> result_sections(const std::vector<std::string>& lines) {
  std::vector<result_section_t> sections;
  result_section_t* current = nullptr;
  auto add_section = [&](const std::string& title) {
    sections.push_back({title, {}});
    current = &sections.back();
  };

  for (const std::string& line : lines) {
    if (starts_with(line, "STATIC ANALYZER")) {
      add_section("Overview");
    } else if (starts_with(line, "[phase ")) {
      const std::size_t close = line.find(']');
      const std::string title = close == std::string::npos
          ? line : line.substr(close + 2);
      add_section(capitalize_title(title.empty() ? "Phase" : title));
    } else if (line == "summary") {
      add_section("Final Summary");
    } else if (current == nullptr) {
      add_section("Report");
    }
    if (current != nullptr) current->lines.push_back(line);
  }
  if (sections.empty()) sections.push_back({"Report", lines});
  return sections;
}



constexpr int kPairHeader = 1;
constexpr int kPairPhase = 2;
constexpr int kPairSection = 3;
constexpr int kPairSuccess = 4;
constexpr int kPairWarning = 5;
constexpr int kPairError = 6;
constexpr int kPairMuted = 7;
constexpr int kPairJsonKey = 8;
constexpr int kPairJsonValue = 9;
constexpr int kPairJsonLiteral = 10;
constexpr int kPairJsonPunctuation = 11;
constexpr int kPairLogo = 12;

// Rows the live progress screen reserves below the logo: the block itself ends at
// top+7, plus the blank spacer, plus the footer at rows-2. The logo may claim
// rows-11 and no more, otherwise the spinner lands on the footer line.
constexpr int kProgressBlockRows = 11;

// Splash logo for the live progress screen and the plain-terminal banner, drawn
// in red. STATIC_ANALYZER_LOGO overrides the path, a missing or empty file just
// means no logo is drawn.
std::filesystem::path logo_path() {
  const char* override_path = std::getenv("STATIC_ANALYZER_LOGO");
  if (override_path != nullptr && *override_path != '\0') return override_path;
#ifdef STATIC_ANALYZER_SOURCE_DIR
  return std::filesystem::path(STATIC_ANALYZER_SOURCE_DIR) / "logos" / "pdcursor.logo";
#else
  return std::filesystem::current_path() / "logos" / "pdcursor.logo";
#endif
}

struct window_size_t {
  int rows = 24;
  int cols = 80;
};

// Size of the console stdout is attached to, in character cells. The 80x24
// fallback is only reached when there is no console to ask, which the PDCurses
// session has already ruled out by the time it draws.
window_size_t console_window_size() {
  window_size_t size;
#ifdef _WIN32
  const HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
  if (out == nullptr || out == INVALID_HANDLE_VALUE) return size;
  CONSOLE_SCREEN_BUFFER_INFO info{};
  if (!GetConsoleScreenBufferInfo(out, &info)) return size;
  size.cols = info.srWindow.Right - info.srWindow.Left + 1;
  size.rows = info.srWindow.Bottom - info.srWindow.Top + 1;
#else
  struct winsize win {};
  if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &win) == 0 && win.ws_col > 0 && win.ws_row > 0) {
    size.cols = win.ws_col;
    size.rows = win.ws_row;
  }
#endif
  return size;
}

#ifdef _WIN32
// Grow the console window until the logo and the progress block under it both
// fit, so the art can be drawn at its own size rather than dropped for want of
// room. How many cells the display and the current console font can actually
// provide varies by machine, so the request is clamped to
// GetLargestConsoleWindowSize() and the caller re-reads the window afterwards
// instead of assuming the request was met.
void enlarge_console(int want_cols, int want_rows) {
  const HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
  if (out == nullptr || out == INVALID_HANDLE_VALUE) return;

  CONSOLE_SCREEN_BUFFER_INFO info{};
  if (!GetConsoleScreenBufferInfo(out, &info)) return;

  const int have_cols = info.srWindow.Right - info.srWindow.Left + 1;
  const int have_rows = info.srWindow.Bottom - info.srWindow.Top + 1;
  if (want_cols <= have_cols && want_rows <= have_rows) return;

  const COORD largest = GetLargestConsoleWindowSize(out);
  const int cols = std::max(have_cols, std::min(want_cols, static_cast<int>(largest.X)));
  const int rows = std::max(have_rows, std::min(want_rows, static_cast<int>(largest.Y)));

  // Shrink to a single cell first. SetConsoleScreenBufferSize refuses a buffer
  // smaller than the window it already has, and SetConsoleWindowInfo refuses a
  // window larger than the display allows, so growing straight from the current
  // size can fail on either count.
  const SMALL_RECT tiny{0, 0, 0, 0};
  SetConsoleWindowInfo(out, TRUE, &tiny);

  // Only ever grow the buffer - its height is the scrollback the user had.
  const COORD buffer{
      static_cast<SHORT>(std::max(cols, static_cast<int>(info.dwSize.X))),
      static_cast<SHORT>(std::max(rows, static_cast<int>(info.dwSize.Y)))};
  SetConsoleScreenBufferSize(out, buffer);

  const SMALL_RECT window{
      0, 0, static_cast<SHORT>(cols - 1), static_cast<SHORT>(rows - 1)};
  SetConsoleWindowInfo(out, TRUE, &window);
}
#endif

bool starts_with(const std::string& text, const std::string& prefix) {
  return text.size() >= prefix.size() &&
         text.compare(0, prefix.size(), prefix) == 0;
}

int json_line_color(const std::string& line) {
  const auto first = line.find_first_not_of(" \t");
  if (first == std::string::npos) return kPairMuted;
  if (line[first] == '{' || line[first] == '}' || line[first] == '[' || line[first] == ']') {
    return kPairJsonPunctuation;
  }
  if (line[first] == '"') {
    const auto colon = line.find(':', first);
    return colon == std::string::npos ? kPairJsonValue : kPairJsonKey;
  }
  if (line.find("true") != std::string::npos || line.find("false") != std::string::npos ||
      line.find("null") != std::string::npos) return kPairJsonLiteral;
  if (line.find_first_of("0123456789-") != std::string::npos) return kPairJsonValue;
  return kPairMuted;
}

struct line_style_t {
  int  pair = kPairMuted;
  bool bold = false;
};

// First integer at or after `from`, or -1 when there is none.
long long number_at(const std::string& line, std::size_t from) {
  while (from < line.size() && !std::isdigit(static_cast<unsigned char>(line[from]))) ++from;
  if (from >= line.size()) return -1;
  long long value = 0;
  while (from < line.size() && std::isdigit(static_cast<unsigned char>(line[from]))) {
    value = value * 10 + (line[from] - '0');
    ++from;
  }
  return value;
}

// The report reaches this file as plain text, so the colouriser has to know the
// vocabulary the reporters emit. The CTI and YARA blocks carry the
// security-relevant signals, so their markers are matched explicitly rather
// than being left to fall through to grey - which is where the whole CTI report
// used to end up, including the [MAL ...] findings.
line_style_t result_style(const std::string& line) {
  if (starts_with(line, "===") || starts_with(line, "STATIC ANALYZER")) return {kPairHeader, true};
  if (starts_with(line, "[phase ")) return {kPairPhase, true};
  if (starts_with(line, "  -- ") || starts_with(line, "-- ")) return {kPairSection, true};

  // CTI verdict tags, and the family lines underneath them.
  if (line.find("[MAL") != std::string::npos) return {kPairError, true};
  if (line.find("[SUS") != std::string::npos) return {kPairWarning, true};
  if (line.find("[BEN") != std::string::npos) return {kPairSuccess, false};
  if (line.find("families:") != std::string::npos) return {kPairError, false};

  // YARA headline: "no matches" is the quiet case, anything else is a hit.
  if (line.find("Matches:") != std::string::npos) {
    return line.find("no matches") != std::string::npos
               ? line_style_t{kPairSuccess, false}
               : line_style_t{kPairError, true};
  }
  const std::size_t loaded_at = line.find("Rules loaded:");
  if (loaded_at != std::string::npos) {
    // "N / M" - green only when every rule file actually loaded.
    const long long loaded = number_at(line, loaded_at);
    const std::size_t slash = line.find('/', loaded_at);
    const long long found = slash == std::string::npos ? -1 : number_at(line, slash);
    return (found < 0 || loaded == found) ? line_style_t{kPairSuccess, false}
                                          : line_style_t{kPairWarning, false};
  }
  if (line.find("Rule files failed:") != std::string::npos) return {kPairError, true};
  const std::size_t tags_at = line.find("Tags:");
  if (tags_at != std::string::npos && tags_at < 8u) return {kPairJsonKey, false};  // cyan

  // Provider statistics rows: the mal / sus columns are the reason to read them.
  if (line.find(" queries ") != std::string::npos && line.find(" mal ") != std::string::npos) {
    const std::size_t mal = line.find(" mal ");
    if (number_at(line, mal + 5) > 0) return {kPairError, true};
    const std::size_t sus = line.find(" sus ");
    if (sus != std::string::npos && number_at(line, sus + 5) > 0) return {kPairWarning, true};
    return {kPairMuted, false};
  }

  // xxd rows: colour the offset, the hex bytes and the ASCII column separately.
  // The leading bullet from print_bullet() is stripped with the rest of the
  // padding, so the offset field starts at the first hex digit.
  if (line.find(':') != std::string::npos) {
    const std::size_t colon = line.find(':');
    bool hexish = colon >= 4;
    for (std::size_t i = 0; hexish && i < colon; ++i) {
      if (!std::isxdigit(static_cast<unsigned char>(line[i]))) hexish = false;
    }
    if (hexish) {
      if (line.find('|') != std::string::npos) return {kPairJsonValue, false};  // green
      return {kPairPhase, false};                                               // yellow
    }
  }

  if (line.find("Result:") != std::string::npos ||
      line.find("Status:               ok") != std::string::npos ||
      line.find("[+]") != std::string::npos) return {kPairSuccess, false};
  if (line.find("[-]") != std::string::npos || line.find("FAILED") != std::string::npos ||
      line.find("failed") != std::string::npos) return {kPairError, false};
  if (line.find("[!]") != std::string::npos || line.find("warning") != std::string::npos ||
      line.find("Warning") != std::string::npos) return {kPairWarning, false};
  return {kPairMuted, false};
}

bool is_heading_line(const std::string& line) {
  return starts_with(line, "  -- ") || starts_with(line, "===");
}

// The content pane drew report lines with "%-*.*s", which truncates anything
// wider than the frame. Every long CTI reason and YARA offset list was silently
// cut off at the pane edge with no way to read the rest. Break on spaces where
// possible, hard-break tokens that cannot fit, and carry the source line's
// leading indentation onto the continuation lines so a wrapped bullet still
// reads as part of its parent.
std::vector<std::string> wrap_lines(const std::vector<std::string>& lines, int width) {
  if (width < 8) width = 8;
  std::vector<std::string> out;
  out.reserve(lines.size());
  for (const std::string& line : lines) {
    if (static_cast<int>(line.size()) <= width) {
      out.push_back(line);
      continue;
    }
    const std::size_t first_text = line.find_first_not_of(' ');
    const std::size_t indent_len = std::min(
        first_text == std::string::npos ? line.size() : first_text,
        static_cast<std::size_t>(std::max(0, width / 4)));
    const std::string indent = line.substr(0, indent_len);
    const std::size_t room = static_cast<std::size_t>(width) - indent.size();
    std::string rest = line.substr(indent_len);
    while (!rest.empty()) {
      std::size_t take = std::min(room, rest.size());
      if (take < rest.size()) {
        const std::size_t space = rest.rfind(' ', take);
        if (space != std::string::npos && space > 0) take = space;
      }
      std::string chunk = rest.substr(0, take);
      while (!chunk.empty() && chunk.back() == ' ') chunk.pop_back();
      rest.erase(0, take);
      while (!rest.empty() && rest.front() == ' ') rest.erase(0, 1);
      out.push_back(indent + chunk);
    }
  }
  return out;
}

std::string spinner_frame(std::size_t tick) {
  static constexpr const char* frames[] = {"|", "/", "-", "\\"};
  return frames[tick % (sizeof(frames) / sizeof(frames[0]))];
}

std::string activity_dots(std::size_t tick) {
  const std::size_t active = (tick / 2) % 4;
  std::string dots = "....";
  dots[active] = '*';
  return dots;
}

std::string elapsed_text(std::chrono::steady_clock::time_point started) {
  const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(
      std::chrono::steady_clock::now() - started).count();
  const long long total = seconds < 0 ? 0 : seconds;
  const long long hours = total / 3600;
  const long long minutes = (total % 3600) / 60;
  const long long secs = total % 60;
  std::ostringstream out;
  out << (hours < 10 ? "0" : "") << hours << ':'
      << (minutes < 10 ? "0" : "") << minutes << ':'
      << (secs < 10 ? "0" : "") << secs;
  return out.str();
}

}  // namespace

logo_t load_logo() {
  logo_t logo;
  std::ifstream input(logo_path(), std::ios::binary);
  if (!input) return logo;
  std::string line;
  while (std::getline(input, line)) {
    if (!line.empty() && line.back() == '\r') line.pop_back();
    logo.lines.push_back(line);
  }
  // Trailing blank lines are padding in the file, not part of the art, and
  // would otherwise push the progress block off the bottom of the screen.
  while (!logo.lines.empty() && logo.lines.back().empty()) logo.lines.pop_back();
  for (const std::string& entry : logo.lines) {
    logo.width = std::max(logo.width, static_cast<int>(entry.size()));
  }
  return logo;
}

void print_logo_banner() {
  // A redirected run is not looking at a terminal, and 76 lines of art in a
  // captured report is noise rather than a banner.
  if (!terminal_available()) return;

  const logo_t logo = load_logo();
  if (logo.lines.empty()) return;

  const window_size_t size = console_window_size();
  const int left = std::max(0, (size.cols - logo.width) / 2);
  const std::string margin(static_cast<std::size_t>(left), ' ');

  std::cout << '\n';
  for (const std::string& line : logo.lines) {
    std::cout << console::paint(console::red, margin + line) << '\n';
  }
  std::cout << std::flush;
}

struct session::impl {
  bool active = false;
  bool finished = false;
  bool success = false;
  std::streambuf* original_cout = nullptr;
  std::ostringstream captured;
  std::thread spinner;
  std::atomic<bool> stop{false};
  std::mutex state_mutex;
  std::size_t total_phases = 0;
  std::size_t current_phase = 0;
  std::atomic<std::size_t> tick{0};
  std::chrono::steady_clock::time_point started_at = std::chrono::steady_clock::now();
  std::string input;
  std::string phase_label = "starting analysis";
  std::string dashboard_path;
  std::vector<std::string> logo_lines;
  int logo_width = 0;
  std::vector<export_file_t> export_files;
  std::size_t selected_export = 0;
  std::size_t export_top = 0;
  // Scroll offset of the Export Manager preview pane. The preview re-reads the
  // file on every render, so the offset has to live here rather than in a
  // buffer, and it is reset whenever a different file is selected.
  std::size_t export_preview_top = 0;

  ~impl() {
    shutdown();
  }

  void initialize_colors() {
    if (start_color() == ERR) return;
    use_default_colors();
    init_pair(kPairHeader, COLOR_CYAN, -1);
    init_pair(kPairPhase, COLOR_YELLOW, -1);
    init_pair(kPairSection, COLOR_MAGENTA, -1);
    init_pair(kPairSuccess, COLOR_GREEN, -1);
    init_pair(kPairWarning, COLOR_YELLOW, -1);
    init_pair(kPairError, COLOR_RED, -1);
    init_pair(kPairMuted, COLOR_WHITE, -1);
    init_pair(kPairJsonKey, COLOR_CYAN, -1);
    init_pair(kPairJsonValue, COLOR_GREEN, -1);
    init_pair(kPairJsonLiteral, COLOR_YELLOW, -1);
    init_pair(kPairJsonPunctuation, COLOR_MAGENTA, -1);
    init_pair(kPairLogo, COLOR_RED, -1);
  }

  void render() {
    if (!active) return;
    std::lock_guard<std::mutex> lock(state_mutex);
    int rows = 24;
    int cols = 80;
    getmaxyx(stdscr, rows, cols);
    erase();

    // The logo is drawn at the size it has in the file - never rescaled, no
    // matter which sheet logos/pdcursor.logo currently holds - from its first
    // line, in red, starting at the top of the pane. begin() has already grown
    // the window so the whole sheet fits, and the progress block is drawn after
    // the art rather than over it.
    //
    // begin() could not get the cells it asked for when the display or the
    // console font is the limit, so the art is clipped to what the pane really
    // has: horizontally to a centred window on the sheet, and vertically to the
    // top of the art so the progress block below always keeps its rows.
    // Clipping is explicit because a %s wider than the pane wraps onto the next
    // line and corrupts the whole layout.
    const int logo_rows = std::max(0, rows - kProgressBlockRows);
    int top = 0;
    if (!logo_lines.empty() && logo_rows > 0) {
      const int logo_height = static_cast<int>(logo_lines.size());
      const int visible = std::min(logo_height, logo_rows);
      const int logo_left = std::max(0, (cols - logo_width) / 2);
      const int clipped = std::min(logo_width, std::max(0, cols - logo_left));
      const int first_col = std::max(0, (logo_width - cols) / 2);
      attron(COLOR_PAIR(kPairLogo) | A_BOLD);
      for (int i = 0; i < visible; ++i) {
        const std::string& line = logo_lines[static_cast<std::size_t>(i)];
        // A short line (a blank spacer, or art narrower than the centre slice)
        // still consumes its row; skipping the write must not reuse the row
        // below, or the next line would be drawn on top of this one.
        if (static_cast<int>(line.size()) > first_col && clipped > 0) {
          mvprintw(top + i, logo_left, "%.*s", clipped, line.c_str() + first_col);
        }
      }
      attroff(COLOR_PAIR(kPairLogo) | A_BOLD);
      // The sheet owns rows [0, visible); one blank spacer, then the block.
      top = visible + 1;
    }

    attron(COLOR_PAIR(kPairHeader) | A_BOLD);
    mvprintw(top, 0, "STATIC ANALYZER");
    attroff(COLOR_PAIR(kPairHeader) | A_BOLD);
    attron(COLOR_PAIR(kPairMuted));
    mvprintw(top + 1, 0, "Input: %.*s", std::max(1, cols - 10), input.c_str());
    mvprintw(top + 2, 0, "Elapsed: %s  Activity: %s",
             elapsed_text(started_at).c_str(), activity_dots(tick.load()).c_str());
    attroff(COLOR_PAIR(kPairMuted));

    const int bar_width = std::max(10, std::min(60, cols - 20));
    const std::size_t done = std::min(current_phase, total_phases);
    const int filled = total_phases == 0
        ? 0
        : static_cast<int>((done * static_cast<std::size_t>(bar_width)) / total_phases);
    std::string bar(static_cast<std::size_t>(filled), '#');
    bar.append(static_cast<std::size_t>(bar_width - filled), '.');
    attron(COLOR_PAIR(kPairPhase));
    mvprintw(top + 3, 0, "Progress: [%s] %zu/%zu", bar.c_str(), done, total_phases);
    attroff(COLOR_PAIR(kPairPhase));
    attron(COLOR_PAIR(kPairSection) | A_BOLD);
    mvprintw(top + 5, 0, "Phase: %.*s", std::max(1, cols - 10), phase_label.c_str());
    attroff(COLOR_PAIR(kPairSection) | A_BOLD);
    attron(COLOR_PAIR(kPairSuccess));
    mvprintw(top + 7, 0, "Analyzing %s", spinner_frame(tick).c_str());
    attroff(COLOR_PAIR(kPairSuccess));
    attron(COLOR_PAIR(kPairMuted));
    mvprintw(rows - 2, 0, "Results will be displayed when analysis completes.");
    attroff(COLOR_PAIR(kPairMuted));
    refresh();
  }

  void load_exports() {
    export_files.clear();
    const std::filesystem::path root = std::filesystem::current_path() / "exports";
    if (!std::filesystem::is_directory(root)) return;
    for (const auto& entry : std::filesystem::recursive_directory_iterator(root)) {
      if (!entry.is_regular_file()) continue;
      std::error_code ec;
      const auto size = entry.file_size(ec);
      if (ec) continue;
      const std::string ext = entry.path().extension().string();
      export_files.push_back({entry.path().string(), size,
          ext == ".json" || ext == ".txt" || ext == ".asm" ||
          ext == ".dot" || ext == ".log" || ext == ".yaml" || ext == ".yml"});
    }
  }

  std::string export_preview(std::size_t index) const {
    if (index >= export_files.size()) return "No export selected.";
    const export_file_t& file = export_files[index];
    if (!file.text) return "Binary artifact — content preview unavailable.";
    std::ifstream input(file.path, std::ios::binary);
    if (!input) return "Unable to read export file.";
    std::string content((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
    constexpr std::size_t kMaxPreview = 128u * 1024u;
    if (content.size() > kMaxPreview) {
      content.resize(kMaxPreview);
      content += "\n\n[preview truncated]";
    }
    return content;
  }

  void open_dashboard() {
    if (dashboard_path.empty() || !std::filesystem::is_regular_file(dashboard_path)) return;
#ifdef _WIN32
    ShellExecuteA(nullptr, "open", dashboard_path.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
#else
    std::system(("xdg-open '" + dashboard_path + "' >/dev/null 2>&1 &").c_str());
#endif
  }

  void show_results() {
    const std::vector<std::string> lines = result_lines(captured.str());
    load_exports();
    auto sections = result_sections(lines);
    result_section_t exports_section;
    exports_section.title = "Export Manager";
    exports_section.lines.reserve(export_files.size());
    for (const auto& file : export_files) {
      exports_section.lines.push_back(file.path + "  [" + std::to_string(file.size) + " bytes]");
    }
    if (!export_files.empty()) sections.push_back(std::move(exports_section));
    std::size_t selected = 0;
    std::vector<std::size_t> section_top(sections.size(), 0);
    // Folded view of every section. A report line wider than the pane used to
    // be clipped, so the cache is rebuilt only when the pane width changes.
    std::vector<std::vector<std::string>> wrapped;
    int wrapped_width = -1;
    // The sidebar and the content pane are separate focus targets. The content
    // pane is entered with Enter/Right and left again with Esc/Left, so Up/Down
    // can move the section list and scroll the text independently.
    bool reading = false;
    // Export Manager adds a third level: the file list sits between the section
    // menu and the preview, so Esc has somewhere to step back to. Without it
    // there was no way out of the file list at all.
    bool browsing = false;
    bool running = true;
    while (running) {
      int rows = 24;
      int cols = 80;
      getmaxyx(stdscr, rows, cols);
      erase();
      const int left_width = std::max(18, std::min(30, cols / 3));
      const int right_x = left_width + 3;
      const int right_width = std::max(10, cols - right_x - 2);
      const int body_rows = std::max(1, rows - 6);
      const int visible = std::max(1, body_rows - 2);
      const std::size_t file_list_rows =
          static_cast<std::size_t>(std::max(3, visible / 2));
      const int file_content_x = right_x + std::max(14, right_width / 2);
      // Wrap and draw at the same width, or a line folded at one width would be
      // clipped again by the other.
      const int body_width = std::max(8, right_width - 4);

      if (body_width != wrapped_width) {
        wrapped_width = body_width;
        wrapped.clear();
        wrapped.reserve(sections.size());
        for (const result_section_t& entry : sections) {
          wrapped.push_back(wrap_lines(entry.lines, wrapped_width));
        }
      }

      attron(COLOR_PAIR(kPairHeader) | A_BOLD);
      mvprintw(0, 0, "STATIC ANALYZER - LAYERED RESULTS");
      attroff(COLOR_PAIR(kPairHeader) | A_BOLD);
      attron(COLOR_PAIR(kPairMuted));
      mvprintw(1, 22, "Sections: %zu | Terminal: %dx%d", sections.size(), cols, rows);
      attroff(COLOR_PAIR(kPairMuted));

      // Layered navigation panel.
      attron(COLOR_PAIR(kPairSection) | A_BOLD);
      mvprintw(3, 2, "SECTIONS");
      attroff(COLOR_PAIR(kPairSection) | A_BOLD);
      for (int row = 0; row < body_rows - 1; ++row) {
        const std::size_t index = static_cast<std::size_t>(row);
        if (index >= sections.size()) break;
        const bool active = index == selected;
        const int color = active ? kPairPhase : kPairMuted;
        attron(COLOR_PAIR(color) | (active ? A_REVERSE | A_BOLD : A_NORMAL));
        mvprintw(4 + row, 1, " %-*.*s ", left_width - 2, left_width - 4,
                 sections[index].title.c_str());
        attroff(COLOR_PAIR(color) | (active ? A_REVERSE | A_BOLD : A_NORMAL));
      }

      // "Back to sections" affordance, shown while the text pane has focus.
      if (reading || browsing) {
        const std::string back = browsing ? " < Esc: sections > "
                                          : " < Esc: files > ";
        attron(COLOR_PAIR(kPairPhase) | A_REVERSE | A_BOLD);
        mvprintw(rows - 3, 1, "%-*.*s", left_width - 1, left_width - 2, back.c_str());
        attroff(COLOR_PAIR(kPairPhase) | A_REVERSE | A_BOLD);
      }

      // Framed layered result table.
      const std::string horizontal(static_cast<std::size_t>(right_width), '-');
      attron(COLOR_PAIR(kPairSection));
      mvprintw(3, right_x, "+%s+", horizontal.c_str());
      mvprintw(rows - 4, right_x, "+%s+", horizontal.c_str());
      for (int row = 4; row < rows - 4; ++row) mvaddch(row, right_x, '|');
      mvaddch(3, right_x + right_width, '+');
      mvaddch(rows - 4, right_x + right_width, '+');
      for (int row = 5; row < rows - 5; ++row) mvaddch(row, right_x + right_width, '|');
      attroff(COLOR_PAIR(kPairSection));

      const result_section_t& section = sections[selected];
      const std::vector<std::string>& body = wrapped[selected];
      const bool filesystem_view = section.title == "Export Manager";
      const bool dashboard_view = section.title == "Dashboard";
      // The open-dashboard action belongs to the Dashboard panel only, so it is
      // not offered from unrelated sections.
      const int action_rows = dashboard_view ? 1 : 0;
      const int content_rows =
          std::max(1, visible - action_rows);
      // Last reachable first-line index. Scrolling stops once the final line sits
      // at the bottom of the pane; clamping to lines-1 instead would let the view
      // run past the end until a single line sat alone at the top.
      const std::size_t scroll_max =
          body.size() > static_cast<std::size_t>(content_rows)
              ? body.size() - static_cast<std::size_t>(content_rows)
              : 0;
      const std::size_t max_top = filesystem_view
          ? (export_files.empty() ? 0 : export_files.size() - 1)
          : scroll_max;
      // Last reachable first-line index of the Export Manager preview. Counts
      // lines on demand: the preview is re-read from disk every render, so no
      // buffer is kept around.
      const int preview_rows_now = std::max(1, rows - 5);
      const auto preview_max = [&]() -> std::size_t {
        std::istringstream counter(export_preview(selected_export));
        std::string tmp;
        std::size_t n = 0;
        while (std::getline(counter, tmp)) ++n;
        return n > static_cast<std::size_t>(preview_rows_now)
                   ? n - static_cast<std::size_t>(preview_rows_now)
                   : 0;
      };
      if (filesystem_view) {
        if (selected_export >= export_files.size()) selected_export = 0;
        if (export_top > max_top) export_top = max_top;
        // Keep the file list scrolled so the selection stays visible.
        if (selected_export < export_top) export_top = selected_export;
        if (selected_export >= export_top + file_list_rows) {
          export_top = selected_export - file_list_rows + 1;
        }
      } else if (section_top[selected] > max_top) {
        section_top[selected] = max_top;
      }

      // "  -- " headings are the section's table of contents. A CTI phase holds
      // hundreds of progress lines before the first finding, so [ and ] step
      // between headings rather than making the reader page there.
      const auto jump_heading = [&](int direction) {
        if (filesystem_view || body.empty()) return;
        if (direction > 0) {
          std::size_t index = std::min(section_top[selected] + 1, body.size() - 1);
          while (index < body.size() && !is_heading_line(body[index])) ++index;
          section_top[selected] = index < body.size() ? std::min(index, max_top) : max_top;
        } else {
          std::size_t index = section_top[selected];
          while (index > 0) {
            --index;
            if (is_heading_line(body[index])) break;
          }
          section_top[selected] = std::min(index, max_top);
        }
      };
      attron(COLOR_PAIR(kPairHeader) | A_BOLD);
      mvprintw(3, right_x + 2, " %-*.*s ", right_width - 4, right_width - 5,
               section.title.c_str());
      attroff(COLOR_PAIR(kPairHeader) | A_BOLD);
      if (dashboard_view) {
        // In-panel button: shown only while the Dashboard panel is selected.
        const std::string label = "[A] Open Dashboard";
        const bool has_file = !dashboard_path.empty() &&
                              std::filesystem::is_regular_file(dashboard_path);
        const int color = has_file ? kPairSuccess : kPairMuted;
        attron(COLOR_PAIR(color) | A_BOLD | A_REVERSE);
        mvprintw(5, right_x + 2, " %-*.*s ", right_width - 4, right_width - 5,
                 label.c_str());
        attroff(COLOR_PAIR(color) | A_BOLD | A_REVERSE);
        attron(COLOR_PAIR(kPairMuted));
        if (has_file) {
          std::string shown = dashboard_path;
          if (static_cast<int>(shown.size()) > right_width - 6)
            shown = shown.substr(shown.size() - static_cast<std::size_t>(right_width - 6));
          mvprintw(6, right_x + 2, "%.*s", right_width - 4, shown.c_str());
        } else {
          mvprintw(6, right_x + 2, "%.*s", right_width - 4,
                   "no dashboard file generated for this run");
        }
        attroff(COLOR_PAIR(kPairMuted));
      }
      if (filesystem_view) {
        const std::size_t list_rows = file_list_rows;
        const int content_x = file_content_x;
        const int content_width = std::max(8, right_x + right_width - content_x - 2);
        attron(COLOR_PAIR(kPairSection));
        for (int row = 5; row < rows - 4; ++row) {
          mvaddch(row, right_x + right_width / 2, '|');
        }
        attroff(COLOR_PAIR(kPairSection));
        attron(COLOR_PAIR(kPairMuted));
        mvprintw(5, right_x + 2, "FILES");
        mvprintw(5, content_x, "CONTENT");
        for (std::size_t row = 0; row < list_rows; ++row) {
          const std::size_t index = export_top + row;
          if (index >= export_files.size()) break;
          const bool active = index == selected_export;
          attron(COLOR_PAIR(active ? kPairPhase : kPairMuted) |
                 (active ? A_REVERSE | A_BOLD : A_NORMAL));
          mvprintw(6 + static_cast<int>(row), right_x + 2, "%-*.*s",
                   right_width / 2 - 4, right_width / 2 - 5,
                   export_files[index].path.c_str());
          attroff(COLOR_PAIR(active ? kPairPhase : kPairMuted) |
                 (active ? A_REVERSE | A_BOLD : A_NORMAL));
        }
        const std::string preview = export_preview(selected_export);
        const bool json_file = selected_export < export_files.size() &&
            export_files[selected_export].path.size() >= 5 &&
            export_files[selected_export].path.substr(
                export_files[selected_export].path.size() - 5) == ".json";
        std::istringstream stream(preview);
        std::string line;
        int row = 6;
        std::size_t skipped = 0;
        const int preview_rows = rows - 5;
        // Total line count, needed for both the scrollbar and the clamp.
        std::size_t preview_total = 0;
        {
          std::istringstream counter(preview);
          std::string tmp;
          while (std::getline(counter, tmp)) ++preview_total;
        }
        const std::size_t preview_max =
            preview_total > static_cast<std::size_t>(preview_rows)
                ? preview_total - static_cast<std::size_t>(preview_rows)
                : 0;
        if (export_preview_top > preview_max) export_preview_top = preview_max;
        // Skip the lines scrolled past before drawing the visible window.
        while (skipped < export_preview_top && std::getline(stream, line)) ++skipped;
        while (row < rows - 4 && std::getline(stream, line)) {
          const int color = json_file ? json_line_color(line) : kPairMuted;
          attron(COLOR_PAIR(color));
          mvprintw(row++, content_x, "%-*.*s", content_width - 1, content_width - 2,
                   line.c_str());
          attroff(COLOR_PAIR(color));
        }
        // Scrollbar for the preview pane.
        if (preview_rows > 0 && preview_max > 0) {
          const int thumb = std::max(1, static_cast<int>(
              (static_cast<long long>(preview_rows) * static_cast<long long>(preview_rows)) /
              static_cast<long long>(preview_total)));
          const int span = preview_rows - thumb;
          const int pos = span <= 0 ? 0 : static_cast<int>(
              (static_cast<long long>(export_preview_top) * static_cast<long long>(span)) /
              static_cast<long long>(preview_max));
          for (int r = 0; r < preview_rows; ++r) {
            const bool on_thumb = r >= pos && r < pos + thumb;
            attron(COLOR_PAIR(on_thumb ? kPairPhase : kPairMuted) |
                   (on_thumb ? A_BOLD : A_NORMAL));
            mvaddch(5 + r, content_x + content_width - 1,
                    on_thumb ? ACS_CKBOARD : ACS_VLINE);
            attroff(COLOR_PAIR(on_thumb ? kPairPhase : kPairMuted) |
                    (on_thumb ? A_BOLD : A_NORMAL));
          }
        }
        attron(COLOR_PAIR(kPairMuted));
        mvprintw(4, content_x, "CONTENT  line %zu/%zu",
                 export_preview_top + 1, preview_total);
        attroff(COLOR_PAIR(kPairMuted));
      } else {
        const int body_top = 5 + (dashboard_view ? 2 : 0);
        for (int row = 0; row < content_rows; ++row) {
          const std::size_t index = section_top[selected] + static_cast<std::size_t>(row);
          if (index >= body.size()) break;
          const line_style_t style = result_style(body[index]);
          attron(COLOR_PAIR(style.pair) | (style.bold ? A_BOLD : A_NORMAL));
          mvprintw(body_top + row, right_x + 2, "%-*.*s", body_width, body_width,
                   body[index].c_str());
          attroff(COLOR_PAIR(style.pair) | (style.bold ? A_BOLD : A_NORMAL));
        }
        // Vertical scrollbar down the right edge of the frame, so the reader can
        // see how far through a long section they are and drag/jump by clicking.
        const int track_top = body_top;
        const int track_rows = content_rows;
        const std::size_t total = body.size();
        if (track_rows > 0 && total > static_cast<std::size_t>(track_rows)) {
          const std::size_t top = section_top[selected];
          const int thumb = std::max(1, static_cast<int>(
              (static_cast<long long>(track_rows) * static_cast<long long>(track_rows)) /
              static_cast<long long>(total)));
          const int span = track_rows - thumb;
          const int pos = span <= 0 ? 0 : static_cast<int>(
              (static_cast<long long>(top) * static_cast<long long>(span)) /
              static_cast<long long>(scroll_max == 0 ? 1 : scroll_max));
          for (int row = 0; row < track_rows; ++row) {
            const bool on_thumb = row >= pos && row < pos + thumb;
            const int color = on_thumb ? kPairPhase : kPairMuted;
            attron(COLOR_PAIR(color) | (on_thumb ? A_BOLD : A_NORMAL));
            mvaddch(track_top + row, right_x + right_width - 1,
                    on_thumb ? ACS_CKBOARD : ACS_VLINE);
            attroff(COLOR_PAIR(color) | (on_thumb ? A_BOLD : A_NORMAL));
          }
        } else if (track_rows > 0) {
          for (int row = 0; row < track_rows; ++row) {
            attron(COLOR_PAIR(kPairMuted));
            mvaddch(track_top + row, right_x + right_width - 1, ACS_VLINE);
            attroff(COLOR_PAIR(kPairMuted));
          }
        }
      }

      attron(COLOR_PAIR(kPairMuted));
      if (reading) {
        mvprintw(rows - 3, 0, "Esc/Left: back | Up/Down: scroll | PgUp/PgDn: page | Home/End: jump | [ ]: heading | q: close");
      } else if (browsing) {
        mvprintw(rows - 3, 0, "Enter: preview | Esc: back to sections | Up/Down: pick file | q: close");
      } else if (filesystem_view) {
        mvprintw(rows - 3, 0, "Down/Enter: open file list | Up: back to sections | q: close");
      } else if (dashboard_view) {
        mvprintw(rows - 3, 0, "Enter: read section | Up/Down: select | PgUp/PgDn: scroll | A: open | q: close");
      } else {
        mvprintw(rows - 3, 0, "Enter: read section | Up/Down: select | PgUp/PgDn: scroll | [ ]: heading | q: close");
      }
      mvprintw(rows - 2, 0, "%s | Selected: %zu/%zu | Lines: %zu | Showing %zu-%zu",
               reading ? "READING" : (browsing ? "FILES" : "SECTIONS"),
               selected + 1, sections.size(), body.size(),
               body.empty() ? 0 : section_top[selected] + 1,
               std::min(body.size(), section_top[selected] + static_cast<std::size_t>(visible)));
      attroff(COLOR_PAIR(kPairMuted));
      refresh();

      const int key = getch();
      const int page = std::max(1, visible - 1);
      switch (key) {
        case KEY_MOUSE: {
          getmouse();
          if (filesystem_view && MOUSE_X_POS >= right_x + 2 &&
              MOUSE_X_POS < file_content_x && MOUSE_Y_POS >= 6 &&
              MOUSE_Y_POS < 6 + static_cast<int>(file_list_rows)) {
            const std::size_t index = export_top +
                static_cast<std::size_t>(MOUSE_Y_POS - 6);
            if (index < export_files.size()) {
              if (index != selected_export) export_preview_top = 0;
              selected_export = index;
            }
            browsing = true;
          } else if (filesystem_view) {
            // Clicking the preview scrollbar jumps through the selected file.
            const int preview_content_w =
                std::max(8, right_x + right_width - file_content_x - 2);
            if (MOUSE_X_POS == file_content_x + preview_content_w - 1 &&
                MOUSE_Y_POS >= 5 && MOUSE_Y_POS < 5 + preview_rows_now) {
              reading = true;
              const std::size_t pmax = preview_max();
              if (pmax > 0) {
                const int frac = MOUSE_Y_POS - 5;
                const int denom = preview_rows_now - 1 < 1 ? 1 : preview_rows_now - 1;
                export_preview_top = static_cast<std::size_t>(
                    (static_cast<long long>(frac) * static_cast<long long>(pmax)) /
                    static_cast<long long>(denom));
                if (export_preview_top > pmax) export_preview_top = pmax;
              }
            }
          } else if (!filesystem_view) {
            // Clicking the sidebar selects that section; clicking the scrollbar
            // jumps the current section to the corresponding offset.
            if (MOUSE_X_POS < right_x && MOUSE_Y_POS >= 4 &&
                MOUSE_Y_POS < 4 + body_rows - 1) {
              const std::size_t index =
                  static_cast<std::size_t>(MOUSE_Y_POS - 4);
              if (index < sections.size()) {
                selected = index;
                reading = false;
              }
            } else if (MOUSE_X_POS == right_x + right_width - 1 && max_top > 0 &&
                       MOUSE_Y_POS >= 5 && MOUSE_Y_POS < 5 + content_rows) {
              reading = true;
              const int track_rows = std::max(1, content_rows);
              const int frac = MOUSE_Y_POS - 5;
              section_top[selected] = static_cast<std::size_t>(
                  (static_cast<long long>(frac) * static_cast<long long>(max_top)) /
                  static_cast<long long>(track_rows - 1 < 1 ? 1 : track_rows - 1));
              if (section_top[selected] > max_top) section_top[selected] = max_top;
            }
          }
          break;
        }
        case KEY_UP:
          if (reading) {
            // Inside the content pane: scroll the text.
            if (filesystem_view) {
              if (export_preview_top > 0) --export_preview_top;
            } else if (section_top[selected] > 0) {
              --section_top[selected];
            }
          } else if (filesystem_view && browsing) {
            if (selected_export > 0) {
              --selected_export;
              export_preview_top = 0;
            }
          } else if (filesystem_view) {
            // On the file list, Up at the top backs out to the section menu.
            browsing = false;
          } else if (selected > 0) {
            --selected;
            section_top[selected] = 0;
          }
          break;
        case KEY_DOWN:
          if (reading) {
            if (filesystem_view) {
              if (export_preview_top < preview_max()) ++export_preview_top;
            } else if (section_top[selected] < max_top) {
              ++section_top[selected];
            }
          } else if (filesystem_view && browsing) {
            if (selected_export + 1 < export_files.size()) {
              ++selected_export;
              export_preview_top = 0;
            }
          } else if (filesystem_view) {
            // Enter the file list from the section menu.
            browsing = true;
          } else if (selected + 1 < sections.size()) {
            ++selected;
            section_top[selected] = 0;
          }
          break;
        case KEY_ENTER:
        case '\r':
        case '\n':
        case KEY_RIGHT:
          // Drill in: section menu -> file list -> preview.
          if (filesystem_view) {
            if (!browsing) browsing = true;
            else reading = true;
          } else {
            reading = true;
          }
          break;
        case 27:      // Esc
        case KEY_LEFT:
        case '\b':    // Backspace
          // Step back out one level: preview -> file list -> section menu.
          if (reading) {
            reading = false;
          } else if (browsing) {
            browsing = false;
          }
          break;
        case KEY_PPAGE:
          if (reading && filesystem_view) {
            export_preview_top = export_preview_top > static_cast<std::size_t>(page)
                ? export_preview_top - static_cast<std::size_t>(page) : 0;
          } else if (reading) {
            section_top[selected] = section_top[selected] > static_cast<std::size_t>(page)
                ? section_top[selected] - static_cast<std::size_t>(page) : 0;
          } else if (filesystem_view) {
            selected_export = selected_export > static_cast<std::size_t>(page)
                ? selected_export - static_cast<std::size_t>(page) : 0;
          } else {
            section_top[selected] = section_top[selected] > static_cast<std::size_t>(page)
                ? section_top[selected] - static_cast<std::size_t>(page) : 0;
          }
          break;
        case KEY_NPAGE:
          if (reading && filesystem_view) {
            export_preview_top = std::min(preview_max(),
                                          export_preview_top + static_cast<std::size_t>(page));
          } else if (reading) {
            section_top[selected] = std::min(max_top, section_top[selected] + static_cast<std::size_t>(page));
          } else if (filesystem_view) {
            selected_export = std::min(max_top, selected_export + static_cast<std::size_t>(page));
          } else {
            section_top[selected] = std::min(max_top, section_top[selected] + static_cast<std::size_t>(page));
          }
          break;
        case KEY_HOME:
          if (reading && filesystem_view) export_preview_top = 0;
          else if (reading) section_top[selected] = 0;
          else if (filesystem_view) selected_export = 0;
          else section_top[selected] = 0;
          break;
        case KEY_END:
          if (reading && filesystem_view) export_preview_top = preview_max();
          else if (reading) section_top[selected] = max_top;
          else if (filesystem_view) selected_export = max_top;
          else section_top[selected] = max_top;
          break;
        case '[':
          jump_heading(-1);
          break;
        case ']':
          jump_heading(1);
          break;
        case 'a':
        case 'A':
          // Only the Dashboard panel exposes the open action.
          if (sections[selected].title == "Dashboard") open_dashboard();
          break;
        case 'q':
        case 'Q':
          running = false;
          break;
        default:
          break;
      }
      if (key == 'q' || key == 'Q') running = false;
    }
  }

  void shutdown() {
    if (!active) return;
    stop.store(true);
    if (spinner.joinable()) spinner.join();
    endwin();
    if (original_cout != nullptr) {
      std::cout.rdbuf(original_cout);
      original_cout = nullptr;
    }
    active = false;
  }
};

session::session() : impl_(std::make_unique<impl>()) {}
session::~session() = default;
session::session(session&&) noexcept = default;
session& session::operator=(session&&) noexcept = default;

bool session::begin(const std::string& input, std::size_t total_phases) {
  if (impl_->active || !terminal_available()) return false;
  if (!initscr()) return false;
  noecho();
  curs_set(0);
  keypad(stdscr, TRUE);
  mousemask(ALL_MOUSE_EVENTS, nullptr);
  impl_->initialize_colors();

  const logo_t logo = load_logo();
  impl_->logo_lines = logo.lines;
  impl_->logo_width = logo.width;
#ifdef _WIN32
  // Grow the window before the first frame so the logo can be drawn whole above
  // the progress block. resize_term() is what makes the new size visible to
  // getmaxyx(), which the spinner thread redraws from.
  if (!impl_->logo_lines.empty()) {
    // +1 for the blank spacer that separates the art from the block, so the
    // request matches what render() actually consumes.
    enlarge_console(impl_->logo_width + 2,
                    static_cast<int>(impl_->logo_lines.size()) + kProgressBlockRows + 1);
    const window_size_t size = console_window_size();
    resize_term(size.rows, size.cols);
  }
#endif

  impl_->active = true;
  impl_->finished = false;
  impl_->success = false;
  impl_->total_phases = total_phases;
  impl_->current_phase = 0;
  impl_->input = input;
  impl_->started_at = std::chrono::steady_clock::now();
  impl_->phase_label = "starting analysis";
  impl_->original_cout = std::cout.rdbuf(impl_->captured.rdbuf());
  impl_->spinner = std::thread([raw = impl_.get()] {
    while (!raw->stop.load()) {
      raw->render();
      std::this_thread::sleep_for(std::chrono::milliseconds(120));
      ++raw->tick;
    }
  });
  impl_->render();
  return true;
}

void session::phase(std::size_t current, const std::string& label) {
  if (!impl_ || !impl_->active) return;
  std::lock_guard<std::mutex> lock(impl_->state_mutex);
  impl_->current_phase = current;
  impl_->phase_label = label;
}

void session::set_total(std::size_t total_phases) {
  if (!impl_ || !impl_->active) return;
  std::lock_guard<std::mutex> lock(impl_->state_mutex);
  impl_->total_phases = total_phases;
}

void session::set_dashboard_path(const std::string& path) {
  if (impl_) impl_->dashboard_path = path;
}

void session::complete(bool success) {
  if (!impl_ || !impl_->active || impl_->finished) return;
  impl_->success = success;
  impl_->finished = true;
  {
    std::lock_guard<std::mutex> lock(impl_->state_mutex);
    impl_->current_phase = impl_->total_phases;
    impl_->phase_label = success ? "analysis complete" : "analysis finished with errors";
  }
  impl_->stop.store(true);
  if (impl_->spinner.joinable()) impl_->spinner.join();
  impl_->render();
  impl_->show_results();
  endwin();
  if (impl_->original_cout != nullptr) {
    std::cout.rdbuf(impl_->original_cout);
    impl_->original_cout = nullptr;
  }
  impl_->active = false;
}

void session::shutdown() {
  if (impl_) impl_->shutdown();
}

bool session::active() const noexcept {
  return impl_ && impl_->active;
}

}  // namespace curses_ui
