#include "banner.hpp"

#include "console.hpp"

#include <cstdlib>
#include <fstream>
#include <ostream>
#include <system_error>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <sys/ioctl.h>
#include <unistd.h>
#endif

namespace banner {
namespace {

// Windows asks the console attached to a HANDLE; POSIX asks about a file
// descriptor. Both need a window size to centre in, and both have to cope with
// "there is no console" - a redirected stream, a service, a pipe - which is why
// this returns a default rather than failing.
int console_cols() {
#if defined(_WIN32)
  const HANDLE handle = GetStdHandle(STD_ERROR_HANDLE);
  CONSOLE_SCREEN_BUFFER_INFO info{};
  if (handle == nullptr || handle == INVALID_HANDLE_VALUE) return 0;
  if (!GetConsoleScreenBufferInfo(handle, &info)) return 0;
  return info.srWindow.Right - info.srWindow.Left + 1;
#else
  struct winsize size {};
  if (ioctl(STDERR_FILENO, TIOCGWINSZ, &size) != 0) return 0;
  return size.ws_col;
#endif
}

bool stream_is_terminal() {
#if defined(_WIN32)
  const HANDLE handle = GetStdHandle(STD_ERROR_HANDLE);
  return handle != nullptr && handle != INVALID_HANDLE_VALUE &&
         GetConsoleMode(handle, nullptr) != 0;
#else
  return isatty(STDERR_FILENO) != 0;
#endif
}

}  // namespace

std::filesystem::path logos_dir() {
  if (const char* dir = std::getenv("STATIC_ANALYZER_LOGO_DIR");
      dir != nullptr && *dir != '\0') {
    return dir;
  }
#ifdef STATIC_ANALYZER_SOURCE_DIR
  return std::filesystem::path(STATIC_ANALYZER_SOURCE_DIR) / "logos";
#else
  return std::filesystem::current_path() / "logos";
#endif
}

std::filesystem::path resolve(std::string_view override_env, const char* primary,
                              std::initializer_list<const char*> fallbacks) {
  const char* value = override_env.empty() ? nullptr : std::getenv(override_env.data());
  // getenv keys are NUL-terminated; the string_view callers pass are literals,
  // so the data() is usable as a name only when it is one. Both current callers
  // pass a literal, which is checked here rather than trusted.
  if (value != nullptr && *value != '\0') return value;

  const std::filesystem::path dir = logos_dir();
  std::error_code error;
  auto usable = [&](const char* name) {
    if (name == nullptr) return false;
    const std::filesystem::path candidate = dir / name;
    return std::filesystem::is_regular_file(candidate, error) && !error &&
           std::filesystem::file_size(candidate, error) > 0 && !error;
  };

  if (usable(primary)) return dir / primary;
  for (const char* fallback : fallbacks) {
    if (usable(fallback)) return dir / fallback;
  }
  return dir / (primary != nullptr ? primary : "");
}

art_t load(const std::filesystem::path& path) {
  art_t art;
  std::ifstream input(path, std::ios::binary);
  if (!input) return art;
  std::string line;
  while (std::getline(input, line)) {
    if (!line.empty() && line.back() == '\r') line.pop_back();
    art.lines.push_back(line);
  }
  // Trailing blank lines are padding in the file, not part of the art, and would
  // otherwise push everything after it down the screen.
  while (!art.lines.empty() && art.lines.back().empty()) art.lines.pop_back();
  for (const std::string& entry : art.lines) {
    const int length = static_cast<int>(entry.size());
    if (length > art.width) art.width = length;
  }
  return art;
}

void print_centred(std::ostream& out, const art_t& art, std::string_view colour,
                   bool require_terminal) {
  if (art.empty()) return;
  if (require_terminal && !stream_is_terminal()) return;

  int left = 0;
  if (const int cols = console_cols(); cols > art.width) {
    left = (cols - art.width) / 2;
  }
  const std::string margin(static_cast<std::size_t>(left), ' ');

  out << '\n';
  for (const std::string& line : art.lines) {
    out << console::paint(colour, margin + line) << '\n';
  }
  out << std::flush;
}

void print_crash_banner() {
  // No try/catch: the caller is a fault handler, this body only touches the
  // standard library, and a throw escaping into a signal handler is worse than
  // a missing banner. print_centred() already tolerates a missing file.
  print_centred(std::cerr, load(resolve("STATIC_ANALYZER_CRASH_LOGO", "crash.logo",
                                        {"daorcs.logo", "pdcursor.logo"})),
                console::red, /*require_terminal=*/false);
}

}  // namespace banner