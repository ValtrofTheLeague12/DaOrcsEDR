#pragma once

#include <filesystem>
#include <initializer_list>
#include <string>
#include <vector>

// Centred, coloured ASCII banners.
//
// This exists so the startup logo and the CRASH logo resolve their directory the
// same way. They are printed from opposite ends of the program - one from the
// results browser's start-up path, one from inside a fault handler that has
// already lost the ability to rely on anything else being correct - and two
// copies of "where does logos/ live" is how the crash one ends up silently
// finding nothing and printing an empty box.
//
// Deliberately free of curses and of any UI state: the crash path calls this
// while the process is dying, so it may only use the standard library.
namespace banner {

struct art_t {
  std::vector<std::string> lines;
  int width = 0;
  bool empty() const { return lines.empty(); }
};

// The directory logos are loaded from.
//   $STATIC_ANALYZER_LOGO_DIR wins outright (a full path to a file)
//   otherwise <source dir>/logos, or ./logos when built without it
std::filesystem::path logos_dir();

// The full path of a logo, trying `primary` then each of `fallbacks` in order.
// An empty name, a missing file and an empty file are all "not this one", which
// is why the caller passes a chain rather than a single required name.
std::filesystem::path resolve(std::string_view override_env,
                              const char* primary,
                              std::initializer_list<const char*> fallbacks);

// Read a logo file. Returns an empty art_t when there is nothing to read.
art_t load(const std::filesystem::path& path);

// Paint `art` centred horizontally in `colour` on `out`.
//
// `require_terminal` suppresses the banner when the stream is redirected. That
// is right for the startup logo - 30 lines of art in a captured log is noise -
// and wrong for the crash logo, where the whole point is that it is seen.
void print_centred(std::ostream& out, const art_t& art, std::string_view colour,
                   bool require_terminal);

// The crash banner: logos/crash.logo, centred, red, on stderr.
//
// stderr rather than stdout because that is where the rest of the crash report
// goes, and not gated on the stream being a terminal - an operator piping the
// output to a file still gets the banner in it. Best-effort by construction:
// every step is guarded, because the caller is usually a dying process.
void print_crash_banner();

}  // namespace banner