// test_main.hpp
//
// A test harness, not a framework.
//
// The project has no test target and no gtest, and this file is the reason
// neither is needed to get a first suite running: `unit_tests` is a plain
// executable, the macros below are the entire API, and the exit code is what
// CI reads.
//
// That was a deliberate choice over vendoring a framework. gtest is ~30 files
// and a build-system change; this is one header. The trade is that it does
// less - no fixtures, no parameterised types, no filtering - which for testing
// pure functions is not a real loss.
//
// What it does give, and what the standard library does not, is one place where
// a failure names the expression rather than printing two values and leaving the
// reader to work out which one is wrong.

#pragma once

#include <cctype>
#include <csignal>
#include <cstdio>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "banner.hpp"

// Deliberately NOT including console.hpp.
//
// console.hpp pulls in file_analyzer.hpp and extractor.hpp, which is the whole
// analyzer header graph, into every test translation unit - for two colour
// constants and one function. Including it made a unit test of a path resolver
// depend on headers that have nothing to do with path resolution, which is the
// opposite of what a test should need. The two escapes are written out below
// instead, and they are the same two codes console.hpp defines.
//
// The harness also does not compile banner's console dependency (see
// console_stub.cpp): linking console.cpp would drag in logging -> redact ->
// file_hasher, so a test could not build because a logging sink changed.

namespace ut {

// console::cyan / console::red, copied rather than included. If the theme ever
// changes these, the banners here are wrong until someone notices - which is
// the accepted cost of not making a path-resolution test link the world.
inline constexpr std::string_view kCyan = "\x1b[36m";
inline constexpr std::string_view kRed = "\x1b[31m";

struct Case {
  const char* name;
  void (*fn)();
};

inline std::vector<Case>& registry() {
  static std::vector<Case> cases;
  return cases;
}

// Set by the assertion macros. A case that has already failed keeps failing
// rather than reporting the next thing that is also wrong, which is what makes
// one broken invariant produce one line of output instead of six.
inline bool& current_failed() {
  static bool failed = false;
  return failed;
}

struct Registrar {
  Registrar(const char* name, void (*fn)()) { registry().push_back({name, fn}); }
};

[[noreturn]] inline void fail(const char* file, int line,
                              const std::string& detail) {
  current_failed() = true;
  std::fprintf(stderr, "  FAIL %s:%d\n    %s\n", file, line, detail.c_str());
  // Thrown rather than returned: an assertion deep inside a helper should
  // abandon the case, not carry on asserting on state the failure invalidated.
  throw std::exception();
}

inline std::string show(const std::string& v) { return "\"" + v + "\""; }
inline std::string show(const char* v) { return show(std::string(v ? v : "(null)")); }
inline std::string show(bool v) { return v ? "true" : "false"; }

// The suite's identity logo, printed once when a run starts.
//
// daorcs rather than crash.logo: one banner per run is not a failure, and
// showing the red crash art at the top of a passing run teaches the reader that
// the banner means nothing. The crash banner keeps crash.logo for the opposite
// reason.
inline void print_startup_banner() {
  const std::filesystem::path file =
      banner::resolve("STATIC_ANALYZER_LOGO_DIR", "daorcs.logo",
                      {"pdcursor.logo", "crash.logo"});
  if (file.empty()) return;
  // banner::load(), not a hand-rolled read: it already handles the empty file,
  // the missing file and the trailing-newline cases, and re-implementing those
  // three edge cases here is how the two readers drift.
  const banner::art_t art = banner::load(file);
  if (art.lines.empty()) return;
  // require_terminal = true: art redirected into CI output is noise.
  banner::print_centred(std::cout, art, kCyan, /*require_terminal=*/true);
}

// A crash inside a test is a bug in the test or in the code it exercises, and
// either way the operator needs to know WHICH test died. The last-started name
// is kept in a plain global for exactly that: unwinding is not something to be
// attempted from here.
inline const char*& current_case() {
  static const char* name = "";
  return name;
}

inline void crash_handler(int sig) {
  // Everything below is best-effort by design. The process is already in a state
  // it will not recover from, and anything that allocates or throws here makes
  // the diagnosis worse rather than better.
  std::fprintf(stderr, "\n[unit] crashed with signal %d during: %s\n", sig,
               current_case()[0] ? current_case() : "(before any test)");
  std::fflush(stderr);
  banner::print_crash_banner();
  std::fflush(stderr);
  std::signal(sig, SIG_DFL);
  std::raise(sig);
}

inline void install_crash_handler() {
  for (int sig : {SIGSEGV, SIGABRT, SIGILL, SIGFPE}) {
    std::signal(sig, &crash_handler);
  }
}
inline std::string show(int v) { return std::to_string(v); }
inline std::string show(long v) { return std::to_string(v); }
inline std::string show(long long v) { return std::to_string(v); }
inline std::string show(unsigned v) { return std::to_string(v); }
inline std::string show(unsigned long v) { return std::to_string(v); }
inline std::string show(unsigned long long v) { return std::to_string(v); }
inline std::string show(double v) { return std::to_string(v); }

template <typename A, typename B>
inline void equal(const A& a, const B& b, const char* ea, const char* eb,
                  const char* file, int line) {
  if (!(a == b)) {
    fail(file, line,
         std::string(ea) + " == " + eb + "\n    left  = " + show(a) +
             "\n    right = " + show(b));
  }
}

inline int run(const char* suite) {
  // The startup logo, and the crash logo on the way down.
  //
  // These are the analyzer's own banner functions rather than a copy. They were
  // written for a dying process - every step guarded, standard library only, no
  // reliance on anything else still being correct - and they resolve logos/
  // identically to the way the analyzer does. A second implementation here would
  // be the exact duplication that module's comment warns about, and the one that
  // would drift first.
  //
  // Startup is gated on a terminal, because 30 lines of art in a redirected log
  // is noise. The crash banner deliberately is not, gated on nothing: an
  // operator piping the output to a file still needs to see the run died.
  print_startup_banner();
  install_crash_handler();

  std::printf("== %s ==\n", suite);
  std::fflush(stdout);
  int passed = 0;
  std::vector<std::string> failed;
  for (const Case& c : registry()) {
    current_failed() = false;
    current_case() = c.name;
    std::printf("  ...  %s\n", c.name);
    std::fflush(stdout);
    try {
      c.fn();
    } catch (const std::exception&) {
      // Already reported by fail().
    } catch (...) {
      current_failed() = true;
      std::fprintf(stderr, "  FAIL %s: threw a non-standard exception\n", c.name);
    }
    if (current_failed()) {
      failed.push_back(c.name);
    } else {
      ++passed;
      std::printf("  ok    %s\n", c.name);
    }
    std::fflush(stdout);
  }
  std::printf("\n%d passed, %zu failed\n", passed, failed.size());
  for (const std::string& f : failed) std::printf("  failed: %s\n", f.c_str());
  std::fflush(stdout);
  return failed.empty() ? 0 : 1;
}

}  // namespace ut

#define UT_CONCAT_(a, b) a##b
#define UT_CONCAT(a, b) UT_CONCAT_(a, b)

// Registers at static-init time, so a new test needs no edit anywhere else.
#define TEST(name)                                                     \
  static void name();                                                  \
  static ::ut::Registrar UT_CONCAT(ut_reg_, name)(#name, &name);       \
  static void name()

#define CHECK(cond)                                                    \
  do {                                                                 \
    if (!(cond)) ::ut::fail(__FILE__, __LINE__, "expected: " #cond);   \
  } while (0)

#define CHECK_EQ(a, b) ::ut::equal((a), (b), #a, #b, __FILE__, __LINE__)

#define UT_MAIN(suite)                                                 \
  int main() { return ::ut::run(suite); }