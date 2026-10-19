// console_stub.cpp
//
// A link-time stand-in for console.cpp, used ONLY by the unit-test binaries.
//
// Why it exists:
//
//   The test harness prints the suite logo at start and the crash logo on a
//   fault, by calling the analyzer's own banner::print_centred() rather than
//   reimplementing "where logos/ lives" - the duplication that module exists to
//   prevent. print_centred() in turn calls console::paint().
//
//   console::paint() is defined in console.cpp, and console.cpp defines the
//   LOG_* helpers, which call into logging.cpp -> redact.cpp -> file_hasher.cpp
//   and its own dependencies. Compiling that chain into a unit-test binary would
//   mean a test of app_paths' path resolution could not build because a logging
//   sink changed - which is precisely the coupling tests exist to be free of.
//
// So this defines the one function banner.cpp actually calls. The colour
// constants (console::red, console::cyan, ...) are `inline constexpr` in
// console.hpp and need no definition.
//
// It is a stub, not a replacement: nothing here writes to a log, and no test
// asserts on console behaviour. The real console is linked into the analyzer and
// is the thing under test everywhere else.

#include "console.hpp"

#include <string>
#include <string_view>

namespace console {

std::string paint(std::string_view color, std::string_view message) {
  // Wrapped the way the real one does. If banner.cpp ever stops calling paint()
  // and reaches into console internals instead, this file fails to link and
  // says so - which is the correct outcome, not something to paper over.
  std::string out;
  out.reserve(color.size() + message.size() + reset.size());
  out.append(color);
  out.append(message);
  out.append(reset);
  return out;
}

}  // namespace console