#pragma once

// cpp-dump glue for the analyzer's debug stack. Include this (not
// debug_dump.hpp) at every SA_DUMP(...) call site.
//
//   SA_DUMP("section", values, "path", redact::file_summary(p));
//
// SA_DUMP evaluates nothing and formats nothing when the run has no --debug,
// so leaving it in hot paths is free. cpp-dump only understands the standard
// types out of the box (arithmetic, string, containers, maps, tuples, enum
// via CPP_DUMP_DEFINE_EXPORT_ENUM); dumping a project struct without its
// export macro prints "unsupported type", which is a signal to pass a
// built-in view (map/vector of strings) instead.

#include "debug_dump.hpp"

#include "cpp-dump.hpp"

// cpp-dump writes to std::clog by default. This explicit specialization
// routes every record through debug_dump::write(), which applies redaction
// and lands it in the dump file. It has to be visible in each translation
// unit that uses cpp_dump(...) before that use, which is why it lives here
// and not in debug_dump.cpp.
namespace cpp_dump {

template <>
inline void write_log(std::string_view output) { ::debug_dump::write(output); }

}  // namespace cpp_dump

// Gated dump: no evaluation, no formatting when --debug was not given.
#define SA_DUMP(...)                                     \
  do {                                                   \
    if (::debug_dump::enabled()) cpp_dump(__VA_ARGS__);  \
  } while (0)
