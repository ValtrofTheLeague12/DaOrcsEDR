#pragma once

// Debug dumper: writes --debug state dumps to logs/dumps/<run_id>-dumps.log.
//
// The heavy parts (the cpp-dump include, the write_log() redirection and the
// SA_DUMP macro) live in debug_dump_macro.hpp so that files which only need to
// *read* the dump file (the crash handler, main) do not pay for the template
// machinery. Instrumentation sites should include debug_dump_macro.hpp instead.

#include <filesystem>
#include <string>
#include <string_view>

namespace debug_dump {

// Creates <logs_root>/dumps, opens <logs_root>/dumps/<run_id>-dumps.log and
// applies the cpp-dump options (file:line labels, no ANSI colour). After this
// enabled() is true and SA_DUMP(...) starts writing. A failure to open the
// file leaves the dumper disabled rather than aborting the run.
void init(const std::filesystem::path& logs_root, std::string_view run_id,
          bool mirror_stderr);

bool enabled();

// Sink for the cpp_dump::write_log() specialization: redacts, appends and
// flushes one record. Never called when !enabled().
void write(std::string_view record);

// Absolute path of the open dump file ("" when disabled).
std::string log_path();

}  // namespace debug_dump
