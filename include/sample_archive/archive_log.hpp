#pragma once

// Minimal stderr logger for the sample_archive CLI.
//
// sample_archive is deliberately decoupled from the analyzer's logging
// subsystem (logging::init writes rotating run logs under logs/ and pulls in
// the whole core library). This tool only needs timestamped diagnostics on
// stderr, so it carries a tiny self-contained logger instead.

#include <string>

namespace archive_log {

enum class level { debug, info, warn, error };

void set_verbose(bool on);
bool verbose();

// Always emitted (stderr). Used for the one-line failure reason the CLI
// prints before exiting nonzero.
void error(const std::string& msg);

// Emitted when verbose mode is on (--verbose). Used for progress notes such
// as per-chunk throughput or frame boundaries.
void debug(const std::string& msg);

// General progress notes, also gated on --verbose so default output stays
// clean and script-friendly (stdout keeps the machine-readable summary).
void info(const std::string& msg);

void warn(const std::string& msg);

}  // namespace archive_log
