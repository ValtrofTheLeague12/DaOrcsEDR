// planner_stubs.cpp
//
// A link-time stand-in for the *runtime* half of the analyzer, used ONLY by
// unit/c++/test_pipeline_planner.cpp.
//
// Why a second stub file when console_stub.cpp already exists:
//
//   pipeline_planner.cpp is one translation unit holding both halves of the
//   planner. The half worth unit-testing - catalog(), from_name(), load(),
//   normalize() - is pure and needs nothing but a config. The other half,
//   run_phases(), dispatches into every run_* phase in the analyzer, plus
//   resume state, the logging sink, redaction and the crash dumper.
//
//   Linking the real run_* would mean compiling all 29 analysis phases, and
//   with them radare2, capa, LIEF and the rest: a test that checks that
//   "graphs" pulls in "radare2" could then fail to build because a disassembly
//   backend changed. That is the coupling tests exist to be free of, and it is
//   the same argument that got console_stub.cpp written.
//
//   redact is the awkward one. pipeline_planner.cpp uses redact::scrub() to
//   keep a secret out of the log, but the real redact.cpp depends on
//   file_hasher.cpp and the rest of the sink chain. Two small functions are
//   not worth that, so they are stubbed here instead of linked - which is why
//   this file exists at all rather than the tests calling only parse_default().
//
// What is stubbed, and what that means:
//
//   Every symbol below is reached only from run_phases(), write_run_summary()
//   and header_count() - the paths that execute phases against a real sample.
//   test_pipeline_planner.cpp calls none of them. They exist here purely so the
//   linker is satisfied, and each returns a harmless empty value.
//
//   This is safe to do silently, because a stub that is never called cannot
//   make a wrong result look right. It would NOT be safe if a future test
//   started exercising run_phases(): that test would be asserting against
//   these no-ops. The header comment on run_phases() in pipeline_planner.hpp
//   should be read with that in mind.
//
// The one genuine risk is signature drift going unnoticed. If a run_* signature
// changes in pipeline.hpp, this file stops compiling - loudly, which is the
// correct outcome and the reason the stubs are hand-declared against the real
// headers rather than generated from a list of names.

#include "console.hpp"
#include "crash_handler.hpp"
#include "debug_dump.hpp"
#include "exporter.hpp"
#include "logging.hpp"
#include "phase_compression.hpp"
#include "pipeline.hpp"
#include "redact.hpp"
#include "report.hpp"
#include "resume.hpp"

#include <filesystem>
#include <string>
#include <string_view>

// ---------------------------------------------------------------------------
// pipeline::run_* - the phase dispatch table
// ---------------------------------------------------------------------------
namespace pipeline {

// Every run_* phase has the same shape: it takes the run context and does the
// work. The macro keeps the 29 definitions honest against pipeline.hpp - a
// mismatch is a compile error here, not a silent link failure later.
#define IA_STUB_RUN(fn) void fn(context&) {}

IA_STUB_RUN(run_preamble)
IA_STUB_RUN(run_hashes)
IA_STUB_RUN(run_sections)
IA_STUB_RUN(run_generic_sections)
IA_STUB_RUN(run_strings_and_ioc)
IA_STUB_RUN(run_iat_and_malapi)
IA_STUB_RUN(run_got)
IA_STUB_RUN(run_byte_histogram)
IA_STUB_RUN(run_packer)
IA_STUB_RUN(run_die)
IA_STUB_RUN(run_opcodes)
IA_STUB_RUN(run_debug_symbols)
IA_STUB_RUN(run_signature)
IA_STUB_RUN(run_capa)
IA_STUB_RUN(run_radare2)
IA_STUB_RUN(run_graphviz)
IA_STUB_RUN(run_xref_asm)
IA_STUB_RUN(run_guards)
IA_STUB_RUN(run_full_extraction)
IA_STUB_RUN(run_hexdump)
IA_STUB_RUN(run_cminer)
IA_STUB_RUN(run_error_recovery)
IA_STUB_RUN(run_cti)
IA_STUB_RUN(run_ml_score)
IA_STUB_RUN(run_yara_gen)
IA_STUB_RUN(run_export)
IA_STUB_RUN(run_dashboard)
IA_STUB_RUN(run_sanity)
IA_STUB_RUN(run_summary)

#undef IA_STUB_RUN

// The one phase with a different shape: compression writes next to the sample
// rather than into exports/, so it takes an output directory and a level.
void run_compression(context&, const std::string&, int) {}

}  // namespace pipeline

// ---------------------------------------------------------------------------
// resume - checkpoint state for --resume
// ---------------------------------------------------------------------------
namespace resume {

void begin(std::string_view, std::string_view, std::string_view, std::string_view,
           std::string_view) {}

void phase_completed(std::string_view) {}

// False, not true: if these stubs were ever reached, "stop requested" would
// mean "yes, give up". Reporting the opposite is the safe direction to fail.
bool stop_requested() { return false; }

std::filesystem::path path_for(std::string_view, const std::filesystem::path&) {
  return {};
}

}  // namespace resume

// ---------------------------------------------------------------------------
// logging - the real sink drags in redact -> file_hasher
// ---------------------------------------------------------------------------
namespace logging {

std::string current_run_id() { return {}; }

namespace internal {

// Disabled: the planner logs a lot of debug detail and a test binary has
// nowhere to put it. Returning false keeps those calls cheap and silent.
bool enabled() { return false; }

spdlog::level::level_enum to_spdlog(level) noexcept {
  return spdlog::level::level_enum::info;
}

void emit_impl(spdlog::level::level_enum, status, const char*, const char*,
               const char*, const char*, int, std::string) {}

}  // namespace internal
}  // namespace logging

// ---------------------------------------------------------------------------
// debug_dump - only writes when a run was started with --debug
// ---------------------------------------------------------------------------
namespace debug_dump {
bool enabled() { return false; }
void write(std::string_view) {}
}  // namespace debug_dump

// ---------------------------------------------------------------------------
// redact
// ---------------------------------------------------------------------------
namespace redact {

// Pass-through, and that is the point worth being explicit about: the real
// scrub() replaces registered secrets with a placeholder, and nothing here is
// registered. Returning the input unchanged keeps the planner's own strings
// readable in a failure message. Nothing prints - logging::internal::enabled()
// is false above - so a real secret could not leak even if one were passed in.
std::string scrub(std::string_view text) { return std::string(text); }

bool is_secret_name(std::string_view) { return false; }

}  // namespace redact

// ---------------------------------------------------------------------------
// crash / exporter / report - reached only from the execution paths
// ---------------------------------------------------------------------------
namespace crash {
// The real handler writes the crash logo and a state file. A test binary that
// provably cannot reach this should not be able to scribble a state file.
void set_state(std::string_view, std::string_view) {}
}  // namespace crash

namespace exporter {
namespace dir {
// write_run_summary() asks for the run's root directory. Returning empty
// rather than a real path means a stray call writes nowhere.
std::filesystem::path run_root(const std::string&) { return {}; }
}  // namespace dir
}  // namespace exporter

// Declared in include/main/report.hpp. A no-op, so a warning during config
// loading does not interleave with the harness's own per-test output.
void print_warn(const std::string&) {}