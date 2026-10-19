// phase_die.cpp
//
// Phase: Detect It Easy. Spawns python/die_scan.py through die_runner and
// prints the classified verdict. A missing die-python installation is a skip,
// not a failure (same policy as the optional ML model); every other runner
// status is an error. The parsed result stays on ctx.die_result for the
// export and summary phases.

#include "pipeline.hpp"

#include <chrono>
#include <string>

#include "console.hpp"
#include "die_runner.hpp"
#include "logging.hpp"
#include "pipeline_planner.hpp"

namespace pipeline {

void run_die(context& ctx) {
  phase(ctx, true, "Detect It Easy scan");
  const auto started = report_clock::now();

  die_runner::options opts;
  // Interpreter override: DIE_PYTHON=<path>; the default is the project venv
  // on Windows (where die-python is installed) and python3 elsewhere.
  if (const std::string py = env_or_empty("DIE_PYTHON"); !py.empty())
    opts.python = py;
  int timeout_s = 120;
  if (const std::string raw = env_or_empty("DIE_TIMEOUT"); !raw.empty()) {
    try { timeout_s = std::stoi(raw); } catch (const std::exception&) {}
  }
  if (timeout_s <= 0) timeout_s = 120;
  opts.timeout = std::chrono::seconds(timeout_s);

  const die_runner::result_t res = die_runner::scan_file(ctx.info.filepath, opts);
  ctx.die_result = res;

  using st = die_runner::status;
  if (res.st == st::not_installed) {
    // Optional dependency absent: record the reason so run_summary() can
    // report "skipped (and here is why)" instead of a bare failure.
    ctx.die_skip_reason = res.error;
    print_kv("DIE", "skipped (" + res.error + ")");
  } else if (res.st != st::ok) {
    console::error(res.error);
  } else {
    const auto label = [](const die_runner::entry_t& e) {
      const std::string detail = e.version.empty() ? e.info : e.version;
      return e.name + (detail.empty() ? std::string() : " " + detail);
    };
    if (res.packed) {
      print_kv_colored("Verdict", "PACKED (Detect It Easy)", console::red);
      for (const auto& e : res.packers)
        print_bullet("Packer: " + label(e), console::red);
    } else if (res.unknown_only) {
      print_kv_colored("Verdict",
                       "no packer/compiler matched (DIE reported Unknown)",
                       console::yellow);
    } else {
      print_kv_colored("Verdict", "not packed", console::green);
    }
    for (const auto& e : res.compilers)
      print_bullet("Compiler: " + label(e), console::yellow);
    for (const auto& e : res.linkers)
      print_bullet("Linker: " + label(e), console::yellow);
    for (const auto& e : res.others)
      print_bullet("Other: " + label(e));
    print_kv("DIE",
             std::to_string(res.packers.size()) + " packer(s), " +
             std::to_string(res.compilers.size()) + " compiler(s), " +
             std::to_string(res.linkers.size()) + " linker(s), " +
             std::to_string(res.unknown_count) + " unknown, " +
             std::to_string(res.databases) + " signature db(s)" +
             (res.die_version.empty() ? "" : ", DIE " + res.die_version));
  }
  print_duration(elapsed_ms(started));
}

}  // namespace pipeline
