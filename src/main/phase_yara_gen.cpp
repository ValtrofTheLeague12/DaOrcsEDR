// phase_yara_gen.cpp
//
// Phase: YARA rule generation via yarGen-Go.
//
// Opt-in per pipeline, and the reason is in the name: `yara` scans with rules
// you already have, `yara_gen` writes new ones. It is slow - tens of seconds to
// minutes, because yarGen copies the sample aside and scores its strings and
// opcodes against a 794 MB database - and the output is a rule set that an
// analyst then has to review. Neither belongs on a default run.
//
// A missing yarGen-Go checkout is reported as a skip rather than a failure, on
// the same policy as the optional ML model: it is a tool the project does not
// require to analyze anything, so its absence is a fact, not a fault.
//
// The generated .yar lands next to the other artifacts and the parsed result
// stays on ctx.yara_gen_result for the export and summary phases.

#include "pipeline.hpp"

#include <chrono>
#include <filesystem>
#include <string>

#include "console.hpp"
#include "exporter.hpp"
#include "logging.hpp"
#include "pipeline_planner.hpp"
#include "report.hpp"
#include "yara_gen.hpp"

namespace pipeline {

void run_yara_gen(context& ctx) {
  phase(ctx, true, "YARA rule generation");
  const auto started = report_clock::now();

  yara_gen::options opts;

  // Interpreter override, matching the other python-backed runners.
  if (const std::string py = env_or_empty("YARGEN_PYTHON"); !py.empty())
    opts.python = py;

  // yarGen is slow on a large sample, so the default here is deliberately much
  // longer than the other runners' 120s. Measured on the project's own inert
  // fixture it is already ~100s.
  int timeout_s = 600;
  if (const std::string raw = env_or_empty("YARGEN_TIMEOUT"); !raw.empty()) {
    try { timeout_s = std::stoi(raw); } catch (const std::exception&) {}
  }
  if (timeout_s <= 0) timeout_s = 600;
  opts.timeout = std::chrono::seconds(timeout_s);

  if (const std::string author = env_or_empty("YARGEN_AUTHOR"); !author.empty())
    opts.author = author;
  if (const std::string id = env_or_empty("YARGEN_IDENTIFIER"); !id.empty())
    opts.identifier = id;

  // The rule file joins the artifact set, so it is named after the sample like
  // every other output and lands in its own folder.
  //
  // ctx.stem is normally set by the recon phase, but yara_gen is opt-in and
  // nothing requires recon to have run - so it may be empty. Derive it the same
  // way recon does rather than producing "exports/_analysis/..." when it is.
  const std::string stem = ctx.stem.empty()
                               ? exporter::make_stem(ctx.info, ctx.file_hash)
                               : ctx.stem;
  const std::filesystem::path out =
      std::filesystem::path("exports") / (stem + "_analysis") / "yara_gen" /
      (stem + "_generated.yar");
  std::error_code ec;
  std::filesystem::create_directories(out.parent_path(), ec);
  opts.out_path = out.string();

  const yara_gen::result_t res = yara_gen::generate(ctx.info.filepath, opts);
  ctx.yara_gen_result = res;

  using st = yara_gen::status;
  if (res.st == st::yargen_missing) {
    // Optional tool absent: record why, so run_summary() says "skipped (and
    // here is why)" instead of leaving an absent section unexplained.
    ctx.yara_gen_skip_reason = res.error;
    print_kv("YARA gen", "skipped (" + res.error + ")");
  } else if (res.st == st::script_missing) {
    ctx.yara_gen_skip_reason = res.error;
    print_kv("YARA gen", "skipped (" + res.error + ")");
  } else if (res.st != st::ok) {
    // A real failure: yarGen ran and did not deliver rules. Not skippable, and
    // the hints are yarGen's own numbered fix steps, so they are worth showing.
    console::error("rule generation failed: " + res.error);
    for (const std::string& hint : res.hints) console::error(hint);
  } else {
    const int total = res.simple_rules + res.super_rules;
    print_kv_colored("Rules", std::to_string(total) + " generated",
                     console::green);
    print_kv("  file", res.rule_file);
    print_kv("  composition",
             std::to_string(res.simple_rules) + " simple, " +
                 std::to_string(res.super_rules) + " super");
    // Said out loud because it changes how much the rules are worth, and
    // nothing else in the output hints at it.
    if (!res.llm_used) {
      // The reason comes from the wrapper, because the wrapper is what knows
      // whether the config is absent or present-but-keyless, and those want
      // different fixes.
      print_kv("  llm pass", "skipped (" +
          (res.llm_reason.empty() ? std::string("no LLM available")
                                   : res.llm_reason) + ")");
    }
    print_kv("  author", res.author + ", id " + res.identifier);
    print_bullet("generated rules are UNREVIEWED - validate before deploying",
                 console::yellow);
  }

  print_duration(elapsed_ms(started));
}

}  // namespace pipeline