// static_analyzer entry point.
//
// This file owns only the process lifecycle - the tracing hooks, logging, the
// local Python API server and the PDCurses session - and the order in which the
// pipeline phases run. The phases themselves live in src/main/ (see
// include/main/pipeline.hpp for the run_* declarations and the context they
// share), and the report vocabulary they print with lives in
// include/main/report.hpp.

#include "console.hpp"
#include "curses_ui.hpp"
#include "local_api.hpp"
#include "logging.hpp"
#include "pipeline.hpp"
#include "process_runner.hpp"
#include "trace.hpp"

#include <chrono>
#include <cstdlib>
#include <iostream>
#include <string>

void trace_process_start() __attribute__((constructor, no_instrument_function));
void trace_process_stop()  __attribute__((destructor,  no_instrument_function));

void trace_process_start() {
  trace_enable();
  const std::string memory = PrintMemoryInfo();
  trace_write_text("[memory] process startup\n");
  trace_write_text(memory);
}

void trace_process_stop() {
  const std::string memory = PrintMemoryInfo();
  trace_write_text("[memory] process shutdown\n");
  trace_write_text(memory);
  trace_disable();
}

int main(int argc, char** argv) {
  console::enable_utf8_output();
  logging::init();
  trace_enable();

  // Keep credentials out of every child process, and do it before the first one
  // exists: the local MalAPI server (py api/server.py) is launched long before
  // the CTI phase runs, and CreateProcess would otherwise hand it the whole
  // environment - including the Bitwarden session token and the CTI API keys.
  // Marking a name is a process-wide policy, so doing it once here covers the
  // whole run, whichever phase goes on to apply a key.
  proc::protect_env_var("BW_SESSION");

  pipeline::context ctx;
  ctx.path = argc > 1 ? argv[1] : "a.exe";

  // Pre-detection placeholder; rescaled by set_total() once the format is known.
  constexpr int kAllPhases = 25;
  curses_ui::session curses_session;
  const bool curses_started = curses_session.begin(
      ctx.path, static_cast<std::size_t>(kAllPhases));
  if (!curses_started) {
    // The same logo the progress screen would have drawn, so both paths open a
    // run the same way. print_logo_banner() is a no-op when stdout is not a
    // terminal, which is the case that also disables the browser.
    curses_ui::print_logo_banner();
    const char* mode = std::getenv("STATIC_ANALYZER_CURSES");
    std::cerr << "[curses] UI not active (STATIC_ANALYZER_CURSES="
              << (mode ? mode : "<unset>") << ").\n";
  }
  ctx.curses = &curses_session;

  // -------- Local Python API server ------------------------------------------
  // server.py (auto-generated) binds 127.0.0.1:60000 (hard-coded in app.run;
  // 8080 is taken by the Oracle listener, 5000 by a stale instance) and
  // opens yaml/malapi/<Name>.yaml relative to its CWD, so it must be
  // launched from python/ — the directory that contains the yaml/ tree.
  local_api::local_api_server api;
  {
    local_api::launch_options api_opts;
    api_opts.python          = "py";                      // 'py' launcher ('python' is not on PATH)
    api_opts.script          = "api/server.py";           // relative to working_dir
    api_opts.working_dir     = "python";                  // contains yaml/malapi/
    api_opts.extra_env       = {"PYTHONUNBUFFERED=1"};
    api_opts.base_url        = "http://127.0.0.1:60000";  // matches app.run(port=60000)
    api_opts.health_path     = "/health";
    api_opts.startup_timeout = std::chrono::milliseconds{10000};

    LOG_INFO("trace: starting local API server: '{} {}' (cwd='{}', poll={}{})",
             api_opts.python, api_opts.script, api_opts.working_dir,
             api_opts.base_url, api_opts.health_path);

    const auto st = api.start(api_opts);

    if (st != local_api::launch_status::ok) {
      LOG_ERROR("trace: local_api start failed: {}", local_api::to_string(st));

      const std::string err = api.std_err();
      if (!err.empty()) {
        LOG_ERROR("trace: local_api stderr:\n{}", err);
      } else {
        LOG_ERROR("trace: local_api produced no stderr. If the status above "
                  "is 'not_found', the interpreter or script path is wrong. "
                  "If it is 'died_early', the script crashed before it could "
                  "bind — run 'cd python && py api/server.py' by hand to "
                  "see the traceback.");
      }
    } else {
      LOG_INFO("trace: local API server ready pid={}", api.pid());
    }
  }
  ctx.api = &api;

  // -------- Pipeline ---------------------------------------------------------
  // The phase order is the whole of the pipeline's control flow; each run_*
  // owns its own "[phase n/total]" header and its own applicability gate.
  pipeline::run_preamble(ctx);
  pipeline::run_hashes(ctx);
  pipeline::run_sections(ctx);
  pipeline::run_generic_sections(ctx);
  pipeline::run_strings_and_ioc(ctx);
  pipeline::run_iat_and_malapi(ctx);
  pipeline::run_got(ctx);
  pipeline::run_byte_histogram(ctx);
  pipeline::run_packer(ctx);
  pipeline::run_opcodes(ctx);
  pipeline::run_debug_symbols(ctx);
  pipeline::run_signature(ctx);
  pipeline::run_capa(ctx);
  pipeline::run_radare2(ctx);
  pipeline::run_graphviz(ctx);
  pipeline::run_xref_asm(ctx);
  pipeline::run_guards(ctx);
  pipeline::run_full_extraction(ctx);
  pipeline::run_xxd(ctx);
  pipeline::run_cminer(ctx);
  pipeline::run_error_recovery(ctx);
  pipeline::run_cti(ctx);
  pipeline::run_export(ctx);
  pipeline::run_dashboard(ctx);
  pipeline::run_sanity(ctx);
  pipeline::run_summary(ctx);

  // -------- Result and shutdown ----------------------------------------------
  int rc = EXIT_SUCCESS;
  if (ctx.failed) {
    print_kv_colored("Result", "FAILED", console::red);
    rc = EXIT_FAILURE;
  } else if (!ctx.capa_report.ok()) {
    print_kv_colored("Result", "capa failed", console::red);
    rc = EXIT_FAILURE;
  } else if (ctx.r2_result.st == r2::status::not_found ||
             ctx.r2_result.st == r2::status::launch_failed ||
             ctx.r2_result.st == r2::status::timed_out) {
    print_kv_colored("Result",
                     std::string("radare2 ") + r2::to_string(ctx.r2_result.st),
                     console::red);
    rc = EXIT_FAILURE;
  } else {
    print_kv_colored("Result", "success", console::green);
  }

  ctx.curses = nullptr;

  // Stop the local API server *before* the results browser, not after.
  // complete() blocks on getch() until the user presses q, so anything placed
  // after it keeps the server alive for the whole browsing session - holding
  // 127.0.0.1:60000 and its memory long after the last phase that needed it
  // (run_cti / run_dashboard) has finished. Nothing below this point does.
  //
  // This is release, not the only cleanup: stop() is idempotent, the destructor
  // calls it again on the exception path, and proc::child puts the interpreter
  // in a job object with JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, so the kernel reaps
  // py.exe and its python.exe child even if this process is killed outright.
  api.stop();
  if (api.exit_code() != 0) {
    LOG_DEBUG("trace: local API server exited with code {}", api.exit_code());
  }

  curses_session.complete(rc == EXIT_SUCCESS);

  return rc;
}
