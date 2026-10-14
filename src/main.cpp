// static_analyzer entry point.
//
// This file owns only the process lifecycle - the tracing hooks, logging, the
// local Python API server and the PDCurses session - and the order in which the
// pipeline phases run. The phases themselves live in src/main/ (see
// include/main/pipeline.hpp for the run_* declarations and the context they
// share), and the report vocabulary they print with lives in
// include/main/report.hpp.

#include "console.hpp"
#include "crash_handler.hpp"
#include "curses_ui.hpp"
#include "debug_dump.hpp"
#include "local_api.hpp"
#include "logging.hpp"
#include "mega_runner.hpp"
#include "pipeline.hpp"
#include "pipeline_planner.hpp"
#include "process_runner.hpp"
#include "redact.hpp"
#include "trace.hpp"

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

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

namespace {

void print_usage(std::ostream& os) {
  os << "Usage: static_analyzer [options] [file]\n"
        "\n"
        "  file                   sample to analyze (default: a.exe)\n"
        "  -p, --pipeline <spec>  run a pipeline config instead of the default:\n"
        "                           a bare name like 'extract_strings' (from\n"
        "                           .\\pipelines or next to the executable),\n"
        "                           a .yaml/.yml/.json file path,\n"
        "                           inline JSON like '[\"strings\",\"model\"]',\n"
        "                           or 'default'\n"
        "  --list-phases          list the selectable phases and exit\n"
        "  --list-pipelines       list the available named pipelines and exit\n"
        "      --json             with --list-phases: emit JSON\n"
        "  --debug                write state dumps (SA_DUMP) to\n"
        "                           logs/dumps/<run_id>-dumps.log with file:line\n"
        "                           labels; every registered secret is redacted\n"
        "  --crash-selftest       deliberately dereference null right after the\n"
        "                           handlers are installed, to prove\n"
        "                           logs/crash/<run_id>-<pid>.txt/.dmp are written\n"
        "  artifact actions      configured in config/artifacts.yaml (bundling\n"
        "                           and remote upload are disabled by default)\n"
        "  -h, --help             show this help\n"
        "\n"
        "A pipeline selects which analysis phases run and in what order: YAML\n"
        "with Jenkins-style 'stages', a flat 'phases:' list, or a JSON array.\n"
        "'export' and 'summary' are appended when missing, and prerequisites\n"
        "(e.g. extraction for hexdump) are inserted the same way.\n";
}

}  // namespace

int main(int argc, char** argv) {
  console::enable_utf8_output();

  // Register every credential this process can see before anything is logged
  // or dumped: the registry is read by debug_dump::write(), by the LOG_*
  // choke point in logging.cpp and by the crash report. Seeding reads .env*
  // and the two credential JSON files, so it never logs the values itself.
  redact::seed();

  logging::init();
  trace_enable();

  // Keep credentials out of every child process, and do it before the first one
  // exists: the local MalAPI server (py api/server.py) is launched long before
  // the CTI phase runs, and CreateProcess would otherwise hand it the whole
  // environment - including the Bitwarden session token and the CTI API keys.
  // Marking a name is a process-wide policy, so doing it once here covers the
  // whole run, whichever phase goes on to apply a key.
  proc::protect_env_var("BW_SESSION");

  // -------- CLI ---------------------------------------------------------------
  // Everything before the sample path is an option so a config file can follow
  // the input: `static_analyzer sample.exe --pipeline pipelines/quick.yaml`.
  std::string pipeline_spec;
  std::string input_path;
  bool list_phases = false;
  bool list_pipelines = false;
  bool list_json = false;
  bool debug_dumps = false;
  bool crash_selftest = false;
  for (int i = 1; i < argc; ++i) {
    const std::string arg = argv[i];
    if (arg == "-h" || arg == "--help") {
      print_usage(std::cout);
      return 0;
    } else if (arg == "-p" || arg == "--pipeline") {
      if (i + 1 >= argc) {
        std::cerr << "error: " << arg << " needs a value\n";
        return 2;
      }
      pipeline_spec = argv[++i];
    } else if (arg == "--list-phases") {
      list_phases = true;
    } else if (arg == "--list-pipelines") {
      list_pipelines = true;
    } else if (arg == "--json") {
      list_json = true;
    } else if (arg == "--debug") {
      debug_dumps = true;
    } else if (arg == "--crash-selftest") {
      crash_selftest = true;
    } else if (arg.size() > 1 && arg[0] == '-') {
      std::cerr << "error: unknown option '" << arg << "'\n\n";
      print_usage(std::cerr);
      return 2;
    } else if (input_path.empty()) {
      input_path = arg;
    } else {
      std::cerr << "error: multiple input files ('" << input_path << "', '"
                << arg << "')\n";
      return 2;
    }
  }
  if (list_phases && list_pipelines) {
    std::cerr << "error: --list-phases and --list-pipelines are mutually exclusive\n";
    return 2;
  }
  if (list_phases) {
    pipeline::planner::print_catalog(list_json);
    return 0;
  }
  if (list_pipelines) {
    if (list_json) {
      std::cerr << "error: --json is only valid together with --list-phases\n";
      return 2;
    }
    pipeline::planner::print_pipelines();
    return 0;
  }
  if (list_json) {
    std::cerr << "error: --json is only valid together with --list-phases\n";
    return 2;
  }

  // -------- Pipeline config ---------------------------------------------------
  // Loaded before anything else starts so a bad config fails fast (exit 2) and
  // so cfg.environment can be exported before the child services are launched.
  pipeline::planner::pipeline_config cfg;
  try {
    cfg = pipeline::planner::load(pipeline_spec);
    cfg.artifacts = pipeline::planner::load_artifact_options();
  } catch (const std::exception& e) {
    std::cerr << "pipeline error: " << e.what() << "\n";
    return 2;
  }
  pipeline::planner::apply_environment(cfg);

  // -------- Debug stack ------------------------------------------------------
  // Seeded a second time because apply_environment() may have put new
  // credentials into this process' environment (a pipeline can export them),
  // and the environment scan is what picks those up. The crash handlers are
  // installed regardless of --debug: a report with a stack is useful even when
  // no dumps were requested; the dump file only opens with --debug.
  redact::seed();

  const std::filesystem::path logs_root("logs");
  if (debug_dumps) {
    debug_dump::init(logs_root, logging::current_run_id(), /*mirror_stderr=*/true);
  }
  crash::install(logs_root, logging::current_run_id());

  if (crash_selftest) {
    crash::self_test();  // does not return: the report is the test
  }

  // Lazy service ownership follows the plan: only what the selected phases use
  // is ever launched (the planner inserts no service for the rest).
  const bool want_malapi = pipeline::planner::has(cfg, pipeline::planner::phase_id::iat);
  const bool want_ml     = pipeline::planner::has(cfg, pipeline::planner::phase_id::model);
  const auto run_started = std::chrono::steady_clock::now();

  pipeline::context ctx;
  ctx.path = input_path.empty() ? "a.exe" : input_path;
  crash::set_state("startup", ctx.path);

  // Pre-detection placeholder; rescaled by set_total() once the format is known.
  constexpr int kAllPhases = 26;
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
  if (!want_malapi) {
    LOG_INFO("trace: pipeline has no 'iat' phase; not launching the MalAPI service");
  } else {
    local_api::launch_options api_opts;
#ifdef _WIN32
    api_opts.python          = "py";
#else
    api_opts.python          = "python3";
#endif
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

  // -------- EMBER2024 ML scoring service -------------------------------------
  // ml/serve.py is a third local REST service, launched and owned exactly like
  // the MalAPI server above. Two things are deliberately different:
  //
  //   * It runs from its OWN virtualenv (ml/_t/venv). thrember and its
  //     polars/matplotlib/sklearn tree plus the signify==0.7.1 pin must not leak
  //     into the interpreter that runs python/api/server.py, so the interpreter
  //     is the venv's, not `py`.
  //   * It is OPTIONAL. No model.txt, no venv, no service: the ML phase is
  //     skipped and the run continues. A missing model must never turn a good
  //     static analysis into a failed one.
  //
  // ML_SKIP=1 skips the launch entirely.
  local_api::local_api_server ml_server;
  bool ml_started = false;
  if (!want_ml) {
    LOG_INFO("trace: pipeline has no 'model' phase; not launching the ML service");
  } else {
    const char* skip = std::getenv("ML_SKIP");
    const bool ml_skip = skip != nullptr &&
                         (std::string(skip) == "1" || std::string(skip) == "true");

    // The service binds 127.0.0.1 only, which is what makes it safe to launch
    // unattended: /score takes a filesystem path, so a reachable port would be
    // an arbitrary-file parser. serve.py refuses to bind a non-loopback address
    // without a token, and the host is not configurable here for the same
    // reason - an env var must not be able to expose a file parser.
    const std::string ml_python =
#ifdef _WIN32
        "ml/_t/venv/Scripts/python.exe";
#else
        "ml/_t/venv/bin/python";
#endif

    if (ml_skip) {
      LOG_INFO("trace: ML_SKIP set; not launching the scoring service");
    } else {
      local_api::launch_options ml_opts;
      ml_opts.python      = ml_python;
      ml_opts.script      = "serve.py";   // relative to working_dir
      ml_opts.working_dir = "ml";          // holds serve.py and model.txt
      ml_opts.extra_env   = {"PYTHONUNBUFFERED=1"};
      ml_opts.base_url    = "http://127.0.0.1:60010";  // serve.py's --port default
      ml_opts.health_path = "/health";
      // Loading a 39 MB LightGBM model plus thrember's import tree is slow on a
      // cold start, so the default 10 s budget is too tight here.
      ml_opts.startup_timeout = std::chrono::milliseconds{60000};
      ml_opts.request_timeout_ms = 60000;   // scoring parses the file with pefile
      ml_opts.max_retries        = 1;

      LOG_INFO("trace: starting ML scoring service: '{} {}' (cwd='{}', url={})",
               ml_opts.python, ml_opts.script, ml_opts.working_dir,
               ml_opts.base_url);

      const auto st = ml_server.start(ml_opts);
      if (st != local_api::launch_status::ok) {
        // Informational, not an error: the phase will skip itself.
        LOG_WARN("trace: ML scoring service unavailable ({}). The ML phase will "
                 "be skipped; every other phase is unaffected.",
                 local_api::to_string(st));
        const std::string err = ml_server.std_err();
        if (!err.empty()) {
          LOG_WARN("trace: ML service stderr:\n{}", err);
        } else {
          LOG_WARN("trace: ML service produced no stderr. A 'not_found' status "
                   "means {} is missing - create it with "
                   "'python -m venv ml/_t/venv' and "
                   "'ml/_t/venv/Scripts/pip install -r ml/requirements.txt'. "
                   "A 'died_early' status means the interpreter started but "
                   "thrember/lightgbm failed to import - run "
                   "'ml/_t/venv/Scripts/python ml/serve.py' by hand.",
                   ml_python);
        }
      } else {
        ml_started = true;
        LOG_INFO("trace: ML scoring service ready pid={}", ml_server.pid());
      }
    }
  }
  if (ml_started) ctx.ml_api_server = &ml_server;

  // -------- Pipeline ---------------------------------------------------------
  // The planner owns the phase order: prologue (preamble + hashes), then every
  // phase the config selected, in config order. Each run_* still owns its own
  // "[phase n/total]" header and its own applicability gate.
  //
  // The try/catch exists for the crash stack: a phase that throws is logged
  // with its state and then rethrown, so std::terminate writes a report
  // (stack + active phase) instead of the process dying message-less.
  try {
    pipeline::planner::run_phases(ctx, cfg);
  } catch (const std::exception& e) {
    LOG_CRITICAL("pipeline: unhandled exception while running phases "
                 "(state: {}): {}",
                 crash::state_line(), e.what());
    throw;
  } catch (...) {
    LOG_CRITICAL("pipeline: unhandled unknown exception while running phases "
                 "(state: {})",
                 crash::state_line());
    throw;
  }

  // -------- Human-readable hash ------------------------------------------------
  // main() owns the process, so it reports the read-aloud PGP words next to the
  // exit result too - run_hashes prints them at the top of the run and
  // run_summary in its recap; this is the process-owner's closing line. Empty
  // (so silent) when the hash failed to compute or produced no valid hex.
  const std::string words = hasher::human_words(ctx.file_hash.hash);
  if (!words.empty()) print_kv("Words", words);

  // -------- Result and shutdown ----------------------------------------------
  // capa / radare2 are only run-failing when the pipeline selected them: a
  // ["strings"] run must not exit non-zero because capa never ran.
  int rc = EXIT_SUCCESS;
  if (ctx.failed) {
    print_kv_colored("Result", "FAILED", console::red);
    rc = EXIT_FAILURE;
  } else if (pipeline::planner::has(cfg, pipeline::planner::phase_id::capa) &&
             !ctx.capa_report.ok()) {
    print_kv_colored("Result", "capa failed", console::red);
    rc = EXIT_FAILURE;
  } else if (pipeline::planner::has(cfg, pipeline::planner::phase_id::radare2) &&
             (ctx.r2_result.st == r2::status::not_found ||
              ctx.r2_result.st == r2::status::launch_failed ||
              ctx.r2_result.st == r2::status::timed_out)) {
    print_kv_colored("Result",
                     std::string("radare2 ") + r2::to_string(ctx.r2_result.st),
                     console::red);
    rc = EXIT_FAILURE;
  } else {
    print_kv_colored("Result", "success", console::green);
  }

  // The bundle source must include this run's machine-readable manifest.
  // Write once before sealing, then write again below with the final archive
  // paths and upload outcome included.
  const bool artifact_actions_enabled =
      cfg.artifacts.store_artifact || cfg.artifacts.upload_artifacts;
  if (artifact_actions_enabled) {
    const auto run_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - run_started)
            .count();
    pipeline::planner::write_run_summary(ctx, cfg, rc, run_ms);
    mega_runner::options upload_options;
    upload_options.artifact_name = ctx.stem;
    upload_options.source_directory =
        (std::filesystem::absolute("exports") / (ctx.stem + "_analysis")).string();
    upload_options.output_root = std::filesystem::absolute("exports").string();
    upload_options.uploader_script = cfg.artifacts.uploader_script;
    upload_options.remote_root = cfg.artifacts.remote_root;
    upload_options.timeout_seconds = cfg.artifacts.timeout_seconds;
    upload_options.upload = cfg.artifacts.upload_artifacts;

    LOG_INFO("artifacts: {} evidence bundle for '{}'",
             upload_options.upload ? "building and uploading" : "building local",
             ctx.stem);
    const mega_runner::result upload = mega_runner::run(upload_options);
    if (!upload.standard_output.empty()) std::cout << upload.standard_output;
    if (!upload.standard_error.empty()) std::cerr << upload.standard_error;
    if (!upload.ok) {
      ctx.artifact_action_error = upload.error;
      LOG_ERROR("artifacts: {}", ctx.artifact_action_error);
      std::cerr << "artifacts: " << ctx.artifact_action_error << "\n";
      rc = EXIT_FAILURE;
      print_kv_colored("Result", "FAILED (artifact bundle action)", console::red);
    } else {
      ctx.artifact_bundle_created = upload.bundle_created;
      ctx.artifact_bundle_uploaded = upload.uploaded;
      ctx.exported_artifacts.insert(ctx.exported_artifacts.end(),
                                    upload.artifacts.begin(),
                                    upload.artifacts.end());
    }
  }

  // Machine-readable manifest of the run (phases, artifacts, result) for the
  // API layer; written before the results browser blocks on getch().
  {
    const auto run_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - run_started)
            .count();
    pipeline::planner::write_run_summary(ctx, cfg, rc, run_ms);
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

  // Same reasoning for the ML service: stop it before the results browser, not
  // after. complete() blocks on getch(), and the scoring service holds a 39 MB
  // LightGBM model plus thrember's import tree in memory - worth reclaiming the
  // moment the last phase that needed it is done.
  if (ml_started) {
    ml_server.stop();
    if (ml_server.exit_code() != 0) {
      LOG_DEBUG("trace: ML scoring service exited with code {}",
                ml_server.exit_code());
    }
  }

  curses_session.complete(rc == EXIT_SUCCESS);

  return rc;
}
