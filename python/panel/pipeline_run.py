"""Run one pipeline and stream its output to the Build page.

A build answers "can the binary be produced"; the Tests section answers "does
the code behave" with fixtures and synthetic samples. Neither answers the
operator's oldest question - "what does a run of MY pipeline on MY sample
actually look like, right now" - because until now the panel had no way to
watch the analyzer work. This module is that: it starts `static_analyzer.exe
--no-curses --pipeline <name> <sample>` as a subprocess, captures its combined
stdout/stderr line by line into a job log, and exposes the whole thing to one
poll endpoint.

The rules mirror build.py's job machinery deliberately:

  * exactly one run at a time. The analyzer writes exports/, takes minutes and
    can saturate a core; a queued second run would sit invisible behind a
    spinner and the two would fight over the sample's own checkpoint files.
  * the job log keeps head AND tail with the same truncation arithmetic, so a
    long run's first phases survive on screen.
  * the refusal is a payload, not an exception: "already running", "no
    binary", "no such pipeline", "sample not found" are answers the page
    shows, each with the reason.

One line is NOT inherited from the parent environment: `IA_ARTIFACT_UPLOAD=0`
is forced on every child, exactly as build_checks.py does for its tests. A
button in a browser must never push the evidence bundle to the operator's
cloud account; the Artifacts page remains where upload happens on purpose.

The sample path is validated before anything is done with it, in
python/panel/samples.py: an allowed executable extension, no traversal, no
Win32 name tricks, and a RESOLVED path that stays inside the repo's sample
roots. A packed sample is then refused outright by the gate in start() -
UPX markers or whole-file entropy at the analyzer's own threshold - because
the panel knowing a file is packed and running it anyway is the panel
spending a whole run on unpacking loops whose later phases cannot be
trusted. The refusal is a payload with `code: "sample-packed"`; the only way
past it is the explicit `allow_packed` the page asks for on purpose.

A run may be given a maximum duration. A pipeline analysing a hostile or
pathological sample can wedge - an unpacking loop, a blocking network call, a
pipeline that waits on a service that is down - and the operator watching it
needs a bound they set in advance rather than a Stop button they have to notice
and press. When the duration expires the run is killed and the job records that
it was the clock that ended it, not the analyzer.

Termination is two-stage, and the second stage is the one that cannot be
ignored:

  * `terminate()` first, so the analyzer can flush and exit on its own terms.
    On POSIX that is SIGTERM, which the analyzer handles.
  * after `KILL_GRACE`, `kill()` - `SIGKILL` on POSIX, `TerminateProcess` on
    Windows. Neither can be caught, which is exactly why it is the fallback and
    not the first move.

The panel's Stop button goes through the same two stages; only the trigger
differs (a person versus the clock).
"""

from __future__ import annotations

import logging
import os
import shlex
import subprocess
import threading
import time
from pathlib import Path

from . import config, pe_tools, samples

MAX_LOG_LINES = 4000

# Finished runs are kept this long so a reload still shows the result, exactly
# like the build jobs.
JOB_TTL = 3600.0

# How long a terminated run has to exit on its own before it is killed outright,
# and how often the watchdog re-checks. The grace is what makes terminate()
# worth trying at all: on POSIX it is SIGTERM, which the analyzer's own handler
# turns into a flush, and a kill that arrives during that flush is how a run
# loses the tail of its own log.
KILL_GRACE = 5.0
WATCHDOG_TICK = 0.25

# Bounds on a run's maximum duration. The floor is 10s because a value below it
# cannot be meant: the analyzer needs longer than that to parse a PE and write
# its first phase, so a smaller number would kill every run before it began and
# look like a broken panel rather than a deliberate limit. The ceiling is a day,
# matching MEGA_TIMEOUT's shape - past that it is a runaway, not an analysis.
MIN_DURATION_SEC = 10
MAX_DURATION_SEC = 86400

# Where build.ps1 leaves the analyzer. Derived from config.REPO at call time
# rather than at import: the unit tests point config.REPO at a tmp repo, and a
# path frozen at import would make "is the binary built" check the wrong tree.
# It also stops a stubbed test from ever reaching the real binary.
_DEFAULT_PIPELINE = "default"

_jobs: dict[str, dict] = {}
_procs: dict[str, subprocess.Popen] = {}
_jobs_lock = threading.Lock()
_running: str | None = None

# For tests: the constructor the runner uses, in one indirection that
# monkeypatch can replace without touching the real subprocess module.
_POPEN = subprocess.Popen

# Refusals are payloads the page shows, not exceptions - but an OVERRIDDEN
# packed gate is a decision an operator made about a hostile file, and that
# belongs in the panel's own record, not only on the screen.
log = logging.getLogger("panel.pipeline_run")

# What the packed refusal and the override say about the ANALYZER's own
# tripwire (samples.analyzer_packed_stop reads it from config/analysis.yaml).
# The panel gate is pre-spawn; IA_INTERRUPT_IF_PACKED is mid-run - and with it
# on, overriding the panel gate would only buy a run the analyzer kills at the
# histogram phase. Said out loud rather than left to be discovered.
PACKED_STOP_ON = ("IA_INTERRUPT_IF_PACKED is ON in config/analysis.yaml, so "
                  "even an overridden run is stopped at the histogram phase - "
                  "switch it off on Analysis Configuration to analyse a packed "
                  "sample all the way through")
PACKED_STOP_OFF = ("IA_INTERRUPT_IF_PACKED is off, so an overridden run would "
                   "analyse the sample fully")


def _display_command(argv: list[str]) -> str:
    """The argv as one line a person can read - and paste back - on this host.

    A plain " ".join() is ambiguous the moment a path contains a space: the
    page shows the command as evidence, so it should be the command a shell
    would actually accept, not a string that merely contains the same words.
    """
    return (subprocess.list2cmdline(argv) if os.name == "nt"
            else shlex.join(argv))


def _now() -> float:
    return time.time()


def _prune(now: float) -> None:
    global _running
    for jid in [k for k, v in _jobs.items()
                if v.get("state") != "running" and now - v.get("finished_at", now) > JOB_TTL]:
        del _jobs[jid]
        _procs.pop(jid, None)
    if _running is not None and _running not in _jobs:
        _running = None


def _job_view(job: dict) -> dict:
    keys = ("id", "state", "pipeline", "sample", "started_at", "finished_at",
            "exit_code", "error", "command", "log_line_count", "log_dropped",
            "duration_sec", "deadline", "timed_out", "packed")
    out = {k: job.get(k) for k in keys}
    # `log` is copied in explicitly like build.py does: it is the one field the
    # caller actually wants, and a list that omitted it would be
    # indistinguishable from a running job that just has not spoken yet.
    out["log"] = list(job.get("log") or [])
    return out


def _exe() -> Path:
    return config.REPO / "build-ucrt" / "static_analyzer.exe"


def pipelines_known() -> list[str]:
    """Pipeline names the run may ask for: every yaml on disk plus the built-in.

    `--pipeline default` names the built-in plan, which needs no file - listed
    without one, or every run of the default pipeline would fail validation.
    """
    names = []
    for p in sorted((config.REPO / "pipelines").glob("*.yaml")):
        names.append(p.stem)
    if _DEFAULT_PIPELINE not in names:
        names.insert(0, _DEFAULT_PIPELINE)
    return names


def _validate_pipeline(name: str) -> str | None:
    """The refusal reason, or None when the name is runnable."""
    if not name or name.strip().lower().startswith("--"):
        return f"'{name}' is not a pipeline name"
    path = config.REPO / "pipelines" / f"{name}.yaml"
    if path.is_file() or name == _DEFAULT_PIPELINE:
        return None
    known = ", ".join(pipelines_known())
    return f"no pipeline named '{name}' (known: {known})"


def _validate_duration(seconds: object) -> tuple[int | None, str | None]:
    """A duration in seconds, or (None, reason) when it cannot be used.

    `None` (and an absent key) means no limit, which is the pre-existing
    behaviour and stays the default: a watchdog that switched itself on would
    start killing long-but-legitimate runs whose operator never asked for a
    bound. Explicit only.

    Rejects booleans before integers because `isinstance(True, int)` is True in
    Python, and `{"duration": true}` would otherwise quietly become a one-second
    limit - a JSON mistake that reads as a deliberate choice.
    """
    if seconds is None:
        return None, None
    if isinstance(seconds, bool) or not isinstance(seconds, (int, float)):
        return None, "duration must be a number of seconds"
    if isinstance(seconds, float) and not seconds.is_integer():
        return None, "duration must be a whole number of seconds"
    value = int(seconds)
    if value < MIN_DURATION_SEC:
        return None, (f"duration must be at least {MIN_DURATION_SEC}s - shorter "
                      "than that kills every run before it starts")
    if value > MAX_DURATION_SEC:
        return None, (f"duration must be at most {MAX_DURATION_SEC}s "
                      f"({MAX_DURATION_SEC // 3600}h)")
    return value, None


def _kill(proc: subprocess.Popen, job_id: str) -> None:
    """Two-stage termination, used by both Stop and the duration watchdog.

    Stage one is `terminate()`: SIGTERM on POSIX, which the analyzer handles and
    flushes on. Stage two, after KILL_GRACE, is `kill()` - SIGKILL on POSIX,
    TerminateProcess on Windows. Both are uncatchable, so stage two is only
    reached by a process that ignored stage one.

    Runs in its own thread so the watchdog is not the thing that blocks: a
    terminate() on Windows can wait briefly on the process handle, and blocking
    there would stall the tick that is supposed to enforce the limit.
    """
    try:
        proc.terminate()
    except Exception:  # noqa: BLE001 - an already-dead process is not an error
        return

    deadline = _now() + KILL_GRACE
    while _now() < deadline:
        if proc.poll() is not None:
            return
        time.sleep(WATCHDOG_TICK)

    if proc.poll() is None:
        _append(job_id, f"--- the process did not exit within {KILL_GRACE:.0f}s; killing it")
        try:
            proc.kill()
        except Exception:  # noqa: BLE001
            pass


def start(pipeline: str, sample: str, duration: object = None,
          allow_packed: bool = False) -> dict:
    """Start one pipeline run. Refuses while another is running.

    `duration` is a maximum in seconds, or None for no limit. An unusable value
    is refused here rather than clamped, so the number the page shows back is
    the number that was asked for.

    `allow_packed` is the page's explicit packed override, and defaults off.
    A packed sample is refused with `code: "sample-packed"` before anything is
    spawned; True is a person ticking the override on purpose, and is logged
    as such. The refusal payloads all carry a machine-readable `code` so the
    page switches on the reason rather than on the sentence.

    Returns {ok, ...} rather than raising, mirroring build.start_build(): every
    refusal here is a sentence the page can show, not a stack trace.
    """
    global _running

    with _jobs_lock:
        _prune(_now())
        running = _running
        if running is not None and _jobs.get(running, {}).get("state") == "running":
            return {"ok": False, "code": "already-running",
                    "error": "a pipeline run is already in progress",
                    "detail": f"job {running} is still on the machine; stop it "
                              "or wait for it to finish",
                    "job_id": running}

    if not _exe().is_file():
        return {"ok": False, "code": "no-binary",
                "error": f"{_exe().name} is not built",
                "detail": "build it on this page first; the run cannot start "
                          "without the binary"}

    why = _validate_pipeline(pipeline)
    if why:
        return {"ok": False, "code": "bad-pipeline", "error": why}

    # Validation and existence in one step; the resolved path is what the
    # analyzer is handed, not the string that named it. samples.resolve is the
    # same function the page's inspect endpoint answers from, so a path the
    # page shows as valid is a path this gate accepts.
    full_sample, why = samples.resolve(sample)
    if why:
        return {"ok": False, "code": "bad-sample", "error": why}

    limit, why = _validate_duration(duration)
    if why:
        return {"ok": False, "code": "bad-duration", "error": why}

    # --- the packed gate ---------------------------------------------------
    #
    # Runs before the spawn, not inside the analyzer: the panel already knows
    # the file is packed (it may have packed it itself on the Build page), and
    # a run started anyway is a run spent in unpacking loops whose later
    # phases cannot be trusted. The analyzer's own entropy tripwire
    # (IA_INTERRUPT_IF_PACKED) stays as the independent backstop.
    verdict = pe_tools.pack_verdict(Path(full_sample))
    if verdict.get("error"):
        # An unreadable file is not a verdict. The analyzer will fail to open
        # it with a sentence of its own; the panel does not guess either way.
        log.warning("no packed verdict for %s: %s", full_sample,
                    verdict["error"])
    elif verdict["packed"] and not allow_packed:
        stop_info = samples.analyzer_packed_stop()
        # The override's cost is named BEFORE the operator takes it: with the
        # analyzer's own tripwire on, an overridden run still dies at the
        # histogram phase, so "run anyway" would buy a truncated run.
        analyzer_note = (PACKED_STOP_ON if stop_info["enabled"]
                         else PACKED_STOP_OFF)
        log.warning("refused packed sample %s (%s): %s", full_sample,
                    verdict["method"], verdict["evidence"])
        return {"ok": False, "code": "sample-packed",
                "error": f"{os.path.basename(full_sample)} is packed "
                         f"({verdict['method']})",
                "detail": verdict["evidence"]
                          + " - execution from the panel is prevented; unpack "
                            "it, or repeat with allow_packed=true from the "
                            "page's packed override. " + analyzer_note,
                "packed": verdict,
                "analyzer_packed_stop": stop_info}
    elif verdict["packed"]:
        # The one path where a packed file is deliberately run: a person
        # ticked the override. Loud enough to grep for after the fact.
        log.warning("packed gate OVERRIDDEN for %s by operator request (%s)",
                    full_sample, verdict["evidence"])

    jid = f"r{_now():.0f}{os.getpid() % 1000:03d}"
    argv = [str(_exe()), "--no-curses", "--pipeline", pipeline, full_sample]

    job = {
        "id": jid, "state": "running", "pipeline": pipeline,
        "sample": full_sample, "started_at": round(_now(), 1),
        "finished_at": None, "exit_code": None, "error": None,
        "log": [], "log_line_count": 0, "log_dropped": 0,
        "command": _display_command(argv),
        # The limit as configured, and the clock the watchdog reads. Both are on
        # the job so the page can say "this run had 10s and took 10s" rather
        # than only "it died".
        "duration_sec": limit,
        "deadline": (round(_now() + limit, 1) if limit else None),
        "timed_out": False,
        # The verdict the gate decided on, on the job so the page can label a
        # live run "packed" rather than only refusing a new one.
        "packed": verdict,
    }

    with _jobs_lock:
        _jobs[jid] = job
        _running = jid

    threading.Thread(target=_run, args=(jid, argv), daemon=True,
                     name="pipeline-run").start()
    if limit:
        threading.Thread(target=_watch, args=(jid, limit), daemon=True,
                         name="pipeline-watchdog").start()
    # An overridden run the analyzer will kill mid-flight deserves its warning
    # on the success payload too, not only in the log: the page shows it next
    # to the run it just started.
    warning = None
    if verdict.get("packed") and allow_packed:
        stop_info = samples.analyzer_packed_stop()
        if stop_info["enabled"]:
            warning = PACKED_STOP_ON
    return {"ok": True, "job_id": jid, "command": job["command"],
            "pipeline": pipeline, "duration_sec": limit, "packed": verdict,
            "warning": warning}


def _watch(job_id: str, limit: int) -> None:
    """Kill the run once it has had `limit` seconds.

    Holds no lock while waiting: it sleeps the whole duration in ticks and only
    takes `_jobs_lock` to look. Waiting under the lock would block every log
    append and every poll for the length of the run.
    """
    deadline = _now() + limit
    while _now() < deadline:
        with _jobs_lock:
            job = _jobs.get(job_id)
            if job is None or job["state"] != "running":
                return  # finished, stopped, or pruned on its own
        time.sleep(WATCHDOG_TICK)

    with _jobs_lock:
        job = _jobs.get(job_id)
        if job is None or job["state"] != "running":
            return
        # Marked before the kill so the log line and the state agree even if
        # the kill itself races the process exiting.
        job["timed_out"] = True
        proc = _procs.get(job_id)

    _append(job_id, f"--- {limit}s limit reached; stopping the run")
    if proc is None:
        # The process was never registered: _run has not reached _POPEN yet, or
        # it has already finished. Nothing to signal, and the job's own exit
        # path will set the state.
        return
    _kill(proc, job_id)


def stop(job_id: str) -> dict:
    """Terminate a running run. Already-finished runs say so rather than lying.

    Shares `_kill` with the duration watchdog, so a Stop and a timeout end a run
    the same way: SIGTERM, then SIGKILL if it is ignored. `stopped` records that
    a person asked, which is what lets the page say which of the two happened.
    """
    with _jobs_lock:
        job = _jobs.get(job_id)
        if job is None:
            return {"ok": False, "error": f"no such run: {job_id}"}
        if job["state"] != "running":
            return {"ok": False,
                    "error": f"run {job_id} is {job['state']}, nothing to stop"}
        job["stopped"] = True

    # The signal is sent outside the lock: terminate() can block on a Windows
    # handle briefly, and the whole log path holds the same lock when it appends.
    proc = _procs.get(job_id)
    if proc is None:
        return {"ok": False, "error": "the process handle has not been "
                                      "registered yet; try again in a moment"}
    _append(job_id, "--- stop requested from the panel")
    # _kill blocks for up to KILL_GRACE waiting for the process to exit, so it
    # goes in its own thread: the Stop button returning in 5s would read as a
    # hung panel.
    threading.Thread(target=_kill, args=(proc, job_id), daemon=True,
                     name="pipeline-stop").start()
    return {"ok": True, "job_id": job_id, "state": "stopping"}


def _append(job_id: str, line: str) -> None:
    with _jobs_lock:
        job = _jobs.get(job_id)
        if not job:
            return
        log = job["log"]
        log.append(line)
        # build.py's arithmetic verbatim: keep the head as well as the tail, let
        # log_line_count keep rising past the cap, accumulate the drop count.
        if len(log) > MAX_LOG_LINES:
            dropped = len(log) - MAX_LOG_LINES // 2
            del log[:dropped]
            job["log_dropped"] = job.get("log_dropped", 0) + dropped
        job["log_line_count"] += 1


# args (argv, env_kwargs) land here pretty much verbatim from start(); tests
# call it directly, synchronously, with _POPEN replaced.
def _run(job_id: str, argv: list[str]) -> None:
    global _running
    try:
        env = dict(os.environ)
        # The single most important line in this file. The analysis settings
        # say MEGA_UPLOAD: true, so without this a run started from a browser
        # would push an evidence bundle to the operator's cloud account.
        # Forced, not inherited, exactly as the Tests section does.
        env["IA_ARTIFACT_UPLOAD"] = "0"
        # stdout is a pipe here, so the analyzer's startup logo is suppressed
        # by default. The panel's log IS the operator's view of the run, though,
        # so opt back in - and let a crash add crash.logo to the same log the
        # way it does on a terminal.
        env["STATIC_ANALYZER_FORCE_LOGO"] = "1"

        proc = _POPEN(  # noqa: mypy: indirection for tests
            argv, cwd=str(config.REPO), env=env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding="utf-8", errors="replace", bufsize=1,
        )
        with _jobs_lock:
            _procs[job_id] = proc

        stream = getattr(proc, "stdout", None)
        if stream is not None:
            for line in stream:
                _append(job_id, line.rstrip("\n"))
        code = proc.wait()

        with _jobs_lock:
            job = _jobs.get(job_id)
            if job:
                job["exit_code"] = code
                job["finished_at"] = round(_now(), 1)
                # "done" for exit 0, "failed" for anything else; the analyzer
                # treats unknown input and config errors both as non-zero, and
                # the page's chip maps states the way the build log does.
                #
                # A run killed by the clock or by Stop exits non-zero too, and
                # calling that "static_analyzer exited 1" would blame the
                # analyzer for a decision the panel made. The two markers are
                # set before the signal is sent, so whichever of us gets the
                # lock first, the reason is already recorded. It becomes its own
                # state rather than "failed" because the fault is neither the
                # binary's nor the input's.
                if job.get("timed_out") or job.get("stopped"):
                    job["state"] = "stopped"
                    why = (f"the {job['duration_sec']}s limit was reached and the "
                           "run was stopped" if job.get("timed_out")
                           else "stopped from the panel")
                    job["error"] = why
                else:
                    job["state"] = "done" if code == 0 else "failed"
                    if code != 0:
                        job["error"] = f"static_analyzer exited {code}"
    except Exception as exc:  # noqa: BLE001 - a job must report, not vanish
        with _jobs_lock:
            job = _jobs.get(job_id)
            if job:
                job["state"] = "error"
                job["error"] = f"{type(exc).__name__}: {exc}"
                job["finished_at"] = round(_now(), 1)
    finally:
        with _jobs_lock:
            _procs.pop(job_id, None)
            if _running == job_id:
                _running = None


def job(job_id: str) -> dict | None:
    """One run's state and log, or None if the id is unknown or expired."""
    with _jobs_lock:
        _prune(_now())
        run = _jobs.get(job_id)
        return _job_view(dict(run)) if run else None


def current() -> dict | None:
    """The running run, if any, else the most recent finished one.

    The Build page polls this: the running run keeps the log flowing, and a
    just-finished one keeps its output on screen until something replaces it -
    otherwise a run that ended a second ago would blank the panel.
    """
    with _jobs_lock:
        _prune(_now())
        rid = _running
        if rid:
            run = _jobs[rid]
            if run.get("state") == "running":
                return _job_view(dict(run))
        # Fall through to the newest entry on the store, running or not.
        newest = max(_jobs.values(),
                     key=lambda r: r.get("started_at") or 0) if _jobs else None
        return _job_view(dict(newest)) if newest else None


def status() -> dict:
    """The payload the poll endpoint returns: whether something is live."""
    current_run = current()
    return {"running": current_run is not None and current_run["state"] == "running",
            "job_id": current_run.get("id") if current_run else None}
