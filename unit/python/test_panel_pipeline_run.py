"""The pipeline-run watcher's contract, without running the real analyzer.

Everything here runs against a stubbed `_POPEN` (the module's one indirection)
or calls the runner synchronously, so a full suite lands well under a second -
the same discipline the rest of the unit tree keeps after a stubbed-vs-real
test once cost a minute a build.

What the tests actually pin:

  * every refusal names the file or condition it refused - binary missing,
    pipeline unknown, sample missing, run already in progress;
  * the child is started with `--no-curses`, the requested pipeline and the
    absolute sample path, in a repo-rooted cwd;
  * IA_ARTIFACT_UPLOAD=0 is forced, not inherited. This is the one property
    whose failure mode (a browser button uploading evidence to the operator's
    cloud account) is worse than a refusal, so it gets the direct assertion;
  * the log is captured in order, truncates like build.py's arithmetic, and
    the finished job's state/exit code land;
  * stop() terminates the live child and refuses on finished/unknown ids.
"""

from __future__ import annotations

import sys
import threading
import time
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "python"))

from panel.pipeline import pipeline_run as pr  # noqa: E402


# --- the stub ----------------------------------------------------------------

class FakeProc:
    """subprocess.Popen-shaped enough for the runner: lines, wait, terminate."""

    def __init__(self, lines: list[str], code: int):
        self._lines = lines
        self._code = code
        self.stdout = iter(lines)
        self.terminated = False
        self.killed = False
        # poll() is what _kill and the watchdog use to tell "it exited" from
        # "it is ignoring me". None means alive, matching Popen.
        self._poll = None
        self.calls: list[tuple] = []

    def wait(self) -> int:
        return self._code

    def poll(self):
        return self._poll

    def terminate(self) -> None:
        self.terminated = True

    def kill(self) -> None:
        self.killed = True
        self._poll = -9


@pytest.fixture(autouse=True)
def clean_store():
    with pr._jobs_lock:
        pr._jobs.clear()
        pr._procs.clear()
        pr._running = None
    yield
    with pr._jobs_lock:
        pr._jobs.clear()
        pr._procs.clear()
        pr._running = None


@pytest.fixture()
def repo(tmp_path, monkeypatch):
    """A repo-shaped tmp tree: built exe, one pipeline yaml, one sample in
    samples/ - the run gate only accepts paths inside the sample roots."""
    monkeypatch.setattr(pr.config, "REPO", tmp_path)
    (tmp_path / "build-ucrt").mkdir()
    (tmp_path / "build-ucrt" / "static_analyzer.exe").write_text("binary")
    (tmp_path / "pipelines").mkdir()
    (tmp_path / "pipelines" / "quick.yaml").write_text("stages: []\n")
    (tmp_path / "samples").mkdir()
    (tmp_path / "samples" / "sample.exe").write_bytes(b"MZ")
    return tmp_path


class TestRefusals:
    def test_start_refuses_without_the_binary(self, repo, monkeypatch):
        (repo / "build-ucrt" / "static_analyzer.exe").unlink()
        out = pr.start("quick", "samples/sample.exe")
        assert not out["ok"]
        assert "not built" in out["error"]

    def test_start_refuses_an_unknown_pipeline_and_names_the_known_ones(
            self, repo, monkeypatch):
        out = pr.start("nope", "samples/sample.exe")
        assert not out["ok"]
        assert "'nope'" in out["error"]
        assert "quick" in out["error"] and "default" in out["error"]

    def test_start_refuses_a_missing_sample_and_shows_the_resolved_path(
            self, repo, monkeypatch):
        out = pr.start("quick", "samples/missing.exe")
        assert not out["ok"]
        assert out["code"] == "bad-sample"
        assert "missing.exe" in out["error"]
        assert str(repo) in out["error"]

    def test_start_refuses_an_empty_sample(self, repo):
        out = pr.start("quick", "")
        assert not out["ok"]
        assert "no sample given" in out["error"]

    def test_start_refuses_while_a_run_is_in_progress(self, repo):
        # fabricate the running state the guard looks at, exactly the way
        # build.py's zombie guard is tested
        with pr._jobs_lock:
            pr._jobs["r1"] = {"id": "r1", "state": "running"}
            pr._running = "r1"
        second = pr.start("quick", "samples/sample.exe")
        assert not second["ok"]
        assert "already in progress" in second["error"]
        assert second["job_id"] == "r1"

    def test_the_built_in_default_needs_no_yaml_file(self, repo, monkeypatch):
        monkeypatch.setattr(pr, "_POPEN", lambda a, **k: FakeProc([], 0))
        out = pr.start("default", "samples/sample.exe")
        assert out["ok"], out
        assert out["pipeline"] == "default"


class TestTheChildProcess:
    @pytest.fixture()
    def started(self, repo, monkeypatch):
        """A launched run against a stub, returning (proc, job) after the
        thread finishes; start() really spawns the thread via threading.Thread,
        so joins on the module-level thread registry entry."""
        procs = []

        class Tracker(FakeProc):
            def __init__(self):
                super().__init__(["phase: entry\n", "phase: exit\n"], 0)
                procs.append(self)

            def wait(self) -> int:
                return self._code

        args: dict = {}

        def popen(argv, **kwargs):
            args["argv"] = argv
            args.update(kwargs)
            return Tracker()

        monkeypatch.setattr(pr, "_POPEN", popen)
        out = pr.start("quick", "samples/sample.exe")
        assert out["ok"], out
        jid = out["job_id"]

        # the runner runs in a daemon thread; give it a bounded window
        deadline = time.time() + 30
        while time.time() < deadline:
            job = pr.job(jid)
            if job and job["state"] != "running":
                break
            time.sleep(0.02)
        else:
            raise AssertionError("the run thread never finished")

        procs_joined = [t for t in threading.enumerate()
                        if t.name == "pipeline-run"]
        for t in procs_joined:
            t.join(timeout=2)
        return args, pr.job(jid)

    def test_the_child_args_carry_no_curses_pipeline_and_sample(self, started):
        args, job = started
        argv = args["argv"]
        assert argv[1] == "--no-curses"
        assert argv[argv.index("--pipeline") + 1] == "quick"
        assert argv[-1].endswith("sample.exe")
        assert Path(argv[-1]).is_absolute()

    def test_cwd_is_the_repo_root(self, started):
        args, _ = started
        assert Path(args["cwd"]) == pr.config.REPO

    def test_upload_is_forced_off_not_inherited(self, started):
        args, _ = started
        assert args["env"]["IA_ARTIFACT_UPLOAD"] == "0"

    def test_startup_logo_is_forced_into_the_captured_log(self, started):
        # stdout is a pipe, so the analyzer would otherwise drop daorcs.logo.
        # The panel log is the operator's screen; the env flag is what makes the
        # banner appear there without changing the CLI's redirected behaviour.
        args, _ = started
        assert args["env"]["STATIC_ANALYZER_FORCE_LOGO"] == "1"

    def test_output_is_captured_in_order_and_the_job_finishes_clean(self, started):
        _, job = started
        assert job["state"] == "done"
        assert job["exit_code"] == 0
        assert [l.strip() for l in job["log"]] == ["phase: entry", "phase: exit"]
        assert job["error"] is None

    def test_a_failing_exit_marks_the_job_failed_with_the_reason(self, repo,
                                                                 monkeypatch):
        monkeypatch.setattr(pr, "_POPEN",
                            lambda argv, **kw: FakeProc(["boom\n"], 3))
        out = pr.start("quick", "samples/sample.exe")
        assert out["ok"]
        deadline = time.time() + 30
        while time.time() < deadline:
            if pr.job(out["job_id"])["state"] != "running":
                break
            time.sleep(0.02)
        job = pr.job(out["job_id"])
        assert job["state"] == "failed"
        assert "3" in job["error"]


class TestStop:
    def test_stop_terminates_the_live_child_and_records_it(self, repo,
                                                           monkeypatch):
        handler = threading.Event()

        def popen(argv, **kwargs):
            p = FakeProc([], 0)

            def hang():
                handler.wait(timeout=20)
                return 0
            p.wait = hang  # the reader loop would end instantly; make it block
            p.stdout = []
            return p

        monkeypatch.setattr(pr, "_POPEN", popen)
        out = pr.start("quick", "samples/sample.exe")
        assert out["ok"]

        deadline = time.time() + 20
        while time.time() < deadline:
            with pr._jobs_lock:
                if out["job_id"] in pr._procs:
                    break
            time.sleep(0.01)

        stop = pr.stop(out["job_id"])
        assert stop["ok"], stop
        with pr._jobs_lock:
            assert pr._procs[out["job_id"]].terminated, "terminate was not called"
        log = pr.job(out["job_id"])["log"]
        assert any("stop requested" in l for l in log)
        handler.set()

    def test_stop_refuses_an_unknown_or_finished_id(self, repo, monkeypatch):
        monkeypatch.setattr(pr, "_POPEN", lambda a, **k: FakeProc([], 0))
        out = pr.start("quick", "samples/sample.exe")
        # let it finish
        deadline = time.time() + 30
        while time.time() < deadline:
            if pr.job(out["job_id"])["state"] != "running":
                break
            time.sleep(0.02)
        stop = pr.stop(out["job_id"])
        assert not stop["ok"]
        assert "nothing to stop" in stop["error"]
        assert not pr.stop("r000")["ok"], "an unknown id is refused too"


class TestTheLog:
    def test_truncation_keeps_the_head_count_and_the_drop_count(self, monkeypatch):
        monkeypatch.setattr(pr, "MAX_LOG_LINES", 10)
        with pr._jobs_lock:
            pr._jobs["r1"] = {"id": "r1", "log": [], "log_dropped": 0,
                              "log_line_count": 0}
        for i in range(12):
            pr._append("r1", str(i))
        with pr._jobs_lock:
            job = pr._jobs["r1"]
        assert job["log_line_count"] == 12
        # dropped ~ len-5 at the moment of crossing (11-10//2=6): the arithmetic
        # in build.py, asserted so a silent change of it fails here
        assert job["log_dropped"] == 6, "accumulates, never re-assigns"
        assert len(job["log"]) == 6
        assert "10" in job["log"] and "11" in job["log"], "the tail survives"
        assert "0" not in job["log"] or job["log_dropped"] >= 1, "the head went first"

    def test_current_serves_the_finished_run_after_it_ends(self, repo,
                                                           monkeypatch):
        monkeypatch.setattr(pr, "_POPEN",
                            lambda a, **k: FakeProc(["one\n"], 0))
        out = pr.start("default", "samples/sample.exe")
        assert out["ok"]
        deadline = time.time() + 30
        while time.time() < deadline:
            if pr.job(out["job_id"])["state"] != "running":
                break
            time.sleep(0.02)

        latest = pr.current()
        assert latest is not None, "a run that just finished stays on screen"
        assert latest["id"] == out["job_id"]
        assert latest["state"] == "done"
        assert "one" in latest["log"]

    def test_current_is_none_before_anything_ran(self, repo):
        assert pr.current() is None


class TestDurationValidation:
    """The bounds are refused, not clamped: the page echoes back what it asked
    for, so silently adjusting the number would make the panel lie."""

    def test_absent_and_null_both_mean_no_limit(self):
        assert pr._validate_duration(None) == (None, None)

    def test_a_bare_number_is_the_limit(self):
        assert pr._validate_duration(10) == (10, None)
        assert pr._validate_duration(86400) == (86400, None)

    def test_a_whole_float_is_accepted(self):
        assert pr._validate_duration(30.0) == (30, None)

    def test_a_fractional_second_is_refused(self):
        value, why = pr._validate_duration(10.5)
        assert value is None
        assert "whole number" in why

    def test_below_the_floor_is_refused_and_says_why(self):
        value, why = pr._validate_duration(9)
        assert value is None
        assert "at least 10s" in why

    def test_above_the_ceiling_is_refused(self):
        value, why = pr._validate_duration(86401)
        assert value is None
        assert "at most" in why

    def test_a_boolean_is_not_a_duration(self):
        # isinstance(True, int) is True in Python; without this guard
        # {"duration": true} would become a silent one-second limit.
        value, why = pr._validate_duration(True)
        assert value is None
        assert "number" in why

    def test_a_string_is_refused(self):
        value, why = pr._validate_duration("30")
        assert value is None
        assert "number" in why

    def test_start_refuses_an_unusable_duration(self, repo, monkeypatch):
        monkeypatch.setattr(pr, "_POPEN", lambda a, **k: FakeProc([], 0))
        out = pr.start("quick", "samples/sample.exe", 5)
        assert not out["ok"]
        assert "at least 10s" in out["error"]

    def test_a_bounded_start_records_the_limit_and_a_deadline(self, repo,
                                                              monkeypatch):
        monkeypatch.setattr(pr, "_POPEN", lambda a, **k: FakeProc([], 0))
        out = pr.start("quick", "samples/sample.exe", 30)
        assert out["ok"], out
        assert out["duration_sec"] == 30
        view = pr.job(out["job_id"])
        assert view["duration_sec"] == 30
        assert view["deadline"] is not None

    def test_an_unbounded_start_has_no_deadline(self, repo, monkeypatch):
        monkeypatch.setattr(pr, "_POPEN", lambda a, **k: FakeProc([], 0))
        out = pr.start("quick", "samples/sample.exe")
        assert out["ok"], out
        assert out["duration_sec"] is None
        assert pr.job(out["job_id"])["deadline"] is None


class TestTheWatchdog:
    """The clock ends a run, and the job says so rather than blaming the
    analyzer for a non-zero exit it was handed."""

    @pytest.fixture()
    def hanging(self, repo, monkeypatch):
        """A run that never exits on its own; returns (job_id, proc, release)."""
        release = threading.Event()

        def popen(argv, **kwargs):
            p = FakeProc([], 0)
            p.stdout = []
            p._poll = None

            def wait():
                release.wait(timeout=20)
                return p._poll if p._poll is not None else 0
            p.wait = wait
            return p

        monkeypatch.setattr(pr, "_POPEN", popen)
        out = pr.start("quick", "samples/sample.exe", 10)
        assert out["ok"], out
        jid = out["job_id"]
        deadline = time.time() + 20
        while time.time() < deadline:
            with pr._jobs_lock:
                if jid in pr._procs:
                    break
            time.sleep(0.01)
        with pr._jobs_lock:
            proc = pr._procs[jid]
        yield jid, proc, release
        release.set()

    def test_the_limit_terminates_then_kills_and_marks_it_timed_out(self, hanging):
        jid, proc, release = hanging
        # The watchdog reads `limit` from its own thread args and sleeps it, so a
        # test cannot reach the expiry without waiting it. What is asserted here
        # instead is the pair of things the expiry actually does: _kill's
        # two-stage escalation, and the state a timed-out run lands in.
        pr._kill(proc, jid)
        assert proc.terminated, "terminate must be tried before kill"
        assert proc.killed, "a process that ignores terminate is killed"
        assert any("did not exit within" in l for l in pr.job(jid)["log"])

        # A killed child reports a non-zero code; the job must read as stopped,
        # not failed.
        with pr._jobs_lock:
            pr._jobs[jid]["timed_out"] = True
            pr._jobs[jid]["duration_sec"] = 10
        release.set()
        deadline = time.time() + 20
        while time.time() < deadline:
            if pr.job(jid)["state"] != "running":
                break
            time.sleep(0.02)
        view = pr.job(jid)
        assert view["state"] == "stopped", view
        assert view["timed_out"] is True
        assert "limit was reached" in view["error"]

    def test_kill_leaves_a_cooperative_process_alone(self, monkeypatch):
        """If terminate works, kill is never sent - the point of the grace."""
        monkeypatch.setattr(pr, "KILL_GRACE", 0.2)
        monkeypatch.setattr(pr, "WATCHDOG_TICK", 0.02)
        p = FakeProc([], 0)
        p.terminate = lambda: setattr(p, "_poll", 0)  # exits on SIGTERM
        pr._kill(p, "r1")
        assert p.killed is False

    def test_the_watchdog_does_not_fire_on_a_finished_run(self, repo, monkeypatch):
        monkeypatch.setattr(pr, "_POPEN", lambda a, **k: FakeProc(["x\n"], 0))
        out = pr.start("quick", "samples/sample.exe", 10)
        assert out["ok"]
        jid = out["job_id"]
        deadline = time.time() + 30
        while time.time() < deadline:
            if pr.job(jid)["state"] != "running":
                break
            time.sleep(0.02)
        # The watchdog thread is still sleeping its 10s. It must wake to a
        # finished job and do nothing, not flip a finished run to timed_out.
        pr._watch(jid, 0)  # force the post-sleep branch immediately
        view = pr.job(jid)
        assert view["state"] == "done"
        assert view["timed_out"] is False


class TestStoppedIsNotFailed:
    def test_a_stopped_run_reports_stopped_and_a_reason_not_an_exit_code(
            self, repo, monkeypatch):
        """A killed child exits non-zero; the state must not read as a failure."""
        release = threading.Event()

        def popen(argv, **kwargs):
            p = FakeProc([], 0)
            p.stdout = []
            p._poll = None

            def wait():
                release.wait(timeout=20)
                return p._poll if p._poll is not None else 1
            p.wait = wait
            return p

        monkeypatch.setattr(pr, "_POPEN", popen)
        out = pr.start("quick", "samples/sample.exe")
        assert out["ok"]
        jid = out["job_id"]
        deadline = time.time() + 20
        while time.time() < deadline:
            with pr._jobs_lock:
                if jid in pr._procs:
                    break
            time.sleep(0.01)

        stop = pr.stop(jid)
        assert stop["ok"], stop
        with pr._jobs_lock:
            proc = pr._procs[jid]
        proc._poll = 1          # the kill lands; the child reports non-zero
        release.set()

        deadline = time.time() + 20
        while time.time() < deadline:
            job = pr.job(jid)
            if job and job["state"] != "running":
                break
            time.sleep(0.02)
        view = pr.job(jid)
        assert view["state"] == "stopped", view
        assert "stopped from the panel" in view["error"]
        assert view["exit_code"] == 1


class TestSamplePathRules:
    """The box takes a typed path, so the gate is the only thing between a
    browser and the analyzer. Every rule refuses BEFORE a spawn, and the
    refusal names the rule; the resolved-path containment is the one that
    carries the weight, so it gets the direct assertions."""

    def test_a_non_executable_extension_is_refused_and_names_the_allowed_one(
            self, repo):
        (repo / "samples" / "notes.txt").write_text("hi")
        out = pr.start("quick", "samples/notes.txt")
        assert not out["ok"]
        assert out["code"] == "bad-sample"
        assert ".exe" in out["error"] and ".sys" in out["error"]

    def test_traversal_is_refused_even_when_it_would_resolve_inside(self, repo):
        out = pr.start("quick", "samples/../secret.exe")
        assert not out["ok"]
        assert ".." in out["error"]

    def test_an_absolute_path_outside_the_sample_roots_is_refused(
            self, repo, tmp_path_factory):
        outside = tmp_path_factory.mktemp("elsewhere") / "evil.exe"
        outside.write_bytes(b"MZ")
        out = pr.start("quick", str(outside))
        assert not out["ok"]
        assert "sample roots" in out["error"]

    def test_an_absolute_path_INSIDE_a_root_is_accepted(self, repo, monkeypatch):
        monkeypatch.setattr(pr, "_POPEN", lambda a, **k: FakeProc([], 0))
        inside = repo / "samples" / "sample.exe"
        out = pr.start("quick", str(inside))
        assert out["ok"], out

    def test_an_ntfs_stream_is_refused(self, repo):
        out = pr.start("quick", "samples/sample.exe:zone")
        assert not out["ok"]
        assert "alternate data streams" in out["error"]

    def test_a_trailing_dot_is_refused_because_windows_strips_it(self, repo):
        out = pr.start("quick", "samples/new.exe.")
        assert not out["ok"]
        assert "dot or a space" in out["error"]

    def test_control_characters_are_refused(self, repo):
        out = pr.start("quick", "samples/bad\x01.exe")
        assert not out["ok"]
        assert "control characters" in out["error"]

    def test_a_reserved_device_name_is_refused(self, repo):
        out = pr.start("quick", "samples/CON.exe")
        assert not out["ok"]
        assert "reserved" in out["error"]


class TestPackedGate:
    """A packed sample is refused BEFORE anything is spawned - the panel
    knowing a file is packed and running it anyway is a run spent in
    unpacking loops - and the override is explicit, recorded, and honest
    about what the analyzer's own tripwire will do to the overridden run."""

    # UPX leaves its own section names in the file; finding one is a fact.
    UPX_BYTES = b"MZ" + b"\0" * 200 + b"UPX0" + b"\0" * 64 + b"UPX1"

    @pytest.fixture()
    def packed(self, repo):
        (repo / "samples" / "packed.exe").write_bytes(self.UPX_BYTES)
        return repo

    def test_a_packed_sample_is_refused_and_nothing_is_spawned(self, packed,
                                                               monkeypatch):
        spawned = []
        monkeypatch.setattr(pr, "_POPEN",
                            lambda a, **k: spawned.append(a) or FakeProc([], 0))
        out = pr.start("quick", "samples/packed.exe")
        assert not out["ok"]
        assert out["code"] == "sample-packed"
        assert "packed (upx)" in out["error"]
        assert "UPX0" in out["detail"], "the refusal names the evidence"
        assert spawned == [], "the gate is pre-spawn, not an analyzer flag"

    def test_the_refusal_reports_what_the_analyzer_stop_will_do(self, packed,
                                                                monkeypatch):
        # config/analysis.yaml does not exist in the tmp repo -> the flag is
        # absent -> the analyzer's own stop reads as off (the binary default).
        out = pr.start("quick", "samples/packed.exe")
        assert out["analyzer_packed_stop"]["present"] is False
        assert out["analyzer_packed_stop"]["enabled"] is False
        assert "IA_INTERRUPT_IF_PACKED is off" in out["detail"]

    def test_the_refusal_says_the_analyzer_will_overrule_an_override(
            self, packed, monkeypatch):
        # With the analyzer's own tripwire on, "run anyway" would only buy a
        # run the analyzer kills at the histogram phase - and the refusal
        # says so BEFORE the operator takes the override.
        cfg = packed / "config"
        cfg.mkdir()
        (cfg / "analysis.yaml").write_text("IA_INTERRUPT_IF_PACKED: true\n")
        out = pr.start("quick", "samples/packed.exe")
        assert out["analyzer_packed_stop"]["enabled"] is True
        assert "even an overridden run is stopped" in out["detail"]

    def test_allow_packed_starts_the_run_and_records_the_verdict(
            self, packed, monkeypatch):
        monkeypatch.setattr(pr, "_POPEN", lambda a, **k: FakeProc([], 0))
        out = pr.start("quick", "samples/packed.exe", allow_packed=True)
        assert out["ok"], out
        assert out["packed"]["packed"] is True
        assert out["packed"]["method"] == "upx"
        deadline = time.time() + 30
        while time.time() < deadline:
            if pr.job(out["job_id"])["state"] != "running":
                break
            time.sleep(0.02)
        view = pr.job(out["job_id"])
        assert view["packed"]["packed"] is True, "the job carries the verdict"

    def test_an_overridden_start_warns_when_the_analyzer_stop_is_on(
            self, packed, monkeypatch):
        monkeypatch.setattr(pr, "_POPEN", lambda a, **k: FakeProc([], 0))
        cfg = packed / "config"
        cfg.mkdir()
        (cfg / "analysis.yaml").write_text("IA_INTERRUPT_IF_PACKED: true\n")
        out = pr.start("quick", "samples/packed.exe", allow_packed=True)
        assert out["ok"], out
        assert "histogram phase" in out["warning"]

    def test_high_entropy_is_packed_by_the_other_method(self, repo,
                                                        monkeypatch):
        import os as _os
        (repo / "samples" / "random.exe").write_bytes(_os.urandom(1 << 16))
        monkeypatch.setattr(pr, "_POPEN", lambda a, **k: FakeProc([], 0))
        out = pr.start("quick", "samples/random.exe")
        assert not out["ok"]
        assert out["code"] == "sample-packed"
        assert out["packed"]["method"] == "entropy"

    def test_a_clean_sample_carries_a_clean_verdict(self, repo, monkeypatch):
        monkeypatch.setattr(pr, "_POPEN", lambda a, **k: FakeProc([], 0))
        out = pr.start("quick", "samples/sample.exe")
        assert out["ok"], out
        assert out["packed"]["packed"] is False
        assert out["warning"] is None
