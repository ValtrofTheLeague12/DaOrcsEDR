"""Tests for Windows VMMap snapshots without launching the real tool."""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "python"))

from panel.analysis import memory_profiling as M  # noqa: E402


@pytest.fixture
def repo(tmp_path):
    root = tmp_path / "repo"
    (root / "config").mkdir(parents=True)
    (root / "samples").mkdir()
    (root / "samples" / "sample.exe").write_bytes(b"MZsample")
    (root / "samples" / "notes.txt").write_text("not an executable")
    vmmap = root / M.VMMAP_RELATIVE / "VMMap64.exe"
    vmmap.parent.mkdir(parents=True)
    vmmap.write_bytes(b"test executable")
    analyzer = root / M.ANALYZER_RELATIVE
    analyzer.parent.mkdir()
    analyzer.write_bytes(b"test executable")
    return root


class FakeProcess:
    pid = 4321

    def __init__(self, returncode=0, wait_error=None):
        self.returncode = returncode
        self.wait_error = wait_error
        self.killed = False
        self.exited = False

    def poll(self):
        return self.returncode if self.exited else None

    def wait(self, timeout=None):
        if self.wait_error and not self.killed:
            raise self.wait_error
        self.exited = True
        return self.returncode

    def kill(self):
        self.killed = True
        self.exited = True
        self.returncode = -9


def _fake_popen(monkeypatch, process=None):
    proc = process or FakeProcess()
    monkeypatch.setattr(M, "_POPEN", lambda *args, **kwargs: proc)
    return proc


def _fake_vmmap(args, **kwargs):
    Path(args[-1]).write_bytes(b"VMMap snapshot")
    return subprocess.CompletedProcess(args, 0, "snapshot saved", "")


def _wait_for_job(job_id):
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        job = M.job(job_id)
        if job is None or job["state"] != "running":
            return job
        time.sleep(0.01)
    raise AssertionError("VMMap profile worker did not finish")


class TestSettings:
    def test_defaults_are_disabled_and_profile_the_analyzer(self, repo):
        assert M.load(repo) == {
            "enabled": False, "target": "analyzer", "sample": "",
        }

    def test_write_round_trips(self, repo):
        M.write(repo, {
            "enabled": True, "target": "sample", "sample": "samples/sample.exe",
        })
        assert M.load(repo) == {
            "enabled": True, "target": "sample", "sample": "samples/sample.exe",
        }

    def test_unknown_key_is_refused(self, repo):
        with pytest.raises(ValueError, match="not a memory-profiling setting"):
            M.write(repo, {"target": "analyzer", "sample_dir": "samples"})

    def test_unknown_target_is_refused(self, repo):
        with pytest.raises(ValueError, match="'target' must be one of"):
            M.write(repo, {"target": "both"})

    def test_malformed_file_is_reported_by_snapshot(self, repo):
        (repo / "config" / "memory_profiling.json").write_text("{")
        snapshot = M.snapshot(repo)
        assert snapshot["error"]
        assert snapshot["settings"]["enabled"] is False


class TestSampleResolution:
    def test_executable_under_a_sample_root_is_accepted(self, repo):
        path, why = M._resolve_sample(repo, "samples/sample.exe")
        assert why is None
        assert path == (repo / "samples" / "sample.exe").resolve()

    def test_outside_sample_roots_is_refused(self, repo):
        (repo / "outside.exe").write_bytes(b"MZ")
        path, why = M._resolve_sample(repo, "outside.exe")
        assert path is None
        assert "sample roots" in why

    def test_traversal_is_refused(self, repo):
        path, why = M._resolve_sample(repo, "../outside.exe")
        assert path is None
        assert "'..'" in why

    def test_sample_picker_lists_only_windows_executables(self, repo):
        assert [s["name"] for s in M.samples(repo)] == ["sample.exe"]

    def test_non_pe_executable_is_rejected(self, repo):
        (repo / "samples" / "broken.exe").write_bytes(b"not PE")
        assert not M._is_windows_executable(repo / "samples" / "broken.exe")


class TestVMMapCommand:
    def test_builds_process_snapshot_command(self, repo, tmp_path):
        output = tmp_path / "capture.mmp"
        args = M._vmmap_command(repo, 123, output)
        assert args == [
            str(repo / M.VMMAP_RELATIVE / "VMMap64.exe"),
            "-accepteula", "-p", "123", str(output),
        ]

    def test_32_bit_launcher_requests_64_bit_scan(self, repo, tmp_path):
        executable = repo / M.VMMAP_RELATIVE / "VMMap64.exe"
        executable.unlink()
        executable.with_name("VMMap.exe").write_bytes(b"32-bit launcher")
        args = M._vmmap_command(repo, 123, tmp_path / "capture.mmp")
        assert "-64" in args

    def test_launches_selected_windows_executable(self, repo):
        sample = (repo / "samples" / "sample.exe").resolve()
        assert M._target_command(repo, "sample", sample) == [str(sample)]

    def test_analyzer_command_includes_required_sample(self, repo):
        sample = (repo / "samples" / "sample.exe").resolve()
        args = M._target_command(repo, "analyzer", sample)
        assert args[:4] == [
            str(repo / M.ANALYZER_RELATIVE),
            "--no-curses", "--pipeline", "default",
        ]
        assert args[-1] == str(sample)

    def test_analyzer_command_requires_a_sample(self, repo):
        with pytest.raises(ValueError, match="select a Windows .exe"):
            M._target_command(repo, "analyzer", None)

    def test_missing_installation_reports_actionable_error(self, repo):
        (repo / M.VMMAP_RELATIVE / "VMMap64.exe").unlink()
        state = M.vmmap_state(repo)
        assert not state["installed"]
        assert "VMMap64.exe" in state["error"]


class TestVMMapCSV:
    def test_parses_category_summary_and_root_regions(self, tmp_path):
        csv_export = tmp_path / "layout.csv"
        csv_export.write_text(
            '"Process:","sample.exe"\r\n'
            '"PID:","1234"\r\n\r\n'
            '"Type","Size","Committed","Private","Total WS","Private WS",'
            '"Shareable WS","Shared WS","Locked WS","Blocks","Largest",\r\n'
            '"Total","1 024","512","256","128","64","64","64","","1",""\r\n'
            '"Free","256","","","","","","","","1","256"\r\n'
            '"Heap","512","256","128","64","32","32","32","","1","512"\r\n\r\n'
            '"Address","Type","Size","Committed","Private","Total WS",'
            '"Private WS","Shareable WS","Shared WS","Locked WS","Blocks",'
            '"Protection","Details",\r\n'
            '"0000000000100000","Heap","512","256","128","64","32","32",'
            '"32","","1","Read/Write","sample heap"\r\n'
            '"  0000000000100000","Heap","256","128","64","32","16","16",'
            '"16","","","Read/Write","child region"\r\n',
            encoding="utf-8",
        )

        result = M._parse_vmmap_csv(csv_export)

        assert result["process_name"] == "sample.exe"
        assert result["process_id"] == "1234"
        assert result["totals"]["size_bytes"] == 1024 * 1024
        assert result["categories"] == [{
            "type": "Heap",
            "size_bytes": 512 * 1024,
            "committed_bytes": 256 * 1024,
            "total_ws_bytes": 64 * 1024,
            "private_ws_bytes": 32 * 1024,
        }]
        assert result["region_count"] == 1
        assert result["regions"][0]["address"] == "0000000000100000"
        assert result["regions"][0]["details"] == "sample heap"

    def test_refuses_oversized_export(self, tmp_path):
        csv_export = tmp_path / "large.csv"
        csv_export.write_bytes(b"x" * (M.MAX_LAYOUT_BYTES + 1))
        with pytest.raises(ValueError, match="too large"):
            M._parse_vmmap_csv(csv_export)


class TestStart:
    def test_missing_analyzer_binary_blocks_profile(self, repo, monkeypatch):
        (repo / M.ANALYZER_RELATIVE).unlink()
        result = M.start(repo, target="analyzer")
        assert result["ok"] is False
        assert "not built" in result["error"]

    def test_missing_sample_is_refused(self, repo):
        result = M.start(repo, target="sample", sample="samples/notes.txt")
        assert result["ok"] is False
        assert "Windows .exe" in result["error"]

    def test_analyzer_profile_requires_a_sample(self, repo):
        result = M.start(repo, target="analyzer")
        assert result["ok"] is False
        assert "select a Windows .exe" in result["error"]

    def test_start_creates_an_analyzer_job(self, repo, monkeypatch):
        _fake_popen(monkeypatch)
        monkeypatch.setattr(M, "_RUN", _fake_vmmap)
        result = M.start(repo, target="analyzer", sample="samples/sample.exe")
        assert result["ok"] is True
        _wait_for_job(result["job"]["id"])
        finished = M.job(result["job"]["id"])
        assert finished["target"] == "analyzer"
        assert Path(finished["report_dir"]).parent.name == "memory_profiling"
        assert Path(finished["snapshot_path"]).is_file()
        assert Path(finished["csv_path"]).is_file()

    def test_generated_executable_is_captured_as_sample(self, repo, monkeypatch):
        _fake_popen(monkeypatch)
        monkeypatch.setattr(M, "_RUN", _fake_vmmap)
        result = M.start_generated(repo, "samples/sample.exe")
        assert result["ok"] is True
        _wait_for_job(result["job"]["id"])
        assert result["job"]["target"] == "sample"


class TestProfileWorker:
    def _job(self, job_id, out_dir):
        out_dir.mkdir()
        M._jobs[job_id] = {
            "id": job_id, "state": "running", "target": "analyzer",
            "started_at": M._now(), "output_dir": str(out_dir), "log": [],
            "log_line_count": 0, "log_dropped": 0,
        }

    def test_profile_sets_offline_and_no_upload_environment(
            self, repo, monkeypatch, tmp_path):
        captured = {}

        def fake_popen(args, **kwargs):
            captured.update(kwargs)
            return FakeProcess()

        monkeypatch.setattr(M, "_POPEN", fake_popen)
        monkeypatch.setattr(M, "_RUN", _fake_vmmap)
        job_id = "mprofile"
        out_dir = tmp_path / "reports"
        self._job(job_id, out_dir)
        try:
            sample = (repo / "samples" / "sample.exe").resolve()
            M._run_profile(job_id, repo, "analyzer", sample, 10)
            assert M._jobs[job_id]["state"] == "done"
            assert Path(M._jobs[job_id]["snapshot_path"]).is_file()
            assert Path(M._jobs[job_id]["csv_path"]).is_file()
        finally:
            M._jobs.pop(job_id, None)
        assert captured["env"]["STATIC_ANALYZER_CURSES"] == "0"
        assert captured["env"]["CTI_SKIP"] == "1"
        assert captured["env"]["IA_ARTIFACT_UPLOAD"] == "0"

    def test_vmmap_failure_kills_target_and_is_reported(
            self, repo, monkeypatch, tmp_path):
        process = FakeProcess()
        monkeypatch.setattr(M, "_POPEN", lambda *a, **k: process)
        monkeypatch.setattr(
            M, "_RUN",
            lambda args, **kwargs: subprocess.CompletedProcess(args, 2, "", "scan failed"),
        )
        job_id = "mvmmapfail"
        out_dir = tmp_path / "reports"
        self._job(job_id, out_dir)
        try:
            sample = (repo / "samples" / "sample.exe").resolve()
            M._run_profile(job_id, repo, "analyzer", sample, 10)
            assert M._jobs[job_id]["state"] == "failed"
            assert "VMMap failed to capture" in M._jobs[job_id]["error"]
            assert process.killed
        finally:
            M._jobs.pop(job_id, None)

    def test_target_timeout_is_reported_as_failed(self, repo, monkeypatch, tmp_path):
        process = FakeProcess(wait_error=subprocess.TimeoutExpired("target", 10))
        _fake_popen(monkeypatch, process)
        monkeypatch.setattr(M, "_RUN", _fake_vmmap)
        job_id = "mtimeout"
        out_dir = tmp_path / "reports"
        self._job(job_id, out_dir)
        try:
            sample = (repo / "samples" / "sample.exe").resolve()
            M._run_profile(job_id, repo, "analyzer", sample, 10)
            assert M._jobs[job_id]["state"] == "failed"
            assert "exceeded 10s" in M._jobs[job_id]["error"]
            assert process.killed
        finally:
            M._jobs.pop(job_id, None)

    def test_nonzero_target_exit_keeps_successful_vmmap_capture(
            self, repo, monkeypatch, tmp_path):
        process = FakeProcess(returncode=1)
        process.exited = True
        _fake_popen(monkeypatch, process)
        monkeypatch.setattr(M, "_RUN", _fake_vmmap)
        job_id = "mtargetfailed"
        out_dir = tmp_path / "reports"
        self._job(job_id, out_dir)
        try:
            sample = (repo / "samples" / "sample.exe").resolve()
            M._run_profile(job_id, repo, "analyzer", sample, 10)
            result = M.job(job_id)
            assert result["state"] == "done"
            assert result["exit_code"] == 1
            assert "snapshot was captured successfully" in result["warning"]
            assert Path(result["snapshot_path"]).is_file()
            assert Path(result["csv_path"]).is_file()
        finally:
            M._jobs.pop(job_id, None)

    def test_missing_snapshot_is_reported(self, repo, monkeypatch, tmp_path):
        _fake_popen(monkeypatch)
        monkeypatch.setattr(
            M, "_RUN",
            lambda args, **kwargs: subprocess.CompletedProcess(args, 0, "", ""),
        )
        job_id = "mnosnapshot"
        out_dir = tmp_path / "reports"
        self._job(job_id, out_dir)
        try:
            sample = (repo / "samples" / "sample.exe").resolve()
            M._run_profile(job_id, repo, "analyzer", sample, 10)
            assert M._jobs[job_id]["state"] == "failed"
            assert "did not create a snapshot" in M._jobs[job_id]["error"]
        finally:
            M._jobs.pop(job_id, None)
