"""samples.py - the one implementation of the sample-path rules - and the two
endpoints that speak it: the picker's inspect, and the run gate over HTTP.

Two things are pinned here that the module tests in test_panel_pipeline_run.py
cannot reach:

  * that the ENDPOINT refuses with the same sentences the gate refuses with -
    one implementation, so a path the page shows as valid is a path the gate
    accepts, and the client cannot play the two against each other;
  * that the packed refusal survives the trip through Flask with its
    machine-readable `code` intact, because the page switches on `code` rather
    than on the sentence.

The Flask client follows the pattern test_panel_hardening_endpoints.py
establishes: routes live in create_app()'s closure, so create_app() IS the
unit, and config.REPO is monkeypatched so nothing touches the real tree. With
ADMIN_PANEL_TOKEN unset the auth gate passes everything, which is fine here -
auth is not what these tests are about.
"""

from __future__ import annotations

import io
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "python"))

from panel import config, samples  # noqa: E402

UPX_BYTES = b"MZ" + b"\0" * 200 + b"UPX0" + b"\0" * 64 + b"UPX1"


@pytest.fixture()
def repo(tmp_path, monkeypatch):
    """A tmp repo with one clean sample in samples/."""
    monkeypatch.setattr(config, "REPO", tmp_path)
    (tmp_path / "samples").mkdir()
    (tmp_path / "samples" / "clean.exe").write_bytes(b"MZ" * 256)
    return tmp_path


class TestMeta:
    def test_a_clean_sample_describes_itself(self, repo):
        got = samples.meta("samples/clean.exe")
        assert got["ok"] is True
        assert got["relative"] == "samples/clean.exe"
        assert got["bytes"] == 512
        assert got["packed"]["packed"] is False
        assert got["analyzer_packed_stop"]["key"] == "IA_INTERRUPT_IF_PACKED"

    def test_a_refusal_is_ok_false_with_the_rule_sentence(self, repo):
        got = samples.meta("samples/../escape.exe")
        assert got["ok"] is False
        assert ".." in got["error"]
        assert set(got) == {"ok", "error"}, "no metadata leaks for a refused path"

    def test_the_analyzer_stop_state_comes_from_the_config_file(self, repo):
        cfg = repo / "config"
        cfg.mkdir()
        (cfg / "analysis.yaml").write_text("IA_INTERRUPT_IF_PACKED: true\n")
        got = samples.meta("samples/clean.exe")
        assert got["analyzer_packed_stop"]["present"] is True
        assert got["analyzer_packed_stop"]["enabled"] is True


class TestTheEndpoints:
    @pytest.fixture()
    def client(self, repo, monkeypatch):
        from panel.app import create_app
        app = create_app()
        app.config.update(TESTING=True)
        return app.test_client()

    def test_inspect_validates_and_describes_a_path(self, client):
        res = client.post("/api/build/samples/inspect",
                          json={"path": "samples/clean.exe"})
        assert res.status_code == 200
        data = res.get_json()
        assert data["ok"] is True
        assert data["packed"]["packed"] is False
        assert "analyzer_packed_stop" in data

    def test_inspect_refuses_traversal_with_a_400_and_the_sentence(self, client):
        res = client.post("/api/build/samples/inspect",
                          json={"path": "samples/../../etc/passwd.exe"})
        assert res.status_code == 400
        assert ".." in res.get_json()["error"]

    def test_inspect_demands_a_string_path(self, client):
        res = client.post("/api/build/samples/inspect", json={"path": 42})
        assert res.status_code == 400

    def test_a_file_outside_the_sample_roots_is_refused(self, client, repo):
        (repo / "outside.exe").write_bytes(b"MZ")
        res = client.post("/api/build/samples/inspect",
                          json={"path": "outside.exe"})
        assert res.status_code == 400
        assert "sample roots" in res.get_json()["error"]

    def test_list_returns_the_executables_under_the_roots(self, client):
        res = client.get("/api/build/samples")
        assert res.status_code == 200
        data = res.get_json()
        assert data["ok"] is True
        assert [f["name"] for f in data["files"]] == ["clean.exe"]
        assert data["upload_max_bytes"] > 0

    def test_upload_admits_a_clean_sample_and_lists_it(self, client, repo,
                                                       monkeypatch):
        from panel import samples as samples_mod
        monkeypatch.setattr(samples_mod.clamd, "scan_file",
                            lambda path, timeout=60.0: {
                                "verdict": "clean", "signature": None,
                                "seconds": 0.0})

        res = client.post(
            "/api/build/samples/upload",
            data={"file": (io.BytesIO(b"MZ" * 64), "uploaded.exe")},
            content_type="multipart/form-data")

        assert res.status_code == 200
        data = res.get_json()
        assert data["ok"] is True
        assert data["file"]["name"] == "uploaded.exe"
        assert (repo / "samples" / "uploaded.exe").is_file()
        assert data["sha256"]
        listed = client.get("/api/build/samples").get_json()
        assert any(f["name"] == "uploaded.exe" for f in listed["files"])

    def test_upload_refuses_an_unreachable_scanner_until_explicitly_allowed(
            self, client, repo, monkeypatch):
        from panel import samples as samples_mod
        monkeypatch.setattr(samples_mod.clamd, "scan_file",
                            lambda path, timeout=60.0: {
                                "verdict": "unavailable", "signature": None,
                                "seconds": 0.0, "error": "clamd is down"})

        refused = client.post(
            "/api/build/samples/upload",
            data={"file": (io.BytesIO(b"MZ" * 64), "unscanned.exe")},
            content_type="multipart/form-data")
        assert refused.status_code == 400
        assert refused.get_json()["code"] == "scan-unavailable"
        assert not (repo / "samples" / "unscanned.exe").exists()

        admitted = client.post(
            "/api/build/samples/upload",
            data={"file": (io.BytesIO(b"MZ" * 64), "unscanned.exe"),
                  "allow_unscanned": "true"},
            content_type="multipart/form-data")
        assert admitted.status_code == 200
        assert admitted.get_json()["ok"] is True
        assert (repo / "samples" / "unscanned.exe").is_file()

    def test_upload_requires_a_file_field(self, client):
        res = client.post("/api/build/samples/upload",
                          data={}, content_type="multipart/form-data")
        assert res.status_code == 400
        assert res.get_json()["code"] == "no-file"

    def test_the_run_gate_refuses_a_packed_sample_over_http_with_its_code(
            self, client, repo, monkeypatch):
        from panel import pipeline_run
        (repo / "build-ucrt").mkdir()
        (repo / "build-ucrt" / "static_analyzer.exe").write_text("binary")
        (repo / "samples" / "packed.exe").write_bytes(UPX_BYTES)

        res = client.post("/api/pipeline-run",
                          json={"pipeline": "default",
                                "sample": "samples/packed.exe"})

        assert res.status_code == 400
        data = res.get_json()
        assert data["code"] == "sample-packed"
        assert "packed (upx)" in data["error"]
        assert data["analyzer_packed_stop"]["enabled"] is False

    def test_allow_packed_over_http_starts_the_run_and_is_logged_as_overridden(
            self, client, repo, monkeypatch):
        from panel import pipeline_run

        class StubProc:
            stdout = []
            def wait(self): return 0
            def poll(self): return 0
            def terminate(self): pass
            def kill(self): pass

        monkeypatch.setattr(pipeline_run, "_POPEN", lambda a, **k: StubProc())
        (repo / "build-ucrt").mkdir()
        (repo / "build-ucrt" / "static_analyzer.exe").write_text("binary")
        (repo / "samples" / "packed.exe").write_bytes(UPX_BYTES)

        res = client.post("/api/pipeline-run",
                          json={"pipeline": "default",
                                "sample": "samples/packed.exe",
                                "allow_packed": True})

        assert res.status_code == 200
        data = res.get_json()
        assert data["ok"] is True
        assert data["packed"]["packed"] is True
        assert data["warning"] is None, "the analyzer stop is off in a tmp repo"

    def test_the_packed_refusal_is_400_not_409(self, client, repo):
        # 409 means "a run is already going"; a packed sample is a rule
        # refusal, and the page reads the two differently.
        (repo / "build-ucrt").mkdir()
        (repo / "build-ucrt" / "static_analyzer.exe").write_text("binary")
        (repo / "samples" / "packed.exe").write_bytes(UPX_BYTES)

        res = client.post("/api/pipeline-run",
                          json={"pipeline": "default",
                                "sample": "samples/packed.exe"})
        assert res.status_code == 400
