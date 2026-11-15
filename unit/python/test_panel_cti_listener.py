"""Start / stop for the generated CTI artifact server.

``host_server.py`` only writes ``server.py``. The listener controller is the
other half, and these tests pin the decisions that make the Launch button safe:

  * a missing/invalid generated server is refused before anything is spawned;
  * a port held by another process is reported, never adopted;
  * "running" means the generated server's own /health answered;
  * Stop never kills a listener whose command line is not
    ``stix-server/server.py`` - notably not the root analyzer ``server.py``.

Nothing here spawns a real process or dials a real port: ``_spawn``,
``_listeners`` and ``_health`` are the seams.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "python"))

from panel.app import create_app  # noqa: E402
from panel.artifacts import cti_listener, cti_server  # noqa: E402
from panel.core import config  # noqa: E402


@pytest.fixture(autouse=True)
def reset_launch_tracking():
    cti_listener._LAUNCHED.update(ip=None, port=None, pid=None, log=None)
    yield
    cti_listener._LAUNCHED.update(ip=None, port=None, pid=None, log=None)


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    (repo / "stix-server").mkdir(parents=True)
    return repo


def _config(repo: Path, ip: str = "127.0.0.1", port: int = 4321) -> None:
    path = repo / cti_server.CONFIG_RELATIVE
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"server": {"ip": ip, "port": port}}),
                    encoding="utf-8")


def _server(repo: Path) -> Path:
    path = repo / "stix-server" / "server.py"
    path.write_text("print('generated')\n", encoding="utf-8")
    return path


def _listener(pid: int = 4242, command: str | None = None) -> dict:
    return {
        "pid": pid,
        "name": "python.exe",
        "command": command
        or r'"C:\repo\stix-server\Scripts\python.exe" C:\repo\stix-server\server.py',
    }


class _Proc:
    def __init__(self, pid: int = 4242, returncode=None) -> None:
        self.pid = pid
        self.returncode = returncode

    def poll(self):
        return self.returncode


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------

class TestStatus:
    def test_a_stopped_listener_reports_the_loopback_url_for_a_wildcard_bind(
            self, repo, monkeypatch):
        _config(repo, ip="0.0.0.0", port=8772)
        monkeypatch.setattr(cti_listener, "_listeners", lambda port: [])

        out = cti_listener.status(repo)

        assert out["state"] == "stopped"
        assert out["url"] == "http://127.0.0.1:8772/"
        assert out["port"] == 8772

    def test_running_requires_our_process_and_a_healthy_route(
            self, repo, monkeypatch):
        _config(repo)
        monkeypatch.setattr(cti_listener, "_listeners",
                            lambda port: [_listener()])
        monkeypatch.setattr(cti_listener, "_health", lambda ip, port: (True, ""))

        out = cti_listener.status(repo)

        assert out["state"] == "running"
        assert out["pid"] == 4242
        assert out["url"] == "http://127.0.0.1:4321/"

    def test_our_process_without_a_health_answer_is_unhealthy(
            self, repo, monkeypatch):
        _config(repo)
        monkeypatch.setattr(cti_listener, "_listeners",
                            lambda port: [_listener()])
        monkeypatch.setattr(cti_listener, "_health",
                            lambda ip, port: (False, "connection refused"))

        out = cti_listener.status(repo)

        assert out["state"] == "unhealthy"
        assert "connection refused" in out["detail"]

    def test_another_process_on_the_port_is_foreign(self, repo, monkeypatch):
        _config(repo)
        monkeypatch.setattr(cti_listener, "_listeners", lambda port: [
            {"pid": 9, "name": "node.exe", "command": "node vite.js"},
        ])
        monkeypatch.setattr(cti_listener, "_health",
                            lambda ip, port: pytest.fail("must not probe a foreign port"))

        out = cti_listener.status(repo)

        assert out["state"] == "foreign"
        assert "pid 9" in out["detail"]

    def test_a_broken_config_is_an_error_not_a_silent_stop(self, repo):
        path = repo / cti_server.CONFIG_RELATIVE
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{", encoding="utf-8")

        out = cti_listener.status(repo)

        assert out["state"] == "error"
        assert "not valid JSON" in out["detail"]


# ---------------------------------------------------------------------------
# Start
# ---------------------------------------------------------------------------

class TestStart:
    def test_a_missing_generated_server_is_refused_without_spawning(
            self, repo, monkeypatch):
        _config(repo)
        spawned: list = []
        monkeypatch.setattr(cti_listener, "_spawn", lambda *a: spawned.append(a))

        out = cti_listener.start(repo)

        assert out["ok"] is False
        assert out["code"] == "blocked"
        assert "Generate Server" in out["detail"]
        assert spawned == []

    def test_a_bad_config_is_refused_without_spawning(self, repo, monkeypatch):
        _server(repo)
        path = repo / cti_server.CONFIG_RELATIVE
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{", encoding="utf-8")
        spawned: list = []
        monkeypatch.setattr(cti_listener, "_spawn", lambda *a: spawned.append(a))

        out = cti_listener.start(repo)

        assert out["ok"] is False
        assert out["code"] == "blocked"
        assert spawned == []

    def test_an_already_running_server_is_not_spawned_twice(
            self, repo, monkeypatch):
        _server(repo)
        _config(repo)
        monkeypatch.setattr(cti_listener, "_listeners",
                            lambda port: [_listener()])
        monkeypatch.setattr(cti_listener, "_health", lambda ip, port: (True, ""))
        spawned: list = []
        monkeypatch.setattr(cti_listener, "_spawn", lambda *a: spawned.append(a))

        out = cti_listener.start(repo)

        assert out["ok"] is True
        assert out["code"] == "already-running"
        assert spawned == []

    def test_a_held_port_is_reported_as_held_not_started(
            self, repo, monkeypatch):
        _server(repo)
        _config(repo)
        monkeypatch.setattr(cti_listener, "_listeners", lambda port: [
            {"pid": 99, "name": "python.exe", "command": "somebody else.py"},
        ])
        spawned: list = []
        monkeypatch.setattr(cti_listener, "_spawn", lambda *a: spawned.append(a))

        out = cti_listener.start(repo)

        assert out["ok"] is False
        assert out["code"] == "port-held"
        assert "pid 99" in out["detail"]
        assert spawned == []

    def test_start_reports_ready_only_after_health_answers(
            self, repo, monkeypatch):
        script = _server(repo)
        _config(repo)
        log = repo / "listener.log"
        log.write_text("booting\n", encoding="utf-8")
        spawned: dict = {}

        def spawn(repo_arg, script_arg, cwd, log_arg):
            spawned.update(repo=repo_arg, script=script_arg, cwd=cwd, log=log_arg)
            return _Proc()

        # The pre-spawn check sees nothing; once spawned, the listener exists.
        def listeners(port):
            return [_listener()] if spawned else []

        monkeypatch.setattr(cti_listener, "_spawn", spawn)
        monkeypatch.setattr(cti_listener, "_listeners", listeners)
        monkeypatch.setattr(cti_listener, "_health", lambda ip, port: (True, ""))
        monkeypatch.setattr(cti_listener, "_log_path", lambda: log)

        out = cti_listener.start(repo)

        assert out["ok"] is True
        assert out["code"] == "started"
        assert spawned["script"] == script
        assert spawned["cwd"] == repo / "stix-server"
        assert out["status"]["state"] == "running"
        assert out["pid"] == 4242
        assert cti_listener._LAUNCHED["port"] == 4321

    def test_a_process_that_dies_early_carries_the_log_tail(
            self, repo, monkeypatch):
        _server(repo)
        _config(repo)
        log = repo / "listener.log"
        log.write_text("Traceback: no flask\n", encoding="utf-8")
        monkeypatch.setattr(cti_listener, "_spawn", lambda *a: _Proc(7, returncode=1))
        monkeypatch.setattr(cti_listener, "_listeners", lambda port: [])
        monkeypatch.setattr(cti_listener, "_log_path", lambda: log)

        out = cti_listener.start(repo)

        assert out["ok"] is False
        assert out["code"] == "exited"
        assert "Traceback: no flask" in out["detail"]
        assert str(log) in out["detail"]


# ---------------------------------------------------------------------------
# Stop
# ---------------------------------------------------------------------------

class TestStop:
    def test_refuses_to_kill_a_listener_that_is_not_ours(self, repo, monkeypatch):
        _config(repo)
        monkeypatch.setattr(cti_listener, "_listeners", lambda port: [
            {"pid": 9, "name": "node.exe", "command": "node vite.js"},
        ])
        killed: list = []
        monkeypatch.setattr(cti_listener.launcher, "_kill",
                            lambda pid: killed.append(pid) or True)

        out = cti_listener.stop(repo)

        assert out["ok"] is False
        assert out["code"] == "not-ours"
        assert "refusing to kill" in out["detail"]
        assert killed == []

    def test_stops_our_listener_and_waits_for_the_port(self, repo, monkeypatch):
        _config(repo)
        calls = {"n": 0}

        def listeners(port):
            calls["n"] += 1
            return [_listener(pid=11)] if calls["n"] == 1 else []

        monkeypatch.setattr(cti_listener, "_listeners", listeners)
        killed: list = []
        monkeypatch.setattr(cti_listener.launcher, "_kill",
                            lambda pid: killed.append(pid) or True)

        out = cti_listener.stop(repo)

        assert out["ok"] is True
        assert out["code"] == "stopped"
        assert killed == [11]
        assert out["status"]["state"] == "stopped"

    def test_nothing_listening_is_not_reported_as_stopped(self, repo, monkeypatch):
        _config(repo)
        monkeypatch.setattr(cti_listener, "_listeners", lambda port: [])

        out = cti_listener.stop(repo)

        assert out["ok"] is False
        assert out["code"] == "not-running"

    def test_stop_can_find_a_server_this_panel_started_on_an_old_port(
            self, repo, monkeypatch):
        _config(repo, port=4321)
        cti_listener._LAUNCHED.update(
            ip="127.0.0.1", port=5555, pid=77, log=None)
        seen: list[int] = []
        state = {"killed": False}

        def listeners(port):
            seen.append(port)
            if port == 5555 and not state["killed"]:
                return [_listener(pid=77)]
            return []

        def kill(pid):
            state["killed"] = True
            return True

        monkeypatch.setattr(cti_listener, "_listeners", listeners)
        monkeypatch.setattr(cti_listener.launcher, "_kill", kill)

        out = cti_listener.stop(repo)

        assert seen[:2] == [4321, 5555]
        assert out["ok"] is True
        assert "pid 77" in out["detail"]


# ---------------------------------------------------------------------------
# Command-line ownership
# ---------------------------------------------------------------------------

def test_only_the_generated_server_counts_as_ours():
    assert cti_listener._looks_like(
        r'"C:\repo\stix-server\Scripts\python.exe" C:\repo\stix-server\server.py')
    assert cti_listener._looks_like(
        '"C:/repo/stix-server/Scripts/python.exe" C:/repo/stix-server/server.py')
    assert not cti_listener._looks_like(
        r'"C:\repo\python\Scripts\python.exe" C:\repo\server.py')
    assert not cti_listener._looks_like(
        r'"C:\repo\python\Scripts\python.exe" C:\repo\python\api\server.py')


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------

@pytest.fixture
def client(tmp_path, monkeypatch):
    repo = tmp_path / "panel-repo"
    repo.mkdir()
    monkeypatch.setattr(config, "REPO", repo)
    return create_app().test_client(), repo


def test_api_reports_listener_status(client, monkeypatch):
    http, _repo = client
    monkeypatch.setattr(cti_listener, "status", lambda repo: {
        "state": "stopped", "ip": "127.0.0.1", "port": 4321,
        "url": "http://127.0.0.1:4321/", "pid": None, "log": None,
        "detail": "",
    })

    response = http.get("/api/threat-intelligence/listener")

    assert response.status_code == 200
    assert response.get_json()["state"] == "stopped"


@pytest.mark.parametrize("action,code", [("start", "started"), ("stop", "stopped")])
def test_api_controls_the_listener(client, monkeypatch, action, code):
    http, _repo = client
    monkeypatch.setattr(
        cti_listener, "control",
        lambda requested, repo: {
            "ok": True, "code": code, "detail": "done", "pid": 1,
            "log": None, "tail": [],
            "status": {"state": "running" if requested == "start" else "stopped",
                       "ip": "127.0.0.1", "port": 4321,
                       "url": "http://127.0.0.1:4321/", "pid": None,
                       "log": None, "detail": ""},
        },
    )

    response = http.post(f"/api/threat-intelligence/listener/{action}")

    assert response.status_code == 200
    assert response.get_json()["code"] == code


def test_api_rejects_an_unknown_listener_action(client):
    http, _repo = client

    response = http.post("/api/threat-intelligence/listener/restart")

    assert response.status_code == 400
    assert "start or stop" in response.get_json()["error"]
