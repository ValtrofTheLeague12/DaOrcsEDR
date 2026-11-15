"""Start / stop for the three Python services.

The panel could always say the Analyzer API was down. These tests pin the four
decisions that make the new buttons safe rather than merely working:

  * the allowlist is server-side - a container key is a 404, not a button;
  * a missing prerequisite refuses with the reason and spawns nothing;
  * "started" means the endpoint the card shows answered, not that Popen
    returned;
  * stop refuses a listener whose command line does not look like the service.

Nothing here spawns a real process: `_spawn` and `_listeners` are the seam.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "python"))

from panel.host import launcher, services  # noqa: E402
from panel.core import config  # noqa: E402


def _probe(up: bool, key: str = "analyzer") -> services.Probe:
    return services.Probe(key=key, name="Analyzer API",
                          endpoint="http://127.0.0.1:60025/health",
                          up=up, code="200" if up else "down", ms=3.0)


# ---------------------------------------------------------------------------
# The allowlist
# ---------------------------------------------------------------------------

class TestAllowlist:
    def test_only_the_three_python_services_have_a_rule(self):
        assert set(launcher.units()) == {"analyzer", "malapi", "ml"}

    def test_malapi_runs_from_python_so_its_yaml_resolves(self):
        # api/server.py opens yaml/malapi/*.yaml relative to the working
        # directory, so the repo root would make every route a 500.
        assert launcher.units()["malapi"].cwd == REPO / "python"

    def test_a_container_key_is_not_startable_through_this_route(self):
        with pytest.raises(launcher.ControlError) as info:
            launcher.control("guacamole", "start")
        assert info.value.status == 404
        assert info.value.code == "unknown-service"

    def test_action_must_be_start_or_stop(self):
        with pytest.raises(launcher.ControlError) as info:
            launcher.control("analyzer", "restart")
        assert info.value.status == 400
        assert info.value.code == "bad-action"


# ---------------------------------------------------------------------------
# Refusals before anything is spawned
# ---------------------------------------------------------------------------

class TestBlocked:
    def test_a_missing_model_is_refused_by_name(self, tmp_path, monkeypatch):
        monkeypatch.setattr(launcher, "REPO", tmp_path)
        (tmp_path / "ml").mkdir()
        (tmp_path / "ml" / "serve.py").write_text("print('x')\n", encoding="utf-8")
        monkeypatch.setattr(launcher, "units", lambda: {
            "ml": launcher.Unit("ml", "ML scorer",
                                [sys.executable, "serve.py"], tmp_path, 1.0),
        })

        why = launcher.blocker("ml")
        assert "model.txt" in why

    def test_a_zero_byte_driver_is_not_usable(self, tmp_path, monkeypatch):
        monkeypatch.setattr(launcher, "REPO", tmp_path)
        (tmp_path / "ml").mkdir()
        (tmp_path / "ml" / "serve.py").write_text("", encoding="utf-8")
        monkeypatch.setattr(launcher, "units", lambda: {
            "ml": launcher.Unit("ml", "ML scorer",
                                [sys.executable, "serve.py"], tmp_path, 1.0),
        })

        assert "missing or empty" in launcher.blocker("ml")

    def test_start_does_not_spawn_when_blocked(self, monkeypatch):
        monkeypatch.setattr(launcher, "blocker", lambda key: "no model")
        spawned: list = []
        monkeypatch.setattr(launcher, "_spawn", lambda unit, path: spawned.append(unit))

        out = launcher.start("analyzer")
        assert out["ok"] is False
        assert out["code"] == "blocked"
        assert out["detail"] == "no model"
        assert spawned == []

    def test_a_held_port_is_reported_as_held_not_started(self, monkeypatch):
        monkeypatch.setattr(launcher, "blocker", lambda key: "")
        monkeypatch.setattr(services, "probe_one", lambda key: _probe(False))
        monkeypatch.setattr(launcher, "_listeners",
                            lambda port: [{"pid": 99, "name": "python.exe",
                                           "command": "something else"}])
        spawned: list = []
        monkeypatch.setattr(launcher, "_spawn", lambda unit, path: spawned.append(unit))

        out = launcher.start("analyzer")
        assert out["ok"] is False
        assert out["code"] == "port-held"
        assert "pid 99" in out["detail"]
        assert spawned == []


# ---------------------------------------------------------------------------
# Start
# ---------------------------------------------------------------------------

class _Proc:
    def __init__(self, pid: int = 4242, returncode=None) -> None:
        self.pid = pid
        self.returncode = returncode

    def poll(self):
        return self.returncode


class TestStart:
    def _fake(self, tmp_path, monkeypatch):
        unit = launcher.Unit("analyzer", "Analyzer API",
                             [sys.executable, "server.py"], tmp_path, 1.0)
        monkeypatch.setattr(launcher, "units", lambda: {"analyzer": unit})
        monkeypatch.setattr(launcher, "blocker", lambda key: "")
        monkeypatch.setattr(launcher, "_listeners", lambda port: [])
        monkeypatch.setattr(launcher, "POLL_SECONDS", 0.01)
        # The real probe would dial .env's endpoint, which makes these tests
        # depend on whether the operator happens to have the service running.
        monkeypatch.setattr(services, "probe_one", lambda key: _probe(False))
        log = tmp_path / "start.log"
        log.write_text("booting\n", encoding="utf-8")
        monkeypatch.setattr(launcher, "_log_path", lambda key: log)
        return unit, log

    def test_start_reports_ready_only_after_the_probe_answers(self, tmp_path,
                                                              monkeypatch):
        unit, log = self._fake(tmp_path, monkeypatch)
        spawned: dict = {}

        def spawn(u, path):
            spawned["unit"], spawned["path"] = u, path
            return _Proc()

        monkeypatch.setattr(launcher, "_spawn", spawn)
        answers = iter([_probe(False), _probe(True)])
        monkeypatch.setattr(services, "probe_one", lambda key: next(answers))

        out = launcher.start("analyzer")

        assert out["ok"] is True
        assert out["code"] == "started"
        assert out["pid"] == 4242
        assert spawned["unit"].cwd == tmp_path
        assert spawned["path"] == log

    def test_the_reported_pid_is_the_listener_not_the_redirector(self, tmp_path,
                                                                 monkeypatch):
        # A venv's python.exe re-execs the real interpreter, which is the one
        # holding the socket. Start and Stop must name the same process, or an
        # operator comparing them with Task Manager sees two python.exe.
        self._fake(tmp_path, monkeypatch)
        monkeypatch.setattr(launcher, "_spawn", lambda u, p: _Proc(4242))
        answers = iter([_probe(False), _probe(True), _probe(True)])
        monkeypatch.setattr(services, "probe_one", lambda key: next(answers))
        calls = {"n": 0}

        def listeners(port):
            calls["n"] += 1
            # The first call is the pre-spawn "is the port already held" check.
            if calls["n"] == 1:
                return []
            return [{"pid": 5000, "name": "python.exe", "command": "server.py"}]

        monkeypatch.setattr(launcher, "_listeners", listeners)

        out = launcher.start("analyzer")
        assert out["pid"] == 5000
        assert "pid 5000" in out["detail"]

    def test_an_already_running_service_is_not_spawned_twice(self, tmp_path,
                                                             monkeypatch):
        self._fake(tmp_path, monkeypatch)
        monkeypatch.setattr(services, "probe_one", lambda key: _probe(True))
        spawned: list = []
        monkeypatch.setattr(launcher, "_spawn", lambda u, p: spawned.append(u))

        out = launcher.start("analyzer")
        assert out["ok"] is True
        assert out["code"] == "already-running"
        assert spawned == []

    def test_a_process_that_dies_early_carries_the_log_tail(self, tmp_path,
                                                            monkeypatch):
        _, log = self._fake(tmp_path, monkeypatch)
        log.write_text("Traceback: no flask\n", encoding="utf-8")
        monkeypatch.setattr(launcher, "_spawn", lambda u, p: _Proc(7, returncode=1))
        answered = iter([_probe(False)])
        monkeypatch.setattr(services, "probe_one", lambda key: next(answered))

        out = launcher.start("analyzer")
        assert out["ok"] is False
        assert out["code"] == "exited"
        assert "Traceback: no flask" in out["detail"]
        assert str(log) in out["detail"]


# ---------------------------------------------------------------------------
# Stop
# ---------------------------------------------------------------------------

class TestStop:
    def _spec(self) -> services.Spec:
        return services.Spec(key="analyzer", name="Analyzer API", description="",
                             host="127.0.0.1", port=60025)

    def test_refuses_to_kill_a_listener_that_is_not_the_service(self, monkeypatch):
        monkeypatch.setattr(services, "spec_for", lambda key: self._spec())
        monkeypatch.setattr(launcher, "_listeners", lambda port: [
            {"pid": 9, "name": "node.exe", "command": "node vite.js"}])
        killed: list = []
        monkeypatch.setattr(launcher, "_kill",
                            lambda pid: killed.append(pid) or True)

        out = launcher.stop("analyzer")
        assert out["ok"] is False
        assert out["code"] == "not-ours"
        assert "refusing to kill" in out["detail"]
        assert killed == []

    def test_stops_the_matching_listener_and_waits_for_the_port(self, monkeypatch):
        monkeypatch.setattr(services, "spec_for", lambda key: self._spec())
        calls = {"n": 0}

        def listeners(port):
            calls["n"] += 1
            if calls["n"] == 1:
                return [{"pid": 11, "name": "python.exe",
                         "command": '"C:\\venv\\python.exe" server.py'}]
            return []

        monkeypatch.setattr(launcher, "_listeners", listeners)
        killed: list = []
        monkeypatch.setattr(launcher, "_kill",
                            lambda pid: killed.append(pid) or True)

        out = launcher.stop("analyzer")
        assert out["ok"] is True
        assert out["code"] == "stopped"
        assert killed == [11]
        assert "pid 11" in out["detail"]

    def test_nothing_listening_is_not_reported_as_stopped(self, monkeypatch):
        monkeypatch.setattr(services, "spec_for", lambda key: self._spec())
        monkeypatch.setattr(launcher, "_listeners", lambda port: [])
        monkeypatch.setattr(services, "probe_one", lambda key: _probe(False))

        out = launcher.stop("analyzer")
        assert out["ok"] is False
        assert out["code"] == "not-running"


# ---------------------------------------------------------------------------
# Command-line ownership
# ---------------------------------------------------------------------------

class TestOwnership:
    def test_the_two_python_apis_are_not_confused(self):
        assert launcher._looks_like("analyzer", r'"C:\venv\python.exe" server.py')
        assert not launcher._looks_like("analyzer", r'"C:\venv\python.exe" api\server.py')
        assert launcher._looks_like("malapi", r'"C:\venv\python.exe" api/server.py')
        assert not launcher._looks_like("ml", r'"C:\venv\python.exe" api\server.py')
        assert launcher._looks_like("ml", r'"C:\venv\python.exe" ml/serve.py --port 60010')

    def test_an_unrelated_python_is_not_ours(self):
        assert not launcher._looks_like("analyzer", r'"C:\venv\python.exe" manage.py runserver')


# ---------------------------------------------------------------------------
# The overview tells the UI which cards get buttons
# ---------------------------------------------------------------------------

class TestOverviewFlags:
    def test_only_the_python_services_are_controllable(self, monkeypatch):
        keys = ("analyzer", "malapi", "ml", "kafka", "panel")
        monkeypatch.setattr(services, "_specs", lambda: [
            services.Spec(key=k, name=k, description="", host="127.0.0.1", port=1)
            for k in keys])
        monkeypatch.setattr(services, "probe_all", lambda: [
            services.Probe(key=k, name=k, endpoint="http://127.0.0.1:1/") for k in keys])
        monkeypatch.setattr(services, "_record", lambda probes: None)
        monkeypatch.setattr(services.netinfo, "network_facts", lambda h, p: {})

        payload = services._build_overview()
        flags = {s["key"]: s["control"] for s in payload["services"]}
        assert flags == {"analyzer": True, "malapi": True, "ml": True,
                         "kafka": False, "panel": False}


# ---------------------------------------------------------------------------
# The pointer to where a container-backed card is actually controlled
# ---------------------------------------------------------------------------

class TestContainerPointer:
    """A card the panel cannot start must say who can.

    The join is the Containers page's own join, so these pin that the two
    surfaces agree rather than that a hand-written table exists.
    """

    def _specs(self, monkeypatch):
        monkeypatch.setattr(services, "_specs", lambda: [
            services.Spec(key="cyberchef", name="CyberChef API", description="",
                          host="127.0.0.1", port=60001),
            services.Spec(key="cyberchef-ui", name="CyberChef UI", description="",
                          host="127.0.0.1", port=8081),
            services.Spec(key="guacamole", name="Guacamole", description="",
                          host="127.0.0.1", port=61000),
            services.Spec(key="kafka", name="Kafka broker", description="",
                          host="127.0.0.1", port=9092, scheme="tcp", kind="tcp"),
            services.Spec(key="kafka-ui", name="Kafka UI", description="",
                          host="127.0.0.1", port=8080),
            services.Spec(key="analyzer", name="Analyzer API", description="",
                          host="127.0.0.1", port=60025),
        ])

    def _compose(self, monkeypatch):
        monkeypatch.setattr(config, "compose_projects", lambda: [
            {"label": "ia", "file": REPO / "compose.yaml",
             "services": ["cyberchef-api", "cyberchef-ui", "guacamole"]},
            {"label": "kafka-agent", "file": REPO / "kafka-agent" / "docker-compose.yaml",
             "services": ["kafka", "kafka-agent", "kafka-ui"]},
        ])

    def test_a_container_card_names_its_compose_unit(self, monkeypatch):
        self._specs(monkeypatch)
        self._compose(monkeypatch)

        mapped = services.container_index()

        assert mapped["cyberchef"] == {"project": "ia", "service": "cyberchef-api"}
        assert mapped["cyberchef-ui"] == {"project": "ia", "service": "cyberchef-ui"}
        assert mapped["guacamole"] == {"project": "ia", "service": "guacamole"}
        assert mapped["kafka"] == {"project": "kafka-agent", "service": "kafka"}
        assert mapped["kafka-ui"] == {"project": "kafka-agent", "service": "kafka-ui"}

    def test_a_python_service_is_not_called_a_container(self, monkeypatch):
        # The three services this panel runs itself have no compose unit, and
        # a wrong pointer would send the reader looking for a container that
        # does not exist.
        self._specs(monkeypatch)
        self._compose(monkeypatch)

        assert "analyzer" not in services.container_index()

    def test_a_compose_service_with_no_spec_is_ignored(self, monkeypatch):
        # `kafka-agent` is a real compose service and has no Spec, so nothing
        # claims to manage it from the Services page.
        self._specs(monkeypatch)
        self._compose(monkeypatch)

        keys = set(services.container_index())
        assert "kafka-agent" not in keys
        assert len(keys) == 5

    def test_the_overview_carries_the_pointer_per_card(self, monkeypatch):
        self._specs(monkeypatch)
        self._compose(monkeypatch)
        monkeypatch.setattr(services, "probe_all", lambda: [
            services.Probe(key=s.key, name=s.name, endpoint=s.endpoint)
            for s in services._specs()])
        monkeypatch.setattr(services, "_record", lambda probes: None)
        monkeypatch.setattr(services.netinfo, "network_facts", lambda h, p: {})
        monkeypatch.setattr(services, "_control_fields",
                            lambda key: {"control": False, "control_blocked": ""})

        payload = {s["key"]: s for s in services._build_overview()["services"]}

        assert payload["cyberchef"]["container"] == {
            "project": "ia", "service": "cyberchef-api"}
        # A Python service says None rather than an empty object, so the UI has
        # one falsy thing to test.
        assert payload["analyzer"]["container"] is None


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@pytest.fixture()
def client():
    from panel.app import create_app

    return create_app().test_client()


class TestRoutes:
    def test_start_returns_the_launcher_result(self, client, monkeypatch):
        payload = {"ok": True, "key": "analyzer", "action": "start",
                   "code": "started", "detail": "ready in 1.2 s (pid 10)",
                   "pid": 10, "log": None, "ms": 1200.0, "tail": []}
        monkeypatch.setattr(launcher, "control", lambda key, action: payload)

        res = client.post("/api/services/analyzer/start")
        assert res.status_code == 200
        assert res.get_json()["code"] == "started"

    def test_a_refused_start_keeps_its_status_and_reason(self, client,
                                                          monkeypatch):
        payload = {"ok": False, "key": "ml", "action": "start",
                   "code": "blocked", "detail": "ml/model.txt is missing",
                   "pid": None, "log": None, "ms": None, "tail": []}
        monkeypatch.setattr(launcher, "control", lambda key, action: payload)

        res = client.post("/api/services/ml/start")
        assert res.status_code == 409
        assert res.get_json()["detail"] == "ml/model.txt is missing"

    def test_a_bad_action_is_400_before_the_launcher_runs(self, client,
                                                          monkeypatch):
        called: list = []
        monkeypatch.setattr(launcher, "control", lambda k, a: called.append(a))
        res = client.post("/api/services/analyzer/restart")
        assert res.status_code == 400
        assert called == []

    def test_an_unknown_service_is_404(self, client):
        res = client.post("/api/services/kafka/start")
        assert res.status_code == 404
