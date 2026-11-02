"""Endpoint configuration: what the Networking page may change, and what it may not.

The module exists because writing `.env` is the one edit on this panel that can
make the console disagree with the services it is watching. So these tests pin
the invariants rather than the shape of the code:

  * an IP literal must be an address this host actually has - a Tailscale IP
    that is currently down is refused, because it would bind and then fail;
  * the port check is a real bind, and the service's own port is exempt;
  * only the Analyzer API is editable: MalAPI and ML are launched by the
    analyzer at compiled addresses, and a form that moved them would lie;
  * restart stops *before* writing, because stop finds its listener by the
    port in .env;
  * a save that would be shadowed by the process environment says so instead
    of reporting success.

Nothing here writes the real `.env`: `config.ENV_FILE` is redirected to a
temp file for every test that touches it.
"""

from __future__ import annotations

import socket
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "python"))

from panel.core import config  # noqa: E402
from panel.host import endpoints, launcher, services  # noqa: E402


@pytest.fixture()
def env_file(tmp_path, monkeypatch):
    path = tmp_path / ".env"
    path.write_text("SA_API_HOST=127.0.0.1\nSA_API_PORT=60025\nOTHER=keep\n",
                    encoding="utf-8")
    monkeypatch.setattr(config, "ENV_FILE", path)
    return path


@pytest.fixture()
def local_addresses(monkeypatch):
    monkeypatch.setattr(endpoints, "addresses", lambda: [
        {"address": "127.0.0.1", "adapter": "loopback", "family": "IPv4",
         "loopback": True},
        {"address": "192.168.56.1", "adapter": "VBox", "family": "IPv4",
         "loopback": False},
        {"address": "100.95.199.25", "adapter": "Tailscale", "family": "IPv4",
         "loopback": False},
    ])


@pytest.fixture()
def specs(monkeypatch):
    def fake():
        return [
            services.Spec(key="analyzer", name="Analyzer API", description="",
                          host="127.0.0.1", port=60025),
            services.Spec(key="malapi", name="MalAPI", description="",
                          host="127.0.0.1", port=60000),
            services.Spec(key="ml", name="ML scorer", description="",
                          host="127.0.0.1", port=60010),
        ]

    monkeypatch.setattr(services, "_specs", fake)
    monkeypatch.setattr(services, "port_of", lambda key: next(
        (s.port for s in fake() if s.key == key), 0))
    return fake


# ---------------------------------------------------------------------------
# Interfaces
# ---------------------------------------------------------------------------

class TestAddresses:
    def test_loopback_and_real_interfaces_are_offered(self):
        found = {a["address"] for a in endpoints.addresses()}
        assert "127.0.0.1" in found
        assert "::1" in found
        # This host has Tailscale in .env; when it is up, it must be offered.
        assert any(a["family"] == "IPv4" and not a["loopback"] for a in
                   endpoints.addresses())

    def test_link_local_ipv6_is_not_offered(self):
        # fe80:: needs a scope id, so offering it invites an unusable choice.
        assert not [a for a in endpoints.addresses()
                    if a["address"].lower().startswith("fe80")]

    def test_loopback_comes_first(self):
        assert endpoints.addresses()[0]["address"] == "127.0.0.1"


# ---------------------------------------------------------------------------
# Host and port validation
# ---------------------------------------------------------------------------

class TestHost:
    def test_loopback_and_localhost_are_loopback(self, local_addresses):
        for value in ("127.0.0.1", "::1", "localhost"):
            result = endpoints.check_host(value)
            assert result["ok"], value
            assert result["loopback"], value

    def test_an_address_on_an_interface_is_accepted(self, local_addresses):
        result = endpoints.check_host("192.168.56.1")
        assert result["ok"] is True
        assert result["loopback"] is False

    def test_an_address_this_host_does_not_have_is_refused(self,
                                                           local_addresses):
        result = endpoints.check_host("10.9.9.9")
        assert result["ok"] is False
        assert result["code"] == "invalid-host"
        assert "not on any interface" in result["detail"]

    def test_a_hostname_is_accepted_but_not_verified(self, local_addresses):
        result = endpoints.check_host("this-box.internal")
        assert result["ok"] is True
        assert "not checked" in result["detail"]

    def test_junk_is_refused(self, local_addresses):
        for value in ("", "not a host!", "a/b"):
            assert endpoints.check_host(value)["ok"] is False


class TestPort:
    def test_another_services_port_is_refused_by_name(self, specs,
                                                      local_addresses):
        result = endpoints.check_port(60000, "127.0.0.1", "analyzer")
        assert result["ok"] is False
        assert result["code"] == "port-owned"
        assert "MalAPI" in result["detail"]

    def test_out_of_range_and_non_numeric_are_refused(self, specs):
        for value in (0, 70000, "abc", ""):
            assert endpoints.check_port(value, "127.0.0.1")["ok"] is False

    def test_the_current_port_is_exempt_from_the_bind_test(self, specs,
                                                           monkeypatch):
        # A bind test on the service's own port would always fail while it is
        # running, which would make "keep the port, change the host" impossible.
        monkeypatch.setattr(endpoints, "_can_bind",
                            lambda host, port: "should not be called")
        result = endpoints.check_port(60025, "192.168.56.1", "analyzer")
        assert result["ok"] is True

    def test_a_free_port_is_accepted(self, specs, monkeypatch):
        monkeypatch.setattr(endpoints, "_can_bind", lambda host, port: "")
        result = endpoints.check_port(60030, "127.0.0.1", "analyzer")
        assert result["ok"] is True
        assert result["detail"] == "free now"

    def test_a_held_port_names_the_process(self, specs, monkeypatch):
        monkeypatch.setattr(endpoints, "_can_bind", lambda host, port: "in use")
        monkeypatch.setattr(launcher, "listeners", lambda port: [
            {"pid": 77, "name": "node.exe", "command": "vite"}])
        result = endpoints.check_port(60030, "127.0.0.1", "analyzer")
        assert result["ok"] is False
        assert result["code"] == "port-held"
        assert "pid 77" in result["detail"]

    def test_the_bind_uses_the_address_the_launcher_would_use(self, specs,
                                                              monkeypatch):
        seen = {}

        def can_bind(host, port):
            seen["bind"] = launcher.bind_addr(host)
            return ""

        monkeypatch.setattr(endpoints, "_can_bind", can_bind)
        endpoints.check_port(60030, "192.168.56.1", "analyzer")
        # A non-loopback host is bound as 0.0.0.0, so the test must be too.
        assert seen["bind"] == "0.0.0.0"


# ---------------------------------------------------------------------------
# Applying an endpoint
# ---------------------------------------------------------------------------

class TestApply:
    def test_malapi_and_ml_are_not_editable(self, env_file, specs):
        for key in ("malapi", "ml", "kafka"):
            with pytest.raises(endpoints.EndpointError) as info:
                endpoints.apply(key, "127.0.0.1", 60000, restart=False)
            assert info.value.status == 404

    def test_an_invalid_host_writes_nothing(self, env_file, specs,
                                            local_addresses, monkeypatch):
        monkeypatch.setattr(endpoints, "_can_bind", lambda h, p: "")
        before = env_file.read_text(encoding="utf-8")

        result = endpoints.apply("analyzer", "10.1.2.3", 60030, restart=False)

        assert result["ok"] is False
        assert result["code"] == "invalid-host"
        assert env_file.read_text(encoding="utf-8") == before
        assert not (env_file.parent / ".env.bak").exists()

    def test_a_save_rewrites_only_its_two_keys(self, env_file, specs,
                                               local_addresses, monkeypatch):
        monkeypatch.setattr(endpoints, "_can_bind", lambda h, p: "")

        result = endpoints.apply("analyzer", "192.168.56.1", 60030,
                                 restart=False)

        assert result["ok"] is True
        assert result["code"] == "saved"
        text = env_file.read_text(encoding="utf-8")
        assert "SA_API_HOST=192.168.56.1" in text
        assert "SA_API_PORT=60030" in text
        assert "OTHER=keep" in text
        # One backup, and it is the file from before the change.
        backup = env_file.parent / ".env.bak"
        assert "SA_API_HOST=127.0.0.1" in backup.read_text(encoding="utf-8")

    def test_a_second_save_does_not_overwrite_the_backup(self, env_file, specs,
                                                         local_addresses,
                                                         monkeypatch):
        monkeypatch.setattr(endpoints, "_can_bind", lambda h, p: "")
        endpoints.apply("analyzer", "192.168.56.1", 60030, restart=False)
        endpoints.apply("analyzer", "192.168.56.1", 60031, restart=False)

        backup = env_file.parent / ".env.bak"
        assert "SA_API_PORT=60025" in backup.read_text(encoding="utf-8")

    def test_unchanged_is_not_a_write(self, env_file, specs, local_addresses):
        result = endpoints.apply("analyzer", "127.0.0.1", 60025, restart=False)
        assert result["code"] == "unchanged"
        assert not (env_file.parent / ".env.bak").exists()

    def test_an_off_loopback_save_says_it_widens_the_bind(self, env_file,
                                                         specs,
                                                         local_addresses,
                                                         monkeypatch):
        monkeypatch.setattr(endpoints, "_can_bind", lambda h, p: "")
        result = endpoints.apply("analyzer", "192.168.56.1", 60030,
                                 restart=False)
        assert any("0.0.0.0" in w for w in result["warnings"])
        assert any("no authentication" in w for w in result["warnings"])

    def test_loopback_has_no_warnings(self, env_file, specs, local_addresses,
                                      monkeypatch):
        monkeypatch.setattr(endpoints, "_can_bind", lambda h, p: "")
        result = endpoints.apply("analyzer", "127.0.0.1", 60030, restart=False)
        assert result["warnings"] == []

    def test_the_service_is_stopped_before_the_file_is_written(self, env_file,
                                                               specs,
                                                               local_addresses,
                                                               monkeypatch):
        monkeypatch.setattr(endpoints, "_can_bind", lambda h, p: "")
        calls = []

        def probe_one(key):
            return services.Probe(key=key, name="Analyzer API",
                                  endpoint="http://127.0.0.1:60025/health",
                                  up=True)

        def control(key, action):
            calls.append((action,
                          env_file.read_text(encoding="utf-8").splitlines()))
            return {"ok": True, "detail": f"{action} ok"}

        monkeypatch.setattr(services, "probe_one", probe_one)
        monkeypatch.setattr(launcher, "control", control)
        monkeypatch.setattr(services, "invalidate", lambda: None)

        result = endpoints.apply("analyzer", "127.0.0.1", 60030, restart=True)

        assert result["ok"] is True
        assert [c[0] for c in calls] == ["stop", "start"]
        # Stop saw the OLD port in .env; start saw the new one.
        assert "SA_API_PORT=60025" in calls[0][1]
        assert "SA_API_PORT=60030" in calls[1][1]
        assert result["restart"]["ok"] is True

    def test_a_failed_stop_aborts_the_save(self, env_file, specs,
                                           local_addresses, monkeypatch):
        monkeypatch.setattr(endpoints, "_can_bind", lambda h, p: "")
        monkeypatch.setattr(services, "probe_one", lambda key: services.Probe(
            key=key, name="Analyzer API", endpoint="", up=True))
        monkeypatch.setattr(launcher, "control", lambda key, action: {
            "ok": False, "detail": "pid 9 is not ours"})

        result = endpoints.apply("analyzer", "127.0.0.1", 60030, restart=True)

        assert result["ok"] is False
        assert result["code"] == "stop-failed"
        assert "SA_API_PORT=60025" in env_file.read_text(encoding="utf-8")

    def test_a_shadowed_key_is_saved_but_not_restarted(self, env_file, specs,
                                                       local_addresses,
                                                       monkeypatch):
        monkeypatch.setattr(endpoints, "_can_bind", lambda h, p: "")
        monkeypatch.setenv("SA_API_PORT", "60025")
        monkeypatch.setattr(services, "probe_one", lambda key: services.Probe(
            key=key, name="Analyzer API", endpoint="", up=True))
        called = []
        monkeypatch.setattr(launcher, "control",
                            lambda key, action: called.append(action))

        result = endpoints.apply("analyzer", "127.0.0.1", 60030, restart=True)

        assert result["ok"] is True
        assert result["code"] == "saved-shadowed"
        assert result["shadowed"] == ["SA_API_PORT"]
        assert called == []
        assert "SA_API_PORT=60030" in env_file.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# The endpoint agent
# ---------------------------------------------------------------------------

class TestBrokerParsing:
    def test_host_port_forms(self):
        assert endpoints._split_broker("192.168.56.1:9092") == (
            "192.168.56.1", 9092)
        assert endpoints._split_broker("[::1]:9092") == ("::1", 9092)

    def test_malformed_forms(self):
        for value in ("", "no-port", "host:", "host:notaport", "h:0",
                      "h:70000", "a:b:c"):
            assert endpoints._split_broker(value) is None


class TestAgent:
    def test_a_broker_on_loopback_is_warned_about(self, local_addresses,
                                                  monkeypatch):
        monkeypatch.setattr(socket, "create_connection",
                            lambda *a, **k: (_ for _ in ()).throw(
                                OSError(10061, "refused")))
        result = endpoints.check_agent("127.0.0.1:9092", "analysis-artifacts")
        assert result["ok"] is True
        assert any("OWN machine" in w for w in result["warnings"])

    def test_an_unreachable_broker_is_a_warning_not_a_refusal(self,
                                                              local_addresses,
                                                              monkeypatch):
        monkeypatch.setattr(socket, "create_connection",
                            lambda *a, **k: (_ for _ in ()).throw(
                                OSError(10061, "refused")))
        result = endpoints.check_agent("192.168.56.1:9092",
                                       "analysis-artifacts")
        assert result["ok"] is True
        assert any("nothing accepted" in w for w in result["warnings"])

    def test_a_reachable_broker_has_no_reachability_warning(self,
                                                            local_addresses,
                                                            monkeypatch):
        class Conn:
            def __enter__(self): return self
            def __exit__(self, *a): return False

        monkeypatch.setattr(socket, "create_connection",
                            lambda *a, **k: Conn())
        result = endpoints.check_agent("192.168.56.1:9092",
                                       "analysis-artifacts")
        assert not any("nothing accepted" in w for w in result["warnings"])

    def test_a_foreign_address_is_an_error(self, local_addresses):
        result = endpoints.check_agent("10.9.9.9:9092", "analysis-artifacts")
        assert result["ok"] is False
        assert any("not on any interface" in e for e in result["errors"])

    def test_a_bad_topic_is_an_error(self, local_addresses, monkeypatch):
        monkeypatch.setattr(socket, "create_connection",
                            lambda *a, **k: None)
        result = endpoints.check_agent("192.168.56.1:9092", "bad topic!")
        assert result["ok"] is False
        assert any("topic" in e for e in result["errors"])

    def test_a_non_default_port_warns_about_the_compose_publish(
            self, local_addresses, monkeypatch):
        class Conn:
            def __enter__(self): return self
            def __exit__(self, *a): return False

        monkeypatch.setattr(socket, "create_connection",
                            lambda *a, **k: Conn())
        result = endpoints.check_agent("192.168.56.1:9093",
                                       "analysis-artifacts")
        assert any("compose file publishes 9092" in w
                   for w in result["warnings"])

    def test_the_template_keeps_the_rest_of_the_example(self, monkeypatch):
        monkeypatch.setattr(endpoints, "_agent_example", lambda: {
            "brokers": "192.168.56.1:9092",
            "topic": "analysis-artifacts",
            "doc": {"watch_dirs": ["%PUBLIC%\\Downloads"],
                    "kafka": {"producer_config": {"x": 1}}},
            "path": None,
        })
        doc = endpoints.agent_template("10.0.0.5:9092", "other")
        assert doc["watch_dirs"] == ["%PUBLIC%\\Downloads"]
        assert doc["kafka"]["bootstrap_servers"] == "10.0.0.5:9092"
        assert doc["kafka"]["topic"] == "other"
        assert doc["kafka"]["producer_config"] == {"x": 1}

    def test_saving_an_invalid_agent_config_writes_nothing(self, env_file,
                                                           local_addresses):
        before = env_file.read_text(encoding="utf-8")
        result = endpoints.save_agent("10.9.9.9:9092", "topic")
        assert result["ok"] is False
        assert env_file.read_text(encoding="utf-8") == before

    def test_saving_a_valid_agent_config_writes_both_keys(
            self, env_file, local_addresses, monkeypatch):
        monkeypatch.setattr(endpoints, "_agent_example", lambda: {
            "brokers": "", "topic": "", "doc": None, "path": None})

        class Conn:
            def __enter__(self): return self
            def __exit__(self, *a): return False

        monkeypatch.setattr(socket, "create_connection",
                            lambda *a, **k: Conn())
        result = endpoints.save_agent("192.168.56.1:9092", "analysis-artifacts")

        assert result["ok"] is True
        text = env_file.read_text(encoding="utf-8")
        assert "AGENT_KAFKA_BROKERS=192.168.56.1:9092" in text
        assert "AGENT_KAFKA_TOPIC=analysis-artifacts" in text
        assert result["agent"]["transport"] == "kafka"


# ---------------------------------------------------------------------------
# Snapshot and routes
# ---------------------------------------------------------------------------

class TestSnapshot:
    def test_only_the_analyzer_is_editable_and_the_rest_explain_why(
            self, env_file, specs, local_addresses, monkeypatch):
        monkeypatch.setattr(endpoints, "agent_snapshot", lambda: {"brokers": ""})
        snap = endpoints.snapshot()

        assert [e["key"] for e in snap["editable"]] == ["analyzer"]
        fixed = {f["key"]: f for f in snap["fixed"]}
        assert set(fixed) == {"malapi", "ml"}
        assert fixed["malapi"]["host"] == "127.0.0.1"
        assert fixed["malapi"]["port"] == 60000
        assert "src/main.cpp" in fixed["malapi"]["reason"]
        # The configured value is still reported, so the page can show the
        # difference between "what .env says" and "what the analyzer uses".
        assert fixed["ml"]["configured"]["port"] == 60010


@pytest.fixture()
def client():
    from panel.app import create_app

    return create_app().test_client()


class TestRoutes:
    def test_the_snapshot_route_returns_the_three_sections(self, client,
                                                           monkeypatch):
        monkeypatch.setattr(endpoints, "snapshot", lambda: {
            "editable": [], "fixed": [], "addresses": [], "agent": {}})

        res = client.get("/api/network/endpoints")

        assert res.status_code == 200
        assert set(res.get_json()) == {"editable", "fixed", "addresses", "agent"}

    def test_an_invalid_port_keeps_its_code_and_status(self, client,
                                                       monkeypatch):
        monkeypatch.setattr(endpoints, "apply", lambda key, host, port, restart: {
            "ok": False, "key": key, "code": "invalid-port",
            "detail": "port not available"})

        res = client.put("/api/network/endpoints/analyzer",
                         json={"host": "127.0.0.1", "port": 1})

        assert res.status_code == 400
        assert res.get_json()["code"] == "invalid-port"

    def test_a_fixed_endpoint_is_404(self, client):
        res = client.put("/api/network/endpoints/malapi",
                         json={"host": "127.0.0.1", "port": 60000})
        assert res.status_code == 404

    def test_a_missing_body_is_400(self, client):
        res = client.put("/api/network/endpoints/analyzer", json={"host": "x"})
        assert res.status_code == 400

    def test_agent_invalid_is_400_and_valid_is_200(self, client, monkeypatch):
        monkeypatch.setattr(endpoints, "save_agent", lambda b, t: {
            "ok": False, "code": "invalid-agent", "detail": "bad"})
        assert client.put("/api/network/agent",
                          json={"brokers": "x", "topic": "t"}).status_code == 400

        monkeypatch.setattr(endpoints, "save_agent", lambda b, t: {
            "ok": True, "code": "saved", "detail": "saved",
            "agent": {"template": {"kafka": {}}}})
        res = client.put("/api/network/agent",
                         json={"brokers": "192.168.56.1:9092",
                               "topic": "analysis-artifacts"})
        assert res.status_code == 200
        assert res.get_json()["ok"] is True
