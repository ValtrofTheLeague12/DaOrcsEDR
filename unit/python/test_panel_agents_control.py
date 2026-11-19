"""The panel-side scan-pause proxy: agent_control() posts to one agent.

The fleet card's Terminate/Start agent buttons go through this proxy. The
real agent is a Windows service on another machine, so the tests stub the
HTTP layer and pin the contract: the right URL, a JSON body with the action,
a structured answer, and honest refusals (unknown action/agent locally;
unsupported/unreachable proxies surface as 502s, not exceptions).
"""

from __future__ import annotations

import io
import json
import sys
import urllib.error
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "python"))

from panel.host import agents as af  # noqa: E402

ENTRY = {"name": "win-user", "url": "http://192.168.56.106:8787"}


class FakeResponse(io.BytesIO):
    """urlopen() returns a context manager wrapping the body."""

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


@pytest.fixture(autouse=True)
def address_book(monkeypatch):
    monkeypatch.setattr(af, "_load", lambda: [dict(ENTRY)])
    monkeypatch.setattr(af, "_save", lambda _agents: None)


def _stub_post(monkeypatch, *, body=b'{"ok": true, "action": "stop", "scan_paused": true}',
               exc=None):
    captured = {}

    def fake_urlopen(request, timeout=None):
        captured["url"] = request.full_url
        captured["method"] = request.get_method()
        captured["body"] = bytes(request.data)
        if exc is not None:
            raise exc
        return FakeResponse(body)

    monkeypatch.setattr(af.urllib.request, "urlopen", fake_urlopen)
    return captured


def test_stop_posts_the_action_and_returns_the_state(monkeypatch):
    captured = _stub_post(monkeypatch)
    result = af.agent_control("win-user", "stop")
    assert captured["url"] == ENTRY["url"] + "/api/v1/control"
    assert captured["method"] == "POST"
    assert json.loads(captured["body"]) == {"action": "stop"}
    assert result == {
        "ok": True,
        "action": "stop",
        "agent": "win-user",
        "url": ENTRY["url"],
        "scan_paused": True,
    }


def test_start_round_trips(monkeypatch):
    _stub_post(
        monkeypatch,
        body=b'{"ok": true, "action": "start", "scan_paused": false}',
    )
    result = af.agent_control("win-user", "start")
    assert result["action"] == "start"
    assert result["scan_paused"] is False


def test_unknown_action_is_refused_without_touching_the_network(monkeypatch):
    captured = _stub_post(monkeypatch)
    for bad in ("restart", "", None, {"x": 1}):
        with pytest.raises(af.AgentError) as excinfo:
            af.agent_control("win-user", bad)
        assert excinfo.value.code == "invalid-action"
        assert excinfo.value.status == 400
    assert captured == {}


def test_action_is_case_and_space_insensitive(monkeypatch):
    captured = _stub_post(monkeypatch)
    result = af.agent_control("win-user", "  STOP ")
    assert result["action"] == "stop"
    assert json.loads(captured["body"]) == {"action": "stop"}


def test_unknown_agent_is_refused(monkeypatch):
    _stub_post(monkeypatch)
    with pytest.raises(af.AgentError) as excinfo:
        af.agent_control("no-such-box", "stop")
    assert excinfo.value.code == "not-found"
    assert excinfo.value.status == 404


def test_agent_without_the_route_reports_unsupported(monkeypatch):
    """404/405 from the agent means it predates the control endpoint."""
    _stub_post(
        monkeypatch,
        exc=urllib.error.HTTPError(
            ENTRY["url"], 404, "not found", {}, io.BytesIO(b"{}")),
    )
    with pytest.raises(af.AgentError) as excinfo:
        af.agent_control("win-user", "stop")
    assert excinfo.value.code == "unsupported"
    assert excinfo.value.status == 502
    assert "/api/v1/control" in str(excinfo.value)


def test_unreachable_agent_is_a_502(monkeypatch):
    _stub_post(
        monkeypatch,
        exc=urllib.error.URLError("connection refused"),
    )
    with pytest.raises(af.AgentError) as excinfo:
        af.agent_control("win-user", "stop")
    assert excinfo.value.code == "unreachable"
    assert excinfo.value.status == 502


def test_non_json_answer_is_reported(monkeypatch):
    _stub_post(monkeypatch, body=b"<html>gateway error</html>")
    with pytest.raises(af.AgentError) as excinfo:
        af.agent_control("win-user", "stop")
    assert excinfo.value.code == "invalid-response"
    assert excinfo.value.status == 502
