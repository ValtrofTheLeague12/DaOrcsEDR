"""Endpoint-agent heartbeat registry and prober.

Each endpoint agent runs its own read-only HTTP API (``endpoint_agent.py``),
which means the panel cannot discover agents: there is no central registry and
no push channel. This module owns the small inventory the operator maintains by
hand - a name and a base URL per agent - and probes each agent's heartbeat.

Where it lives
--------------
``%APPDATA%/IAProject/agents.json``, beside the other generated files. It is
operator state, not repository content: which machines this console watches is
per-install, so it is written to the profile and never committed.

What a probe means
------------------
One `GET /api/v1/health` with a short timeout. "Online" only claims that the
agent answered this request; the heartbeat body carries the real detail
(service state, Kafka result, counters, last error). An agent that is saved but
powered off is still saved - removing it because a VM is rebooting would be
hostile.

The agent API is read-only and unauthenticated (0.4.1 and later), so there is
nothing to store here beyond the address. An agent still running 0.4.0 answers
401; that is reported as ``auth`` so the fix is legible.
"""

from __future__ import annotations

import concurrent.futures
import ipaddress
import json
import os
import re
import threading
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from ..core import config

FILE_NAME = "agents.json"
DEFAULT_PORT = 8787
DEFAULT_SCHEME = "http"
PROBE_TIMEOUT = 4.0
MAX_AGENTS = 64
MAX_DETECTIONS = 500
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$")
_HOSTNAME = re.compile(
    r"^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)"
    r"(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$"
)

_LOCK = threading.Lock()


class AgentError(Exception):
    """A request this module refuses, with an HTTP status for the route."""

    def __init__(self, message: str, code: str, status: int) -> None:
        super().__init__(message)
        self.code = code
        self.status = status


def config_path() -> Path:
    return config.appdata_root() / FILE_NAME


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def _normalise_url(value: object) -> str:
    """Return ``http://host:port`` for what the operator typed.

    ``192.168.56.106``, ``192.168.56.106:8787`` and
    ``http://192.168.56.106:8787`` are all accepted, because all three are
    reasonable things to paste. A path, query or credentials are refused: the
    probe appends its own fixed routes, so a base URL with a path can only
    produce a surprising request.
    """
    if not isinstance(value, str) or not value.strip():
        raise AgentError("an agent URL is required", "invalid-url", 400)
    text = value.strip()
    if "://" not in text:
        text = f"{DEFAULT_SCHEME}://{text}"
    parsed = urlparse(text)
    if parsed.scheme not in ("http", "https"):
        raise AgentError("the URL must use http or https", "invalid-url", 400)
    if parsed.username or parsed.password:
        raise AgentError("do not put credentials in the URL", "invalid-url", 400)
    if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise AgentError(
            "use only scheme, host and port (for example "
            "http://192.168.56.106:8787)", "invalid-url", 400)
    host = parsed.hostname
    if not host:
        raise AgentError("the URL has no host", "invalid-url", 400)
    if not _HOSTNAME.match(host):
        raise AgentError(f"not a valid host name or address: {host}",
                         "invalid-url", 400)
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None and (
            literal.is_link_local or literal.is_multicast
            or literal.is_unspecified):
        # An operator can point this form at any host. Link-local addresses
        # (169.254.169.254 is the cloud metadata service) are never an endpoint
        # agent, so refusing them removes the one obviously wrong target.
        raise AgentError(
            f"{host} is not a usable endpoint-agent address", "invalid-url", 400)
    try:
        port = parsed.port or DEFAULT_PORT
    except ValueError as exc:
        raise AgentError("not a valid port", "invalid-url", 400) from exc
    if not 1 <= port <= 65535:
        raise AgentError("the port must be between 1 and 65535",
                         "invalid-url", 400)
    return f"{parsed.scheme}://{host}:{port}"


def _normalise_name(value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise AgentError("an agent name is required", "invalid-name", 400)
    name = value.strip()
    if not _NAME.match(name):
        raise AgentError(
            "the name must start with a letter or digit and use only letters, "
            "digits, spaces, dots, underscores and hyphens", "invalid-name", 400)
    return name


# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------

def _load() -> list[dict]:
    path = config_path()
    try:
        raw = json.loads(path.read_text(encoding="utf-8-sig"))
    except FileNotFoundError:
        return []
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise AgentError(
            f"cannot read {path}: {exc}", "config-error", 500) from exc
    agents = raw.get("agents") if isinstance(raw, dict) else None
    if not isinstance(agents, list):
        raise AgentError(
            f"{path} does not contain an agents list", "config-error", 500)
    clean: list[dict] = []
    for item in agents:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        url = item.get("url")
        if not isinstance(name, str) or not isinstance(url, str):
            continue
        clean.append({"name": name, "url": url})
    return clean


def _save(agents: list[dict]) -> None:
    path = config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"agents": [
        {"name": a["name"], "url": a["url"]}
        for a in agents
    ]}
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    try:
        os.chmod(temp, 0o600)
    except OSError:
        pass
    temp.replace(path)


def list_agents() -> list[dict]:
    """Saved agents, address only."""
    with _LOCK:
        agents = _load()
    return [{"name": item["name"], "url": item["url"]} for item in agents]


def _find(agents: list[dict], name: str) -> dict | None:
    for item in agents:
        if item["name"].lower() == name.lower():
            return item
    return None


def add_agent(name: object, url: object) -> dict:
    """Create or replace one saved agent, keyed by name."""
    clean_name = _normalise_name(name)
    clean_url = _normalise_url(url)
    with _LOCK:
        agents = _load()
        clash = next(
            (item for item in agents
             if item["url"] == clean_url and
             item["name"].lower() != clean_name.lower()),
            None,
        )
        if clash is not None:
            raise AgentError(
                f"{clean_url} is already registered as {clash['name']!r}",
                "duplicate-url", 409)
        existing = _find(agents, clean_name)
        if existing is None:
            if len(agents) >= MAX_AGENTS:
                raise AgentError(
                    f"at most {MAX_AGENTS} agents can be registered",
                    "too-many-agents", 409)
            agents.append({"name": clean_name, "url": clean_url})
        else:
            existing["url"] = clean_url
        _save(agents)
        saved = _find(agents, clean_name)
        assert saved is not None
        return {"name": saved["name"], "url": saved["url"]}


def remove_agent(name: str) -> dict:
    with _LOCK:
        agents = _load()
        target = _find(agents, name)
        if target is None:
            raise AgentError(f"agent not found: {name}", "not-found", 404)
        agents = [item for item in agents if item is not target]
        _save(agents)
    return {"name": target["name"], "url": target["url"]}


# ---------------------------------------------------------------------------
# Probes
# ---------------------------------------------------------------------------

def _request_json(url: str, timeout: float = PROBE_TIMEOUT) -> dict:
    request = urllib.request.Request(url, method="GET")
    request.add_header("Accept", "application/json")
    with urllib.request.urlopen(request, timeout=timeout) as response:
        body = response.read(1024 * 1024)
    data = json.loads(body.decode("utf-8"))
    if not isinstance(data, dict):
        raise ValueError("the response is not a JSON object")
    return data


def _probe_one(entry: dict) -> dict:
    started = datetime.now(timezone.utc)
    base = {
        "name": entry["name"],
        "url": entry["url"],
        "online": False,
        "code": "unreachable",
        "detail": None,
        "latency_ms": None,
        "health": None,
    }
    try:
        health = _request_json(entry["url"].rstrip("/") + "/api/v1/health")
    except urllib.error.HTTPError as exc:
        code = "auth" if exc.code in (401, 403) else "http-error"
        detail = (
            "the agent requires a token, so it is still running 0.4.0 or "
            "older; update it to 0.4.1 or later"
            if code == "auth"
            else f"the agent answered HTTP {exc.code}"
        )
        base.update(code=code, detail=detail)
        return base
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        reason = getattr(exc, "reason", exc)
        base.update(detail=f"cannot reach the agent: {reason}")
        return base
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        base.update(code="invalid-response",
                    detail=f"the agent did not return a heartbeat: {exc}")
        return base

    base.update(
        online=True,
        code="ok",
        latency_ms=round(
            (datetime.now(timezone.utc) - started).total_seconds() * 1000, 1),
        health=health,
    )
    status = health.get("status")
    if isinstance(status, str) and status in ("degraded", "starting", "error",
                                              "failed"):
        base["code"] = "degraded" if status == "degraded" else status
        base["detail"] = f"agent reports status {status!r}"
    return base


def snapshot() -> dict:
    """Probe every saved agent concurrently and return one page-sized payload."""
    entries = _load()
    if not entries:
        return {
            "config_file": str(config_path()),
            "checked_at": _utc_now(),
            "count": 0,
            "online": 0,
            "agents": [],
        }

    # Eight workers keeps a rack of powered-off VMs from serialising four
    # seconds each, without opening one socket per agent at once.
    with concurrent.futures.ThreadPoolExecutor(
            max_workers=min(8, len(entries))) as pool:
        probes = list(pool.map(_probe_one, entries))
    probes.sort(key=lambda item: item["name"].lower())
    return {
        "config_file": str(config_path()),
        "checked_at": _utc_now(),
        "count": len(probes),
        "online": sum(1 for item in probes if item["online"]),
        "agents": probes,
    }


def test_agent(url: object) -> dict:
    """Probe an address without saving it - the form's Test button."""
    return _probe_one({"name": "test", "url": _normalise_url(url)})


def detections(name: str, limit: int) -> dict:
    """Proxy one agent's newest detections for the UI drawer."""
    if not isinstance(limit, int) or isinstance(limit, bool):
        raise AgentError("limit must be a whole number", "invalid-limit", 400)
    limit = max(1, min(limit, MAX_DETECTIONS))
    with _LOCK:
        entry = _find(_load(), name)
    if entry is None:
        raise AgentError(f"agent not found: {name}", "not-found", 404)
    try:
        body = _request_json(
            f"{entry['url'].rstrip('/')}/api/v1/detections?limit={limit}")
    except urllib.error.HTTPError as exc:
        code = "auth" if exc.code in (401, 403) else "http-error"
        raise AgentError(
            "the agent requires a token (0.4.0 or older); update it to 0.4.1 "
            "or later" if code == "auth"
            else f"the agent answered HTTP {exc.code}", code, 502) from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise AgentError(f"cannot reach the agent: {exc}", "unreachable",
                         502) from exc
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise AgentError(f"the agent did not return detections: {exc}",
                         "invalid-response", 502) from exc
    body["agent"] = entry["name"]
    body["url"] = entry["url"]
    return body
