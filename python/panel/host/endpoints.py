"""Service endpoint configuration - the panel's half of `admin-terminal/netcfg.py`.

One service endpoint is editable here, not three, and that is deliberate:

  * the **Analyzer API** (`server.py`) reads `SA_API_HOST` / `SA_API_PORT` from
    `.env` itself, so moving it moves the thing the panel probes;
  * **MalAPI** and the **ML scorer** are launched by the analyzer at compiled
    addresses (`http://127.0.0.1:60000` and `:60010`, `src/main.cpp`). The
    `.env` values only move the standalone copy the panel starts by hand, so a
    form that offered to move them would be describing a change the next
    analysis ignores. They are reported, with that sentence, and not editable.

Validation is the point of the module, not the writing:

  * an IP literal must be on one of this host's interfaces (`ifaddr`), because
    saving an address Tailscale is not currently carrying guarantees a bind
    that cannot work;
  * the port must be inside 1-65535, must not be another watched service's, and
    must actually be bindable - a real `bind()`, not "netstat said free".

Nothing is written until every check passes, and `.env.bak` keeps the previous
copy the first time the panel touches the file.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import shutil
import socket
from pathlib import Path

from ..core import config
from . import launcher, services

# The only endpoint this page may move. See the module docstring for why the
# other two are not here - it is a fact about the analyzer, not a missing rule.
EDITABLE = ("analyzer",)

ENV_KEYS = {"analyzer": ("SA_API_HOST", "SA_API_PORT")}

# Where the analyzer launches its own copies. Kept next to the Specs rather than
# inferred from .env, because that is exactly the mistake this page prevents.
FIXED = {
    "malapi": {
        "name": "MalAPI",
        "host": "127.0.0.1",
        "port": 60000,
        "env": ("MALAPI_HOST", "MALAPI_PORT"),
        "reason": "Each analysis run starts its own copy at this address "
                  "(src/main.cpp), so it is fixed here.",
    },
    "ml": {
        "name": "ML scorer",
        "host": "127.0.0.1",
        "port": 60010,
        "env": ("ML_HOST", "ML_PORT"),
        "reason": "Each analysis run starts its own copy at this address "
                  "(src/main.cpp), so it is fixed here.",
    },
}

# Hostnames are accepted, as in the terminal: the panel cannot prove what a
# name resolves to, and pretending a DNS name must be local would break the
# legitimate "bind me on this box's own name" case.
_HOSTNAME = re.compile(
    r"^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)"
    r"(\.[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)*$"
)
_TOPIC = re.compile(r"^[A-Za-z0-9._-]{1,249}$")

# HTTP status per outcome, mirroring launcher.HTTP_STATUS so a caller sees the
# same vocabulary on both controls.
HTTP_STATUS = {
    "unknown-service": 404,
    "invalid-host": 400,
    "invalid-port": 400,
    "port-owned": 400,
    "invalid-brokers": 400,
    "invalid-topic": 400,
    "port-held": 409,
    "stop-failed": 409,
    "saved": 200,
    "saved-shadowed": 200,
    "unchanged": 200,
}


class EndpointError(Exception):
    """A request this module refuses outright - unknown key, bad body."""

    def __init__(self, message: str, code: str, status: int) -> None:
        super().__init__(message)
        self.code = code
        self.status = status


# ---------------------------------------------------------------------------
# Interfaces
# ---------------------------------------------------------------------------

def addresses() -> list[dict]:
    """Every address a service could be bound to on this host.

    `ifaddr` is already a dependency (the ClamAV TCP transport uses it), and it
    is the same lister on Windows and POSIX, so the choices offered here match
    the ones the rest of the panel already trusts.

    Link-local IPv6 is dropped: `fe80::` cannot be dialled without a scope id,
    so offering it would be offering a typo. Loopback is listed first because it
    is the safe default and the one most edits want.
    """
    out: list[dict] = [
        {"address": "127.0.0.1", "adapter": "loopback", "family": "IPv4",
         "loopback": True},
        {"address": "::1", "adapter": "loopback", "family": "IPv6",
         "loopback": True},
    ]
    try:
        import ifaddr  # noqa: PLC0415 - optional at import time, like netinfo
        adapters = ifaddr.get_adapters()
    except Exception:  # noqa: BLE001 - an unreadable lister is not a 500
        return out

    seen = {entry["address"] for entry in out}
    for adapter in adapters:
        for ip in adapter.ips:
            raw = ip.ip
            address = raw[0] if isinstance(raw, tuple) else raw
            if not isinstance(address, str) or address in seen:
                continue
            try:
                parsed = ipaddress.ip_address(address)
            except ValueError:
                continue
            if parsed.is_link_local:
                continue
            seen.add(address)
            out.append({
                "address": address,
                "adapter": adapter.nice_name,
                "family": f"IPv{parsed.version}",
                "loopback": parsed.is_loopback,
            })

    # Loopback, then IPv4, then IPv6 - each group alphabetical by adapter.
    out[2:] = sorted(out[2:], key=lambda a: (a["family"] != "IPv4", a["adapter"]))
    return out


def _local_addresses() -> set[str]:
    return {entry["address"] for entry in addresses()}


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def check_host(value: str) -> dict:
    """Is this a usable bind host? Returns {ok, detail, code, loopback}."""
    host = (value or "").strip()
    if not host:
        return {"ok": False, "code": "invalid-host", "detail": "empty",
                "loopback": False}
    if host == "localhost":
        return {"ok": True, "code": "", "detail": "localhost", "loopback": True}

    try:
        parsed = ipaddress.ip_address(host)
    except ValueError:
        if _HOSTNAME.match(host):
            return {"ok": True, "code": "",
                    "detail": "hostname - not checked against local interfaces",
                    "loopback": False}
        return {"ok": False, "code": "invalid-host",
                "detail": "not an IP address, 'localhost' or a valid hostname",
                "loopback": False}

    if parsed.is_loopback:
        return {"ok": True, "code": "", "detail": "loopback", "loopback": True}
    if host not in _local_addresses():
        return {
            "ok": False, "code": "invalid-host",
            "detail": (f"{host} is not on any interface of this host - pick an "
                       f"address from the list, or bring the adapter up first"),
            "loopback": False,
        }
    return {"ok": True, "code": "", "detail": "on a local interface",
            "loopback": False}


def _port_owner(port: int, own_key: str) -> str:
    """The name of the watched service that already uses `port`, or ''."""
    for spec in services._specs():
        if spec.key != own_key and spec.port == port:
            return spec.name
    return ""


def _can_bind(host: str, port: int) -> str:
    """Bind `bind_addr(host):port` for real. '' on success, the reason on failure.

    A bind is the only check that answers the question: a listener on 0.0.0.0
    conflicts with every address, and a socket in TIME_WAIT may or may not. No
    SO_REUSEADDR is set, so Windows' default exclusive bind gives the honest
    answer.
    """
    bind = launcher.bind_addr(host)
    family = socket.AF_INET6 if ":" in bind else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    try:
        sock.bind((bind, port))
    except OSError as exc:
        return exc.strerror or str(exc)
    finally:
        sock.close()
    return ""


def check_port(value, host: str, own_key: str = "analyzer") -> dict:
    """Is this port usable for `own_key` on `host`? {ok, code, detail}."""
    try:
        port = int(value)
    except (TypeError, ValueError):
        return {"ok": False, "code": "invalid-port", "detail": "not a number"}
    if not 1 <= port <= 65535:
        return {"ok": False, "code": "invalid-port",
                "detail": "out of range 1-65535"}

    owner = _port_owner(port, own_key)
    if owner:
        return {"ok": False, "code": "port-owned",
                "detail": f"port {port} belongs to {owner}"}

    current = services.port_of(own_key)
    if port == current:
        # The service is (or was) listening there. A bind test would fail on
        # its own socket and block the one edit that needs no rebind.
        return {"ok": True, "code": "", "detail": "the current port"}

    why = _can_bind(host, port)
    if why:
        who = launcher.listeners(port)
        held = "; ".join(f"pid {p['pid']} ({p['name']})" for p in who)
        detail = f"port {port} cannot be bound on {launcher.bind_addr(host)}"
        if held:
            detail += f" - held by {held}"
        else:
            detail += f" - {why}"
        return {"ok": False, "code": "port-held", "detail": detail}
    return {"ok": True, "code": "", "detail": "free now"}


# ---------------------------------------------------------------------------
# Snapshot
# ---------------------------------------------------------------------------

def _current(key: str) -> dict:
    host_key, port_key = ENV_KEYS[key]
    return {"host": config.setting(host_key, "127.0.0.1"),
            "port": config.setting_int(port_key, 60025)}


def _warnings(host: str) -> list[str]:
    """What else changes when this host is saved. Empty for loopback."""
    if check_host(host).get("loopback"):
        return []
    bind = launcher.bind_addr(host)
    return [
        f"binds {bind}, not only {host}: every interface can reach it",
        "the Analyzer API has no authentication - anyone who can route here "
        "can upload samples and start analyses",
    ]


def snapshot() -> dict:
    """Everything the Networking > Configuration tab draws."""
    editable = []
    for key in EDITABLE:
        host_key, port_key = ENV_KEYS[key]
        spec = services.spec_for(key)
        current = _current(key)
        editable.append({
            "key": key,
            "name": spec.name if spec else key,
            "host": current["host"],
            "port": current["port"],
            "env": {"host": host_key, "port": port_key},
            "bind": launcher.bind_addr(current["host"]),
            "warnings": _warnings(current["host"]),
        })

    fixed = []
    for key, rule in FIXED.items():
        host_key, port_key = rule["env"]
        spec = services.spec_for(key)
        fixed.append({
            "key": key,
            "name": rule["name"],
            "host": rule["host"],
            "port": rule["port"],
            "configured": {
                "host": config.setting(host_key, rule["host"]),
                "port": config.setting_int(port_key, rule["port"]),
            },
            "ui_url": (spec.base + spec.ui_path) if spec and spec.ui_path else None,
            "reason": rule["reason"],
        })

    return {
        "editable": editable,
        "fixed": fixed,
        "addresses": addresses(),
        "agent": agent_snapshot(),
        "env_file": str(config.ENV_FILE),
    }


# ---------------------------------------------------------------------------
# Applying an endpoint
# ---------------------------------------------------------------------------

def _rewrite(values: dict[str, str]) -> Path:
    """Replace the named lines in .env, keeping every other line intact.

    Read with utf-8-sig (the file may carry a BOM) and written with LF so a
    panel edit and a terminal edit produce the same file. `.env.bak` is written
    once, before the first change - a second edit must not overwrite the
    original with an already-modified copy.
    """
    env_file = config.ENV_FILE
    lines: list[str] = []
    if env_file.is_file():
        lines = env_file.read_text(encoding="utf-8-sig").splitlines()

    out: list[str] = []
    seen: set[str] = set()
    for line in lines:
        stripped = line.strip()
        key = ""
        if stripped and not stripped.startswith("#") and "=" in stripped:
            key = stripped.split("=", 1)[0].strip()
        if key in values:
            out.append(f"{key}={values[key]}")
            seen.add(key)
        else:
            out.append(line)
    for key, value in values.items():
        if key not in seen:
            out.append(f"{key}={value}")

    backup = env_file.with_name(env_file.name + ".bak")
    if env_file.is_file() and not backup.exists():
        shutil.copy2(env_file, backup)

    env_file.parent.mkdir(parents=True, exist_ok=True)
    with open(env_file, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(out) + "\n")
    return env_file


def _result(ok: bool, key: str, code: str, detail: str, **extra) -> dict:
    return {"ok": ok, "key": key, "code": code, "detail": detail, **extra}


def apply(key: str, host: str, port, restart: bool = True) -> dict:
    """Validate, then write the endpoint. Restart *before* writing, if asked.

    The order matters: `launcher.stop()` finds the listener by the port in
    `.env`. Write first and the old port is no longer in the file, so stop
    would look on the new port, find nothing, and leave the old process running
    while the panel points somewhere else.

    Refusing to restart does not roll back the file: the save is a config edit,
    the restart is a convenience. It does refuse to write at all when a stop
    fails, because that leaves the service running on an address the config no
    longer names.
    """
    if key not in EDITABLE:
        raise EndpointError(f"no editable endpoint for '{key}'",
                            "unknown-service", 404)
    host_key, port_key = ENV_KEYS[key]
    previous = _current(key)

    host_check = check_host(str(host))
    if not host_check["ok"]:
        return _result(False, key, host_check["code"], host_check["detail"],
                       previous=previous)

    port_check = check_port(port, str(host), key)
    if not port_check["ok"]:
        return _result(False, key, port_check["code"], port_check["detail"],
                       previous=previous)

    host = str(host).strip()
    port = int(port)
    if host == previous["host"] and port == previous["port"]:
        return _result(True, key, "unchanged",
                       f"{key} is already {host}:{port}", previous=previous,
                       changed=None, warnings=_warnings(host),
                       shadowed=[], restart=None)

    # Process env beats .env in config.setting(). If the panel was started with
    # SA_API_PORT exported, writing the file changes nothing this process sees,
    # and restarting would bind the child on the new port while the panel keeps
    # probing the old one. Save, say so, do not restart.
    shadowed = [name for name in (host_key, port_key) if name in os.environ]

    was_up = False
    if not shadowed and restart:
        probe = services.probe_one(key)
        was_up = bool(probe and probe.up)
        if was_up:
            stopped = launcher.control(key, "stop")
            if not stopped["ok"]:
                return _result(False, key, "stop-failed",
                               "could not stop the running service, so the "
                               f"endpoint was not changed: {stopped['detail']}",
                               previous=previous, stop=stopped)

    _rewrite({host_key: host, port_key: port})
    services.invalidate()

    restarted = None
    if was_up:
        restarted = launcher.control(key, "start")

    warnings = _warnings(host)
    code = "saved-shadowed" if shadowed else "saved"
    detail = f"{key} endpoint set to {host}:{port}"
    if shadowed:
        detail += (f" - but {', '.join(shadowed)} is set in this process's "
                   "environment, which takes precedence until the panel is "
                   "restarted")
    elif was_up and restarted:
        detail += (f"; restarted: {restarted['detail']}"
                   if restarted["ok"]
                   else f"; restart failed: {restarted['detail']}")

    return _result(True, key, code, detail, previous=previous,
                   changed={"host": host, "port": port}, warnings=warnings,
                   shadowed=shadowed, restart=restarted)


# ---------------------------------------------------------------------------
# The endpoint agent
# ---------------------------------------------------------------------------
#
# The agent is installed on other machines and reads agent.json beside its exe.
# There is no channel to push a config to it, so this section owns what the
# panel can honestly own: the broker address the agent should be pointed at,
# the topic, validation of both, and a template to copy across.
#
# Kafka is the agent's only transport (`agent/endpoint_agent.py` imports
# confluent_kafka and publishes chunks). A "communication method" picker would
# invent a second implementation, so the page says what is true instead.

AGENT_BROKERS = "AGENT_KAFKA_BROKERS"
AGENT_TOPIC = "AGENT_KAFKA_TOPIC"
_AGENT_FALLBACK = {"brokers": "192.168.56.1:9092", "topic": "analysis-artifacts"}


def _agent_example() -> dict:
    """bootstrap_servers / topic from agent/agent.example.json, when present."""
    path = config.REPO / "agent" / "agent.example.json"
    try:
        doc = json.loads(path.read_text(encoding="utf-8-sig"))
        kafka = doc.get("kafka") or {}
        return {
            "brokers": str(kafka.get("bootstrap_servers")
                           or _AGENT_FALLBACK["brokers"]),
            "topic": str(kafka.get("topic") or _AGENT_FALLBACK["topic"]),
            "doc": doc,
            "path": str(path),
        }
    except (OSError, ValueError):
        return {"brokers": _AGENT_FALLBACK["brokers"],
                "topic": _AGENT_FALLBACK["topic"], "doc": None, "path": None}


def _split_broker(value: str) -> tuple[str, int] | None:
    """host:port from one bootstrap entry. IPv6 is expected as [addr]:port."""
    value = value.strip()
    if not value:
        return None
    if value.startswith("["):
        end = value.find("]")
        if end == -1 or not value[end + 1:].startswith(":"):
            return None
        host, raw_port = value[1:end], value[end + 2:]
    else:
        if value.count(":") != 1:
            return None
        host, raw_port = value.rsplit(":", 1)
    try:
        port = int(raw_port)
    except ValueError:
        return None
    if not 1 <= port <= 65535:
        return None
    return host, port


def check_agent(brokers: str, topic: str) -> dict:
    """Syntax, host reachability of the broker, and the topic. Never a 500."""
    errors: list[str] = []
    warnings: list[str] = []

    entries = [part for part in (brokers or "").split(",") if part.strip()]
    if not entries:
        errors.append("a broker address is required (host:port)")

    parsed = []
    for entry in entries:
        split = _split_broker(entry)
        if split is None:
            errors.append(f"'{entry.strip()}' is not host:port")
            continue
        host, port = split
        check = check_host(host)
        if not check["ok"]:
            errors.append(f"broker {host}: {check['detail']}")
            continue
        if host in ("127.0.0.1", "::1", "localhost"):
            warnings.append(
                f"{host} is the broker on the agent's OWN machine - endpoints "
                "elsewhere will not reach this host")
        parsed.append((host, port))

    if not _TOPIC.match((topic or "").strip()):
        errors.append("topic must be 1-249 characters of A-Z a-z 0-9 . _ -")

    compose_port = config.kafka_port()
    if parsed and all(port != compose_port for _, port in parsed):
        warnings.append(
            f"the kafka compose file publishes {compose_port}; another port "
            "needs compose.yaml edited before the broker listens there")

    # Reachability is a warning, not an error: a broker that is stopped is a
    # valid thing to configure, and a form that refuses it cannot be used
    # during setup - which is when it is most needed.
    if not errors:
        host, port = parsed[0]
        try:
            with socket.create_connection((host, port), timeout=1.5):
                pass
        except OSError as exc:
            warnings.append(f"nothing accepted a connection on {host}:{port} "
                            f"({exc.strerror or exc}) - the broker may be "
                            "stopped")
    else:
        warnings.append("reachability was not checked because the address "
                        "is not valid")

    return {"ok": not errors, "errors": errors, "warnings": warnings,
            "brokers": parsed, "compose_port": compose_port}


def agent_snapshot() -> dict:
    example = _agent_example()
    brokers = config.setting(AGENT_BROKERS, example["brokers"])
    topic = config.setting(AGENT_TOPIC, example["topic"])
    return {
        "brokers": brokers,
        "topic": topic,
        "validation": check_agent(brokers, topic),
        "template": agent_template(brokers, topic),
        "example_file": example["path"],
        "transport": "kafka",
        "transport_note": (
            "The endpoint agent publishes to Kafka; it has no other transport. "
            "The panel cannot push this file to installed agents. On Windows, "
            "the installer registers the DaOrcsEndpointAgent service; copy "
            "this file to %PROGRAMDATA%\\DaOrcs\\Agent\\agent.json and restart "
            "that service on each endpoint."
        ),
    }


def agent_template(brokers: str, topic: str) -> dict:
    """agent.example.json with this section's two values applied."""
    example = _agent_example()
    doc = json.loads(json.dumps(example["doc"])) if example["doc"] else {
        "watch_dirs": ["%PUBLIC%\\Downloads", "%PUBLIC%\\Desktop"],
        "scan_interval_seconds": 5,
        "stable_seconds": 2,
        "chunk_bytes": 262144,
        "state_file": "%PROGRAMDATA%\\DaOrcs\\Agent\\state.sqlite3",
        "log_file": "%PROGRAMDATA%\\DaOrcs\\Agent\\logs\\agent.log",
        "log_level": "INFO",
        "kafka": {"producer_config": {}},
    }
    kafka = doc.setdefault("kafka", {})
    kafka["bootstrap_servers"] = brokers
    kafka["topic"] = topic
    return doc


def save_agent(brokers: str, topic: str) -> dict:
    """Validate and store the agent's broker/topic. Nothing local is restarted.

    These keys are a template plus the panel's own idea of where the broker is;
    no process on this host reads them, so a save is complete when the file is
    written. The template in the response is what gets deployed.
    """
    brokers = str(brokers or "").strip()
    topic = str(topic or "").strip()
    check = check_agent(brokers, topic)
    if not check["ok"]:
        return {"ok": False, "code": "invalid-agent",
                "detail": "; ".join(check["errors"]), "validation": check,
                "agent": agent_snapshot()}

    _rewrite({AGENT_BROKERS: brokers, AGENT_TOPIC: topic})
    return {
        "ok": True,
        "code": "saved",
        "detail": f"agent will use {brokers} (topic {topic})",
        "validation": check,
        "agent": agent_snapshot(),
    }
