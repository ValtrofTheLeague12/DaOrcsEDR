"""Listener address and hide-list for the generated CTI artifact server.

The STIX/CTI catalog server template reads ``stix-server/config/cti_config.json``
at startup. The Threat Intelligence panel is the only writer, so the file lives
beside the server it configures rather than in the analyzer's config.

The panel owns ``server.ip``, ``server.port`` and ``banned_artifacts``. Other
keys in the file (notably ``catalog_file``) are preserved when either is
updated.

``banned_artifacts`` holds structured ban entries::

    {"name": "<artifact name or null>", "hash": "<SHA-256 or null>"}

Each entry must have at least one of ``name`` or ``hash``. The generated
server drops a matching artifact before rendering, so a ban hides it from the
catalog UI without deleting the row from the catalog file.
"""

from __future__ import annotations

import ipaddress
import json
import os
from pathlib import Path
from typing import Any

CONFIG_RELATIVE = Path("stix-server") / "config" / "cti_config.json"
DEFAULT_IP = "0.0.0.0"
DEFAULT_PORT = 8765
MAX_HOST_LENGTH = 253
BANNED_KEY = "banned_artifacts"
MAX_BANNED = 1000
MAX_BAN_LENGTH = 256


class BannedArtifact(dict[str, Any]):
    """A structured ban entry: ``{"name": str | None, "hash": str | None}``."""

    def __init__(self, name: str | None, hash_value: str | None):
        super().__init__({"name": name, "hash": hash_value})

    @property
    def name(self) -> str | None:
        return self.get("name")

    @property
    def hash(self) -> str | None:
        return self.get("hash")

    def key(self) -> str:
        """A stable display key: name + hash when both present."""
        parts = [p for p in (self.name, self.hash) if p]
        return " · ".join(parts) if parts else "(empty ban)"


def config_path(repo: Path) -> Path:
    return repo / CONFIG_RELATIVE


def _parse_ip(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("'ip' must be text")
    host = value.strip()
    if not host or len(host) > MAX_HOST_LENGTH:
        raise ValueError("'ip' must be a non-empty bind address")
    if any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in host):
        raise ValueError("'ip' must not contain whitespace or control characters")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        raise ValueError("'ip' must be a valid IPv4 or IPv6 address") from None
    return host


def _parse_port(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("'port' must be an integer from 1 to 65535")
    if not 1 <= value <= 65535:
        raise ValueError("'port' must be an integer from 1 to 65535")
    return value


def _parse_banned(value: object) -> list[dict[str, str | None]]:
    """Normalise the hide-list: structured ``{"name", "hash"}`` entries.

    Each entry must be an object with at least one of ``name`` or ``hash``
    being a non-empty string. Entries are deduplicated by (name, hash) pair
    and order is kept. Legacy flat strings are upgraded to objects with
    ``hash`` set to ``null``.
    """
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError(
            "'banned' must be a list of {\"name\", \"hash\"} objects")

    banned: list[dict[str, str | None]] = []
    seen: set[tuple[str | None, str | None]] = set()
    for entry in value:
        name: str | None = None
        hash_value: str | None = None

        if isinstance(entry, dict):
            raw_name = entry.get("name")
            raw_hash = entry.get("hash")
            name = raw_name.strip() if isinstance(raw_name, str) and raw_name.strip() else None
            hash_value = raw_hash.strip() if isinstance(raw_hash, str) and raw_hash.strip() else None
        elif isinstance(entry, str):
            # Legacy flat string: treat as a hash (most common legacy case).
            hash_value = entry.strip()
        else:
            raise ValueError("each banned artifact must be an object or text")

        if not name and not hash_value:
            raise ValueError("a banned artifact must have a name or a hash")
        if name and len(name) > MAX_BAN_LENGTH:
            raise ValueError(
                f"a banned name must be at most {MAX_BAN_LENGTH} characters")
        if hash_value and len(hash_value) > MAX_BAN_LENGTH:
            raise ValueError(
                f"a banned hash must be at most {MAX_BAN_LENGTH} characters")

        pair = (name, hash_value)
        if pair not in seen:
            seen.add(pair)
            banned.append({"name": name, "hash": hash_value})

    if len(banned) > MAX_BANNED:
        raise ValueError(f"at most {MAX_BANNED} artifacts may be banned")
    return banned


def read(repo: Path) -> dict:
    """The saved listener address, never raising.

    A missing file is not an error: the panel shows the defaults until the
    operator saves them. A file that exists but cannot be understood is
    reported in ``error`` so the UI can say why the saved values are unusable
    instead of silently presenting the defaults as if they were stored.
    """
    path = config_path(repo)
    out = {
        "path": CONFIG_RELATIVE.as_posix(),
        "exists": False,
        "ip": DEFAULT_IP,
        "port": DEFAULT_PORT,
        "banned": [],
        "error": None,
    }
    try:
        # utf-8-sig: tolerate a BOM added by a Windows editor or PowerShell.
        raw = path.read_text(encoding="utf-8-sig")
    except FileNotFoundError:
        return out
    except OSError as exc:
        out["error"] = f"could not read {CONFIG_RELATIVE.as_posix()}: {exc}"
        return out

    out["exists"] = True
    try:
        data = json.loads(raw or "{}")
    except json.JSONDecodeError as exc:
        out["error"] = f"{CONFIG_RELATIVE.as_posix()} is not valid JSON: {exc}"
        return out
    if not isinstance(data, dict):
        out["error"] = f"{CONFIG_RELATIVE.as_posix()} must be a JSON object"
        return out
    server = data.get("server")
    if not isinstance(server, dict):
        out["error"] = f"{CONFIG_RELATIVE.as_posix()} must contain a server object"
    else:
        try:
            out["ip"] = _parse_ip(server.get("ip"))
            out["port"] = _parse_port(server.get("port"))
        except ValueError as exc:
            out["error"] = f"server in {CONFIG_RELATIVE.as_posix()} is invalid: {exc}"

    try:
        out["banned"] = _parse_banned(data.get(BANNED_KEY))
    except ValueError as exc:
        if out["error"] is None:
            out["error"] = (
                f"{BANNED_KEY} in {CONFIG_RELATIVE.as_posix()} is invalid: {exc}")
    return out


def write(repo: Path, patch: dict) -> dict:
    """Update the saved listener address or hide-list, preserving other keys."""
    if not isinstance(patch, dict):
        raise ValueError("body must be a JSON object")
    unknown = sorted(
        key for key in patch if key not in ("ip", "port", "banned"))
    if unknown:
        raise ValueError("not a CTI server setting: " + ", ".join(unknown))
    if not patch:
        return read(repo)

    ip = _parse_ip(patch["ip"]) if "ip" in patch else None
    port = _parse_port(patch["port"]) if "port" in patch else None
    banned = _parse_banned(patch["banned"]) if "banned" in patch else None

    path = config_path(repo)
    data: dict = {}
    try:
        # Same BOM tolerance as read(); the rewrite below emits plain UTF-8.
        raw = path.read_text(encoding="utf-8-sig")
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise ValueError(f"could not read {CONFIG_RELATIVE.as_posix()}: {exc}") from exc
    else:
        try:
            loaded = json.loads(raw or "{}")
        except json.JSONDecodeError as exc:
            # Refuse to rewrite a file whose other keys we cannot see.
            raise ValueError(
                f"{CONFIG_RELATIVE.as_posix()} is not valid JSON: {exc}"
            ) from exc
        if not isinstance(loaded, dict):
            raise ValueError(
                f"{CONFIG_RELATIVE.as_posix()} must be a JSON object")
        data = loaded

    server = data.get("server")
    if server is None:
        server = {}
    elif not isinstance(server, dict):
        raise ValueError(
            f"{CONFIG_RELATIVE.as_posix()} 'server' must be a JSON object")
    server = dict(server)
    if ip is not None:
        server["ip"] = ip
    if port is not None:
        server["port"] = port
    if ip is not None or port is not None or "server" in data:
        data["server"] = server
    elif banned is not None:
        # A ban-only write to a file with no listener still needs a usable
        # listener, because the generated server refuses to start without one.
        data["server"] = {"ip": DEFAULT_IP, "port": DEFAULT_PORT}
    if banned is not None:
        data[BANNED_KEY] = banned

    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    try:
        tmp.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)
    return read(repo)
