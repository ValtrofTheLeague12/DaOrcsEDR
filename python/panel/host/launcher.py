"""Start and stop the three Python services the panel watches.

The Services page has always been able to say that the Analyzer API, MalAPI and
the ML scorer are down. This module is what lets it do something about it: the
panel's half of `admin-terminal/activate.py` and `stop.py`, under the same
rules.

  * Only these three keys can be started. Everything else on the page is a
    container or a VM and belongs to its own control surface, so the allowlist
    is here rather than in the UI - a crafted URL to `/api/services/kafka/start`
    is a 404 before any process is considered.
  * A service whose prerequisites are missing is refused *with the reason*
    instead of spawning a process that dies a second later. "The ML scorer is
    missing model.txt" is an answer; "started, then down" is a mystery.
  * Stop refuses to kill a listener whose command line does not look like the
    service. "Something is on port 60025" is not the same as "our analyzer is
    on 60025", and the difference is somebody else's process.
  * Start waits for the endpoint the panel actually probes, so "started" and
    "the card is green" cannot disagree.

Children are started detached, exactly as the terminal does: a service that
dies when the browser closes is not a service. Nothing here holds the child's
handle past the request.
"""
from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from ..core import config
from . import services

REPO = config.REPO

# The only services with a start rule. The UI reads the same list through
# services.overview(), so it never has to guess which cards get buttons.
UNIT_KEYS = ("analyzer", "malapi", "ml")

# How long to wait for the endpoint after spawning. The analyzer and MalAPI are
# Flask apps that answer almost immediately; the ML scorer loads a 39 MB
# LightGBM model first. These are deadlines, not expectations.
READY_SECONDS = {"analyzer": 20.0, "malapi": 15.0, "ml": 30.0}

POLL_SECONDS = 0.25
STOP_SECONDS = 5.0

# HTTP status for each outcome. `ok` is the payload's own field; this map is
# only so a non-browser caller (curl, the docs' Try it out) sees the truth.
HTTP_STATUS = {
    "unknown-service": 404,
    "bad-action": 400,
    "blocked": 409,
    "port-held": 409,
    "busy": 409,
    "not-running": 409,
    "not-ours": 409,
    "timeout": 502,
    "exited": 502,
    "spawn-failed": 502,
    "stop-failed": 502,
}

_LOCKS: dict[str, threading.Lock] = {key: threading.Lock() for key in UNIT_KEYS}


class ControlError(Exception):
    """A request the API refuses outright - bad action, unknown key."""

    def __init__(self, message: str, code: str, status: int) -> None:
        super().__init__(message)
        self.code = code
        self.status = status


@dataclass(frozen=True)
class Unit:
    key: str
    name: str
    argv: list[str]
    cwd: Path
    ready: float


# ---------------------------------------------------------------------------
# What to run
# ---------------------------------------------------------------------------

def _loopback(host: str) -> bool:
    if host in ("localhost", "127.0.0.1", "::1"):
        return True
    import ipaddress

    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _bind_addr(host: str) -> str:
    """The address to hand the OS, mirroring admin-terminal/core.bind_addr().

    A configured non-loopback host binds every interface: the analyzer's own
    MalAPI/ML clients dial 127.0.0.1, and binding only the external address
    would cut the pipeline off from its own services.
    """
    if host in ("127.0.0.1", "::1", "localhost", "0.0.0.0", "::"):
        return host
    import ipaddress

    try:
        return "::" if ipaddress.ip_address(host).version == 6 else "0.0.0.0"
    except ValueError:
        return "0.0.0.0"


# Public names for the two helpers other host modules need. `endpoints.py`
# validates a save with the same bind address the launcher would use, and asks
# the same listener lookup who is holding a port; duplicating either would let
# "valid" and "actually startable" drift apart.
bind_addr = _bind_addr


def python_exe() -> Path:
    """The interpreter running the panel.

    MalAPI and the analyzer API need flask and PyYAML - the panel itself
    requires both, so `sys.executable` is the one interpreter guaranteed to
    have them, even if the repo has been moved and python/.venv is not where
    the terminal expects it.
    """
    return Path(sys.executable)


def ml_python() -> Path:
    """The ML scorer's own venv (lightgbm, sklearn, pefile, thrember)."""
    base = REPO / "ml" / "_t" / "venv"
    return base / ("Scripts" if os.name == "nt" else "bin") / "python.exe"


def units() -> dict[str, Unit]:
    """Every startable service, resolved fresh so .env edits are honoured."""
    py = python_exe()
    ml_host = config.setting("ML_HOST", "127.0.0.1")
    return {
        "analyzer": Unit(
            "analyzer", "Analyzer API",
            [str(py), "server.py"], REPO, READY_SECONDS["analyzer"]),
        # MalAPI opens yaml/malapi/*.yaml relative to its working directory, so
        # its cwd is python/, not the repo root. The analyzer launches it the
        # same way (src/main.cpp, local_api working_dir = "python").
        "malapi": Unit(
            "malapi", "MalAPI",
            [str(py), str(REPO / "python" / "api" / "server.py")],
            REPO / "python", READY_SECONDS["malapi"]),
        "ml": Unit(
            "ml", "ML scorer",
            [str(ml_python()), str(REPO / "ml" / "serve.py"),
             "--host", _bind_addr(ml_host), "--port", str(config.ml_port())],
            REPO, READY_SECONDS["ml"]),
    }


def _usable(path: Path) -> bool:
    """Present and non-empty. A zero-byte script imports and does nothing."""
    try:
        return path.is_file() and path.stat().st_size > 0
    except OSError:
        return False


def blocker(key: str) -> str:
    """Why `key` cannot be started right now. Empty string = startable.

    Checked before spawning so a missing model or an unbuilt analyzer is one
    clear sentence in the card instead of a process that exits a second later.
    """
    unit = units().get(key)
    if unit is None:
        return f"no start rule for '{key}'"
    if not Path(unit.argv[0]).is_file():
        return "python/.venv is missing - recreate it first"

    if key == "analyzer":
        raw = os.environ.get("SA_ANALYZER") or config.setting("SA_ANALYZER")
        analyzer = Path(raw) if raw else REPO / "build-ucrt" / "static_analyzer.exe"
        if not analyzer.is_absolute():
            analyzer = REPO / analyzer
        if not analyzer.is_file():
            return ("static analyzer is not built "
                    f"({analyzer.relative_to(REPO) if analyzer.is_relative_to(REPO) else analyzer})"
                    " - build it from the Build page")
        if not _usable(REPO / "server.py"):
            return "server.py is missing"
    elif key == "malapi":
        if not _usable(REPO / "python" / "api" / "server.py"):
            return "python/api/server.py is missing or empty"
    elif key == "ml":
        if not _usable(REPO / "ml" / "serve.py"):
            return "ml/serve.py is missing or empty"
        if not _usable(REPO / "ml" / "model.txt"):
            return "ml/model.txt is missing - train or install the model first"
        if not _loopback(config.setting("ML_HOST", "127.0.0.1")) \
                and not config.ml_token():
            return ("ML_HOST is off-loopback and ML_SERVE_TOKEN is unset - "
                    "ml/serve.py refuses that bind")
    return ""


# ---------------------------------------------------------------------------
# Process lookup
# ---------------------------------------------------------------------------

def _powershell(script: str) -> str:
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, timeout=15,
            encoding="utf-8", errors="replace")
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return out.stdout.strip()


_PS_LISTENERS = """
$rows = @()
$conns = Get-NetTCPConnection -State Listen -LocalPort {port} -ErrorAction SilentlyContinue
foreach ($c in $conns) {{
  $p = Get-CimInstance Win32_Process -Filter ('ProcessId=' + $c.OwningProcess) -ErrorAction SilentlyContinue
  $rows += [pscustomobject]@{{ pid = [int]$c.OwningProcess; name = "$($p.Name)"; command = "$($p.CommandLine)" }}
}}
if ($rows.Count -gt 0) {{ ConvertTo-Json -InputObject $rows -Compress -Depth 3 }}
"""


def _posix_command(pid: int) -> str:
    try:
        raw = Path(f"/proc/{pid}/cmdline").read_bytes()
    except OSError:
        return ""
    return raw.replace(b"\x00", b" ").decode("utf-8", "replace").strip()


def _listeners(port: int) -> list[dict]:
    """Every process listening on a local TCP port: pid, name, command line.

    Windows uses Get-NetTCPConnection rather than parsing netstat because the
    state column is localised ("LISTENING" becomes "ECOUTE" on a French
    install) - the cmdlet's -State parameter is not.
    """
    if port <= 0:
        return []
    if os.name == "nt":
        raw = _powershell(_PS_LISTENERS.format(port=int(port)))
        if not raw:
            return []
        try:
            data = json.loads(raw)
        except ValueError:
            return []
        if isinstance(data, dict):
            data = [data]
        return [{"pid": int(row.get("pid") or 0),
                 "name": str(row.get("name") or ""),
                 "command": str(row.get("command") or "")}
                for row in data if row.get("pid")]

    exe = shutil.which("lsof")
    if not exe:
        return []
    try:
        out = subprocess.run(
            [exe, "-nP", f"-iTCP:{port}", "-sTCP:LISTEN", "-Fpc"],
            capture_output=True, text=True, timeout=10, errors="replace")
    except (OSError, subprocess.TimeoutExpired):
        return []
    rows, pid = [], None
    for line in out.stdout.splitlines():
        if line.startswith("p"):
            pid = int(line[1:] or 0)
        elif line.startswith("c") and pid:
            rows.append({"pid": pid, "name": line[1:],
                         "command": _posix_command(pid)})
            pid = None
    return rows


# Public alias - endpoints.py needs to name whoever holds a port when a bind
# fails, and it must be the same PowerShell/CIM lookup the stop path uses.
listeners = _listeners


def _looks_like(key: str, command: str) -> bool:
    """Does this command line belong to the service we are about to stop?

    The markers are the script names from `units()`, compared after slash
    normalisation. `serve.py` is checked against MalAPI's `api/server.py`
    explicitly, because "server.py" alone would match both Python APIs.
    """
    low = (command or "").lower().replace("/", "\\")
    if key == "malapi":
        return "api\\server.py" in low
    if key == "ml":
        return "serve.py" in low and "api\\server.py" not in low
    return "server.py" in low and "api\\server.py" not in low


def _kill(pid: int) -> bool:
    if os.name == "nt":
        try:
            out = subprocess.run(
                ["taskkill", "/PID", str(pid), "/T", "/F"],
                capture_output=True, text=True, timeout=20,
                encoding="utf-8", errors="replace")
        except (OSError, subprocess.TimeoutExpired):
            return False
        return out.returncode == 0
    try:
        os.killpg(os.getpgid(pid), signal.SIGTERM)
    except OSError:
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            return False
    return True


# ---------------------------------------------------------------------------
# Spawning and logs
# ---------------------------------------------------------------------------

def _log_path(key: str) -> Path:
    folder = config.logs_dir() / "panel-services"
    folder.mkdir(parents=True, exist_ok=True)
    return folder / f"{key}-{datetime.now():%Y%m%dT%H%M%S}.log"


def _spawn(unit: Unit, log_path: Path) -> subprocess.Popen:
    """Start the service detached, its output going to the panel's log tree.

    CREATE_NO_WINDOW gives the child a hidden console. A venv launcher
    re-execs the real interpreter, and a child spawned from a process with no
    console would otherwise be handed a visible one - a stray window whose
    closure kills the listener. Same reasoning as admin-terminal/core.py.
    """
    env = dict(os.environ)
    env.setdefault("PYTHONUNBUFFERED", "1")
    if unit.key == "ml" and config.ml_token():
        env["ML_SERVE_TOKEN"] = config.ml_token()

    if os.name == "nt":
        flags = (getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
                 | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x200))
        extra = {"creationflags": flags}
    else:
        extra = {"start_new_session": True}

    with open(log_path, "ab") as log:
        log.write(f"\n=== {datetime.now():%Y-%m-%d %H:%M:%S} "
                  f"$ {' '.join(unit.argv)}  (cwd={unit.cwd})\n".encode())
        log.flush()
        return subprocess.Popen(
            unit.argv, cwd=str(unit.cwd), stdin=subprocess.DEVNULL,
            stdout=log, stderr=subprocess.STDOUT, env=env, **extra)


def _tail(path: Path, limit: int = 8) -> list[str]:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    return [ln.rstrip() for ln in lines if ln.strip()][-limit:]


def _detail_with_tail(detail: str, path: Path | None) -> str:
    """A failure an operator can act on: the sentence, the log, the last line."""
    if path is None:
        return detail
    lines = _tail(path, 3)
    text = f"{detail}\nlog: {path}"
    if lines:
        text += "\n" + "\n".join(ln[:200] for ln in lines)
    return text


def _result(ok: bool, key: str, action: str, *, code: str, detail: str,
            pid: int | None = None, log: Path | None = None,
            ms: float | None = None, tail: list[str] | None = None) -> dict:
    return {"ok": ok, "key": key, "action": action, "code": code,
            "detail": detail, "pid": pid,
            "log": str(log) if log else None,
            "ms": round(ms, 1) if ms is not None else None,
            "tail": tail or []}


# ---------------------------------------------------------------------------
# Actions
# ---------------------------------------------------------------------------

def start(key: str) -> dict:
    unit = units().get(key)
    if unit is None:
        raise ControlError(f"no start rule for '{key}'", "unknown-service", 404)

    lock = _LOCKS.setdefault(key, threading.Lock())
    if not lock.acquire(blocking=False):
        return _result(False, key, "start", code="busy",
                       detail=f"a {key} action is already running")
    try:
        reason = blocker(key)
        if reason:
            return _result(False, key, "start", code="blocked", detail=reason)

        current = services.probe_one(key)
        if current and current.up:
            return _result(True, key, "start", code="already-running",
                           detail=f"{unit.name} is already answering at "
                                  f"{current.endpoint} ({current.ms:.0f} ms)")

        # Nothing answered the probe, but something may still hold the port:
        # a half-booted instance, or an unrelated process. Spawning would only
        # fail to bind, so say what is actually there.
        held = _listeners(services.port_of(key))
        if held:
            who = "; ".join(f"pid {p['pid']} ({p['name']})" for p in held)
            return _result(False, key, "start", code="port-held",
                           detail=f"port {services.port_of(key)} is held by "
                                  f"{who}, which is not answering the health "
                                  f"check - stop it first")

        log_path = _log_path(key)
        try:
            proc = _spawn(unit, log_path)
        except OSError as exc:
            return _result(False, key, "start", code="spawn-failed",
                           detail=_detail_with_tail(f"could not launch: {exc}",
                                                    log_path))
        except Exception as exc:  # noqa: BLE001 - a failed spawn is an answer
            return _result(False, key, "start", code="spawn-failed",
                           detail=_detail_with_tail(
                               f"{type(exc).__name__}: {exc}", log_path))

        started = time.monotonic()

        def ready(elapsed: float) -> dict:
            """Success, with the pid an operator will actually find.

            Not necessarily the pid Popen returned: a venv's `python.exe` is a
            redirector that re-execs the real interpreter, and the real one is
            what holds the socket. Stop reports the listener, so start reports
            the same number rather than a parent that Task Manager shows as a
            second, idle python.exe.
            """
            listening = _listeners(services.port_of(key))
            pid = (listening[0].get("pid") if listening else 0) or proc.pid
            return _result(True, key, "start", code="started",
                           detail=f"ready in {elapsed:.1f} s (pid {pid})",
                           pid=pid, log=log_path, ms=elapsed * 1000,
                           tail=_tail(log_path, 4))

        while True:
            if proc.poll() is not None:
                services.invalidate()
                return _result(
                    False, key, "start", code="exited",
                    detail=_detail_with_tail(
                        f"process exited with code {proc.returncode} before "
                        f"{unit.name} answered", log_path),
                    pid=proc.pid, log=log_path, tail=_tail(log_path))

            probe = services.probe_one(key)
            elapsed = time.monotonic() - started
            if probe and probe.up:
                services.invalidate()
                return ready(elapsed)
            if elapsed >= unit.ready:
                services.invalidate()
                probe = services.probe_one(key)
                if probe and probe.up:
                    return ready(elapsed)
                return _result(
                    False, key, "start", code="timeout",
                    detail=_detail_with_tail(
                        f"started (pid {proc.pid}) but nothing answered "
                        f"{unit.name}'s endpoint within {unit.ready:.0f} s",
                        log_path),
                    pid=proc.pid, log=log_path, tail=_tail(log_path))
            time.sleep(POLL_SECONDS)
    finally:
        lock.release()


def stop(key: str) -> dict:
    spec = services.spec_for(key)
    if spec is None or key not in UNIT_KEYS:
        raise ControlError(f"no stop rule for '{key}'", "unknown-service", 404)

    lock = _LOCKS.setdefault(key, threading.Lock())
    if not lock.acquire(blocking=False):
        return _result(False, key, "stop", code="busy",
                       detail=f"a {key} action is already running")
    try:
        listeners = _listeners(spec.port)
        if not listeners:
            probe = services.probe_one(key)
            if probe and probe.up:
                return _result(
                    False, key, "stop", code="not-running",
                    detail=f"{spec.name} answers at {probe.endpoint}, but "
                           f"nothing is listening on port {spec.port} here - "
                           f"it is running on another host")
            return _result(False, key, "stop", code="not-running",
                           detail=f"nothing is listening on port {spec.port}")

        ours = [p for p in listeners if _looks_like(key, p["command"])]
        if not ours:
            who = "; ".join(
                f"pid {p['pid']} ({p['name']}): {p['command'] or 'no command line'}"
                for p in listeners)
            return _result(
                False, key, "stop", code="not-ours",
                detail=f"port {spec.port} is held by something that is not "
                       f"{spec.name} - refusing to kill it: {who}")

        killed, failed = [], []
        for proc in ours:
            (killed if _kill(proc["pid"]) else failed).append(proc)

        deadline = time.monotonic() + STOP_SECONDS
        while time.monotonic() < deadline:
            if not _listeners(spec.port):
                break
            time.sleep(0.2)

        services.invalidate()
        still = _listeners(spec.port)
        if still:
            who = "; ".join(f"pid {p['pid']} ({p['name']})" for p in still)
            return _result(False, key, "stop", code="stop-failed",
                           detail=f"still listening on port {spec.port}: {who}")
        if failed:
            who = "; ".join(f"pid {p['pid']} ({p['name']})" for p in failed)
            return _result(False, key, "stop", code="stop-failed",
                           detail=f"could not kill {who}")

        who = ", ".join(f"pid {p['pid']} ({p['name']})" for p in killed)
        return _result(True, key, "stop", code="stopped",
                       detail=f"stopped {spec.name}: {who}",
                       pid=killed[0]["pid"] if killed else None)
    finally:
        lock.release()


def control(key: str, action: str) -> dict:
    if action not in ("start", "stop"):
        raise ControlError("action must be start or stop", "bad-action", 400)
    return start(key) if action == "start" else stop(key)
