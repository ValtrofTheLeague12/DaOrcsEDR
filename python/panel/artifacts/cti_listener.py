"""Start, stop and inspect the generated CTI artifact server.

``stix-server/host_server.py`` only writes ``server.py``; it deliberately does
not start a long-running listener. This module is the missing half: the panel's
Launch button spawns that generated file, and Stop shuts it down again.

The rules mirror ``panel.host.launcher`` because the failure modes are the same:

  * the listener address comes from ``stix-server/config/cti_config.json`` - the
    same file the generated server reads - so "saved" and "launched" cannot
    drift apart;
  * a missing or invalid generated server is refused *with the reason* before a
    process is spawned;
  * the server is announced as running only after its own ``/health`` answers,
    not when ``Popen`` returns;
  * Stop refuses to kill a listener whose command line does not point at
    ``stix-server/server.py``. A busy port and *our* port are different facts.

Everything here is synchronous and short-lived. The child itself is detached,
exactly as the panel's other services are: closing the browser must not close
the catalog server.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path

from ..core import config
from ..host import launcher
from . import cti_server

READY_SECONDS = 20.0
POLL_SECONDS = 0.25
STOP_SECONDS = 5.0
HEALTH_TIMEOUT = 2.0
MAX_DETAIL = 400

_LOCK = threading.Lock()

# The listener the panel itself launched. Kept in memory so a config edit made
# while the server is running does not make Stop forget which port to look at.
_LAUNCHED: dict = {"ip": None, "port": None, "pid": None, "log": None}


def _stix_dir(repo: Path) -> Path:
    return repo / "stix-server"


def _script(repo: Path) -> Path:
    return _stix_dir(repo) / "server.py"


def interpreter(repo: Path) -> Path:
    """The interpreter used to run the generated server.

    Prefer stix-server's own virtualenv: it declares the generated server's
    dependencies (Flask, bcrypt, Supabase). Falling back to the panel's
    interpreter keeps this working when both share an environment.
    """
    stix_dir = _stix_dir(repo)
    candidates = [
        stix_dir / "Scripts" / "python.exe",
        stix_dir / "Scripts" / "python",
        stix_dir / "bin" / "python",
    ]
    return next((path for path in candidates if path.is_file()), Path(sys.executable))


def _usable(path: Path) -> bool:
    try:
        return path.is_file() and path.stat().st_size > 0
    except OSError:
        return False


def _dial_host(ip: str) -> str:
    """The address a local health check should connect to.

    A wildcard bind accepts loopback but not the literal 0.0.0.0 / :: in a URL.
    """
    if ip in ("0.0.0.0", "*"):
        return "127.0.0.1"
    if ip == "::":
        return "::1"
    return ip


def _url(ip: str, port: int, path: str = "/") -> str:
    host = _dial_host(ip)
    if ":" in host:
        # A zone id (fe80::1%12) is legal in a socket but must be escaped in a
        # URL. Percent-encoding it is harmless for addresses that have none.
        host = f"[{host.replace('%', '%25')}]"
    return f"http://{host}:{port}{path}"


def _health(ip: str, port: int) -> tuple[bool, str]:
    """Ask the generated server's public /health route whether it is ready."""
    url = _url(ip, port, "/health")
    try:
        with urllib.request.urlopen(url, timeout=HEALTH_TIMEOUT) as response:
            raw = response.read(512)
    except urllib.error.HTTPError as exc:
        return False, f"{url} answered HTTP {exc.code}"
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return False, f"{url} did not answer: {exc}"
    try:
        payload = json.loads(raw.decode("utf-8", "replace") or "{}")
    except ValueError:
        payload = {}
    if isinstance(payload, dict) and payload.get("ok") is True:
        return True, ""
    return False, f"{url} answered without ok=true"


def _looks_like(command: str) -> bool:
    """Is this command line the generated CTI server, not some other server.py?

    The repository also has a root ``server.py`` (the analyzer API), so matching
    ``server.py`` alone would let Stop kill the wrong process. The generated
    listener is the one under ``stix-server``.
    """
    low = (command or "").lower().replace("/", "\\")
    return "stix-server\\server.py" in low


def _log_path() -> Path:
    folder = config.logs_dir() / "panel-services"
    folder.mkdir(parents=True, exist_ok=True)
    return folder / f"cti-{datetime.now():%Y%m%dT%H%M%S}.log"


def _tail(path: Path | None, limit: int = 8) -> list[str]:
    if path is None:
        return []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    return [line.rstrip()[:MAX_DETAIL] for line in lines if line.strip()][-limit:]


def _detail_with_tail(detail: str, path: Path | None) -> str:
    text = detail
    if path is not None:
        text += f"\nlog: {path}"
    tail = _tail(path, 4)
    if tail:
        text += "\n" + "\n".join(tail)
    return text


def _spawn(repo: Path, script: Path, stix_dir: Path,
           log_path: Path) -> subprocess.Popen:
    """Start the generated server detached, with output in the panel log tree."""
    env = dict(os.environ)
    env.setdefault("PYTHONUNBUFFERED", "1")
    python = interpreter(repo)

    if os.name == "nt":
        flags = (getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
                 | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x200))
        extra = {"creationflags": flags}
    else:
        extra = {"start_new_session": True}

    with open(log_path, "ab") as log:
        log.write(
            f"\n=== {datetime.now():%Y-%m-%d %H:%M:%S} "
            f"$ {python} {script}  (cwd={stix_dir})\n".encode()
        )
        log.flush()
        return subprocess.Popen(
            [str(python), str(script)],
            cwd=str(stix_dir),
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
            env=env,
            **extra,
        )


def _listeners(port: int) -> list[dict]:
    return launcher.listeners(port)


def _ours(port: int) -> list[dict]:
    return [row for row in _listeners(port) if _looks_like(row.get("command", ""))]


def _status_for(ip: str, port: int, *, log: Path | None = None) -> dict:
    listeners = _listeners(port)
    ours = [row for row in listeners if _looks_like(row.get("command", ""))]
    if ours:
        pid = int(ours[0].get("pid") or 0) or None
        ok, why = _health(ip, port)
        return {
            "state": "running" if ok else "unhealthy",
            "ip": ip,
            "port": port,
            "url": _url(ip, port),
            "pid": pid,
            "log": str(log) if log else None,
            "detail": "" if ok else why,
        }
    if listeners:
        who = "; ".join(
            f"pid {row['pid']} ({row['name']})" for row in listeners
        )
        return {
            "state": "foreign",
            "ip": ip,
            "port": port,
            "url": _url(ip, port),
            "pid": None,
            "log": str(log) if log else None,
            "detail": f"port {port} is held by {who}, which is not the generated CTI server",
        }
    return {
        "state": "stopped",
        "ip": ip,
        "port": port,
        "url": _url(ip, port),
        "pid": None,
        "log": str(log) if log else None,
        "detail": "",
    }


def status(repo: Path | None = None) -> dict:
    """The listener as it stands now, never raising.

    A broken config is reported as ``state: error`` instead of pretending the
    server is stopped, because the caller cannot meaningfully Start or Stop
    without knowing which address to use.
    """
    repo = repo or config.REPO
    state = cti_server.read(repo)
    if state.get("error"):
        return {
            "state": "error",
            "ip": state.get("ip") or cti_server.DEFAULT_IP,
            "port": state.get("port") or cti_server.DEFAULT_PORT,
            "url": None,
            "pid": None,
            "log": None,
            "detail": state["error"],
        }

    current = _status_for(state["ip"], state["port"])
    if current["state"] == "stopped" and _LAUNCHED.get("port"):
        # The config was edited while a server this panel started is still
        # running on the old port. Report the real process rather than a
        # reassuring "stopped" that Stop would then fail to act on.
        previous = _status_for(
            _LAUNCHED.get("ip") or state["ip"],
            int(_LAUNCHED["port"]),
            log=Path(_LAUNCHED["log"]) if _LAUNCHED.get("log") else None,
        )
        if previous["state"] in ("running", "unhealthy"):
            return previous
    return current


def _result(ok: bool, code: str, detail: str, *, status_payload: dict,
            pid: int | None = None, log: Path | None = None,
            tail: list[str] | None = None) -> dict:
    return {
        "ok": ok,
        "code": code,
        "detail": detail,
        "pid": pid,
        "log": str(log) if log else None,
        "tail": tail or [],
        "status": status_payload,
    }


def start(repo: Path | None = None) -> dict:
    """Launch the generated server and wait for its own health route."""
    repo = repo or config.REPO
    if not _LOCK.acquire(blocking=False):
        return _result(False, "busy", "a CTI listener action is already running",
                       status_payload=status(repo))
    try:
        script = _script(repo)
        stix_dir = _stix_dir(repo)
        if not _usable(script):
            return _result(
                False, "blocked",
                "stix-server/server.py is missing or empty - select Generate Server first",
                status_payload=status(repo),
            )

        saved = cti_server.read(repo)
        if saved.get("error"):
            return _result(
                False, "blocked", saved["error"], status_payload=status(repo))
        ip, port = saved["ip"], saved["port"]

        current = _status_for(ip, port)
        if current["state"] == "running":
            return _result(True, "already-running",
                           f"the CTI server is already answering at {current['url']}",
                           status_payload=current, pid=current.get("pid"))
        if current["state"] == "unhealthy":
            return _result(
                False, "port-held",
                f"something is listening on port {port} but {current['detail']}",
                status_payload=current, pid=current.get("pid"),
            )
        if current["state"] == "foreign":
            return _result(
                False, "port-held", current["detail"], status_payload=current)

        log_path = _log_path()
        try:
            proc = _spawn(repo, script, stix_dir, log_path)
        except OSError as exc:
            return _result(
                False, "spawn-failed",
                _detail_with_tail(f"could not launch the CTI server: {exc}", log_path),
                status_payload=_status_for(ip, port), log=log_path,
            )

        started = time.monotonic()
        while True:
            if proc.poll() is not None:
                return _result(
                    False, "exited",
                    _detail_with_tail(
                        f"the CTI server exited with code {proc.returncode} "
                        f"before answering /health", log_path),
                    status_payload=_status_for(ip, port), pid=proc.pid,
                    log=log_path, tail=_tail(log_path),
                )

            ok, why = _health(ip, port)
            elapsed = time.monotonic() - started
            if ok:
                listener = _status_for(ip, port, log=log_path)
                pid = listener.get("pid") or proc.pid
                _LAUNCHED.update(ip=ip, port=port, pid=pid, log=str(log_path))
                return _result(
                    True, "started",
                    f"ready in {elapsed:.1f} s (pid {pid}) at {listener['url']}",
                    status_payload=listener, pid=pid, log=log_path,
                    tail=_tail(log_path, 4),
                )
            if elapsed >= READY_SECONDS:
                return _result(
                    False, "timeout",
                    _detail_with_tail(
                        f"started (pid {proc.pid}) but /health did not answer "
                        f"within {READY_SECONDS:.0f} s: {why}", log_path),
                    status_payload=_status_for(ip, port), pid=proc.pid,
                    log=log_path, tail=_tail(log_path),
                )
            time.sleep(POLL_SECONDS)
    finally:
        _LOCK.release()


def stop(repo: Path | None = None) -> dict:
    """Stop the generated server, but only if the listener is ours."""
    repo = repo or config.REPO
    if not _LOCK.acquire(blocking=False):
        return _result(False, "busy", "a CTI listener action is already running",
                       status_payload=status(repo))
    try:
        saved = cti_server.read(repo)
        if saved.get("error"):
            return _result(False, "blocked", saved["error"],
                           status_payload=status(repo))

        ports = [saved["port"]]
        if _LAUNCHED.get("port") and _LAUNCHED["port"] not in ports:
            ports.append(int(_LAUNCHED["port"]))

        listeners = [(port, row) for port in ports for row in _listeners(port)]
        if not listeners:
            return _result(
                False, "not-running",
                f"nothing is listening on port {saved['port']}",
                status_payload=status(repo),
            )

        ours = [(port, row) for port, row in listeners
                if _looks_like(row.get("command", ""))]
        if not ours:
            who = "; ".join(
                f"pid {row['pid']} ({row['name']}): {row['command'] or 'no command line'}"
                for _port, row in listeners
            )
            return _result(
                False, "not-ours",
                f"refusing to kill a listener that is not the generated CTI "
                f"server: {who}",
                status_payload=status(repo),
            )

        killed, failed = [], []
        for _port, row in ours:
            (killed if launcher._kill(int(row["pid"])) else failed).append(row)

        # Wait for *our* processes to disappear, not for the ports to be empty.
        # If the config was pointed at a port somebody else already owns, that
        # foreign listener must not turn a successful stop into a failure.
        our_ports = {port for port, _row in ours}
        deadline = time.monotonic() + STOP_SECONDS
        while time.monotonic() < deadline:
            if not any(
                row for port in our_ports
                for row in _listeners(port) if _looks_like(row.get("command", ""))
            ):
                break
            time.sleep(0.2)

        still = [
            (port, row) for port in our_ports
            for row in _listeners(port) if _looks_like(row.get("command", ""))
        ]
        if still:
            who = "; ".join(
                f"pid {row['pid']} ({row['name']})" for _port, row in still)
            return _result(
                False, "stop-failed",
                f"the CTI server is still listening: {who}",
                status_payload=status(repo),
            )
        if failed:
            who = "; ".join(
                f"pid {row['pid']} ({row['name']})" for row in failed)
            return _result(
                False, "stop-failed", f"could not stop {who}",
                status_payload=status(repo),
            )

        who = ", ".join(
            f"pid {row['pid']} ({row['name']})" for row in killed)
        _LAUNCHED.update(ip=None, port=None, pid=None, log=None)
        return _result(
            True, "stopped", f"stopped the CTI server: {who}",
            status_payload=status(repo),
            pid=int(killed[0]["pid"]) if killed else None,
        )
    finally:
        _LOCK.release()


def control(action: str, repo: Path | None = None) -> dict:
    if action == "start":
        return start(repo)
    if action == "stop":
        return stop(repo)
    raise ValueError("action must be start or stop")
