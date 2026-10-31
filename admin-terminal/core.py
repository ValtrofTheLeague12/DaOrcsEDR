"""Shared plumbing for the admin terminal: colours, prompts, probing, tables.

Everything the terminal needs lives in admin-terminal/; this module only
reads repo state (.env, logs/, build outputs) - it never writes outside it
except through the caller's explicit actions.
"""
from __future__ import annotations

import ipaddress
import json
import os
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Optional

# ---------------------------------------------------------------------------
# Paths: repo root is one level up (this file sits in admin-terminal/)
# ---------------------------------------------------------------------------
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ADMIN = os.path.dirname(os.path.abspath(__file__))


def appdata_root() -> str:
    """The one directory every generated file belongs under.

    Mirrors include/core/app_paths.hpp and python/panel/core/config.py. The terminal,
    the analyzer and the web panel all read each other's output, so three
    separate implementations of "where does the app put its logs" is how the
    source tree fills up with logs that no tool then reads.
    """
    override = os.environ.get("IA_APPDATA_DIR")
    if override:
        return override
    if os.name == "nt":
        base = os.environ.get("APPDATA")
        if base:
            return os.path.join(base, "IAProject")
        return os.path.join(os.path.expanduser("~"), "AppData", "Roaming", "IAProject")
    xdg = os.environ.get("XDG_DATA_HOME")
    if xdg:
        return os.path.join(xdg, "IAProject")
    return os.path.join(os.path.expanduser("~"), ".local", "share", "IAProject")


ADMIN_LOGS = os.path.join(appdata_root(), "logs")

PY_VENV = os.path.join(REPO, "python", ".venv", "Scripts", "python.exe")
ML_VENV = os.path.join(REPO, "ml", "_t", "venv", "Scripts", "python.exe")
ANALYZER_CMD = [PY_VENV, "server.py"]

# Fixed ports of the other services - the API port must not collide with them.
MALAPI_PORT_DEFAULT = 60000
CYBERCHEF_PORT = 60001
ML_PORT_DEFAULT = 60010
KAFKA_PORT = 9092
GUACAMOLE_PORT = 61000

KNOWN_PORTS = {
    MALAPI_PORT_DEFAULT: "MalAPI",
    CYBERCHEF_PORT: "CyberChef",
    ML_PORT_DEFAULT: "ML scorer",
    KAFKA_PORT: "Kafka broker",
    GUACAMOLE_PORT: "Guacamole",
}

# Display names, keyed by Service.key - netcfg and stop screens use them.
SERVICE_NAMES = {
    "analyzer": "Analyzer API",
    "malapi": "MalAPI",
    "ml": "ML scorer",
    "cyberchef": "CyberChef",
    "kafka": "Kafka broker",
    "guacamole": "Guacamole",
}


# The Analysis VM's SSH trust anchors on the current user's OpenSSH
# known_hosts file. vms.json may override it with an absolute path, a `~`
# path, or a repo-relative path (legacy `qiling_dlls/known_hosts.ssh`).
DEFAULT_KNOWN_HOSTS = "~/.ssh/known_hosts"


def known_hosts_path(configured: str = "") -> str:
    """Resolve the trusted hosts file used for Analysis VM SSH.

    `~` expands to the current user's home, absolute paths are kept as-is,
    and relative paths resolve against the repo root. Blank values fall back
    to the current user's ~/.ssh/known_hosts.
    """
    value = str(configured or "").strip() or DEFAULT_KNOWN_HOSTS
    value = os.path.expanduser(value)
    if os.path.isabs(value):
        return os.path.normpath(value)
    return os.path.normpath(os.path.join(REPO, value))


def setting(name: str, default: str) -> str:
    """Same precedence as server.py: process env, then .env, then default."""
    if name in os.environ:
        return os.environ[name]
    env_file = os.path.join(REPO, ".env")
    if os.path.isfile(env_file):
        with open(env_file, encoding="utf-8-sig") as fh:
            for line in fh:
                entry = line.strip()
                if entry and not entry.startswith("#") and "=" in entry:
                    key, value = entry.split("=", 1)
                    if key.strip() == name:
                        return value.strip().strip("\"'")
    return default


def _int_setting(name: str, default: int) -> int:
    try:
        return int(setting(name, str(default)))
    except ValueError:
        return default


def analyzer_host() -> str:
    return setting("SA_API_HOST", "127.0.0.1")


def analyzer_port() -> int:
    return _int_setting("SA_API_PORT", 60020)


def analyzer_addr() -> str:
    return f"{analyzer_host()}:{analyzer_port()}"


def malapi_host() -> str:
    return setting("MALAPI_HOST", "127.0.0.1")


def malapi_port() -> int:
    return _int_setting("MALAPI_PORT", MALAPI_PORT_DEFAULT)


def ml_host() -> str:
    return setting("ML_HOST", "127.0.0.1")


def ml_port() -> int:
    return _int_setting("ML_PORT", ML_PORT_DEFAULT)


def ml_token() -> str:
    """Bearer token netcfg generates when ML is exposed off-loopback."""
    return setting("ML_SERVE_TOKEN", "")


def host_for(key: str) -> str:
    if key == "analyzer":
        return analyzer_host()
    if key == "malapi":
        return malapi_host()
    if key == "ml":
        return ml_host()
    return "127.0.0.1"


def port_for(key: str) -> int:
    if key == "analyzer":
        return analyzer_port()
    if key == "malapi":
        return malapi_port()
    if key == "ml":
        return ml_port()
    if key == "cyberchef":
        return CYBERCHEF_PORT
    if key == "kafka":
        return KAFKA_PORT
    if key == "guacamole":
        return GUACAMOLE_PORT
    return 0


def service_ports() -> dict[str, int]:
    """Every service's current port - netcfg rejects collisions with these."""
    return {key: port_for(key) for key in SERVICE_NAMES}


def bind_addr(host: str) -> str:
    """Address a service should actually hand to the OS.

    A configured non-loopback host (the analyzer's own IP, say) binds every
    interface instead: 0.0.0.0 still answers on that IP *and* on 127.0.0.1,
    which is where the analyzer's hardcoded MalAPI/ML clients connect. Binding
    only the external IP would cut its own pipeline off.
    """
    if host in ("127.0.0.1", "::1", "localhost", "0.0.0.0", "::"):
        return host
    try:
        return "::" if ipaddress.ip_address(host).version == 6 else "0.0.0.0"
    except ValueError:                     # hostname - IPv4 bind covers it
        return "0.0.0.0"


def probe_host(host: str) -> str:
    """Host to dial when checking a service (0.0.0.0 is not routable)."""
    return {"0.0.0.0": "127.0.0.1", "::": "::1"}.get(host, host)


def service_env(key: str) -> dict[str, str]:
    """Environment a service needs from .env (spawned children do not read it)."""
    if key == "malapi":
        return {"MALAPI_HOST": malapi_host(), "MALAPI_PORT": str(malapi_port())}
    if key == "ml":
        env = {"ML_PORT": str(ml_port())}
        if ml_token():
            env["ML_SERVE_TOKEN"] = ml_token()
        return env
    if key == "analyzer":
        return {"SA_API_HOST": analyzer_host(),
                "SA_API_PORT": str(analyzer_port())}
    return {}


def ensure_admin_logs() -> str:
    os.makedirs(ADMIN_LOGS, exist_ok=True)
    return ADMIN_LOGS


# ---------------------------------------------------------------------------
# Console cosmetics (Windows VT enabled transparently)
# ---------------------------------------------------------------------------
if os.name == "nt":  # enable ANSI on the real console
    try:
        import ctypes
        k32 = ctypes.windll.kernel32
        mode = ctypes.c_ulong()
        k32.GetConsoleMode(k32.GetStdHandle(-11), ctypes.byref(mode))
        k32.SetConsoleMode(k32.GetStdHandle(-11), mode.value | 0x0004)
    except Exception:  # noqa: BLE001 - plain pipes just lose colours
        pass

BOLD, DIM, RESET = "\033[1m", "\033[2m", "\033[0m"
GREEN, RED, YELLOW, CYAN, MAGENTA, BLUE = (
    "\033[92m", "\033[91m", "\033[93m", "\033[96m", "\033[95m", "\033[94m")

try:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:  # noqa: BLE001 - exotic streams just lose glyphs
    pass


def paint(text: str, *codes: str) -> str:
    if not sys.stdout.isatty():
        return text
    return "".join(codes) + text + RESET


def clear() -> None:
    if sys.stdout.isatty():
        print("\033[H\033[2J", end="")


def is_tty() -> bool:
    return sys.stdout.isatty()


# ---------------------------------------------------------------------------
# Input helpers
# ---------------------------------------------------------------------------
def ask(msg: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    got = input(f"{msg}{suffix}: ").strip()
    return got or default


def ask_int(msg: str, default: Optional[int] = None,
            lo: int = 1, hi: int = 65535) -> int:
    while True:
        raw = ask(msg, "" if default is None else str(default))
        try:
            val = int(raw)
        except ValueError:
            print(paint(f"  ! '{raw}' is not a number", RED))
            continue
        if not (lo <= val <= hi):
            print(paint(f"  ! must be between {lo} and {hi}", RED))
            continue
        return val


def confirm(msg: str, default: bool = False) -> bool:
    hint = "Y/n" if default else "y/N"
    got = ask(f"{msg} [{hint}]", "").lower()
    if not got:
        return default
    return got in ("y", "yes")


def pause(msg: str = "Press Enter to return to the menu") -> None:
    try:
        input(f"\n{msg} ")
    except EOFError:
        pass


def timestamp() -> str:
    return datetime.now().strftime("%Y-%m-%d_%H%M%S")


# ---------------------------------------------------------------------------
# Service model + probing
# ---------------------------------------------------------------------------
@dataclass
class Service:
    key: str                        # short id used by --only / activation
    name: str                       # display name in the console
    endpoint: str                   # http(s)://... or tcp://host:port
    kind: str = "http"              # "http" | "tcp"
    expect: int = 200               # expected HTTP status
    timeout: float = 3.0
    label: Optional[str] = None     # shorter endpoint shown in the table
    detail: Optional[Callable[[bytes], str]] = None   # body -> short note
    # filled by the probe
    up: bool = field(default=False, init=False)
    code: str = field(default="", init=False)         # "200" / "down"
    note: str = field(default="", init=False)
    ms: float = field(default=0.0, init=False)

    @property
    def shown(self) -> str:
        return self.label or self.endpoint


def _analyzer_note(body: bytes) -> str:
    try:
        d = json.loads(body)
        return f"queued={d.get('queued', '?')} running={d.get('running', '?')}"
    except Exception:  # noqa: BLE001
        return ""


def _malapi_note(body: bytes) -> str:
    try:
        d = json.loads(body)
        name = d.get("name") or d.get("api") or ""
        return name[:28]
    except Exception:  # noqa: BLE001
        return ""


def services(only: Optional[set[str]] = None) -> list[Service]:
    """Fresh registry - every endpoint follows the current .env."""
    addr = f"{probe_host(analyzer_host())}:{analyzer_port()}"
    malapi = f"{probe_host(malapi_host())}:{malapi_port()}"
    ml = f"{probe_host(ml_host())}:{ml_port()}"
    all_svcs = [
        Service("analyzer", "Analyzer API", f"{addr}/health",
                detail=_analyzer_note),
        Service("malapi", "MalAPI",
                f"{malapi}/malapi/AdjustTokenPrivileges/",
                label=f"{malapi}/malapi/...",
                detail=_malapi_note),
        Service("cyberchef", "CyberChef", f"127.0.0.1:{CYBERCHEF_PORT}/"),
        Service("guacamole", "Guacamole", f"127.0.0.1:{GUACAMOLE_PORT}/"),
        Service("ml", "ML scorer", f"{ml}/health"),
        Service("kafka", "Kafka broker", f"tcp://127.0.0.1:{KAFKA_PORT}",
                kind="tcp"),
        # Service("vault", "Vault", "127.0.0.1:8200/v1/sys/health"),
    ]
    if only:
        all_svcs = [s for s in all_svcs if s.key in only]
    return all_svcs


def why(exc: Exception) -> str:
    """Compact failure reason: 'connection refused', 'timed out', ..."""
    reason = getattr(exc, "reason", None)          # urllib.URLError
    if reason is not None:
        exc = reason  # type: ignore[assignment]
    if isinstance(exc, ConnectionRefusedError):
        return "connection refused"
    if isinstance(exc, TimeoutError):
        return "timed out"
    if isinstance(exc, OSError) and exc.strerror:
        return exc.strerror[:26]
    text = str(exc) or type(exc).__name__
    if "]" in text:                                # [WinError 10061] ...
        text = text.rsplit("]", 1)[-1].strip() or text
    return text[:26]


def probe(svc: Service) -> None:
    started = time.monotonic()
    url = svc.endpoint
    if "://" not in url:
        url = "http://" + url
    try:
        if svc.kind == "tcp":
            _, _, port = svc.endpoint.rpartition(":")
            host = svc.endpoint.split("://", 1)[-1].rsplit(":", 1)[0]
            with socket.create_connection((host, int(port)), timeout=svc.timeout):
                pass
            svc.up, svc.code = True, "open"
        else:
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, timeout=svc.timeout) as resp:
                body = resp.read(4096)
                status = resp.status
            svc.code = str(status)
            svc.up = status == svc.expect
            if svc.detail and svc.up:
                svc.note = svc.detail(body)
    except urllib.error.HTTPError as exc:          # answered, but not expected
        svc.code = str(exc.code)
        svc.up = exc.code == svc.expect
        svc.note = "unexpected status"
    except Exception as exc:                       # noqa: BLE001 - down, capture why
        svc.up = False
        svc.code = "down"
        svc.note = why(exc)
    finally:
        svc.ms = (time.monotonic() - started) * 1000


def probe_all(services_: list[Service]) -> None:
    threads = [threading.Thread(target=probe, args=(s,), daemon=True)
               for s in services_]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=max(s.timeout for s in services_) + 1.0)


def wait_ready(key: str, timeout: float = 20.0) -> bool:
    """Poll one service until it answers, for post-activation checks."""
    deadline = time.monotonic() + timeout
    while True:
        svc = next((s for s in services({key})), None)
        if svc is None:
            return False
        probe(svc)
        if svc.up:
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.5)


# ---------------------------------------------------------------------------
# Generic table rendering
# ---------------------------------------------------------------------------
def table(title: str, right: str, cols: tuple[int, ...],
          head: tuple[str, ...],
          rows: list[list[tuple[str, tuple[str, ...]]]]) -> str:
    """One box: title line, header, rows of (text, colour codes) cells."""
    total = sum(w + 2 for w in cols) + len(cols) + 1

    def rule(left: str, mid: str, right_: str) -> str:
        return left + mid.join("─" * (w + 2) for w in cols) + right_

    def row(cells: list[tuple[str, tuple[str, ...]]]) -> str:
        parts = []
        for i, (text, codes) in enumerate(cells):
            w = cols[i]
            parts.append(paint(text[:w].ljust(w), *codes))
        return "│ " + " │ ".join(parts) + " │"

    pad = max(1, total - len(title) - len(right))
    out = ["",
           " " + paint(title, BOLD, CYAN) + " " * pad + DIM + right + RESET,
           rule("┌", "┬", "┐"),
           row([(h, (BOLD, MAGENTA)) for h in head]),
           rule("├", "┼", "┤")]
    out.extend(row(r) for r in rows)
    out.append(rule("└", "┴", "┘"))
    return "\n".join(out)


def service_rows(svcs: list[Service]) -> list[list[tuple[str, tuple[str, ...]]]]:
    rows = []
    for s in svcs:
        if s.up:
            label, colour = " UP ", GREEN
        elif s.code in ("", "down"):
            label, colour = "DOWN", RED
        else:
            label, colour = "FAIL", YELLOW
        endpoint = s.shown.replace("http://", "").replace("tcp://", "")
        note = s.note or ("ok" if s.up else "")
        ms_colour = YELLOW if (s.up and s.ms > 1500) else DIM
        rows.append([
            (s.name, (BOLD,)),
            (endpoint, ()),
            (label, (BOLD, colour)),
            (f"{s.ms:.0f} ms", (ms_colour,)),
            (note, () if s.up else (colour,)),
        ])
    return rows


def render_services(svcs: list[Service], right: str = "") -> str:
    right = right or datetime.now().strftime("%H:%M:%S")
    up = sum(1 for s in svcs if s.up)
    body = table("SERVICE STATUS", right, (16, 32, 8, 9, 26),
                 ("SERVICE", "ENDPOINT", "STATUS", "LATENCY", "DETAIL"),
                 service_rows(svcs))
    return body + "\n" + paint(f"  {up}/{len(svcs)} up", DIM)


# ---------------------------------------------------------------------------
# Process helpers: listeners, detached spawns, streamed commands
# ---------------------------------------------------------------------------
def listener_pid(port: int) -> Optional[int]:
    """PID listening on a local TCP port, or None (needs no admin rights)."""
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "(Get-NetTCPConnection -LocalPort %d -State Listen "
             "-ErrorAction SilentlyContinue | Select-Object -First 1 "
             "-ExpandProperty OwningProcess)" % port],
            capture_output=True, text=True, timeout=10).stdout.strip()
        return int(out) if out else None
    except Exception:  # noqa: BLE001
        return None


def process_name(pid: int) -> str:
    try:
        out = subprocess.run(["tasklist", "/FI", f"PID eq {pid}"],
                             capture_output=True, text=True,
                             timeout=10).stdout.splitlines()
        for line in out[1:]:
            parts = line.split()
            if parts and parts[1] == str(pid):
                return parts[0]
    except Exception:  # noqa: BLE001
        pass
    return "?"


def kill_port(port: int) -> bool:
    """Force-kill whatever listens on a port (used for API restarts)."""
    pid = listener_pid(port)
    if not pid:
        return False
    try:
        subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"],
                       capture_output=True, timeout=15)
        return True
    except Exception:  # noqa: BLE001
        return False


def spawn_detached(cmd: list[str], cwd: str, log_path: str,
                   env: Optional[dict] = None) -> int:
    """Start a service as a background process; stdout -> log file.

    CREATE_NO_WINDOW gives the service its own *hidden* console.  That
    matters because services re-exec themselves down the line (a venv
    launcher starts the real interpreter, Flask can restart itself): a
    child spawned by a parent with no console would be handed a brand new,
    visible one - a stray cmd window whose closure kills the listener.
    Descendants inherit the hidden console instead, so no window ever
    appears and nothing the user closes can take the service down.
    DETACHED_PROCESS must not be combined with it (Windows ignores
    CREATE_NO_WINDOW in that case).
    """
    ensure_admin_logs()
    with open(log_path, "ab") as logf:
        logf.write(f"\n=== {datetime.now():%Y-%m-%d %H:%M:%S} "
                   f"$ {' '.join(cmd)}  (cwd={cwd})\n".encode())
        logf.flush()
        child_env = dict(env or os.environ)
        child_env.setdefault("PYTHONUNBUFFERED", "1")
        proc = subprocess.Popen(
            cmd, cwd=cwd, stdout=logf, stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL, env=child_env,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
            | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x200))
    return proc.pid


def _colourise(line: str) -> str:
    low = line.lower()
    if "error" in low or "fatal" in low or "failed" in low:
        return paint(line, RED)
    if "warning" in low or "warn" in low:
        return paint(line, YELLOW)
    if line.startswith("> "):
        return paint(line, CYAN)
    return line


def run_stream(cmd: list[str], cwd: str, log_path: Optional[str] = None,
               env: Optional[dict] = None) -> int:
    """Run a command, echo every line live, tee to a log file.

    Ctrl+C kills the whole child tree and returns 130 instead of leaking it.
    """
    if log_path:
        ensure_admin_logs()
    logf = open(log_path, "ab") if log_path else None
    if logf:
        logf.write(f"\n=== {datetime.now():%Y-%m-%d %H:%M:%S} "
                   f"$ {' '.join(cmd)}  (cwd={cwd})\n".encode())
        logf.flush()

    child_env = dict(env or os.environ)
    child_env.setdefault("PYTHONUNBUFFERED", "1")
    proc = subprocess.Popen(
        cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL, env=child_env, bufsize=0,
        creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x200))
    try:
        for raw in proc.stdout:
            if logf:
                logf.write(raw)
                logf.flush()
            line = raw.decode("utf-8", "replace").rstrip("\r\n")
            if line:
                print(_colourise(line))
        code = proc.wait()
    except KeyboardInterrupt:
        print(paint("\n  ! interrupted - killing child process tree", YELLOW))
        try:
            subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                           capture_output=True, timeout=15)
        except Exception:  # noqa: BLE001
            proc.kill()
        code = 130
    finally:
        if logf:
            logf.close()
    return code
