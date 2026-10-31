"""ClamAV: service status, sample submission and scan results.

Three questions, deliberately answered by three different mechanisms:

  results()   reads the JSON documents the scanner already wrote
              (python/clamd/results/<stem>_<stamp>_<rand>.json). It never
              invents a verdict and never re-scans. A zero-byte file (an
              interrupted SFTP download, of which there are two real examples
              on disk) is reported as failed with the reason attached.

  status()    reports whether the SELECTED transport can actually run, and it
              selects nothing itself: the transport is the one recorded in
              config/dynamic_analysis.json (the Dynamic Analysis >
              Configuration radio group). Choosing it in two places would let
              the panel check one path and submit down the other.

                sftp selected -> check the driver scripts in python/clamd/:
                                 scan_remote.py, clamd-python.py, vm_info.json
                                 and paramiko. No SSH session is opened by a
                                 status poll.

                tcp selected  -> use the operator's SocketValidator to open the
                                 socket, then ask clamd for PING and VERSION.
                                 A daemon that does not answer cannot scan.

              Read-only in both cases.

  start_submit()
              is the one action with real side effects, and it has two
              transports because the lab has two:

                sftp  deploys the sample into the analysis VM with the
                      host-side driver that is already in the repo,
                      python/clamd/scan_remote.py, and scans it there. The
                      panel only spawns that script and reads the JSON it
                      brings home - the SSH/SFTP/freshclam logic is not
                      duplicated here.

                tcp   talks to a clamd that is listening on a TCP port
                      directly, using the operator's SocketValidator in
                      python/panel/utils/socket_validator.py to open the
                      socket, then speaks clamd's INSTREAM command on it.
                      That module is used as-is and is not modified.

Both paths write the same result document shape as clamd-python.py, so the
Results tab cannot tell which transport produced a row.

The scanner contract lives in python/clamd/clamd-python.py: each run writes
one JSON document with {ok, verdict, status, signature, filename, sha256,
clamd_version, endpoint, seconds, date_of_analysis}.
"""

from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import os
import re
import secrets
import shutil
import struct
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from ..build import build
from ..core import config
from ..samples import dynamic_analysis

CLAMD_DIR = config.REPO / "python" / "clamd"
RESULTS_DIR = CLAMD_DIR / "results"
VM_INFO_FILE = CLAMD_DIR / "vm_info.json"

# The existing tools. Neither is edited by the panel: scan_remote.py owns the
# deploy -> run -> collect flow, socket_validator.py owns the TCP client.
SCAN_REMOTE = CLAMD_DIR / "scan_remote.py"
CLAMD_SCANNER = CLAMD_DIR / "clamd-python.py"
SOCKET_VALIDATOR = Path(__file__).resolve().parents[1] / "utils" / "socket_validator.py"

# A clamd configured with StreamMaxLength 25M refuses anything larger, and
# buffering more than that in a staging file to find out is pointless.
SUBMIT_MAX_BYTES = 25 * 1024 * 1024
# SFTP includes a freshclam pass when the VM allows it, so it gets room; TCP is
# one INSTREAM request and gets the daemon's own timeout plus slack.
SUBMIT_TIMEOUT = {"sftp": 900.0, "tcp": 180.0}

_MAX_FILES = 200  # newest files parsed; the directory is small, this is a guard
_ANSI = re.compile(r"\x1b\[[0-9;]*m")

# Jobs live in the same store as builds and utility runs, so one GET
# /api/build/<id> can follow any of them and a reload never orphans one.
_jobs = build._jobs
_jobs_lock = build._jobs_lock
_now = build._now
_prune = build._prune

_submit_running: str | None = None


class SubmitError(Exception):
    """A refusal with a machine-readable code the route can map to a status."""

    def __init__(self, message: str, code: str = "submit-failed"):
        super().__init__(message)
        self.code = code

    def as_dict(self) -> dict:
        return {"ok": False, "code": self.code, "error": str(self)}


def _vm_info() -> dict:
    try:
        data = json.loads(VM_INFO_FILE.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _result_entry(path: Path) -> dict:
    entry = {
        "file": path.name,
        "bytes": 0,
        "modified": 0.0,
        "verdict": "failed",
        "signature": "",
        "filename": "",
        "sha256": "",
        "clamd_version": "",
        "endpoint": "",
        "seconds": None,
        "detail": "",
    }
    try:
        stat = path.stat()
        entry["bytes"] = stat.st_size
        entry["modified"] = stat.st_mtime
    except OSError:
        entry["detail"] = "unreadable file"
        return entry
    if entry["bytes"] == 0:
        entry["detail"] = "zero bytes - SFTP download was interrupted"
        return entry
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        entry["detail"] = f"unparseable result: {exc}"
        return entry
    if not isinstance(doc, dict):
        entry["detail"] = "result is not a JSON object"
        return entry
    verdict = str(doc.get("verdict", "") or "").lower()
    entry["verdict"] = verdict if verdict in ("infected", "clean") else "failed"
    entry["signature"] = str(doc.get("signature", "") or "")
    entry["filename"] = str(doc.get("filename", "") or "")
    entry["sha256"] = str(doc.get("sha256", "") or "")
    entry["clamd_version"] = str(doc.get("clamd_version", "") or "")
    entry["endpoint"] = str(doc.get("endpoint", "") or "")
    try:
        entry["seconds"] = float(doc.get("seconds")) if doc.get("seconds") is not None else None
    except (TypeError, ValueError):
        entry["seconds"] = None
    if entry["verdict"] == "failed":
        entry["detail"] = str(doc.get("detail", "") or doc.get("error", "") or "scanner reported an error")
    return entry


def results(limit: int = 50) -> dict:
    """Newest ClamAV result files plus verdict counts."""
    files: list[dict] = []
    present = RESULTS_DIR.is_dir()
    if present:
        try:
            paths = sorted(RESULTS_DIR.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
        except OSError:
            paths = []
        for path in paths[:_MAX_FILES]:
            if path.is_file():
                files.append(_result_entry(path))
    counts = {"infected": 0, "clean": 0, "failed": 0}
    for f in files:
        if f["verdict"] in counts:
            counts[f["verdict"]] += 1
    total_bytes = sum(f["bytes"] for f in files)
    return {
        "present": present,
        "path": str(RESULTS_DIR),
        "file_count": len(files),
        "total_bytes": total_bytes,
        "counts": counts,
        "files": files[: max(1, min(limit, 200))],
        "checked_at": round(time.time(), 1),
    }


def result_document(name: str) -> dict:
    """One result file exactly as the scanner wrote it.

    This is the evidence behind a verdict, not a re-derivation of it: the page
    shows the bytes so the operator can check the document a row was read from.

    `name` must be a bare `<something>.json` file name as it appeared in
    results(). A separator, a parent reference or any other suffix is refused
    rather than resolved, so a crafted name cannot read outside RESULTS_DIR.
    """
    base = str(name or "").strip()
    if (not base or base in (".", "..") or "/" in base or "\\" in base
            or Path(base).name != base
            or Path(base).suffix.lower() != ".json"):
        raise SubmitError(f"'{name}' is not a result file name", "bad-name")
    path = RESULTS_DIR / base
    if not path.is_file():
        raise SubmitError(f"no result file named '{base}'", "not-found")
    try:
        stat = path.stat()
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise SubmitError(f"cannot read {base}: {exc}", "unreadable") from exc
    return {"name": base, "bytes": stat.st_size,
            "modified": stat.st_mtime, "raw": raw}



# ---------------------------------------------------------------------------
# status: connection-test checks mirroring test_clamd_connection.sh
# ---------------------------------------------------------------------------


def _clamd_cfg() -> dict:
    try:
        data = json.loads(VM_INFO_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    cfg = data.get("clamd") if isinstance(data, dict) else None
    return cfg if isinstance(cfg, dict) else {}


def _run(args: list[str], timeout: float) -> tuple[int, str]:
    import shutil
    import subprocess
    if not args or not shutil.which(args[0]):
        return 127, f"{args[0] if args else '?'} not on PATH"
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout,
                              encoding="utf-8", errors="replace", check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        return 127, f"{type(exc).__name__}: {exc}"
    out = ((proc.stdout or "") + (proc.stderr or "")).strip()
    return proc.returncode, out.splitlines()[-1] if out else ""


def _check(name: str, ok: bool, detail: str, advisory: bool = False,
           echo: str = "", icon: str = "check") -> dict:
    """One check.

    `name` is the machine label (a file name, a command), `detail` is the
    evidence, and `echo` is the sentence the transcript prints *before* the
    result - a shell script echoes what it is about to do, and a bare list of
    outcomes does not say which step produced which line. `icon` names the glyph
    the page draws for this kind of step; it is a hint, and an unknown value
    falls back to a tick.
    """
    return {"name": name, "ok": ok, "detail": detail, "advisory": advisory,
            "echo": echo or name, "icon": icon}


def _clean_output(text: str) -> str:
    """The last useful line of captured print() narration, ANSI stripped."""
    lines = [ln.strip() for ln in _ANSI.sub("", text).splitlines() if ln.strip()]
    return lines[-1] if lines else ""


def _trace_lines(text: str) -> list[str]:
    """Captured print() narration, ANSI stripped, blank lines dropped."""
    return [ln.rstrip() for ln in _ANSI.sub("", text).splitlines() if ln.strip()]


def _file_usable(path: Path) -> bool:
    """A driver must be there AND have something in it.

    A zero-byte script or module imports cleanly and then does nothing, which is
    exactly the state the operator's socket_validator.py was found in. Reporting
    it as present would offer a transport that silently cannot run.
    """
    try:
        return path.is_file() and path.stat().st_size > 0
    except OSError:
        return False


def _probe(label: str, driver: Path, files: list[Path],
           modules: tuple[str, ...], detail: str) -> dict:
    """One transport, as a fact: every file and module it needs is here."""
    missing = [p.name for p in files if not _file_usable(p)]
    absent = [m for m in modules if importlib.util.find_spec(m) is None]
    if missing:
        reason = "missing or empty: " + ", ".join(missing)
    elif absent:
        reason = (", ".join(absent) + " not installed (pip install "
                  + " ".join(absent) + ")")
    else:
        reason = None
    return {"id": label, "available": reason is None, "reason": reason,
            "path": str(driver), "files": [str(p) for p in files],
            "detail": detail}


def transports() -> dict:
    """Which ways this host can actually move a sample to a scanner, right now.

    SFTP needs the whole python/clamd/ driver - the host-side script, the in-VM
    scanner it deploys and the vm_info.json it reads. TCP is the operator's
    socket client, which imports ifaddr and colorama. A transport missing any
    of them is a button that fails after the upload, not a transport.
    """
    return {
        "sftp": _probe(
            "sftp", SCAN_REMOTE,
            [SCAN_REMOTE, CLAMD_SCANNER, VM_INFO_FILE],
            ("paramiko",),
            "python/clamd/scan_remote.py - SSH/SFTP into the analysis VM, "
            "scan there, bring the result JSON home"),
        "tcp": _probe(
            "tcp", SOCKET_VALIDATOR, [SOCKET_VALIDATOR],
            ("ifaddr", "colorama"),
            "panel/utils/socket_validator.py - open a TCP socket to clamd and "
            "send the sample with INSTREAM"),
    }


def _communication() -> dict:
    """The selected transport, read from config/dynamic_analysis.json.

    One place decides. The ClamAV page neither offers a second choice nor
    guesses: a malformed file is an error it reports, not a silent fallback
    that would submit down a path nobody selected.
    """
    path = dynamic_analysis.CONFIG_RELATIVE.as_posix()
    try:
        settings = dynamic_analysis.load(config.REPO)
    except (OSError, ValueError) as exc:
        return {"mode": dynamic_analysis.DEFAULT_COMMUNICATION,
                "path": path, "error": str(exc)}
    return {"mode": settings["communication"], "path": path, "error": None}


def _sftp_checks() -> list[dict]:
    """The driver files in python/clamd/, which is what the SFTP path runs.

    No SSH session is opened: a status poll must stay cheap and must not be the
    thing that keeps a stopped VM half-awake. Whether a daemon answers is
    proved by a scan; whether the driver can start is proved here.
    """
    checks: list[dict] = []
    for label, path, echo, icon in (
            ("scan_remote.py", SCAN_REMOTE,
             "locating the host-side SFTP driver", "file-code"),
            ("clamd-python.py", CLAMD_SCANNER,
             "locating the in-VM scanner it deploys", "file-code"),
            ("vm_info.json", VM_INFO_FILE,
             "locating the VM details both of them read", "file-text")):
        exists = path.is_file()
        checks.append(_check(label, exists,
                             str(path) if exists else f"missing at {path}",
                             echo=echo, icon=icon))
    found = importlib.util.find_spec("paramiko") is not None
    checks.append(_check("paramiko installed", found,
                         "importable" if found else "pip install paramiko",
                         echo="checking the SSH library is importable",
                         icon="code"))
    info = _vm_info()
    vm_ip = str(info.get("VM_IP", "") or "")
    vm_host = str(info.get("VM_HOST", "") or "")
    vm_port = info.get("VM_PORT", 22)
    checks.append(_check(
        "VM target", bool(vm_ip or vm_host),
        f"{vm_host}@{vm_ip}:{vm_port}" if (vm_ip or vm_host)
        else "vm_info.json names no VM",
        echo="reading the VM address out of vm_info.json", icon="wifi"))
    return checks


def _probe_tcp(validator_cls, host: str, port: int,
               timeout: float = 10.0) -> dict:
    """Open the socket with the operator's client, then ask clamd directly.

    The client owns the interface check and the connect (it sets its own 3s
    timeout); this only speaks the two commands that answer "is it alive and
    what is it". Every line it prints is captured into `trace`, so the status
    page can show the connection test's own output instead of paraphrasing it.
    """
    sink = io.StringIO()
    validator = None
    sock = None
    try:
        with contextlib.redirect_stdout(sink):
            validator = validator_cls(host)
            sock = validator.establish_tcp_connection(port)
    except Exception as exc:  # noqa: BLE001 - a refusal is the answer
        return {"connected": False, "pong": False, "version": "",
                "detail": f"{type(exc).__name__}: {exc}",
                "trace": _trace_lines(sink.getvalue())}
    if sock is None:
        return {"connected": False, "pong": False, "version": "",
                "detail": _clean_output(sink.getvalue()) or "connection failed",
                "trace": _trace_lines(sink.getvalue())}

    pong = False
    version = ""
    detail = ""
    try:
        sock.settimeout(timeout)
        sock.sendall(b"zPING\0")
        pong = b"PONG" in _recv_reply(sock).upper()
        sock.sendall(b"zVERSION\0")
        version = _recv_reply(sock).decode("utf-8", "replace").strip("\0\r\n ")
    except OSError as exc:
        detail = f"{type(exc).__name__}: {exc}"
    finally:
        try:
            with contextlib.redirect_stdout(sink):
                validator.closeConnection(sock)
        except Exception:  # noqa: BLE001 - closing is best-effort
            pass
    return {"connected": True, "pong": pong, "version": version,
            "detail": detail, "trace": _trace_lines(sink.getvalue())}


def _tcp_checks() -> tuple[list[dict], str, bool, list[str]]:
    """(checks, version, answered, trace) for the socket_validator transport."""
    checks: list[dict] = []
    usable = _file_usable(SOCKET_VALIDATOR)
    detail = (str(SOCKET_VALIDATOR) if usable
              else f"empty at {SOCKET_VALIDATOR}" if SOCKET_VALIDATOR.is_file()
              else f"missing at {SOCKET_VALIDATOR}")
    checks.append(_check(
        "socket_validator.py", usable, detail,
        echo="locating the operator's TCP client", icon="file-code"))
    for module, echo in (
            ("ifaddr", "checking ifaddr - the client enumerates every adapter"),
            ("colorama", "checking colorama - the client colours its output")):
        found = importlib.util.find_spec(module) is not None
        checks.append(_check(f"{module} installed", found,
                             "importable" if found else f"pip install {module}",
                             echo=echo, icon="code"))
    if not all(c["ok"] for c in checks):
        return checks, "", False, []

    host, port = _tcp_target()
    # The address the validator will actually dial, so this row can never
    # disagree with the scan that follows it.
    checks.append(_check("clamd target", True, f"{host}:{port}",
                         echo="resolving the clamd address", icon="wifi"))
    try:
        validator_cls = _socket_validator()
    except SubmitError as exc:
        checks.append(_check("socket client loads", False, str(exc),
                             echo="importing socket_validator.py unchanged",
                             icon="code"))
        return checks, "", False, []
    checks.append(_check("socket client loads", True,
                         "panel/utils/socket_validator.py, imported unchanged",
                         echo="importing socket_validator.py unchanged",
                         icon="code"))

    probe = _probe_tcp(validator_cls, host, port)
    checks.append(_check("connect", probe["connected"],
                         probe["detail"] or f"{host}:{port}",
                         echo="opening the socket, exactly as a scan does",
                         icon="plug"))
    checks.append(_check("PING -> PONG", probe["pong"],
                         "clamd answered PONG" if probe["pong"]
                         else ("not connected, so clamd was never asked"
                               if not probe["connected"]
                               else (probe["detail"] or "no answer")),
                         echo="asking clamd for PING and VERSION",
                         icon="activity"))
    return checks, probe["version"], probe["pong"], probe["trace"]


def _condense_trace(trace: list[str]) -> list[str]:
    """Fold the socket client's per-adapter enumeration into one line.

    SocketValidator prints a line for every network adapter, plus a "found
    within host only network" line for each, just to prove the target IP is
    local. On this host that is dozens of lines that change whenever a VPN or
    virtual adapter is installed, and they bury the connect result. The count
    is kept, so the log says what was folded rather than silently dropping it.
    """
    out: list[str] = []
    folded = 0

    def flush() -> None:
        nonlocal folded
        if folded:
            out.append(f"… {folded} interface lines omitted "
                       "(the client checks every adapter)")
            folded = 0

    for line in trace:
        stripped = line.strip()
        if (stripped.startswith("IPs of network adapter")
                or stripped.startswith("Given IP Adrress is found within host only network")
                or stripped.startswith("Given IP is found in interface")):
            folded += 1
            continue
        flush()
        out.append(line)
    flush()
    return out


def _status_output(comm: dict, endpoint: str, checks: list[dict],
                   trace: list[str]) -> list[str]:
    """The connection test as a transcript, for the console on the page.

    A shell script echoes what it is about to do, then prints the result. This
    does the same: every step is announced as ``[n/total] intent`` and the line
    under it is that step's evidence, so a failure is attributable to a step
    rather than to a list. The text is generated here rather than assembled in
    the browser so the console and the check cards can never disagree.
    """
    total = len(checks)
    failed = [c for c in checks if not c["ok"] and not c.get("advisory")]
    passed = [c for c in checks if c["ok"]]
    if failed:
        summary = f"{total} steps - {len(passed)} passed, {len(failed)} failed"
    else:
        summary = f"{total} steps - every step passed"

    lines = [f"$ clamd connection test - {comm['mode']} ({comm['path']})",
             f"  endpoint {endpoint}",
             f"  {summary}",
             ""]
    for i, c in enumerate(checks, 1):
        lines.append(f"[{i}/{total}] {c.get('echo') or c['name']}")
        mark = "ok" if c["ok"] else ("info" if c.get("advisory") else "FAIL")
        lines.append(f"[{mark:4}] {c['name']}: {c['detail']}")
    if trace:
        lines.append("")
        if comm["mode"] == "tcp":
            lines.append("  socket_validator.py said:")
            lines.extend("    " + line for line in _condense_trace(trace))
        else:
            lines.extend("  note  " + line for line in trace)
    lines.append("--- ready" if not failed else "--- not ready")
    return lines


def status() -> dict:
    """Whether the selected transport can run, and the evidence for it.

    The transport comes from config/dynamic_analysis.json - the same file the
    Dynamic Analysis page writes - and the endpoint details from
    python/clamd/vm_info.json, which is what the scripts themselves read.
    """
    cfg = _clamd_cfg()
    info = _vm_info()
    socket_path = str(cfg.get("socket", "/var/run/clamav/clamd.ctl") or "")
    conn_mode = str(cfg.get("mode", "unix") or "unix")

    comm = _communication()
    ways = transports()
    version = ""
    reachable = False
    trace: list[str] = []

    if comm["mode"] == "sftp":
        checks = _sftp_checks()
        vm_ip = str(info.get("VM_IP", "") or "")
        vm_host = str(info.get("VM_HOST", "") or "")
        vm_port = info.get("VM_PORT", 22)
        endpoint = f"ssh://{vm_host}@{vm_ip}:{vm_port}"
        trace = ["file checks only - no SSH session opened"]
        note = ("SFTP transport: python/clamd/scan_remote.py deploys the sample "
                "and scans it inside the analysis VM. These checks verify the "
                "driver files and the VM details it reads; they open no SSH "
                "session, so the daemon itself is proved by a scan.")
    else:
        checks, version, reachable, trace = _tcp_checks()
        host, port = _tcp_target()
        endpoint = f"tcp://{host}:{port}"
        note = ("TCP transport: panel/utils/socket_validator.py opens the "
                "socket and clamd is asked for PING and VERSION on it. This "
                "page never SSHes anywhere.")

    hard_ok = all(c["ok"] or c.get("advisory") for c in checks)
    return {
        "ready": hard_ok,
        "reachable": reachable,
        "mode": conn_mode,
        "endpoint": endpoint,
        "version": version,
        "checked_at": round(time.time(), 1),
        # The connection test's own output: the rows above plus the client's
        # narration. Rendered by the Service status tab's Output panel.
        "output": _status_output(comm, endpoint, checks, trace),
        # The choice, where it was written, and why it could not be read.
        "communication": comm,
        "transports": ways,
        "default_transport": comm["mode"],
        "vm": {
            "ip": str(info.get("VM_IP", "") or ""),
            "host": str(info.get("VM_HOST", "") or ""),
            "port": info.get("VM_PORT", 22),
        },
        "checks": checks,
        "ok": hard_ok,
        "note": note,
    }


def scan_file(path, timeout: float = 60.0) -> dict:
    """Scan one local file through clamdscan; never raises, never blocks forever.

    Verdicts and their evidence: exit 0 -> "clean"; exit 1 -> "infected", with
    the signature parsed out of clamdscan's "<path>: <signature> FOUND" line;
    anything else (no binary on PATH, no daemon answering, timeout) ->
    "unavailable". The CALLER owns the policy for each verdict - the upload
    route quarantines infected files and refuses unscanned ones by default -
    this function only reports what the scanner said, with the raw line kept
    as detail because "ok" from a scanner that was not actually asked is the
    one answer worse than "unavailable".
    """
    import shutil
    import time
    started = time.monotonic()
    scan_bin = shutil.which("clamdscan")
    if not scan_bin:
        return {"verdict": "unavailable", "signature": None, "seconds": 0.0,
                "error": "clamdscan not on PATH"}

    cfg = _clamd_cfg()
    mode = str(cfg.get("mode", "unix") or "unix")
    args = [scan_bin, "--no-summary"]
    if mode != "unix":
        # The daemon lives in the analysis VM; a TCP-mode config means the
        # local binary is a client, and a scan has to be told where to go.
        try:
            port = int(cfg.get("port", 3310) or 3310)
        except (TypeError, ValueError):
            port = 3310
        args += ["--host", str(cfg.get("host", "127.0.0.1") or "127.0.0.1"),
                 "--port", str(port)]
    args.append(str(path))

    code, out = _run(args, timeout)
    seconds = round(time.monotonic() - started, 2)
    if code == 0:
        return {"verdict": "clean", "signature": None, "seconds": seconds}
    if code == 1:
        body = out.split(":", 1)[1] if ":" in out else out
        signature = body.replace("FOUND", "").strip()
        return {"verdict": "infected", "signature": signature or "unknown",
                "seconds": seconds, "detail": out[:200]}
    return {"verdict": "unavailable", "signature": None, "seconds": seconds,
            "error": out[:200] or f"clamdscan exited {code}"}


# ---------------------------------------------------------------------------
# Submitting a sample
#
# One job per scan, in the shared job store, for the same reason the build and
# utility runs use it: the work outlives an HTTP request, and a reload should
# reattach rather than orphan a half-finished SFTP deploy.
# ---------------------------------------------------------------------------


def _log(job_id: str, line: str) -> None:
    line = _ANSI.sub("", line)
    with _jobs_lock:
        job = _jobs.get(job_id)
        if job is None:
            return
        job["log"].append(line)
        job["log_line_count"] += 1
        if len(job["log"]) > 4000:
            drop = len(job["log"]) - 4000
            del job["log"][:drop]
            job["log_dropped"] += drop


class _LogPipe(io.TextIOBase):
    """A stdout replacement for code that narrates with print().

    SocketValidator says what it is doing with print() - useful output for the
    operator, but not a return value. Redirecting stdout into the job log
    captures it without changing that module.
    """

    def __init__(self, job_id: str):
        self._job_id = job_id
        self._buf = ""

    def writable(self) -> bool:
        return True

    def write(self, text: str) -> int:  # noqa: D401 - io protocol
        self._buf += text
        while "\n" in self._buf:
            line, self._buf = self._buf.split("\n", 1)
            if line.strip():
                _log(self._job_id, "    " + line.rstrip())
        return len(text)

    def flush(self) -> None:
        if self._buf.strip():
            _log(self._job_id, "    " + self._buf.rstrip())
        self._buf = ""


def _kill_tree(proc: subprocess.Popen) -> None:
    """Kill the child and everything it started.

    scan_remote.py spawns ssh inside paramiko's own process, but a timed-out
    local tool on Windows is one process with children; proc.kill() would leave
    whatever it started running and holding the pipe that the reader is
    blocked on.
    """
    if proc.poll() is not None:
        return
    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                           capture_output=True, timeout=15)
        else:
            proc.kill()
    except (OSError, subprocess.SubprocessError):
        pass


def _stage_upload(filename: str, stream) -> dict:
    """Stream one upload to a private temp directory, hashing as it goes.

    The client's name is a NAME only. The size cap is enforced while writing so
    an oversized body is cut off mid-write rather than buffered whole.
    """
    name = Path(str(filename or "").replace("\\", "/")).name.strip()
    if not name or name in (".", ".."):
        raise SubmitError("the upload has no usable file name", "bad-name")

    folder = Path(tempfile.mkdtemp(prefix="ia-clamd-"))
    dest = folder / name
    digest = hashlib.sha256()
    total = 0
    try:
        with dest.open("wb") as fh:
            while True:
                chunk = stream.read(64 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > SUBMIT_MAX_BYTES:
                    raise SubmitError(
                        f"the sample exceeds the {SUBMIT_MAX_BYTES // (1024 * 1024)} "
                        "MiB limit", "too-large")
                fh.write(chunk)
                digest.update(chunk)
        if total == 0:
            raise SubmitError("the uploaded sample is empty", "empty")
    except SubmitError:
        shutil.rmtree(folder, ignore_errors=True)
        raise
    except OSError as exc:
        shutil.rmtree(folder, ignore_errors=True)
        raise SubmitError(f"cannot stage the upload: {exc}", "stage-failed") from exc

    return {"path": dest, "folder": folder, "name": name, "bytes": total,
            "sha256": digest.hexdigest()}


def _write_result(doc: dict) -> Path:
    """Persist one result document where the Results tab already reads from."""
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%dT%H%M%S")
    stem = Path(str(doc.get("filename") or "sample")).stem or "sample"
    name = f"{stem}_{stamp}_{secrets.token_hex(3)}.json"
    path = RESULTS_DIR / name
    path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    return path


def _scan_sftp(job_id: str, staged: dict) -> tuple[dict, Path]:
    """Deploy, scan and collect with the repo's own driver.

    Nothing about the SSH/SFTP flow is reimplemented here: scan_remote.py is
    the contract, and the panel reads the JSON it brings home.
    """
    if not SCAN_REMOTE.is_file():
        raise SubmitError(f"{SCAN_REMOTE} is missing", "transport-unavailable")

    before = ({p.name for p in RESULTS_DIR.glob("*.json")}
              if RESULTS_DIR.is_dir() else set())
    argv = [sys.executable, str(SCAN_REMOTE), str(staged["path"])]
    _log(job_id, f"    $ {' '.join(argv)}")

    proc = subprocess.Popen(
        argv, cwd=str(config.REPO), stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, text=True, encoding="utf-8",
        errors="replace", bufsize=1,
        env={**os.environ, "PYTHONUNBUFFERED": "1"},
    )
    timed_out = threading.Event()

    def expire() -> None:
        timed_out.set()
        _kill_tree(proc)

    timer = threading.Timer(SUBMIT_TIMEOUT["sftp"], expire)
    timer.daemon = True
    timer.start()
    try:
        # Reading stdout line by line is what makes the log live. The watchdog
        # is what stops a hung child from keeping this loop open forever;
        # wait(timeout) alone cannot, because it is only reached at EOF.
        assert proc.stdout is not None
        for line in proc.stdout:
            _log(job_id, "    " + line.rstrip("\r\n"))
        code = proc.wait()
    finally:
        timer.cancel()

    if timed_out.is_set():
        raise SubmitError(
            f"scan_remote.py did not finish within "
            f"{int(SUBMIT_TIMEOUT['sftp'])}s", "timeout")

    new = [p for p in RESULTS_DIR.glob("*.json") if p.name not in before]
    if not new:
        raise SubmitError(
            f"scan_remote.py exited {code} without writing a result file",
            "no-result")
    path = max(new, key=lambda p: p.stat().st_mtime)
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise SubmitError(f"the result file is unreadable: {exc}",
                          "bad-result") from exc
    if not isinstance(doc, dict):
        raise SubmitError("the result file is not a JSON object", "bad-result")
    _log(job_id, f"    result: {path}")
    return doc, path


def _socket_validator():
    """Load the operator's socket client by path, unchanged.

    socket_validator.py is an operator-supplied tool, not a panel module, so
    it is loaded from its file: that is exactly how its own __main__ runs it,
    and it keeps the tool free of panel-specific edits.
    """
    if not _file_usable(SOCKET_VALIDATOR):
        raise SubmitError(f"{SOCKET_VALIDATOR} is missing or empty",
                          "transport-unavailable")
    if importlib.util.find_spec("ifaddr") is None:
        raise SubmitError("ifaddr is not installed (pip install ifaddr)",
                          "transport-unavailable")
    spec = importlib.util.spec_from_file_location(
        "ia_socket_validator", SOCKET_VALIDATOR)
    if spec is None or spec.loader is None:
        raise SubmitError("cannot load socket_validator.py",
                          "transport-unavailable")
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as exc:  # noqa: BLE001 - a broken module is an answer
        raise SubmitError(f"cannot load socket_validator.py: {exc}",
                          "transport-unavailable") from exc
    # An empty or unrelated file imports perfectly well and then has nothing in
    # it. That is a transport that cannot run, not a crash on the status poll.
    validator = getattr(module, "SocketValidator", None)
    if validator is None:
        raise SubmitError(
            "socket_validator.py defines no SocketValidator "
            f"({SOCKET_VALIDATOR.stat().st_size} bytes)",
            "transport-unavailable")
    return validator


def _tcp_target() -> tuple[str, int]:
    cfg = _clamd_cfg()
    info = _vm_info()
    host = str(cfg.get("host", "") or "").strip()
    vm_ip = str(info.get("VM_IP", "") or "").strip()
    # vm_info's unix-mode 127.0.0.1 is the guest's own loopback. For a TCP scan
    # from the host, the daemon has to be the VM's address unless the config
    # names a different one explicitly.
    if (not host or host in ("127.0.0.1", "localhost", "::1")) and vm_ip:
        host = vm_ip
    try:
        port = int(cfg.get("port", 3310) or 3310)
    except (TypeError, ValueError):
        port = 3310
    return host or "127.0.0.1", port


def _recv_reply(sock) -> bytes:
    data = b""
    while True:
        part = sock.recv(4096)
        if not part:
            break
        data += part
        # clamd terminates its reply with \n or \0 depending on version.
        if b"\0" in data or b"\n" in data:
            break
    return data


def _parse_instream(reply: bytes) -> tuple[str, str, str]:
    """(status, signature, detail) from clamd's INSTREAM reply."""
    text = reply.decode("utf-8", "replace").replace("\0", "").strip()
    if not text:
        return "ERROR", "", "clamd closed the connection without a reply"
    upper = text.upper()
    if "FOUND" in upper:
        signature = text.rsplit(":", 1)[-1].replace("FOUND", "").strip()
        return "FOUND", signature or "unknown", ""
    if "ERROR" in upper:
        detail = text.split("ERROR")[0].strip(" .:") or text
        return "ERROR", "", detail
    if upper.endswith("OK") or ": OK" in upper:
        return "OK", "", ""
    return "ERROR", "", text[:200]


def _scan_tcp(job_id: str, staged: dict) -> tuple[dict, Path]:
    """Open a TCP socket with SocketValidator, then speak INSTREAM on it."""
    validator_cls = _socket_validator()
    host, port = _tcp_target()
    _log(job_id, f"    transport: TCP {host}:{port} (INSTREAM)")
    _log(job_id, "    socket:    panel/utils/socket_validator.py")

    sink = _LogPipe(job_id)
    validator = None
    sock = None
    try:
        with contextlib.redirect_stdout(sink):
            validator = validator_cls(host)
            sock = validator.establish_tcp_connection(port)
    except SubmitError:
        raise
    except Exception as exc:  # noqa: BLE001 - the validator raises TypeError
        raise SubmitError(f"socket_validator rejected {host}: {exc}",
                          "connect-failed") from exc
    finally:
        sink.flush()

    if sock is None:
        raise SubmitError(f"socket_validator could not connect to {host}:{port}",
                          "connect-failed")

    started = time.perf_counter()
    try:
        try:
            sock.settimeout(float(_clamd_cfg().get("timeout", 60) or 60))
            data = staged["path"].read_bytes()
            _log(job_id, f"    INSTREAM {staged['name']} ({staged['bytes']:,} bytes)")
            sock.sendall(b"zINSTREAM\0")
            for offset in range(0, len(data), 8192):
                chunk = data[offset:offset + 8192]
                sock.sendall(struct.pack(">I", len(chunk)) + chunk)
            sock.sendall(struct.pack(">I", 0))
            reply = _recv_reply(sock)
        except SubmitError:
            raise
        except Exception as exc:  # noqa: BLE001 - timeout, reset, refused
            raise SubmitError(f"INSTREAM failed: {type(exc).__name__}: {exc}",
                              "scan-failed") from exc
    finally:
        if validator is not None:
            try:
                with contextlib.redirect_stdout(sink):
                    validator.closeConnection(sock)
                sink.flush()
            except Exception:  # noqa: BLE001 - closing is best-effort
                pass

    seconds = round(time.perf_counter() - started, 2)
    status, signature, detail = _parse_instream(reply)
    _log(job_id, f"    clamd: {status}" + (f" ({signature})" if signature else ""))
    if status == "ERROR":
        raise SubmitError(f"clamd rejected the stream: {detail or 'no detail'}",
                          "scan-failed")

    doc = {
        "ok": True,
        "error": "",
        "date_of_analysis": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "sample": staged["name"],
        "filename": staged["name"],
        "sha256": staged["sha256"],
        "verdict": "infected" if status == "FOUND" else "clean",
        "status": status,
        "signature": signature,
        "detail": detail,
        "clamd_version": "",
        "endpoint": f"tcp:{host}:{port}",
        "seconds": seconds,
    }
    path = _write_result(doc)
    _log(job_id, f"    result: {path}")
    return doc, path


def _set_row(job_id: str, row: dict) -> None:
    with _jobs_lock:
        job = _jobs.get(job_id)
        if job is not None:
            job["results"] = [dict(row)]


def _finish(job_id: str, *, state: str, code: int, summary: str) -> None:
    with _jobs_lock:
        job = _jobs.get(job_id)
        if job is None or job.get("state") != "running":
            return
        job.update(state=state, exit_code=code,
                   finished_at=round(_now(), 1), summary=summary)


def _run_submit(job_id: str, staged: dict, mode: str) -> None:
    global _submit_running
    row = {
        "id": "scan", "label": staged["name"], "state": "running", "detail": None,
        "duration": None, "verdict": None, "signature": None,
        "sha256": staged["sha256"], "bytes": staged["bytes"], "result_file": None,
    }
    started = time.time()
    try:
        _set_row(job_id, row)
        doc, path = (_scan_sftp(job_id, staged) if mode == "sftp"
                     else _scan_tcp(job_id, staged))
        verdict = str(doc.get("verdict", "") or "").lower()
        signature = str(doc.get("signature", "") or "")
        duration = round(time.time() - started, 2)
        if verdict not in ("clean", "infected"):
            detail = str(doc.get("detail") or doc.get("error")
                         or "the scanner reported no verdict")
            row.update(state="failed", detail=detail, duration=duration)
            _set_row(job_id, row)
            _log(job_id, f"--- {staged['name']}: FAILED ({detail})")
            _finish(job_id, state="failed", code=1, summary=f"failed: {detail}")
            return
        row.update(state="passed", verdict=verdict, signature=signature,
                   detail=(f"infected: {signature}" if signature else verdict),
                   duration=duration, result_file=str(path))
        _set_row(job_id, row)
        _log(job_id,
             f"--- {staged['name']}: {'INFECTED' if verdict == 'infected' else 'CLEAN'}"
             + (f" ({signature})" if signature else "")
             + f" in {duration}s")
        _finish(job_id, state="passed", code=0,
                summary=verdict + (f": {signature}" if signature else ""))
    except SubmitError as exc:
        duration = round(time.time() - started, 2)
        row.update(state="failed", detail=str(exc), duration=duration)
        _set_row(job_id, row)
        _log(job_id, f"--- {staged['name']}: FAILED ({exc})")
        _finish(job_id, state="failed", code=1, summary=f"failed: {exc}")
    except Exception as exc:  # noqa: BLE001 - a dead thread must not zombie the job
        duration = round(time.time() - started, 2)
        row.update(state="failed", detail=f"{type(exc).__name__}: {exc}",
                   duration=duration)
        _set_row(job_id, row)
        _log(job_id, f"    {type(exc).__name__}: {exc}")
        _finish(job_id, state="failed", code=1,
                summary=f"crashed: {type(exc).__name__}")
    finally:
        shutil.rmtree(staged["folder"], ignore_errors=True)
        with _jobs_lock:
            if _submit_running == job_id:
                globals()["_submit_running"] = None


def start_submit(filename: str, stream, mode: str | None = None) -> dict:
    """Stage one upload and scan it. Returns a job handle, or a refusal.

    The transport is NOT a parameter of this feature: it is whatever
    config/dynamic_analysis.json says, because the ClamAV page and the Dynamic
    Analysis page must not be able to disagree about how a sample travels. An
    explicit `mode` is accepted only when it matches, so an old client gets a
    sentence rather than a scan down a path the operator did not choose.

    The configured transport is also checked for availability before a byte of
    the sample is written: a missing driver script is a refusal, not a job
    that fails after a 25 MiB upload.
    """
    global _submit_running
    comm = _communication()
    if comm["error"]:
        return {"ok": False, "code": "config-error",
                "error": f"{comm['path']}: {comm['error']}"}
    selected = comm["mode"]
    if mode and mode.strip().lower() not in ("", selected):
        return {"ok": False, "code": "mode-locked",
                "error": (f"the transport is set to '{selected}' in "
                          f"{comm['path']}; change it on the Dynamic Analysis "
                          "page instead of overriding it here")}
    mode = selected

    ways = transports()
    if mode not in ways:
        return {"ok": False, "code": "bad-mode",
                "error": f"unknown transport '{mode}'; expected sftp or tcp"}
    if not ways[mode]["available"]:
        return {"ok": False, "code": "transport-unavailable",
                "error": f"{mode} is not available: {ways[mode]['reason']}"}

    try:
        staged = _stage_upload(filename, stream)
    except SubmitError as exc:
        result = exc.as_dict()
        result["limit_bytes"] = SUBMIT_MAX_BYTES
        return result

    with _jobs_lock:
        _prune(_now())
        if _submit_running is not None:
            shutil.rmtree(staged["folder"], ignore_errors=True)
            return {"ok": False, "error": "a ClamAV scan is already in progress",
                    "job_id": _submit_running}
        jid = f"c{int(_now())}{secrets.token_hex(2)}"
        _jobs[jid] = {
            "id": jid, "state": "running", "kind": "clamd", "mode": mode,
            "started_at": round(_now(), 1), "finished_at": None,
            "exit_code": None, "error": None, "log": [], "log_line_count": 0,
            "log_dropped": 0, "command": "", "artifact": None, "summary": None,
            "selected": [], "results": [],
        }
        # Inside the lock on purpose: check-and-set outside it lets two
        # requests both pass the guard and run two scans.
        globals()["_submit_running"] = jid

    _log(jid, f"ClamAV sample: {staged['name']} ({staged['bytes']:,} bytes)")
    _log(jid, f"sha256: {staged['sha256']}")
    _log(jid, f"transport: {mode}")
    threading.Thread(target=_run_submit, args=(jid, staged, mode), daemon=True,
                     name="clamd-submit").start()
    return {"ok": True, "job_id": jid, "mode": mode, "filename": staged["name"],
            "bytes": staged["bytes"], "sha256": staged["sha256"]}


def current_submit() -> dict | None:
    """The scan in progress, or the most recent one, so a reload reattaches."""
    with _jobs_lock:
        _prune(_now())
        owned = [(k, v) for k, v in _jobs.items() if v.get("kind") == "clamd"]
        if not owned:
            return None
        jid = max(owned, key=lambda kv: (kv[1].get("state") == "running",
                                          kv[1].get("started_at") or 0))[0]
        return build._job_view(dict(_jobs[jid]))
