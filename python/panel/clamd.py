"""ClamAV scan results for the ClamAV panel, read from real result files.

The scanner contract lives in python/clamd/clamd-python.py: each run writes
one JSON document (python/clamd/results/<stem>_<stamp>_<rand>.json) with
{ok, verdict, status, signature, filename, sha256, clamd_version, endpoint,
seconds, date_of_analysis}. This module reads those files - it never invents
verdicts, never re-scans, and never talks to the VM. A zero-byte file (an
interrupted SFTP download, of which there are two real examples on disk) is
reported as failed with the reason attached, not silently skipped.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from . import config

RESULTS_DIR = config.REPO / "python" / "clamd" / "results"
VM_INFO_FILE = config.REPO / "python" / "clamd" / "vm_info.json"

_MAX_FILES = 200  # newest files parsed; the directory is small, this is a guard


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


def _check(name: str, ok: bool, detail: str, advisory: bool = False) -> dict:
    return {"name": name, "ok": ok, "detail": detail, "advisory": advisory}


def status() -> dict:
    """Connection-test status mirroring test_clamd_connection.sh."""
    import shutil
    cfg = _clamd_cfg()
    try:
        info = json.loads(VM_INFO_FILE.read_text(encoding="utf-8"))
        info = info if isinstance(info, dict) else {}
    except (OSError, ValueError):
        info = {}
    socket_path = str(cfg.get("socket", "/var/run/clamav/clamd.ctl") or "")
    mode = str(cfg.get("mode", "unix") or "unix")
    host = str(cfg.get("host", "127.0.0.1") or "127.0.0.1")
    try:
        port = int(cfg.get("port", 3310) or 3310)
    except (TypeError, ValueError):
        port = 3310

    checks: list[dict] = []

    scan_bin = shutil.which("clamdscan")
    checks.append(_check("clamdscan present", bool(scan_bin), scan_bin or "not on PATH"))

    code, out = _run(["tasklist", "/FI", "IMAGENAME eq clamd.exe", "/FO", "CSV"], 10)
    running = "clamd" in out.lower() if code == 0 else False
    if not running:
        checks.append(_check("clamd process (this host)", False,
                             "no local clamd.exe - daemon lives in the VM", advisory=True))
    else:
        checks.append(_check("clamd process (this host)", True, out[:120]))

    if mode == "unix":
        sock = Path(socket_path)
        exists = sock.exists()
        checks.append(_check("control socket", exists,
                             socket_path if exists else f"{socket_path} - VM path, not present on this host",
                             advisory=not exists))
    else:
        checks.append(_check("tcp endpoint", True, f"{host}:{port}"))

    version = ""
    ping_ok = False
    if scan_bin:
        if mode == "unix":
            code, out = _run([scan_bin, "--ping"], 15)
        else:
            code, out = _run([scan_bin, "--ping", "--host", host, "--port", str(port)], 15)
        ping_ok = code == 0 and "PONG" in out.upper()
        checks.append(_check("PING -> PONG", ping_ok,
                             out[:160] if ping_ok else (out[:160] or "no local clamd to answer"),
                             advisory=not ping_ok))
        code, out = _run([scan_bin, "--version"], 15)
        if code == 0 and out:
            version = out[:160]
            checks.append(_check("VERSION", True, version))
        else:
            checks.append(_check("VERSION", False, out[:160] or "unavailable locally", advisory=True))
    else:
        checks.append(_check("PING -> PONG", False, "clamdscan not on PATH - cannot probe", advisory=True))
        checks.append(_check("VERSION", False, "clamdscan not on PATH", advisory=True))

    hard_ok = all(c["ok"] or c.get("advisory") for c in checks)
    reachable = ping_ok or bool(version)
    endpoint = f"unix:{socket_path}" if mode == "unix" else f"tcp:{host}:{port}"
    return {
        "reachable": reachable,
        "mode": mode,
        "endpoint": endpoint,
        "version": version,
        "vm": {
            "ip": str(info.get("VM_IP", "") or ""),
            "host": str(info.get("VM_HOST", "") or ""),
            "port": info.get("VM_PORT", 22),
        },
        "checks": checks,
        "ok": hard_ok,
        "note": "Local checks only: the clamd daemon runs inside the analysis VM and answers over SSH, so PING/VERSION reflect a local daemon if one exists.",
    }
