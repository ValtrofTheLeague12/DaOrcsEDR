"""Qiling emulation runs for the Qiling panel, read from real run artefacts.

Two on-disk sources, both produced by the harness in
python/qiling/_qiling_script.py:

  qiling_dlls/results/*_qiling_out.zip
      Per-sample run bundle: summary.json (sample, hashes, arch, elapsed,
      api_counts, behaviour_tags, attack_hints, iocs, yara_hits, dumps),
      events.jsonl, trace.log, report.md, plus memory dumps. The panel reads
      summary.json + the zip listing + trace tail out of the archive - it
      never extracts dumps to disk.

  config/systemd/qilin-service/artifacts/qilin-service.log
      Service-wide log: the [dump] / [sweep] / [ioc] / [summary] lines every
      run appends. Shown as the live output tail.

Rootfs state comes from the payload tree (qiling_dlls/examples/rootfs/ per
arch, archive size) - the same facts admin-terminal/qiling_setup.py validates
before deploying.
"""

from __future__ import annotations

import importlib
import json
import re
import sys
import threading
import time
import uuid
import zipfile
from pathlib import Path

from . import config

PAYLOAD_DIR = config.REPO / "qiling_dlls"
RESULTS_DIR = PAYLOAD_DIR / "results"
ROOTFS_DIR = PAYLOAD_DIR / "examples" / "rootfs"
ARCHIVE = PAYLOAD_DIR / "rootfs.tar.gz"
HARNESS = config.REPO / "python" / "qiling" / "_qiling_script.py"
SERVICE_LOG = config.REPO / "config" / "systemd" / "qilin-service" / "artifacts" / "qilin-service.log"
VM_INFO_FILE = PAYLOAD_DIR / "vm_info.json"

_TAIL_BYTES = 64 * 1024
_TAIL_LINES = 120
_ANSI = re.compile(r"\x1b\[[0-9;?]*[a-zA-Z]")


def _tail_lines(path: Path, max_lines: int = _TAIL_LINES) -> list[str]:
    try:
        size = path.stat().st_size
    except OSError:
        return []
    if size == 0:
        return []
    with path.open("rb") as fh:
        fh.seek(max(0, size - _TAIL_BYTES))
        data = fh.read()
    text = _ANSI.sub("", data.decode("utf-8", "replace"))
    lines = text.splitlines()
    return lines[-max_lines:]


def _zip_tail(zf: zipfile.ZipFile, name: str, max_lines: int = _TAIL_LINES) -> list[str]:
    try:
        raw = zf.read(name)
    except KeyError:
        return []
    text = _ANSI.sub("", raw.decode("utf-8", "replace"))
    return text.splitlines()[-max_lines:]


def _run_entry(path: Path) -> dict:
    entry = {
        "file": path.name,
        "stem": path.stem,
        "bytes": 0,
        "modified": 0.0,
        "ok": False,
        "detail": "",
        "sample": "",
        "arch": "",
        "elapsed_s": None,
        "end": "",
        "events": 0,
        "api_calls": 0,
        "api_counts": {},
        "behaviour_tags": {},
        "attack_hints": {},
        "ioc_count": 0,
        "iocs": [],
        "iocs_truncated": False,
        "yara_hits": [],
        "dump_count": 0,
        "hashes": {},
        "files": [],
        "trace_tail": [],
    }
    if path.name.endswith("_qiling_out.zip"):
        entry["stem"] = path.name[: -len("_qiling_out.zip")]
    try:
        stat = path.stat()
        entry["bytes"] = stat.st_size
        entry["modified"] = stat.st_mtime
    except OSError:
        entry["detail"] = "unreadable file"
        return entry
    try:
        zf = zipfile.ZipFile(path)
    except zipfile.BadZipFile as exc:
        entry["detail"] = f"not a zip: {exc}"
        return entry
    with zf:
        try:
            names = zf.namelist()
        except zipfile.BadZipFile as exc:
            entry["detail"] = f"corrupt zip: {exc}"
            return entry
        entry["files"] = [{"path": n, "bytes": zf.getinfo(n).file_size} for n in names]
        try:
            summary = json.loads(zf.read("summary.json").decode("utf-8"))
        except (KeyError, ValueError, UnicodeDecodeError) as exc:
            entry["detail"] = f"summary.json unreadable: {exc}"
            return entry
        if not isinstance(summary, dict):
            entry["detail"] = "summary.json is not an object"
            return entry
        entry["ok"] = True
        entry["sample"] = str(summary.get("sample", "") or "")
        entry["arch"] = str(summary.get("arch", "") or "")
        try:
            entry["elapsed_s"] = float(summary.get("elapsed_s")) if summary.get("elapsed_s") is not None else None
        except (TypeError, ValueError):
            entry["elapsed_s"] = None
        entry["end"] = str(summary.get("end", "") or "")
        try:
            entry["events"] = int(summary.get("events_written", 0) or 0)
        except (TypeError, ValueError):
            entry["events"] = 0
        api_counts = summary.get("api_counts") if isinstance(summary.get("api_counts"), dict) else {}
        try:
            entry["api_calls"] = sum(int(v) for v in api_counts.values())
        except (TypeError, ValueError):
            entry["api_calls"] = 0
        entry["api_counts"] = {str(k): v for k, v in api_counts.items()}
        tags = summary.get("behaviour_tags")
        entry["behaviour_tags"] = tags if isinstance(tags, dict) else {}
        hints = summary.get("attack_hints")
        entry["attack_hints"] = hints if isinstance(hints, dict) else {}
        iocs = summary.get("iocs") if isinstance(summary.get("iocs"), list) else []
        entry["ioc_count"] = len(iocs)
        entry["iocs"] = [str(i) for i in iocs[:100]]
        entry["iocs_truncated"] = len(iocs) > 100
        yara = summary.get("yara_hits") if isinstance(summary.get("yara_hits"), list) else []
        entry["yara_hits"] = yara[:50]
        dumps = summary.get("dumps") if isinstance(summary.get("dumps"), list) else []
        entry["dump_count"] = len(dumps)
        hashes = summary.get("sample_hashes")
        entry["hashes"] = hashes if isinstance(hashes, dict) else {}
        entry["trace_tail"] = _zip_tail(zf, "trace.log")
    return entry


def _rootfs() -> dict:
    out: dict = {
        "archive_present": ARCHIVE.is_file(),
        "archive_bytes": 0,
        "complete": False,
        "trees": [],
    }
    try:
        out["archive_bytes"] = ARCHIVE.stat().st_size if ARCHIVE.is_file() else 0
    except OSError:
        out["archive_bytes"] = 0
    for arch in ("x86_windows", "x8664_windows"):
        windows = ROOTFS_DIR / arch / "Windows"
        system32 = windows / "System32"
        try:
            files = sum(1 for _ in windows.rglob("*") if _.is_file()) if windows.is_dir() else 0
        except OSError:
            files = 0
        ok = (system32.is_dir()
              and (system32 / "kernel32.dll").is_file()
              and (system32 / "ntdll.dll").is_file()
              and (windows / "registry" / "SYSTEM").is_file())
        out["trees"].append({"arch": arch, "files": files, "complete": ok})
    out["complete"] = all(t["complete"] for t in out["trees"])
    return out


def _harness() -> dict:
    version = ""
    try:
        for line in HARNESS.read_text(encoding="utf-8").splitlines()[:12]:
            if "v5" in line or "1.4.6" in line:
                version = line.strip().lstrip("# ").strip()
                break
    except OSError:
        pass
    return {
        "present": HARNESS.is_file(),
        "path": "python/qiling/_qiling_script.py",
        "version": version or "Qiling 1.4.6 harness",
        "service": "qilin-service.service",
        "service_type": "oneshot",
    }


def runs(limit: int = 20) -> dict:
    """Newest Qiling run bundles plus rootfs/harness state and log tail."""
    entries: list[dict] = []
    present = RESULTS_DIR.is_dir()
    if present:
        try:
            paths = sorted(RESULTS_DIR.glob("*_qiling_out.zip"),
                           key=lambda p: p.stat().st_mtime, reverse=True)
        except OSError:
            paths = []
        for path in paths[:50]:
            if path.is_file():
                entries.append(_run_entry(path))
    try:
        vm_info = json.loads(VM_INFO_FILE.read_text(encoding="utf-8"))
        vm_info = vm_info if isinstance(vm_info, dict) else {}
    except (OSError, ValueError):
        vm_info = {}
    log_size = 0
    try:
        log_size = SERVICE_LOG.stat().st_size
    except OSError:
        pass
    return {
        "present": present,
        "path": str(RESULTS_DIR),
        "file_count": len(entries),
        "runs": entries[: max(1, min(limit, 50))],
        "rootfs": _rootfs(),
        "harness": _harness(),
        "service_log": {
            "present": SERVICE_LOG.is_file(),
            "bytes": log_size,
            "tail": _tail_lines(SERVICE_LOG),
        },
        "vm": {
            "name": str(vm_info.get("VM_NAME", "") or ""),
            "ip": str(vm_info.get("VM_IP", "") or ""),
            "port": vm_info.get("VM_PORT", 22),
        },
        "checked_at": round(time.time(), 1),
    }


# ---------------------------------------------------------------------------
# VM status: the Qiling analysis VM itself (VirtualBox + SSH reachability).
#
# Delegates to python/qiling/_check_vm_connection.py - the exact functions the
# admin-terminal "Qiling VM Control" screen and the standalone CLI use - so the
# panel can never disagree with them about whether the VM is up. Imported
# lazily and by path (it is not a package module) and never for side effects.
# ---------------------------------------------------------------------------

_CHECK_DIR = config.REPO / "python" / "qiling"


def _load_check_module():
    if str(_CHECK_DIR) not in sys.path:
        sys.path.insert(0, str(_CHECK_DIR))
    return importlib.import_module("_check_vm_connection")


def vm_status() -> dict:
    """VBoxManage / VM registration / power / TCP checks, no SSH login."""
    out = {
        "checked_at": round(time.time(), 1),
        "available": False,
        "checks": [],
        "ok": False,
        "vm_name": "",
        "vm_ip": "",
        "running": False,
        "error": "",
    }
    try:
        info = json.loads(VM_INFO_FILE.read_text(encoding="utf-8"))
        info = info if isinstance(info, dict) else {}
    except (OSError, ValueError):
        info = {}
    out["vm_name"] = str(info.get("VM_NAME", "") or "")
    out["vm_ip"] = str(info.get("VM_IP", "") or "")
    try:
        mod = _load_check_module()
        raw = mod.run_checks(ssh=False)
    except Exception as exc:  # noqa: BLE001 - a status page must not 500
        out["error"] = f"{type(exc).__name__}: {exc}"
        return out
    out["available"] = True
    out["checks"] = [
        {"name": c.name, "ok": bool(c.ok), "detail": str(c.detail)}
        for c in raw
    ]
    out["ok"] = all(c.ok for c in raw)
    for c in raw:
        if c.name == "VM power":
            out["running"] = bool(c.ok)
    return out


# ---------------------------------------------------------------------------
# Guest CPU / RAM: read live from inside the running VM over SSH.
#
# Only meaningful while the VM is up; when it is powered off or SSH times out
# the caller gets available:false with the reason, never zeros - a powered-off
# guest is not a guest idling at 0%.
#
# One exec_command returns key=value-ish lines parsed with float(), and every
# number is read from /proc and nproc rather than `free`/`df`, whose column
# layout differs between coreutils and busybox and would corrupt the values.
# ---------------------------------------------------------------------------

def guest_metrics(timeout: float = 8.0) -> dict:
    out = {
        "available": False,
        "reachable": False,
        "cores": None,
        "load": {"1": None, "5": None, "15": None},
        "memory": {"total_bytes": None, "used_bytes": None,
                   "available_bytes": None, "percent": None,
                   "swap_total_bytes": None, "swap_used_bytes": None},
        "disk": {"total_bytes": None, "used_bytes": None, "free_bytes": None,
                 "percent": None},
        "uptime_seconds": None,
        "error": "",
    }
    try:
        info = json.loads(VM_INFO_FILE.read_text(encoding="utf-8"))
        info = info if isinstance(info, dict) else {}
    except (OSError, ValueError):
        info = {}
    host = str(info.get("VM_IP", "") or "").strip()
    user = str(info.get("VM_HOST", "") or "").strip()
    password = str(info.get("VM_PASSWORD", "") or "")
    try:
        port = int(info.get("VM_PORT", 22) or 22)
    except (TypeError, ValueError):
        port = 22
    if not host or not user:
        out["error"] = "vm_info.json: VM_IP and VM_HOST are required"
        return out
    try:
        import paramiko
    except ImportError:
        out["error"] = "paramiko is not installed (pip install paramiko)"
        return out

    # Every value from /proc or nproc: stable across distros. `nproc` then
    # /proc/loadavg, the four meminfo keys, uptime seconds, then df's triple.
    cmd = (
        "nproc 2>/dev/null; "
        "cat /proc/loadavg 2>/dev/null; "
        "awk '/^MemTotal:|^MemAvailable:|^SwapTotal:|^SwapFree:/{print $1$2}' "
        "/proc/meminfo 2>/dev/null; "
        "cut -d' ' -f1 /proc/uptime 2>/dev/null; "
        "df -B1 / 2>/dev/null | awk 'NR==2{print $2, $3, $4}'"
    )

    def _f(v):
        try:
            return float(v)
        except (TypeError, ValueError):
            return None

    client = paramiko.SSHClient()
    try:
        try:
            client.load_system_host_keys()
        except OSError:
            pass
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(host, port=port, username=user, password=password,
                       timeout=timeout, banner_timeout=timeout,
                       auth_timeout=timeout)
        out["reachable"] = True
        _stdin, stdout, _stderr = client.exec_command(cmd, timeout=timeout)
        text = stdout.read().decode("utf-8", "replace")
    except Exception as exc:  # noqa: BLE001 - powered off / refused / timeout
        out["error"] = f"{type(exc).__name__}: {exc}"
        return out
    finally:
        try:
            client.close()
        except Exception:  # noqa: BLE001
            pass

    out["available"] = True
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    if lines:
        out["cores"] = int(_f(lines[0]) or 0) or None
    if len(lines) >= 2:
        parts = lines[1].split()
        for key, idx in (("1", 0), ("5", 1), ("15", 2)):
            out["load"][key] = _f(parts[idx]) if len(parts) > idx else None
    mem = {}
    for line in lines[2:6]:
        m = re.match(r"^(MemTotal|MemAvailable|SwapTotal|SwapFree)(\d+)$", line)
        if m:
            mem[m.group(1)] = float(m.group(2)) * 1024  # kB -> bytes
    total, avail = mem.get("MemTotal"), mem.get("MemAvailable")
    if total:
        used = total - (avail if avail is not None else 0)
        out["memory"].update({
            "total_bytes": int(total),
            "available_bytes": int(avail) if avail is not None else None,
            "used_bytes": int(used),
            "percent": round(used / total * 100, 1),
        })
    swap_total, swap_free = mem.get("SwapTotal"), mem.get("SwapFree")
    if swap_total:
        out["memory"]["swap_total_bytes"] = int(swap_total)
        out["memory"]["swap_used_bytes"] = int(swap_total - (swap_free or 0))
    # The df triple is the last line; uptime is the numeric-only line before it.
    if len(lines) >= 2 and _f(lines[-2]) is not None:
        out["uptime_seconds"] = _f(lines[-2])
    df = lines[-1].split() if lines else []
    if len(df) == 3 and all(_f(p) is not None for p in df):
        dt, du, dfree = float(df[0]), float(df[1]), float(df[2])
        out["disk"] = {
            "total_bytes": int(dt), "used_bytes": int(du),
            "free_bytes": int(dfree),
            "percent": round(du / dt * 100, 1) if dt else None,
        }
    if out["cores"] is None and not out["memory"]["total_bytes"]:
        out["available"] = False
        out["error"] = out["error"] or "guest returned no /proc data"
    return out


# ---------------------------------------------------------------------------
# Generate rootfs - a long, interactive job, not a request.
#
# admin-terminal/qiling_setup.py:setup_rootfs() runs dll_collector.bat through
# Start-Process -Verb RunAs, so it pops a Windows UAC prompt on the machine the
# panel runs on (the operator will see it; the browser never does) and takes
# minutes. It is therefore run on a worker thread and reported through a job
# handle rather than blocking the request.
#
# setup_rootfs() is imported from admin-terminal/, which is on sys.path only
# for this call. It is safe: unlike _configure_quiling.py it has no
# module-scope execution - importing it opens no SSH session and pushes no
# rootfs. control()'s deploy path is deliberately NOT wired here; that would
# upload 116 MB to the VM, which is a separate explicit action.
# ---------------------------------------------------------------------------

_ADMIN_DIR = config.REPO / "admin-terminal"
_jobs: dict[str, dict] = {}
_jobs_lock = threading.Lock()


def _run_rootfs_job(job_id: str) -> None:
    def _set(**kw):
        with _jobs_lock:
            _jobs[job_id].update(kw)

    _set(state="running", started_at=round(time.time(), 1))
    try:
        if str(_ADMIN_DIR) not in sys.path:
            sys.path.insert(0, str(_ADMIN_DIR))
        import core  # admin-terminal shared plumbing
        import qiling_setup
        core.ensure_admin_logs()
        qiling_setup.setup_rootfs()
        complete = qiling_setup.rootfs_exists()
        _set(state="done", complete=complete, finished_at=round(time.time(), 1),
             detail=("rootfs collected, validated and packaged"
                     if complete else
                     "collector finished but the tree is still incomplete"))
    except Exception as exc:  # noqa: BLE001 - surface any failure to the UI
        _set(state="error", finished_at=round(time.time(), 1),
             detail=f"{type(exc).__name__}: {exc}")


def generate_rootfs() -> dict:
    """Start a rootfs build on a worker thread; returns the job handle."""
    job_id = uuid.uuid4().hex[:12]
    with _jobs_lock:
        # One build at a time: two elevated collectors racing over the same
        # tree would corrupt it.
        active = next((j for j in _jobs.values() if j.get("state") == "running"), None)
        if active:
            return {"job_id": active["id"], "state": "running",
                    "already_running": True,
                    "detail": "a rootfs build is already in progress"}
        _jobs[job_id] = {"id": job_id, "state": "queued",
                         "created_at": round(time.time(), 1), "detail": ""}
    threading.Thread(target=_run_rootfs_job, args=(job_id,),
                     name=f"rootfs-{job_id}", daemon=True).start()
    with _jobs_lock:
        return {"job_id": job_id, "state": _jobs[job_id]["state"],
                "already_running": False, "detail": ""}


def rootfs_job(job_id: str) -> dict | None:
    with _jobs_lock:
        job = _jobs.get(job_id)
        if job is None:
            return None
        return {
            "id": job["id"], "state": job["state"], "detail": job.get("detail", ""),
            "complete": job.get("complete"),
            "created_at": job.get("created_at"),
            "started_at": job.get("started_at"),
            "finished_at": job.get("finished_at"),
            "rootfs": _rootfs(),
        }


