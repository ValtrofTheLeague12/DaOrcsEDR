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

import contextlib
import hashlib
import importlib
import importlib.util
import io
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import uuid
import zipfile
from pathlib import Path

from ..build import build
from ..core import config
from ..samples import dynamic_analysis
from ..utils.vm_utility import Service, VirtualUtility

PAYLOAD_DIR = config.REPO / "qiling_dlls"
RESULTS_DIR = PAYLOAD_DIR / "results"
ROOTFS_DIR = PAYLOAD_DIR / "examples" / "rootfs"
ARCHIVE = PAYLOAD_DIR / "rootfs.tar.gz"
HARNESS = config.REPO / "python" / "qiling" / "_qiling_script.py"
SERVICE_LOG = config.REPO / "config" / "systemd" / "qilin-service" / "artifacts" / "qilin-service.log"
VM_INFO_FILE = PAYLOAD_DIR / "vm_info.json"

# Submission. The transport is not chosen here: config/dynamic_analysis.json
# holds it, exactly as it does for ClamAV, so the Dynamic Analysis page and this
# page cannot disagree about how a sample reaches the guest.
ADMIN_DIR = config.REPO / "admin-terminal"
QILING_UPLOAD = ADMIN_DIR / "qiling_upload.py"
QILING_SETUP = ADMIN_DIR / "qiling_setup.py"
VMS_FILE = ADMIN_DIR / "vms.json"
SOCKET_VALIDATOR = Path(__file__).resolve().parents[1] / "utils" / "socket_validator.py"
CLAMD_VM_INFO = config.REPO / "python" / "clamd" / "vm_info.json"

SUBMIT_MAX_BYTES = 25 * 1024 * 1024
# SFTP packages/uploads the 117 MiB rootfs when the guest lacks it and then runs
# the sample, so the job's own watchdog is generous. The TCP path relies on the
# utility client's socket timeout instead.
SFTP_TIMEOUT = 1800.0
DEFAULT_TIMEOUT = 60
DEFAULT_MAX_INSN = 1_000_000
PING_TIMEOUT = 10.0

_ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")

# Submission jobs live in the shared job store so /api/build/<id> can follow
# them and a reload reattaches instead of orphaning a running upload.
_submit_jobs = build._jobs
_submit_lock = build._jobs_lock
_submit_now = build._now
_submit_prune = build._prune
_submit_running: str | None = None

_TAIL_BYTES = 64 * 1024
_TAIL_LINES = 120


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
    text = data.decode("utf-8", "replace")
    lines = text.splitlines()
    return lines[-max_lines:]


def _zip_tail(zf: zipfile.ZipFile, name: str, max_lines: int = _TAIL_LINES) -> list[str]:
    try:
        raw = zf.read(name)
    except KeyError:
        return []
    text = raw.decode("utf-8", "replace")
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
        "archive": str(ARCHIVE),
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
        files = 0
        total = 0
        try:
            if windows.is_dir():
                for entry in windows.rglob("*"):
                    if entry.is_file():
                        files += 1
                        total += entry.stat().st_size
        except OSError:
            pass
        ok = (system32.is_dir()
              and (system32 / "kernel32.dll").is_file()
              and (system32 / "ntdll.dll").is_file()
              and (windows / "registry" / "SYSTEM").is_file())
        out["trees"].append({"arch": arch, "files": files, "bytes": total,
                             "path": str(windows), "complete": ok})
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
    """Live CPU / RAM for the Qiling guest, served from the shared collector.

    This used to open its own paramiko session on every call - and the Qiling
    panel calls it on mount and on every Check Status, so each click paid a
    full SSH handshake (8 s worst case) while the Statistics page was already
    collecting the same guest every 15 s in vmmetrics' daemon thread. It now
    reads vmmetrics' cache, which is populated in the background and answers
    immediately. `timeout` is kept for callers that still pass it; the cached
    collector owns its own connect timeout.

    The shape stays the one this panel has always served, so the frontend
    contract does not move: vmmetrics' payload carries the same /proc-derived
    fields under the same names.
    """
    from ..network import vmmetrics

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
        "collected_at": None,
        "age_seconds": None,
    }
    try:
        info = json.loads(VM_INFO_FILE.read_text(encoding="utf-8"))
        info = info if isinstance(info, dict) else {}
    except (OSError, ValueError):
        info = {}
    host = str(info.get("VM_IP", "") or "").strip()
    name = str(info.get("VM_NAME", "") or "").strip() or "Analysis VM"
    if not host:
        out["error"] = "vm_info.json: VM_IP and VM_HOST are required"
        return out

    try:
        payload = vmmetrics.for_guest(name, host)
    except Exception as exc:  # noqa: BLE001 - a status page must not 500
        out["error"] = f"{type(exc).__name__}: {exc}"
        return out
    if payload is None:
        out["error"] = "vm_info.json has no VM_IP/VM_HOST pair for this guest"
        return out

    state = payload.get("state") or "down"
    # `pending` means the collector is running but has not sampled yet: the
    # machine is instrumented and may well be up, it just has no answer. That
    # is not "unreachable", and painting it as such would be a false negative.
    out["reachable"] = state in ("up", "pending")
    out["available"] = state == "up"
    out["collected_at"] = payload.get("collected_at")
    out["age_seconds"] = payload.get("age_seconds")
    if state != "up":
        out["error"] = (payload.get("error")
                        or ("the collector has not sampled this guest yet"
                            if state == "pending" else ""))
        return out

    out["cores"] = payload.get("cores")
    out["load"] = payload.get("load") or out["load"]
    mem = payload.get("memory") or {}
    out["memory"] = {
        "total_bytes": mem.get("total_bytes"),
        "used_bytes": mem.get("used_bytes"),
        "available_bytes": mem.get("available_bytes"),
        "percent": mem.get("percent"),
        "swap_total_bytes": mem.get("swap_total_bytes"),
        "swap_used_bytes": mem.get("swap_used_bytes"),
    }
    out["disk"] = payload.get("disk") or out["disk"]
    out["uptime_seconds"] = payload.get("uptime_seconds")
    out["age_seconds"] = payload.get("age_seconds")
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


# ---------------------------------------------------------------------------
# Submit a sample
#
# Same two transports as ClamAV, because the lab has the same two ways to reach
# the guest:
#
#   sftp  admin-terminal/qiling_upload.py - package the local rootfs when the
#         guest lacks it, upload harness + sample over SFTP, run Qiling over
#         SSH and download the report zip. The panel spawns the CLI; it does
#         not reimplement any of the SSH/SFTP flow.
#
#   tcp   panel/utils/socket_validator.py opens the VM utility socket and
#         panel/utils/vm_utility.py does the work: preflight, chunked sample
#         upload, qiling_run, qiling_report. The report lands in
#         qiling_dlls/results/ just like the SFTP path.
#
# The transport is read from config/dynamic_analysis.json. One job per run, in
# the shared job store, so /api/build/<id> follows it and a reload reattaches.
# ---------------------------------------------------------------------------


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


def _file_usable(path: Path) -> bool:
    try:
        return path.is_file() and path.stat().st_size > 0
    except OSError:
        return False


def _probe(label: str, driver: Path, files: list[Path],
           modules: tuple[str, ...], detail: str) -> dict:
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
            "modules": list(modules), "detail": detail}


def _rootfs_reason() -> str | None:
    rootfs = _rootfs()
    if not rootfs["complete"]:
        return "the local Qiling rootfs is incomplete; build it first"
    if not ARCHIVE.is_file():
        return f"missing {ARCHIVE.name}; build the rootfs first"
    return None


def transports() -> dict:
    """Which ways this host can move a sample to Qiling, right now."""
    rootfs_reason = _rootfs_reason()
    sftp = _probe(
        "sftp", QILING_UPLOAD,
        [QILING_UPLOAD, QILING_SETUP, VMS_FILE, HARNESS, ARCHIVE],
        (),
        "admin-terminal/qiling_upload.py - SSH/SFTP into the analysis VM, "
        "upload harness + sample, run Qiling, bring the report zip home")
    tcp = _probe(
        "tcp", SOCKET_VALIDATOR,
        [SOCKET_VALIDATOR, VM_INFO_FILE],
        ("ifaddr", "loguru"),
        "panel/utils/vm_utility.py - upload the sample to the VM utility "
        "server, run Qiling there and download the evidence archive")
    if rootfs_reason:
        for way in (sftp, tcp):
            if way["available"]:
                way.update(available=False, reason=rootfs_reason)
    return {"sftp": sftp, "tcp": tcp}


def _check(name: str, ok: bool, detail: str, advisory: bool = False,
           echo: str = "", icon: str = "check") -> dict:
    """One connection-test step: the label, its evidence, and what it announced.

    `echo` is the sentence the transcript prints before the result, so a failed
    step is attributable rather than an unexplained red row.
    """
    return {"name": name, "ok": ok, "detail": detail, "advisory": advisory,
            "echo": echo or name, "icon": icon}


def _trace_lines(text: str) -> list[str]:
    """Captured print() narration, blank lines dropped; ANSI is kept."""
    return [ln.rstrip() for ln in text.splitlines() if ln.strip()]


def _clean_output(text: str) -> str:
    """The last useful line of captured narration, ANSI stripped."""
    lines = [ln.strip() for ln in _ANSI.sub("", text).splitlines() if ln.strip()]
    return lines[-1] if lines else ""


def _condense_trace(trace: list[str]) -> list[str]:
    """Fold the socket client's per-adapter enumeration into one line."""
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


# How a file in a transport probe reads in the connection test.
_STEP_ECHO: dict[str, str] = {
    "qiling_upload.py": "locating the host-side SFTP driver",
    "qiling_setup.py": "locating the rootfs packager it calls",
    "vms.json": "locating the VM inventory it reads",
    "_qiling_script.py": "locating the in-VM harness it deploys",
    "rootfs.tar.gz": "locating the rootfs archive it may upload",
    "socket_validator.py": "locating the operator's TCP client",
    "vm_info.json": "locating the VM details the transport reads",
}

_STEP_ICON: dict[str, str] = {
    "qiling_upload.py": "file-code",
    "qiling_setup.py": "file-code",
    "vms.json": "file-text",
    "_qiling_script.py": "file-code",
    "rootfs.tar.gz": "artifacts",
    "socket_validator.py": "file-code",
    "vm_info.json": "file-text",
}


def _endpoint(mode: str, info: dict) -> str:
    """The address this transport actually dials."""
    if mode == "sftp":
        host = str(info.get("VM_HOST", "") or "")
        ip = str(info.get("VM_IP", "") or "")
        port = info.get("VM_PORT", 22)
        return f"ssh://{host}@{ip}:{port}" if (host or ip) else "ssh://not-configured"
    host, port = _utility_target()
    return f"tcp://{host}:{port}"


def _probe_tcp(validator_cls, host: str, port: int,
               timeout: float = 10.0) -> dict:
    """Open the VM utility socket with the operator's client and close it.

    The client owns the interface check and the connect; every line it prints
    is captured so the connection test can show it. Whether the harness itself
    works is proved by a run (or the explicit service ping), not by this probe.
    """
    sink = io.StringIO()
    validator = None
    sock = None
    try:
        with contextlib.redirect_stdout(sink):
            validator = validator_cls(host)
            sock = validator.establish_tcp_connection(port)
    except Exception as exc:  # noqa: BLE001 - a refusal is the answer
        detail = f"{type(exc).__name__}: {exc}"
        return {"connected": False, "detail": detail,
                "trace": _trace_lines(sink.getvalue())}
    if sock is None:
        detail = _clean_output(sink.getvalue()) or "connection failed"
        return {"connected": False, "detail": detail,
                "trace": _trace_lines(sink.getvalue())}

    try:
        sock.settimeout(timeout)
    except OSError:
        pass
    try:
        with contextlib.redirect_stdout(sink):
            validator.closeConnection(sock)
    except Exception:  # noqa: BLE001 - closing is best-effort
        pass
    return {"connected": True, "detail": "",
            "trace": _trace_lines(sink.getvalue())}


def _transport_checks(mode: str, way: dict) -> tuple[list[dict], list[str]]:
    """The selected transport's steps, and the client narration behind them."""
    checks: list[dict] = []
    for raw in way.get("files") or []:
        path = Path(raw)
        usable = _file_usable(path)
        name = path.name
        checks.append(_check(
            name, usable,
            str(path) if usable else f"missing or empty at {path}",
            echo=_STEP_ECHO.get(name, f"checking {name}"),
            icon=_STEP_ICON.get(name, "check")))

    for module in way.get("modules") or []:
        found = importlib.util.find_spec(module) is not None
        checks.append(_check(
            f"{module} installed", found,
            "importable" if found else f"pip install {module}",
            echo=f"checking {module} is importable", icon="code"))

    rootfs = _rootfs()
    checks.append(_check(
        "rootfs complete", rootfs["complete"],
        "x86 + x64 trees present" if rootfs["complete"]
        else "the local Qiling rootfs is incomplete; build it first",
        echo="checking the rootfs trees the run needs", icon="artifacts"))

    info = _vm_info()
    vm_ip = str(info.get("VM_IP", "") or "")
    vm_host = str(info.get("VM_HOST", "") or "")
    vm_port = info.get("VM_PORT", 22)
    checks.append(_check(
        "VM target", bool(vm_ip or vm_host),
        f"{vm_host}@{vm_ip}:{vm_port}" if (vm_ip or vm_host)
        else "vm_info.json names no VM",
        echo="reading the VM address out of vm_info.json", icon="wifi"))

    if mode == "sftp":
        return checks, ["file checks only - no SSH session opened"]

    try:
        validator_cls = _socket_validator()
    except SubmitError as exc:
        checks.append(_check("socket client loads", False, str(exc),
                             echo="importing socket_validator.py unchanged",
                             icon="code"))
        return checks, []

    host, port = _utility_target()
    checks.append(_check("VM utility target", True, f"{host}:{port}",
                         echo="resolving the VM utility address", icon="wifi"))
    probe = _probe_tcp(validator_cls, host, port)
    checks.append(_check(
        "connect", probe["connected"],
        f"{host}:{port} (socket opened for the probe)" if probe["connected"]
        else (probe["detail"] or "connection failed"),
        echo="opening the socket, exactly as a submission does", icon="plug"))
    return checks, probe["trace"]


def _status_output(comm: dict, endpoint: str, checks: list[dict],
                   trace: list[str]) -> list[str]:
    """The connection test as a transcript, for the console on the page."""
    total = len(checks)
    failed = [c for c in checks if not c["ok"] and not c.get("advisory")]
    passed = [c for c in checks if c["ok"]]
    if not checks:
        summary = "no steps recorded"
    elif failed:
        summary = f"{total} steps - {len(passed)} passed, {len(failed)} failed"
    else:
        summary = f"{total} steps - every step passed"

    lines = [f"$ qiling connection test - {comm['mode']} ({comm['path']})",
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
    lines.append("--- ready" if checks and not failed else "--- not ready")
    return lines


def _communication() -> dict:
    """The selected transport, read from config/dynamic_analysis.json."""
    path = dynamic_analysis.CONFIG_RELATIVE.as_posix()
    try:
        settings = dynamic_analysis.load(config.REPO)
    except (OSError, ValueError) as exc:
        return {"mode": dynamic_analysis.DEFAULT_COMMUNICATION,
                "path": path, "error": str(exc)}
    return {"mode": settings["communication"], "path": path, "error": None}


def submission_info() -> dict:
    """Transport choice, the connection test, and the last/current submission."""
    comm = _communication()
    ways = transports()
    info = _vm_info()
    mode = comm["mode"]
    way = ways.get(mode)
    if way is None:
        checks: list[dict] = []
        trace: list[str] = []
        ready = False
    else:
        checks, trace = _transport_checks(mode, way)
        hard_ok = all(c["ok"] or c.get("advisory") for c in checks)
        ready = not comm["error"] and hard_ok and way["available"]

    endpoint = _endpoint(mode, info)
    if mode == "sftp":
        note = ("SFTP transport: admin-terminal/qiling_upload.py packages the "
                "rootfs when the guest lacks it, uploads the harness and sample, "
                "runs Qiling over SSH and brings the report zip home. These "
                "checks verify the driver files and the VM details it reads; "
                "they open no SSH session, so the harness itself is proved by "
                "a run.")
    else:
        note = ("TCP transport: panel/utils/socket_validator.py opens the VM "
                "utility socket, and panel/utils/vm_utility.py uploads the "
                "sample, runs Qiling and downloads the evidence archive. "
                "`connect` is the path check; service health is the Ping "
                "button, which asks the guest through the same utility server.")

    return {
        "communication": comm,
        "transports": ways,
        "default_transport": mode,
        "mode": _harness().get("service_type") or "oneshot",
        "endpoint": endpoint,
        "checked_at": round(time.time(), 1),
        "checks": checks,
        "output": _status_output(comm, endpoint, checks, trace),
        "note": note,
        "vm": {
            "ip": str(info.get("VM_IP", "") or ""),
            "host": str(info.get("VM_HOST", "") or ""),
            "port": info.get("VM_PORT", 22),
        },
        "ready": ready,
        "current": current_submit(),
        "limits": {"max_bytes": SUBMIT_MAX_BYTES,
                   "timeout": [1, 600], "max_insn": [1, 100_000_000]},
    }


def ping() -> dict:
    """Ping the Qiling service through ``panel/utils/vm_utility.py``.

    The socket is opened with the operator's SocketValidator - the same client
    a submission uses - and handed to
    ``VirtualUtility.ping_service(Service.QILING_SERVICE)``. The reply is
    returned verbatim under ``response``; ``ok`` only says the utility server
    answered, while ``alive`` is the guest's own verdict.
    """
    host, port = _utility_target()
    endpoint = f"tcp://{host}:{port}"
    checked_at = round(time.time(), 1)
    started = time.perf_counter()
    base = {"ok": False, "alive": False, "endpoint": endpoint,
            "checked_at": checked_at, "seconds": 0.0, "detail": "",
            "state": "", "error": None, "code": None, "response": None}

    try:
        validator_cls = _socket_validator()
    except SubmitError as exc:
        return {**base, "code": exc.code, "error": str(exc), "detail": str(exc)}

    validator = None
    sock = None
    state = ""
    try:
        validator = validator_cls(host)
        sock = validator.establish_tcp_connection(port)
        if sock is None:
            detail = f"could not connect to the VM utility server at {endpoint}"
            return {**base, "error": detail, "detail": detail,
                    "seconds": round(time.perf_counter() - started, 2)}
        sock.settimeout(PING_TIMEOUT)
        utility = VirtualUtility(sock)
        response = utility.ping_service(Service.QILING_SERVICE)
        try:
            info = utility.recover_information_about_services_status(
                Service.QILING_SERVICE)
            state = str(info.get("state") or "")
        except Exception:  # noqa: BLE001 - the ping already answered
            state = ""
    except Exception as exc:  # noqa: BLE001 - a refusal is the answer
        detail = f"{type(exc).__name__}: {exc}"
        return {**base, "error": detail, "detail": detail,
                "seconds": round(time.perf_counter() - started, 2)}
    finally:
        if sock is not None:
            try:
                if validator is not None:
                    validator.closeConnection(sock)
                else:
                    sock.close()
            except Exception:  # noqa: BLE001 - closing is best-effort
                pass

    seconds = round(time.perf_counter() - started, 2)
    if not isinstance(response, dict):
        detail = "the VM utility server returned no ping result"
        return {**base, "seconds": seconds, "error": detail, "detail": detail}

    body = response.get("result", response.get("results"))
    if isinstance(body, dict):
        text = str(body.get("detail") or body.get("output")
                   or body.get("result") or "")
        alive = bool(body.get("active", body.get("alive", False)))
        state = str(body.get("state") or state)
    else:
        text = str(body or "")
        alive = "PONG" in text.upper()
    detail = text.strip() or ("qiling is active on the VM" if alive
                              else "qiling is not active on the VM")
    return {"ok": True, "alive": alive, "endpoint": endpoint,
            "checked_at": checked_at, "seconds": seconds, "detail": detail,
            "state": state, "error": None,
            "code": None if alive else "no-pong", "response": response}



def _stage_upload(filename: str, stream) -> dict:
    """Stream one upload to a private temp directory, hashing as it goes."""
    name = Path(str(filename or "").replace("\\", "/")).name.strip()
    if not name or name in (".", ".."):
        raise SubmitError("the upload has no usable file name", "bad-name")

    folder = Path(tempfile.mkdtemp(prefix="ia-qiling-"))
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


def _log(job_id: str, line: str) -> None:
    # ANSI is preserved so the browser's Console can render the colours the
    # CLI and the utility client emit.
    with _submit_lock:
        job = _submit_jobs.get(job_id)
        if job is None:
            return
        job["log"].append(line)
        job["log_line_count"] += 1
        if len(job["log"]) > 4000:
            drop = len(job["log"]) - 4000
            del job["log"][:drop]
            job["log_dropped"] += drop


class _LogPipe(io.TextIOBase):
    """A stdout replacement for code that narrates with print()."""

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


def _socket_validator():
    """Load the operator's socket client by path, unchanged."""
    if not _file_usable(SOCKET_VALIDATOR):
        raise SubmitError(f"{SOCKET_VALIDATOR} is missing or empty",
                          "transport-unavailable")
    if importlib.util.find_spec("ifaddr") is None:
        raise SubmitError("ifaddr is not installed (pip install ifaddr)",
                          "transport-unavailable")
    spec = importlib.util.spec_from_file_location(
        "ia_qiling_socket_validator", SOCKET_VALIDATOR)
    if spec is None or spec.loader is None:
        raise SubmitError("cannot load socket_validator.py",
                          "transport-unavailable")
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as exc:  # noqa: BLE001 - a broken module is an answer
        raise SubmitError(f"cannot load socket_validator.py: {exc}",
                          "transport-unavailable") from exc
    validator = getattr(module, "SocketValidator", None)
    if validator is None:
        raise SubmitError(
            "socket_validator.py defines no SocketValidator "
            f"({SOCKET_VALIDATOR.stat().st_size} bytes)",
            "transport-unavailable")
    return validator


def _utility_target() -> tuple[str, int]:
    """The VM utility server address used by panel/utils/vm_utility.py."""
    info = _vm_info()
    host = str(info.get("VM_IP", "") or "").strip()
    port = 3310
    try:
        cfg = json.loads(CLAMD_VM_INFO.read_text(encoding="utf-8"))
        clamd_cfg = cfg.get("clamd") if isinstance(cfg, dict) else None
        if isinstance(clamd_cfg, dict):
            port = int(clamd_cfg.get("port", 3310) or 3310)
    except (OSError, ValueError, TypeError):
        port = 3310
    return host or "127.0.0.1", port


def _run_sftp(job_id: str, staged: dict, timeout: int, max_insn: int) -> dict:
    """Package/upload/run/collect with admin-terminal/qiling_upload.py."""
    if not _file_usable(QILING_UPLOAD):
        raise SubmitError(f"{QILING_UPLOAD} is missing", "transport-unavailable")

    before = ({p.name for p in RESULTS_DIR.glob("*_qiling_out.zip")}
              if RESULTS_DIR.is_dir() else set())
    argv = [sys.executable, str(QILING_UPLOAD), str(staged["path"]),
            "--no-vm-start"]
    if timeout > 0:
        argv += ["--timeout", str(timeout)]
    if max_insn > 0:
        argv += ["--max-insn", str(max_insn)]
    _log(job_id, f"    $ {' '.join(argv)}")

    proc = subprocess.Popen(
        argv, cwd=str(config.REPO), stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        encoding="utf-8", errors="replace", bufsize=1,
        env={**os.environ, "PYTHONUNBUFFERED": "1"},
    )
    timed_out = threading.Event()

    def expire() -> None:
        timed_out.set()
        _kill_tree(proc)

    timer = threading.Timer(SFTP_TIMEOUT, expire)
    timer.daemon = True
    timer.start()
    try:
        assert proc.stdout is not None
        for line in proc.stdout:
            _log(job_id, "    " + line.rstrip("\r\n"))
        code = proc.wait()
    finally:
        timer.cancel()

    if timed_out.is_set():
        raise SubmitError(
            f"qiling_upload.py did not finish within "
            f"{int(SFTP_TIMEOUT)}s", "timeout")
    if code != 0:
        raise SubmitError(f"qiling_upload.py exited {code}", "run-failed")

    new = [p for p in RESULTS_DIR.glob("*_qiling_out.zip")
           if p.name not in before]
    if not new:
        raise SubmitError(
            "qiling_upload.py exited 0 without writing a report zip",
            "no-result")
    report = max(new, key=lambda p: p.stat().st_mtime)
    _log(job_id, f"    report: {report}")
    return {"ok": True, "report": str(report), "report_bytes": report.stat().st_size,
            "architecture": "", "sha256": ""}


def _run_tcp(job_id: str, staged: dict, timeout: int, max_insn: int) -> dict:
    """Upload chunks through the VM utility socket and run Qiling there."""
    validator_cls = _socket_validator()
    host, port = _utility_target()
    _log(job_id, f"    transport: TCP {host}:{port} (VM utility)")
    _log(job_id, "    socket:    panel/utils/socket_validator.py")

    sink = _LogPipe(job_id)
    validator = None
    sock = None
    try:
        with contextlib.redirect_stdout(sink):
            validator = validator_cls(host)
            sock = validator.establish_tcp_connection(port)
    except Exception as exc:  # noqa: BLE001 - a refusal is the answer
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
            sock.settimeout(max(float(configured_socket_timeout()), 700.0))
            utility = VirtualUtility(sock)
            _log(job_id, f"    uploading {staged['name']} in chunks "
                         f"({staged['bytes']:,} bytes)")
            last_progress = -1

            def report_upload_progress(sent: int, total: int) -> None:
                nonlocal last_progress
                percent = sent * 100 // total
                milestone = percent // 10
                if milestone > last_progress:
                    last_progress = milestone
                    _log(job_id, f"    upload: {percent}% ({sent:,}/{total:,} bytes)")

            _log(job_id, "    running Qiling on the VM (preflight, run, report)")
            result = utility.analyze_qiling_sample_vm(
                staged["path"], timeout=timeout, max_insn=max_insn,
                progress=report_upload_progress)
        except SubmitError:
            raise
        except Exception as exc:  # noqa: BLE001 - timeout, reset, refused
            raise SubmitError(
                f"VM upload or Qiling run failed: {type(exc).__name__}: {exc}",
                "run-failed") from exc
    finally:
        if validator is not None:
            try:
                with contextlib.redirect_stdout(sink):
                    validator.closeConnection(sock)
                sink.flush()
            except Exception:  # noqa: BLE001 - closing is best-effort
                pass

    seconds = round(time.perf_counter() - started, 2)
    report = str(result.get("report") or "")
    if not report:
        raise SubmitError("the VM returned no report path", "no-result")
    _log(job_id, f"    report: {report}")
    return {"ok": True, "report": report,
            "report_bytes": result.get("report_bytes", 0),
            "architecture": result.get("architecture", ""),
            "sha256": result.get("sha256", ""),
            "exit_code": result.get("exit_code"),
            "seconds": seconds}


def configured_socket_timeout() -> float:
    try:
        settings = dynamic_analysis.load(config.REPO)
        value = float(settings.get("socket_timeout", 30.0))
    except (OSError, ValueError, TypeError):
        return 30.0
    return value if value > 0 else 30.0


def _set_row(job_id: str, row: dict) -> None:
    with _submit_lock:
        job = _submit_jobs.get(job_id)
        if job is not None:
            job["results"] = [dict(row)]


def _finish(job_id: str, *, state: str, code: int, summary: str) -> None:
    with _submit_lock:
        job = _submit_jobs.get(job_id)
        if job is None or job.get("state") != "running":
            return
        job.update(state=state, exit_code=code,
                   finished_at=round(_submit_now(), 1), summary=summary)


def _run_submit(job_id: str, staged: dict, mode: str,
                timeout: int, max_insn: int) -> None:
    global _submit_running
    row = {
        "id": "run", "label": staged["name"], "state": "running",
        "detail": None, "duration": None, "report_file": None,
        "bytes": staged["bytes"], "architecture": None,
        "sha256": staged["sha256"],
    }
    started = time.time()
    try:
        _set_row(job_id, row)
        result = (_run_sftp(job_id, staged, timeout, max_insn)
                  if mode == "sftp"
                  else _run_tcp(job_id, staged, timeout, max_insn))
        duration = round(time.time() - started, 2)
        report = str(result.get("report") or "")
        row.update(state="passed", detail=report, duration=duration,
                   report_file=report,
                   bytes=result.get("report_bytes") or staged["bytes"],
                   architecture=result.get("architecture") or "")
        _set_row(job_id, row)
        _log(job_id, f"--- {staged['name']}: report ready in {duration}s")
        _finish(job_id, state="passed", code=0,
                summary=f"report: {Path(report).name}")
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
        with _submit_lock:
            if _submit_running == job_id:
                globals()["_submit_running"] = None


def start_submit(filename: str, stream, mode: str | None = None,
                 timeout: int | None = None,
                 max_insn: int | None = None) -> dict:
    """Stage one upload and run it with Qiling. Returns a job handle or refusal."""
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
        timeout = int(timeout if timeout is not None else DEFAULT_TIMEOUT)
        max_insn = int(max_insn if max_insn is not None else DEFAULT_MAX_INSN)
    except (TypeError, ValueError):
        return {"ok": False, "code": "bad-limit",
                "error": "timeout and max_insn must be integers"}
    if not 1 <= timeout <= 600:
        return {"ok": False, "code": "bad-limit",
                "error": "timeout must be from 1 to 600 seconds"}
    if not 1 <= max_insn <= 100_000_000:
        return {"ok": False, "code": "bad-limit",
                "error": "max_insn must be from 1 to 100000000"}

    try:
        staged = _stage_upload(filename, stream)
    except SubmitError as exc:
        result = exc.as_dict()
        result["limit_bytes"] = SUBMIT_MAX_BYTES
        return result

    with _submit_lock:
        _submit_prune(_submit_now())
        if _submit_running is not None:
            shutil.rmtree(staged["folder"], ignore_errors=True)
            return {"ok": False, "error": "a Qiling run is already in progress",
                    "job_id": _submit_running}
        jid = f"q{int(_submit_now())}{secrets.token_hex(2)}"
        _submit_jobs[jid] = {
            "id": jid, "state": "running", "kind": "qiling", "mode": mode,
            "started_at": round(_submit_now(), 1), "finished_at": None,
            "exit_code": None, "error": None, "log": [], "log_line_count": 0,
            "log_dropped": 0, "command": "", "artifact": None, "summary": None,
            "selected": [], "results": [],
        }
        globals()["_submit_running"] = jid

    _log(jid, f"Qiling sample: {staged['name']} ({staged['bytes']:,} bytes)")
    _log(jid, f"sha256: {staged['sha256']}")
    _log(jid, f"transport: {mode}")
    _log(jid, f"limits: timeout {timeout}s, max_insn {max_insn:,}")
    threading.Thread(target=_run_submit,
                     args=(jid, staged, mode, timeout, max_insn),
                     daemon=True, name="qiling-submit").start()
    return {"ok": True, "job_id": jid, "mode": mode,
            "filename": staged["name"], "bytes": staged["bytes"],
            "sha256": staged["sha256"]}


def current_submit() -> dict | None:
    """The run in progress, or the most recent one, so a reload reattaches."""
    with _submit_lock:
        _submit_prune(_submit_now())
        owned = [(k, v) for k, v in _submit_jobs.items()
                 if v.get("kind") == "qiling"]
        if not owned:
            return None
        jid = max(owned, key=lambda kv: (kv[1].get("state") == "running",
                                          kv[1].get("started_at") or 0))[0]
        return build._job_view(dict(_submit_jobs[jid]))


