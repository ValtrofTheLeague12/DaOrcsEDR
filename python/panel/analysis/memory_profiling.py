"""Windows process memory snapshots with Sysinternals VMMap.

Two targets, both run natively on Windows:

    analyzer   run the Windows analyzer, optionally on a selected executable,
               and save a VMMap process snapshot.
    sample     run a selected Windows executable and save a VMMap snapshot.

The setting lives in config/memory_profiling.json, beside the other
panel-owned configuration (dynamic_analysis.json, hardening.json,
yara_check.json). It is deliberately NOT a key in config/analysis.yaml: the
C++ loader there treats an unknown key as a startup error, and merely opening
this page must never be able to break the next analysis run.

VMMap is a snapshot tool, not an allocation tracer: it records a process's
virtual-memory regions and working set, but does not attribute allocations to
functions or detect individual leaks. Each capture saves a native .mmp
snapshot and a CSV export; the dashboard visualizes the CSV categories and
address-ordered regions, while the native file remains available for VMMap.

Runs happen as background jobs because the analyzer may take minutes. Each job
starts the selected program, immediately asks VMMap to capture its process,
and saves both exports and the process log under exports/memory_profiling/.
"""

from __future__ import annotations

import json
import csv
import io
import logging
import os
import re
import shutil
import subprocess
import threading
import time
import uuid
from pathlib import Path

from ..core import config

log = logging.getLogger("panel.memory_profiling")

CONFIG_RELATIVE = Path("config") / "memory_profiling.json"
OUTPUT_RELATIVE = Path("exports") / "memory_profiling"

VMMAP_RELATIVE = Path("tools") / "sysinternals"
ANALYZER_RELATIVE = Path("build-ucrt") / "static_analyzer.exe"
SNAPSHOT_TIMEOUT = 120

# The two things VMMap can scan. Kept in this order because it is the order the
# page shows and the order the API validates against.
TARGETS = ("analyzer", "sample")
DEFAULT_TARGET = "analyzer"

# A profile is a diagnostic, not a fuzz run. The ceiling is the same one the
# pipeline runner uses for a run: a day is already a runaway, not an analysis.
MIN_TIMEOUT = 10
MAX_TIMEOUT = 86400
DEFAULT_TIMEOUT = 1800

# Snapshot and target logs stay on disk. Only the job's scrollback is bounded.
MAX_LOG_LINES = 2000
JOB_TTL = 3600.0
MAX_LAYOUT_BYTES = 20 * 1024 * 1024
MAX_LAYOUT_REGIONS = 2000

_write_lock = threading.RLock()
_jobs: dict[str, dict] = {}
_jobs_lock = threading.Lock()
_running: str | None = None

# Replaced by tests so no test starts processes.
_RUN = subprocess.run
_POPEN = subprocess.Popen


def config_path(repo: Path) -> Path:
    return repo / CONFIG_RELATIVE


def defaults() -> dict:
    return {"enabled": False, "target": DEFAULT_TARGET, "sample": ""}


def _coerce_bool(value: object) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in (0, 1):
        return bool(value)
    if isinstance(value, str):
        low = value.strip().lower()
        if low in ("1", "true", "yes", "on"):
            return True
        if low in ("0", "false", "no", "off", ""):
            return False
    raise ValueError("'enabled' must be a boolean")


def _coerce_target(value: object) -> str:
    if not isinstance(value, str) or value not in TARGETS:
        raise ValueError("'target' must be one of: " + ", ".join(TARGETS))
    return value


def load(repo: Path) -> dict:
    """The stored setting, with defaults filled in for an absent file.

    Missing is not an error: the default is a disabled profiler. A malformed
    file is reported by snapshot() rather than raised into every caller, and an
    unknown key is refused on write, so a typo cannot silently select a target
    nobody chose.
    """
    path = config_path(repo)
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return defaults()
    except OSError as exc:
        raise OSError(f"could not read {path}: {exc}") from exc
    if not raw.strip():
        return defaults()
    try:
        loaded = json.loads(raw)
    except ValueError as exc:
        raise ValueError(f"{CONFIG_RELATIVE.as_posix()} is not valid JSON: {exc}") from exc
    if not isinstance(loaded, dict):
        raise ValueError(f"{CONFIG_RELATIVE.as_posix()} must be a JSON object")

    settings = defaults()
    for key, value in loaded.items():
        if key == "enabled":
            settings["enabled"] = _coerce_bool(value)
        elif key == "target":
            settings["target"] = _coerce_target(value)
        elif key == "sample":
            if value is None:
                settings["sample"] = ""
            elif isinstance(value, str):
                settings["sample"] = value
            else:
                raise ValueError("'sample' must be a string")
        else:
            raise ValueError(
                f"not a memory-profiling setting: {key} "
                f"(known: enabled, target, sample)")
    return settings


def write(repo: Path, patch: dict) -> dict:
    """Set the option. The file is rewritten whole, like the other JSON config."""
    if not isinstance(patch, dict):
        raise ValueError("body must be a JSON object")
    unknown = [k for k in patch if k not in ("enabled", "target", "sample")]
    if unknown:
        raise ValueError("not a memory-profiling setting: " + ", ".join(sorted(unknown)))

    with _write_lock:
        current = load(repo)
        if "enabled" in patch:
            current["enabled"] = _coerce_bool(patch["enabled"])
        if "target" in patch:
            current["target"] = _coerce_target(patch["target"])
        if "sample" in patch:
            value = patch["sample"]
            if value is None:
                current["sample"] = ""
            elif isinstance(value, str):
                current["sample"] = value
            else:
                raise ValueError("'sample' must be a string")

        path = config_path(repo)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_text(json.dumps(current, indent=2) + "\n", encoding="utf-8")
        os.replace(tmp, path)
    return current


def vmmap_state(repo: Path) -> dict:
    """Whether VMMap and the Windows analyzer are available."""
    override = os.environ.get("VMMAP_EXE", "").strip()
    if override:
        configured = Path(override)
        if not configured.is_absolute():
            configured = repo / configured
        candidates = (configured,)
    else:
        candidates = (
            repo / VMMAP_RELATIVE / "VMMap64.exe",
            repo / VMMAP_RELATIVE / "vmmap64.exe",
            repo / VMMAP_RELATIVE / "VMMap.exe",
            Path(os.environ.get("ProgramFiles", "C:/Program Files"))
                / "Sysinternals" / "VMMap64.exe",
            Path(os.environ.get("ProgramFiles(x86)", "C:/Program Files (x86)"))
                / "Sysinternals" / "VMMap.exe",
        )
    executable = next((path for path in candidates if path.is_file()), None)
    if executable is None and not override:
        found = shutil.which("VMMap64.exe") or shutil.which("VMMap.exe")
        executable = Path(found) if found else None
    analyzer = repo / ANALYZER_RELATIVE
    state = {
        "installed": executable is not None,
        "executable": str(executable.resolve()) if executable else None,
        "local_install": (
            executable.resolve().is_relative_to(repo.resolve())
            if executable else False
        ),
        "analyzer_present": analyzer.is_file(),
        "analyzer": ANALYZER_RELATIVE.as_posix(),
        "error": None,
        "warning": None,
    }
    if executable is None:
        if override:
            state["error"] = f"VMMAP_EXE does not point to a VMMap executable: {override}"
        else:
            state["error"] = (
                f"VMMap was not found. Put VMMap64.exe under "
                f"{VMMAP_RELATIVE.as_posix()}/ or set VMMAP_EXE.")
    return state


def _analyzer_sample(repo: Path, sample: str | None) -> tuple[Path | None, str | None]:
    """Resolve the required sample for an analyzer profile."""
    if not sample:
        return None, "select a Windows .exe for the analyzer to analyze"
    path, why = _resolve_sample(repo, sample)
    if why is not None:
        return None, why
    if path is None or not _is_windows_executable(path):
        return None, "the analyzer sample must be a Windows .exe"
    return path, None


def _is_windows_executable(path: Path) -> bool:
    if path.suffix.lower() != ".exe":
        return False
    try:
        with path.open("rb") as stream:
            return stream.read(2) == b"MZ"
    except OSError:
        return False


def _resolve_sample(repo: Path, sample: str) -> tuple[Path | None, str | None]:
    """A file selected from the sample roots, or the refusal sentence."""
    if not sample or not sample.strip():
        return None, "no sample selected"
    if sample.strip().startswith("--"):
        return None, f"'{sample}' looks like an option, not a sample path"
    if any(ord(c) < 32 for c in sample):
        return None, "control characters are not allowed in a sample path"
    if ".." in Path(sample).parts:
        return None, "a sample path may not contain '..' segments"

    raw = Path(sample)
    try:
        path = (repo / raw).resolve() if not raw.is_absolute() else raw.resolve()
        roots = [(repo / r).resolve() for r in config.SAMPLE_ROOTS]
    except OSError as exc:
        return None, f"could not resolve the sample path: {exc}"
    if not any(path.is_relative_to(root) for root in roots):
        return None, (
            "the sample must resolve inside the repo's sample roots "
            f"({', '.join(config.SAMPLE_ROOTS)})")
    try:
        if not path.is_file():
            return None, f"sample not found: {path}"
    except OSError as exc:
        return None, f"could not read the sample: {exc}"
    return path, None


def samples(repo: Path) -> list[dict]:
    """Files under the sample roots, for the target picker.

    Restrict the picker to PE executables, the inputs the runner can launch.
    """
    out: list[dict] = []
    seen: set[Path] = set()
    for root_name in config.SAMPLE_ROOTS:
        root = (repo / root_name)
        if not root.is_dir():
            continue
        try:
            children = list(root.iterdir())
        except OSError:
            continue
        for path in children:
            try:
                if not path.is_file() or not _is_windows_executable(path):
                    continue
                resolved = path.resolve()
            except OSError:
                continue
            if resolved in seen:
                continue
            seen.add(resolved)
            try:
                rel = path.relative_to(repo).as_posix()
                size = path.stat().st_size
            except (ValueError, OSError):
                continue
            out.append({
                "path": rel,
                "name": path.name,
                "bytes": size,
            })
    out.sort(key=lambda entry: (entry["path"].lower(), entry["name"].lower()))
    return out


def _now() -> float:
    return time.time()


def _prune(now: float) -> None:
    global _running
    for jid in [k for k, v in _jobs.items()
                if v.get("state") != "running"
                and now - v.get("finished_at", now) > JOB_TTL]:
        _jobs.pop(jid, None)
    if _running is not None and _running not in _jobs:
        _running = None


def _append(job_id: str, line: str) -> None:
    with _jobs_lock:
        job = _jobs.get(job_id)
        if job is None:
            return
        job["log"].append(line)
        job["log_line_count"] = job.get("log_line_count", 0) + 1
        if len(job["log"]) > MAX_LOG_LINES:
            drop = len(job["log"]) - MAX_LOG_LINES
            del job["log"][:drop]
            job["log_dropped"] = job.get("log_dropped", 0) + drop


def _job_view(job: dict) -> dict:
    keys = ("id", "state", "target", "sample", "started_at", "finished_at",
            "exit_code", "error", "warning", "command", "container", "output_dir",
            "report_dir", "snapshot_path", "csv_path", "log_line_count",
            "log_dropped", "duration_sec")
    out = {k: job.get(k) for k in keys}
    out["log"] = list(job.get("log") or [])
    return out


def _target_command(repo: Path, target: str, sample: Path | None) -> list[str]:
    """Build the executable command whose live process VMMap will scan."""
    if target == "analyzer":
        if sample is None:
            raise ValueError("select a Windows .exe for the analyzer to analyze")
        analyzer = repo / ANALYZER_RELATIVE
        if not analyzer.is_file():
            raise ValueError(f"{ANALYZER_RELATIVE.as_posix()} is not built")
        command = [str(analyzer), "--no-curses", "--pipeline", "default"]
    elif target == "sample":
        if sample is None:
            raise ValueError("a Windows executable is required for the sample target")
        command = [str(sample)]
    else:
        raise ValueError(f"unknown profiling target: {target}")
    if sample is not None and target == "analyzer":
        command.append(str(sample))
    return command


def _vmmap_command(repo: Path, pid: int, output: Path) -> list[str]:
    """Ask VMMap to scan one live process; the extension selects export format."""
    state = vmmap_state(repo)
    if not state["installed"] or not state["executable"]:
        raise ValueError(state["error"] or "VMMap is not installed")
    args = [state["executable"], "-accepteula"]
    if Path(state["executable"]).name.lower() == "vmmap.exe":
        args.append("-64")
    return [*args, "-p", str(pid), str(output)]


def _run_profile(job_id: str, repo: Path, target: str,
                 sample: Path | None, timeout: int) -> None:
    job = _jobs[job_id]
    try:
        target_args = _target_command(repo, target, sample)
        snapshot = Path(job["output_dir"]) / "snapshot.mmp"
        csv_export = Path(job["output_dir"]) / "memory-map.csv"
    except ValueError as exc:
        _finish(job_id, -1, str(exc))
        return
    target_display = subprocess.list2cmdline(target_args)
    with _jobs_lock:
        job["command"] = target_display
        job["snapshot_path"] = str(snapshot)
        job["csv_path"] = str(csv_export)
    _append(job_id, f"$ {target_display}")

    env = os.environ.copy()
    env["STATIC_ANALYZER_CURSES"] = "0"
    env["CTI_SKIP"] = "1"
    env["IA_ARTIFACT_UPLOAD"] = "0"
    target_log = Path(job["output_dir"]) / "target.log"
    started = time.monotonic()
    proc = None
    try:
        with target_log.open("w", encoding="utf-8", errors="replace") as stream:
            proc = _POPEN(
                target_args, stdout=stream, stderr=subprocess.STDOUT,
                cwd=str(repo), env=env,
            )
            vmmap_commands = (
                (snapshot, "native snapshot"),
                (csv_export, "CSV memory map"),
            )
            displays = []
            for export_path, export_label in vmmap_commands:
                vmmap_args = _vmmap_command(repo, proc.pid, export_path)
                display = subprocess.list2cmdline(vmmap_args)
                displays.append(display)
                with _jobs_lock:
                    job["command"] = f"{target_display} ; " + " ; ".join(displays)
                _append(job_id, f"$ {display}")
                remaining = max(
                    1, min(SNAPSHOT_TIMEOUT, timeout - (time.monotonic() - started)))
                try:
                    result = _RUN(
                        vmmap_args, capture_output=True, text=True, timeout=remaining,
                        encoding="utf-8", errors="replace", check=False,
                        cwd=str(repo),
                    )
                except subprocess.TimeoutExpired:
                    if proc.poll() is None:
                        proc.kill()
                        proc.wait()
                    _finish(job_id, -1,
                            f"VMMap {export_label} exceeded its time limit")
                    return
                for line in ((result.stdout or "") + "\n" + (result.stderr or "")).splitlines():
                    if line.strip():
                        _append(job_id, line)
                if result.returncode != 0:
                    if proc.poll() is None:
                        proc.kill()
                        proc.wait()
                    message = (
                        "VMMap failed to capture the process"
                        if export_path == snapshot
                        else "VMMap failed to export the CSV memory map"
                    )
                    _finish(
                        job_id, result.returncode,
                        f"{message} (exit {result.returncode})")
                    return
                if not export_path.is_file():
                    if proc.poll() is None:
                        proc.kill()
                        proc.wait()
                    if export_path == snapshot:
                        error = (
                            "VMMap did not create a snapshot; the target may "
                            "have exited before it was scanned")
                    else:
                        error = (
                            "VMMap did not create the CSV memory map; the "
                            "target may have exited before it was scanned")
                    _finish(
                        job_id, -1, error)
                    return
            remaining = timeout - (time.monotonic() - started)
            if remaining <= 0:
                if proc.poll() is None:
                    proc.kill()
                    proc.wait()
                _finish(job_id, -1, f"the profile exceeded {timeout}s and was killed")
                return
            try:
                returncode = proc.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                if proc.poll() is None:
                    proc.kill()
                    proc.wait()
                _finish(job_id, -1, f"the profile exceeded {timeout}s and was killed")
                return
    except (OSError, ValueError) as exc:
        if proc is not None and proc.poll() is None:
            proc.kill()
            proc.wait()
        _finish(job_id, -1, f"could not start the target or VMMap: {exc}")
        return

    try:
        with target_log.open("r", encoding="utf-8", errors="replace") as stream:
            for line in stream:
                _append(job_id, line.rstrip("\r\n"))
    except OSError as exc:
        _append(job_id, f"could not read target log: {exc}")
    if returncode != 0:
        with _jobs_lock:
            job["warning"] = (
                f"The profiled process exited {returncode}; the VMMap snapshot "
                "was captured successfully. See the process output for details."
            )
        _finish(job_id, returncode, None, capture_succeeded=True)
    else:
        _finish(job_id, 0, None)


def _finish(job_id: str, code: int, error: str | None,
            capture_succeeded: bool = False) -> None:
    global _running
    with _jobs_lock:
        job = _jobs.get(job_id)
        if job is not None:
            job["state"] = (
                "done" if error is None and (code == 0 or capture_succeeded)
                else "failed"
            )
            job["exit_code"] = code
            job["error"] = error
            job["finished_at"] = _now()
            started = job.get("started_at") or job["finished_at"]
            job["duration_sec"] = round(job["finished_at"] - started, 1)
        if _running == job_id:
            _running = None


def start(repo: Path, target: str | None = None,
          sample: str | None = None, timeout: object = None) -> dict:
    """Begin one profile. Returns the job view, or {ok: false, error}."""
    global _running
    try:
        settings = load(repo)
    except (ValueError, OSError) as exc:
        return {"ok": False, "error": str(exc)}
    try:
        target = _coerce_target(target if target is not None else settings["target"])
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}
    if target == "analyzer" and not (repo / ANALYZER_RELATIVE).is_file():
        return {"ok": False,
                "error": f"{ANALYZER_RELATIVE.as_posix()} is not built"}
    if target == "sample" and not sample:
        sample = settings.get("sample") or None
    if target == "sample" and not sample:
        return {"ok": False, "error": "select a sample to profile"}

    path, why = (
        _analyzer_sample(repo, sample) if target == "analyzer"
        else _resolve_sample(repo, sample)
    )
    if why is not None:
        return {"ok": False, "error": why}
    if target == "sample" and (path is None or not _is_windows_executable(path)):
        return {"ok": False, "error": "the selected sample must be a Windows .exe"}

    if timeout is None:
        limit = DEFAULT_TIMEOUT
    elif isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        return {"ok": False, "error": "timeout must be a whole number of seconds"}
    else:
        limit = int(timeout)
        if limit < MIN_TIMEOUT or limit > MAX_TIMEOUT:
            return {"ok": False,
                    "error": f"timeout must be between {MIN_TIMEOUT} and {MAX_TIMEOUT}s"}

    state = vmmap_state(repo)
    if not state["installed"]:
        return {"ok": False, "error": state["error"]}
    if target == "analyzer" and not state["analyzer_present"]:
        return {"ok": False,
                "error": f"{ANALYZER_RELATIVE.as_posix()} is not built"}

    with _jobs_lock:
        _prune(_now())
        if _running is not None:
            return {"ok": False, "error": "a memory profile is already running",
                    "job_id": _running}

        # Inside the lock: the check above and the claim below have to be one
        # step, or two clicks that arrive together both pass it.
        out_dir = (repo / OUTPUT_RELATIVE
                   / f"{time.strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}")
        try:
            out_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            return {"ok": False, "error": f"could not create {out_dir}: {exc}"}

        jid = f"m{uuid.uuid4().hex[:12]}"
        job = {
            "id": jid,
            "state": "running",
            "target": target,
            "sample": str(path) if path is not None else None,
            "started_at": _now(),
            "finished_at": None,
            "exit_code": None,
            "error": None,
            "command": "",
            "container": None,
            "output_dir": str(out_dir),
            "report_dir": str(out_dir),
            "snapshot_path": None,
            "csv_path": None,
            "log": [],
            "log_line_count": 0,
            "log_dropped": 0,
            "duration_sec": None,
        }
        _jobs[jid] = job
        _running = jid

    threading.Thread(
        target=_run_profile, args=(jid, repo, target, path, limit),
        daemon=True, name="memory-profile").start()
    return {"ok": True, "job": _job_view(job)}


def start_generated(repo: Path, executable: str | None = None,
                    timeout: object = None) -> dict:
    """Capture a VMMap snapshot of the generated Windows executable."""
    return start(repo, target="sample", sample=executable, timeout=timeout)


def job(job_id: str) -> dict | None:
    with _jobs_lock:
        entry = _jobs.get(job_id)
        return _job_view(entry) if entry else None


def _csv_number(value: str) -> int | None:
    compact = re.sub(r"[\s,\u00a0\u202f]", "", value)
    return int(compact) if compact.isdigit() else None


def _parse_vmmap_csv(path: Path) -> dict:
    """Read VMMap's CSV summary and address-ordered region table."""
    try:
        if path.stat().st_size > MAX_LAYOUT_BYTES:
            raise ValueError("the VMMap CSV is too large to display in the panel")
        raw = path.read_bytes()
    except OSError as exc:
        raise ValueError(f"could not read the VMMap CSV: {exc}") from exc
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        # VMMap writes CSV using the active Windows ANSI code page unless a
        # Unicode BOM is present.
        text = raw.decode("mbcs" if os.name == "nt" else "cp1252", errors="replace")

    process_name = None
    process_id = None
    summary_headers = None
    region_headers = None
    summary = []
    regions = []
    for row in csv.reader(io.StringIO(text, newline="")):
        if not row:
            continue
        first = row[0].strip()
        if first == "Process:" and len(row) > 1:
            process_name = row[1].strip()
        elif first == "PID:" and len(row) > 1:
            process_id = row[1].strip()
        elif first == "Type" and "Size" in row:
            summary_headers = [cell.strip() for cell in row]
        elif first == "Address" and "Type" in row:
            region_headers = [cell.strip() for cell in row]
        elif summary_headers is not None and region_headers is None:
            summary.append(dict(zip(summary_headers, row)))
        elif region_headers is not None and len(row) >= 2:
            regions.append(dict(zip(region_headers, row)))

    def amount(entry: dict, key: str) -> int | None:
        value = _csv_number(entry.get(key, "").strip())
        return value * 1024 if value is not None else None

    totals_row = next((entry for entry in summary if entry.get("Type") == "Total"), None)
    if totals_row is None:
        raise ValueError("the VMMap CSV has no summary total")

    categories = []
    for entry in summary:
        kind = entry.get("Type", "").strip()
        if not kind or kind in ("Total", "Free"):
            continue
        categories.append({
            "type": kind,
            "size_bytes": amount(entry, "Size"),
            "committed_bytes": amount(entry, "Committed"),
            "total_ws_bytes": amount(entry, "Total WS"),
            "private_ws_bytes": amount(entry, "Private WS"),
        })
    categories.sort(key=lambda entry: entry["size_bytes"] or 0, reverse=True)

    layout_regions = []
    total_regions = 0
    for entry in regions:
        raw_address = entry.get("Address", "")
        address = raw_address.strip()
        if not re.fullmatch(r"(?:0x)?[0-9A-Fa-f]{1,16}", address):
            continue
        if raw_address != raw_address.lstrip():
            continue
        total_regions += 1
        if len(layout_regions) >= MAX_LAYOUT_REGIONS:
            continue
        layout_regions.append({
            "address": address.removeprefix("0x").removeprefix("0X").upper(),
            "type": entry.get("Type", "").strip(),
            "size_bytes": amount(entry, "Size"),
            "committed_bytes": amount(entry, "Committed"),
            "total_ws_bytes": amount(entry, "Total WS"),
            "protection": entry.get("Protection", "").strip(),
            "details": entry.get("Details", "").strip(),
        })

    layout_regions.sort(key=lambda entry: int(entry["address"], 16))
    return {
        "process_name": process_name,
        "process_id": process_id,
        "totals": {
            "size_bytes": amount(totals_row, "Size"),
            "committed_bytes": amount(totals_row, "Committed"),
            "private_bytes": amount(totals_row, "Private"),
            "total_ws_bytes": amount(totals_row, "Total WS"),
            "private_ws_bytes": amount(totals_row, "Private WS"),
            "shareable_ws_bytes": amount(totals_row, "Shareable WS"),
        },
        "categories": categories,
        "regions": layout_regions,
        "region_count": total_regions,
        "regions_truncated": total_regions > len(layout_regions),
    }


def layout(job_id: str) -> dict | None:
    """Return parsed CSV for a known job, never an arbitrary caller-supplied path."""
    with _jobs_lock:
        entry = _jobs.get(job_id)
        path = Path(entry["csv_path"]) if entry and entry.get("csv_path") else None
    if entry is None:
        return None
    if path is None or not path.is_file():
        return {"error": "this profile has no completed VMMap CSV export"}
    try:
        return {"layout": _parse_vmmap_csv(path)}
    except ValueError as exc:
        return {"error": str(exc)}


def snapshot_file(job_id: str) -> Path | None:
    """Return the native snapshot path for a known in-memory job."""
    with _jobs_lock:
        entry = _jobs.get(job_id)
        path = Path(entry["snapshot_path"]) if entry and entry.get("snapshot_path") else None
    return path if path is not None and path.is_file() else None


def snapshot(repo: Path) -> dict:
    """The option, the environment it needs, and the last/current profile."""
    try:
        settings = load(repo)
        error = None
    except (ValueError, OSError) as exc:
        settings = defaults()
        error = str(exc)

    state = vmmap_state(repo)
    with _jobs_lock:
        _prune(_now())
        current = _jobs.get(_running) if _running else None
        recent = sorted(
            _jobs.values(),
            key=lambda j: j.get("started_at") or 0,
            reverse=True,
        )[:1]

    return {
        "path": CONFIG_RELATIVE.as_posix(),
        "exists": config_path(repo).is_file(),
        "settings": settings,
        "targets": [
            {
                "id": "analyzer",
                "label": "The Windows analyzer",
                "summary": "Analyze a selected Windows .exe and capture the analyzer process.",
                "detail": (
                    "Runs the actual Windows analyzer on a selected Windows "
                    "sample and captures its process memory regions and working set. "
                    "VMMap does not "
                    "trace allocations by function or detect individual leaks."
                ),
            },
            {
                "id": "sample",
                "label": "A selected sample",
                "summary": "Run a selected Windows .exe and save a VMMap snapshot.",
                "detail": (
                    "Captures the process memory map and working set. Short-lived "
                    "programs may exit before VMMap can scan them. This is not "
                    "function-level allocation tracing."
                ),
            },
        ],
        "samples": samples(repo),
        "vmmap": state,
        "current": _job_view(current) if current else None,
        "last": _job_view(recent[0]) if recent else None,
        "error": error,
    }
