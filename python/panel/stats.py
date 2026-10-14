"""Cross-concern statistics for the dashboard.

One aggregate view over everything the panel can see: services, the machine,
logs, analysis runs, containers. Each contributor is called defensively, so a
section that cannot be read (docker down, no exports yet) degrades to nulls
rather than taking the whole payload down - a stats page that 500s when one
dependency is unavailable is worse than useless.

Trends
------
`history` is an in-process ring buffer sampled on each call. It is explicitly
scoped to this panel's lifetime and resets on restart. There is no persistence
here on purpose: a stats page that quietly writes a database is a stats page
that eventually needs migrating. `window_seconds` says how far back it reaches
so the UI can label it honestly rather than implying a week of history.
"""

from __future__ import annotations

import json
import time
from collections import deque
from pathlib import Path

from . import config, logs, services, system

HISTORY_LEN = 60          # samples retained
MIN_SAMPLE_INTERVAL = 2.0  # seconds; below this the trend is noise

_history: deque[dict] = deque(maxlen=HISTORY_LEN)
_last_sample: float = 0.0


def _record(svc: dict, mach: dict) -> None:
    global _last_sample
    now = time.time()
    if now - _last_sample < MIN_SAMPLE_INTERVAL:
        return
    _last_sample = now
    # `mach` is the flattened shape _machine() returns: cpu/memory are already
    # scalars there, not the nested dict system.info() produces.
    _history.append({
        "t": round(now),
        "cpu": mach.get("cpu"),
        "memory": mach.get("memory"),
        "up": svc.get("up"),
        "total": svc.get("total"),
    })


def _safe(fn, default):
    try:
        return fn()
    except Exception:  # noqa: BLE001 - a stats panel must never 500
        return default


# ---------------------------------------------------------------------------
# contributors
# ---------------------------------------------------------------------------

def _services() -> dict:
    ov = _safe(services.overview, {})
    items = ov.get("services", [])
    latencies = sorted(p["ms"] for p in items if p.get("ms") is not None)
    return {
        "up": ov.get("up", 0),
        "total": ov.get("total", len(items)),
        "items": [
            {"key": p["key"], "name": p["name"], "up": p["up"], "ms": p.get("ms")}
            for p in items
        ],
        "median_ms": latencies[len(latencies) // 2] if latencies else None,
        "ml_auth": ov.get("ml_auth"),
    }


def _machine() -> dict:
    m = _safe(system.info, {})
    disks = m.get("disks") or []
    return {
        "cpu": (m.get("cpu") or {}).get("load_percent"),
        "cores": (m.get("cpu") or {}).get("logical_cores"),
        "memory": (m.get("memory") or {}).get("load_percent"),
        "uptime_seconds": m.get("uptime_seconds"),
        "host": (m.get("host") or {}).get("name"),
        "disk_used_percent": disks[0].get("used_percent") if disks else None,
        "disk_free_bytes": disks[0].get("free_bytes") if disks else None,
        "disk_total_bytes": disks[0].get("total_bytes") if disks else None,
    }


def _logstats() -> dict:
    data = _safe(logs.list_logs, {})
    files = [f for g in data.get("groups", []) for f in g.get("files", [])]
    biggest = max(files, key=lambda f: f.get("bytes", 0), default=None)
    by_source = [
        {
            "label": g["label"],
            "files": len(g["files"]),
            "bytes": sum(f.get("bytes", 0) for f in g["files"]),
        }
        for g in data.get("groups", [])
        if g.get("present") and g.get("files")
    ]
    by_source.sort(key=lambda s: s["bytes"], reverse=True)
    return {
        "files": len(files),
        "bytes": data.get("total_bytes", 0),
        "sources": len(by_source),
        "largest": biggest,
        "by_source": by_source,
    }


def _runstats() -> dict:
    """Read exports/ directly.

    The analyzer's own task API only covers a 24h retention window, so counting
    runs off disk is the only way to see the whole history.
    """
    root: Path = config.REPO / "exports"
    runs: list[Path] = []
    if root.is_dir():
        runs = sorted((p for p in root.glob("*_analysis") if p.is_dir()),
                      key=lambda p: p.stat().st_mtime, reverse=True)

    total_files = 0
    total_bytes = 0
    results: dict[str, int] = {}
    last_run = None

    for run in runs:
        try:
            stat = run.stat()
            if last_run is None:
                last_run = stat.st_mtime
            for p in run.rglob("*"):
                if p.is_file():
                    total_files += 1
                    total_bytes += p.stat().st_size
        except OSError:
            continue

        summary = run / "run_summary.json"
        try:
            data = json.loads(summary.read_text(encoding="utf-8"))
            verdict = str(data.get("result") or "unknown")
        except (OSError, ValueError):
            verdict = "unknown"
        results[verdict] = results.get(verdict, 0) + 1

    return {
        "count": len(runs),
        "artifacts": total_files,
        "bytes": total_bytes,
        "results": results,
        "last_run_at": last_run,
        "present": root.is_dir(),
    }


def _containers() -> dict:
    """Read docker state if we can; report unavailable rather than guessing."""
    return _containers_cached()


# `docker info` plus one `docker compose ps` per project is several subprocesses,
# and the Statistics panel reads this on a 5s poll. Cached for the same reason
# containers.py caches its snapshot, so the two surfaces stay coherent.
_CONTAINERS_TTL = 8.0
_containers_cache: dict = {"at": 0.0, "payload": None}


def _containers_cached() -> dict:
    now = time.time()
    if _containers_cache["payload"] is not None and \
            now - _containers_cache["at"] < _CONTAINERS_TTL:
        return _containers_cache["payload"]
    payload = _containers_uncached()
    _containers_cache.update(at=time.time(), payload=payload)
    return payload


def _containers_uncached() -> dict:
    import shutil
    import subprocess

    exe = shutil.which("docker")
    if not exe:
        return {"available": False, "reason": "docker not on PATH",
                "total": None, "running": None, "stopped": None}

    try:
        proc = subprocess.run(
            [exe, "info", "--format", "{{.ServerVersion}}"],
            capture_output=True, text=True, timeout=12, encoding="utf-8",
            errors="replace", check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return {"available": False, "reason": f"{type(exc).__name__}", "total": None,
                "running": None, "stopped": None}

    if proc.returncode != 0:
        err = (proc.stderr or "").strip().splitlines()
        detail = err[-1] if err else "daemon not responding"
        return {"available": True, "running": False, "version": None,
                "reason": detail, "total": None, "running_count": None}

    total = 0
    running = 0
    for project in config.compose_projects():
        try:
            ps = subprocess.run(
                [exe, "compose", "-f", str(project["file"]), "ps", "-a",
                 "--format", "json"],
                capture_output=True, text=True, timeout=20, encoding="utf-8",
                errors="replace", check=False,
            )
        except (OSError, subprocess.SubprocessError):
            continue
        # `ps --format json` is JSON-lines on some builds and a single array on
        # others, so both shapes are accepted rather than assuming one.
        text = (ps.stdout or "").strip()
        rows: list = []
        if text:
            try:
                parsed = json.loads(text)
                rows = parsed if isinstance(parsed, list) else [parsed]
            except ValueError:
                rows = []
                for line in text.splitlines():
                    try:
                        rows.append(json.loads(line))
                    except ValueError:
                        continue
        for row in rows:
            if not isinstance(row, dict):
                continue
            total += 1
            state = str(row.get("State") or row.get("state") or "").lower()
            if state == "running":
                running += 1

    return {
        "available": True,
        "running": True,
        "version": (proc.stdout or "").strip() or None,
        "total": total,
        "running_count": running,
        "stopped": (total - running) if total else 0,
        "reason": None,
    }


# ---------------------------------------------------------------------------
# payload
# ---------------------------------------------------------------------------

def snapshot() -> dict:
    svc = _services()
    mach = _machine()
    _record(svc, mach)

    span = 0.0
    if len(_history) > 1:
        span = float(_history[-1]["t"] - _history[0]["t"])

    return {
        "generated_at": round(time.time(), 1),
        "services": svc,
        "machine": mach,
        "logs": _logstats(),
        "runs": _runstats(),
        "containers": _containers(),
        "history": {
            "samples": len(_history),
            "window_seconds": round(span),
            "cpu": [h["cpu"] for h in _history],
            "memory": [h["memory"] for h in _history],
            "up": [h["up"] for h in _history],
            "total": _history[-1]["total"] if _history else None,
        },
    }