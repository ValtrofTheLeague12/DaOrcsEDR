"""Live Docker state for the Containers panel, read from the Docker CLI."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor

from . import config

_CACHE_TTL = 4.0
_cache: dict = {"at": 0.0, "payload": None}

# --- trend history -----------------------------------------------------------
#
# Same shape of idea as stats.py's `_history` ring buffer, but per container:
# each snapshot appends one (cpu %, mem %) sample per running container keyed
# by "<project>/<name>". The panel is the only consumer, so the history lives
# here in-process and resets on restart - like stats.py, there is deliberately
# no persistence: a status page that quietly writes a database is a status page
# that eventually needs migrating.
#
# A stopped container keeps its old samples but appends nulls, so its chart
# visibly breaks instead of freezing on the last live value or dropping to
# zero. A container that disappears entirely keeps its track until it goes
# quiet for HISTORY_TTL, then is pruned - so a recreate does not inherit the
# old container's line, but a single missed poll does not wipe the chart.

HISTORY_LEN = 60          # samples per container (~8 min at the UI's 8s poll)
MIN_SAMPLE_INTERVAL = 2.0  # seconds; below this the trend is noise
HISTORY_TTL = 300.0        # seconds of silence before a dead track is pruned

_history: dict[str, dict] = {}


def _exe() -> str | None:
    return shutil.which("docker")


def _run(args: list[str], timeout: float):
    try:
        return subprocess.run(
            args, capture_output=True, text=True, timeout=timeout,
            encoding="utf-8", errors="replace", check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None


def _json_lines(text: str) -> list[dict]:
    out: list[dict] = []
    text = (text or "").strip()
    if not text:
        return out
    try:
        parsed = json.loads(text)
        if isinstance(parsed, list):
            return [r for r in parsed if isinstance(r, dict)]
        if isinstance(parsed, dict):
            return [parsed]
    except ValueError:
        pass
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if isinstance(row, dict):
            out.append(row)
    return out


_SIZE_RE = re.compile(r"^\s*([\d.,]+)\s*([KMGTPE]?i?B)\s*$", re.IGNORECASE)
_SIZE_MULT = {
    "B": 1, "KB": 1024, "MB": 1024 ** 2, "GB": 1024 ** 3,
    "TB": 1024 ** 4, "PB": 1024 ** 5, "KIB": 1024, "MIB": 1024 ** 2,
    "GIB": 1024 ** 3, "TIB": 1024 ** 4,
    "K": 1024, "M": 1024 ** 2, "G": 1024 ** 3,
}


def parse_size(text) -> int | None:
    if text is None:
        return None
    s = str(text).strip()
    if not s or s in ("-", "--"):
        return None
    if s == "0B":
        return 0
    m = _SIZE_RE.match(s)
    if not m:
        return None
    try:
        number = float(m.group(1).replace(",", ""))
    except ValueError:
        return None
    mult = _SIZE_MULT.get(m.group(2).upper())
    if mult is None:
        return None
    return int(number * mult)


def parse_percent(text) -> float | None:
    if text is None:
        return None
    s = str(text).strip().rstrip("%").strip()
    if not s or s in ("-", "--"):
        return None
    try:
        return round(float(s), 2)
    except ValueError:
        return None


def _parse_pair(text) -> tuple:
    if not text or "/" not in str(text):
        return None, None
    left, _, right = str(text).partition("/")
    return parse_size(left), parse_size(right)


def _parse_ports(text) -> list[str]:
    if not text:
        return []
    return [p.strip() for p in str(text).split(",") if p.strip()]


def _label(labels: str, key: str):
    m = re.search(r"(?:^|,)" + re.escape(key) + r"=([^,]+)", labels or "")
    return m.group(1).strip() if m else None


def _state_of(raw: str) -> str:
    s = (raw or "").strip().lower()
    if s in ("running", "exited", "created", "paused", "restarting"):
        return s
    if s in ("removing", "dead"):
        return "exited"
    return "exited" if not s else s


def _health_of(raw) -> str:
    s = (raw or "").strip().lower()
    return s if s in ("healthy", "unhealthy", "starting") else "none"


def _size_parts(text) -> tuple:
    if not text:
        return None, None
    s = str(text).strip()
    head, _, tail = s.partition("(")
    rw = parse_size(head.strip())
    virt = None
    m = re.search(r"virtual\s+([^)]+)", tail)
    if m:
        virt = parse_size(m.group(1))
    return rw, virt


def _collect_info(exe: str) -> dict:
    proc = _run([exe, "info", "--format", "{{json .}}"], 10)
    if proc is None:
        return {"ok": False, "error": "could not run docker"}
    if proc.returncode != 0:
        err = (proc.stderr or "").strip().splitlines()
        return {"ok": False, "error": err[-1] if err else "daemon not responding"}
    try:
        data = json.loads(proc.stdout or "{}")
        return {"ok": True, "data": data if isinstance(data, dict) else {}}
    except ValueError:
        return {"ok": False, "error": "daemon returned non-JSON info"}


def _collect_ps(exe: str) -> list[dict]:
    proc = _run([exe, "ps", "-a", "--format", "{{json .}}"], 15)
    if proc is None or proc.returncode != 0:
        return []
    return _json_lines(proc.stdout or "")

def _history_record(entries: list[dict]) -> None:
    """Append one (cpu %, mem %) sample per known container.

    Called once per snapshot build - which is itself cached for _CACHE_TTL, so
    the sample rate is bounded by the poll rate, not by the number of callers.
    Unknown keys (a container seen for the first time) start a fresh track;
    known keys absent from this snapshot get a null sample so their chart
    breaks visibly instead of freezing.
    """
    now = time.time()
    last = _history.get("__last__", 0.0)
    if now - last < MIN_SAMPLE_INTERVAL:
        return
    _history["__last__"] = now

    seen: set[str] = set()
    for entry in entries:
        key = entry["project"] + "/" + entry["name"]
        seen.add(key)
        track = _history.get(key)
        if track is None:
            track = {"cpu": [], "mem": [], "last_seen": now}
            _history[key] = track
        track["cpu"].append(entry.get("cpu_percent"))
        track["mem"].append(entry.get("mem_percent"))
        del track["cpu"][:-HISTORY_LEN]
        del track["mem"][:-HISTORY_LEN]
        track["last_seen"] = now

    # Null-sample the tracks that went quiet this round; prune the ones that
    # have been quiet longer than HISTORY_TTL so a removed container's line
    # eventually disappears instead of lingering forever.
    for key in [k for k in _history if k != "__last__" and k not in seen]:
        track = _history[key]
        if now - track.get("last_seen", 0.0) > HISTORY_TTL:
            del _history[key]
            continue
        track["cpu"].append(None)
        track["mem"].append(None)
        del track["cpu"][:-HISTORY_LEN]
        del track["mem"][:-HISTORY_LEN]


def _history_attach(entries: list[dict]) -> dict:
    """The trend payload: per-container series plus the window they cover."""
    _history_record(entries)
    series = {}
    for key, track in _history.items():
        if key == "__last__":
            continue
        series[key] = {"cpu": list(track["cpu"]), "mem": list(track["mem"])}
    samples = max((len(t["cpu"]) for t in series.values()), default=0)
    return {"samples": samples, "window_seconds": round(samples * 8), "series": series}


def list_containers() -> dict:
    now = time.time()
    if _cache["payload"] is not None and now - _cache["at"] < _CACHE_TTL:
        return _cache["payload"]
    exe = _exe()
    if not exe:
        payload = {
            "daemon": {"available": False, "running": False,
                       "version": None, "error": "docker not on PATH"},
            "engine": None, "storage": None, "projects": [],
            "stats_available": False, "updated_at": round(now, 1),
        }
        _cache.update(at=now, payload=payload)
        return payload
    with ThreadPoolExecutor(max_workers=4) as pool:
        f_info = pool.submit(_collect_info, exe)
        f_ps = pool.submit(_collect_ps, exe)
        f_stats = pool.submit(_collect_stats, exe)
        f_df = pool.submit(_collect_df, exe)
        info = f_info.result()
        ps_rows = f_ps.result()
        stats_by_key = f_stats.result()
        df_rows = f_df.result()
    daemon = {"available": True, "running": False,
              "version": None, "error": None}
    engine = None
    if not info.get("ok"):
        daemon["error"] = info.get("error") or "daemon not responding"
    else:
        d = info["data"]
        daemon["running"] = True
        daemon["version"] = d.get("ServerVersion")
        engine = {
            "version": d.get("ServerVersion"),
            "os": d.get("OperatingSystem"),
            "kernel": d.get("KernelVersion"),
            "arch": d.get("Architecture"),
            "ostype": d.get("OSType"),
            "docker_root": d.get("DockerRootDir"),
            "cpus": d.get("NCPU"),
            "memory_total_bytes": d.get("MemTotal"),
            "containers_total": d.get("Containers"),
            "containers_running": d.get("ContainersRunning"),
            "containers_paused": d.get("ContainersPaused"),
            "containers_stopped": d.get("ContainersStopped"),
            "images": d.get("Images"),
            "cpu_percent": None, "memory_used_bytes": None,
            "memory_percent": None, "net_rx_bytes": None,
            "net_tx_bytes": None, "block_read_bytes": None,
            "block_write_bytes": None, "pids": None,
            "stats_containers": 0, "stats_partial": False,
        }
    skeleton = _projects_skeleton()
    standalone = {"label": "standalone", "compose_file": "",
                  "containers": []}
    seen = set()
    agg_cpu = 0.0
    agg_mem = 0
    agg_rx = 0
    agg_tx = 0
    agg_br = 0
    agg_bw = 0
    agg_pids = 0
    agg_count = 0
    agg_partial = False
    for row in ps_rows:
        labels = str(row.get("Labels") or "")
        service = _label(labels, "com.docker.compose.service")
        compose_project = _label(labels, "com.docker.compose.project")
        name_full = str(row.get("Names") or "")
        image = row.get("Image")
        cid = str(row.get("ID") or "")
        state = _state_of(str(row.get("State") or ""))
        status = str(row.get("Status") or "")
        health = _health_of(row.get("HealthStatus"))
        if service:
            proj = _find_project(skeleton, service)
            group = proj
            if proj:
                disp_proj = proj["label"]
            else:
                disp_proj = compose_project or "standalone"
            disp_name = service
            controllable = proj is not None
        else:
            group = None
            disp_proj = "standalone"
            disp_name = name_full or cid[:12]
            controllable = False
        stat = (stats_by_key.get(cid) or stats_by_key.get(name_full)
                or stats_by_key.get(cid[:12]))
        cpu = None
        mem_pct = None
        mem_used = None
        mem_limit = None
        rx = None
        tx = None
        br = None
        bw = None
        pids = None
        if stat and state == "running":
            cpu = parse_percent(stat.get("CPUPerc"))
            mem_pct = parse_percent(stat.get("MemPerc"))
            mem_used, mem_limit = _parse_pair(stat.get("MemUsage"))
            rx, tx = _parse_pair(stat.get("NetIO"))
            br, bw = _parse_pair(stat.get("BlockIO"))
            try:
                pids = int(str(stat.get("PIDs") or "").strip())
            except (ValueError, TypeError):
                pids = None
            agg_count += 1
            if cpu is not None:
                agg_cpu += cpu
            if mem_used is not None:
                agg_mem += mem_used
            if rx is not None:
                agg_rx += rx
            if tx is not None:
                agg_tx += tx
            if br is not None:
                agg_br += br
            if bw is not None:
                agg_bw += bw
            if pids is not None:
                agg_pids += pids
        elif state == "running":
            agg_partial = True
        rw, virt = _size_parts(row.get("Size"))
        compose_rel = ""
        try:
            cfg = _label(labels, "com.docker.compose.project.config_files") or ""
            if cfg:
                first = cfg.split(",")[0].strip()
                try:
                    from pathlib import Path
                    compose_rel = str(Path(first).relative_to(config.REPO))
                except (ValueError, OSError):
                    compose_rel = first
        except Exception:
            compose_rel = ""
        if group is not None:
            compose_file = group["compose_file"]
        else:
            compose_file = compose_rel
        entry = {
            "project": disp_proj, "name": disp_name,
            "container_name": name_full or None, "id": cid or None,
            "image": image, "state": state, "status": status,
            "health": health, "ports": _parse_ports(row.get("Ports")),
            "compose_file": compose_file,
            "created": row.get("CreatedAt"),
            "running_for": row.get("RunningFor"),
            "networks": row.get("Networks") or None,
            "cpu_percent": cpu, "mem_percent": mem_pct,
            "mem_used_bytes": mem_used, "mem_limit_bytes": mem_limit,
            "net_rx_bytes": rx, "net_tx_bytes": tx,
            "block_read_bytes": br, "block_write_bytes": bw,
            "pids": pids, "size_rw_bytes": rw,
            "size_virtual_bytes": virt, "controllable": controllable,
        }
        if group is not None:
            group["containers"].append(entry)
            seen.add(group["label"] + "/" + disp_name)
        else:
            standalone["containers"].append(entry)
    for proj in skeleton:
        for service in proj["services"]:
            if (proj["label"] + "/" + service) not in seen:
                proj["containers"].append({
                    "project": proj["label"], "name": service,
                    "container_name": None, "id": None, "image": None,
                    "state": "missing", "status": "Not created",
                    "health": "none", "ports": [],
                    "compose_file": proj["compose_file"],
                    "created": None, "running_for": None, "networks": None,
                    "cpu_percent": None, "mem_percent": None,
                    "mem_used_bytes": None, "mem_limit_bytes": None,
                    "net_rx_bytes": None, "net_tx_bytes": None,
                    "block_read_bytes": None, "block_write_bytes": None,
                    "pids": None, "size_rw_bytes": None,
                    "size_virtual_bytes": None, "controllable": False,
                })
    projects = [p for p in skeleton if p["containers"] or p["services"]]
    if standalone["containers"]:
        projects.append(standalone)
    for p in projects:
        p["containers"].sort(key=lambda c: (c["state"] != "running", c["name"]))
        p.pop("services", None)
    if engine is not None:
        total_mem = engine.get("memory_total_bytes") or 0
        engine["cpu_percent"] = round(agg_cpu, 2) if agg_count else None
        engine["memory_used_bytes"] = agg_mem if agg_count else None
        if agg_count and total_mem:
            engine["memory_percent"] = round(agg_mem / total_mem * 100, 1)
        engine["net_rx_bytes"] = agg_rx if agg_count else None
        engine["net_tx_bytes"] = agg_tx if agg_count else None
        engine["block_read_bytes"] = agg_br if agg_count else None
        engine["block_write_bytes"] = agg_bw if agg_count else None
        engine["pids"] = agg_pids if agg_count else None
        engine["stats_containers"] = agg_count
        engine["stats_partial"] = agg_partial
    storage = None
    if df_rows:
        by_type = {}
        for row in df_rows:
            t = str(row.get("Type") or "").lower().replace(" ", "_")
            if not t:
                continue
            by_type[t] = {
                "total": row.get("TotalCount"),
                "active": row.get("Active"),
                "size_bytes": parse_size(row.get("Size")),
                "size": row.get("Size"),
                "reclaimable_bytes": parse_size(
                    str(row.get("Reclaimable") or "").split("(")[0]),
                "reclaimable": row.get("Reclaimable"),
            }
        storage = by_type or None
    entries = [c for p in projects for c in p["containers"]]
    history = _history_attach(entries)
    payload = {
        "daemon": daemon, "engine": engine, "storage": storage,
        "projects": projects, "stats_available": bool(stats_by_key),
        "stats_containers": agg_count, "updated_at": round(now, 1),
        "history": history,
    }
    _cache.update(at=now, payload=payload)
    return payload

def summary() -> dict:
    try:
        data = list_containers()
    except Exception:
        return {"available": False, "running": False, "version": None,
                "reason": "containers unreadable", "total": None,
                "running_count": None, "stopped": None}
    daemon = data.get("daemon") or {}
    engine = data.get("engine") or {}
    total = sum(len(p.get("containers", [])) for p in data.get("projects", []))
    running = sum(1 for p in data.get("projects", [])
                  for c in p.get("containers", []) if c.get("state") == "running")
    return {
        "available": bool(daemon.get("available")),
        "running": bool(daemon.get("running")),
        "version": daemon.get("version") or engine.get("version"),
        "reason": daemon.get("error"),
        "total": total, "running_count": running,
        "stopped": (total - running) if total else 0,
        "cpu_percent": engine.get("cpu_percent"),
        "memory_used_bytes": engine.get("memory_used_bytes"),
        "memory_percent": engine.get("memory_percent"),
    }


def control(project: str, service: str, action: str):
    if action not in ("start", "stop"):
        return False, "action must be start or stop"
    target = next((p for p in config.compose_projects()
                   if p["label"] == project), None)
    if target is None or service not in target["services"]:
        return False, "unknown service " + project + "/" + service
    exe = _exe()
    if not exe:
        return False, "docker not on PATH"
    cid = None
    try:
        for row in _collect_ps(exe):
            svc = _label(str(row.get("Labels") or ""),
                         "com.docker.compose.service")
            if svc == service:
                cid = str(row.get("ID") or "") or None
                break
    except Exception:
        cid = None
    if action == "stop":
        if not cid:
            return False, service + " is not running"
        proc = _run([exe, "stop", cid], 60)
        if proc is None:
            return False, "could not run docker"
        if proc.returncode != 0:
            err = (proc.stderr or proc.stdout or "").strip().splitlines()
            return False, err[-1] if err else "docker stop failed"
        _cache["at"] = 0.0
        return True, service + " stopped"
    if cid:
        proc = _run([exe, "start", cid], 60)
        if proc is None:
            return False, "could not run docker"
        if proc.returncode != 0:
            err = (proc.stderr or proc.stdout or "").strip().splitlines()
            return False, err[-1] if err else "docker start failed"
        _cache["at"] = 0.0
        return True, service + " started"
    proc = _run([exe, "compose", "-f", str(target["file"]),
                 "up", "-d", service], 180)
    if proc is None:
        return False, "could not run docker"
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "").strip().splitlines()
        return False, err[-1] if err else "docker compose up failed"
    _cache["at"] = 0.0
    return True, service + " created and started"


def _collect_stats(exe: str) -> dict:
    proc = _run([exe, "stats", "--no-stream", "--format", "{{json .}}"], 20)
    if proc is None or proc.returncode != 0:
        return {}
    out: dict = {}
    for row in _json_lines(proc.stdout or ""):
        out[str(row.get("ID") or "")] = row
        out[str(row.get("Name") or "")] = row
        out[str(row.get("Container") or "")] = row
    return out


def _collect_df(exe: str) -> list[dict]:
    proc = _run([exe, "system", "df", "--format", "{{json .}}"], 15)
    if proc is None or proc.returncode != 0:
        return []
    return _json_lines(proc.stdout or "")


def _projects_skeleton() -> list[dict]:
    out = []
    for proj in config.compose_projects():
        try:
            rel = str(proj["file"].relative_to(config.REPO))
        except ValueError:
            rel = str(proj["file"])
        out.append({
            "label": proj["label"], "compose_file": rel,
            "services": list(proj["services"]), "containers": [],
        })
    return out


def _find_project(skeleton: list[dict], service: str):
    for proj in skeleton:
        if service in proj["services"]:
            return proj
    return None
