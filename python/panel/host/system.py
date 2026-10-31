"""General information about the machine the panel runs on.

Why not psutil: it is not in the project venv, and adding a dependency for a
read-only status page is a poor trade. Everything here is stdlib plus ctypes
against the Win32 API that actually owns the numbers, so there is no sampling
layer of our own between the panel and the kernel.

`GetSystemTimes` is sampled twice rather than read once: the API reports
cumulative kernel/user/idle time since boot, so a single call tells you
nothing about current load. The first sample primes the delta.
"""

from __future__ import annotations

import ctypes
import json
import os
import platform
import shutil
import socket
import subprocess
import sys
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

from ..core import config

# CPU/RAM trend history: an in-process ring buffer sampled on each info() call,
# same idea as stats.py's `_history`. Scoped to the panel's lifetime and reset
# on restart, with no persistence on purpose - a status page that quietly
# writes a database is a status page that eventually needs migrating.
HISTORY_LEN = 60
MIN_SAMPLE_INTERVAL = 2.0
_history: deque[dict] = deque(maxlen=HISTORY_LEN)
_last_sample: float = 0.0

# Top-process cache: see top_processes() for why. invalidate() is called by the
# /api/system refresh path so a manual Refresh always produces a fresh sample.
_TOP_PROC_TTL = 5.0
_TOP_PROC_CACHE: dict = {"at": 0.0, "payload": None}


def invalidate_processes() -> None:
    """Drop the cached top-process sample so the next call re-measures."""
    _TOP_PROC_CACHE.update(at=0.0, payload=None)


# ---------------------------------------------------------------------------
# Win32 memory
# ---------------------------------------------------------------------------

class _MemoryStatusEx(ctypes.Structure):
    _fields_ = [
        ("dwLength", ctypes.c_ulong),
        ("dwMemoryLoad", ctypes.c_ulong),
        ("ullTotalPhys", ctypes.c_ulonglong),
        ("ullAvailPhys", ctypes.c_ulonglong),
        ("ullTotalPageFile", ctypes.c_ulonglong),
        ("ullAvailPageFile", ctypes.c_ulonglong),
        ("ullTotalVirtual", ctypes.c_ulonglong),
        ("ullAvailVirtual", ctypes.c_ulonglong),
        ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
    ]


def _memory() -> dict:
    if os.name != "nt":
        # Not reachable on this box, but keeps the module honest if it moves.
        info: dict = {}
        try:
            load = os.getloadavg()[0] / os.cpu_count() * 100 if hasattr(os, "getloadavg") else None
        except (OSError, AttributeError):
            load = None
        return {"load_percent": load, "total_bytes": None, "available_bytes": None}

    st = _MemoryStatusEx()
    st.dwLength = ctypes.sizeof(_MemoryStatusEx)
    if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(st)):
        return {"load_percent": None, "total_bytes": None, "available_bytes": None}
    return {
        "load_percent": int(st.dwMemoryLoad),
        "total_bytes": int(st.ullTotalPhys),
        "available_bytes": int(st.ullAvailPhys),
    }


# ---------------------------------------------------------------------------
# Win32 CPU + uptime
# ---------------------------------------------------------------------------

class _FileTime(ctypes.Structure):
    _fields_ = [("dwLowDateTime", ctypes.c_ulong),
                ("dwHighDateTime", ctypes.c_ulong)]


def _filetime_to_int(ft: _FileTime) -> int:
    return (ft.dwHighDateTime << 32) | ft.dwLowDateTime


def _system_times() -> tuple[int, int, int] | None:
    if os.name != "nt":
        return None
    idle, kernel, user = _FileTime(), _FileTime(), _FileTime()
    if not ctypes.windll.kernel32.GetSystemTimes(
            ctypes.byref(idle), ctypes.byref(kernel), ctypes.byref(user)):
        return None
    return (_filetime_to_int(idle), _filetime_to_int(kernel), _filetime_to_int(user))


def _cpu_load(sample_seconds: float = 0.12) -> float | None:
    """Percent busy across a short window, or None off Windows."""
    first = _system_times()
    if first is None:
        return None
    time.sleep(sample_seconds)
    second = _system_times()
    if second is None:
        return None

    idle_delta = second[0] - first[0]
    # Kernel time includes idle, so the total delta is kernel+user, not +idle.
    total_delta = (second[1] - first[1]) + (second[2] - first[2])
    if total_delta <= 0:
        return None
    return round(max(0.0, min(100.0, (1.0 - idle_delta / total_delta) * 100)), 1)


def _uptime_seconds() -> float | None:
    if os.name == "nt":
        try:
            return round(ctypes.windll.kernel32.GetTickCount64() / 1000)
        except (AttributeError, OSError):
            return None
    try:
        return round(time.clock_gettime(time.CLOCK_BOOTTIME))
    except AttributeError:
        return None


# ---------------------------------------------------------------------------
# Top memory consumers (host processes), read from the OS.
#
# PowerShell Get-Process gives WorkingSet64 (bytes) and TotalProcessorTime
# (cumulative CPU seconds). CPU *percent* needs a delta over an interval, which
# a single snapshot cannot give - so two samples MIN apart are taken and the
# per-process CPU time difference is divided by elapsed wall time and cores to
# approximate a percent. It is an approximation and is labelled as one; the
# memory figure is exact.
# ---------------------------------------------------------------------------

def _ps_processes() -> list[dict]:
    """[{'name','pid','mem_bytes','cpu_seconds'}] for every process, best-effort."""
    if os.name != "nt":
        return []
    script = (
        "Get-Process | Select-Object Name,Id,"
        "@{n='mem';e={$_.WorkingSet64}},"
        "@{n='cpu';e={$_.CPU.TotalSeconds}} | ConvertTo-Json -Compress"
    )
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, timeout=15,
            encoding="utf-8", errors="replace", check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    raw = (proc.stdout or "").strip()
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except ValueError:
        return []
    rows = data if isinstance(data, list) else [data]
    out: list[dict] = []
    for r in rows:
        if not isinstance(r, dict):
            continue
        try:
            out.append({
                "name": str(r.get("Name") or "?"),
                "pid": int(r.get("Id") or 0),
                "mem_bytes": int(r.get("mem") or 0),
                "cpu_seconds": float(r.get("cpu") or 0.0),
            })
        except (TypeError, ValueError):
            continue
    return out


def top_processes(limit: int = 5, sample_seconds: float = 0.4) -> dict:
    """Top N host processes by memory, with an approximate CPU percent.

    Cached, because this is the most expensive thing /api/system does: two
    PowerShell launches plus a deliberate sleep to get a CPU delta. The UI polls
    that endpoint every 5s, so without a cache the panel spent ~1.6s of every
    5s window spawning PowerShell to learn that the top five processes had not
    changed. A 5s TTL - the same as the poll interval - means the expensive path
    runs at most once per poll, and a refresh button still forces a new sample.
    """
    cached = _TOP_PROC_CACHE.get("payload")
    if cached is not None and time.time() - _TOP_PROC_CACHE["at"] < _TOP_PROC_TTL:
        return cached
    payload = _top_processes_uncached(limit, sample_seconds)
    _TOP_PROC_CACHE.update(at=time.time(), payload=payload)
    return payload


def _top_processes_uncached(limit: int, sample_seconds: float) -> dict:
    cores = os.cpu_count() or 1
    first = _ps_processes()
    if not first:
        return {"available": False, "cores": cores, "processes": [],
                "note": "process list unavailable (non-Windows or PowerShell failed)"}
    t0 = time.monotonic()
    time.sleep(sample_seconds)
    second = _ps_processes()
    elapsed = time.monotonic() - t0
    first_cpu = {p["pid"]: p["cpu_seconds"] for p in first}

    for p in second:
        prev = first_cpu.get(p["pid"])
        if prev is not None and elapsed > 0:
            # CPU time is summed across cores; divide by elapsed AND cores to
            # get a 0-100% figure comparable to the whole-machine meter.
            p["cpu_percent"] = round(max(0.0, (p["cpu_seconds"] - prev) / elapsed / cores * 100), 1)
        else:
            p["cpu_percent"] = None

    top = sorted(second, key=lambda p: p["mem_bytes"], reverse=True)[: max(1, min(limit, 20))]
    return {
        "available": True,
        "cores": cores,
        "sample_seconds": round(elapsed, 2),
        "processes": [
            {
                "name": p["name"],
                "pid": p["pid"],
                "mem_bytes": p["mem_bytes"],
                "mem_percent": None,  # filled below once total is known
                "cpu_percent": p["cpu_percent"],
            }
            for p in top
        ],
        "note": "CPU% is a per-process approximation over a short sample; memory is exact.",
    }


# ---------------------------------------------------------------------------
# GPU
# ---------------------------------------------------------------------------
#
# Two independent sources, because neither covers the whole answer:
#
#   * `Win32_VideoController` (CIM) - the inventory. Every adapter the box has,
#     including the integrated one and any software/RDP adapter. But its
#     `AdapterRAM` is a uint32, so it silently reports a WRONG (usually 4 GB)
#     figure for any card with more than 4 GB of VRAM. It is used here for names,
#     driver versions and modes - never as a VRAM total when a better source
#     exists.
#
#   * `nvidia-smi` - live metrics for NVIDIA cards: utilisation, temperature,
#     real VRAM in use/total, power draw, core clock. This is the precise source
#     and it is preferred wherever it answers.
#
# There is deliberately no synthesised metric for a non-NVIDIA adapter. Windows'
# `GPU Engine` performance counters could be summed, but they are per
# (process, engine, device) instances that need de-duplicating across LUIDs to
# mean anything, and they cost ~1s per sample. Reporting nothing is better than
# reporting a number that does not correspond to the card next to it - so those
# adapters carry `live: false` and the UI says why instead of drawing a zero.

_GPU_CACHE_TTL = 4.0
_gpu_cache: dict = {"at": 0.0, "payload": None}

# nvidia-smi emits "[N/A]" for anything a card does not expose - a laptop GPU
# with no enforced power limit reports power.limit that way, for instance. A
# missing reading must stay None and never collapse to 0, or the UI would draw
# an idle GPU that is actually drawing power.
_UNSET = {"", "[n/a]", "n/a", "[not supported]", "not supported", "[unknown]"}


def _num(value, as_int: bool = False):
    raw = str(value).strip()
    if raw.lower() in _UNSET:
        return None
    try:
        return int(float(raw)) if as_int else float(raw)
    except (TypeError, ValueError):
        return None


# Software adapters are not GPUs and would otherwise pad the list with things
# like "Microsoft Basic Display Adapter" or an RDP mirror driver.
_SOFTWARE_ADAPTERS = (
    "microsoft basic display",
    "basic display adapter",
    "remote display adapter",
    "rdp display",
    "indirect display",
    "virtual display",
)


def _video_controllers() -> list[dict]:
    """Adapter inventory from CIM. Names, driver, mode - not VRAM totals."""
    script = (
        "Get-CimInstance Win32_VideoController | "
        "Select-Object Name,DriverVersion,VideoModeDescription,Status,"
        "AdapterCompatibility,AdapterRAM | ConvertTo-Json -Compress"
    )
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, timeout=15,
            encoding="utf-8", errors="replace", check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    raw = (proc.stdout or "").strip()
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except ValueError:
        return []
    rows = data if isinstance(data, list) else [data]

    out: list[dict] = []
    for r in rows:
        if not isinstance(r, dict):
            continue
        name = str(r.get("Name") or "").strip()
        if not name:
            continue
        vendor = str(r.get("AdapterCompatibility") or "").strip()
        haystack = f"{name} {vendor}".lower()
        if any(soft in haystack for soft in _SOFTWARE_ADAPTERS):
            continue
        mode = str(r.get("VideoModeDescription") or "").strip()
        out.append({
            "name": name,
            "vendor": vendor or None,
            "driver_version": str(r.get("DriverVersion") or "").strip() or None,
            "mode": mode or None,
            "status": str(r.get("Status") or "").strip() or None,
            # `AdapterRAM` is a uint32, so it silently clamps to 4 GB for any
            # card with more, and for an integrated GPU it reports a slice of
            # SHARED system memory rather than dedicated VRAM. Either way it is
            # not a real figure, so it is tagged approximate and the UI
            # de-emphasises it instead of printing it as a hard number.
            "vram_bytes": _num(r.get("AdapterRAM"), as_int=True),
            "vram_source": "wmi-adapterram-approx",
        })
    return out


_NVIDIA_FIELDS = (
    "name", "utilization.gpu", "utilization.memory", "memory.used", "memory.total",
    "temperature.gpu", "power.draw", "power.limit", "clocks.sm",
)


def _nvidia() -> list[dict]:
    """Live metrics per NVIDIA GPU. Empty list when nvidia-smi is absent."""
    exe = shutil.which("nvidia-smi")
    if not exe:
        return []
    query = ",".join(_NVIDIA_FIELDS)
    try:
        proc = subprocess.run(
            [exe, f"--query-gpu={query}", "--format=csv,noheader,nounits"],
            capture_output=True, text=True, timeout=12,
            encoding="utf-8", errors="replace", check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    if proc.returncode != 0:
        return []

    out: list[dict] = []
    for line in (proc.stdout or "").splitlines():
        line = line.strip()
        if not line:
            continue
        cols = [c.strip() for c in line.split(",")]
        if len(cols) < len(_NVIDIA_FIELDS):
            # A field containing a comma would shift every column after it;
            # better to drop the row than report temperature as utilisation.
            continue
        mem_used = _num(cols[3], as_int=True)
        mem_total = _num(cols[4], as_int=True)
        out.append({
            "name": cols[0],
            # nvidia-smi reports MiB; the UI speaks bytes everywhere else.
            "memory_used_bytes": mem_used * 1024 * 1024 if mem_used is not None else None,
            "memory_total_bytes": mem_total * 1024 * 1024 if mem_total is not None else None,
            "memory_percent": (
                round(mem_used / mem_total * 100, 1)
                if mem_used is not None and mem_total else None
            ),
            "utilization_percent": _num(cols[1]),
            "memory_utilization_percent": _num(cols[2]),
            "temperature_c": _num(cols[5], as_int=True),
            "power_draw_w": _num(cols[6]),
            "power_limit_w": _num(cols[7]),
            "clock_mhz": _num(cols[8], as_int=True),
        })
    return out


def _match_adapter(device: dict, adapters: list[dict]) -> dict | None:
    """Fold nvidia-smi metrics onto the CIM adapter of the same card.

    Name matching is loose on purpose: CIM reports "NVIDIA GeForce RTX 3050
    Laptop GPU" and nvidia-smi usually reports the identical string, but driver
    suffixes and whitespace vary. A prefix containment in either direction is
    enough to pair them and far better than leaving the metrics orphaned.
    """
    name = str(device.get("name") or "").strip().lower()
    if not name:
        return None
    for a in adapters:
        other = str(a.get("name") or "").strip().lower()
        if other and (other.startswith(name) or name.startswith(other)):
            return a
    return None


def gpu() -> dict:
    """GPU inventory plus live metrics, cached for _GPU_CACHE_TTL.

    Cached because /api/system is polled every 5s and this shells out twice
    (CIM + nvidia-smi); without the cache each poll would pay for both. Same
    shape as containers.py's snapshot cache, for the same reason.
    """
    now = time.time()
    if _gpu_cache["payload"] is not None and now - _gpu_cache["at"] < _GPU_CACHE_TTL:
        return _gpu_cache["payload"]

    adapters = _video_controllers()
    devices = _nvidia()

    # Pair each NVIDIA device with its CIM adapter so the UI can show one row
    # per card with inventory AND live numbers together.
    matched: set[int] = set()
    merged: list[dict] = []
    for dev in devices:
        adapter = _match_adapter(dev, adapters)
        idx = adapters.index(adapter) if adapter else None
        if idx is not None:
            matched.add(idx)
        # `adapter` is None whenever CIM could not be read at all (a PowerShell
        # timeout or a non-JSON reply) or simply named the card differently -
        # and nvidia-smi's live metrics are the more valuable half of the row,
        # so they are kept either way. Spreading None would raise, which is how
        # one unreadable CIM query took down all of /api/system.
        merged.append({
            **(adapter or {}),
            **dev,
            # nvidia-smi is authoritative for VRAM on this card; the CIM uint32
            # would be wrong for anything over 4 GB.
            "vram_bytes": dev.get("memory_total_bytes"),
            "vram_source": "nvidia-smi",
            "live": True,
            # Present and None when CIM did not supply it, so the UI can tell
            # "no driver version reported" from a field that was never sent.
            "driver_version": (adapter or {}).get("driver_version"),
        })

    # Anything CIM saw that nvidia-smi did not cover (an Intel/AMD iGPU) is
    # reported as inventory only, explicitly marked as having no live source.
    for i, a in enumerate(adapters):
        if i in matched:
            continue
        merged.append({**a, "live": False})

    payload = {
        "available": bool(merged),
        "adapters": merged,
        "count": len(merged),
        "live_count": sum(1 for d in merged if d.get("live")),
        "note": (
            "Live utilisation, VRAM, temperature and power come from nvidia-smi "
            "and are only available for NVIDIA cards."
            if merged else
            "No display adapters reported by Windows."
        ),
    }
    _gpu_cache.update(at=now, payload=payload)
    return payload


# ---------------------------------------------------------------------------
# Disks
# ---------------------------------------------------------------------------
#
# Real volumes, enumerated - not two hardcoded paths.
#
# This used to be `shutil.disk_usage()` on the repo and the home directory. Both
# of those live on C:\ on a default install, so the panel reported the same
# physical disk twice under two different, equally confusing labels
# ("C:\Users\<you>\Desktop\IAProject" and "C:\Users\<you>") and silently omitted
# every other drive on the box. An operator asking "which disk is filling up"
# got a duplicate answer instead of the one that mattered.
#
# Win32_LogicalDisk is the authoritative source: it reports each mounted volume
# by its drive letter, with the real capacity (unlike the uint32 AdapterRAM trap
# in the GPU section, Size here is a full 64-bit figure), so one row means one
# physical volume and the letters are what people actually recognise.

# DriveType 3 = local fixed disk. Removable (2) and network-mapped (4) are
# deliberately excluded: a USB stick unplugged between two polls would make the
# meter flap, and a mapped drive is somebody else's storage.
_FIXED_DISKS = (
    'Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" | '
    'Select-Object DeviceID,VolumeName,Size,FreeSpace,FileSystem | '
    "ConvertTo-Json -Compress"
)


_VOLUME_CACHE_TTL = 10.0
_volume_cache: dict = {"at": 0.0, "payload": None}


def _volumes() -> list[dict]:
    """Every fixed volume on the box, keyed by drive letter.

    Cached: this is a PowerShell spawn on every call, and /api/system is polled
    every 5s while /api/stats reads it too. Ten seconds keeps a drive that fills
    up mid-session visible without paying a subprocess per poll.
    """
    now = time.time()
    if _volume_cache["payload"] is not None and now - _volume_cache["at"] < _VOLUME_CACHE_TTL:
        return _volume_cache["payload"]

    vols = _volumes_uncached()
    _volume_cache.update(at=time.time(), payload=vols)
    return vols


def _volumes_uncached() -> list[dict]:
    """Every fixed volume on the box, keyed by drive letter."""
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", _FIXED_DISKS],
            capture_output=True, text=True, timeout=15,
            encoding="utf-8", errors="replace", check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    raw = (proc.stdout or "").strip()
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except ValueError:
        return []
    rows = data if isinstance(data, list) else [data]

    out: list[dict] = []
    for r in rows:
        if not isinstance(r, dict):
            continue
        device = str(r.get("DeviceID") or "").strip()
        if not device:
            continue
        total = _num(r.get("Size"), as_int=True)
        free = _num(r.get("FreeSpace"), as_int=True)
        if not total or free is None:
            # An unmounted or BitLocker-locked volume reports null here. Listing
            # it as 0% full would be a lie, so it is skipped entirely.
            continue
        used = max(0, total - free)
        out.append({
            "device": device,                       # "C:"
            "path": device + "\\",                  # "C:\"  (key kept for the UI)
            "name": str(r.get("VolumeName") or "").strip() or None,
            "filesystem": str(r.get("FileSystem") or "").strip() or None,
            "total_bytes": total,
            "free_bytes": free,
            "used_bytes": used,
            "used_percent": round(used / total * 100, 1) if total else None,
        })
    # Stable order, so the meter does not reshuffle between polls.
    out.sort(key=lambda d: d["device"])
    return out


def _disk(path: Path) -> dict | None:
    """Fallback for one path, used only when volume enumeration fails."""
    try:
        usage = shutil.disk_usage(path)
    except OSError:
        return None
    return {
        "device": None,
        "path": str(path),
        "name": None,
        "filesystem": None,
        "total_bytes": usage.total,
        "used_bytes": usage.used,
        "free_bytes": usage.free,
        "used_percent": round(usage.used / usage.total * 100, 1) if usage.total else None,
    }


def _disks() -> list[dict]:
    """Fixed volumes, or a path-based fallback if CIM will not answer."""
    vols = _volumes()
    if vols:
        return vols
    return [d for d in (_disk(config.REPO), _disk(Path.home())) if d]


# ---------------------------------------------------------------------------
# Payload
# ---------------------------------------------------------------------------

PANEL_STARTED = time.time()


def _record(cpu_pct, mem_pct, gpu_pct=None) -> None:
    global _last_sample
    now = time.time()
    if now - _last_sample < MIN_SAMPLE_INTERVAL:
        return
    _last_sample = now
    _history.append({"t": round(now), "cpu": cpu_pct, "memory": mem_pct, "gpu": gpu_pct})


def info() -> dict:
    mem = _memory()
    total = mem.get("total_bytes") or 0
    avail = mem.get("available_bytes") or 0
    cpu_pct = _cpu_load()
    mem_pct = mem.get("load_percent")
    # GPU first: it is cached, so this is free on most polls, and the sampled
    # utilisation is recorded alongside cpu/memory so the chart has a history.
    gpu_info = gpu()
    live = [d for d in gpu_info["adapters"] if d.get("live")]
    gpu_pct = max((d["utilization_percent"] for d in live
                   if d.get("utilization_percent") is not None), default=None)
    _record(cpu_pct, mem_pct, gpu_pct)

    span = 0
    if len(_history) > 1:
        span = int(_history[-1]["t"] - _history[0]["t"])

    procs = top_processes()
    for p in procs.get("processes", []):
        if total:
            p["mem_percent"] = round(p["mem_bytes"] / total * 100, 1)

    return {
        "host": {
            "name": socket.gethostname(),
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "processor": platform.processor() or None,
        },
        "runtime": {
            "python": platform.python_version(),
            "executable": sys.executable,
            "panel_uptime_seconds": round(time.time() - PANEL_STARTED),
        },
        "cpu": {
            "logical_cores": os.cpu_count(),
            "load_percent": cpu_pct,
        },
        "memory": {
            **mem,
            "used_bytes": (total - avail) if total else None,
        },
        "gpu": gpu_info,
        "uptime_seconds": _uptime_seconds(),
        "disks": _disks(),
        "panel": {
            "repo": str(config.REPO),
            "env_file_exists": config.ENV_FILE.is_file(),
            "compose_projects": len(config.compose_projects()),
        },
        "history": {
            "samples": len(_history),
            "window_seconds": span,
            "cpu": [h["cpu"] for h in _history],
            "memory": [h["memory"] for h in _history],
            # Null whenever no live GPU source answered, so the chart breaks
            # rather than implying an idle GPU on a box with none.
            "gpu": [h["gpu"] for h in _history],
        },
        "top_processes": procs,
    }