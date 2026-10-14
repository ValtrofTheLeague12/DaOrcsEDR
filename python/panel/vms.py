"""VirtualBox machine inventory and power control.

Everything a sandbox VM is, read from VBoxManage: its name, what state it is in,
the address it holds, and what is actually answering on it. Plus start/stop.

Reuse over reimplementation, deliberately:

  * names, running state and power control come from
    python/qiling/_check_vm_connection.py, which already owns the VBoxManage
    invocation, the VM-name quoting rules and the wait-for-transition polling.
  * the port list and the TCP probe come from netmap.py, so the machine list
    and the network map cannot disagree about what "SSH is open" means.

The only thing written here is `showvminfo`, which the checker does not expose
and which is what turns a name into an address.

Why this is a separate module from netmap: netmap answers "what does this host
look like right now" and is polled every 15 seconds on a page that must never
block. This answers "which machines exist and may I touch one", costs a
`showvminfo` per machine, and is the only place in the panel that causes a VM to
change state. Mixing the two would mean the read-only status page inherits the
latency of the slow one, and the safe one would become harder to reason about.

Safety: control() resolves the requested name against the registered machine
list before running anything, mirroring containers.control(). A crafted name
cannot reach VBoxManage - it is rejected first. The name is also passed as a
single argv element with no shell, so it is inert even if that check is
somehow bypassed.
"""

from __future__ import annotations

import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from . import netmap
from .netmap import basename_only, run_tool

# Cache TTL.
#
# Shorter than virt.detect()'s because this one moves: a VM started from the
# panel should show as running on the next poll, not in half a minute. Long
# enough that opening the page twice in a row does not re-run showvminfo for
# every machine.
_CACHE_TTL = 10.0
_cache: dict = {"at": 0.0, "payload": None}

# Start is headless. A GUI window per machine on a console an operator is
# already using is not what a batch lab wants, and headless is what the Qiling
# tooling assumes.
_HEADLESS = True

_ACTIONS = ("start", "stop")

# VBoxManage states that mean "the machine is executing".
_LIVE_STATES = ("running", "starting", "live snapshotting", "restoring",
                "paused")


def _checker():
    return netmap._load_check()


# ---------------------------------------------------------------------------
# showvminfo
# ---------------------------------------------------------------------------

def _machine_readable(exe: str, name: str) -> dict:
    """Parse `showvminfo --machinereadable` into a dict.

    The format is one `key="value"` per line, which is exactly why it exists:
    it is a stable parse target where the human-readable output is not. Values
    may contain escaped quotes, so the split is on the LAST quote on the line.
    """
    proc = run_tool([exe, "showvminfo", name, "--machinereadable"], 15)
    if proc is None or proc.returncode != 0:
        return {}
    out: dict = {}
    for line in (proc.stdout or "").splitlines():
        line = line.strip()
        if "=" not in line:
            continue
        key, _, val = line.partition("=")
        val = val.strip()
        if len(val) >= 2 and val.startswith('"') and val.endswith('"'):
            val = val[1:-1]
        out[key.strip()] = val
    return out


def _first_present(info: dict, *keys: str) -> str:
    for key in keys:
        val = str(info.get(key) or "").strip()
        if val and val not in ("0.0.0.0", "::", "fe80::", "none"):
            return val
    return ""


def _int_or_none(value) -> int | None:
    try:
        num = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return num if num > 0 else None


def _run_log(info: dict) -> str:
    """Read a bounded tail of the VM's latest VirtualBox run log."""
    candidates: list[Path] = []
    log_folder = str(info.get("LogFldr") or "").strip()
    if log_folder:
        candidates.append(Path(log_folder))
    config_file = str(info.get("CfgFile") or "").strip()
    if config_file:
        candidates.append(Path(config_file).parent / "Logs")

    for folder in candidates:
        for filename in ("VBox.log", "VBox.log.1"):
            path = folder / filename
            try:
                if not path.is_file():
                    continue
                with path.open("rb") as stream:
                    size = path.stat().st_size
                    stream.seek(max(0, size - 32768))
                    content = stream.read(32768).decode("utf-8", errors="replace")
                lines = content.splitlines()
                if size > 32768 and lines:
                    lines = lines[1:]
                return "\n".join(lines[-80:])
            except OSError:
                continue
    return "No VirtualBox run log is available for this machine yet."


# ---------------------------------------------------------------------------
# listing
# ---------------------------------------------------------------------------

def _describe(name: str, running: bool, exe: str) -> dict:
    info = _machine_readable(exe, name)
    state = str(info.get("VMState") or ("running" if running else "poweroff"))
    ip = _first_present(info, "guestip", "guestip6")
    adapter = _first_present(info, "bridgeadapter1", "hostonlyadapter1")

    vm = {
        "name": name,
        "uuid": str(info.get("UUID") or "") or None,
        "os": str(info.get("ostype") or "") or None,
        "state": state,
        "running": running or state in _LIVE_STATES,
        "ip": ip or None,
        "mac": _first_present(info, "guestmac", "macaddress1") or None,
        "adapter": adapter or None,
        # VirtualBox reports `memory` in MB in machinereadable output, despite
        # the key being a bare number in a format where other values are bytes.
        # Taken raw; the UI decides whether to show MB or GB.
        "memory_mb": _int_or_none(info.get("memory")),
        "cpus": _int_or_none(info.get("cpus")),
        "services": [],
        "services_open": 0,
        "probed": False,
        "detail": "",
        "run_log": _run_log(info),
    }

    # Only a running guest can be listening. Probing a powered-off machine
    # returns ten closes, which costs the full timeout each and then renders as
    # "no services" - a statement about the hypervisor, not about the machine.
    if not vm["running"] or not ip:
        vm["detail"] = "off" if not vm["running"] else "no guest address"
        return vm

    vm["probed"] = True
    vm["services"] = netmap.probe_vm_services(ip)
    vm["services_open"] = sum(1 for s in vm["services"] if s["open"])
    return vm


def listing() -> dict:
    """Every registered VirtualBox machine, with address and live services."""
    now = time.time()
    if _cache["payload"] is not None and now - _cache["at"] < _CACHE_TTL:
        return _cache["payload"]

    try:
        mod = _checker()
        exe = mod.vboxmanage_path()
        names = mod.list_vms()
        live = set(mod.list_running_vms())
    except Exception as exc:  # noqa: BLE001 - no VirtualBox is a normal state
        payload = {
            "generated_at": round(now, 1), "vms": [],
            "counts": {"total": 0, "running": 0},
            "available": False, "error": basename_only(exc),
        }
        _cache.update(at=now, payload=payload)
        return payload

    def one(name):
        try:
            return _describe(name, name in live, exe)
        except Exception as exc:  # noqa: BLE001 - one bad machine, not a dead list
            return {
                "name": name,
                "running": name in live,
                "run_log": "Run log unavailable because machine details could not be read.",
                "error": basename_only(exc),
            }

    # showvminfo is a process spawn per machine. Concurrency matters once a host
    # carries more than a handful; the cap stops a 200-machine box from trying
    # to fork 200 VBoxManage processes at once.
    with ThreadPoolExecutor(max_workers=min(8, max(1, len(names)))) as pool:
        vms = list(pool.map(one, names))

    vms.sort(key=lambda v: (not v.get("running"), v.get("name", "")))

    payload = {
        "generated_at": round(now, 1),
        "vms": vms,
        "counts": {
            "total": len(vms),
            "running": sum(1 for v in vms if v.get("running")),
        },
        "available": True,
        "error": None,
    }
    _cache.update(at=now, payload=payload)
    return payload


# ---------------------------------------------------------------------------
# power control
# ---------------------------------------------------------------------------

def invalidate() -> None:
    """Drop the cached listing so the next GET reflects a power change."""
    _cache.update(at=0.0, payload=None)


def control(name: str, action: str) -> dict:
    """Start or stop a registered machine.

    Returns `{ok, detail}` rather than raising: a refused action is an answer
    the UI shows, not an exception that takes the panel down.
    """
    if action not in _ACTIONS:
        return {"ok": False, "detail": f"unknown action '{action}'"}

    name = str(name or "").strip()
    if not name:
        return {"ok": False, "detail": "no machine name given"}

    try:
        mod = _checker()
        registered = mod.list_vms()
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "detail": basename_only(exc)}

    # Allowlist. Without this the name would go straight to VBoxManage, and a
    # name is a client-supplied string.
    if name not in registered:
        shown = ", ".join(registered[:8]) or "none"
        return {"ok": False,
                "detail": f"'{name}' is not a registered machine (have: {shown})"}

    try:
        if action == "start":
            ok, detail = mod.start_vm(name, headless=_HEADLESS)
        else:
            # Hard poweroff, not ACPI shutdown: a guest running malware can
            # ignore or stall an ACPI power button, and a sandbox that will not
            # power down is worse than one that loses a snapshot.
            ok, detail = mod.stop_vm(name)
    except Exception as exc:  # noqa: BLE001 - VBoxManage refusing is an answer
        return {"ok": False, "detail": basename_only(exc)}

    if ok:
        invalidate()
    return {"ok": bool(ok), "detail": basename_only(detail),
            "name": name, "action": action}


if __name__ == "__main__":  # manual probe: `python -m python.panel.vms`
    import json

    print(json.dumps(listing(), indent=2))