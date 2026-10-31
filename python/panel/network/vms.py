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

Duplicates are removed, by UUID rather than by name or address. VirtualBox will
happily return the same registration twice in a single `list vms` - after a
snapshot restore, or on a host whose machine folder was copied - and rendering
that twice makes the fleet count wrong. The drop is reported in
`counts.duplicates` and `duplicate_names` rather than done silently, because a
machine vanishing from a list with no explanation reads as a fault.

Live CPU/RAM/disk for the machines the panel holds credentials for comes from
vmmetrics, which is a separate module precisely so this listing does not inherit
SSH latency.

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

import re
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from ..core import config
from . import netmap
from . import vmmetrics
from .netmap import basename_only, run_tool

# Cache TTL.
#
# Shorter than virt.detect()'s because this one moves: a VM started from the
# panel should show as running on the next poll, not in half a minute. Long
# enough that opening the page twice in a row does not re-run showvminfo for
# every machine.
_CACHE_TTL = 10.0
_cache: dict = {"at": 0.0, "payload": None}

# Default launch mode.
#
# Headless stays the default for the reasons it was chosen: a GUI window per
# machine on a console an operator is already using is not what a batch lab
# wants, and headless is what the Qiling tooling assumes. But "default" is not
# "the only option" - opening a guest's console is a real thing an operator does
# when a headless boot failed for a reason only visible on screen, so the mode
# is a parameter the caller chooses rather than a constant baked in here.
_DEFAULT_HEADLESS = True

# States a machine can only be in because it failed. Reported to the operator
# rather than shown as an ordinary powered-off machine, because "my VM is off"
# and "my VM died" call for completely different responses.
#
# These are the same states the frontend's log parser treats as failures; the
# two lists must agree or a crash gets reported by the log and denied by the
# status chip.
_CRASH_STATES = frozenset({
    "aborted", "baddimage", "unavailable", "unreachable", "hostcachemiss",
})

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


# ---------------------------------------------------------------------------
# Guest properties
#
# `showvminfo --machinereadable` carries `guestip`, which is the obvious place to
# get an address and the wrong one. Measured on this host's own machine, it
# returns NO guestip at all - the key is absent, not merely empty - so the card
# showed an em dash for a machine that is perfectly reachable and has Guest
# Additions 7.2.8 installed.
#
# The guest itself reports far more than an address, and reports it through
# `VBoxManage guestproperty enumerate`, which is ONE subprocess for the whole
# set rather than one per property. The shape is:
#
#   /VirtualBox/GuestInfo/OS/Release = '7.0.12+kali-amd64' @ 2026-10-12T12:01:46Z
#   /VirtualBox/GuestAdd/Version     = '7.2.8'  @ ... TRANSIENT, RDONLYGUEST
#
# Two parsing details that are not obvious and will silently lose data if
# guessed:
#
#   * The value is single-quoted AND the value itself can contain a quote. The
#     guest kernel's `#1 SMP PREPTRANSFORM ...` version string is one. So the
#     closing quote is found by anchoring on the ` @ <timestamp>` that follows,
#     not by taking the next quote.
#   * An empty value is `''`, which is a legitimate reading of "this guest
#     reports no service pack" rather than a parse failure.
# ---------------------------------------------------------------------------

# path = 'value' @ timestamp[ flags]
_PROP = re.compile(r"^(?P<path>\S+)\s+=\s+'(?P<value>.*)'\s+@\s+"
                   r"(?P<stamp>\S+)(?P<flags>.*)$")

# Addresses VirtualBox reports as "none" rather than omitting.
_EMPTY_ADDRS = frozenset({"0.0.0.0", "::", "fe80::", "none", ""})


def _guest_properties(exe: str, name: str) -> dict[str, str]:
    """All guest properties for a machine as `{path: value}`."""
    proc = run_tool([exe, "guestproperty", "enumerate", name], 15)
    if proc is None or proc.returncode != 0:
        return {}
    # run_tool decodes as plain utf-8, so a BOM would survive as U+FEFF and land
    # on the FIRST property's path - corrupting exactly one value with no error
    # anywhere. Windows tools emit one often enough to be worth the strip.
    text = (proc.stdout or "").lstrip("\ufeff")
    out: dict[str, str] = {}
    for line in text.splitlines():
        m = _PROP.match(line.strip())
        if m:
            out[m.group("path")] = m.group("value").strip()
    return out


def _prop(props: dict[str, str], *path: str) -> str:
    """First non-empty value among `path`, or ''."""
    for key in path:
        val = str(props.get(key) or "").strip()
        if val and val not in _EMPTY_ADDRS:
            return val
    return ""


def _guest_networks(props: dict[str, str]) -> list[dict]:
    """Every /VirtualBox/GuestInfo/Net/<n>/{V4,V6} group the guest reported.

    Grouped by adapter index rather than flattened, because a dual-stack
    adapter reports one V4 and one V6 for the SAME NIC and showing them as two
    unrelated addresses sends the reader looking for two machines.
    """
    groups: dict[str, dict] = {}
    for path, value in props.items():
        m = re.match(r"^/VirtualBox/GuestInfo/Net/(\d+)/(V4|V6)/(\w+)$", path)
        if not m or not value.strip():
            continue
        index, family, field = m.groups()
        entry = groups.setdefault(index, {"index": int(index), "v4": None,
                                          "v4_prefix": None, "v6": None})
        if family == "V4":
            if field == "IP" and value not in _EMPTY_ADDRS:
                entry["v4"] = value.strip()
            elif field in ("Prefix", "IPS") and entry["v4"]:
                try:
                    entry["v4_prefix"] = int(value)
                except ValueError:
                    pass
        elif field == "IP" and value not in _EMPTY_ADDRS:
            entry["v6"] = value.strip()
    return [groups[k] for k in sorted(groups, key=int) if groups[k]["v4"] or groups[k]["v6"]]


def _configured_endpoint(name: str) -> dict:
    """What the project's own config says this machine's address is.

    `qiling_dlls/vm_info.json` is the source of truth for the analysis VM's SSH
    endpoint, and the panel already depends on it: vmmetrics reads the same file
    to decide which guest it holds credentials for. So the address is already
    known to this codebase at all times, including while the machine is powered
    off - which is exactly when the card used to show an em dash and leave the
    operator thinking nothing was configured.

    It is reported separately from `ip` and never merged into it. This is where
    the tooling EXPECTS the machine to be; `ip` is where the machine SAYS it
    is. Those agree most of the time, and the time they do not is precisely
    when it matters - a re-IP'd sandbox, or a config left pointing at a machine
    that has since been rebuilt. Drawing a configured address in the same place
    as a measured one would make that disagreement invisible, and an operator
    would SSH to an address that is not there.
    """
    info = config.vm_info()
    if not info or info["name"] != name:
        return {}
    return {
        "ip": info["ip"],
        "port": info["port"],
        "source": "qiling_dlls/vm_info.json",
    }


def _guest_summary(props: dict[str, str]) -> dict:
    """The guest's own account of itself, for the card.

    Null everywhere when Guest Additions is not installed - which is a normal
    state for a freshly built sandbox, and is reported as such rather than
    guessed at.
    """
    if not props:
        return {}
    version = _prop(props, "/VirtualBox/GuestAdd/VersionExt",
                    "/VirtualBox/GuestAdd/Version")
    users_raw = _prop(props, "/VirtualBox/GuestInfo/OS/LoggedOnUsers")
    return {
        "additions": version or None,
        "additions_core": _prop(props, "/VirtualBox/GuestAdd/Version") or None,
        "product": _prop(props, "/VirtualBox/GuestInfo/OS/Product") or None,
        "release": _prop(props, "/VirtualBox/GuestInfo/OS/Release") or None,
        "version": _prop(props, "/VirtualBox/GuestInfo/OS/Version") or None,
        "service_pack": _prop(props, "/VirtualBox/GuestInfo/OS/ServicePack") or None,
        "hostname": _prop(props, "/VirtualBox/GuestInfo/Misc/Hostname") or None,
        "logged_on_users": [u for u in re.split(r",\s*", users_raw) if u] or None,
        "net": _guest_networks(props),
    }


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
        # True when the state is one a machine can only reach by failing. Kept as
        # its own boolean so the UI does not have to re-derive the list, and so
        # the two definitions of "this went wrong" cannot drift apart.
        "crashed": crashed(state),
        "ip": ip or None,
        "ip6": _first_present(info, "guestip6") or None,
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
        # Live CPU / RAM / disk from inside the guest, when the panel holds
        # credentials for it. Null means "no credentials for this machine",
        # which the card renders as such - it does NOT mean an idle machine.
        "metrics": vmmetrics.for_guest(name, ip or None),
    }

    # Guest properties, and only for a machine that is actually running.
    #
    # This is a second VBoxManage spawn per machine on top of showvminfo, and
    # the listing already polls every 10 seconds, so it is not free on a host
    # carrying a lot of machines. It is skipped for a powered-off one for two
    # reasons: a stopped guest has no /Net/ properties to recover, so the only
    # thing it would contribute is an OS string left over from the previous
    # boot - stale by definition and worse than saying nothing.
    guest: dict = {}
    if vm["running"]:
        guest = _guest_summary(_guest_properties(exe, name))

    # The address the panel probes and shows comes from the guest itself when
    # Guest Additions reported one, and falls back to showvminfo's guestip
    # otherwise. The fallback is kept because it is sometimes right when Guest
    # Additions is absent - but on this host it returned nothing at all for a
    # machine with Additions 7.2.8 installed, so it is the fallback it is
    # described as, not the primary source.
    nets = guest.get("net") or []
    guest_v4 = next((n["v4"] for n in nets if n.get("v4")), None)
    guest_v6 = next((n["v6"] for n in nets if n.get("v6")), None)
    vm["ip"] = guest_v4 or vm["ip"]
    vm["ip6"] = guest_v6 or vm["ip6"]
    vm["guest"] = guest
    vm["configured"] = _configured_endpoint(name)

    # Only a running guest can be listening. Probing a powered-off machine
    # returns ten closes, which costs the full timeout each and then renders as
    # "no services" - a statement about the hypervisor, not about the machine.
    if not vm["running"] or not vm["ip"]:
        vm["detail"] = "off" if not vm["running"] else "no guest address"
        return vm

    vm["probed"] = True
    vm["services"] = netmap.probe_vm_services(vm["ip"])
    vm["services_open"] = sum(1 for s in vm["services"] if s["open"])
    return vm


def _identity(vm: dict) -> str:
    """The key two rows must share to be the same machine.

    UUID first, because it is the only identifier VirtualBox guarantees to be
    unique per registration - two clones are different UUIDs. The name is only
    a fallback for the case where showvminfo failed and there is no UUID to
    compare, where two nameless rows would otherwise collapse into one.

    Deliberately NOT the IP: a powered-off machine keeps the address it last
    held, so two machines that were cloned from the same snapshot and have both
    been shut down legitimately report the same IP. Keying on it would delete a
    real machine off the fleet.
    """
    uuid = str(vm.get("uuid") or "").strip()
    if uuid:
        return f"uuid:{uuid.lower()}"
    name = str(vm.get("name") or "").strip().lower()
    return f"name:{name}" if name else ""


def _dedupe(vms: list[dict]) -> tuple[list[dict], list[dict]]:
    """Collapse rows describing the same registration. Returns (kept, dropped).

    First occurrence wins, so the order showvminfo answered in is preserved for
    the machines that survive.
    """
    kept: list[dict] = []
    dropped: list[dict] = []
    seen: dict[str, str] = {}
    for vm in vms:
        key = _identity(vm)
        if not key:
            kept.append(vm)
            continue
        if key in seen:
            dropped.append(vm)
            continue
        seen[key] = str(vm.get("name") or "")
        kept.append(vm)
    return kept, dropped


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
            "counts": {"total": 0, "running": 0, "duplicates": 0},
            "duplicate_names": [],
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
                # No state could be read, so nothing is claimed about it. The
                # frontend treats a missing flag as "not crashed" rather than
                # guessing, and this row already says why it is incomplete.
                "crashed": False,
                "guest": {},
                "configured": {},
                "run_log": "Run log unavailable because machine details could not be read.",
                "error": basename_only(exc),
            }

    # showvminfo is a process spawn per machine. Concurrency matters once a host
    # carries more than a handful; the cap stops a 200-machine box from trying
    # to fork 200 VBoxManage processes at once.
    with ThreadPoolExecutor(max_workers=min(8, max(1, len(names)))) as pool:
        raw = list(pool.map(one, names))

    vms, dropped = _dedupe(raw)

    vms.sort(key=lambda v: (not v.get("running"), v.get("name", "")))

    payload = {
        "generated_at": round(now, 1),
        "vms": vms,
        "counts": {
            "total": len(vms),
            "running": sum(1 for v in vms if v.get("running")),
            # Reported rather than hidden: a machine disappearing from the list
            # with no explanation is the kind of thing an operator assumes is a
            # VirtualBox fault.
            "duplicates": len(dropped),
        },
        "duplicate_names": sorted({str(v.get("name") or "") for v in dropped}),
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


def crashed(state: str) -> bool:
    """Whether a raw VBoxManage state means the machine failed, not stopped."""
    return str(state or "").strip().lower() in _CRASH_STATES


def control(name: str, action: str, headless: bool = _DEFAULT_HEADLESS) -> dict:
    """Start or stop a registered machine.

    `headless` only means anything for `start`; `stop` is a poweroff either way
    and ignores it rather than rejecting the call, so a client that keeps the
    mode in its own state can post the same body either way.

    Returns `{ok, detail}` rather than raising: a refused action is an answer
    the UI shows, not an exception that takes the panel down.
    """
    if action not in _ACTIONS:
        return {"ok": False, "detail": f"unknown action '{action}'"}

    name = str(name or "").strip()
    if not name:
        return {"ok": False, "detail": "no machine name given"}

    # Coerced rather than trusted. The body is client-supplied JSON and this
    # value reaches a VBoxManage argument list.
    headless = bool(headless)

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
            ok, detail = mod.start_vm(name, headless=headless)
        else:
            # Hard poweroff, not ACPI shutdown: a guest running malware can
            # ignore or stall an ACPI power button, and a sandbox that will not
            # power down is worse than one that loses a snapshot.
            ok, detail = mod.stop_vm(name)
    except Exception as exc:  # noqa: BLE001 - VBoxManage refusing is an answer
        return {"ok": False, "detail": basename_only(exc)}

    if ok:
        invalidate()
    result = {"ok": bool(ok), "detail": basename_only(detail),
              "name": name, "action": action}
    if action == "start":
        # Echoed so the operator's confirmation can name the mode they chose
        # rather than the panel agreeing with whatever it assumed.
        result["headless"] = headless
    return result


if __name__ == "__main__":  # manual probe: `python -m python.panel.network.vms`
    import json

    print(json.dumps(listing(), indent=2))