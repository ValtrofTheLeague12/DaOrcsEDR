"""Hypervisor auto-detection - which virtualisation tool does this box actually have?

The lab is not tied to VirtualBox. This module answers "what is installed, and
what does it say it is" for the four hypervisors that realistically appear on a
Windows analysis box, so the network panel can describe the machine it is
running on instead of describing one specific vendor's idea of it.

Detection is deliberately evidence-based rather than registry-based:

  * an executable that exists AND prints a version banner when run is installed.
    A left-over registry entry from an uninstall, or a Program Files directory
    that outlived the product, reports installed and then fails every later
    call. Running the binary is the only check that cannot lie.
  * a missing tool is a NORMAL state, not an error. Every probe returns a
    structured "installed: false" rather than raising, because "QEMU is not on
    this box" is exactly what an operator wants to know.

Caching is not optional here. Detection shells out to up to four binaries plus
one PowerShell call, and /api/netmap is polled every 15 seconds - so an
uncached probe would spawn a PowerShell process every fifteen seconds forever
for information that changes roughly never.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time

from . import config

# Seconds a detection result stays valid.
#
# Deliberately longer than the 8s VirtualBox cache in netmap: nothing here is
# asked per-endpoint, and machine counts change far more slowly than a guest
# port flipping. Thirty seconds means a panel left open overnight re-detects a
# freshly installed hypervisor without the operator reloading.
_CACHE_TTL = 30.0
_cache: dict = {"at": 0.0, "payload": None}


def _run(args: list[str], timeout: float = 8.0):
    """Run a probe binary. Returns None if it is missing or misbehaved.

    OSError covers the two common failure modes on Windows equally well - the
    file does not exist, and it exists but is not a runnable image - so they
    collapse to the same "not usable" answer instead of raising per binary.
    """
    try:
        return subprocess.run(
            args, capture_output=True, text=True, timeout=timeout,
            encoding="utf-8", errors="replace", check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None


def _which(names: list[str], extra: list[str]) -> str | None:
    """First resolvable path among absolute candidates, then PATH.

    Absolute candidates come first on purpose. A repo-local build or a venv shim
    earlier on PATH would otherwise shadow the real installation, and the panel
    would describe the wrong build.
    """
    for path in extra:
        if path and os.path.isfile(path):
            return path
    for name in names:
        found = shutil.which(name)
        if found:
            return found
    return None


def _blank(slots: dict) -> dict:
    """A not-installed record with the same shape as an installed one.

    Shape parity is the point: the front end can map over `detected` without
    null-checking every field, which is the same defensive-payload rule the
    other panels follow.
    """
    return {
        "installed": False,
        "exe": None,
        "version": None,
        "machines": {"total": 0, "running": 0, "names": [], "running_names": []},
        "detail": "",
        **slots,
    }


# ---------------------------------------------------------------------------
# per-hypervisor probes
# ---------------------------------------------------------------------------

def _virtualbox() -> dict:
    """VirtualBox: VBoxManage answers --version and lists both machine sets."""
    out = _blank({"id": "virtualbox", "name": "VirtualBox"})
    path = config.VBOXMANAGE if config.VBOXMANAGE.exists() else None
    path = path and str(path) or _which(["VBoxManage"], [])
    if not path:
        out["detail"] = "VBoxManage not found"
        return out

    ver = _run([path, "--version"])
    if ver is None or ver.returncode != 0:
        # Present on disk but will not run - a half-removed install. Reporting
        # it as installed here would send the operator to debug the wrong thing.
        out["detail"] = "VBoxManage present but not runnable"
        return out

    lines = [ln.strip() for ln in (ver.stdout or "").splitlines() if ln.strip()]
    out.update(installed=True, exe=path.rsplit("\\", 1)[-1],
               version=lines[0] if lines else None, detail="")

    listed = _run([path, "list", "vms"])
    running = _run([path, "list", "runningvms"])

    def parse(proc) -> list[str]:
        if proc is None or proc.returncode != 0:
            return []
        names = []
        for line in (proc.stdout or "").splitlines():
            line = line.strip()
            # `<name> {<uuid>}` - the name is quoted when it contains spaces.
            if not line or line.startswith(("Name", "---", "*")):
                continue
            name = line.split('"')[1] if '"' in line else line.split("{")[0].strip()
            if name:
                names.append(name)
        return names

    all_vms, live = parse(listed), parse(running)
    out["machines"] = {
        "total": len(all_vms),
        "running": len(live),
        "names": sorted(all_vms),
        "running_names": sorted(live),
    }
    return out


def _qemu() -> dict:
    """QEMU.

    QEMU has no registry of machines - a `qemu-system-*` invocation is its own
    machine definition, so the count is unknown until something launches one.
    Reporting 0 would read as "no VMs" and mean "cannot tell", so `total` is
    left at 0 and `detail` says why. Scanning a disk directory for .qcow2 is
    not done here: which directory holds a lab's disks is not something this
    module can know, and guessing would invent data.
    """
    out = _blank({"id": "qemu", "name": "QEMU"})
    base = r"C:\Program Files\qemu"
    path = _which(["qemu-system-x86_64", "qemu-img"], [
        rf"{base}\qemu-system-x86_64.exe",
        rf"{base}\qemu-img.exe",
        rf"{base}\qemu-system-aarch64.exe",
    ])
    if not path:
        out["detail"] = "qemu-system-* not found"
        return out

    ver = _run([path, "--version"])
    if ver is None or ver.returncode != 0:
        out["detail"] = "QEMU present but not runnable"
        return out

    lines = [ln.strip() for ln in (ver.stdout or "").splitlines() if ln.strip()]
    out.update(installed=True, exe=path.rsplit("\\", 1)[-1],
               version=lines[0] if lines else None)
    out["detail"] = "no machine registry - count unknown until a VM is launched"
    return out


def _vmware() -> dict:
    """VMware Workstation, via vmrun.

    Workstation installs to Program Files on 64-bit builds and Program Files
    (x86) on 32-bit ones, so both are candidates; this box has neither, which
    is the common case for a malware lab that standardised on VirtualBox.
    """
    out = _blank({"id": "vmware", "name": "VMware Workstation"})
    path = _which(["vmrun"], [
        r"C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe",
        r"C:\Program Files\VMware\VMware Workstation\vmrun.exe",
    ])
    if not path:
        out["detail"] = "vmrun not found"
        return out

    listed = _run([path, "list"])
    if listed is None:
        out["detail"] = "vmrun present but not runnable"
        return out

    stdout = listed.stdout or ""
    lines = [ln.strip() for ln in stdout.splitlines() if ln.strip()]
    version = next((ln for ln in lines if ln.lower().startswith("vmware")), None)
    # `vmrun list` reports "Total running VMs: N" then one path per running VM.
    running = [ln for ln in lines[1:] if not ln.lower().startswith("total")]
    out.update(
        installed=True,
        exe=path.rsplit("\\", 1)[-1],
        version=version,
        machines={
            "total": len(running),
            "running": len(running),
            "names": [ln.rsplit("\\", 1)[-1] for ln in running],
            "running_names": [ln.rsplit("\\", 1)[-1] for ln in running],
        },
        detail="vmrun list reports running VMs only",
    )
    return out


def _hyperv() -> dict:
    """Hyper-V, by the presence of the `vmms` management service.

    NOT by `System32\\vmcompute.exe`: that binary ships with Windows whether or
    not the Hyper-V role is enabled, so its existence reports Hyper-V installed
    on every Windows machine ever made. The service is the honest signal.
    """
    out = _blank({"id": "hyperv", "name": "Hyper-V"})
    script = (
        "$s = Get-Service -Name vmms -ErrorAction SilentlyContinue; "
        "if ($s) { $s.Status.ToString() }"
    )
    proc = _run(["powershell", "-NoProfile", "-NonInteractive",
                 "-Command", script], 12)
    if proc is None or proc.returncode != 0 or not (proc.stdout or "").strip():
        out["detail"] = "vmms service absent - role not enabled"
        return out

    status = (proc.stdout or "").strip()
    out.update(installed=True, exe="vmms", version=f"service {status}",
               detail="managed by Hyper-V, not a desktop hypervisor")
    return out


# ---------------------------------------------------------------------------
# aggregation
# ---------------------------------------------------------------------------

# Probes run concurrently. Each one is an external process, and serially that
# is up to four sequential spawns plus a PowerShell launch - seconds of latency
# on a page the operator is already waiting to see. A failure in one is that
# tool's problem and is recorded on its own record, never the others'.
_PROBES = {
    "virtualbox": _virtualbox,
    "qemu": _qemu,
    "vmware": _vmware,
    "hyperv": _hyperv,
}


def _run_all() -> list[dict]:
    from concurrent.futures import ThreadPoolExecutor

    with ThreadPoolExecutor(max_workers=len(_PROBES)) as pool:
        return list(pool.map(lambda fn: _guard(fn), _PROBES.values()))


def _guard(fn) -> dict:
    """A probe that raises must not take the whole detection with it."""
    try:
        return fn()
    except Exception as exc:  # noqa: BLE001 - one bad probe, not a dead panel
        rec = _blank({"id": fn.__name__.strip("_"), "name": fn.__name__})
        rec["detail"] = f"{type(exc).__name__}: {exc}"
        return rec


def detect(force: bool = False) -> dict:
    """What hypervisors are installed, and which one this project should use.

    `primary` is the one the lab is actually wired to, which is NOT always the
    only one installed: a box can legitimately have both VirtualBox and
    Hyper-V, and the analysis VM in vm_info.json belongs to whichever created
    it. VirtualBox wins the tie because that is what the Qiling tooling targets;
    otherwise the first installed tool in probe order is reported, and the UI
    shows the rest as alternatives rather than silently picking for the user.
    """
    now = time.time()
    if not force and _cache["payload"] is not None and now - _cache["at"] < _CACHE_TTL:
        return _cache["payload"]

    found = _run_all()
    # Stable order regardless of thread completion order, so the UI does not
    # reshuffle rows between polls.
    found.sort(key=lambda h: list(_PROBES).index(h["id"]) if h["id"] in _PROBES else 99)

    installed = [h for h in found if h.get("installed")]
    primary = None
    if installed:
        preferred = next((h for h in installed if h["id"] == "virtualbox"), None)
        primary = (preferred or installed[0])["id"]

    payload = {
        "checked_at": round(now, 1),
        "detected": found,
        "installed": [h["id"] for h in installed],
        "primary": primary,
        "count": len(installed),
    }
    _cache.update(at=now, payload=payload)
    return payload


def machine_count(hypervisor_id: str) -> int:
    """Registered machines for one hypervisor, 0 if it is not installed."""
    for h in detect()["detected"]:
        if h["id"] == hypervisor_id:
            return int(h["machines"]["total"] or 0)
    return 0


if __name__ == "__main__":  # manual probe: `python -m python.panel.virt`
    print(json.dumps(detect(force=True), indent=2))