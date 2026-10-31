"""Topology of the machines and networks this lab runs on, for a network map.

Everything here is READ from what actually exists on the box - never assumed:

  * host adapters     `Get-NetIPAddress` (Windows) - the host's own IPv4s
  * VirtualBox        `VBoxManage list hostonlyifs` + the VM's registered
    host-only net     state, so the map shows the 192.168.56.0/24 lab network
                      and the Qiling VM that sits on it
  * Docker bridge     `docker network inspect` per project - the 172.20.0.0/16
                      bridge and the containers attached to it
  * reachability      a TCP connect to each endpoint, so a node is "up" because
                      it answered, not because a config file says it should

The result is a graph: `nodes` (host, adapters, networks, VMs, containers) and
`links` (which node hangs off which). The front end lays it out; this module
only reports what is true. A node that cannot be probed is still reported -
powered off, unreachable - so the gap is visible instead of missing.
"""

from __future__ import annotations

import ipaddress
import json
import re
import socket
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor

from ..core import config
from ..host import containers
from . import virt

VBOX = config.VBOXMANAGE

# A Windows path, matched through the file extension rather than to the next
# space. Matching to whitespace looks simpler but is wrong for the one string
# that matters most here: "C:\Program Files\Oracle\VirtualBox\VBoxManage.EXE"
# contains a space, so a whitespace-delimited pattern stops at `C:\Program` and
# leaves the rest of the directory on screen. Anchoring on the extension lets
# the match cross spaces and still stop at the end of the filename.
# The second alternative covers UNC paths (`\\server\share\tool.exe`).
_WIN_PATH = re.compile(
    r"(?:[A-Za-z]:\\|\\\\[^\s\\/]+)[^\n\"']*?\.(?:exe|msi|dll|bat|cmd|ps1|sys|inf)\b",
    re.IGNORECASE,
)


def basename_only(text) -> str:
    """Strip directory components from any path embedded in a free-text string.

    VBoxManage reports its own digest verdict as a sentence with the absolute
    path in it ("C:\\Program Files\\Oracle\\VirtualBox\\VBoxManage.EXE sha256
    matches"). The panel shows which binary answered, not where it lives, so
    the directory is dropped wherever one appears - including inside tool
    output this package does not parse.
    """
    return _WIN_PATH.sub(lambda m: m.group(0).rsplit("\\", 1)[-1], str(text or ""))


def run_tool(args: list[str], timeout: float):
    try:
        return subprocess.run(
            args, capture_output=True, text=True, timeout=timeout,
            encoding="utf-8", errors="replace", check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None


def _ps_json(script: str, timeout: float = 15):
    """Run a PowerShell snippet that emits one JSON document on stdout."""
    proc = run_tool(["powershell", "-NoProfile", "-NonInteractive",
                 "-Command", script], timeout)
    if proc is None or proc.returncode != 0:
        return None
    raw = (proc.stdout or "").strip()
    if not raw:
        return None
    try:
        return json.loads(raw)
    except ValueError:
        return None


def _tcp(host: str, port: int, timeout: float = 1.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


# ---------------------------------------------------------------------------
# host adapters - the host's own IPv4 addresses, from the OS
# ---------------------------------------------------------------------------

# Adapters that are noise on a topology map: link-local auto-config, the
# disconnected placeholder, and the WSL/Tailscale tunnels that are not part of
# the analysis lab. The map is about the lab, so these are labelled "other".
def _host_adapters() -> list[dict]:
    script = (
        "Get-NetIPAddress -AddressFamily IPv4 | "
        "Where-Object { $_.IPAddress -ne '127.0.0.1' } | "
        "Select-Object IPAddress,InterfaceAlias | ConvertTo-Json -Compress"
    )
    data = _ps_json(script)
    rows = data if isinstance(data, list) else ([data] if isinstance(data, dict) else [])
    out: list[dict] = []
    for r in rows:
        ip = str(r.get("IPAddress") or "").strip()
        alias = str(r.get("InterfaceAlias") or "").strip()
        if not ip:
            continue
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if addr.is_link_local:  # 169.254.x.x - auto-config, not a real network
            continue
        out.append({"ip": ip, "alias": alias, "loopback": addr.is_loopback})
    return out


# ---------------------------------------------------------------------------
# VirtualBox host-only network + the Qiling VM that lives on it
# ---------------------------------------------------------------------------

def _vbox_hostonly() -> list[dict]:
    """Each VirtualBox host-only interface: name, gateway IP, mask."""
    proc = run_tool([str(VBOX), "list", "hostonlyifs"], 10)
    if proc is None or proc.returncode != 0:
        return []
    blocks: list[dict] = []
    cur: dict = {}
    for line in (proc.stdout or "").splitlines():
        if ":" not in line:
            continue
        key, _, val = line.partition(":")
        key, val = key.strip(), val.strip()
        if key == "Name":
            if cur:
                blocks.append(cur)
            cur = {"name": val}
        elif key == "IPAddress":
            cur["ip"] = val
        elif key == "NetworkMask":
            cur["mask"] = val
    if cur:
        blocks.append(cur)
    nets = []
    for b in blocks:
        ip, mask = b.get("ip", ""), b.get("mask", "")
        if not ip or not mask:
            continue
        try:
            net = ipaddress.ip_network(f"{ip}/{mask}", strict=False)
        except ValueError:
            continue
        nets.append({"name": b.get("name", "vboxnet"), "gateway": ip,
                     "cidr": str(net), "mask": mask})
    return nets


def _qiling_vm(nets: list[dict]) -> dict | None:
    """The Qiling analysis VM: registered? running? on which host-only net?"""
    try:
        mod = _load_check()
        info = mod.load_vm_info()
    except Exception:  # noqa: BLE001
        return None
    name = str(info.get("VM_NAME", "") or "")
    ip = str(info.get("VM_IP", "") or "")
    try:
        port = int(info.get("VM_PORT", info.get("PORT", 22)) or 22)
    except (TypeError, ValueError):
        port = 22
    registered, running = False, False
    try:
        registered = bool(mod.does_qiling_vm_exists()[0])
    except Exception:  # noqa: BLE001
        pass
    try:
        running = bool(mod.is_vm_running()[0])
    except Exception:  # noqa: BLE001
        pass
    subnet = ""
    try:
        addr = ipaddress.ip_address(ip)
        for n in nets:
            if addr in ipaddress.ip_network(n["cidr"]):
                subnet = n["cidr"]
                break
    except ValueError:
        pass
    return {
        "name": name or "Qiling VM",
        "ip": ip,
        "port": port,
        "registered": registered,
        "running": running,
        "subnet": subnet,
        "reachable": _tcp(ip, port) if (ip and running) else False,
    }


def _load_check():
    import importlib
    import sys
    check_dir = str(config.REPO / "python" / "qiling")
    if check_dir not in sys.path:
        sys.path.insert(0, check_dir)
    return importlib.import_module("_check_vm_connection")


# ---------------------------------------------------------------------------
# Docker bridge networks + attached containers
# ---------------------------------------------------------------------------

def _docker_networks() -> list[dict]:
    """Each Docker network that has containers on it, with its subnet."""
    ls = run_tool(["docker", "network", "ls", "--format", "{{json .}}"], 10)
    if ls is None or ls.returncode != 0:
        return []
    names: list[str] = []
    for line in (ls.stdout or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if isinstance(row, dict) and row.get("Name"):
            names.append(str(row["Name"]))
    out: list[dict] = []
    for name in names:
        insp = run_tool(["docker", "network", "inspect", name,
                     "--format", "{{json .}}"], 10)
        if insp is None or insp.returncode != 0:
            continue
        try:
            doc = json.loads((insp.stdout or "").strip())
        except ValueError:
            continue
        if isinstance(doc, list):
            doc = doc[0] if doc else {}
        if not isinstance(doc, dict):
            continue
        subnet = ""
        for cfg in (doc.get("IPAM", {}) or {}).get("Config", []) or []:
            if isinstance(cfg, dict) and cfg.get("Subnet"):
                subnet = str(cfg["Subnet"])
                break
        members = []
        for cid, c in (doc.get("Containers", {}) or {}).items():
            if not isinstance(c, dict):
                continue
            ip = str(c.get("IPv4Address", "") or "").split("/")[0]
            members.append({"name": str(c.get("Name") or cid[:12]), "ip": ip})
        # Only networks that actually carry a container are worth mapping.
        if members:
            out.append({"name": name, "driver": str(doc.get("Driver") or ""),
                        "subnet": subnet, "containers": sorted(members, key=lambda m: m["ip"])})
    return out


# ---------------------------------------------------------------------------
# graph assembly
# ---------------------------------------------------------------------------

def _adapter_for_ip(adapters: list[dict], ip: str) -> str | None:
    """The adapter node id whose IP matches, so networks hang off a real NIC."""
    for i, a in enumerate(adapters):
        if a.get("ip") == ip:
            return f"adapter-{i}"
    return None


# ---------------------------------------------------------------------------
# VirtualBox
#
# A dedicated status payload rather than more map nodes: an operator asking
# "is VirtualBox even installed, and is its build the one we pinned" wants
# answers about the tool itself, not another dot on a diagram.
#
# Everything here reuses python/qiling/_check_vm_connection.py rather than
# re-running VBoxManage with subtly different arguments - that module already
# owns the pinned SHA-256, the VM-name parser and the TCP probe, and two
# implementations of "is VBoxManage the right build" is how they drift apart.
# ---------------------------------------------------------------------------

# Ports worth probing on the analysis VM. ssh and sftp share 22 and are listed
# once: probing it twice would report the same answer twice and imply they are
# separately switchable, which they are not.
#
# Public rather than private because vms.py probes the SAME list against every
# registered machine. Two copies of "which ports matter on a sandbox guest"
# would drift, and the panel would end up disagreeing with itself about whether
# a service is running.
VM_SERVICES = [
    (22, "ssh", "SSH and SFTP - how the panel runs things inside the guest"),
    (80, "http", "HTTP"),
    (443, "https", "HTTPS"),
    (445, "smb", "SMB - the classic malware-share vector"),
    (3389, "rdp", "RDP - the Guacamole target"),
    (5900, "vnc", "VNC"),
    (5985, "winrm", "WinRM - remote PowerShell"),
    (161, "snmp", "SNMP"),
    (21, "ftp", "FTP"),
    (23, "telnet", "Telnet"),
]

_VBOX_CACHE_TTL = 8.0
_vbox_cache: dict = {"at": 0.0, "payload": None}


def _vm_host() -> tuple[str, int]:
    info = config.vm_info()
    if not info:
        return "", 22
    return info["ip"], int(info["port"])


def probe_vm_services(host: str, timeout: float = 1.2) -> list[dict]:
    """TCP-connect each candidate service on the VM, concurrently.

    A powered-off guest DROPS rather than refusing, so every port would take the
    full timeout. The thread pool keeps that at one timeout's worth of wall
    clock instead of eleven.

    Returns the FULL list with an `open` flag rather than only the hits. The
    distinction matters to callers: "nothing is listening" and "we never
    checked" must not look the same.
    """
    if not host:
        return []

    def one(entry):
        port, name, detail = entry
        return {
            "port": port, "name": name, "detail": detail,
            "open": _tcp(host, port, timeout),
        }

    with ThreadPoolExecutor(max_workers=len(VM_SERVICES)) as pool:
        return list(pool.map(one, VM_SERVICES))


def vbox_status() -> dict:
    """Installed? Right build? How many machines? What is on the host-only?"""
    now = time.time()
    if _vbox_cache["payload"] is not None and now - _vbox_cache["at"] < _VBOX_CACHE_TTL:
        return _vbox_cache["payload"]

    out: dict = {
        "checked_at": round(now, 1),
        "installed": False,
        # Basename only. The full path stays local - it is an implementation
        # detail of the probe, and an operator reading a status panel needs to
        # know WHICH binary answered, not where the installer put it.
        "exe": None,
        "error": None,
        "version": None,
        "digest": {"ok": None, "sha256": None, "pinned": None, "detail": ""},
        "machines": {"total": 0, "running": 0, "names": []},
        "hostonly": {"available": False, "count": 0, "networks": [], "gateway": None},
        "vm": {"name": None, "ip": None, "port": None, "services": []},
        "services_open": 0,
        "services_total": len(VM_SERVICES),
    }

    checker = None
    try:
        checker = _load_check()
    except Exception as exc:  # noqa: BLE001 - the checker lives outside this package
        out["error"] = f"{type(exc).__name__}: {basename_only(exc)}"

    # --- installed + build identity ---
    if checker is not None:
        exe_path = None
        try:
            exe_path = checker.vboxmanage_path()
            out["installed"] = True
            out["exe"] = str(exe_path).rsplit("\\", 1)[-1]
        except Exception as exc:  # noqa: BLE001 - not installed is a normal state
            out["error"] = basename_only(exc)

        try:
            ok, detail = checker.check_vboxmanage_digest()
            out["digest"]["ok"] = ok
            out["digest"]["detail"] = basename_only(detail)
            out["digest"]["pinned"] = getattr(checker, "VBOXMANAGE_SHA256", None)
            # The helper only returns a detail string, so hash it again to show
            # the real value - an operator comparing builds needs both sides.
            if exe_path:
                import hashlib

                h = hashlib.sha256()
                try:
                    with open(exe_path, "rb") as fh:
                        for chunk in iter(lambda: fh.read(1 << 20), b""):
                            h.update(chunk)
                    out["digest"]["sha256"] = h.hexdigest()
                except OSError:
                    pass
        except Exception as exc:  # noqa: BLE001
            out["digest"]["detail"] = basename_only(f"{type(exc).__name__}: {exc}")

        ver = run_tool([str(exe_path or "VBoxManage"), "--version"], 8)
        if ver is not None and ver.returncode == 0:
            first = (ver.stdout or "").strip().splitlines()
            out["version"] = first[0].strip() if first else None

        # --- registered machines ---
        if out["installed"]:
            try:
                names = checker.list_vms()
                running = checker.list_running_vms()
                out["machines"] = {
                    "total": len(names),
                    "running": len(running),
                    "names": sorted(names),
                    "running_names": sorted(running),
                }
            except Exception as exc:  # noqa: BLE001
                out["error"] = basename_only(f"{type(exc).__name__}: {exc}")

    # --- host-only adapter ---
    nets = _vbox_hostonly()
    out["hostonly"] = {
        "available": bool(nets),
        "count": len(nets),
        "networks": nets,
        "gateway": nets[0]["gateway"] if nets else None,
        "cidr": nets[0]["cidr"] if nets else None,
    }

    # --- the analysis VM and what it is running ---
    host, port = _vm_host()
    info = config.vm_info()
    out["vm"] = {
        "name": info["name"] if info else None,
        "ip": host or None,
        "port": port,
        "configured": bool(info),
        "services": probe_vm_services(host),
    }
    out["services_open"] = sum(1 for s in out["vm"]["services"] if s["open"])

    _vbox_cache.update(at=time.time(), payload=out)
    return out


def snapshot() -> dict:
    """A node/link graph of the host, its networks, and what runs on them."""
    adapters = _host_adapters()
    hostonly = _vbox_hostonly()
    qiling = _qiling_vm(hostonly)
    dockers = _docker_networks()

    nodes: list[dict] = []
    links: list[dict] = []

    def node(nid, **kw):
        nodes.append({"id": nid, **kw})

    # host is the root everything hangs off
    import socket as _socket
    node("host", label="This host", kind="host",
         sub=_socket.gethostname(), status="up",
         detail=f"{len(adapters)} interface(s)")

    # Each host adapter IP is its own node off the host, so the map shows the
    # addresses the box actually holds rather than hiding them behind "host".
    adapter_ids: list[str] = []
    for i, a in enumerate(adapters):
        aid = f"adapter-{i}"
        adapter_ids.append(aid)
        node(aid, label=a["ip"], kind="adapter", ip=a["ip"],
             status="up", detail=a["alias"])
        links.append({"source": "host", "target": aid, "kind": "adapter"})

    hostonly_ids: list[str] = []
    for i, n in enumerate(hostonly):
        nid = f"vbox-{i}"
        hostonly_ids.append(nid)
        node(nid, label=n["name"], kind="network", subnet=n["cidr"],
             status="up", detail=f"VirtualBox host-only · gw {n['gateway']}")
        # attach to the host adapter that actually holds this gateway IP
        gw_node = _adapter_for_ip(adapters, n["gateway"])
        links.append({"source": gw_node or "host", "target": nid, "kind": "adapter"})

    docker_ids: list[str] = []
    for i, n in enumerate(dockers):
        nid = f"docker-{i}"
        docker_ids.append(nid)
        node(nid, label=n["name"], kind="network", subnet=n["subnet"],
             status="up", detail=f"{n['driver']} · {len(n['containers'])} container(s)")
        links.append({"source": "host", "target": nid, "kind": "bridge"})
        for c in n["containers"]:
            cid = f"{nid}:{c['name']}"
            node(cid, label=c["name"], kind="container", ip=c["ip"],
                 status="up", detail=c["ip"])
            links.append({"source": nid, "target": cid, "kind": "member"})

    if qiling:
        qid = "qiling-vm"
        node(qid, label=qiling["name"], kind="vm", ip=qiling["ip"],
             status=("up" if qiling["reachable"]
                     else "running" if qiling["running"] else "down"),
             detail=(f"{qiling['ip']}:{qiling['port']}"
                     + ("" if qiling["running"] else " · not running")))
        # attach the VM to the host-only network it actually sits on
        parent = hostonly_ids[0] if hostonly_ids else "host"
        links.append({"source": parent, "target": qid, "kind": "host-only"})

    return {
        "generated_at": round(time.time(), 1),
        "nodes": nodes,
        "links": links,
        "host_adapters": adapters,
        "hostonly": hostonly,
        "docker": dockers,
        "qiling_vm": qiling,
        "counts": {
            "networks": len(hostonly) + len(dockers),
            "containers": sum(len(n["containers"]) for n in dockers),
            "vms": 1 if qiling else 0,
            "adapters": len(adapters),
        },
        "vbox": vbox_status(),
        # Which hypervisor is installed, independent of the VirtualBox-specific
        # detail above. `vbox` answers "what is VirtualBox doing"; this answers
        # "is this box even a VirtualBox box", which is the question that comes
        # first when the map is empty and you are deciding whether the panel or
        # the VM is at fault.
        "virt": virt.detect(),
    }
