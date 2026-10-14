"""Check Analysis VMs - Qiling emulation harness and CAPEv2 sandbox.

Status is derived from what actually exists in the repo:

  Qiling  - the PE harness (python/qiling/_qiling_script.py), its rootfs
            archive, whether `qiling` is importable, and its trace log.
  SSH     - trust is checked against the current user's ~/.ssh/known_hosts
            (override with known_hosts_file in admin-terminal/vms.json).
  Power   - VirtualBox/Qiling VM state comes from
            python/qiling/_check_vm_connection.py (same functions as the
            standalone script); full control lives in section 10,
            Qiling VM Control (admin-terminal/qiling_vm.py).
  CAPEv2  - the agent-side config (kafka-agent/config/cape-config.yaml)
            and, when configured, a live API endpoint.

Endpoints/IPs are stored in admin-terminal/vms.json - edit it or use the
[u]pdate key here to point at your VMs.
"""
from __future__ import annotations

import importlib.util
import json
import os
import re
import shutil
import socket
import subprocess
import time
from datetime import datetime

import core

# qiling_dlls/ is the VM payload (rootfs archive + tree, vm_info.json) and is
# also the remote_dir name, so it keeps its basename. The Python tooling lives
# in python/qiling/ with the rest of the tree.
QILING_DIR = os.path.join(core.REPO, "qiling_dlls")
QILING_SCRIPTS = os.path.join(core.REPO, "python", "qiling")
QILING_SCRIPT = os.path.join(QILING_SCRIPTS, "_qiling_script.py")
ROOTFS_TAR = os.path.join(QILING_DIR, "rootfs.tar.gz")
ROOTFS_DIR = os.path.join(QILING_DIR, "examples", "rootfs")
QILING_TRACE = os.path.join(QILING_DIR, "trace.log")
CAPE_CONFIG = os.path.join(core.REPO, "kafka-agent", "config",
                           "cape-config.yaml")
VMS_FILE = os.path.join(core.ADMIN, "vms.json")

DEFAULT_VMS = {
    "qiling": {
        "name": "Qiling",
        "host": "192.168.56.105",
        "port": 22,
        "kind": "ssh",
        "username": "YOUR_VM_USERNAME",
        "remote_dir": "qiling_dlls",
        "remote_python": "python3",
        "identity_file": "",
        "password": "",
        "path": "/",
        "known_hosts_file": "~/.ssh/known_hosts",
        "hint": "Analysis VM SSH; verify its key in ~/.ssh/known_hosts",
    },
    "capev2": {
        "name": "CAPEv2",
        "host": "127.0.0.1",
        "port": 8090,        # CAPE's REST API port by convention
        "kind": "http",
        "path": "/apiv2/",
        "hint": "CAPE API endpoint (edit vms.json)",
    },
}


def load_vms() -> dict:
    if not os.path.isfile(VMS_FILE):
        save_vms(DEFAULT_VMS)
        return json.loads(json.dumps(DEFAULT_VMS))
    try:
        with open(VMS_FILE, encoding="utf-8") as fh:
            data = json.load(fh)
        if not isinstance(data, dict):
            raise ValueError("VM configuration must be an object")
    except (ValueError, OSError):
        return json.loads(json.dumps(DEFAULT_VMS))

    for key, defaults in DEFAULT_VMS.items():
        config = data.get(key)
        if not isinstance(config, dict):
            data[key] = dict(defaults)
            continue
        merged = {**defaults, **config}
        if not isinstance(merged.get("host"), str):
            merged["host"] = defaults["host"]
        try:
            port = int(merged.get("port", defaults["port"]) or 0)
        except (TypeError, ValueError):
            port = defaults["port"]
        merged["port"] = port if 0 <= port <= 65535 else defaults["port"]
        for field in ("name", "kind", "path", "hint", "username",
                      "remote_dir", "known_hosts_file", "remote_python",
                      "identity_file", "password"):
            if field in defaults and not isinstance(merged.get(field), str):
                merged[field] = defaults[field]
        if merged["kind"] not in ("http", "tcp", "local", "ssh"):
            merged["kind"] = defaults["kind"]
        if not merged["path"].startswith("/"):
            merged["path"] = defaults["path"]
        data[key] = merged
    return data


def save_vms(data: dict) -> None:
    with open(VMS_FILE, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)


# ---------------------------------------------------------------------------
# python/qiling/_check_vm_connection.py - shared VM checks and power control
# ---------------------------------------------------------------------------
_VM_CHECK = None


def vm_check():
    """Load the VM check module (python/qiling/_check_vm_connection.py) once."""
    global _VM_CHECK
    if _VM_CHECK is not None:
        return _VM_CHECK
    path = os.path.join(QILING_SCRIPTS, "_check_vm_connection.py")
    if not os.path.isfile(path):
        raise RuntimeError(f"VM check module missing: {path}")
    spec = importlib.util.spec_from_file_location("check_vm_connection", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load VM check module: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    _VM_CHECK = module
    return module


def vm_call(fn, *args, **kwargs):
    """Run a VM check function; any failure becomes (False, detail)."""
    try:
        return fn(*args, **kwargs)
    except Exception as exc:  # noqa: BLE001 - status screens must not crash
        return False, str(exc) or type(exc).__name__


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------
def _qiling_importable() -> tuple[bool, str]:
    """Ask every candidate interpreter whether `qiling` imports."""
    candidates = [os.path.join(core.REPO, "python", ".venv", "Scripts",
                               "python.exe"),
                  os.path.join(core.REPO, "ml", "_t", "venv", "Scripts",
                               "python.exe"),
                  shutil.which("python") or "python"]
    for py in candidates:
        if not py or (os.path.sep in py and not os.path.isfile(py)):
            continue
        try:
            out = subprocess.run(
                [py, "-c", "import qiling, sys; "
                           "sys.stdout.write(getattr(qiling, '__version__', 'ok'))"],
                capture_output=True, text=True, timeout=20)
            if out.returncode == 0:
                return True, f"{os.path.basename(os.path.dirname(py))}: " \
                             f"qiling {out.stdout.strip()}"
        except Exception:  # noqa: BLE001
            continue
    return False, "qiling not installed (pip install qiling==1.4.6)"


def _file_row(label: str, path: str) -> list[tuple[str, tuple[str, ...]]]:
    if os.path.isfile(path):
        size = os.path.getsize(path)
        detail = f"{size / (1024 * 1024):.1f} MB" if size > 1024 * 1024 \
            else f"{size} B"
        return [(label, (core.BOLD,)), ("file", ()),
                (" OK ", (core.BOLD, core.GREEN)), (detail, ())]
    return [(label, (core.BOLD,)), ("file", ()),
            ("MISS", (core.BOLD, core.RED)),
            (os.path.relpath(path, core.REPO), (core.RED,))]


def _probe_endpoint(host: str, port: int, path: str = "/",
                    kind: str = "http") -> tuple[bool, str, float]:
    started = time.monotonic()
    try:
        if kind == "tcp":
            with socket.create_connection((host, port), timeout=3.0):
                pass
            return True, "open", (time.monotonic() - started) * 1000
        import urllib.request
        url_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
        url = f"http://{url_host}:{port}{path}"
        with urllib.request.urlopen(url, timeout=3.0) as resp:
            return resp.status < 400, f"HTTP {resp.status}", \
                (time.monotonic() - started) * 1000
    except Exception as exc:  # noqa: BLE001
        return False, core.why(exc), (time.monotonic() - started) * 1000


def _dir_row(label: str, path: str) -> list[tuple[str, tuple[str, ...]]]:
    if os.path.isdir(path):
        n = sum(len(files) for _, _, files in os.walk(path))
        return [(label, (core.BOLD,)), ("dir", ()),
                (" OK ", (core.BOLD, core.GREEN)), (f"{n} files", ())]
    return [(label, (core.BOLD,)), ("dir", ()),
            ("MISS", (core.BOLD, core.RED)),
            (os.path.relpath(path, core.REPO), (core.RED,))]


def _fmt_mtime(path: str) -> str:
    if not os.path.isfile(path):
        return "missing"
    return datetime.fromtimestamp(os.path.getmtime(path)).strftime(
        "%Y-%m-%d %H:%M")


def _vm_control_rows() -> list[list[tuple[str, tuple[str, ...]]]]:
    """VirtualBox/Qiling VM power rows via _check_vm_connection.py."""
    def row(label: str, target: str, status: str, colour: str,
            detail: str) -> list[tuple[str, tuple[str, ...]]]:
        return [(label, (core.BOLD,)), (target, ()),
                (status, (core.BOLD, colour)),
                (detail, () if colour == core.GREEN else (colour,))]

    try:
        mod = vm_check()
    except Exception as exc:  # noqa: BLE001
        return [row("  VM control", "module", "MISS", core.RED, str(exc))]

    digest_ok, digest_detail = vm_call(mod.check_vboxmanage_digest)
    rows = [row("  VirtualBox", "VBoxManage", " OK " if digest_ok else "FAIL",
                core.GREEN if digest_ok else core.RED, digest_detail)]

    exists, exists_detail = vm_call(mod.does_qiling_vm_exists)
    running, running_detail = vm_call(mod.is_vm_running)
    info = vm_call(mod.load_vm_info)
    name = info.get("VM_NAME", "?") if isinstance(info, dict) else "?"
    if not exists:
        rows.append(row("  Qiling VM", name, "MISS", core.RED, exists_detail))
    elif running:
        rows.append(row("  Qiling VM", name, "RUN ", core.GREEN,
                        running_detail))
    else:
        rows.append(row("  Qiling VM", name, "STOP", core.YELLOW,
                        running_detail))
    return rows


def _ensure_vm_running() -> bool:
    """Offer to start the Qiling VM when a deploy needs it running."""
    try:
        mod = vm_check()
    except Exception as exc:  # noqa: BLE001
        print(core.paint(f"  ! cannot check VM power: {exc}", core.YELLOW))
        return True
    running, _ = vm_call(mod.is_vm_running)
    if running:
        return True
    if core.confirm("  Qiling VM is not running; start it now?", True):
        ok, detail = vm_call(mod.start_vm)
        print(core.paint(f"  {'[+]' if ok else '[-]'} {detail}",
                         core.GREEN if ok else core.RED))
        return ok
    print(core.paint("  ! deploying needs the VM running", core.YELLOW))
    return False


# ---------------------------------------------------------------------------
# Screen
# ---------------------------------------------------------------------------
def screen() -> None:
    vms = load_vms()
    print(core.paint("\n  ANALYSIS VMs", core.CYAN, core.BOLD))

    rows: list[list[tuple[str, tuple[str, ...]]]] = []

    # --- Qiling local prerequisites -------------------------------------
    ok, detail = _qiling_importable()
    rows.append([
        ("Qiling", (core.BOLD,)), ("harness", ()),
        (" UP " if ok else "DOWN", (core.BOLD,
                                    core.GREEN if ok else core.RED)),
        (detail, () if ok else (core.RED,)),
    ])
    rows.append(_file_row("  script", QILING_SCRIPT))
    rows.append(_file_row("  rootfs.tar.gz", ROOTFS_TAR))
    rows.append(_dir_row("  rootfs/", ROOTFS_DIR))
    rows.append([("  trace.log", (core.BOLD,)), ("log", ()),
                 (" OK " if os.path.isfile(QILING_TRACE) else "none",
                  (core.BOLD, core.GREEN if os.path.isfile(QILING_TRACE)
                   else core.YELLOW)),
                 (_fmt_mtime(QILING_TRACE), ())])
    qiling = vms.get("qiling", DEFAULT_VMS["qiling"])
    known_hosts_path = core.known_hosts_path(
        qiling.get("known_hosts_file", ""))
    known_hosts_ready = False
    if os.path.isfile(known_hosts_path):
        with open(known_hosts_path, encoding="utf-8", errors="replace") as fh:
            known_hosts_ready = any(
                line.strip() and not line.lstrip().startswith("#")
                for line in fh)
    rows.append([
        ("  Analysis VM", (core.BOLD,)),
        (f"{qiling['host']}:{qiling['port']}", ()),
        (" READY " if known_hosts_ready else "NO KEY",
         (core.BOLD, core.GREEN if known_hosts_ready else core.YELLOW)),
        (f"user={qiling['username']}; SSH key trust "
         f"{'configured' if known_hosts_ready else 'needed'}",
         () if known_hosts_ready else (core.YELLOW,)),
    ])
    rows.extend(_vm_control_rows())

    # --- CAPEv2 -----------------------------------------------------------
    cape = vms.get("capev2", DEFAULT_VMS["capev2"])
    rows.append([("CAPEv2", (core.BOLD,)), ("config", ()),
                 (" OK " if os.path.isfile(CAPE_CONFIG) else "MISS",
                  (core.BOLD, core.GREEN if os.path.isfile(CAPE_CONFIG)
                   else core.RED)),
                 ("cape-config.yaml" if os.path.isfile(CAPE_CONFIG)
                  else "kafka-agent/config/cape-config.yaml missing",
                  () if os.path.isfile(CAPE_CONFIG) else (core.RED,))])

    host, port = cape.get("host", ""), int(cape.get("port", 0) or 0)
    if host and port:
        reachable, why_, ms = _probe_endpoint(
            host, port, cape.get("path", "/"), cape.get("kind", "http"))
        rows.append([
            ("  API", (core.BOLD,)), (f"{host}:{port}", ()),
            (" UP " if reachable else "DOWN",
             (core.BOLD, core.GREEN if reachable else core.RED)),
            (f"{why_} ({ms:.0f} ms)" if reachable else why_,
             () if reachable else (core.RED,)),
        ])
    else:
        rows.append([("  API", (core.BOLD,)), ("not set", ()),
                     ("SKIP", (core.BOLD, core.YELLOW)),
                     ("set host/port in vms.json", (core.YELLOW,))])

    print(core.table("ANALYSIS VMs", "checked now", (14, 18, 8, 40),
                     ("VM", "VIA", "STATUS", "DETAIL"), rows))

    print(core.paint("  [q]iling setup   [d]eploy/run sample   "
                     "[v]m control   [u]pdate endpoints   [Enter]=menu",
                     core.DIM))
    choice = core.ask("  choice", "").lower()
    if choice == "u":
        _update(vms)
    elif choice == "q":
        _qiling_action(vms, run_sample=False)
    elif choice == "d":
        _qiling_action(vms, run_sample=True)
    elif choice == "v":
        import qiling_vm
        qiling_vm.screen()


def _update(vms: dict) -> None:
    for key in ("qiling", "capev2"):
        cfg = vms.setdefault(key, dict(DEFAULT_VMS[key]))
        print(core.paint(f"\n  {cfg.get('name', key)} endpoint", core.BOLD))
        host = core.ask(f"    host (Enter keeps {cfg.get('host', '')})", "").strip()
        if host:
            ok, why_ = netcfg_valid_host(host)
            if not ok:
                print(core.paint(f"    ! invalid host: {why_}", core.RED))
                continue
            cfg["host"] = host
        port_raw = core.ask(f"    port (Enter keeps {cfg.get('port', '')})",
                            "").strip()
        if port_raw:
            try:
                port = int(port_raw)
                if not (1 <= port <= 65535):
                    raise ValueError
                cfg["port"] = port
            except ValueError:
                print(core.paint(f"    ! invalid port '{port_raw}'",
                                 core.RED))
        if key == "qiling":
            username = core.ask(
                f"    SSH username (Enter keeps {cfg.get('username', '')})",
                "").strip()
            if username:
                if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]*", username):
                    print(core.paint("    ! invalid SSH username", core.RED))
                    continue
                cfg["username"] = username
            remote_dir = core.ask(
                f"    remote directory under home "
                f"(Enter keeps {cfg.get('remote_dir', 'qiling_dlls')})",
                "").strip()
            if remote_dir:
                if not re.fullmatch(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*",
                                    remote_dir) or any(
                        part in (".", "..") for part in remote_dir.split("/")):
                    print(core.paint("    ! use a relative path under the "
                                     "SSH user's home", core.RED))
                    continue
                cfg["remote_dir"] = remote_dir
    save_vms(vms)
    print(core.paint("  saved to admin-terminal/vms.json", core.GREEN))
    core.pause()


def _qiling_action(vms: dict, run_sample: bool) -> None:
    from qiling_setup import (
        QilingSetupError,
        allow_vm_subnet_firewall,
        deploy_and_run,
        network_blocked,
        setup_rootfs,
    )

    config = vms.get("qiling", DEFAULT_VMS["qiling"])
    try:
        if not rootfs_exists():
            if not core.confirm(
                    "  rootfs is incomplete; run dll_collector.bat as "
                    "Administrator and package it?", False):
                return
        if run_sample:
            setup_rootfs()
            if not _ensure_vm_running():
                return
            sample = core.ask("  executable path", "").strip().strip('"')
            if not sample:
                return
            try:
                result = deploy_and_run(config, sample)
            except QilingSetupError as exc:
                if not network_blocked(exc) or not core.confirm(
                        "  SSH timed out. Add narrow inbound/outbound HTTP "
                        "and SSH firewall rules for 192.168.56.0/24? "
                        "(Administrator prompt)", False):
                    raise
                allow_vm_subnet_firewall()
                result = deploy_and_run(config, sample)
            print(core.paint(f"  Qiling report downloaded: {result}",
                             core.GREEN, core.BOLD))
        else:
            setup_rootfs()
            print(core.paint("  Qiling rootfs is ready.", core.GREEN, core.BOLD))
    except (QilingSetupError, OSError, subprocess.SubprocessError) as exc:
        print(core.paint(f"  ! Qiling setup failed: {exc}", core.RED))
    core.pause()


def rootfs_exists() -> bool:
    """Return whether both x86 and x64 local Qiling rootfs trees exist."""
    for arch in ("x86_windows", "x8664_windows"):
        windows = os.path.join(ROOTFS_DIR, arch, "Windows")
        system32 = os.path.join(windows, "System32")
        if not (os.path.isdir(system32)
                and os.path.isfile(os.path.join(system32, "kernel32.dll"))
                and os.path.isfile(os.path.join(system32, "ntdll.dll"))
                and os.path.isfile(os.path.join(windows, "registry", "SYSTEM"))):
            return False
    return True


def netcfg_valid_host(value: str):
    from netcfg import valid_host
    return valid_host(value)
