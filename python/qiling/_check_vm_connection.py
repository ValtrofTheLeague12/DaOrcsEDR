"""Verify, connect to, and control the Qiling analysis VM.

Every library function returns an ``(ok, detail)`` tuple and never prints or
exits, so admin-terminal (admin-terminal/qiling_vm.py) can drive exactly the
same checks and power actions.  Running this file directly prints the report:

    python python/qiling/_check_vm_connection.py
    python python/qiling/_check_vm_connection.py --ssh
    python python/qiling/_check_vm_connection.py --json

The VM identity (name, IP, SSH port) comes from qiling_dlls/vm_info.json,
which is VM payload and stays next to the rootfs; SSH credentials come from
admin-terminal/vms.json or the CLI flags.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import shutil
import socket
import subprocess
import sys
import time
from typing import NamedTuple

VBOXMANAGE_SHA256 = "e058bc8a9bf9b8cf81b58efd18c16ae563d08b9641aea4732b336a0d619b7294"

# This script lives in python/qiling/, so the repo root is two levels up and
# the VM payload dir is qiling_dlls/ beside it.
_HERE = pathlib.Path(__file__).resolve().parent
PAYLOAD_DIR = _HERE.parent.parent / "qiling_dlls"
VM_INFO_FILE = PAYLOAD_DIR / "vm_info.json"

# VBoxManage prints machines as:  "Name with spaces" {uuid}
_VM_LINE = re.compile(r'^"(?P<name>.+)"\s+\{(?P<uuid>[0-9a-fA-F-]+)\}',
                      re.MULTILINE)


class VmCheckError(RuntimeError):
    """Configuration or environment problem that blocks a VM check."""


class Check(NamedTuple):
    name: str
    ok: bool
    detail: str


# ---------------------------------------------------------------------------
# vm_info.json
# ---------------------------------------------------------------------------
def load_vm_info() -> dict:
    """Read and validate vm_info.json (VM_NAME, VM_IP, VM_PORT|PORT)."""
    if not VM_INFO_FILE.is_file():
        raise VmCheckError(
            f"{VM_INFO_FILE.name} not found in {VM_INFO_FILE.parent}")
    try:
        data = json.loads(VM_INFO_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise VmCheckError(f"cannot parse {VM_INFO_FILE.name}: {exc}") from exc
    if not isinstance(data, dict):
        raise VmCheckError(f"{VM_INFO_FILE.name} must contain a JSON object")

    name = str(data.get("VM_NAME", "")).strip()
    ip = str(data.get("VM_IP", "")).strip()
    if not name:
        raise VmCheckError(
            "VM_NAME is missing - set the VirtualBox machine name in "
            f"{VM_INFO_FILE.name}")
    if not ip:
        raise VmCheckError(f"VM_IP is missing in {VM_INFO_FILE.name}")
    try:
        port = int(data.get("VM_PORT", data.get("PORT", 22)))
    except (TypeError, ValueError) as exc:
        raise VmCheckError(f"PORT must be an integer in {VM_INFO_FILE.name}") \
            from exc
    if not 1 <= port <= 65535:
        raise VmCheckError(f"PORT must be between 1 and 65535 in "
                           f"{VM_INFO_FILE.name}")
    # Keep extra keys (e.g. GENERATE_ROOTFS_IF_NOT_FOUND) for callers.
    return {**data, "VM_NAME": name, "VM_IP": ip, "PORT": port}


def _vm_name(vm_name: str | None = None) -> str:
    return vm_name if vm_name else load_vm_info()["VM_NAME"]


def _endpoint(config: dict | None = None) -> tuple[str, int]:
    """(host, port) from the config, falling back to vm_info.json."""
    config = config or {}
    info: dict = {}
    try:
        info = load_vm_info()
    except VmCheckError:
        pass
    host = str(config.get("host") or info.get("VM_IP") or "").strip()
    raw_port = config.get("port") or info.get("PORT") or 22
    try:
        port = int(raw_port)
    except (TypeError, ValueError):
        port = 22
    if not 1 <= port <= 65535:
        port = 22
    return host, port


# ---------------------------------------------------------------------------
# VBoxManage
# ---------------------------------------------------------------------------
def vboxmanage_path() -> str:
    path = shutil.which("VBoxManage")
    if not path:
        raise VmCheckError(
            "VBoxManage not found in PATH - install VirtualBox or add it to PATH")
    return path


def check_if_vboxmanage_exists() -> str:
    return vboxmanage_path()


def _run(args: list[str], timeout: float = 90) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            [vboxmanage_path(), *args], capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=timeout)
    except OSError as exc:
        raise VmCheckError(f"could not run VBoxManage: {exc}") from exc
    except subprocess.TimeoutExpired as exc:
        raise VmCheckError(
            f"VBoxManage {' '.join(args)} timed out after {timeout:.0f}s") \
            from exc


def _run_checked(args: list[str], timeout: float = 90) -> subprocess.CompletedProcess:
    result = _run(args, timeout=timeout)
    if result.returncode:
        detail = (result.stderr or result.stdout).strip() \
            or f"exit code {result.returncode}"
        raise VmCheckError(f"VBoxManage {' '.join(args)} failed: {detail}")
    return result


def check_vboxmanage_digest() -> tuple[bool, str]:
    """SHA-256 of VBoxManage against the pinned build.  Mismatch = failed
    check, never an abort, so the rest of the report still runs."""
    try:
        path = vboxmanage_path()
    except VmCheckError as exc:
        return False, str(exc)
    try:
        if os.path.getsize(path) == 0:
            return False, f"{path} is empty - reinstall VirtualBox"
    except OSError as exc:
        return False, f"cannot read {path}: {exc}"

    digest = hashlib.sha256()
    try:
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        return False, f"cannot hash {path}: {exc}"
    hexdigest = digest.hexdigest()
    if hexdigest != VBOXMANAGE_SHA256:
        return False, (f"{path} sha256 {hexdigest[:16]}... != pinned "
                       f"{VBOXMANAGE_SHA256[:16]}...")
    return True, f"{path} sha256 matches"


# ---------------------------------------------------------------------------
# VM registry / power state
# ---------------------------------------------------------------------------
def _parse_vm_names(output: str) -> list[str]:
    return [match.group("name") for match in _VM_LINE.finditer(output)]


def list_vms() -> list[str]:
    return _parse_vm_names(_run_checked(["list", "vms"]).stdout)


def list_running_vms() -> list[str]:
    return _parse_vm_names(_run_checked(["list", "runningvms"]).stdout)


def does_qiling_vm_exists(vm_name: str | None = None) -> tuple[bool, str]:
    name = _vm_name(vm_name)
    registered = list_vms()
    if name in registered:
        return True, f"VM '{name}' is registered"
    shown = ", ".join(registered) or "none"
    return False, f"VM '{name}' not registered (have: {shown})"


vm_exists = does_qiling_vm_exists


def is_vm_running(vm_name: str | None = None) -> tuple[bool, str]:
    name = _vm_name(vm_name)
    if name in list_running_vms():
        return True, f"VM '{name}' is running"
    return False, f"VM '{name}' is not running"


def _wait_until(predicate, timeout: float, interval: float = 1.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if predicate():
                return True
        except VmCheckError:
            pass  # transient VBoxManage failure - keep polling
        time.sleep(interval)
    return False


def start_vm(vm_name: str | None = None, headless: bool = True,
             timeout: float = 60) -> tuple[bool, str]:
    name = _vm_name(vm_name)
    if is_vm_running(name)[0]:
        return True, f"VM '{name}' is already running"
    result = _run(["startvm", name, "--type",
                   "headless" if headless else "gui"], timeout=timeout)
    if result.returncode:
        detail = (result.stderr or result.stdout).strip() \
            or f"exit code {result.returncode}"
        if is_vm_running(name)[0]:
            return True, f"VM '{name}' is already running"
        return False, f"could not start '{name}': {detail}"
    if _wait_until(lambda: name in list_running_vms(), min(timeout, 30)):
        return True, f"VM '{name}' started ({'headless' if headless else 'gui'})"
    return False, f"'{name}' start accepted but the VM never showed as running"


def stop_vm(vm_name: str | None = None, timeout: float = 45) -> tuple[bool, str]:
    """Hard poweroff (VBoxManage controlvm poweroff)."""
    name = _vm_name(vm_name)
    if not is_vm_running(name)[0]:
        return True, f"VM '{name}' is already stopped"
    _run_checked(["controlvm", name, "poweroff"], timeout=timeout)
    if _wait_until(lambda: name not in list_running_vms(), min(timeout, 30)):
        return True, f"VM '{name}' powered off"
    return False, f"'{name}' poweroff sent but the VM is still running"


def shutdown_vm(vm_name: str | None = None,
                timeout: float = 90) -> tuple[bool, str]:
    """Graceful shutdown: ACPI power button, wait for the guest to stop."""
    name = _vm_name(vm_name)
    if not is_vm_running(name)[0]:
        return True, f"VM '{name}' is already stopped"
    _run_checked(["controlvm", name, "acpipowerbutton"], timeout=timeout)
    if _wait_until(lambda: name not in list_running_vms(), timeout):
        return True, f"VM '{name}' shut down gracefully"
    return False, (f"'{name}' ignored the ACPI power button after "
                   f"{timeout:.0f}s - use poweroff")


# ---------------------------------------------------------------------------
# Connectivity
# ---------------------------------------------------------------------------
def tcp_reachable(host: str, port: int, timeout: float = 2.0) -> tuple[bool, str]:
    if not host:
        return False, "no VM host configured"
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            pass
    except OSError as exc:
        return False, f"{host}:{port} unreachable ({exc})"
    return True, f"{host}:{port} reachable"


def check_vm_connection(hostname: str, username: str,
                        password: str | None = None, port: int = 22,
                        known_hosts: str | None = None,
                        identity_file: str | None = None,
                        timeout: float = 10) -> tuple[bool, str]:
    """SSH login probe with paramiko (AutoAddPolicy for host keys).

    Unknown server keys are accepted on first use and recorded in
    known_hosts; a key that CHANGED since it was trusted is still rejected.
    """
    try:
        import paramiko
    except ImportError:
        return False, "paramiko is not installed (pip install paramiko)"
    if not username:
        return False, "no SSH username configured"

    client = paramiko.SSHClient()
    try:
        try:
            client.load_system_host_keys()          # ~/.ssh/known_hosts
        except OSError:
            pass
        if known_hosts:
            trusted = pathlib.Path(known_hosts).expanduser()
            if trusted.is_file():
                try:
                    client.load_system_host_keys(str(trusted))
                except OSError:
                    return False, f"cannot read known_hosts file {trusted}"
            else:
                return False, f"known_hosts file missing: {trusted}"
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            hostname, port=int(port), username=username, password=password,
            key_filename=str(pathlib.Path(identity_file).expanduser())
            if identity_file else None,
            timeout=timeout, banner_timeout=timeout, auth_timeout=timeout,
            allow_agent=not password, look_for_keys=not password)
        transport = client.get_transport()
        version = transport.remote_version if transport else "unknown"
        return True, f"{username}@{hostname}:{port} ok ({version})"
    except paramiko.BadHostKeyException as exc:
        return False, f"host key for {hostname} CHANGED - {exc}"
    except paramiko.AuthenticationException:
        return False, f"authentication failed for {username}@{hostname}"
    except (socket.timeout, TimeoutError, OSError) as exc:
        return False, f"{hostname}:{port} unreachable ({exc})"
    except paramiko.SSHException as exc:
        text = str(exc)
        if "known_hosts" in text or "not found" in text:
            return False, (f"no trusted host key for {hostname}; verify it "
                           "out of band and add it to known_hosts")
        return False, f"SSH error: {text}"
    finally:
        client.close()


# ---------------------------------------------------------------------------
# Combined report (used by admin-terminal and the CLI)
# ---------------------------------------------------------------------------
def run_checks(config: dict | None = None, ssh: bool = False) -> list[Check]:
    """Run every check in order; a failing check never stops the report."""
    config = config or {}
    checks: list[Check] = []

    def record(name: str, fn, *args, **kwargs) -> bool:
        try:
            ok, detail = fn(*args, **kwargs)
        except VmCheckError as exc:
            ok, detail = False, str(exc)
        except Exception as exc:  # noqa: BLE001 - a report must not crash
            ok, detail = False, f"{type(exc).__name__}: {exc}"
        checks.append(Check(name, bool(ok), str(detail)))
        return bool(ok)

    record("VBoxManage", lambda: (True, vboxmanage_path()))
    record("digest", check_vboxmanage_digest)
    if record("VM exists", does_qiling_vm_exists):
        record("VM power", is_vm_running)
    else:
        checks.append(Check("VM power", False, "skipped - VM not registered"))

    host, port = _endpoint(config)
    record("VM endpoint", lambda: (bool(host), host or "no host configured"))
    if host:
        record("VM TCP", lambda: tcp_reachable(host, port))

    if ssh:
        username = str(config.get("username", "")).strip()
        identity = str(config.get("identity_file", "") or "").strip()
        known_hosts = str(config.get("known_hosts_file", "") or "").strip()
        if not username or username.upper().startswith("YOUR_"):
            checks.append(Check("SSH", False,
                                "no username set (admin-terminal/vms.json "
                                "or --username)"))
        else:
            record("SSH", lambda: check_vm_connection(
                host, username, port=port,
                known_hosts=known_hosts or None,
                identity_file=identity or None))
    return checks


def should_run_or_not(config: dict | None = None, ssh: bool = False,
                      as_json: bool = False) -> bool:
    """Print the verification report (CLI).  True when every check passed."""
    from colorama import Fore, init

    init()
    checks = run_checks(config, ssh=ssh)
    if as_json:
        print(json.dumps([check._asdict() for check in checks], indent=2))
        return all(check.ok for check in checks)

    print(Fore.CYAN + f"{'#' * 6} QILING Machine Verification {'#' * 6}"
          + Fore.RESET)
    for check in checks:
        colour = Fore.GREEN if check.ok else Fore.RED
        mark = "[+]" if check.ok else "[-]"
        print(f"{colour}{mark} {check.name}: {check.detail}{Fore.RESET}")
    if all(check.ok for check in checks):
        print(Fore.GREEN + "[+] all checks passed" + Fore.RESET)
        return True
    print(Fore.RED + "[-] one or more checks failed" + Fore.RESET)
    return False


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify the Qiling analysis VM (VirtualBox + SSH)")
    parser.add_argument("--ssh", action="store_true",
                        help="also verify the SSH login (paramiko)")
    parser.add_argument("--json", action="store_true",
                        help="print the checks as JSON")
    parser.add_argument("--host", help="override the VM address "
                                       "(default: vm_info.json VM_IP)")
    parser.add_argument("--port", type=int, help="override the SSH port")
    parser.add_argument("--username", help="SSH user for --ssh")
    parser.add_argument("--known-hosts", dest="known_hosts",
                        help="known_hosts file holding the trusted VM key")
    parser.add_argument("--identity", help="SSH private key for --ssh")
    args = parser.parse_args(argv)

    config = {
        "host": args.host or "",
        "port": args.port or 0,
        "username": args.username or "",
        "known_hosts_file": args.known_hosts or "",
        "identity_file": args.identity or "",
    }
    return 0 if should_run_or_not(config, ssh=args.ssh, as_json=args.json) else 1


if __name__ == "__main__":
    sys.exit(main())
