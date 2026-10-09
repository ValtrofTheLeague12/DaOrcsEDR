"""Qiling VM Control - verify, start, and stop the Qiling analysis VM.

Every check and power action delegates to qiling_dlls/_check_vm_connection.py,
the same functions the standalone script uses, so the menu and the CLI can
never disagree.  VM identity (name, IP, SSH port) comes from
qiling_dlls/vm_info.json; SSH trust settings come from
admin-terminal/vms.json.

    [s] start (headless)   [g] graceful shutdown (ACPI power button)
    [p] power off (hard)   [c] check SSH login (paramiko, strict host keys)
"""
from __future__ import annotations

import core
import vms


def _call(fn, *args, **kwargs):
    """Run a VM check function; any failure becomes (False, detail)."""
    try:
        return fn(*args, **kwargs)
    except Exception as exc:  # noqa: BLE001 - menu screens must not crash
        return False, str(exc) or type(exc).__name__


def _config() -> dict:
    try:
        return dict(vms.load_vms().get("qiling")
                    or vms.DEFAULT_VMS["qiling"])
    except Exception:  # noqa: BLE001
        return dict(vms.DEFAULT_VMS["qiling"])


def _info(mod) -> dict:
    info = _call(mod.load_vm_info)
    return info if isinstance(info, dict) else {}


def _ssh_trust(config: dict) -> tuple[bool, str]:
    path = core.known_hosts_path(config.get("known_hosts_file", ""))
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            ready = any(line.strip() and not line.lstrip().startswith("#")
                        for line in fh)
    except OSError:
        return False, f"no known_hosts at {path}"
    return ready, ("trusted host key configured" if ready
                   else f"{path} contains no host keys")


def _row(label: str, target: str, status: str, colour: str,
         detail: str) -> list[tuple[str, tuple[str, ...]]]:
    return [(label, (core.BOLD,)), (target, ()),
            (status, (core.BOLD, colour)),
            (detail, () if colour == core.GREEN else (colour,))]


def _rows(mod, config: dict) -> list[list[tuple[str, tuple[str, ...]]]]:
    info = _info(mod)
    rows: list[list[tuple[str, tuple[str, ...]]]] = []

    digest_ok, digest_detail = _call(mod.check_vboxmanage_digest)
    rows.append(_row("VirtualBox", "VBoxManage", " OK " if digest_ok else "FAIL",
                     core.GREEN if digest_ok else core.RED, digest_detail))

    exists, exists_detail = _call(mod.does_qiling_vm_exists)
    running, running_detail = _call(mod.is_vm_running)
    name = info.get("VM_NAME", "?")
    if not exists:
        rows.append(_row("Qiling VM", name, "MISS", core.RED, exists_detail))
    elif running:
        rows.append(_row("Qiling VM", name, "RUN ", core.GREEN,
                         running_detail))
    else:
        rows.append(_row("Qiling VM", name, "STOP", core.YELLOW,
                         running_detail))

    host, port = info.get("VM_IP", config.get("host", "")), \
        info.get("PORT", config.get("port", 22))
    tcp_ok, tcp_detail = _call(mod.tcp_reachable, host, port)
    rows.append(_row("Reachability", f"{host}:{port}",
                     " UP " if tcp_ok else "DOWN",
                     core.GREEN if tcp_ok else core.RED, tcp_detail))

    trust_ok, trust_detail = _ssh_trust(config)
    rows.append(_row("SSH trust", config.get("username", ""),
                     "READY" if trust_ok else "NO KEY",
                     core.GREEN if trust_ok else core.YELLOW, trust_detail))
    return rows


def _start(mod) -> None:
    print(core.paint("  starting the Qiling VM (headless)...", core.CYAN))
    ok, detail = _call(mod.start_vm)
    print(core.paint(f"  {'[+]' if ok else '[-]'} {detail}",
                     core.GREEN if ok else core.RED))
    core.pause()


def _shutdown(mod) -> None:
    name = _info(mod).get("VM_NAME", "?")
    if not core.confirm(
            f"  send the ACPI power button to '{name}'? the guest may take "
            "up to a minute to stop", False):
        print(core.paint("  aborted - VM untouched", core.YELLOW))
        core.pause()
        return
    print(core.paint("  waiting for the guest to stop (up to 90s)...",
                     core.CYAN))
    ok, detail = _call(mod.shutdown_vm)
    print(core.paint(f"  {'[+]' if ok else '[-]'} {detail}",
                     core.GREEN if ok else core.RED))
    core.pause()


def _poweroff(mod) -> None:
    name = _info(mod).get("VM_NAME", "?")
    if not core.confirm(
            f"  HARD power off '{name}'? unsaved guest work is lost", False):
        print(core.paint("  aborted - VM untouched", core.YELLOW))
        core.pause()
        return
    ok, detail = _call(mod.stop_vm)
    print(core.paint(f"  {'[+]' if ok else '[-]'} {detail}",
                     core.GREEN if ok else core.RED))
    core.pause()


def _ssh_check(mod, config: dict) -> None:
    info = _info(mod)
    host = info.get("VM_IP") or config.get("host", "")
    port = info.get("PORT") or config.get("port", 22)
    username = str(config.get("username", "")).strip()
    if not username or username.upper().startswith("YOUR_"):
        print(core.paint("  ! set the SSH username first (key [u] on the "
                         "Analysis VMs screen)", core.RED))
        core.pause()
        return
    print(core.paint(f"  checking SSH {username}@{host}:{port} ...", core.CYAN))
    ok, detail = _call(mod.check_vm_connection, host, username, port=port,
                       known_hosts=config.get("known_hosts_file") or None,
                       identity_file=config.get("identity_file") or None)
    print(core.paint(f"  {'[+]' if ok else '[-]'} {detail}",
                     core.GREEN if ok else core.RED))
    core.pause()


def screen() -> None:
    while True:
        core.clear()
        print(core.paint("\n  QILING VM CONTROL", core.CYAN, core.BOLD))
        try:
            mod = vms.vm_check()
        except Exception as exc:  # noqa: BLE001
            print(core.paint(f"  ! {exc}", core.RED))
            core.pause()
            return
        config = _config()
        print(core.table("QILING VM CONTROL", "checked now",
                         (14, 20, 8, 46),
                         ("CHECK", "TARGET", "STATUS", "DETAIL"),
                         _rows(mod, config)))
        print(core.paint("  [s]tart   [g]raceful shutdown   [p]ower off   "
                         "[c]heck SSH   [Enter]=menu", core.DIM))
        try:
            choice = core.ask("  choice", "").lower().strip()
        except EOFError:
            return
        if choice in ("", "b", "q", "\x1b"):
            return
        if choice == "s":
            _start(mod)
        elif choice == "g":
            _shutdown(mod)
        elif choice == "p":
            _poweroff(mod)
        elif choice == "c":
            _ssh_check(mod, config)
        else:
            print(core.paint(f"  ! no such choice '{choice}'", core.RED))
            core.pause()


if __name__ == "__main__":
    screen()
