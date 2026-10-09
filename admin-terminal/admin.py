#!/usr/bin/env python3
"""Admin terminal - interactive menu for running the whole stack.

    python admin-terminal/admin.py            # menu (default)
    python admin-terminal/admin.py --once     # status snapshot only (exit = # down)
    python admin-terminal/admin.py --interval 2 --only analyzer

Menu:
    1  [*] Check Services Status
    2  [*] Activate Services
    3  [*] Change IP and Port (Analyzer, MalAPI, ML)
    4  [*] Check Connected Agents
    5  [*] Check Analysis VMs (Qiling, CAPEv2)
    6  [*] Compile Static Analyzer
    7  [*] Show Logs
    8  [*] Train Model
    9  [*] Stop Services
    10 [*] Qiling VM Control (status/start/shutdown)
    0  [ ] Exit

Everything this tool writes (start/build/train logs, vms.json) lives in
admin-terminal/.
"""
from __future__ import annotations

import argparse
import math
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import core            # noqa: E402
import status as status_mod  # noqa: E402

MENU: list[tuple[str, str, object]] = [
    ("1", "Check Services Status", "status"),
    ("2", "Activate Services", "activate"),
    ("3", "Change IP and Port (Analyzer, MalAPI, ML)", "netcfg"),
    ("4", "Check Connected Agents", "agents"),
    ("5", "Check Analysis VMs (Qiling, CAPEv2)", "vms"),
    ("6", "Compile Static Analyzer", "builder"),
    ("7", "Show Logs", "logview"),
    ("8", "Train Model", "trainer"),
    ("9", "Stop Services", "stop"),
    ("10", "Qiling VM Control (status/start/shutdown)", "qiling_vm"),
]


def _module(name: str):
    return __import__(name)


def quick_line(only: set[str] | None = None) -> str:
    """One-line up/down dots - probed with a short timeout so the menu
    never feels laggy (closed loopback ports answer with RST, not drop)."""
    svcs = core.services(only)
    for s in svcs:
        s.timeout = 0.8
    core.probe_all(svcs)
    parts = []
    for s in svcs:
        dot = core.paint("●", core.GREEN) if s.up else core.paint("○", core.RED)
        parts.append(f"{dot}{s.name}")
    up = sum(1 for s in svcs if s.up)
    right = core.paint(f"{up}/{len(svcs)} up", core.DIM)
    return "  " + "  ".join(parts) + "   " + right


def banner() -> None:
    width = 56
    title = " STATIC ANALYZER - ADMIN TERMINAL "
    endpoint = core.analyzer_addr()
    print()
    print(core.paint("  ┌" + "─" * width + "┐", core.CYAN))
    print(core.paint("  │ ", core.CYAN)
          + core.paint(title, core.BOLD, core.CYAN)
          + " " * (width - len(title)) + core.paint("│", core.CYAN))
    print(core.paint("  │ ", core.CYAN)
          + f"  endpoint {endpoint}".ljust(width)
          + core.paint("│", core.CYAN))
    print(core.paint("  │ ", core.CYAN)
          + f"  repo    {os.path.basename(core.REPO)}".ljust(width)
          + core.paint("│", core.CYAN))
    print(core.paint("  └" + "─" * width + "┘", core.CYAN))


def menu(only: set[str] | None = None, interval: float = 5.0) -> int:
    while True:
        core.clear()
        banner()
        try:
            print(quick_line(only))
        except Exception as exc:  # noqa: BLE001 - summary is best-effort
            print(core.paint(f"  ! status summary unavailable: {exc}",
                             core.YELLOW))
        print()
        for key, label, _mod in MENU:
            print(f"   {key:<2} {core.paint('[*]', core.GREEN)} {label}")
        print(f"   {'0':<2} {core.paint('[ ]', core.DIM)} Exit")
        print()

        try:
            choice = core.ask("  choice", "0").lower()
        except KeyboardInterrupt:
            print()
            return 0

        if choice in ("0", "q", "quit", "exit", "b"):
            return 0
        if choice not in [k for k, _, _ in MENU]:
            print(core.paint(f"  ! no such choice '{choice}'", core.RED))
            core.pause()
            continue

        label = next(lbl for k, lbl, _ in MENU if k == choice)
        mod_name = next(m for k, _, m in MENU if k == choice)
        try:
            mod = _module(mod_name)
            if mod_name == "status":
                mod.screen(only=only, interval=interval)
            elif mod_name == "activate":
                mod.screen(only=only)
            else:
                mod.screen()
        except KeyboardInterrupt:
            print(core.paint(f"\n  ! {label} interrupted", core.YELLOW))
            core.pause()
        except ImportError as exc:
            print(core.paint(f"  ! cannot load {mod_name}: {exc}", core.RED))
            core.pause()
        except EOFError:
            return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Admin terminal - services, activation, build, logs")

    def positive_interval(value: str) -> float:
        try:
            seconds = float(value)
        except ValueError as exc:
            raise argparse.ArgumentTypeError("must be a number greater than 0") from exc
        if not math.isfinite(seconds) or seconds <= 0:
            raise argparse.ArgumentTypeError("must be a number greater than 0")
        return seconds

    p.add_argument("--once", action="store_true",
                   help="print one status snapshot and exit "
                        "(exit code = number of services down)")
    p.add_argument("--interval", type=positive_interval, default=5.0,
                   help="status-screen auto refresh seconds (default 5)")
    p.add_argument("--only", metavar="KEY",
                   help="comma separated subset for --once/status, "
                        "e.g. --only analyzer,malapi")
    args = p.parse_args(argv)

    only: set[str] | None = None
    if args.only is not None:
        only = {n.strip() for n in args.only.split(",") if n.strip()}
        if not only:
            print("--only requires at least one service key")
            return 2
        known = {s.key for s in core.services()}
        unknown = only - known
        if unknown:
            print(f"no service matches {', '.join(sorted(unknown))}; known: "
                  f"{', '.join(sorted(known))}")
            return 2

    if args.once:
        return status_mod.once(only)

    try:
        return menu(only=only, interval=args.interval)
    except KeyboardInterrupt:
        print()
        return 0


if __name__ == "__main__":
    sys.exit(main())
