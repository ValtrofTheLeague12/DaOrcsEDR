"""Compile the static analyzer - cmake ucrt64 preset (what build.ps1 runs).

Compile only: build.ps1's default path *also runs the analyzer on itself*
after building (lines 82-85), which a "compile" action must not do, so we
invoke the same two cmake steps directly.  The [list pipelines] option does
go through build.ps1 -ListPipelines (it exits before the self-analysis).

Output streams live to the terminal and is tee'd to
admin-terminal/logs/build_<timestamp>.log.  Ctrl+C kills the compiler tree
cleanly instead of leaving ninja/clang running.
"""
from __future__ import annotations

import os
import shutil
from datetime import datetime

import core

BUILD_PS1 = os.path.join(core.REPO, "build.ps1")
EXE = os.path.join(core.REPO, "build-ucrt", "static_analyzer.exe")
MSYS_BIN = r"C:\msys64\ucrt64\bin"


def _powershell() -> str:
    return shutil.which("powershell") or "powershell"


def _build_env() -> dict:
    """build.ps1's environment: ucrt64 toolchain first, curses off."""
    env = dict(os.environ)
    env["PATH"] = MSYS_BIN + os.pathsep + env.get("PATH", "")
    env["STATIC_ANALYZER_CURSES"] = "0"
    return env


def _exe_info() -> str:
    if not os.path.isfile(EXE):
        return core.paint("not built yet", core.RED)
    st = os.stat(EXE)
    when = datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M")
    return f"{st.st_size / (1024 * 1024):.1f} MB  built {when}"


def _remove_build_dir() -> bool:
    build_dir = os.path.join(core.REPO, "build-ucrt")
    if not os.path.isdir(build_dir):
        return False
    shutil.rmtree(build_dir)
    return True


def _check_toolchain() -> list[str]:
    """Return a list of problems; empty list = good to go."""
    problems = []
    if not shutil.which("cmake"):
        problems.append("cmake not on PATH (expected C:\\Program Files\\CMake)")
    if not os.path.isdir(MSYS_BIN):
        problems.append(MSYS_BIN + " missing (MSYS2 ucrt64 toolchain)")
    return problems


def _cmake_steps(log: str) -> int:
    """configure + build; first non-zero exit wins."""
    for argv in (["cmake", "--preset", "ucrt64"],
                 ["cmake", "--build", "--preset", "ucrt64-release"]):
        print(core.paint(f"\n  > {' '.join(argv)}", core.CYAN))
        code = core.run_stream(argv, core.REPO, log, env=_build_env())
        if code != 0:
            return code
    return 0


def screen() -> None:
    print(core.paint("\n  COMPILE STATIC ANALYZER", core.CYAN, core.BOLD))
    print(f"  binary : {os.path.relpath(EXE, core.REPO)}")
    print(f"  current: {_exe_info()}")

    problems = _check_toolchain()
    if problems:
        for p in problems:
            print(core.paint(f"  ! {p}", core.RED))
        core.pause()
        return

    print()
    print("  [1] compile (incremental, default)")
    print("  [2] compile clean (delete build-ucrt first)")
    print("  [3] compile + list pipelines (build.ps1 -ListPipelines)")
    print(core.paint("  [Enter]=menu", core.DIM))
    choice = core.ask("  choice", "")

    if choice in ("", "q"):
        return
    if choice not in ("1", "2", "3"):
        print(core.paint(f"  ! no such choice '{choice}'", core.RED))
        core.pause()
        return

    if choice == "2":
        if not core.confirm("  delete build-ucrt and rebuild from scratch?",
                            False):
            print(core.paint("  aborted", core.YELLOW))
            core.pause()
            return
        try:
            removed = _remove_build_dir()
        except OSError as exc:
            print(core.paint(f"  ! could not remove build-ucrt: {exc}",
                             core.RED))
            core.pause()
            return
        if removed:
            print(core.paint("  build-ucrt removed", core.YELLOW))

    log = os.path.join(core.ensure_admin_logs(),
                       f"build_{core.timestamp()}.log")
    print(core.paint(f"  log: {os.path.relpath(log, core.REPO)}", core.DIM))

    if choice == "3":
        if not os.path.isfile(BUILD_PS1):
            print(core.paint("  ! build.ps1 not found at repo root", core.RED))
            core.pause()
            return
        argv = [_powershell(), "-NoProfile", "-ExecutionPolicy", "Bypass",
                "-File", BUILD_PS1, "-ListPipelines"]
        print(core.paint(f"\n  > {' '.join(argv)}", core.CYAN))
        started = core.run_stream(argv, core.REPO, log)
    else:
        started = _cmake_steps(log)

    print()
    if started == 0:
        print(core.paint(f"  compile OK - {_exe_info()}", core.GREEN,
                         core.BOLD))
    elif started == 130:
        print(core.paint("  compile interrupted", core.YELLOW))
    else:
        print(core.paint(f"  compile failed (exit {started}) - see log",
                         core.RED, core.BOLD))
    core.pause()


def compile_now(clean: bool = False) -> int:
    """Headless compile (used by callers that want the exit code)."""
    if clean:
        _remove_build_dir()
    log = os.path.join(core.ensure_admin_logs(),
                       f"build_{core.timestamp()}.log")
    return _cmake_steps(log)
