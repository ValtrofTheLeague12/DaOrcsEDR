#!/usr/bin/env python3
"""Build and drive the in-tree EagleVM virtualiser.

EagleVM is a separate checkout under ``EagleVM/`` with its own CMake build. The
panel needs three things from it:

  * a Release build of ``EagleVM.exe`` (the CLI) and ``EagleVMStub.dll`` (the
    marker library the sample links against);
  * an import library MinGW can link, because the sample factory compiles with
    UCRT64 gcc/g++, not MSVC. ``EagleVMStub.dll`` exports undecorated C names,
    so a plain ``dlltool`` import library is enough;
  * a single ``virtualize()`` call that runs the CLI on a compiled sample and
    copies the stub beside the protected binary.

The build is exposed to the Utils page through the generic job runner in
``utils.py``: ``python eagle.py --build`` streams cmake output there.
``--status`` prints the same state the page reads, so the card and the build
button cannot disagree.
"""

from __future__ import annotations

import glob
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

try:
    from . import build, config
except ImportError:
    # Run as a script (``python panel/eagle.py --status``): the package parent
    # is not on sys.path, and build.py only imports relatively.
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from panel import build, config

PRESET = "x64-release"
TARGETS = ("EagleVM", "EagleVMStub", "EagleVMSandbox")

# What the factory needs before it may offer Instruction Virtualisation.
REQUIRED_ARTIFACTS = ("EagleVM.exe", "EagleVMStub.dll")
OTHER_ARTIFACTS = ("EagleVMSandbox.exe", "EagleVMStub.lib")

# The stub header exports these two names. Kept here rather than parsed out of
# the header: a .def with the wrong name fails at link time with a message that
# names the symbol, which is clearer than a regex that silently misses one.
EXPORTS = ("fnEagleVMBegin", "fnEagleVMEnd")


# ---------------------------------------------------------------------------
# Locating the pieces
# ---------------------------------------------------------------------------

def repo() -> Path:
    """The EagleVM checkout, resolved from config.REPO at call time.

    Deliberately not a module constant: the tests monkeypatch config.REPO, and
    a path captured at import time would make them read the real tree.
    """
    return Path(config.REPO) / "EagleVM"


def build_dir() -> Path:
    return repo() / "out" / "build" / PRESET


def _which(name: str) -> str | None:
    for folder in os.environ.get("PATH", "").split(os.pathsep):
        if not folder:
            continue
        cand = Path(folder) / (name + ".exe")
        if cand.is_file():
            return str(cand)
    return None


def _rel(path: Path) -> str:
    try:
        return str(path.relative_to(config.REPO))
    except ValueError:
        return str(path)


def vcvars64() -> str | None:
    """The MSVC environment batch, or None.

    ``IA_VCVARS64`` wins, then ``VCINSTALLDIR`` (set when the panel was started
    from a developer prompt), then the standard install roots. vswhere is not
    used: on the Build Tools install this project targets it reports nothing,
    and a discovery step that silently finds nothing is worse than a glob.
    """
    override = os.environ.get("IA_VCVARS64")
    if override:
        cand = Path(override)
        return str(cand) if cand.is_file() else None

    vc_install = os.environ.get("VCINSTALLDIR")
    if vc_install:
        cand = Path(vc_install) / "Auxiliary" / "Build" / "vcvars64.bat"
        if cand.is_file():
            return str(cand)

    patterns = (
        r"C:\Program Files\Microsoft Visual Studio\*\*\VC\Auxiliary\Build\vcvars64.bat",
        r"C:\Program Files (x86)\Microsoft Visual Studio\*\*\VC\Auxiliary\Build\vcvars64.bat",
    )
    for pattern in patterns:
        hits = sorted(glob.glob(pattern))
        if hits:
            return hits[-1]
    return None


def _artifact(name: str) -> dict:
    path = build_dir() / name
    try:
        st = path.stat()
    except OSError:
        return {"name": name, "exists": False, "path": _rel(path),
                "bytes": None, "modified": None}
    return {"name": name, "exists": True, "path": _rel(path),
            "bytes": st.st_size, "modified": st.st_mtime}


def status() -> dict:
    """Everything the Utils card and the factory gate need, resolved now."""
    root = repo()
    cmake = _which("cmake")
    ninja = _which("ninja")
    vcvars = vcvars64()
    artifacts = {name: _artifact(name) for name in
                 REQUIRED_ARTIFACTS + OTHER_ARTIFACTS}

    missing = [name for name in REQUIRED_ARTIFACTS
               if not artifacts[name]["exists"]]
    toolchain_missing = []
    if not vcvars:
        toolchain_missing.append("vcvars64.bat")
    if not cmake:
        toolchain_missing.append("cmake")
    if not ninja:
        toolchain_missing.append("ninja")

    ready = not missing
    available = root.is_dir() and not toolchain_missing

    if not root.is_dir():
        reason = f"{_rel(root)} was not found"
    elif toolchain_missing:
        reason = "missing from PATH: " + ", ".join(toolchain_missing)
        if "vcvars64.bat" in toolchain_missing:
            reason += (" - set IA_VCVARS64 to the batch file if Visual Studio "
                       "is installed somewhere unusual")
    elif missing:
        reason = ("not built yet: " + ", ".join(missing)
                  + " - build it here before virtualising a sample")
    else:
        reason = None

    return {
        "ok": ready,
        "ready": ready,
        "available": available,
        "repo": _rel(root),
        "repo_exists": root.is_dir(),
        "preset": PRESET,
        "build_dir": _rel(build_dir()),
        "build_dir_exists": build_dir().is_dir(),
        "toolchain": {"vcvars64": vcvars, "cmake": cmake, "ninja": ninja},
        "artifacts": artifacts,
        "missing": missing,
        "reason": reason,
        "note": ("ready to virtualise" if ready
                 else (reason or "not built yet")),
    }


# ---------------------------------------------------------------------------
# The MinGW import library
# ---------------------------------------------------------------------------

def _dlltool() -> str | None:
    ucrt = getattr(build, "UCRT64", None)
    if ucrt:
        cand = Path(ucrt) / "bin" / "dlltool.exe"
        if cand.is_file():
            return str(cand)
    return _which("dlltool")


def _def_text() -> str:
    return "LIBRARY EagleVMStub.dll\nEXPORTS\n" + "".join(
        f"    {name}\n" for name in EXPORTS)


def import_lib() -> Path:
    """Build (or reuse) a MinGW import library for EagleVMStub.dll.

    The DLL is MSVC-built and ships a .lib for MSVC; MinGW cannot consume that.
    ``dlltool`` produces an ``.a`` from the export names, which is all the
    sample needs because the exports are undecorated C symbols.

    Cached under the panel cache and rebuilt whenever the DLL is newer, so a
    rebuilt stub cannot be linked against a stale import table.
    """
    dll = build_dir() / "EagleVMStub.dll"
    if not dll.is_file():
        raise RuntimeError(f"{_rel(dll)} was not built")

    cache = Path(config.panel_cache_dir()) / "eagle"
    cache.mkdir(parents=True, exist_ok=True)
    def_file = cache / "EagleVMStub.def"
    lib = cache / "libEagleVMStub.a"

    if lib.is_file() and lib.stat().st_mtime >= dll.stat().st_mtime:
        return lib

    tool = _dlltool()
    if not tool:
        raise RuntimeError(
            "dlltool was not found - set IA_MSYS2_UCRT64 to the MSYS2 UCRT64 "
            "root, or put its bin/ on PATH")

    def_file.write_text(_def_text(), encoding="utf-8")
    proc = subprocess.run(
        [tool, "-d", str(def_file), "-l", str(lib), "-D", dll.name],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        check=False,
    )
    if proc.returncode != 0 or not lib.is_file():
        detail = (proc.stderr or proc.stdout or "").strip()
        raise RuntimeError(
            "dlltool could not build the import library"
            + (f": {detail}" if detail else ""))
    return lib


def toolchain() -> dict:
    """Paths the sample factory links and runs against, or a clear error."""
    state = status()
    if not state["ready"]:
        raise RuntimeError(state["reason"] or "EagleVM is not built")
    return {
        "exe": build_dir() / "EagleVM.exe",
        "stub_dll": build_dir() / "EagleVMStub.dll",
        "include": repo() / "EagleVM.Stub" / "Headers",
        "lib": import_lib(),
    }


def virtualize(exe: Path, *, cwd: Path | None = None) -> tuple[Path, str]:
    """Run EagleVM on ``exe`` and return ``(<stem>_protected.exe, output)``.

    EagleVM writes its output to the *current working directory*, not beside
    the input, so the caller passes the directory the sample lives in. The stub
    DLL is copied there too: the protected binary imports it at load time and a
    sample that only runs from the build tree is not a sample.
    """
    tc = toolchain()
    work = Path(cwd) if cwd is not None else exe.parent
    proc = subprocess.run(
        [str(tc["exe"]), str(exe)],
        cwd=str(work), capture_output=True, text=True,
        encoding="utf-8", errors="replace", check=False, timeout=600,
    )
    output = ((proc.stdout or "") + (proc.stderr or "")).strip()
    protected = work / f"{exe.stem}_protected.exe"
    if proc.returncode != 0 or not protected.is_file():
        raise RuntimeError(
            f"EagleVM exited {proc.returncode} and wrote no protected binary"
            + (f"\n{output}" if output else ""))
    shutil.copy2(tc["stub_dll"], work / tc["stub_dll"].name)
    return protected, output


# ---------------------------------------------------------------------------
# The build
# ---------------------------------------------------------------------------

def _batch(vcvars: str) -> str:
    root = repo()
    targets = " ".join(TARGETS)
    return (
        "@echo off\r\n"
        "setlocal\r\n"
        f'call "{vcvars}" >nul 2>&1\r\n'
        "if errorlevel 1 (\r\n"
        "  echo [eagle] vcvars64.bat failed\r\n"
        "  exit /b 1\r\n"
        ")\r\n"
        f'cd /d "{root}"\r\n'
        f"echo [eagle] configuring {PRESET}\r\n"
        f"cmake --preset {PRESET}\r\n"
        "if errorlevel 1 exit /b %errorlevel%\r\n"
        f"echo [eagle] building {targets}\r\n"
        f'cmake --build "out\\build\\{PRESET}" --target {targets} --parallel\r\n'
        "exit /b %errorlevel%\r\n"
    )


def build() -> int:
    """Configure and build. Streams output; returns the process exit code."""
    state = status()
    if not state["repo_exists"]:
        print(f"[eagle] {_rel(repo())} was not found", flush=True)
        return 1
    vcvars = state["toolchain"]["vcvars64"]
    if not vcvars:
        print("[eagle] vcvars64.bat was not found - set IA_VCVARS64", flush=True)
        return 1
    if not state["toolchain"]["cmake"]:
        print("[eagle] cmake was not found on PATH", flush=True)
        return 1

    cache = Path(config.panel_cache_dir())
    cache.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix="eagle-build-", suffix=".cmd",
                                dir=str(cache))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as fh:
            fh.write(_batch(vcvars))
        proc = subprocess.Popen(
            ["cmd", "/c", name], stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True, encoding="utf-8",
            errors="replace", bufsize=1,
        )
        for line in proc.stdout:
            print(line.rstrip("\r\n"), flush=True)
        return proc.wait()
    finally:
        try:
            os.unlink(name)
        except OSError:
            pass


def main(argv: list[str]) -> int:
    if "--status" in argv:
        print(json.dumps(status(), indent=2))
        return 0
    if "--build" in argv:
        return build()
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
