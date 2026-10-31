"""Build the analyzer: dependency report, one-at-a-time builds, live log.

This is the panel's view of the C++ toolchain, and it exists because the two
things that go wrong when a build breaks are both invisible from a web page.
The first is a missing dependency, which CMake reports as a configure failure
buried in a wall of output; the second is a half-finished build, which looks
identical to a good one until you try to run the result.

So dependencies are reported BEFORE anything is built, by reading what
CMakeLists.txt actually asks for rather than a list maintained here. A hardcoded
list drifts the moment someone adds a find_package(), and then the panel
certifies a build that cannot configure - worse than having no check at all.

The build itself runs `build.ps1`, not a reimplementation of it. That file is
what the operator runs by hand; the panel running its own cmake invocation would
produce a binary that differs from the terminal one for reasons nobody would
find until a crash, and "the panel builds what I build" is worth more here than
tidiness.

Building is CPU-heavy and writes into the repository tree, so exactly one may run
at a time and the running one is visible rather than queued behind a spinner.

Two dependency reports, because they answer different questions and a build is
only half of what can go wrong:

  * the toolchain - can this project COMPILE. Read from CMakeLists.txt.
  * the analysis stack - MalAPI, capa, the rule packs, the ML scorer and the
    rest of what the analyzer shells out to. This is the list that decides
    whether an analysis produces results or silently skips half its phases, and
    nothing in CMake describes it.

The stack list is read from generate_sbom.py, which is already the project's own
manifest of vendored checkouts and Python subsystems, rather than typed out here
for the same reason CMakeLists.txt is parsed.
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

from ..core import config

# ---------------------------------------------------------------------------
# layout
# ---------------------------------------------------------------------------

CMAKELISTS = config.REPO / "CMakeLists.txt"
PRESETS = config.REPO / "CMakePresets.json"
BUILD_SCRIPT = config.REPO / "build.ps1"

# MSYS2 UCRT64. Hardcoded because CMakePresets.json hardcodes it too - the
# preset points CMAKE_CXX_COMPILER straight at C:/msys64/ucrt64/bin/g++, so a
# sysroot anywhere else would not be the one being compiled against.
UCRT64 = Path(os.environ.get("IA_MSYS2_UCRT64", r"C:\msys64\ucrt64"))

# Where build.ps1 leaves the analyzer, and where the other executables land.
ANALYZER = "static_analyzer.exe"

# Log lines kept per job. A full C++ compile of this project runs to tens of
# thousands; keeping them all would grow a status panel's memory with every build
# and nobody scrolls past the first few thousand.
MAX_LOG_LINES = 4000

# Finished jobs are kept this long so a reload still shows the result.
JOB_TTL = 3600.0

# ---------------------------------------------------------------------------
# dependency discovery
# ---------------------------------------------------------------------------

# What to look for, per kind of declaration, and how MSYS2 names the artefact.
#
# `lib<name>.a` is the MSYS2/MinGW convention and is the whole reason a naive
# check reports capstone, crypto, magic and yara as missing when they are
# sitting right there in ucrt64/lib.
_LIB_PREFIXES = ("lib", "")

# CMake ships a Find module for these, so they resolve by searching the sysroot
# and do NOT need a config package. Treating their absent config dir as "missing"
# would be a false alarm.
_FIND_MODULES = {"Curses", "PkgConfig", "Threads", "ZLIB", "BZip2", "LibLZMA"}

# Find modules that resolve by looking for a PROGRAM on PATH rather than a
# library in the sysroot. "Git" is here because CMakeLists.txt asks for it
# quietly (`find_package(Git QUIET)`), and judging it by the presence of a
# config directory would report a missing Git on any machine that has one.
_PATH_FIND_MODULES = {"Git": "git"}

_TOOLS = [
    ("cmake", "Build system. Required by both presets."),
    ("g++", "C++ compiler. The ucrt64 preset pins it to MSYS2's g++."),
    ("make", "MinGW Makefiles generator - the preset's generator."),
    ("pkg-config", "Needed by pkg_check_modules(re2)."),
    ("powershell", "Runs build.ps1."),
]


def _which(name: str) -> str | None:
    # shutil.which resolves against the live PATH. On Windows it also honours
    # PATHEXT, so "cmake" finds cmake.exe without the suffix.
    import shutil

    return shutil.which(name)


def _lib_files(names: list[str]) -> str | None:
    """First existing static/import library for any of `names`, MSYS2 style."""
    libdir = UCRT64 / "lib"
    for name in names:
        for prefix in _LIB_PREFIXES:
            for suffix in (".a", ".dll.a", ".lib"):
                cand = libdir / f"{prefix}{name}{suffix}"
                if cand.is_file():
                    return str(cand)
    return None


def _header(rel: str) -> str | None:
    tail = rel.replace("/", os.sep)
    # Sysroot first, then the declared HINTS directories, because that is the
    # order CMake searches and it makes the reported path the one the build
    # would actually use.
    for root in [UCRT64 / "include", *_hint_dirs()]:
        cand = root / tail
        if cand.is_file():
            return str(cand)
    return None


def _raw_file(name: str) -> str | None:
    """A literal filename declared by find_file, searched in the sysroot.

    CMakeLists.txt declares these as `find_file(CAPSTONE_STATIC_LIBRARY
    libcapstone.a HINTS "C:/msys64/ucrt64/lib" REQUIRED)` on Windows, so the
    name already carries the `lib` prefix and the extension. Searching for
    `lib<name>.a` on a name that is already `libcapstone.a` would produce
    `liblibcapstone.a`, which is why this exists separately from _lib_files.
    """
    for root in (UCRT64 / "lib", UCRT64 / "include", UCRT64 / "bin"):
        cand = root / name
        if cand.is_file():
            return str(cand)
    return None


def _pkgconfig(module: str) -> str | None:
    cand = UCRT64 / "lib" / "pkgconfig" / f"{module}.pc"
    return str(cand) if cand.is_file() else None


def _cmake_config(pkg: str) -> str | None:
    for root in (UCRT64 / "lib" / "cmake", UCRT64 / "share" / "cmake3"):
        cand = root / pkg
        if cand.is_dir():
            return str(cand)
    return None


def _in_tree_dir(name: str) -> str | None:
    """A vendored subdirectory, which is how spdlog is provided on Windows."""
    cand = config.REPO / name
    return str(cand) if (cand / "CMakeLists.txt").is_file() else None


def _parse_cmakelists() -> dict:
    """Every dependency CMakeLists.txt declares.

    Two things this has to get right, or it certifies a build that cannot
    configure:

    Dashes are part of the name. `find_package(yaml-cpp)` truncated to `yaml`
    when the character class was `\\w`, and then reported a package nobody asked
    about as missing.

    The WIN32 branch wins on Windows. CMakeLists.txt guards several lookups with
    `if(WIN32) ... else() ... endif()` - spdlog is vendored with
    add_subdirectory on Windows and only find_package'd elsewhere; tlsh.h is the
    required header on Windows while tlsh/tlsh.h is the fallback elsewhere.
    Reading the whole file reports else-branch entries as missing on a host that
    never uses them, which is a false alarm wearing the same clothes as a real
    one.
    """
    try:
        src = CMAKELISTS.read_text(encoding="utf-8")
    except OSError:
        return {}

    # CMakeLists.txt guards some lookups with if(WIN32) ... else() ... endif().
    # The merge that matches what CMake does here is:
    #
    #     (everything  -  the else-branch)  +  the WIN32 branch
    #
    # Anything outside both branches is unguarded and has to be kept - LIEF,
    # yaml-cpp, capstone and yara sit in no if(), and dropping them would report
    # a clean machine as missing four dependencies. But where BOTH branches
    # declare the same thing, the WIN32 spelling is the one that runs: tlsh.h
    # rather than tlsh/tlsh.h, a vendored spdlog rather than find_package.
    win = "\n".join(re.findall(r"if\s*\(\s*WIN32\s*\)(.*?)(?:else\s*\(\s*\)|endif)",
                               src, flags=re.S))
    # Tempered, not plain `.*?`: a non-greedy `.*?else\(\)` still spans across an
    # intervening `endif()`, so the first if(WIN32) block would swallow every
    # later block's else-branch. That silently emptied the libraries list -
    # capstone, crypto, magic and yara all live in one if(WIN32) block and
    # vanished from the report. `(?:(?!endif).)*?` cannot cross a block end.
    els = "\n".join(re.findall(
        r"if\s*\(\s*WIN32\s*\)(?:(?!endif).)*?else\s*\(\s*\)(.*?)\s*endif",
        src, flags=re.S))

    patterns = {
        "packages": r"find_package\(\s*([A-Za-z0-9_-]+)",
        # The WIN32 branch uses find_file with the literal archive name
        # (find_file(CAPSTONE_STATIC_LIBRARY libcapstone.a ...)), and the
        # else() branch uses find_library NAMES. Both are declared dependencies;
        # reading only find_library reported capstone, yara, crypto and magic as
        # absent from a machine that has all four sitting in ucrt64/lib.
        "files": r"find_file\(\s*\w+\s+([A-Za-z0-9_.+-]+)",
        "headers": r"find_path\(\s*\w+\s+([A-Za-z0-9_./-]+)",
        "pkg_modules": (r"pkg_check_modules\(\s*\w+\s+(?:REQUIRED\s+)?"
                        r"(?:[A-Za-z0-9_]+\s+)*([A-Za-z0-9_.-]+)"),
        "subdirs": (r"add_subdirectory\(\s*\"?\$\{CMAKE_SOURCE_DIR\}/?([A-Za-z0-9_.-]+)"),
    }
    multi_pattern = r"find_library\(\s*\w+\s+NAMES\s+([A-Za-z0-9_\s]+?)\s*(?:REQUIRED)?\s*\)"

    def names(pattern: str, text: str) -> set[str]:
        found = re.findall(pattern, text)
        if pattern == multi_pattern:
            return {n for group in found for n in group.split()}
        return set(found)

    out: dict = {}
    for kind, pattern in patterns.items():
        everything = names(pattern, src)
        superseded = names(pattern, els)
        chosen = names(pattern, win)
        out[kind] = sorted((everything - superseded) | chosen)

    # find_library survives in the WIN32 branch for pdcurses and tlsh; take the
    # unguarded ones plus whatever the branch kept, same supersede rule.
    out["libraries"] = sorted(
        (names(multi_pattern, src) - names(multi_pattern, els))
        | names(multi_pattern, win))

    # The bare add_subdirectory(spdlog) form carries the vendored copy the
    # WIN32 branch depends on, and names no path for the pattern above.
    bare = re.findall(r"add_subdirectory\(\s*([A-Za-z0-9_.-]+)\s*\)", win or src)
    out["subdirs"] = sorted(set(out["subdirs"]) | set(bare))

    # REQUIRED decides whether a miss is a warning or a stopped build. Read from
    # the whole file: a header REQUIRED in either branch is one this build
    # expects to find on at least one platform.
    out["required_paths"] = set(
        re.findall(r"find_path\(\s*\w+\s+([A-Za-z0-9_./-]+)[^)]*?\bREQUIRED\b",
                   src, flags=re.S))
    out["required_libs"] = set(
        n for group in re.findall(r"find_library\(\s*\w+\s+NAMES\s+([^)]*?)\bREQUIRED\b",
                                  src, flags=re.S)
        for n in group.split())
    # Same for find_package. Read as "REQUIRED and not OPTIONAL_COMPONENTS"-free
    # to avoid matching REQUIRED inside an extra's argument list; the alternative
    # is a lookbehind that reads worse than it saves.
    #
    # Without this, `find_package(Git QUIET)` is treated as required and an
    # absent git disables the Build button over something CMake would have
    # shrugged at - a report that cries wolf is worse than no report.
    out["required_packages"] = {
        name for name in re.findall(r"find_package\(\s*([A-Za-z0-9_-]+)", src)
        if re.search(r"find_package\(\s*" + re.escape(name) + r"\b[^)]*?\bREQUIRED\b",
                     src, flags=re.S)
    }
    out["optional_packages"] = set(out["packages"]) - out["required_packages"]
    out["win32_branch"] = bool(win.strip())
    return out


def _hint_dirs() -> list[Path]:
    """Every directory CMakeLists.txt names in a HINTS/PATHS argument.

    Read from the file rather than hardcoded because at least one dependency
    (graphviz/cgraph.h) does not live in the MSYS2 sysroot at all - it is found
    under C:/Program Files/Graphviz. Resolving only against UCRT64 reported it
    missing on a machine where the build itself reports it enabled, which is
    worse than reporting nothing: it trains the reader to ignore the red.

    Scoped to find_path/find_library/find_file arguments so a stray quoted
    string elsewhere in the file cannot be mistaken for a search root.
    """
    out: list[Path] = []
    try:
        text = CMAKELISTS.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return out
    for match in re.finditer(
            r"(find_path|find_library|find_file)\s*\(.*?(?:HINTS|PATHS)\s+(.*?)\)",
            text, re.S):
        for raw in re.findall(r'"([^"]+)"', match.group(2)):
            p = Path(raw)
            # Deduplicated but order-preserving: the sysroot appears in nearly
            # every declaration, and search order decides which path gets
            # reported when a header exists in two trees.
            if p.is_dir() and p not in out:
                out.append(p)
    return out


def dependencies() -> dict:
    """Check every declared dependency. Never raises.

    Mirrors CMake's own search rather than guessing: REQUIRED declarations make
    a missing entry a hard configure failure, so each one is reported with the
    exact artefact that satisfied it (or nothing) and whether it is REQUIRED.
    `required` matters because a missing optional header is a warning in a build
    and a missing REQUIRED library is the build stopping.
    """
    declared = _parse_cmakelists()
    if not declared:
        return {"available": False, "reason": f"{CMAKELISTS.name} not readable",
                "tools": [], "dependencies": [], "missing_required": 0}

    tools = []
    for name, why in _TOOLS:
        found = _which(name)
        tools.append({"name": name, "found": bool(found), "path": found,
                      "why": why})

    deps: list[dict] = []

    for pkg in declared["packages"]:
        # Curses/PkgConfig/Threads/ZLIB/BZip2/LibLZMA are CMake's own Find
        # modules: they search the sysroot rather than needing a config package,
        # so "no config dir" says nothing about whether they will resolve.
        # Git is one too - FindGit looks for the git executable on PATH.
        builtin = pkg in _FIND_MODULES
        hit = None
        note = "CONFIG package"
        if builtin:
            hit = str(UCRT64 / "lib") if UCRT64.is_dir() else None
            note = "CMake Find module (sysroot search)"
        elif pkg in _PATH_FIND_MODULES:
            # FindGit and friends resolve by running a program, so the honest
            # check is whether that program is on PATH.
            hit = _which(_PATH_FIND_MODULES[pkg])
            note = f"CMake Find{pkg} (on PATH)"
        else:
            # A vendored copy satisfies a find_package on the WIN32 branch:
            # add_subdirectory(spdlog) builds it in-tree with no package at all.
            vendored = _in_tree_dir(pkg)
            if vendored:
                hit, note = vendored, "vendored (add_subdirectory)"
            else:
                hit = _cmake_config(pkg) or _cmake_config(pkg.lower())
        deps.append({
            "name": pkg, "kind": "package",
            "required": pkg not in declared.get("optional_packages", set()),
            "found": bool(hit), "path": hit, "note": note,
        })

    for mod in declared["pkg_modules"]:
        hit = _pkgconfig(mod)
        deps.append({"name": mod, "kind": "pkg-config", "required": True,
                     "found": bool(hit), "path": hit,
                     "note": "pkg_check_modules"})

    for fname in declared.get("files", []):
        hit = _header(fname) or _raw_file(fname)
        deps.append({"name": fname, "kind": "archive", "required": True,
                     "found": bool(hit), "path": hit, "note": "find_file REQUIRED"})

    for lib in declared["libraries"]:
        hit = _lib_files([lib])
        deps.append({"name": lib, "kind": "library", "required": True,
                     "found": bool(hit), "path": hit, "note": "find_library REQUIRED"})

    for hdr in declared["headers"]:
        hit = _header(hdr)
        note = "find_path"
        if hit and UCRT64 / "include" / hdr.replace("/", os.sep) != Path(hit):
            # Satisfied from a HINTS directory rather than the sysroot. Worth
            # saying: it is the difference between "the build will work" and
            # "the build will work because of something in Program Files".
            note = "find_path (HINTS)"
        deps.append({"name": hdr, "kind": "header",
                     "required": hdr in declared.get("required_paths", set()),
                     "found": bool(hit), "path": hit, "note": note})

    for sub in declared["subdirs"]:
        hit = _in_tree_dir(sub)
        deps.append({"name": sub, "kind": "vendored", "required": bool(hit is None),
                     "found": bool(hit), "path": hit,
                     "note": "add_subdirectory"})

    missing_required = sum(1 for d in deps if d["required"] and not d["found"])

    return {
        "available": True,
        "reason": None,
        "sysroot": str(UCRT64),
        "sysroot_found": UCRT64.is_dir(),
        "tools": tools,
        "dependencies": deps,
        "missing_required": missing_required,
        "counts": {
            "total": len(deps),
            "found": sum(1 for d in deps if d["found"]),
            "missing": sum(1 for d in deps if not d["found"]),
        },
    }


# ---------------------------------------------------------------------------
# Analysis stack
# ---------------------------------------------------------------------------
#
# Everything the analyzer shells out to or reads at analysis time. CMake knows
# none of it: a build can succeed perfectly while capa.exe is missing and every
# analysis silently comes back without a capa section.

_MANIFEST = config.REPO / "generate_sbom.py"
_manifest_cache: dict | None = None


def _manifest() -> dict | None:
    """generate_sbom.py's SUBSYSTEMS / VENDORED / ENVIRONMENTS, or None.

    Loaded rather than retyped. It is already the project's own inventory of
    vendored checkouts and Python subsystems, and a second hand-written copy
    would be a list that silently rots the first time someone adds a rule pack.

    Importing a top-level script is a little unusual, so the failure is
    contained: any error degrades to "manifest unavailable" and the report still
    renders from the explicit checks below, which do not depend on it.
    """
    global _manifest_cache
    if _manifest_cache is not None:
        return _manifest_cache or None
    try:
        spec = importlib.util.spec_from_file_location("_iaproj_manifest", _MANIFEST)
        if spec is None or spec.loader is None:
            _manifest_cache = {}
            return None
        mod = importlib.util.module_from_spec(spec)
        # dataclasses resolves annotations through sys.modules[cls.__module__],
        # so the module has to be registered before it runs or every
        # @dataclass in it raises AttributeError on None.__dict__. Registering
        # under a private name keeps it out of the panel's own namespace.
        sys.modules[spec.name] = mod
        try:
            spec.loader.exec_module(mod)
        except Exception:
            sys.modules.pop(spec.name, None)
            raise
        _manifest_cache = {
            "subsystems": list(getattr(mod, "SUBSYSTEMS", ())),
            "vendored": list(getattr(mod, "VENDORED", ())),
            "environments": dict(getattr(mod, "ENVIRONMENTS", {})),
        }
    except Exception:
        _manifest_cache = {}
        return None
    return _manifest_cache


# Programs and data that must already be unpacked on disk. Not in the manifest
# because they are neither Python requirements nor git checkouts - they are
# release artefacts someone downloaded.
_STACK_PATHS = (
    ("capa", "capa-exec/capa.exe", "program", True,
     "rule engine the analyzer runs on the unpacked sample"),
    ("capa rules", "capa-rules/", "rules", True, "rule pack capa loads"),
    ("capa signatures", "capa-sigs/", "rules", False, "extracted capa signatures"),
    ("yara rules", "yara-rules/", "rules", True, "YARA rule pack"),
    ("malapi (source)", "python/malapi/", "source", True,
     "Windows API lookup server source"),
    ("ml scorer", "ml/", "source", True, "EMBER2024 LightGBM classifier"),
    ("qiling", "python/qiling/", "source", True, "emulation harness"),
    ("qiling dlls", "qiling_dlls/", "data", False, "Windows DLLs for emulation"),
    ("clamav tooling", "python/clamd/", "source", False, "guest-side scanner client"),
    ("kafka agent", "kafka-agent/", "source", False, "sample ingest watcher"),
    ("mitre", "mitre/", "source", False, "ATT&CK technique mapping"),
    ("car analytics", "mittre_car/", "source", False, "MITRE CAR scripts"),
)


def _probe_http(base: str, path: str, timeout: float = 1.5) -> tuple[bool, str]:
    """True when the service answers. Returns (ok, detail).

    config.*_base() yields "host:port", not a URL, so the scheme is added here
    rather than trusting the caller to remember - urlopen's error for a
    schemeless string is "unknown url type", which says nothing about whether
    the service is up.
    """
    base = base.rstrip("/")
    if "://" not in base:
        base = f"http://{base}"
    url = f"{base}{path}"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return True, f"HTTP {resp.status}"
    except urllib.error.HTTPError as exc:
        # Any HTTP status means something is listening and speaking HTTP, which
        # is the question. A 404 on the probe path is not an absent service.
        return True, f"HTTP {exc.code}"
    except urllib.error.URLError as exc:
        return False, _why(exc.reason)
    except Exception as exc:  # timeout, refused, malformed URL
        return False, _why(exc)


def _probe_tcp(host: str, port: int, timeout: float = 1.5) -> tuple[bool, str]:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, f"tcp {host}:{port} open"
    except Exception as exc:
        return False, _why(exc)


def _why(exc: object) -> str:
    """Compact failure reason, for a row's tooltip."""
    reason = getattr(exc, "reason", None) or str(exc) or exc.__class__.__name__
    text = str(reason)
    if "refused" in text.lower():
        return "not running (connection refused)"
    if "timed out" in text.lower():
        return "not answering (timed out)"
    return text


def stack_dependencies() -> dict:
    """Check the analysis stack: MalAPI, capa, rule packs, ML, and the rest.

    Two kinds of question, kept separate because the fixes differ:

      * on-disk - is the file or directory there. Cheap, and the answer changes
        when someone unpacks a release.
      * reachable - is the service answering. A MalAPI tree can be present and
        the server still down, and that reads as "the lookup phase silently
        returns nothing", not as an error.

    Missing REQUIRED entries block the build button only for the toolchain
    report; a missing analysis dependency does not stop a compile, so it is
    reported without gating anything.
    """
    deps: list[dict] = []

    for name, rel, kind, required, why in _STACK_PATHS:
        target = config.REPO / rel
        # A trailing slash means a directory, and a directory that exists but is
        # empty is as useless as an absent one - capa-rules/ with no rules in it
        # produces analyses with no capa output and no error.
        if rel.endswith("/"):
            hit = target.is_dir() and any(target.iterdir())
            found = hit
            note = why if found else f"{why} (empty or absent)"
        else:
            found = target.is_file()
            note = why
        deps.append({"name": name, "kind": kind, "required": required,
                     "found": found, "path": str(target) if found else None,
                     "note": note})

    # The vendored checkouts, from the manifest.
    man = _manifest()
    if man:
        for name, rel, url in man["vendored"]:
            target = config.REPO / rel
            found = target.is_dir()
            deps.append({"name": name, "kind": "vendored", "required": found is False,
                         "found": found, "path": str(target) if found else None,
                         "note": url})
        # Python environments. A subsystem's packages are installed into its own
        # environment, so a missing one means its requirements are not installed
        # anywhere the subsystem will look.
        for key, rel in man["environments"].items():
            target = config.REPO / rel
            if key == "root":
                continue
            found = target.is_dir()
            deps.append({"name": f"venv: {key}", "kind": "venv", "required": False,
                         "found": found, "path": str(target) if found else None,
                         "note": f"python environment for {key}"})
    else:
        deps.append({"name": "generate_sbom.py", "kind": "manifest",
                     "required": False, "found": False, "path": None,
                     "note": f"not importable from {_MANIFEST.name}; "
                             f"vendored checkouts not verified"})

    # Reachable services. Probed, not read from disk, because "installed" and
    # "running" are different failures with different fixes.
    #
    # Probed concurrently. Each probe blocks for its full timeout when the
    # service is down - and on Windows a closed loopback port times out rather
    # than refusing - so two sequential probes would put ~3s on every dashboard
    # poll. Run together it is one timeout.
    malapi_base = config.malapi_base()
    ml_base = config.ml_base()

    def _probe_malapi() -> tuple[bool, str]:
        return _probe_http(malapi_base, "/malapi/AdjustTokenPrivileges/")

    def _probe_ml() -> tuple[bool, str]:
        return _probe_http(ml_base, "/health")

    with ThreadPoolExecutor(max_workers=2) as pool:
        malapi_future = pool.submit(_probe_malapi)
        ml_future = pool.submit(_probe_ml)
        malapi_ok, malapi_detail = malapi_future.result()
        ml_ok, ml_detail = ml_future.result()

    deps.append({"name": "malapi (service)", "kind": "service", "required": True,
                 "found": malapi_ok, "path": malapi_base if malapi_ok else None,
                 "note": malapi_detail if not malapi_ok
                         else "Windows API lookup answering"})

    deps.append({"name": "ml (service)", "kind": "service", "required": True,
                 "found": ml_ok, "path": ml_base if ml_ok else None,
                 "note": ml_detail if not ml_ok else "EMBER2024 scorer answering"})

    return {
        "available": True,
        "manifest": str(_MANIFEST),
        "manifest_loaded": man is not None,
        "dependencies": deps,
        "missing_required": sum(1 for d in deps if d["required"] and not d["found"]),
        "counts": {
            "total": len(deps),
            "found": sum(1 for d in deps if d["found"]),
            "missing": sum(1 for d in deps if not d["found"]),
        },
    }


def overview() -> dict:
    """Both dependency reports plus the current build state, in one payload.

    One call because the panel asks "is this installation ready" and splitting it
    would let it render a green toolchain beside a missing capa.
    """
    return {
        "toolchain": dependencies(),
        "stack": stack_dependencies(),
        "artifacts": artifacts(),
        "jobs": status(),
    }


# ---------------------------------------------------------------------------
# built artefacts
# ---------------------------------------------------------------------------

def artifacts() -> dict:
    """Executables this project has produced, newest first.

    Reads the build tree and the repo root, because MinGW Makefiles puts some
    targets next to the sources and the rest in build-ucrt/. `ready` is the
    field that matters: a present .exe is not the same as one that linked.
    """
    seen: dict[str, dict] = {}
    for root in (config.REPO / "build-ucrt", config.REPO):
        if not root.is_dir():
            continue
        try:
            entries = list(root.glob("*.exe"))
        except OSError:
            continue
        for exe in entries:
            try:
                st = exe.stat()
            except OSError:
                continue
            key = exe.name
            row = {
                "name": key,
                "path": str(exe),
                "relative": str(exe.relative_to(config.REPO)),
                "bytes": st.st_size,
                "modified": st.st_mtime,
            }
            # Prefer the build-tree copy: it is the one the presets actually
            # produced, and a stale root copy beside it is not.
            if key not in seen or str(exe).startswith(str(config.REPO / "build-ucrt")):
                seen[key] = row

    items = sorted(seen.values(), key=lambda r: r["modified"], reverse=True)
    for row in items:
        row["ready"] = row["name"] == ANALYZER and row["bytes"] > 0
    return {
        "artifacts": items,
        "analyzer": seen.get(ANALYZER),
        "analyzer_ready": bool(seen.get(ANALYZER, {}).get("ready")),
        "build_dir": str(config.REPO / "build-ucrt"),
        "build_dir_exists": (config.REPO / "build-ucrt").is_dir(),
    }


# ---------------------------------------------------------------------------
# building
# ---------------------------------------------------------------------------

_jobs: dict[str, dict] = {}
_jobs_lock = threading.Lock()
_running: str | None = None


def _now() -> float:
    return time.time()


def _prune(now: float) -> None:
    global _running
    for jid in [k for k, v in _jobs.items()
                if v.get("state") != "running" and now - v.get("finished_at", now) > JOB_TTL]:
        del _jobs[jid]


def _job_view(job: dict, full: bool = True) -> dict:
    keys = ("id", "state", "clean", "started_at", "finished_at", "exit_code",
            "error", "command", "log_line_count", "artifact",
            # Test jobs share this store, and the page needs to tell a build from
            # a test run and show per-test verdicts. Copied like `log` is:
            # explicitly listed, so adding a field to a job shows up in the API
            # rather than being silently dropped here.
            "kind", "summary", "selected", "results")
    out = {k: job.get(k) for k in keys}
    out["results"] = list(job.get("results") or [])
    # `log` has to be copied in explicitly, not just left off: it is the one
    # field the caller actually wants, and a job list that merely omits it
    # would otherwise look identical to a running job with no output.
    out["log"] = list(job.get("log") or [])
    dropped = job.get("log_dropped") or 0
    if dropped:
        out["log_truncated"] = dropped
    if not full:
        out.pop("log", None)
    return out


def start_build(clean: bool = False) -> dict:
    """Start one build. Refuses while another is running.

    Returns {ok, ...} rather than raising: "a build is already running" is an
    answer the panel shows, not an exception. The refusal is deliberate rather
    than queued - a queued build would sit invisible, and two concurrent builds
    would fight over build-ucrt/ anyway.
    """
    global _running

    with _jobs_lock:
        _prune(_now())
        running = _running
        if running is not None and _jobs.get(running, {}).get("state") == "running":
            return {"ok": False,
                    "error": "a build is already running",
                    "detail": f"job {running} is in progress; wait for it, or open "
                              "it from the job list below to watch its log",
                    "job_id": running}

    if not BUILD_SCRIPT.is_file():
        return {"ok": False, "error": f"{BUILD_SCRIPT.name} not found in the repo root"}
    if not UCRT64.is_dir():
        return {"ok": False,
                "error": f"MSYS2 UCRT64 not found at {UCRT64}",
                "detail": "install MSYS2 UCRT64, or set IA_MSYS2_UCRT64 to its path"}

    powershell = _which("powershell") or _which("pwsh")
    if powershell is None:
        return {"ok": False, "error": "neither powershell nor pwsh is on PATH"}

    jid = f"b{_now():.0f}{os.getpid() % 1000:03d}"
    argv = [powershell, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
            "-File", str(BUILD_SCRIPT), "-NoRun"]
    if clean:
        argv.append("-Clean")

    job = {
        "id": jid, "state": "running", "clean": clean,
        "started_at": round(_now(), 1), "finished_at": None,
        "exit_code": None, "error": None, "log": [], "log_line_count": 0,
        "log_dropped": 0,
        "command": " ".join(argv), "artifact": None,
    }

    with _jobs_lock:
        _jobs[jid] = job
        globals()["_running"] = jid

    threading.Thread(target=_run_build, args=(jid, argv), daemon=True,
                     name="build-job").start()
    return {"ok": True, "job_id": jid, "command": job["command"], "clean": clean}


def self_running_id() -> str | None:
    """The running job id, or None. Never call this while holding _jobs_lock -
    that lock is a plain Lock, not an RLock, so re-entering it deadlocks."""
    with _jobs_lock:
        return _running


def _run_build(job_id: str, argv: list[str]) -> None:
    global _running
    try:
        # The UCRT64 bin directory goes on PATH for the child exactly as
        # build.ps1 does it, so `cmake` finds the same toolchain it would in a
        # terminal that sourced the same environment.
        env = dict(os.environ)
        ucrt_bin = str(UCRT64 / "bin")
        env["PATH"] = f"{ucrt_bin}{os.pathsep}{env.get('PATH', '')}"

        proc = subprocess.Popen(
            argv, cwd=str(config.REPO), env=env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding="utf-8", errors="replace", bufsize=1,
        )
        for line in proc.stdout:
            _append(job_id, line.rstrip("\n"))
        code = proc.wait()

        exe = config.REPO / "build-ucrt" / ANALYZER
        with _jobs_lock:
            job = _jobs[job_id]
            job["exit_code"] = code
            job["finished_at"] = round(_now(), 1)
            if code == 0:
                job["state"] = "done" if exe.is_file() else "failed"
                job["artifact"] = str(exe) if exe.is_file() else None
                if not exe.is_file():
                    # build.ps1 exits 0 only after finding the analyzer, so this
                    # means something replaced it - worth saying rather than
                    # reporting success.
                    job["error"] = (f"build.ps1 exited 0 but {ANALYZER} is not "
                                    "in build-ucrt/")
            else:
                job["state"] = "failed"
                job["error"] = f"build.ps1 exited {code}"
    except Exception as exc:  # noqa: BLE001 - a job must report, not vanish
        with _jobs_lock:
            job = _jobs.get(job_id)
            if job:
                job["state"] = "error"
                job["error"] = f"{type(exc).__name__}: {exc}"
                job["finished_at"] = round(_now(), 1)
    finally:
        with _jobs_lock:
            if _running == job_id:
                _running = None


def _append(job_id: str, line: str) -> None:
    with _jobs_lock:
        job = _jobs.get(job_id)
        if not job:
            return
        log = job["log"]
        log.append(line)
        # Keep the head as well as the tail: the first lines carry the cmake
        # configure output, which is where a missing dependency announces
        # itself, and the tail is where the compiler gives up.
        #
        # `log_line_count` counts every line ever produced, so it keeps rising
        # past MAX_LOG_LINES - the panel shows "4321 lines" while displaying
        # 4000, and that gap is the honest answer.
        #
        # The drop count accumulates. It used to be assigned, which meant a
        # second truncation overwrote the first and the banner under-reported
        # how much of the build was no longer on screen.
        if len(log) > MAX_LOG_LINES:
            dropped = len(log) - MAX_LOG_LINES // 2
            del log[:dropped]
            job["log_dropped"] = job.get("log_dropped", 0) + dropped
        job["log_line_count"] += 1


def job(job_id: str) -> dict | None:
    """One job's state and log, or None if the id is unknown or expired."""
    with _jobs_lock:
        _prune(_now())
        job = _jobs.get(job_id)
        return _job_view(dict(job)) if job else None


def current() -> dict | None:
    """The running job, if any, so a reload reattaches instead of orphaning."""
    with _jobs_lock:
        _prune(_now())
        rid = _running
        if not rid:
            return None
        job = _jobs.get(rid)
        return _job_view(dict(job)) if job else None


def log_text(job_id: str) -> str | None:
    with _jobs_lock:
        job = _jobs.get(job_id)
        return "\n".join(job["log"]) if job else None


def status() -> dict:
    with _jobs_lock:
        _prune(_now())
        return {
            "running": _running,
            "jobs": [_job_view(dict(j), full=False) for j in
                     sorted(_jobs.values(), key=lambda j: j["started_at"], reverse=True)[:10]],
            "script": str(BUILD_SCRIPT),
            "script_found": BUILD_SCRIPT.is_file(),
        }


if __name__ == "__main__":  # manual probe: `python -m python.panel.build.build`
    print(json.dumps({"dependencies": dependencies(), "artifacts": artifacts()},
                     indent=2, default=str))