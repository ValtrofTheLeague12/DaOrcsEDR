#!/usr/bin/env python3
"""Provenance, freshness, validation and a runnable test catalogue for the
Build page.

The page already answers "what is installed". These answer the three questions
that actually decide whether anyone can trust the binary sitting in build-ucrt/:

    provenance   what is it?      commit, branch, dirty - and the commit baked
                                  into the binary, which is how a stale build
                                  gets caught rather than assumed
    freshness    is it current?   newest source mtime vs the executable's
    validation   does it work?    read-only checks, each with its own verdict

Plus a test catalogue the admin picks from. That last one is deliberately a
catalogue rather than a fixed suite: two of these tests write files and one
reaches the network, and a single "Run tests" button cannot say which it is about
to do.

Everything here is read-only except start_tests(). No check runs a build.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import threading
import time
from pathlib import Path

from . import build, config

# ---------------------------------------------------------------------------
# Layout
# ---------------------------------------------------------------------------

ANALYZER = "static_analyzer.exe"
EXE = config.REPO / "build-ucrt" / ANALYZER

# The interpreter the panel itself runs under, which is the project venv. Used
# for the Python-side tests, so they get the same dependencies the panel has
# rather than whatever `python` happens to resolve to.
PYTHON = sys.executable

# objdump, for the DLL-import check. MSYS2's copy, because that is the toolchain
# the binary was linked with.
UCRT_BIN = Path(os.environ.get("IA_MSYS2_UCRT64", r"C:\msys64\ucrt64")) / "bin"
OBJDUMP = UCRT_BIN / "objdump.exe"

# Source trees whose mtime decides whether the executable is current. CMake
# files are included because a changed option or a changed link line produces a
# different binary without any .cpp changing.
SOURCE_GLOBS = (
    "src/**/*.cpp",
    "src/**/*.hpp",
    "include/**/*.hpp",
    "CMakeLists.txt",
    "CMakePresets.json",
)

# Validation is bounded: this runs on a poll, and a hung subprocess would hang
# the page with it.
CHECK_TIMEOUT = 25.0
SMOKE_TIMEOUT = 120.0

# The build page has ONE job store and ONE lock for both builds and tests.
# Two locks over one dict is a data race, and the failure would look like a
# corrupted log rather than a locking bug.
_jobs = build._jobs
_jobs_lock = build._jobs_lock
_now = build._now
_prune = build._prune

_tests_running: str | None = None


# ---------------------------------------------------------------------------
# Provenance
# ---------------------------------------------------------------------------

def _git(*args: str) -> str | None:
    """Run one git command, or None. A missing git is not an error - it is just
    provenance this installation cannot give, and the page says so."""
    try:
        out = subprocess.run(
            ["git", "-C", str(config.REPO), *args],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=CHECK_TIMEOUT, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if out.returncode != 0:
        return None
    return out.stdout.strip()


def git_state() -> dict:
    """The working tree's identity."""
    if _git("rev-parse", "--git-dir") is None:
        return {"available": False,
                "reason": "git is not available here, or this is not a git checkout"}
    commit = _git("rev-parse", "HEAD")
    dirty_files = _git("status", "--porcelain")
    dirty = 0
    if dirty_files is not None:
        dirty = len([ln for ln in dirty_files.splitlines() if ln.strip()])
    return {
        "available": commit is not None,
        "commit": (commit or "")[:40],
        "short": (commit or "")[:7],
        "branch": _git("rev-parse", "--abbrev-ref", "HEAD"),
        "subject": _git("log", "-1", "--pretty=%s"),
        "author_date": _git("log", "-1", "--pretty=%cI"),
        "dirty": dirty > 0,
        "dirty_count": dirty,
    }


def baked_identity() -> dict:
    """The identity compiled into the executable.

    Parsed out of `--version` rather than out of a sidecar file: the binary is
    the artifact that travels, so whatever it says about itself is the only
    claim that travels with it. A missing or unparseable version is reported as
    such instead of being guessed at.
    """
    if not EXE.is_file():
        return {"available": False, "reason": "the analyzer is not built yet"}
    try:
        out = subprocess.run(
            [str(EXE), "--version"], capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=CHECK_TIMEOUT,
            check=False, cwd=str(config.REPO),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"available": False, "reason": f"could not run --version: {exc}"}
    text = (out.stdout or out.stderr or "").strip().splitlines()
    if out.returncode != 0 or not text:
        return {"available": False,
                "reason": f"--version exited {out.returncode}"}
    first = text[0].strip()
    commit = None
    match = re.search(r"\b([0-9a-f]{7,40})\b", first)
    if match:
        commit = match.group(1)
    return {
        "available": True,
        "version": first,
        "commit": commit,
        "raw": "\n".join(text),
    }


def provenance() -> dict:
    """Git, the binary's own claim, and whether the two agree.

    The comparison is the point. "HEAD is bd93684 and the binary says 1a2b3c4"
    is the single most useful sentence this page can produce: it means the thing
    you are running is not the thing in your working tree.
    """
    git = git_state()
    baked = baked_identity()

    head = (git.get("commit") or "").strip()
    built = (baked.get("commit") or "").strip()
    # One side may be a short hash and the other long, or the reverse, so this
    # compares prefixes rather than demanding one canonical length.
    if head and built:
        agrees = head.startswith(built) or built.startswith(head)
        note = ("the binary was built from a different commit than the working tree"
                if not agrees else "the binary was built from the current commit")
    elif not baked.get("available"):
        agrees = None
        note = f"the binary does not report a commit ({baked.get('reason')})"
    elif not git.get("available"):
        agrees = None
        note = f"no git identity here ({git.get('reason')})"
    else:
        agrees = None
        note = "no comparison available"

    return {"git": git, "baked": baked, "agrees": agrees, "note": note}


# ---------------------------------------------------------------------------
# Freshness
# ---------------------------------------------------------------------------

def _newest_source() -> tuple[float | None, str | None]:
    """(mtime, relative path) of the most recently touched input."""
    newest_at: float | None = None
    newest_rel: str | None = None
    for pattern in SOURCE_GLOBS:
        for path in config.REPO.glob(pattern):
            try:
                st = path.stat()
            except OSError:
                continue
            if newest_at is None or st.st_mtime > newest_at:
                newest_at = st.st_mtime
                newest_rel = str(path.relative_to(config.REPO))
    return newest_at, newest_rel


def freshness() -> dict:
    """Is the executable older than the sources it is built from?"""
    try:
        exe_stat = EXE.stat()
        exe_at = exe_stat.st_mtime
    except OSError:
        return {"available": False, "reason": "the analyzer is not built yet",
                "stale": None}

    src_at, src_rel = _newest_source()
    stale = bool(src_at and src_at > exe_at)

    # The few sources newer than the exe, so "stale" is actionable rather than a
    # verdict with nothing behind it.
    newer: list[dict] = []
    if stale:
        for pattern in SOURCE_GLOBS:
            for path in config.REPO.glob(pattern):
                try:
                    st = path.stat()
                except OSError:
                    continue
                if st.st_mtime <= exe_at:
                    continue
                newer.append({"path": str(path.relative_to(config.REPO)),
                              "mtime": round(st.st_mtime, 1)})
        newer.sort(key=lambda r: -r["mtime"])
        newer = newer[:8]

    return {
        "available": True,
        "stale": stale,
        "exe_path": str(EXE.relative_to(config.REPO)),
        "exe_mtime": round(exe_at, 1),
        "exe_bytes": exe_stat.st_size,
        "newest_source": src_rel,
        "newest_source_mtime": round(src_at, 1) if src_at else None,
        "lag_seconds": round(src_at - exe_at, 1) if (stale and src_at) else 0.0,
        "newer_sources": newer,
        "note": ("the executable predates the newest source - rebuild before "
                 "trusting a result from it" if stale else
                 "the executable is newer than every source it is built from"),
    }


# ---------------------------------------------------------------------------
# Build configuration
# ---------------------------------------------------------------------------

def build_configuration() -> dict:
    """The CMake options that decide what is compiled in.

    Worth separating from the toolchain report, which says whether Graphviz is
    INSTALLED. These say whether it was compiled in - the difference between the
    parser existing and the parser being in this binary.
    """
    cache = config.REPO / "build-ucrt" / "CMakeCache.txt"
    try:
        text = cache.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {"available": False,
                "reason": f"{cache.name} not found - configure the project first"}

    values: dict[str, str] = {}
    for line in text.splitlines():
        if not line or line.startswith(("#", "//")) or "=" not in line:
            continue
        if line.startswith(("CMAKE_", "STATIC_ANALYZER_")):
            key, _, value = line.partition("=")
            values[key.strip()] = value.strip()
    options = {k: v for k, v in values.items() if k.startswith("STATIC_ANALYZER_")}
    return {
        "available": True,
        "options": options,
        "generator": values.get("CMAKE_GENERATOR"),
        "build_type": values.get("CMAKE_BUILD_TYPE"),
        "compiler": values.get("CMAKE_CXX_COMPILER"),
        "cache_path": str(cache),
    }


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def _run(argv: list[str], timeout: float) -> dict:
    try:
        out = subprocess.run(
            argv, capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=timeout, check=False,
            cwd=str(config.REPO),
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "code": None, "error": f"timed out after {timeout:.0f}s",
                "output": ""}
    except OSError as exc:
        return {"ok": False, "code": None, "error": str(exc), "output": ""}
    return {"ok": out.returncode == 0, "code": out.returncode, "error": None,
            "output": ((out.stdout or "") + (out.stderr or "")).strip()}


def _check_executable() -> dict:
    if not EXE.is_file():
        return {"ok": False, "detail": "not built"}
    try:
        size = EXE.stat().st_size
    except OSError as exc:
        return {"ok": False, "detail": str(exc)}
    return {"ok": size > 0, "detail": f"{size:,} bytes"}


def _check_runtime_dlls() -> dict:
    """Every imported DLL present beside the executable.

    This project has already been bitten by this: Graphviz installs its own
    zlib1.dll, it sat earlier on PATH than the MinGW one, and the analyzer died
    at load time with STATUS_ENTRYPOINT_NOT_FOUND and no output at all. It
    belongs on a page, permanently.
    """
    if not EXE.is_file():
        return {"ok": False, "detail": "not built"}
    if not OBJDUMP.is_file():
        return {"ok": None, "detail": "objdump not available to inspect imports"}
    try:
        out = subprocess.run([str(OBJDUMP), "-p", str(EXE)], capture_output=True,
                             text=True, encoding="utf-8", errors="replace",
                             timeout=CHECK_TIMEOUT, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"ok": False, "detail": f"objdump failed: {exc}"}

    needed: list[str] = []
    for line in (out.stdout or "").splitlines():
        if "DLL Name:" in line:
            name = line.split("DLL Name:")[1].strip()
            # API sets are resolved by the OS, not by a file on disk.
            if not name.lower().startswith(("api-ms-", "ext-ms-")):
                needed.append(name)

    system = Path(os.environ.get("SYSTEMROOT", r"C:\Windows")) / "System32"
    missing = [n for n in needed
               if not (EXE.parent / n).is_file() and not (system / n).is_file()]
    if missing:
        return {"ok": False, "detail": f"missing beside the exe: {', '.join(missing)}"}
    return {"ok": True, "detail": f"{len(needed)} imports, all resolvable"}


def validation() -> dict:
    """Read-only checks. None of these builds, and none writes to the repo."""
    checks: list[dict] = []

    checks.append({"id": "executable", "label": "Executable present",
                   **_check_executable()})

    if EXE.is_file():
        version = _run([str(EXE), "--version"], CHECK_TIMEOUT)
        checks.append({
            "id": "identity", "label": "Identity (--version)",
            "ok": version["ok"],
            "detail": (version["output"].splitlines() or [""])[0][:120]
                      if version["ok"] else (version["error"] or "exited "
                                              f"{version['code']}"),
        })

        cli = _run([str(EXE), "--list-pipelines"], CHECK_TIMEOUT)
        checks.append({"id": "cli", "label": "CLI surface",
                       "ok": cli["ok"],
                       "detail": "responds" if cli["ok"]
                                 else (cli["error"] or f"exited {cli['code']}")})

        crash = _run([str(EXE), "--crash-demo"], SMOKE_TIMEOUT)
        # Matched against the real wording. "Exited 0" on its own proves
        # nothing: the demo can exit cleanly having written a report nowhere.
        wrote = "report written to" in (crash["output"] or "")
        checks.append({
            "id": "fault", "label": "Fault path (--crash-demo)",
            # Exit 0 alone is not enough: the demo can exit 0 having printed a
            # report nowhere. Both halves are asserted.
            "ok": bool(crash["ok"] and wrote),
            "detail": "report rendered" if wrote
                      else (crash["error"] or f"exited {crash['code']} without a report"),
        })

    checks.append({"id": "dlls", "label": "Runtime DLLs", **_check_runtime_dlls()})

    verdict = None
    states = [c["ok"] for c in checks]
    if any(s is False for s in states):
        verdict = "fail"
    elif all(s is True for s in states):
        verdict = "pass"
    else:
        verdict = "unknown"
    return {"checks": checks, "verdict": verdict,
            "ran_at": round(time.time(), 1)}


# ---------------------------------------------------------------------------
# Test catalogue
# ---------------------------------------------------------------------------

def _has_pytest() -> bool:
    """`pytest` importable in the panel venv. Probed by subprocess rather than
    by find_spec, because the tests RUN under that interpreter and this one may
    be a different build of the same version."""
    try:
        out = subprocess.run(
            [PYTHON, "-c", "import pytest"], capture_output=True,
            timeout=CHECK_TIMEOUT, check=False,
        )
        return out.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


# Every entry declares what it TOUCHES. Two write files, one reaches the
# network, and a button that does not say so is a button nobody should press.
_CATALOGUE_SPEC = [
    {"id": "identity", "label": "Identity", "kind": "smoke",
     "description": "The analyzer reports its own version, commit and build flags.",
     "effects": [], "argv": [ANALYZER, "--version"], "timeout": 30},
    {"id": "cli", "label": "CLI surface", "kind": "smoke",
     "description": "--version, --help, --list-phases and --list-pipelines all "
                    "answer. Proves the binary starts and its argument parsing "
                    "and phase catalog are intact.",
     "effects": [], "script": "tools/selftest_cli.py", "timeout": 180},
    {"id": "crash-demo", "label": "Crash presentation", "kind": "smoke",
     "description": "Renders the red banner, the report and a minidump, then exits "
                    "normally. Proves the presentation without faulting.",
     "effects": ["writes one crash report"], "argv": [ANALYZER, "--crash-demo"],
     "timeout": 60},
    {"id": "crash-selftest", "label": "Crash handlers", "kind": "smoke",
     "description": "Dereferences null on purpose. The handlers must catch it and "
                    "write a report.",
     "effects": ["writes report + minidump", "faults on purpose"],
     "argv": [ANALYZER, "--crash-selftest"], "timeout": 60,
     "expect_code": 0xC0000005},
    {"id": "seal", "label": "Bundle encryption", "kind": "smoke",
     "description": "Seal/open round-trip plus every tamper case: bit flip, "
                    "truncation, chunk reorder, wrong key. Pure, no network.",
     "effects": [], "script": "mega/test_seal.py", "timeout": 180},
    {"id": "analysis", "label": "Analysis run", "kind": "integration",
     "description": "Runs the analyzer over the inert test fixture with the default "
                    "pipeline. Writes exports/ and the run log.",
     "effects": ["writes exports/", "writes the run log"],
     "analysis": "default", "timeout": 900},
]


def catalogue() -> dict:
    """Everything the admin can choose from, with availability and effects."""
    has_pytest = _has_pytest()
    entries: list[dict] = []

    for spec in _CATALOGUE_SPEC:
        entry = dict(spec)
        entry["available"] = True
        entry["unavailable_reason"] = None
        if entry.get("script"):
            entry["available"] = (config.REPO / entry["script"]).is_file()
            if not entry["available"]:
                entry["unavailable_reason"] = f"{entry['script']} not found"
        entries.append(entry)

    tests_dir = config.REPO / "tests"
    suites: list[dict] = []
    if tests_dir.is_dir():
        for path in sorted(tests_dir.glob("test_*.py")):
            suites.append({
                "id": f"pytest:{path.name}",
                "label": path.stem.replace("test_", "").replace("_", " ").title(),
                "kind": "pytest",
                "description": f"{path.name} - pytest suite.",
                "effects": ["as declared by the suite"],
                "pytest_file": path.name,
                "available": has_pytest,
                "unavailable_reason": None if has_pytest else
                    "pytest is not installed in python/.venv",
                "timeout": 900,
            })
    entries.extend(suites)

    return {
        "entries": entries,
        "quick": [e["id"] for e in entries
                  if e["kind"] == "smoke" and e["available"]],
        "pytest_available": has_pytest,
        "sample": _fixture_sample(),
    }


def _fixture_sample() -> str | None:
    """The project's own inert fixture, so "run the analyzer" from a browser can
    never be pointed at a real sample by accident."""
    for candidate in ("quick_test.exe", "tests/fixtures/eicar_ioc_fixture.exe"):
        path = config.REPO / candidate
        if path.is_file():
            return str(path.relative_to(config.REPO))
    return None


def _entry_argv(entry: dict) -> list[str]:
    if entry.get("argv"):
        argv = list(entry["argv"])
        # argv[0] is the ANALYZER constant; resolve it to the built path.
        return [str(EXE), *argv[1:]] if argv[0] == ANALYZER else argv
    if entry.get("script"):
        return [PYTHON, entry["script"]]
    if entry.get("pytest_file"):
        return [PYTHON, "-m", "pytest", "-q",
                str(config.REPO / "tests" / entry["pytest_file"])]
    if entry.get("analysis"):
        return [str(EXE), "--no-curses", "--pipeline", entry["analysis"],
                _fixture_sample() or "a.exe"]
    return []


# ---------------------------------------------------------------------------
# Running them
# ---------------------------------------------------------------------------

def start_tests(ids: list[str]) -> dict:
    """Run the chosen tests, one after another, as a single job."""
    global _tests_running

    cat = catalogue()
    known = {e["id"]: e for e in cat["entries"]}
    chosen = [known[i] for i in ids if i in known]
    if not chosen:
        return {"ok": False, "error": "no known tests selected"}
    missing = [i for i in ids if i not in known]
    unavailable = [e["id"] for e in chosen if not e["available"]]

    with _jobs_lock:
        _prune(_now())
        if _tests_running is not None:
            return {"ok": False, "error": "a test run is already in progress",
                    "job_id": _tests_running}

    jid = f"t{_now():.0f}{os.getpid() % 1000:03d}"
    job = {
        "id": jid, "state": "running", "kind": "tests",
        "started_at": round(_now(), 1), "finished_at": None,
        "exit_code": None, "error": None, "log": [], "log_line_count": 0,
        "log_dropped": 0, "command": "", "artifact": None,
        "results": [{"id": e["id"], "label": e["label"], "state": "pending",
                     "detail": None, "duration": None} for e in chosen],
        "selected": [e["id"] for e in chosen],
    }
    with _jobs_lock:
        _jobs[jid] = job
        globals()["_tests_running"] = jid

    if missing:
        _append(jid, f"skipped unknown test id(s): {', '.join(missing)}")
    if unavailable:
        _append(jid, f"skipped unavailable test(s): {', '.join(unavailable)}")
    _append(jid, f"running {len(chosen)} test(s) with "
                 f"IA_ARTIFACT_UPLOAD=0 (nothing is uploaded from a browser)")

    threading.Thread(target=_run_tests, args=(jid, chosen), daemon=True,
                     name="test-job").start()
    return {"ok": True, "job_id": jid,
            "running": [e["id"] for e in chosen if e["available"]]}


def _append(job_id: str, line: str) -> None:
    # Never call this while holding _jobs_lock. That lock is a plain Lock, not an
    # RLock, so re-entering it from the same thread deadlocks - which presents as
    # a test that hangs forever with the job endpoint refusing to answer. Every
    # log line is therefore emitted AFTER the critical section, not inside it.
    with _jobs_lock:
        job = _jobs.get(job_id)
        if job is None:
            return
        job["log"].append(line)
        job["log_line_count"] += 1
        # Bounded: a chatty suite must not become a leak. This panel was
        # measured at gigabytes once, and an unbounded log list is that shape.
        if len(job["log"]) > 4000:
            drop = len(job["log"]) - 4000
            del job["log"][:drop]
            job["log_dropped"] += drop


def _set_result(job_id: str, entry_id: str, **fields) -> None:
    """Update one test's row in the job, under the lock."""
    with _jobs_lock:
        job = _jobs.get(job_id)
        if job is None:
            return
        for result in job["results"]:
            if result["id"] == entry_id:
                result.update(fields)
                return


def _run_tests(job_id: str, entries: list[dict]) -> None:
    global _tests_running
    passed = failed = 0
    try:
        for entry in entries:
            if not entry["available"]:
                reason = entry.get("unavailable_reason") or "unavailable"
                _set_result(job_id, entry["id"], state="skipped", detail=reason)
                _append(job_id, f"--- {entry['label']}: SKIPPED ({reason})")
                continue

            _set_result(job_id, entry["id"], state="running")
            argv = _entry_argv(entry)
            _append(job_id, "")
            _append(job_id, f"=== {entry['label']} ({entry['id']})")
            _append(job_id, f"    $ {' '.join(argv)}")
            for effect in entry.get("effects") or []:
                _append(job_id, f"    side effect: {effect}")

            env = dict(os.environ)
            # The single most important line in this file. The analysis settings
            # say MEGA_UPLOAD: true, so without this a test started from a
            # browser would push an evidence bundle to the operator's cloud
            # account.
            env["IA_ARTIFACT_UPLOAD"] = "0"
            # Test output is captured through a pipe, where the analyzer would
            # normally suppress its startup logo. The panel is showing this log
            # to an operator, so keep daorcs.logo in it; a crashing test still
            # adds crash.logo through the normal handler.
            env["STATIC_ANALYZER_FORCE_LOGO"] = "1"
            env.setdefault("IA_APPDATA_DIR",
                           str(config.appdata_root() / "test-runs"))

            started = time.time()
            code: int | None
            proc = None
            try:
                proc = subprocess.Popen(
                    argv, cwd=str(config.REPO), env=env,
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    text=True, encoding="utf-8", errors="replace", bufsize=1,
                )
                for line in proc.stdout:
                    _append(job_id, "    " + line.rstrip("\n"))
                code = proc.wait(timeout=entry.get("timeout", SMOKE_TIMEOUT))
            except subprocess.TimeoutExpired:
                proc.kill()
                code = None
                _append(job_id, f"    timed out after {entry.get('timeout')}s")
            except Exception as exc:  # noqa: BLE001 - a job must report, not vanish
                code = None
                _append(job_id, f"    {type(exc).__name__}: {exc}")

            duration = round(time.time() - started, 2)
            expected = entry.get("expect_code")
            if code is None:
                state, detail = "failed", "did not finish"
            elif expected is not None:
                # crash-selftest is supposed to die; a clean exit means the
                # handler did not run, which is a failure, not a pass.
                state = "passed" if code == expected else "failed"
                detail = f"exit {code} (expected {expected})"
            else:
                state = "passed" if code == 0 else "failed"
                detail = "exit 0" if code == 0 else f"exit {code}"

            _set_result(job_id, entry["id"], state=state, detail=detail,
                        duration=duration, code=code)
            if state == "passed":
                passed += 1
            else:
                failed += 1
            _append(job_id,
                    f"--- {entry['label']}: {'PASS' if state == 'passed' else 'FAIL'} "
                    f"({detail}, {duration}s)")

        summary = f"{passed} passed, {failed} failed"
        with _jobs_lock:
            job = _jobs.get(job_id)
            if job:
                job["state"] = "passed" if failed == 0 else "failed"
                job["exit_code"] = 0 if failed == 0 else 1
                job["finished_at"] = round(_now(), 1)
                job["summary"] = summary
    finally:
        # Appends after the lock, for the same reason as everywhere else.
        _append(job_id, "")
        _append(job_id, f"=== {passed} passed, {failed} failed")
        with _jobs_lock:
            if _tests_running == job_id:
                globals()["_tests_running"] = None


def tests_running() -> str | None:
    return _tests_running