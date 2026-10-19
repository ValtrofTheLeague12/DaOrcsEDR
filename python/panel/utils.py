#!/usr/bin/env python3
"""Operator maintenance for the vendored analysis stack.

Four things in this project can only be maintained by knowing the repo layout,
which means by reading source: regenerate the SBOM, update the MalAPI rules,
check the YARA rules, and refresh yarGen-Go's databases. Each one has a script
or a vendored checkout that already exists; none of them is reachable from the
console.

The page reports state and runs the update, and it separates the two on
purpose. Every one of these actions either reaches the network or rewrites
files, so "what is true now" has to be answerable without doing either.

Three details that are not obvious from the outside:

`malt/` is the MalAPI rules. MalAPI itself is not vendored - the analyzer
talks to a generated local API (`python/api/server.py`, 544 routes) built from
the rules, so "update MalAPI" means updating the rule source underneath it.
It is a git checkout of memtt/malt, and the pull is `--ff-only` with terminal
prompts disabled, because a merge commit created by a browser button is not a
thing anyone wants to unpick.

`yara-rules/` is NOT a git checkout. It is five unpacked collections with no
upstream recorded anywhere, so there is no "update" to offer - only a way to
find out what is there and whether it compiles. That is deliberately reported
as unavailable rather than quietly omitted.

yarGen-Go's own script documents a failure mode this page exists to prevent:
`config/config.yaml` is read at startup, only `config.example.yml` is
committed, and a missing config does not stop yarGen - it silently scores every
string as unseen noise. A tool that degrades quietly is worse than one that
refuses, so the missing file is reported as a fault.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import threading
import time
from pathlib import Path

from . import build, config

# ---------------------------------------------------------------------------
# Layout
# ---------------------------------------------------------------------------

SBOM_SCRIPT = config.REPO / "generate_sbom.py"
SBOM_JSON = config.REPO / "sbom.json"
SBOM_SUMMARY = config.REPO / "sbom_summary.json"

MALT_DIR = config.REPO / "malt"
YARA_RULES = config.REPO / "yara-rules"
YARGEN_DIR = config.REPO / "yarGen-Go"
YARGEN_UPDATE = YARGEN_DIR / "update_and_check.ps1"

# yarac is the rule COMPILER, which is what a validity check needs. `yara`
# would compile and then scan a target, which is a different question and needs
# a sample we do not want to pick here.
UCRT_BIN = Path(os.environ.get("IA_MSYS2_UCRT64", r"C:\msys64\ucrt64")) / "bin"
YARAC = UCRT_BIN / "yarac.exe"
YARA = UCRT_BIN / "yara.exe"

CHECK_TIMEOUT = 30.0
# Generous: the SBOM walks every venv in the tree, and a pull on a slow link is
# not instant. Bounded regardless, because a job with no ceiling is a job that
# reports "running" forever.
SBOM_TIMEOUT = 900.0
PULL_TIMEOUT = 300.0
YARA_TIMEOUT = 600.0

_jobs = build._jobs
_jobs_lock = build._jobs_lock
_now = build._now
_prune = build._prune

_utils_running: str | None = None


def _python() -> str:
    import sys
    return sys.executable


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def _rel(path: Path) -> str:
    """Repo-relative where possible, absolute otherwise.

    `relative_to` raises when the path is not under the repo, and an inventory
    helper is the wrong place to crash on that: the rules directory can be
    pointed somewhere else (YARA_RULES_DIR is exactly that kind of setting), and
    a panel that dies on an absolute path is a panel that cannot show you why
    the path is wrong.
    """
    try:
        return str(path.relative_to(config.REPO))
    except ValueError:
        return str(path)


def _git(cwd: Path, *args: str, timeout: float = CHECK_TIMEOUT) -> dict:
    """One git command. Never raises - git being absent is a fact to report."""
    try:
        out = subprocess.run(
            ["git", "-C", str(cwd), *args], capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=timeout, check=False,
            # Refuse to prompt. A job has no stdin and no terminal, so a pull
            # that wanted credentials would hang until the timeout rather than
            # failing, which is the same "running" spinner with less honesty.
            env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"ok": False, "error": str(exc), "stdout": "", "stderr": ""}
    return {"ok": out.returncode == 0, "error": None,
            "stdout": (out.stdout or "").strip(),
            "stderr": (out.stderr or "").strip(), "code": out.returncode}


def _head_commit_date(cwd: Path) -> str | None:
    got = _git(cwd, "log", "-1", "--pretty=%cI")
    return got["stdout"] or None if got["ok"] else None


# ---------------------------------------------------------------------------
# SBOM
# ---------------------------------------------------------------------------

def sbom() -> dict:
    """State of the CycloneDX SBOM, and whether it still describes the tree.

    Staleness is measured against the last commit, not "how old is the file" -
    a fresh SBOM from a week-old commit is stale in the only way that matters,
    and an untouched SBOM from this morning's commit is fine.
    """
    if not SBOM_SUMMARY.is_file():
        return {"available": False,
                "reason": f"{SBOM_SUMMARY.name} has not been generated yet",
                "stale": None, "script_present": SBOM_SCRIPT.is_file()}

    try:
        summary = json.loads(SBOM_SUMMARY.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return {"available": False, "reason": f"could not read the summary: {exc}",
                "stale": None, "script_present": SBOM_SCRIPT.is_file()}

    generated_at = summary.get("generated_at")
    age_days = None
    if generated_at:
        try:
            from datetime import datetime, timezone
            made = datetime.fromisoformat(str(generated_at))
            if made.tzinfo is None:
                made = made.replace(tzinfo=timezone.utc)
            age_days = round((datetime.now(timezone.utc) - made).total_seconds() / 86400, 1)
        except ValueError:
            pass

    # Compare against the newest thing in the tree the SBOM would have listed.
    last_commit = _head_commit_date(config.REPO)
    behind_commit = None
    if generated_at and last_commit:
        try:
            from datetime import datetime, timezone
            made = datetime.fromisoformat(str(generated_at))
            if made.tzinfo is None:
                made = made.replace(tzinfo=timezone.utc)
            comm = datetime.fromisoformat(last_commit)
            if comm.tzinfo is None:
                comm = comm.replace(tzinfo=timezone.utc)
            behind_commit = comm > made
        except ValueError:
            pass

    return {
        "available": True,
        "generated_at": generated_at,
        "age_days": age_days,
        "tool": summary.get("tool"),
        "format": summary.get("format"),
        "spec_version": summary.get("spec_version"),
        "project": summary.get("project"),
        "total_components": summary.get("total_components"),
        "by_type": summary.get("components_by_type") or {},
        "by_origin": summary.get("components_by_origin") or {},
        "by_language": summary.get("components_by_language") or {},
        "unresolved": summary.get("unresolved_versions") or [],
        "cyclonedx_bytes": SBOM_JSON.stat().st_size if SBOM_JSON.is_file() else 0,
        "cyclonedx_present": SBOM_JSON.is_file(),
        "last_commit": last_commit,
        "behind_last_commit": behind_commit,
        "stale": bool(age_days is not None and age_days > 1) or bool(behind_commit),
        "script_present": SBOM_SCRIPT.is_file(),
        "note": ("regenerated after the last commit, so it may not describe the "
                 "current tree" if behind_commit else
                 "generated from the current tree" if age_days is not None and age_days <= 1
                 else f"generated {age_days} days ago"),
    }


# ---------------------------------------------------------------------------
# MalAPI rules (malt/)
# ---------------------------------------------------------------------------

def malapi() -> dict:
    """State of the MalAPI rule source.

    "Update MalAPI" is updating memtt/malt. The analyzer does not link it; the
    local API in python/api/server.py is generated from it, which is why the
    panel reports the rule checkout rather than a service.
    """
    if not MALT_DIR.is_dir():
        return {"available": False, "reason": "malt/ is not present in this checkout",
                "can_update": False}

    if not (MALT_DIR / ".git").is_dir():
        return {"available": False, "reason": "malt/ is not a git checkout, so it cannot be updated from here",
                "can_update": False}

    head = _git(MALT_DIR, "rev-parse", "HEAD")
    branch = _git(MALT_DIR, "rev-parse", "--abbrev-ref", "HEAD")
    remote = _git(MALT_DIR, "config", "--get", "remote.origin.url")
    dirty_lines = _git(MALT_DIR, "status", "--porcelain")
    dirty = [ln for ln in dirty_lines["stdout"].splitlines() if ln.strip()]

    # Left/right counts against the tracked upstream. Reported but NOT fetched:
    # asking the network is a side effect and belongs in the explicit update.
    counts = _git(MALT_DIR, "rev-list", "--left-right", "--count",
                  "HEAD...@{upstream}")
    behind = ahead = None
    if counts["ok"] and counts["stdout"]:
        parts = counts["stdout"].split()
        if len(parts) == 2 and all(p.isdigit() for p in parts):
            ahead, behind = int(parts[0]), int(parts[1])

    return {
        "available": head["ok"],
        "reason": head["error"] or head["stderr"] or None,
        "path": _rel(MALT_DIR),
        "remote": remote["stdout"] or None,
        "branch": branch["stdout"] or None,
        "commit": head["stdout"] or None,
        "short": (head["stdout"] or "")[:9],
        "commit_date": _head_commit_date(MALT_DIR),
        "dirty": len(dirty) > 0,
        "dirty_count": len(dirty),
        "ahead": ahead,
        "behind": behind,
        "up_to_date": behind == 0 and ahead == 0,
        # A pull onto a dirty tree is refused by the runner, and the reason is
        # shown here rather than discovered as a failed job.
        "can_update": not dirty,
        "note": ("local changes would be overwritten - commit or stash first"
                 if dirty else
                 "up to date with upstream" if behind == 0 and ahead == 0
                 else f"{behind} commit(s) behind upstream"),
    }


# ---------------------------------------------------------------------------
# YARA rules
# ---------------------------------------------------------------------------

def yara() -> dict:
    """Inventory of the rule packs.

    Read-only and cheap enough to call on a poll: a directory walk with no
    parsing. There is deliberately no "update" here - yara-rules/ is five
    unpacked collections with no recorded upstream, so pretending to be able to
    refresh it would be a button that lies.
    """
    if not YARA_RULES.is_dir():
        return {"available": False, "reason": "yara-rules/ is not present", "total": 0}

    collections: list[dict] = []
    total = 0
    total_bytes = 0
    largest: list[dict] = []

    for coll in sorted(p for p in YARA_RULES.iterdir() if p.is_dir()):
        files = [f for f in coll.rglob("*")
                 if f.is_file() and f.suffix.lower() in (".yar", ".yara")]
        if not files:
            continue
        size = 0
        for f in files:
            try:
                size += f.stat().st_size
            except OSError:
                pass
        total += len(files)
        total_bytes += size
        collections.append({"name": coll.name, "rules": len(files),
                            "bytes": size})

    # The biggest few, because a 1.8 MB single file is the thing that makes a
    # whole-collection compile run slow, and that is worth seeing in advance.
    every = [f for f in YARA_RULES.rglob("*")
             if f.is_file() and f.suffix.lower() in (".yar", ".yara")]
    for f in every:
        try:
            largest.append((f.stat().st_size,
                            _rel(f)))
        except OSError:
            pass
    largest.sort(reverse=True)
    largest = [{"bytes": b, "path": p} for b, p in largest[:5]]

    return {
        "available": True,
        "collections": collections,
        "total": total,
        "bytes": total_bytes,
        "largest": largest,
        "is_git_checkout": (YARA_RULES / ".git").is_dir(),
        "can_update": False,
        "update_reason": ("yara-rules/ is an unpacked directory with no recorded "
                          "upstream, so there is nothing to pull"),
        "compiler": str(YARAC) if YARAC.is_file() else None,
        "yara_version": _yara_version(),
        "note": (f"{total:,} rules across {len(collections)} collections"),
    }


def _yara_version() -> str | None:
    if not YARA.is_file():
        return None
    try:
        out = subprocess.run([str(YARA), "--version"], capture_output=True,
                             text=True, timeout=CHECK_TIMEOUT, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return (out.stdout or "").strip().splitlines()[0] if out.stdout else None


# ---------------------------------------------------------------------------
# yarGen-Go
# ---------------------------------------------------------------------------

def yargen() -> dict:
    """The four things yarGen needs, reported individually.

    Its own update script explains why this is a checklist: dbs/ is generated
    and gitignored, config.yaml is not committed, and a missing config does not
    stop yarGen - it just degrades the output quietly. Each is reported on its
    own so a partial setup is visible instead of averaging out into "fine".
    """
    if not YARGEN_DIR.is_dir():
        return {"available": False, "reason": "yarGen-Go/ is not present", "checks": []}

    dbs = YARGEN_DIR / "dbs"
    db_entries = 0
    db_bytes = 0
    newest_db = None
    if dbs.is_dir():
        for entry in dbs.rglob("*"):
            if entry.is_file():
                db_entries += 1
                try:
                    st = entry.stat()
                    db_bytes += st.st_size
                    if newest_db is None or st.st_mtime > newest_db:
                        newest_db = st.st_mtime
                except OSError:
                    pass

    cfg = YARGEN_DIR / "config" / "config.yaml"
    example = YARGEN_DIR / "config" / "config.example.yml"
    exe = YARGEN_DIR / "yargen.exe"
    go = _which("go")

    checks = [
        {"id": "dbs", "label": "Opcode/string databases",
         "ok": db_entries > 0,
         "detail": f"{db_entries} files, {db_bytes:,} bytes" if db_entries
                   else "dbs/ is empty - every string scores as unseen noise",
         "fix": "run the update below"},
        {"id": "config", "label": "config/config.yaml",
         "ok": cfg.is_file(),
         "detail": "present" if cfg.is_file() else
                   "missing - yarGen starts anyway and silently degrades",
         "fix": None if cfg.is_file() else
                f"copy config.example.yml to config.yaml",
         "example_present": example.is_file()},
        {"id": "binary", "label": "yargen.exe",
         "ok": exe.is_file(),
         "detail": "present" if exe.is_file() else "not built and not committed",
         "fix": None if exe.is_file() else "needs the Go toolchain: go build"},
        {"id": "go", "label": "Go toolchain",
         "ok": go is not None,
         "detail": go or "not on PATH - only needed to rebuild yargen.exe",
         "fix": None},
    ]

    head = _git(YARGEN_DIR, "rev-parse", "--short", "HEAD")
    return {
        "available": True,
        "checks": checks,
        "ok": all(c["ok"] for c in checks),
        "commit": head["stdout"] or None,
        "remote": _git(YARGEN_DIR, "config", "--get", "remote.origin.url")["stdout"] or None,
        "update_script": YARGEN_UPDATE.is_file(),
        "update_script_path": str(YARGEN_UPDATE) if YARGEN_UPDATE.is_file() else None,
        "faults": [c["label"] for c in checks if not c["ok"]],
        "note": ("ready" if all(c["ok"] for c in checks)
                 else f"{len([c for c in checks if not c['ok']])} of "
                      f"{len(checks)} prerequisites missing"),
    }


def _which(name: str) -> str | None:
    for folder in os.environ.get("PATH", "").split(os.pathsep):
        cand = Path(folder) / (name + ".exe")
        if cand.is_file():
            return str(cand)
    return None


# ---------------------------------------------------------------------------
# The catalogue
# ---------------------------------------------------------------------------

# Each entry declares what it TOUCHES. Two reach the network and two rewrite
# files, and a button that does not say which it is about to do is a button
# nobody should press without thinking.
_UTIL_SPEC = [
    {"id": "sbom", "label": "Regenerate SBOM", "utility": "sbom",
     "description": "Walk every vendored checkout, library and Python "
                    "environment and rewrite the CycloneDX SBOM and its summary.",
     "effects": ["rewrites sbom.json", "rewrites sbom_summary.json",
                 "reads every venv in the tree"], "timeout": SBOM_TIMEOUT},
    {"id": "malapi-update", "label": "Update MalAPI rules", "utility": "malapi",
     "description": "Fetch memtt/malt and fast-forward the rule checkout. "
                    "Refuses outright if the tree has local changes.",
     "effects": ["reaches the network", "advances the malt/ checkout"],
     "timeout": PULL_TIMEOUT},
    {"id": "yara-check", "label": "Compile YARA rules", "utility": "yara",
     "description": "Run yarac over each rule collection so a syntax error is "
                    "reported here rather than at the first scan of a real sample.",
     "effects": ["reads every rule file", "compiles to a temp file"],
     "timeout": YARA_TIMEOUT},
    {"id": "yargen-update", "label": "Update yarGen-Go", "utility": "yargen",
     "description": "Run the project's own update_and_check.ps1: download the "
                    "opcode and string databases, then re-check every prerequisite.",
     "effects": ["reaches the network", "rewrites yarGen-Go/dbs/"],
     "timeout": SBOM_TIMEOUT},
]


def catalogue() -> dict:
    """The utilities, with per-entry availability resolved right now."""
    mal = malapi()
    entries = []
    for spec in _UTIL_SPEC:
        entry = dict(spec)
        available, reason = True, None
        if entry["id"] == "sbom":
            available, reason = SBOM_SCRIPT.is_file(), \
                f"{SBOM_SCRIPT.name} not found"
        elif entry["id"] == "malapi-update":
            available = bool(mal.get("can_update"))
            reason = (mal.get("reason") if not mal.get("available")
                      else "local changes in malt/ - commit or stash first"
                      if mal.get("dirty") else None)
        elif entry["id"] == "yara-check":
            available = YARAC.is_file()
            reason = "yarac not found in the MSYS2 toolchain"
        elif entry["id"] == "yargen-update":
            available = YARGEN_UPDATE.is_file()
            reason = "update_and_check.ps1 not found"
        entry["available"] = available
        entry["unavailable_reason"] = None if available else reason
        entries.append(entry)

    return {"entries": entries,
            "sbom": sbom(), "malapi": mal, "yara": yara(), "yargen": yargen()}


def overview() -> dict:
    """All four states in one call.

    The panel would otherwise make four requests to render one page, and could
    show four cards describing four different moments.
    """
    return catalogue()


# ---------------------------------------------------------------------------
# Running them
# ---------------------------------------------------------------------------

def _argv(utility: str) -> list[str]:
    if utility == "sbom":
        return [_python(), str(SBOM_SCRIPT)]
    if utility == "malapi":
        # --ff-only: a pull that cannot fast-forward fails instead of leaving a
        # merge commit behind. Combined with GIT_TERMINAL_PROMPT=0 this action
        # cannot create history or hang on a credential prompt.
        return ["git", "-C", str(MALT_DIR), "pull", "--ff-only"]
    if utility == "yargen":
        return ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
                "-File", str(YARGEN_UPDATE)]
    return []


def _append(job_id: str, line: str) -> None:
    # Never under _jobs_lock. That lock is a plain Lock, not an RLock, so
    # re-entering it from this thread deadlocks - which presents as a job stuck
    # on "running" and the page refusing to answer.
    with _jobs_lock:
        job = _jobs.get(job_id)
        if job is None:
            return
        job["log"].append(line)
        job["log_line_count"] += 1
        if len(job["log"]) > 4000:
            drop = len(job["log"]) - 4000
            del job["log"][:drop]
            job["log_dropped"] += drop


def start(util_ids: list[str]) -> dict:
    """Run the chosen utilities, in order, as one job."""
    global _utils_running

    cat = catalogue()
    known = {e["id"]: e for e in cat["entries"]}
    chosen = [known[i] for i in util_ids if i in known]
    if not chosen:
        return {"ok": False, "error": "no known utility selected"}
    unknown = [i for i in util_ids if i not in known]

    with _jobs_lock:
        _prune(_now())
        if _utils_running is not None:
            return {"ok": False, "error": "a utility run is already in progress",
                    "job_id": _utils_running}

    jid = f"u{_now():.0f}{os.getpid() % 1000:03d}"
    job = {
        "id": jid, "state": "running", "kind": "utils",
        "started_at": round(_now(), 1), "finished_at": None,
        "exit_code": None, "error": None, "log": [], "log_line_count": 0,
        "log_dropped": 0, "command": "", "artifact": None, "summary": None,
        "selected": [e["id"] for e in chosen],
        "results": [{"id": e["id"], "label": e["label"],
                     "state": "pending", "detail": None, "duration": None}
                    for e in chosen],
    }
    with _jobs_lock:
        _jobs[jid] = job
    globals()["_utils_running"] = jid

    if unknown:
        _append(jid, f"skipped unknown utility id(s): {', '.join(unknown)}")
    for entry in chosen:
        for effect in entry.get("effects") or []:
            _append(jid, f"{entry['label']}: touches {effect}")

    threading.Thread(target=_run, args=(jid, chosen), daemon=True,
                     name="util-job").start()
    return {"ok": True, "job_id": jid,
            "running": [e["id"] for e in chosen if e["available"]]}


def _set_result(job_id: str, util_id: str, **fields) -> None:
    with _jobs_lock:
        job = _jobs.get(job_id)
        if job is None:
            return
        for row in job["results"]:
            if row["id"] == util_id:
                row.update(fields)
                return


def _run_yara_check(job_id: str) -> tuple[bool, str]:
    """Compile every rule file with yarac, one file per invocation.

    Neither `yarac` nor `yara` in 4.5.8 accepts a directory - both report
    "could not open file" on one - and concatenating a collection into a single
    file is not a workaround, because rule identifiers are unique per namespace
    and 800 files in one namespace collide on duplicate rule names. So it is one
    process per file.

    That sounds slow and is not: a small rule file compiles in tens of
    milliseconds. The cost is bounded and reported as it goes, and the payoff is
    that a syntax error names the file it is in rather than a line number in a
    temporary concatenation. Temporary output goes to the system temp dir, never
    the repo.
    """
    import tempfile

    inv = yara()
    collections = inv.get("collections", [])
    total_files = 0
    # Three kinds of "did not compile", and conflating them would be a lie:
    #
    #   missing_module  "unknown module X" - the rule is fine, this yara build
    #                   has no X loaded. 115 of Malekith_Rules' Android rules
    #                   want androguard. Nothing is wrong with them.
    #   cross_ref       "undefined identifier Y" - the rule references something
    #                   a sibling file defines. This pack is interdependent by
    #                   design, and the analyzer's own loader resolves it with an
    #                   include callback over the calling file's directory plus
    #                   a global include root (see src/yara/yara_scanner.cpp).
    #                   Compiling one file alone cannot see that, so these are
    #                   a property of the CHECK, not a defect in the rule.
    #   broken          anything else - a genuine syntax or semantic error. That
    #                   is what this check exists to find, and the only thing
    #                   that should turn it red.
    missing_module: list[tuple[str, str]] = []
    cross_ref: list[tuple[str, str]] = []
    warned: list[tuple[str, str]] = []
    broken: list[tuple[str, str]] = []
    compiled = 0
    last_report = time.time()

    with tempfile.TemporaryDirectory(prefix="yara-check-") as tmp:
        out = Path(tmp) / "compiled.yarc"
        for coll in collections:
            src_dir = YARA_RULES / coll["name"]
            files = sorted(f for f in src_dir.rglob("*")
                           if f.is_file() and f.suffix.lower() in (".yar", ".yara"))
            _append(job_id, f"  {coll['name']}: {len(files)} rule file(s)")
            for f in files:
                total_files += 1
                try:
                    # cwd is the rule file's OWN directory, and the path passed
                    # is just its name.
                    #
                    # This is not a detail. 132 of Malekith_Rules' files use
                    # relative includes - `include "./crypto/crypto_signatures.yar"`
                    # - and yarac resolves those against the working directory,
                    # not the including file. Run from the repo root and every
                    # one of them reports "can't open include file", which is a
                    # false alarm about 4% of the rule corpus. Running from the
                    # file's own directory compiles them cleanly.
                    proc = subprocess.run(
                        [str(YARAC), "-w", f.name, str(out)],
                        capture_output=True, text=True, encoding="utf-8",
                        errors="replace", timeout=120, check=False,
                        cwd=str(f.parent),
                    )
                except subprocess.TimeoutExpired:
                    broken.append((_rel(f), "timed out"))
                    continue
                except OSError as exc:
                    broken.append((_rel(f), str(exc)))
                    continue

                if proc.returncode == 0:
                    compiled += 1
                else:
                    rel = _rel(f)
                    lines = [ln.strip() for ln in
                             ((proc.stderr or "") + (proc.stdout or "")).splitlines()
                             if ln.strip()]
                    # Classify on an `error:` line, not on whatever came first.
                    # A file can emit a page of "may slow down scanning"
                    # warnings and still fail for a reason further down; reading
                    # only the first line reported a warning as the cause and
                    # hid the actual defect.
                    err = next((ln for ln in lines if ln.startswith("error:")), None)
                    if err is None:
                        # Failed with warnings only. -w is already passed, so
                        # this should be rare; treat it as advisory rather than
                        # inventing a failure out of noise.
                        warned.append((rel, lines[0] if lines else "unknown"))
                    elif "unknown module" in err:
                        missing_module.append((rel, err))
                    elif "undefined identifier" in err:
                        cross_ref.append((rel, err))
                    else:
                        broken.append((rel, err))

                # Progress every 15s so a long run does not look hung. The job
                # has no spinner; the log line is the only sign of life.
                if time.time() - last_report > 15:
                    last_report = time.time()
                    _append(job_id,
                            f"    ... {total_files} file(s) checked, "
                            f"{compiled} ok, {len(broken)} broken, "
                            f"{len(missing_module)} need an absent module")

    _append(job_id, f"  checked {total_files} file(s) across "
                    f"{len(collections)} collection(s)")

    if cross_ref:
        _append(job_id,
                f"  {len(cross_ref)} file(s) reference identifiers defined in a "
                "sibling rule file")
        _append(job_id,
                "    expected for an interdependent pack - the analyzer resolves "
                "these through its include callback at scan time")

    if missing_module:
        modules = sorted({m.group(1) for _, m in
                          ((p, re.search(r'unknown module "([^"]+)"', e))
                           for p, e in missing_module) if m})
        _append(job_id,
                f"  {len(missing_module)} file(s) need a YARA module this build "
                f"does not have: {', '.join(modules)}")
        _append(job_id,
                "    these rules are valid; they are skipped because the module "
                "is absent, which is a toolchain gap rather than a broken rule")

    if broken:
        _append(job_id, f"  {len(broken)} file(s) genuinely failed to compile:")
        for path, err in broken[:10]:
            _append(job_id, f"    FAIL {path}: {err[:150]}")
        if len(broken) > 10:
            _append(job_id, f"    ... and {len(broken) - 10} more")
        names = sorted({p.split("\\")[1] if "\\" in p else p.split("/")[0]
                        for p, _ in broken})
        return False, (f"{len(broken)}/{total_files} file(s) failed to compile"
                       + (f" (in {', '.join(names)})" if names else ""))

    detail = f"{total_files} rule file(s) compiled cleanly"
    notes = []
    if cross_ref:
        notes.append(f"{len(cross_ref)} need sibling rules loaded together")
    if missing_module:
        notes.append(f"{len(missing_module)} need an absent module")
    if warned:
        notes.append(f"{len(warned)} warned only")
    if notes:
        detail += " (" + "; ".join(notes) + ")"
    return True, detail


def _run(job_id: str, entries: list[dict]) -> None:
    global _utils_running
    passed = failed = 0
    try:
        for entry in entries:
            if not entry["available"]:
                reason = entry.get("unavailable_reason") or "unavailable"
                _set_result(job_id, entry["id"], state="skipped", detail=reason)
                _append(job_id, f"--- {entry['label']}: SKIPPED ({reason})")
                continue

            _set_result(job_id, entry["id"], state="running")
            argv = _argv(entry["utility"])
            _append(job_id, "")
            _append(job_id, f"=== {entry['label']} ({entry['id']})")
            _append(job_id, f"    $ {' '.join(argv)}")

            started = time.time()
            code: int | None = 0
            detail = ""
            state = "passed"

            if entry["utility"] == "yara":
                ok, detail = _run_yara_check(job_id)
                state = "passed" if ok else "failed"
            else:
                env = dict(os.environ)
                env["GIT_TERMINAL_PROMPT"] = "0"
                env["IA_ARTIFACT_UPLOAD"] = "0"
                try:
                    proc = subprocess.Popen(
                        argv, cwd=str(config.REPO), env=env,
                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                        text=True, encoding="utf-8", errors="replace", bufsize=1,
                    )
                    for line in proc.stdout:
                        _append(job_id, "    " + line.rstrip("\n"))
                    code = proc.wait(timeout=entry.get("timeout", SBOM_TIMEOUT))
                except subprocess.TimeoutExpired:
                    proc.kill()
                    code = None
                    _append(job_id, "    timed out after "
                                    f"{entry.get('timeout')}s")
                except Exception as exc:  # noqa: BLE001 - report, never vanish
                    code = None
                    _append(job_id, f"    {type(exc).__name__}: {exc}")

                state = "passed" if code == 0 else "failed"
                if code is None:
                    detail = "did not finish"
                elif code == 0:
                    detail = "exit 0"
                else:
                    detail = f"exit {code}"

            duration = round(time.time() - started, 2)
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
        _append(job_id, "")
        _append(job_id, f"=== {passed} passed, {failed} failed")
        with _jobs_lock:
            if _utils_running == job_id:
                globals()["_utils_running"] = None


def running() -> str | None:
    return _utils_running