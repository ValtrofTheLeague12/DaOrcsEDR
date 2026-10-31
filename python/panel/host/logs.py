"""Every log the project writes, in one list.

This exists because admin-terminal's logview.py caps its own enumeration: the
admin group is sliced to the 5 newest files out of the 30 present, so 25 of
them cannot be opened from the UI at all. There is no override and no way to
reach the rest.

Nothing here re-implements logview. It enumerates the same five locations from
disk - it just does not throw the rest away.

Tail reads BACKWARD from EOF in growing blocks. That is not an optimisation:
logs/trace.txt is 76 MB and still growing with no rotation, so reading it
forward to show the last 40 lines would pull the whole file through the
panel for nothing.
"""

from __future__ import annotations

import os
import re
import time
from pathlib import Path

from ..core import config

# The admin terminal captures child stdout with its SGR colour codes intact -
# qiling_setup.py in particular writes lines like "\x1b[94m[=)]\x1b[39m ...".
# A browser would render those as literal "[94m" text, so they are stripped here
# rather than shipped and cleaned client-side. The viewer applies its own
# semantic colouring from the log content instead.
_ANSI = re.compile(r"\x1b\[[0-9;?]*[a-zA-Z]")

# (key, label, directory, glob, max files per location or None for no cap)
#
# `None` means no cap, deliberately. The cap is the bug being fixed; any
# number here would reintroduce it somewhere new.
SOURCES: list[tuple[str, str, Path, str, int | None]] = [
    # The analyzer's own logs live under the AppData root now, so it can be run
    # from anywhere without leaving a log tree in whatever directory it was
    # started from. `repo` is kept as a source too: an older tree from before
    # the move, or a run with IA_APPDATA_DIR pointed elsewhere, and silently
    # not showing the operator their crash dumps would be worse than a
    # duplicate line.
    ("appdata", "Analyzer", config.logs_dir(), "*.log", None),
    # trace.txt is a .txt and is the largest file in the tree (~79 MB, still
    # growing, no rotation). It needs its own entry or it is invisible.
    ("appdata-trace", "Analyzer trace", config.logs_dir(), "*.txt", None),
    ("appdata-jsonl", "Analyzer JSONL", config.logs_dir(), "*.jsonl", None),
    ("repo", "Analyzer (pre-AppData)", config.REPO / "logs", "*.log", None),
    ("repo-trace", "Analyzer trace (pre-AppData)", config.REPO / "logs", "*.txt", None),
    ("repo-jsonl", "Analyzer JSONL (pre-AppData)", config.REPO / "logs", "*.jsonl", None),
    ("admin", "Admin terminal", config.ADMIN_TERMINAL / "logs", "*.log", None),
    ("py", "Python API", config.REPO / "python" / "logs", "*.log", None),
    ("py-jsonl", "Python API JSONL", config.REPO / "python" / "logs", "*.jsonl", None),
    ("qiling", "Qiling service", config.REPO / "config" / "systemd" / "qilin-service",
     "*.log", None),
    ("qiling-artifacts", "Qiling artifacts",
     config.REPO / "config" / "systemd" / "qilin-service" / "artifacts", "*.log", None),
    ("clamd", "ClamAV results", config.REPO / "python" / "clamd" / "results", "*.json", None),
    ("qiling-dlls", "Qiling run output", config.REPO / "qiling_dlls" / "results",
     "*.zip", None),
]

# Deliberately NOT listed: yara_rules_*.cache (13-19 MB each, rule caches) and
# *.errors. They sit in logs/ but are not runtime logs, and surfacing two
# 19 MB binaries in a log browser helps nobody.

# Files that are never logs but share a directory with them.
_SKIP_SUFFIX = {".tar.gz", ".dmp", ".cache", ".errors"}


def _age(path: Path) -> float:
    try:
        return time.time() - path.stat().st_mtime
    except OSError:
        return 0.0


def _kind(group: str, path: Path) -> str:
    """Coarse file type, so the viewer can split traces out without guessing.

    `.txt` is treated as a trace regardless of which directory it came from -
    the analyzer's trace.txt is 79 MB and must never be handed to the log
    viewer's generic path by accident.
    """
    suffix = path.suffix.lower()
    if group == "repo-trace" or suffix == ".txt":
        return "trace"
    if suffix in (".jsonl", ".json"):
        return "jsonl"
    if suffix == ".log":
        return "log"
    return "other"


def _entry(path: Path, root: Path, group: str) -> dict:
    try:
        stat = path.stat()
        size, mtime = stat.st_size, stat.st_mtime
    except OSError:
        size, mtime = 0, 0.0
    return {
        # Opaque, server-mangled id. The client never sees a path it can put
        # in a request, so traversal is not expressible.
        "id": _id_for(root, path),
        "group": group,
        "name": path.name,
        "kind": _kind(group, path),
        "bytes": size,
        "modified": mtime,
        "age_seconds": round(_age(path)),
    }


def _id_for(root: Path, path: Path) -> str:
    try:
        rel = path.relative_to(root).as_posix()
    except ValueError:
        rel = path.name
    return f"{abs(hash((str(root), rel))) & 0xFFFFFFFF:08x}{rel}"


def _resolve(key: str) -> tuple[Path, Path] | None:
    """Map an opaque id back to a path, re-reading from SOURCES every time.

    The id is not a stable authorisation token - it is rebuilt each call from
    the live directory listing, so an id for a file that no longer exists (or
    never did) resolves to nothing.
    """
    for group, _label, root, pattern, cap in SOURCES:
        if not root.is_dir():
            continue
        try:
            candidates = sorted(root.glob(pattern))
        except OSError:
            continue
        for path in candidates:
            if not path.is_file():
                continue
            if _id_for(root, path) == key:
                return root, path
    return None


def list_logs() -> dict:
    """Every log found, grouped, newest first within each group."""
    groups: dict[str, dict] = {}
    total = 0
    total_bytes = 0

    for key, label, root, pattern, cap in SOURCES:
        entry = {"key": key, "label": label, "path": str(root), "present": root.is_dir(),
                 "files": []}
        if root.is_dir():
            try:
                candidates = [p for p in sorted(root.glob(pattern)) if p.is_file()]
            except OSError:
                candidates = []
            files = [_entry(p, root, key) for p in candidates]
            files.sort(key=lambda f: f["modified"], reverse=True)
            if cap is not None:
                files = files[:cap]
            entry["files"] = files
            total += len(files)
            total_bytes += sum(f["bytes"] for f in files)
        groups[key] = entry

    return {
        "groups": list(groups.values()),
        "file_count": total,
        "total_bytes": total_bytes,
        "note": "No cap is applied. admin-terminal's logview caps its admin group "
                "at 5 files, which hides most of what is on disk.",
    }


def tail(key: str, lines: int = 80, max_bytes: int = 512 * 1024) -> dict:
    """Last N lines of one log, read backward from EOF."""
    lines = max(1, min(int(lines), 2000))
    resolved = _resolve(key)
    if resolved is None:
        return {"error": "unknown log id", "lines": []}

    root, path = resolved
    try:
        size = path.stat().st_size
    except OSError as exc:
        return {"error": f"{type(exc).__name__}: {exc}", "lines": []}

    if size == 0:
        return {"id": key, "name": path.name, "bytes": 0,
                "lines": [], "empty": True, "ansi_stripped": 0,
                "jsonl": path.suffix == ".jsonl"}

    # Walk backwards in growing blocks until we have enough newlines or hit
    # the byte ceiling, then decode only that slice.
    want = lines
    chunk = 8192
    data = b""
    with path.open("rb") as fh:
        pos = size
        while pos > 0 and data.count(b"\n") < want and len(data) < max_bytes:
            read_size = min(chunk, pos)
            pos -= read_size
            fh.seek(pos)
            data = fh.read(read_size) + data
            chunk = min(chunk * 2, 256 * 1024)
        fh.seek(0, os.SEEK_END)
        total = fh.tell()

    text = data.decode("utf-8", "replace")
    stripped = len(_ANSI.findall(text))
    text = _ANSI.sub("", text)
    out = text.splitlines()
    truncated = pos > 0
    if len(out) > want:
        out = out[-want:]
        truncated = True

    return {
        "id": key,
        "name": path.name,
        "path": str(path.relative_to(root)) if path.is_relative_to(root) else path.name,
        "bytes": total,
        "lines": out,
        "truncated": truncated,
        "returned": len(out),
        # Reported so the viewer can say so rather than silently dropping data.
        "ansi_stripped": stripped,
        "jsonl": path.suffix == ".jsonl" or path.name.endswith(".json"),
    }


# ---------------------------------------------------------------------------
# Trace summary.
#
# Trace output is a different animal from the rest of the logs and deserves its
# own panel for the same reason it deserves its own parser: it is enormous,
# append-only, unrotated, and nobody opens it to read lines. They open it to
# answer a question - how many runs, how many failed, which stage ate the time -
# and reading 79 MB to answer that is not a workflow.
#
# So this computes the answer over a bounded tail and returns numbers, leaving
# the raw lines for the viewer beside it. Bounded is the important word: the
# summary is derived from the same backward window `tail` already reads, so it
# can never cost more than the view next to it.
# ---------------------------------------------------------------------------

_LEVEL = re.compile(
    r"\b(TRACE|DEBUG|INFO|NOTICE|WARN|WARNING|ERROR|FATAL|CRITICAL|CRIT|PANIC)\b")
_BRACKET_TIME = re.compile(r"\[(\d{2})/(\w{3})/(\d{4})(?::(\d{2}):(\d{2}):(\d{2}))?")
_ISO_TIME = re.compile(r"(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2})")
_LEVEL_TONE = {
    "error": "danger", "err": "danger", "fatal": "danger", "critical": "danger",
    "crit": "danger", "panic": "danger", "warn": "warning", "warning": "warning",
    "notice": "warning", "info": "accent", "information": "accent",
    "debug": "muted", "trace": "muted", "verbose": "muted",
}


def _minute_key(line: str) -> str | None:
    """Coarse timestamp bucket, or None when the line carries no time.

    A minute is the right resolution for a run log: it separates the phases of
    one build without pretending to know when a single syscall happened.
    """
    m = _BRACKET_TIME.search(line)
    if m:
        return f"{m.group(3)}-{m.group(2)}-{m.group(1)} {m.group(4) or '00'}:{m.group(5) or '00'}"
    m = _ISO_TIME.search(line)
    if m:
        return f"{m.group(1)}-{m.group(2)}-{m.group(3)} {m.group(4)}:{m.group(5)}"
    return None


def summary(key: str, lines: int = 2000) -> dict:
    """Counts, level split and a per-minute histogram over a bounded tail."""
    # Not named `tail`: that would shadow the module-level function this call
    # needs on the very next line.
    window = tail(key, lines)
    if window.get("error"):
        return {"error": window["error"], "levels": {}, "timeline": [],
                "sources": [], "total": 0}

    rows: list[str] = window.get("lines") or []
    levels: dict[str, int] = {}
    timeline: dict[str, int] = {}
    sources: dict[str, int] = {}

    for line in rows:
        hit = _LEVEL.search(line)
        if hit:
            name = hit.group(1).lower()
            levels[name] = levels.get(name, 0) + 1
        bucket = _minute_key(line)
        if bucket:
            timeline[bucket] = timeline.get(bucket, 0) + 1
        # The logger name, where there is one: "ml.serve:", "[=)", "module.name".
        m = re.match(r"^[\s\dT:,.\-+]*\[?([A-Za-z_][\w.]*)\]?:", line)
        if m and m.group(1) not in ("http", "https"):
            sources[m.group(1)] = sources.get(m.group(1), 0) + 1

    # Sorted by time, and capped, so the chart never gets a thousand bars.
    buckets = sorted(timeline.items())
    if len(buckets) > 48:
        buckets = buckets[-48:]

    return {
        "id": key,
        "name": window.get("name"),
        "sampled_lines": len(rows),
        "truncated": bool(window.get("truncated")),
        "bytes": window.get("bytes"),
        "total": len(rows),
        "levels": dict(sorted(levels.items(), key=lambda kv: -kv[1])),
        "timeline": [{"minute": k, "count": v} for k, v in buckets],
        "sources": [{"name": k, "count": v}
                    for k, v in sorted(sources.items(), key=lambda kv: -kv[1])[:8]],
        "tones": {name: _LEVEL_TONE.get(name, "default") for name in levels},
    }