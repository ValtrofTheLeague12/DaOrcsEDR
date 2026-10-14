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

from . import config

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
    ("repo", "Analyzer", config.REPO / "logs", "*.log", None),
    # trace.txt is a .txt and is the largest file in the tree (~79 MB, still
    # growing, no rotation). It needs its own entry or it is invisible.
    ("repo-trace", "Analyzer trace", config.REPO / "logs", "*.txt", None),
    ("repo-jsonl", "Analyzer JSONL", config.REPO / "logs", "*.jsonl", None),
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