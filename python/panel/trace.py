"""Metrics derived from the C++ analyzer's trace output.

Separate from logs.py because trace.txt is not a log. It is a spdlog call-graph
dump from the native extractor, and every generic-log assumption is false for
it: there are no levels, no logger names and no wall-clock timestamps, and the
lines are not even text in the ordinary sense - one run embeds raw binary
alongside the records, which is why the reader here works on bytes and replaces
anything undecodable rather than raising.

The shape, sampled rather than assumed:

    [trace]  85325.749 ms | depth=01 | ENTER | void f(int) | addr=0x7FF6 | size=112
    [trace]  85325.749 ms | depth=01 | LEAVE | void f(int) | duration=2.600 us (0.000003 s)
    [memory] process shutdown
    === Memory Info ===
    Working Set Size        :  247697408 B  (  236.22 MiB)

So the useful questions are not "what went wrong" but "how deep did it nest, how
long did it take, which symbols dominate, what did it cost in memory" - and none
of those are answerable by scanning the file with a level regex.

Bounded reads only. trace.txt is ~80 MB, append-only and unrotated, so this
walks BACKWARD from EOF in growing blocks exactly like logs.tail does, and never
reads the whole file no matter how large it grows.
"""

from __future__ import annotations

import os
import re
import time
from pathlib import Path

from . import logs

# Backward read window for the aggregate. Larger than a log tail on purpose:
# a 2000-line window of a 300k-events-per-run trace is a rounding error, and
# percentiles computed from it are noise dressed as statistics. 8 MB is roughly
# a quarter-million events and costs well under a frame of I/O.
_WINDOW_BYTES = 8 * 1024 * 1024

# A single spdlog record. The signature can contain spaces, commas, angle
# brackets and `::`, so it is matched lazily up to the next known key rather
# than by splitting on `|`.
_RECORD = re.compile(
    r"^\[(?P<channel>[a-z][a-z0-9_]*)\]\s+"
    r"(?P<ms>\d+(?:\.\d+)?)\s*ms\s*\|\s*"
    r"depth=(?P<depth>\d+)\s*\|\s*"
    r"(?P<kind>ENTER|LEAVE)\s*\|\s*"
    r"(?P<sig>.+?)\s*\|\s*"
    r"(?P<tail>.*)$"
)

# `duration=2.600 us (0.000003 s)` and the ms-only variants that show up when
# spdlog's precision setting is in seconds.
_DURATION = re.compile(r"duration=(?P<num>\d+(?:\.\d+)?)\s*(?P<unit>ns|us|ms|s)\b")

_MEMORY_FIELD = re.compile(r"^(?P<label>[A-Za-z][A-Za-z0-9 /%]*?)\s*:\s*(?P<value>.*)$")

_UNIT_MS = {"ns": 1e-6, "us": 1e-3, "ms": 1.0, "s": 1000.0}


def _read_backward(path: Path, max_bytes: int = _WINDOW_BYTES) -> tuple[str, int, bool]:
    """Last `max_bytes` of the file as text. Returns (text, total_size, clipped).

    The same doubling block read logs.tail uses, for the same reason: reading a
    80 MB file forward to show its end would pull the whole thing through the
    panel.
    """
    try:
        size = path.stat().st_size
    except OSError:
        return "", 0, False
    if size == 0:
        return "", 0, False

    data = b""
    with path.open("rb") as fh:
        pos = size
        chunk = 65536
        while pos > 0 and len(data) < max_bytes:
            read_size = min(chunk, pos)
            pos -= read_size
            fh.seek(pos)
            data = fh.read(read_size) + data
            chunk = min(chunk * 2, 1024 * 1024)

    text = data.decode("utf-8", "replace")
    # A backward read almost always starts mid-line; that fragment is not a
    # record and must not be counted as one.
    clipped = pos > 0
    if clipped:
        newline = text.find("\n")
        if newline >= 0:
            text = text[newline + 1:]
    return text, size, clipped


def _duration_ms(value: str) -> float | None:
    hit = _DURATION.search(value)
    if not hit:
        return None
    try:
        return float(hit.group("num")) * _UNIT_MS[hit.group("unit")]
    except (KeyError, ValueError):
        return None


def _signatures(sig: str) -> list[str]:
    """Reduce a template signature to its parts.

    `std::vector<extractor::(anonymous namespace)::overlay_magic_t, std::allocator<...> >::~vector()`
    tells you the instantiating type and the operation. Collapsed to one line it
    is unreadable, and grouped verbatim it is a unique key for every type in the
    binary - which is exactly how a "top symbols" list becomes a list of 40,000
    distinct entries.
    """
    head = re.split(r"[ (<]", sig.strip(), maxsplit=1)[0]
    return [part for part in (head, sig.strip()) if part]


def _percentile(values: list[float], pct: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int(round((pct / 100) * (len(ordered) - 1)))))
    return ordered[index]


def _parse_memory_block(lines: list[str]) -> dict:
    """Read the `=== Memory Info ===` table that follows a shutdown.

    Only the byte-denominated rows are converted. `Page Fault Count` and
    `Pagefile Usage %` sit in the same table but are a count and a percentage,
    and scaling them by 1024 because they are next to numbers that end in "B"
    would report 300,000 faults as 300 GB - which is precisely the kind of
    confident nonsense a metrics panel must not produce.
    """
    fields: dict[str, dict] = {}
    process_id = None
    for line in lines:
        if line.strip().startswith("Process ID"):
            _, _, value = line.partition(":")
            process_id = value.strip() or None
            continue
        hit = _MEMORY_FIELD.match(line)
        if not hit:
            continue
        label = hit.group("label").strip()
        raw = hit.group("value").strip()
        number = re.match(r"(\d+(?:\.\d+)?)\s*(B|KB|MB|GB|TB)?\b", raw)
        if not number:
            continue
        try:
            amount = float(number.group(1))
        except ValueError:
            continue

        unit = number.group(2)
        if "%" in label:
            fields[label] = {"percent": amount, "raw": raw}
            continue
        if "Count" in label:
            fields[label] = {"count": int(amount), "raw": raw}
            continue
        scale = {"B": 1, "KB": 1024, "MB": 1024 ** 2, "GB": 1024 ** 3,
                 "TB": 1024 ** 4}.get(unit or "B", 1)
        fields[label] = {"bytes": int(amount * scale), "raw": raw}

    if not fields:
        return {}
    return {"process_id": process_id, "fields": fields}


def analyze(key: str) -> dict:
    """Aggregate one trace file into numbers. Never raises."""
    resolved = logs._resolve(key)
    out: dict = {
        "available": False,
        "name": None,
        "bytes": 0,
        "events": 0,
        "malformed": 0,
        "channels": [],
        "depth": {"max": 0, "current": 0},
        "span": {"first_ms": None, "last_ms": None, "duration_ms": None},
        "kinds": {},
        "duration_ms": {"count": 0, "total": 0.0, "avg": None,
                        "p50": None, "p95": None, "max": None},
        "slowest": [],
        "symbols": [],
        "memory": {},
        "analyzed_at": round(time.time(), 1),
        "clipped": False,
        "error": None,
    }
    if resolved is None:
        out["error"] = "unknown log id"
        return out

    _root, path = resolved
    text, size, clipped = _read_backward(path)
    out["name"] = path.name
    out["bytes"] = size
    out["clipped"] = clipped
    if not text:
        out["error"] = "nothing readable in the read window"
        return out

    out["available"] = True
    channels: dict[str, int] = {}
    kinds: dict[str, int] = {}
    symbol_counts: dict[str, int] = {}
    durations: list[float] = []
    slowest: list[dict] = []
    depth_now = 0
    first_ms = last_ms = None

    for line in text.splitlines():
        if not line.startswith("["):
            continue
        hit = _RECORD.match(line)
        if not hit:
            out["malformed"] += 1
            continue

        out["events"] += 1
        channel = hit.group("channel")
        channels[channel] = channels.get(channel, 0) + 1
        kind = hit.group("kind")
        kinds[kind] = kinds.get(kind, 0) + 1

        try:
            depth = int(hit.group("depth"))
        except ValueError:
            depth = 0
        out["depth"]["max"] = max(out["depth"]["max"], depth)
        # ENTER pushes, LEAVE pops. Tracked so the panel can show current nesting
        # as well as the deepest it ever got; a run stuck deep in the stack at
        # the tail of the file is the interesting case.
        depth_now = depth_now + 1 if kind == "ENTER" else max(0, depth_now - 1)

        try:
            ms = float(hit.group("ms"))
        except ValueError:
            ms = None
        if ms is not None:
            if first_ms is None or ms < first_ms:
                first_ms = ms
            if last_ms is None or ms > last_ms:
                last_ms = ms

        sig = hit.group("sig").strip()
        short = _signatures(sig)[0]
        symbol_counts[short] = symbol_counts.get(short, 0) + 1

        value = _duration_ms(hit.group("tail"))
        if value is not None:
            durations.append(value)
            slowest.append({"signature": short, "depth": depth,
                            "duration_ms": round(value, 4)})

    out["depth"]["current"] = depth_now
    out["channels"] = [{"name": k, "count": v}
                       for k, v in sorted(channels.items(), key=lambda kv: -kv[1])]
    out["kinds"] = kinds
    out["span"] = {
        "first_ms": first_ms,
        "last_ms": last_ms,
        "duration_ms": round(last_ms - first_ms, 1)
        if first_ms is not None and last_ms is not None else None,
    }
    if durations:
        total = sum(durations)
        out["duration_ms"] = {
            "count": len(durations),
            "total": round(total, 3),
            "avg": round(total / len(durations), 4),
            "p50": _percentile(durations, 50),
            "p95": _percentile(durations, 95),
            "max": max(durations),
        }
    out["slowest"] = sorted(slowest, key=lambda d: -d["duration_ms"])[:12]
    out["symbols"] = [{"name": k, "count": v}
                      for k, v in sorted(symbol_counts.items(), key=lambda kv: -kv[1])[:12]]
    out["memory"] = _parse_memory_block(text.splitlines()[-200:])
    return out


if __name__ == "__main__":  # manual probe: `python -m python.panel.trace`
    import json

    listing = logs.list_logs()
    for group in listing["groups"]:
        for entry in group["files"]:
            if entry["kind"] == "trace":
                print(json.dumps(analyze(entry["id"]), indent=2))
                raise SystemExit(0)
    print("no trace file present")