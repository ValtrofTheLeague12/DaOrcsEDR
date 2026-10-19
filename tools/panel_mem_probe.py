"""Find the panel's memory growth by exercising it the way the dashboard does.

A leak is a property of the sequence of requests, not of any one handler, so
looking at handlers one at a time is how leaks stay hidden. This walks the same
endpoint set the React app polls, in a loop, and reports the server's RSS after
each round so a steadily rising line is obvious.

Usage: python panel_mem_probe.py <base_url> [rounds]
"""
from __future__ import annotations

import json
import sys
import time
import urllib.error
import urllib.request

# What admin-web polls. Chosen from api.ts rather than from the route table:
# the leak only reproduces for pages somebody actually opens.
ENDPOINTS = [
    "/api/health",
    "/api/stats",
    "/api/overview",
    "/api/system",
    "/api/network",
    "/api/services",
    "/api/logs?lines=200",
    "/api/artifacts?remote_root=%2F",
    "/api/containers",
    "/api/vms",
    "/api/vmmetrics",
    "/api/qiling",
    "/api/analysis/config",
    "/api/docs",
]


def rss_kb(pid: int) -> int | None:
    """Resident set size, via psutil if present and via /proc on Linux."""
    try:
        import psutil  # type: ignore
        return int(psutil.Process(pid).memory_info().rss // 1024)
    except Exception:
        pass
    try:
        with open(f"/proc/{pid}/status", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1])
    except OSError:
        pass
    return None


def hit(url: str, timeout: float = 30.0) -> int:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            body = r.read()
            return len(body)
    except urllib.error.HTTPError as e:
        e.read()
        return -1
    except Exception:
        return -2


def main() -> int:
    base = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:60100"
    rounds = int(sys.argv[2]) if len(sys.argv) > 2 else 6
    pid = int(sys.argv[3]) if len(sys.argv) > 3 else 0

    print(f"target: {base}")
    print(f"endpoints: {len(ENDPOINTS)}")
    print()
    print(f"{'round':>5}  {'RSS MB':>8}  {'delta MB':>9}  {'bytes served':>13}")
    baseline = None
    for r in range(1, rounds + 1):
        served = 0
        for path in ENDPOINTS:
            served += max(0, hit(base + path))
        time.sleep(0.5)
        cur = rss_kb(pid) if pid else None
        if cur is None:
            print(f"{r:>5}  {'n/a':>8}  {'':>9}  {served:>13,}")
            continue
        mb = cur / 1024
        if baseline is None:
            baseline = mb
        print(f"{r:>5}  {mb:>8.1f}  {mb - baseline:>9.1f}  {served:>13,}")
    return 0


if __name__ == "__main__":
    sys.exit(main())