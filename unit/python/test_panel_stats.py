from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "python"))

from panel.host import stats  # noqa: E402


def test_runstats_reuses_recent_filesystem_scan(monkeypatch):
    payload = {"count": 3, "artifacts": 8}
    scans = []

    def scan():
        scans.append(True)
        return payload

    monkeypatch.setattr(stats, "_runstats_cache", {"at": 0.0, "payload": None})
    monkeypatch.setattr(stats, "_runstats_uncached", scan)

    assert stats._runstats() is payload
    assert stats._runstats() is payload
    assert len(scans) == 1
