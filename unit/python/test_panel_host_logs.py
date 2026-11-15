from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "python"))

from panel.host import logs  # noqa: E402


def test_log_tail_preserves_ansi_color_sequences(tmp_path, monkeypatch):
    log_path = tmp_path / "colored.log"
    log_path.write_text("\x1b[32mgreen\x1b[0m\n", encoding="utf-8")
    monkeypatch.setattr(
        logs, "SOURCES",
        [("test", "Test", tmp_path, "*.log", None)],
    )

    key = logs._id_for(tmp_path, log_path)
    result = logs.tail(key)

    assert result["lines"] == ["\x1b[32mgreen\x1b[0m"]
    assert result["ansi_stripped"] == 0
