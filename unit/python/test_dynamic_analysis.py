"""Dynamic-analysis policy: one transport, validated, persisted whole.

The page offers two radios and writes config/dynamic_analysis.json. What is
worth pinning here is the part a radio cannot show: the file is the contract,
an unknown value is refused rather than stored, and a missing file means the
documented default - not "no policy".
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "python"))

from panel import dynamic_analysis as da  # noqa: E402


@pytest.fixture()
def tree(tmp_path):
    return tmp_path


def test_missing_file_is_the_documented_default(tree):
    assert da.load(tree) == {"communication": "tcp"}
    snapshot = da.snapshot(tree)
    assert snapshot["exists"] is False
    assert snapshot["error"] is None
    assert snapshot["settings"] == {"communication": "tcp"}
    assert [o["id"] for o in snapshot["options"]] == ["tcp", "sftp"]
    assert [o["selected"] for o in snapshot["options"]] == [True, False]


def test_write_persists_and_round_trips(tree):
    da.write(tree, {"communication": "sftp"})
    path = tree / "config" / "dynamic_analysis.json"
    assert json.loads(path.read_text(encoding="utf-8")) == {
        "communication": "sftp"}
    assert da.load(tree) == {"communication": "sftp"}
    snapshot = da.snapshot(tree)
    assert snapshot["exists"] is True
    assert snapshot["modified"] is not None
    assert [o["selected"] for o in snapshot["options"]] == [False, True]


def test_unknown_transport_is_refused_and_the_file_untouched(tree):
    da.write(tree, {"communication": "sftp"})
    with pytest.raises(ValueError, match="communication"):
        da.write(tree, {"communication": "udp"})
    assert da.load(tree) == {"communication": "sftp"}


def test_unknown_key_is_refused(tree):
    with pytest.raises(ValueError, match="not a dynamic-analysis setting"):
        da.write(tree, {"network": True})


def test_a_malformed_file_is_reported_not_ignored(tree):
    path = tree / "config" / "dynamic_analysis.json"
    path.parent.mkdir(parents=True)
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(ValueError, match="not valid JSON"):
        da.load(tree)

    snapshot = da.snapshot(tree)
    assert snapshot["error"]
    # The snapshot still answers with the default so the page can render and
    # say what is wrong, rather than failing to load its only control.
    assert snapshot["settings"] == {"communication": "tcp"}


def test_the_options_are_labelled_exactly_as_the_page_shows_them():
    labels = [option["label"] for option in da.OPTIONS]
    assert labels == [
        "Allow TCP/IP Communication",
        "Usage of SFTP Session",
    ]
