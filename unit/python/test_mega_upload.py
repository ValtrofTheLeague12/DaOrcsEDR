"""The bundle uploader's MEGAcmd choreography, without a live account.

A bundle upload was marked FAILED whenever a rerun produced a `mkdir` exit of
54 - "Folder already exists" - on a parent folder that surviving a previous
run is exactly what the sequence normally meets. These tests pin the
arbitration: mkdir's status is advice, the listing decides.
"""

import importlib.util
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]


def _load_upload():
    spec = importlib.util.spec_from_file_location(
        "test_mega_upload_module", REPO / "mega" / "upload.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


upload = _load_upload()


class _Result:
    """The fields of megacmd.Result the uploader reads."""

    def __init__(self, code: int, err: str = "", out: str = ""):
        self.code = code
        self.err = err
        self.out = out


class _FakeCmd:
    """A scripted megacmd.run, recording every call it was asked to make."""

    def __init__(self, script):
        self.script = script
        self.calls = []

    def run(self, command, *args, **kwargs):
        self.calls.append((command, *args))
        check = kwargs.get("check", True)
        result = self.script.get(command, _Result(0))
        if check and result.code != 0:
            raise megacmd_error(
                f"megacmd {command} failed (exit {result.code}): "
                f"{result.err or result.out or '(no output)'}")
        return result


def megacmd_error(message):
    return upload.megacmd.MegaError(message)


def test_mkdir_exit_54_on_an_existing_parent_is_not_a_failure(
        monkeypatch, tmp_path):
    fake = _FakeCmd({
        "mkdir": _Result(54, "Folder already exists: evidence"),
        # the listing arbitrates: the parent IS there, so proceed
        "ls": _Result(0, "evidence"),
        "put": _Result(0, "Upload finished"),
    })
    monkeypatch.setattr(upload.megacmd, "run", fake.run)

    landed = upload.upload_megacmd(tmp_path, "evidence", 60)

    assert landed == f"evidence/{tmp_path.name}"
    assert [c[0] for c in fake.calls] == ["mkdir", "ls", "put"]


def test_mkdir_failure_without_the_folder_is_an_error(monkeypatch, tmp_path):
    fake = _FakeCmd({
        "mkdir": _Result(54, "Folder already exists: evidence"),
        # the listing settles it: the folder is NOT there either
        "ls": _Result(1, "retrieving the account could not find it"),
    })
    monkeypatch.setattr(upload.megacmd, "run", fake.run)

    with pytest.raises(upload.megacmd.MegaError) as excinfo:
        upload.upload_megacmd(tmp_path, "evidence", 60)
    assert "does not" in str(excinfo.value)
    assert [c[0] for c in fake.calls] == ["mkdir", "ls"]


def test_a_clean_mkdir_uploads_without_an_extra_listing(monkeypatch, tmp_path):
    fake = _FakeCmd({
        "mkdir": _Result(0, ""),
        "put": _Result(0, "Upload finished"),
    })
    monkeypatch.setattr(upload.megacmd, "run", fake.run)

    landed = upload.upload_megacmd(tmp_path, "evidence", 60)

    assert landed == f"evidence/{tmp_path.name}"
    assert [c[0] for c in fake.calls] == ["mkdir", "put"]


def test_a_genuinely_missing_parent_still_is_an_error(monkeypatch, tmp_path):
    # A not-found parent (e.g. a typo'd remote root) can also come back as a
    # different nonzero code; only the listing may call it recoverable.
    fake = _FakeCmd({
        "mkdir": _Result(104, "path does not exist: nowhere"),
        "ls": _Result(1, "path does not exist: nowhere"),
    })
    monkeypatch.setattr(upload.megacmd, "run", fake.run)

    with pytest.raises(upload.megacmd.MegaError) as excinfo:
        upload.upload_megacmd(tmp_path, "nowhere", 60)
    assert "path does not exist" in str(excinfo.value)
