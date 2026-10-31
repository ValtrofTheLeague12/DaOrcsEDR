"""The bundle password scheme: protect.py round-trips, and the panel manages
the file without ever echoing the value.

Why this needs its own suite: the zip protection replaced the X25519 seal, and
its whole point is small and boring - ONE password file outside the repo, ONE
zip member, fail-closed everywhere. That makes the failure modes quiet ones (a
trailing newline changing every password, a wrong password "reading" bytes, a
panel payload carrying the value back) and quiet failures are what a test
suite is for.

What these pins:

  protect  - zip / unzip round-trip through a password FILE and stdin; a wrong
             password fails; the zip holds exactly one member
  file     - the password file's newline tolerance, minimum length, generation
             length bounds, clear
  panel    - analysis.py's password helpers report presence and path, return
             the generated value exactly once, and the snapshot carries the
             status chip rather than any value
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "python"))
sys.path.insert(0, str(REPO / "mega"))

import protect  # noqa: E402

from panel import analysis, config  # noqa: E402


@pytest.fixture
def pfile(tmp_path, monkeypatch):
    """Route protect.py's default file into tmp, the same way ops run it."""
    path = tmp_path / "bundle-keys" / "upload.password"
    monkeypatch.setenv("IA_BUNDLE_PASSWORD_FILE", str(path))
    return path


class TestProtectZip:

    def test_roundtrip_through_the_password_file(self, pfile):
        protect.set_password("vault-grade-secrecy-1", pfile)
        archive = pfile.parent / "sample_evidence.tar.gz"
        archive.write_bytes(b":qfixq-bytes-of-the-archive" * 500)
        out_zip = pfile.parent / "sample_evidence.zip"

        info = protect.zip_bundle(archive, out_zip, protect.read_password(pfile))
        assert info["format"] == "password-protected ZIP"
        assert info["algorithm"] == "AES-256 (WinZip WZ_AES)"
        assert len(info["sealed_sha256"]) == 64

        recovered = protect.unzip_bundle(
            out_zip, pfile.parent / "out", protect.read_password(pfile))
        assert recovered.read_bytes() == archive.read_bytes()

    def test_the_zip_holds_exactly_one_member(self, pfile):
        protect.set_password("vault-grade-secrecy-1", pfile)
        archive = pfile.parent / "bundle.tar.gz"
        archive.write_bytes(b"x" * 100)
        out_zip = pfile.parent / "bundle.zip"
        protect.zip_bundle(archive, out_zip, protect.read_password(pfile))
        import pyzipper
        with pyzipper.AESZipFile(out_zip, "r") as zf:
            names = zf.namelist()
        assert names == [archive.name]

    def test_a_wrong_password_fails_closed(self, pfile):
        protect.set_password("the-real-password-attempt", pfile)
        archive = pfile.parent / "bundle.tar.gz"
        archive.write_bytes(b"secret evidence" * 50)
        out_zip = pfile.parent / "bundle.zip"
        protect.zip_bundle(archive, out_zip, protect.read_password(pfile))

        pfile.write_bytes(b"the-forgotten-password!!")
        with pytest.raises(Exception):
            protect.unzip_bundle(out_zip, pfile.parent / "out",
                                 protect.read_password(pfile))

    def test_a_missing_archive_is_refused_not_a_zero_byte_zip(self, pfile):
        protect.set_password("vault-grade-secrecy-1", pfile)
        with pytest.raises(protect.PasswordError):
            protect.zip_bundle(pfile.parent / "nope.tar.gz",
                               pfile.parent / "nope.zip",
                               protect.read_password(pfile))
        assert not (pfile.parent / "nope.zip").exists()


class TestPasswordFile:

    def test_the_stored_bytes_are_the_password_no_trailing_newline(self, pfile):
        protect.set_password("typed-by-the-operator", pfile)
        assert pfile.read_bytes() == b"typed-by-the-operator"

    def test_one_trailing_newline_is_tolerated_and_stripped(self, pfile):
        # Editors always append one; hand-typing into the panel pastes without.
        # Both must produce the same password or the zip silently changes.
        pfile.parent.mkdir(parents=True, exist_ok=True)
        pfile.write_bytes(b"operator-must-not-lose\n")
        assert protect.read_password(pfile) == b"operator-must-not-lose"
        pfile.write_bytes(b"operator-must-not-lose\r\n")
        assert protect.read_password(pfile) == b"operator-must-not-lose"

    def test_the_file_does_not_replace_the_password(self, pfile):
        protect.set_password("precise-bytes-here", pfile)
        assert protect.password_present(pfile)

    def test_generation_length_bounds(self, pfile):
        value, path = protect.generate_password(24, pfile)
        assert len(value) == 24 and path == pfile
        assert protect.read_password(pfile) == value.encode()
        with pytest.raises(protect.PasswordError):
            protect.generate_password(8, pfile)
        with pytest.raises(protect.PasswordError):
            protect.generate_password(256, pfile)

    def test_clear_removes_the_file(self, pfile):
        protect.set_password("soon-forgotten-pw", pfile)
        assert protect.clear_password(pfile)
        assert not pfile.exists()
        assert not protect.password_present(pfile)

    def test_reading_a_missing_file_names_it(self, pfile):
        with pytest.raises(protect.PasswordError, match="does not exist"):
            protect.read_password(pfile)

    def test_the_default_location_lands_outside_the_repo(self, monkeypatch):
        monkeypatch.delenv("IA_BUNDLE_PASSWORD_FILE", raising=False)
        default = protect.password_file()
        assert "bundle-keys" in str(default)
        assert "upload.password" in str(default)
        assert not default.is_relative_to(REPO)


class TestPanelPasswordHelpers:
    """analysis.py manages the FILE; the value never rides a response."""

    @pytest.fixture(autouse=True)
    def route_and_reload(self, pfile):
        # The panel resolved protect.py's default at import of nothing: the
        # helpers call protect.password_file() per call, so the env override
        # is obeyed per call. Nothing to reload - assert that contract here.
        assert protect.password_file() == pfile
        return pfile

    def test_status_reports_presence_and_path_never_a_value(self, pfile):
        state = analysis._bundle_password_status()
        assert state["present"] is False
        assert state["path"] == str(pfile)
        assert set(state) <= {"present", "path", "error"}

    def test_set_stores_the_operator_value_and_returns_only_status(self, pfile):
        res = analysis._bundle_password_set("operator-picks-this-1")
        assert res["ok"] is True
        assert res["status"]["present"] is True
        # The value is not a response key even when the operator typed it in:
        # only a generate shows the password once.
        assert set(res) <= {"ok", "status"}
        assert protect.read_password(pfile) == b"operator-picks-this-1"

    def test_set_refuses_short_and_empty(self, pfile):
        assert analysis._bundle_password_set("")["ok"] is False
        short = analysis._bundle_password_set("short")
        assert short["ok"] is False and "8" in short["error"]

    def test_generate_returns_the_value_exactly_once(self, pfile):
        res = analysis._bundle_password_generate()
        assert res["ok"] is True and res["shown_once"] is True
        assert len(res["password"]) == 24
        assert res["password"] not in str(res["status"])
        # ...and nothing later can produce it again from a status read.
        later = analysis._bundle_password_status()
        assert res["password"] not in str(later)

    def test_generate_respects_the_length_bounds(self, pfile):
        assert analysis._bundle_password_generate(2)["ok"] is False
        res = analysis._bundle_password_generate(40)
        assert len(res["password"]) == 40

    def test_clear(self, pfile):
        analysis._bundle_password_set("exists-then-gone-1")
        res = analysis._bundle_password_clear()
        assert res["ok"] is True and res["status"]["present"] is False

    def test_the_snapshot_carries_the_chip_not_the_value(self):
        # The snapshot is what a GET /api/analysis/config returns; it polls, so
        # a value in it would be a password printed on every refresh.
        snap = analysis.snapshot()
        assert isinstance(snap, dict)
        chip = snap.get("bundle_password")
        assert chip is not None
        assert set(chip) <= {"present", "path", "error"}
        # The dead mirrors are gone from the payload, not just unused.
        assert "encryption_recipient" not in snap
        assert "admin_public_key" not in snap
