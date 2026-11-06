"""mega/share.py: the public-link CLI on top of `mega-export`.

The listing parser and the three actions are exercised here because they are
the parts a live account cannot cheaply assert: "no links yet" (exit 53), a
node that was never exported (exit 53/54), and create being idempotent.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "mega"))

import megacmd  # noqa: E402
import share  # noqa: E402

LINK = "https://mega.nz/folder/mx5xCTgR#7kGMc0tvks3leQsfImUrmg"
FOLDER_LINE = (
    "custom-887143_artifact (folder, shared as exported permanent folder link: "
    f"{LINK})"
)


def _result(code: int, out: str = "", err: str = "") -> megacmd.Result:
    return megacmd.Result("export", [], code, out, err)


class _Scripted:
    def __init__(self, *results):
        self.results = list(results)
        self.calls: list[tuple] = []

    def __call__(self, command, *args, **kwargs):
        self.calls.append((command, *args))
        if not self.results:
            raise AssertionError(f"unexpected megacmd call: {command} {args}")
        return self.results.pop(0)


@pytest.fixture
def operator(monkeypatch):
    """A signed-in account; individual tests script the megacmd calls."""
    monkeypatch.setattr(megacmd, "available", lambda: True)
    monkeypatch.setattr(megacmd, "whoami", lambda timeout=None: "operator@example.com")


class TestParsing:

    def test_a_folder_export_is_parsed(self):
        (entry,) = share.parse_exports(FOLDER_LINE)
        assert entry["path"] == "/custom-887143_artifact"
        assert entry["kind"] == "folder"
        assert entry["link"] == LINK
        assert entry["mode"] == "permanent folder link"

    def test_a_file_export_is_parsed(self):
        text = ("Cases/2026-10/notes.txt (file, shared as exported permanent "
                f"file link: https://mega.nz/file/abc123#key)")
        (entry,) = share.parse_exports(text)
        assert entry["path"] == "/Cases/2026-10/notes.txt"
        assert entry["kind"] == "file"
        assert entry["link"] == "https://mega.nz/file/abc123#key"

    def test_a_path_with_spaces_survives(self):
        (entry,) = share.parse_exports(
            "my case_artifact (folder, shared as exported writable folder link: "
            f"{LINK})")
        assert entry["path"] == "/my case_artifact"
        assert entry["mode"] == "writable folder link"

    def test_noise_is_ignored(self):
        assert share.parse_exports("") == []
        assert share.parse_exports("no links here\n\naccount : a@b.com") == []


class TestNormalise:

    def test_a_bare_name_becomes_absolute(self):
        assert share.normalise("quick_test_artifact") == "/quick_test_artifact"

    def test_a_trailing_slash_is_dropped(self):
        assert share.normalise("/Cases/2026-10/") == "/Cases/2026-10"
        assert share.normalise("/") == "/"

    def test_empty_and_traversal_are_refused(self):
        assert share.normalise("") is None
        assert share.normalise("   ") is None
        assert share.normalise("/a/../b") is None
        assert share.normalise("..\\escape") is None


class TestListing:

    def test_no_exports_is_success(self, operator, monkeypatch, capsys):
        fake = _Scripted(_result(53, "Couldn't find anything exported"))
        monkeypatch.setattr(megacmd, "run", fake)
        assert share.main([]) == 0
        out = capsys.readouterr().out
        assert "operator@example.com" in out
        assert "no public links here" in out

    def test_exports_are_listed_with_their_urls(self, operator, monkeypatch, capsys):
        fake = _Scripted(_result(0, FOLDER_LINE))
        monkeypatch.setattr(megacmd, "run", fake)
        assert share.main([]) == 0
        out = capsys.readouterr().out
        assert "/custom-887143_artifact" in out
        assert LINK in out
        assert "1 export(s)" in out

    def test_remote_root_filters_the_listing(self, operator, monkeypatch, capsys):
        text = (FOLDER_LINE + "\n" +
                "Cases/2026-10/quick_test_artifact (folder, shared as exported "
                f"permanent folder link: {LINK})")
        monkeypatch.setattr(megacmd, "run", _Scripted(_result(0, text)))
        assert share.main(["--remote-root", "/Cases/2026-10"]) == 0
        out = capsys.readouterr().out
        assert "quick_test_artifact" in out
        assert "custom-887143_artifact" not in out

    def test_json_listing_is_machine_readable(self, operator, monkeypatch, capsys):
        monkeypatch.setattr(megacmd, "run", _Scripted(_result(0, FOLDER_LINE)))
        assert share.main(["--json"]) == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["account"] == "operator@example.com"
        assert payload["exports"][0]["link"] == LINK


class TestSinglePath:

    def test_show_prints_only_the_url(self, operator, monkeypatch, capsys):
        fake = _Scripted(_result(0, FOLDER_LINE))
        monkeypatch.setattr(megacmd, "run", fake)
        assert share.main(["/custom-887143_artifact"]) == 0
        assert capsys.readouterr().out.strip() == LINK
        assert fake.calls == [("export", "/custom-887143_artifact")]

    def test_show_never_creates_a_link(self, operator, monkeypatch, capsys):
        fake = _Scripted(_result(53, "not exported"))
        monkeypatch.setattr(megacmd, "run", fake)
        assert share.main(["/custom-887143_artifact"]) == 4
        assert fake.calls == [("export", "/custom-887143_artifact")]
        assert "not exported" in capsys.readouterr().err

    def test_success_without_a_url_is_an_error(self, operator, monkeypatch, capsys):
        monkeypatch.setattr(megacmd, "run", _Scripted(_result(0, "done, somehow")))
        assert share.main(["/custom-887143_artifact"]) == 1
        assert "no link" in capsys.readouterr().err

    def test_create_reuses_an_existing_export(self, operator, monkeypatch, capsys):
        fake = _Scripted(_result(0, FOLDER_LINE))
        monkeypatch.setattr(megacmd, "run", fake)
        assert share.main(["--create", "/custom-887143_artifact"]) == 0
        out = capsys.readouterr().out
        assert "existing" in out
        assert LINK in out
        # Read once; no `-a` was attempted.
        assert fake.calls == [("export", "/custom-887143_artifact")]

    def test_create_publishes_when_there_is_no_link(self, operator, monkeypatch, capsys):
        monkeypatch.setattr(share, "configured_expire", lambda: None)
        fake = _Scripted(
            _result(53, "not exported"),           # show()
            _result(53, "not exported"),           # public_link -> exported_link
            _result(0, f"Exported /custom-887143_artifact: {LINK}"),
        )
        monkeypatch.setattr(megacmd, "run", fake)
        assert share.main(["--create", "/custom-887143_artifact"]) == 0
        assert "created" in capsys.readouterr().out
        assert fake.calls[-1] == ("export", "-a", "-f", "/custom-887143_artifact")

    def test_delete_revokes(self, operator, monkeypatch, capsys):
        fake = _Scripted(
            _result(0, "Disabled export: /custom-887143_artifact"),
            _result(53, "not exported"),          # the re-read after -d
        )
        monkeypatch.setattr(megacmd, "run", fake)
        assert share.main(["--delete", "/custom-887143_artifact"]) == 0
        assert "revoked" in capsys.readouterr().out
        assert fake.calls == [
            ("export", "-d", "/custom-887143_artifact"),
            ("export", "/custom-887143_artifact"),
        ]

    def test_delete_checks_the_link_is_gone(self, operator, monkeypatch, capsys):
        monkeypatch.setattr(megacmd, "run", _Scripted(
            _result(0, "Disabled export: /custom-887143_artifact"),
            _result(0, FOLDER_LINE),              # still exported
        ))
        assert share.main(["--delete", "/custom-887143_artifact"]) == 1
        assert "still has a link" in capsys.readouterr().err

    def test_delete_reports_nothing_to_revoke(self, operator, monkeypatch, capsys):
        monkeypatch.setattr(megacmd, "run",
                            _Scripted(_result(54, "Could not disable export: node not exported.")))
        assert share.main(["--delete", "/custom-887143_artifact"]) == 4
        assert "not exported" in capsys.readouterr().err


class TestExpiry:

    def _create_script(self):
        return _Scripted(
            _result(53, "not exported"),           # show()
            _result(53, "not exported"),           # public_link -> exported_link
            _result(0, f"Exported /custom-887143_artifact: {LINK}"),
        )

    def test_the_configured_expiry_is_used_by_default(
            self, operator, monkeypatch, capsys):
        monkeypatch.setattr(share, "configured_expire", lambda: "7d")
        fake = self._create_script()
        monkeypatch.setattr(megacmd, "run", fake)
        assert share.main(["--create", "/custom-887143_artifact"]) == 0
        assert fake.calls[-1] == (
            "export", "-a", "--expire=7d", "-f", "/custom-887143_artifact")
        assert "expires   7d" in capsys.readouterr().out

    def test_an_explicit_expire_beats_the_config(
            self, operator, monkeypatch, capsys):
        monkeypatch.setattr(share, "configured_expire", lambda: "7d")
        fake = self._create_script()
        monkeypatch.setattr(megacmd, "run", fake)
        assert share.main(["--create", "--expire", "1h", "/custom-887143_artifact"]) == 0
        assert fake.calls[-1] == (
            "export", "-a", "--expire=1h", "-f", "/custom-887143_artifact")

    def test_permanent_ignores_the_config(self, operator, monkeypatch, capsys):
        monkeypatch.setattr(share, "configured_expire", lambda: "7d")
        fake = self._create_script()
        monkeypatch.setattr(megacmd, "run", fake)
        assert share.main(["--create", "--permanent", "/custom-887143_artifact"]) == 0
        assert fake.calls[-1] == ("export", "-a", "-f", "/custom-887143_artifact")
        assert "expires" not in capsys.readouterr().out

    def test_json_create_reports_the_expiry(self, operator, monkeypatch, capsys):
        monkeypatch.setattr(share, "configured_expire", lambda: None)
        monkeypatch.setattr(megacmd, "run", self._create_script())
        assert share.main(["--create", "--expire", "12h",
                           "--json", "/custom-887143_artifact"]) == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["expire"] == "12h"
        assert payload["created"] is True

    def test_expire_only_applies_with_create(self, operator, capsys):
        with pytest.raises(SystemExit) as exc:
            share.main(["--expire", "7d", "/custom-887143_artifact"])
        assert exc.value.code == 2
        assert "--expire/--permanent only apply with --create" in capsys.readouterr().err

    def test_an_invalid_expire_is_refused(self, operator, capsys):
        with pytest.raises(SystemExit) as exc:
            share.main(["--create", "--expire", "7D", "/custom-887143_artifact"])
        assert exc.value.code == 2
        assert "invalid expiry" in capsys.readouterr().err


class TestConfiguredExpire:

    def test_it_reads_the_share_config(self, tmp_path, monkeypatch):
        path = tmp_path / "share.json"
        path.write_text('{"link_expire": "12h"}', encoding="utf-8")
        monkeypatch.setattr(share, "SHARE_CONFIG", path)
        assert share.configured_expire() == "12h"

    def test_an_empty_value_means_permanent(self, tmp_path, monkeypatch):
        path = tmp_path / "share.json"
        path.write_text('{"link_expire": ""}', encoding="utf-8")
        monkeypatch.setattr(share, "SHARE_CONFIG", path)
        assert share.configured_expire() is None

    def test_a_missing_file_means_permanent(self, tmp_path, monkeypatch):
        monkeypatch.setattr(share, "SHARE_CONFIG", tmp_path / "missing.json")
        assert share.configured_expire() is None

    def test_a_broken_file_is_an_error(self, tmp_path, monkeypatch):
        # A policy that cannot be read must not silently become "permanent".
        broken = tmp_path / "share.json"
        broken.write_text("{", encoding="utf-8")
        monkeypatch.setattr(share, "SHARE_CONFIG", broken)
        with pytest.raises(ValueError, match="not valid JSON"):
            share.configured_expire()

    def test_an_invalid_duration_is_an_error(self, tmp_path, monkeypatch):
        path = tmp_path / "share.json"
        path.write_text('{"link_expire": "7 days"}', encoding="utf-8")
        monkeypatch.setattr(share, "SHARE_CONFIG", path)
        with pytest.raises(ValueError, match="not a MEGA duration"):
            share.configured_expire()

    def test_a_broken_config_stops_create(self, operator, monkeypatch, tmp_path, capsys):
        broken = tmp_path / "share.json"
        broken.write_text("{", encoding="utf-8")
        monkeypatch.setattr(share, "SHARE_CONFIG", broken)
        fake = _Scripted()
        monkeypatch.setattr(megacmd, "run", fake)
        assert share.main(["--create", "/custom-887143_artifact"]) == 2
        assert "not valid JSON" in capsys.readouterr().err
        assert fake.calls == []

    def test_permanent_overrides_a_broken_config(self, operator, monkeypatch, tmp_path, capsys):
        broken = tmp_path / "share.json"
        broken.write_text("{", encoding="utf-8")
        monkeypatch.setattr(share, "SHARE_CONFIG", broken)
        fake = _Scripted(
            _result(53, "not exported"),
            _result(53, "not exported"),
            _result(0, f"Exported /custom-887143_artifact: {LINK}"),
        )
        monkeypatch.setattr(megacmd, "run", fake)
        assert share.main(["--create", "--permanent",
                           "/custom-887143_artifact"]) == 0
        assert fake.calls[-1] == ("export", "-a", "-f", "/custom-887143_artifact")


class TestGuards:

    def test_no_session(self, monkeypatch, capsys):
        monkeypatch.setattr(megacmd, "available", lambda: True)
        monkeypatch.setattr(megacmd, "whoami", lambda timeout=None: None)
        assert share.main([]) == 2
        assert "no MEGAcmd session" in capsys.readouterr().err

    def test_no_megacmd(self, monkeypatch, capsys):
        monkeypatch.setattr(megacmd, "available", lambda: False)
        assert share.main([]) == 3
        assert "was not found" in capsys.readouterr().err
