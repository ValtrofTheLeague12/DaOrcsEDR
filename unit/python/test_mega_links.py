"""Public MEGA links: parsing, creation, and what the remote listing exposes.

The link is a capability - MEGA puts the decryption key in the URL fragment -
so two rules are pinned here:

  * listing a page reads an EXISTING export only; it must never create one
  * creating one is the explicit link_for()/end-of-export action

Plus the protected-bundle case: the remote folder holds the AES zip, not the
plaintext tarball, and a listing that only knows the tarball calls every
protected upload "missing".
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "python"))
sys.path.insert(0, str(REPO / "mega"))

import megacmd  # noqa: E402

from panel.artifacts import artifacts  # noqa: E402

LINK = "https://mega.nz/folder/mx5xCTgR#7kGMc0tvks3leQsfImUrmg"


def _result(code: int, out: str) -> megacmd.Result:
    return megacmd.Result("export", [], code, out, "")


class _Scripted:
    def __init__(self, *results):
        self.results = list(results)
        self.calls: list[tuple] = []

    def __call__(self, command, *args, **kwargs):
        self.calls.append((command, *args))
        return self.results.pop(0)


class TestMegacmdLinks:

    def test_an_existing_export_is_read_not_created(self, monkeypatch):
        fake = _Scripted(_result(0, f"shared as exported permanent folder link: {LINK}"))
        monkeypatch.setattr(megacmd, "run", fake)
        assert megacmd.exported_link("/case_artifact") == LINK
        assert fake.calls == [("export", "/case_artifact")]

    def test_a_node_that_is_not_exported_has_no_link(self, monkeypatch):
        fake = _Scripted(_result(53, "/case_artifact is not exported. Use -a to export it"))
        monkeypatch.setattr(megacmd, "run", fake)
        assert megacmd.exported_link("/case_artifact") is None

    def test_public_link_reuses_an_existing_export(self, monkeypatch):
        fake = _Scripted(_result(0, LINK))
        monkeypatch.setattr(megacmd, "run", fake)
        assert megacmd.public_link("/case_artifact") == LINK
        assert len(fake.calls) == 1

    def test_public_link_creates_one_with_force(self, monkeypatch):
        fake = _Scripted(
            _result(53, "not exported"),
            _result(0, f"Exported /case_artifact: {LINK}"),
        )
        monkeypatch.setattr(megacmd, "run", fake)
        assert megacmd.public_link("/case_artifact") == LINK
        assert fake.calls[-1] == ("export", "-a", "-f", "/case_artifact")

    def test_public_link_refuses_a_successful_command_with_no_url(self, monkeypatch):
        fake = _Scripted(_result(53, "not exported"), _result(0, "done, somehow"))
        monkeypatch.setattr(megacmd, "run", fake)
        with pytest.raises(megacmd.MegaError, match="no link"):
            megacmd.public_link("/case_artifact")

    def test_public_link_applies_the_expiry_when_it_creates_one(self, monkeypatch):
        fake = _Scripted(
            _result(53, "not exported"),
            _result(0, f"Exported /case_artifact: {LINK}"),
        )
        monkeypatch.setattr(megacmd, "run", fake)
        assert megacmd.public_link("/case_artifact", expire="7d") == LINK
        assert fake.calls[-1] == (
            "export", "-a", "--expire=7d", "-f", "/case_artifact")

    def test_public_link_leaves_an_existing_export_untouched(self, monkeypatch):
        # MEGA cannot modify an export in place, so an expiry must not be
        # applied to a link that is already out - and must not cause a re-add.
        fake = _Scripted(_result(0, f"shared as exported permanent folder link: {LINK}"))
        monkeypatch.setattr(megacmd, "run", fake)
        assert megacmd.public_link("/case_artifact", expire="7d") == LINK
        assert fake.calls == [("export", "/case_artifact")]

    @pytest.mark.parametrize("bad", ["7", "7D", "-7d", "7 days", "0d", "7z"])
    def test_public_link_rejects_an_invalid_expiry(self, monkeypatch, bad):
        fake = _Scripted()
        monkeypatch.setattr(megacmd, "run", fake)
        with pytest.raises(megacmd.MegaError, match="invalid MEGA link expiry"):
            megacmd.public_link("/case_artifact", expire=bad)
        assert fake.calls == []

    @pytest.mark.parametrize("good", ["12h", "7d", "1m12d3h", "30M", "2y"])
    def test_mega_durations_are_accepted(self, good):
        assert megacmd.valid_duration(good)


class TestRemoteListing:

    def test_a_protected_zip_counts_as_the_archive_and_carries_its_link(self, monkeypatch):
        artifacts.invalidate_remote_cache()

        class Listing:
            def ls(self, path, timeout):
                if path == "/":
                    return [{"name": "case_artifact", "is_dir": True,
                             "size": 0, "date": "01Nov2026 20:45:58"}]
                return [
                    {"name": "case_evidence.zip", "is_dir": False,
                     "size": 21095, "date": "01Nov2026 20:45:53"},
                    {"name": "manifest.json", "is_dir": False,
                     "size": 1206, "date": "01Nov2026 20:45:53"},
                ]

        class Mega:
            def available(self):
                return True

            def whoami(self, timeout=None):
                return "operator@example.com"

            def exported_link(self, path, timeout):
                raise AssertionError("remote polling must not spawn link probes")

        monkeypatch.setattr(artifacts, "_load_mega",
                            lambda: ((Listing(), Mega()), None))
        payload = artifacts.remote("/", force=True)
        bundle = payload["bundles"][0]
        assert bundle["present"] is True
        assert bundle["archive"] == "case_evidence.zip"
        assert bundle["bytes"] == 21095
        assert bundle["link"] is None

    @pytest.mark.parametrize(
        "archive_name",
        ["custom_evidence.zip", "evidence.tar.gz", "legacy-bundle.zip"],
    )
    def test_remote_archive_detection_tolerates_older_archive_names(
        self, monkeypatch, archive_name
    ):
        artifacts.invalidate_remote_cache()

        class Listing:
            def ls(self, path, timeout):
                if path == "/":
                    return [{"name": "current-case_artifact", "is_dir": True,
                             "size": 0, "date": "01Nov2026 20:45:58"}]
                return [
                    {"name": archive_name, "is_dir": False,
                     "size": 1234, "date": "01Nov2026 20:45:53"},
                    {"name": f"{archive_name}.sha256", "is_dir": False,
                     "size": 70, "date": "01Nov2026 20:45:53"},
                    {"name": "manifest.json", "is_dir": False,
                     "size": 1206, "date": "01Nov2026 20:45:53"},
                ]

        class Mega:
            def available(self):
                return True

            def whoami(self, timeout=None):
                return "operator@example.com"

        monkeypatch.setattr(artifacts, "_load_mega",
                            lambda: ((Listing(), Mega()), None))

        bundle = artifacts.remote("/", force=True)["bundles"][0]

        assert bundle["present"] is True
        assert bundle["archive"] == archive_name
        assert bundle["bytes"] == 1234

    def test_missing_configured_remote_root_is_an_empty_available_listing(
        self, monkeypatch
    ):
        artifacts.invalidate_remote_cache()

        class Listing:
            def ls(self, path, timeout):
                raise RuntimeError(
                    "megacmd ls failed (exit 53): Couldn't find evidence"
                )

        class Mega:
            def available(self):
                return True

            def whoami(self, timeout=None):
                return "operator@example.com"

        monkeypatch.setattr(artifacts, "_load_mega",
                            lambda: ((Listing(), Mega()), None))

        result = artifacts.remote("evidence", force=True)

        assert result["available"] is True
        assert result["root_exists"] is False
        assert result["bundles"] == []
        assert "does not exist" in result["reason"]

    def test_unrelated_remote_listing_errors_are_not_hidden(self, monkeypatch):
        artifacts.invalidate_remote_cache()

        class Listing:
            def ls(self, path, timeout):
                raise RuntimeError("MEGAcmd server is not responding")

        class Mega:
            def available(self):
                return True

            def whoami(self, timeout=None):
                return "operator@example.com"

        monkeypatch.setattr(artifacts, "_load_mega",
                            lambda: ((Listing(), Mega()), None))

        result = artifacts.remote("evidence", force=True)

        assert result["available"] is False
        assert "not responding" in result["reason"]

    def test_link_for_creates_a_link_for_a_listed_bundle(self, monkeypatch):
        seen: list[str | None] = []

        class Listing:
            def ls(self, path, timeout):
                return [{"name": "case_artifact", "is_dir": True,
                         "size": 0, "date": "01Nov2026 20:45:58"}]

        class Mega:
            def available(self):
                return True

            def whoami(self):
                return "operator@example.com"

            def public_link(self, path, timeout, expire=None):
                seen.append(expire)
                return LINK

        monkeypatch.setattr(artifacts, "_load_mega",
                            lambda: ((Listing(), Mega()), None))
        monkeypatch.setattr(artifacts.share_settings, "expire",
                            lambda repo: (None, None))
        res = artifacts.link_for("case", "/")
        assert res["ok"] is True
        assert res["link"] == LINK
        assert res["expire"] is None
        assert seen == [None]

    def test_link_for_applies_the_configured_expiry(self, monkeypatch):
        seen: list[str | None] = []

        class Listing:
            def ls(self, path, timeout):
                return [{"name": "case_artifact", "is_dir": True,
                         "size": 0, "date": "01Nov2026 20:45:58"}]

        class Mega:
            def available(self):
                return True

            def whoami(self):
                return "operator@example.com"

            def public_link(self, path, timeout, expire=None):
                seen.append(expire)
                return LINK

        monkeypatch.setattr(artifacts, "_load_mega",
                            lambda: ((Listing(), Mega()), None))
        monkeypatch.setattr(artifacts.share_settings, "expire",
                            lambda repo: ("7d", None))
        res = artifacts.link_for("case", "/")
        assert res["ok"] is True
        assert res["expire"] == "7d"
        assert seen == ["7d"]

    def test_link_for_refuses_when_the_expiry_file_is_broken(self, monkeypatch):
        # A broken policy must stop the link, not publish a permanent one.
        class Listing:
            def ls(self, path, timeout):
                return [{"name": "case_artifact", "is_dir": True,
                         "size": 0, "date": "01Nov2026 20:45:58"}]

        class Mega:
            def available(self):
                return True

            def whoami(self):
                return "operator@example.com"

            def public_link(self, path, timeout, expire=None):
                raise AssertionError("must not be called")

        monkeypatch.setattr(artifacts, "_load_mega",
                            lambda: ((Listing(), Mega()), None))
        monkeypatch.setattr(artifacts.share_settings, "expire",
                            lambda repo: (None, "config/share.json is not valid JSON"))
        res = artifacts.link_for("case", "/")
        assert res["ok"] is False
        assert "share link expiry" in res["error"]

    def test_link_for_refuses_a_bundle_that_is_not_on_mega(self, monkeypatch):
        class Listing:
            def ls(self, path, timeout):
                raise RuntimeError("not found")

        class Mega:
            def available(self):
                return True

            def whoami(self):
                return "operator@example.com"

        monkeypatch.setattr(artifacts, "_load_mega",
                            lambda: ((Listing(), Mega()), None))
        res = artifacts.link_for("case", "/")
        assert res["ok"] is False
        assert "not on MEGA" in res["error"]

    def test_link_for_rejects_a_traversal_name(self):
        assert artifacts.link_for("../escape")["ok"] is False

    def test_dashboard_actions_accept_the_configured_relative_root(self):
        assert artifacts._valid_remote_root("evidence") == "evidence"
        assert artifacts._valid_remote_root("../outside") is None

    def test_deleted_remote_history_is_not_a_current_remote_bundle(
        self, monkeypatch, tmp_path
    ):
        observation = {
            "name": "deleted-case",
            "bytes": 123,
            "total_bytes": 123,
            "file_count": 1,
            "modified": 100.0,
            "first_seen": 90.0,
            "last_seen": 100.0,
        }
        monkeypatch.setattr(artifacts, "local", lambda force=False: [])
        monkeypatch.setattr(
            artifacts, "remote",
            lambda remote_root, force=False: {
                "available": True,
                "account": "operator@example.com",
                "remote_root": remote_root,
                "bundles": [],
                "not_examined": 0,
                "truncated": None,
            },
        )
        monkeypatch.setattr(
            artifacts, "_read_history",
            lambda: {
                "observations": {"deleted-case": observation},
                "updated_at": 100.0,
                "present": True,
            },
        )
        monkeypatch.setattr(
            artifacts, "record",
            lambda *args: {"path": str(tmp_path / "history.json")},
        )
        monkeypatch.setattr(
            artifacts, "history_path", lambda: tmp_path / "history.json"
        )

        payload = artifacts.snapshot("/", force=True)

        assert payload["remote"]["bundles"] == []
        assert payload["unified"] == []
        assert payload["history"]["not_on_remote"] == ["deleted-case"]

    def test_dashboard_returns_while_remote_refresh_runs_in_background(self, monkeypatch):
        root = "/test-background-refresh"
        started = []

        class FakeThread:
            def __init__(self, *, target, args, name, daemon):
                self.target = target
                self.args = args
                started.append((name, daemon))

            def start(self):
                pass

        monkeypatch.setattr(artifacts.threading, "Thread", FakeThread)
        with artifacts._async_remote_lock:
            artifacts._async_remote_cache.pop(root, None)
            artifacts._async_remote_refreshing.discard(root)

        payload = artifacts._remote_nonblocking(root)

        assert payload["refreshing"] is True
        assert payload["remote_root"] == root
        assert started == [("mega-listing-refresh", True)]
        with artifacts._async_remote_lock:
            artifacts._async_remote_refreshing.discard(root)
