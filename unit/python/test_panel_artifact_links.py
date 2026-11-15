"""Public-link plumbing for the Artifacts Remote tab.

The listing poll and the share actions are deliberately separate concerns:

  links_for    one read-only `export` call, filtered to the configured root,
               so the page can show which bundles are already published
  revoke_link  the inverse of link_for: delete the export, leave the evidence

MEGAcmd is faked at the module boundary (`_load_share`) rather than by making
the real CLI available, because the contract under test is the panel's
translation of share.py's answers - not MEGAcmd itself.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "python"))

from panel.artifacts import artifacts  # noqa: E402
from panel.core import config  # noqa: E402


class FakeShare:
    def __init__(self, exports=None, deleted=True, error=None):
        self.exports = exports or []
        self.deleted = deleted
        self.error = error
        self.revoked: list[str] = []

    def normalise(self, path: str) -> str | None:
        path = (path or "").strip().replace("\\", "/")
        if not path:
            return None
        if not path.startswith("/"):
            path = "/" + path
        if any(part == ".." for part in path.split("/")):
            return None
        return path.rstrip("/") or "/"

    def list_exports(self, timeout: int) -> list[dict]:
        if self.error is not None:
            raise self.error
        return self.exports

    def revoke(self, path: str, timeout: int) -> bool:
        self.revoked.append(path)
        if self.error is not None:
            raise self.error
        return self.deleted


class FakeMega:
    def __init__(self, account: str | None = "lab@example.test"):
        self.account = account

    def available(self) -> bool:
        return True

    def missing_message(self) -> str:
        return ""

    def whoami(self, timeout: int | None = None) -> str | None:
        return self.account


def install(monkeypatch, share, mega=None):
    monkeypatch.setattr(
        artifacts, "_load_share", lambda: ((share, mega or FakeMega()), None)
    )
    return share


def export(path: str, link: str = "https://mega.nz/folder/x#key") -> dict:
    return {"path": path, "kind": "folder", "mode": "permanent", "link": link}


class TestLinksFor:

    def test_only_bundles_directly_under_the_root_are_listed(self, monkeypatch):
        share = install(monkeypatch, FakeShare(exports=[
            export("/Cases/2026-10/file_artifact", "https://mega.nz/folder/a#1"),
            # MEGA allows the same folder twice; one name has one URL here.
            export("/Cases/2026-10/file_artifact", "https://mega.nz/folder/b#2"),
            export("/Cases/2026-10/quick_test_artifact", "https://mega.nz/folder/c#3"),
            export("/Cases/2026-10/notes.txt", "https://mega.nz/file/d#4"),
            export("/Cases/2026-10/nested/deep_artifact", "https://mega.nz/folder/e#5"),
            export("/Cases/2026-11/other_artifact", "https://mega.nz/folder/f#6"),
        ]))

        result = artifacts.links_for("/Cases/2026-10")

        assert result["ok"] is True
        assert result["links"] == {
            "file": "https://mega.nz/folder/a#1",
            "quick_test": "https://mega.nz/folder/c#3",
        }
        assert result["account"] == "lab@example.test"
        assert share.revoked == []

    def test_a_relative_root_matches_absolute_export_paths(self, monkeypatch):
        install(monkeypatch, FakeShare(exports=[
            export("/evidence/file_artifact", "https://mega.nz/folder/a#1"),
        ]))

        result = artifacts.links_for("evidence")

        assert result["links"] == {"file": "https://mega.nz/folder/a#1"}

    def test_the_account_root_lists_a_bundle_at_the_top_level(self, monkeypatch):
        install(monkeypatch, FakeShare(exports=[
            export("/file_artifact", "https://mega.nz/folder/a#1"),
        ]))

        result = artifacts.links_for("/")

        assert result["links"] == {"file": "https://mega.nz/folder/a#1"}

    def test_an_export_without_a_link_is_skipped(self, monkeypatch):
        install(monkeypatch, FakeShare(exports=[
            export("/evidence/file_artifact", ""),
        ]))

        assert artifacts.links_for("/evidence")["links"] == {}

    def test_an_invalid_root_is_refused_before_touching_mega(self, monkeypatch):
        called = []
        monkeypatch.setattr(
            artifacts, "_load_share", lambda: called.append(True) or (None, "unused")
        )

        result = artifacts.links_for("/evidence/../secrets")

        assert result == {"ok": False, "error": "invalid MEGA remote root"}
        assert called == []

    def test_a_listing_failure_is_reported_verbatim(self, monkeypatch):
        install(monkeypatch, FakeShare(error=RuntimeError("export failed")))

        result = artifacts.links_for("/evidence")

        assert result["ok"] is False
        assert result["error"] == "export failed"


class TestRevokeLink:

    def test_revoking_targets_the_bundle_folder(self, monkeypatch):
        share = install(monkeypatch, FakeShare(deleted=True))

        result = artifacts.revoke_link("file", "/evidence")

        assert share.revoked == ["/evidence/file_artifact"]
        assert result["ok"] is True
        assert result["deleted"] is True
        assert result["not_exported"] is False
        assert result["remote_path"] == "/evidence/file_artifact"

    def test_a_link_that_was_already_gone_is_not_a_failure(self, monkeypatch):
        share = install(monkeypatch, FakeShare(deleted=False))

        result = artifacts.revoke_link("file", "/evidence")

        assert share.revoked == ["/evidence/file_artifact"]
        assert result["ok"] is True
        assert result["deleted"] is False
        assert result["not_exported"] is True

    def test_a_failed_revocation_keeps_the_target_in_the_error(self, monkeypatch):
        share = install(monkeypatch, FakeShare(error=RuntimeError("still exported")))

        result = artifacts.revoke_link("file", "/evidence")

        assert share.revoked == ["/evidence/file_artifact"]
        assert result["ok"] is False
        assert result["error"] == "still exported"
        assert result["remote_path"] == "/evidence/file_artifact"

    def test_an_invalid_name_is_refused(self, monkeypatch):
        called = []
        monkeypatch.setattr(
            artifacts, "_load_share", lambda: called.append(True) or (None, "unused")
        )

        result = artifacts.revoke_link("../file", "/evidence")

        assert result == {"ok": False, "error": "invalid artifact name"}
        assert called == []


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("IA_APPDATA_DIR", str(tmp_path / "appdata"))
    repo = tmp_path / "repo"
    repo.mkdir()
    monkeypatch.setattr(config, "REPO", repo)
    from panel.app import create_app

    return create_app().test_client()


class TestLinkRoutes:

    def test_get_links_passes_the_requested_root(self, client, monkeypatch):
        seen = []

        def links_for(root):
            seen.append(root)
            return {"ok": True, "links": {"file": "https://mega.nz/folder/a#1"},
                    "account": "lab@example.test", "remote_root": root}

        monkeypatch.setattr(artifacts, "links_for", links_for)

        response = client.get("/api/artifacts/links?remote_root=/evidence")

        assert response.status_code == 200
        assert seen == ["/evidence"]
        assert response.get_json()["links"] == {
            "file": "https://mega.nz/folder/a#1"
        }

    def test_get_links_maps_an_invalid_root_to_400(self, client, monkeypatch):
        monkeypatch.setattr(
            artifacts, "links_for",
            lambda root: {"ok": False, "error": "invalid MEGA remote root"},
        )

        assert client.get("/api/artifacts/links?remote_root=../x").status_code == 400

    def test_get_links_maps_a_missing_client_to_503(self, client, monkeypatch):
        monkeypatch.setattr(
            artifacts, "links_for",
            lambda root: {"ok": False, "error": "MEGAcmd missing - not installed"},
        )

        assert client.get("/api/artifacts/links").status_code == 503

    def test_delete_links_passes_the_name_and_root(self, client, monkeypatch):
        seen = []

        def revoke_link(name, root):
            seen.append((name, root))
            return {"ok": True, "deleted": True, "not_exported": False,
                    "name": name, "remote_path": f"{root}/{name}_artifact",
                    "account": "lab@example.test"}

        monkeypatch.setattr(artifacts, "revoke_link", revoke_link)

        response = client.post(
            "/api/artifacts/link/delete",
            json={"name": " file ", "remote_root": "/evidence"},
        )

        assert response.status_code == 200
        assert seen == [("file", "/evidence")]
        assert response.get_json()["deleted"] is True

    def test_delete_of_an_unexported_bundle_is_a_success(self, client, monkeypatch):
        monkeypatch.setattr(
            artifacts, "revoke_link",
            lambda name, root: {"ok": True, "deleted": False,
                                "not_exported": True, "name": name,
                                "remote_path": "/evidence/file_artifact",
                                "account": "lab@example.test"},
        )

        response = client.post(
            "/api/artifacts/link/delete", json={"name": "file"}
        )

        assert response.status_code == 200
        assert response.get_json()["not_exported"] is True

    def test_delete_maps_a_failure_to_502(self, client, monkeypatch):
        monkeypatch.setattr(
            artifacts, "revoke_link",
            lambda name, root: {"ok": False, "error": "still exported"},
        )

        assert client.post(
            "/api/artifacts/link/delete", json={"name": "file"}
        ).status_code == 502

    def test_delete_refuses_a_non_object_body(self, client):
        response = client.post("/api/artifacts/link/delete", data="nope")

        assert response.status_code == 400
        assert response.get_json()["error"] == "body must be a JSON object"

    def test_delete_refuses_a_non_string_name(self, client):
        response = client.post(
            "/api/artifacts/link/delete", json={"name": ["file"]}
        )

        assert response.status_code == 400
        assert response.get_json()["error"] == "artifact name must be a string"
