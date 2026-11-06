from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "python"))

from panel.core import config  # noqa: E402


@pytest.fixture
def client(tmp_path, monkeypatch):
    (tmp_path / "exports").mkdir()
    monkeypatch.setattr(config, "REPO", tmp_path)
    from panel.app import create_app
    return create_app().test_client()


def test_evidence_tree_lists_files_and_sandbox_serves_html(client, tmp_path):
    restored = tmp_path / "exports" / "case_recovered"
    restored.mkdir()
    report = restored / "report.html"
    report.write_text("<h1>Evidence report</h1>", encoding="utf-8")
    (restored / "bundle.json").write_text("{}", encoding="utf-8")

    listing = client.get("/api/artifacts/local/case/evidence")

    assert listing.status_code == 200
    files = listing.get_json()["files"]
    assert {item["path"] for item in files} == {"report.html", "bundle.json"}
    assert next(item for item in files if item["path"] == "report.html")["html"] is True

    response = client.get("/api/artifacts/local/case/evidence/report.html")

    assert response.status_code == 200
    assert response.headers["Content-Security-Policy"].startswith("sandbox allow-scripts;")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.data == b"<h1>Evidence report</h1>"


def test_evidence_file_route_does_not_follow_symlinks_outside_tree(client, tmp_path):
    restored = tmp_path / "exports" / "case_recovered"
    restored.mkdir()
    secret = tmp_path / "outside.txt"
    secret.write_text("not evidence", encoding="utf-8")
    try:
        (restored / "outside.txt").symlink_to(secret)
    except OSError as exc:
        pytest.skip(f"symlink creation is not permitted: {exc}")

    response = client.get("/api/artifacts/local/case/evidence/outside.txt")

    assert response.status_code == 404


def test_restore_extracts_to_staging_then_publishes_only_on_success(
    client, tmp_path, monkeypatch
):
    bundle = tmp_path / "exports" / "case_artifact"
    bundle.mkdir()
    (bundle / "case_evidence.tar.gz").write_bytes(b"archive")

    def fake_run(command, **_kwargs):
        destination = Path(command[command.index("--dest") + 1])
        (destination / "report.html").write_text("<h1>ok</h1>", encoding="utf-8")
        return SimpleNamespace(returncode=0, stdout="verified and extracted", stderr="")

    monkeypatch.setattr("panel.app.subprocess.run", fake_run)

    response = client.post("/api/artifacts/restore", json={"name": "case"})

    assert response.status_code == 200
    assert (tmp_path / "exports" / "case_recovered" / "report.html").is_file()
    assert not list((tmp_path / "exports").glob(".case-restore-*"))


def test_restore_refuses_to_replace_an_existing_tree(client, tmp_path):
    bundle = tmp_path / "exports" / "case_artifact"
    bundle.mkdir()
    (bundle / "case_evidence.tar.gz").write_bytes(b"archive")
    destination = tmp_path / "exports" / "case_recovered"
    destination.mkdir()
    (destination / "keep.txt").write_text("keep", encoding="utf-8")

    response = client.post("/api/artifacts/restore", json={"name": "case"})

    assert response.status_code == 409
    assert (destination / "keep.txt").read_text(encoding="utf-8") == "keep"
