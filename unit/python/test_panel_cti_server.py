"""stix-server/config/cti_config.json: the generated server's listener + bans.

The Threat Intelligence page saves the bind address and the banned-artifact
list there and reads them back on load. Three behaviours matter:

  * unrelated keys such as ``catalog_file`` survive an update, because the file
    belongs to the generated server rather than to this panel;
  * a file that cannot be read is never overwritten, because that is how the
    rest of the server's configuration would disappear during a repair;
  * a ban hides an artifact from the generated UI without deleting the row.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "python"))

from panel.app import create_app  # noqa: E402
from panel.artifacts import cti_server  # noqa: E402
from panel.core import config  # noqa: E402


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    return tmp_path


@pytest.fixture
def client(tmp_path: Path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    monkeypatch.setattr(config, "REPO", repo)
    return create_app().test_client(), repo


def _write(repo: Path, body) -> Path:
    path = repo / cti_server.CONFIG_RELATIVE
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body if isinstance(body, str) else json.dumps(body),
                    encoding="utf-8")
    return path


def test_missing_file_reports_defaults_without_creating_it(repo):
    state = cti_server.read(repo)

    assert state == {
        "path": "stix-server/config/cti_config.json",
        "exists": False,
        "ip": "0.0.0.0",
        "port": 8765,
        "banned": [],
        "error": None,
    }
    assert not (repo / cti_server.CONFIG_RELATIVE).exists()


def test_write_saves_the_address_and_preserves_the_catalog(repo):
    path = _write(repo, {
        "server": {"ip": "127.0.0.1", "port": 9000},
        "catalog_file": "artifact_catalog.json",
    })

    state = cti_server.write(repo, {"ip": "0.0.0.0", "port": 8765})

    assert state["exists"] is True
    assert state["ip"] == "0.0.0.0"
    assert state["port"] == 8765
    assert state["error"] is None
    assert json.loads(path.read_text(encoding="utf-8")) == {
        "server": {"ip": "0.0.0.0", "port": 8765},
        "catalog_file": "artifact_catalog.json",
    }


def test_write_creates_the_config_directory_when_missing(repo):
    state = cti_server.write(repo, {"ip": "::1", "port": 1234})

    assert state["ip"] == "::1"
    assert state["port"] == 1234
    assert (repo / cti_server.CONFIG_RELATIVE).is_file()


def test_write_saves_banned_artifacts_and_preserves_the_catalog(repo):
    path = _write(repo, {
        "server": {"ip": "127.0.0.1", "port": 9000},
        "catalog_file": "artifact_catalog.json",
    })

    state = cti_server.write(repo, {
        "banned": [
            {"name": "sample.exe", "hash": None},
            {"name": None, "hash": "  " + "a" * 64 + "  "},
            {"name": "sample.exe", "hash": None},
        ],
    })

    assert state["banned"] == [
        {"name": "sample.exe", "hash": None},
        {"name": None, "hash": "a" * 64},
    ]
    assert state["ip"] == "127.0.0.1"
    assert json.loads(path.read_text(encoding="utf-8")) == {
        "server": {"ip": "127.0.0.1", "port": 9000},
        "catalog_file": "artifact_catalog.json",
        "banned_artifacts": [
            {"name": "sample.exe", "hash": None},
            {"name": None, "hash": "a" * 64},
        ],
    }


def test_saving_the_address_keeps_the_existing_bans(repo):
    _write(repo, {
        "server": {"ip": "127.0.0.1", "port": 9000},
        "banned_artifacts": [{"name": "sample.exe", "hash": None}],
    })

    state = cti_server.write(repo, {"ip": "0.0.0.0", "port": 8765})

    assert state["banned"] == [{"name": "sample.exe", "hash": None}]
    assert json.loads((repo / cti_server.CONFIG_RELATIVE).read_text(
        encoding="utf-8"))["banned_artifacts"] == [{"name": "sample.exe", "hash": None}]


def test_a_pure_ban_write_creates_a_usable_listener(repo):
    state = cti_server.write(repo, {"banned": [{"name": "sample.exe", "hash": None}]})

    assert state["banned"] == [{"name": "sample.exe", "hash": None}]
    assert state["error"] is None
    assert state["ip"] == cti_server.DEFAULT_IP
    assert state["port"] == cti_server.DEFAULT_PORT
    assert json.loads((repo / cti_server.CONFIG_RELATIVE).read_text(
        encoding="utf-8")) == {
        "server": {"ip": cti_server.DEFAULT_IP, "port": cti_server.DEFAULT_PORT},
        "banned_artifacts": [{"name": "sample.exe", "hash": None}],
    }


def test_an_invalid_ban_list_is_reported_but_other_values_still_load(repo):
    _write(repo, {
        "server": {"ip": "127.0.0.1", "port": 9000},
        "banned_artifacts": "not-a-list",
    })

    state = cti_server.read(repo)

    assert state["ip"] == "127.0.0.1"
    assert state["port"] == 9000
    assert "banned_artifacts" in state["error"]


def test_clearing_the_ban_list_persists_an_empty_array(repo):
    _write(repo, {"banned_artifacts": [{"name": "sample.exe", "hash": None}]})

    state = cti_server.write(repo, {"banned": []})

    assert state["banned"] == []
    assert state["error"] is None
    assert json.loads((repo / cti_server.CONFIG_RELATIVE).read_text(
        encoding="utf-8")) == {
        "server": {"ip": cti_server.DEFAULT_IP, "port": cti_server.DEFAULT_PORT},
        "banned_artifacts": [],
    }


@pytest.mark.parametrize("patch", [
    {"ip": ""},
    {"ip": "not-an-ip"},
    {"ip": 5},
    {"port": 0},
    {"port": 65536},
    {"port": True},
    {"port": "abc"},
    {"extra": 1},
    {"banned": "sample.exe"},
    {"banned": [1]},
    {"banned": [{"name": None, "hash": None}]},
    {"banned": [{"name": "", "hash": ""}]},
    {"banned": [{"name": "ok", "hash": "x" * 257}]},
    {"banned": [{"name": "x" * 257, "hash": None}]},
    {"banned": [{"name": f"x{i}", "hash": None} for i in range(1001)]},
])
def test_invalid_updates_are_refused_without_writing(repo, patch):
    with pytest.raises(ValueError):
        cti_server.write(repo, patch)

    assert not (repo / cti_server.CONFIG_RELATIVE).exists()


def test_a_broken_file_is_reported_and_never_overwritten(repo):
    path = _write(repo, "{")

    state = cti_server.read(repo)
    assert state["exists"] is True
    assert "not valid JSON" in state["error"]

    with pytest.raises(ValueError):
        cti_server.write(repo, {"ip": "127.0.0.1", "port": 8765})
    assert path.read_text(encoding="utf-8") == "{"


def test_api_reads_and_writes_the_file_in_the_stix_server_config_directory(client):
    http, repo = client

    response = http.get("/api/threat-intelligence/server")
    assert response.status_code == 200
    assert response.get_json()["exists"] is False

    response = http.put(
        "/api/threat-intelligence/server",
        json={"ip": "127.0.0.1", "port": 4321},
    )
    assert response.status_code == 200
    assert response.get_json()["ip"] == "127.0.0.1"
    assert response.get_json()["port"] == 4321

    path = repo / "stix-server" / "config" / "cti_config.json"
    assert json.loads(path.read_text(encoding="utf-8")) == {
        "server": {"ip": "127.0.0.1", "port": 4321},
    }

    response = http.get("/api/threat-intelligence/server")
    assert response.status_code == 200
    assert response.get_json() == {
        "path": "stix-server/config/cti_config.json",
        "exists": True,
        "ip": "127.0.0.1",
        "port": 4321,
        "banned": [],
        "error": None,
    }


def test_api_bans_an_artifact_without_touching_the_listener(client):
    http, repo = client

    response = http.put(
        "/api/threat-intelligence/server",
        json={"ip": "127.0.0.1", "port": 4321,
              "banned": [{"name": "sample.exe", "hash": None}]},
    )
    assert response.status_code == 200
    assert response.get_json()["banned"] == [{"name": "sample.exe", "hash": None}]

    response = http.put(
        "/api/threat-intelligence/server",
        json={"banned": [{"name": None, "hash": "a" * 64}]},
    )
    assert response.status_code == 200
    assert response.get_json()["ip"] == "127.0.0.1"
    assert response.get_json()["port"] == 4321
    assert response.get_json()["banned"] == [{"name": None, "hash": "a" * 64}]

    path = repo / cti_server.CONFIG_RELATIVE
    assert json.loads(path.read_text(encoding="utf-8")) == {
        "server": {"ip": "127.0.0.1", "port": 4321},
        "banned_artifacts": [{"name": None, "hash": "a" * 64}],
    }


def test_api_rejects_an_invalid_ban_list(client):
    http, repo = client

    response = http.put(
        "/api/threat-intelligence/server",
        json={"banned": "sample.exe"},
    )

    assert response.status_code == 400
    assert "banned" in response.get_json()["error"]
    assert not (repo / cti_server.CONFIG_RELATIVE).exists()


def test_api_rejects_an_invalid_port(client):
    http, repo = client

    response = http.put(
        "/api/threat-intelligence/server",
        json={"ip": "0.0.0.0", "port": 70000},
    )

    assert response.status_code == 400
    assert "port" in response.get_json()["error"]
    assert not (repo / cti_server.CONFIG_RELATIVE).exists()
