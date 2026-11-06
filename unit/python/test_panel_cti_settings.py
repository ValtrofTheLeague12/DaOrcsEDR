from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "python"))

from panel.analysis import cti_settings  # noqa: E402
from panel.core import config  # noqa: E402
from panel.app import create_app  # noqa: E402


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("IA_APPDATA_DIR", str(tmp_path / "appdata"))
    repo = tmp_path / "repo"
    repo.mkdir()
    monkeypatch.setattr(config, "REPO", repo)
    monkeypatch.setattr(cti_settings, "_harden", lambda *_args, **_kwargs: None)
    return create_app().test_client()


def test_api_key_write_is_masked_and_saved_outside_the_repository(client, tmp_path):
    key = "test-key-never-return-this"
    response = client.put(
        "/api/threat-intelligence/apis",
        json={"keys": {"virustotal": key}},
    )

    assert response.status_code == 200
    body = response.get_json()
    provider = next(row for row in body["providers"] if row["id"] == "virustotal")
    assert provider["configured"] is True
    assert key not in response.get_data(as_text=True)
    path = tmp_path / "appdata" / "cti-secrets" / "cti-config.json"
    assert path.is_file()
    assert json.loads(path.read_text(encoding="utf-8")) == {
        "keys": {"virustotal": key},
    }
    assert not path.is_relative_to(config.REPO)


def test_key_updates_are_partial_and_null_clears_one_provider(client):
    client.put(
        "/api/threat-intelligence/apis",
        json={"keys": {"otx": "otx-key", "nvd": "nvd-key"}},
    )

    response = client.put(
        "/api/threat-intelligence/apis",
        json={"keys": {"otx": None}},
    )

    assert response.status_code == 200
    body = response.get_json()
    assert next(row for row in body["providers"] if row["id"] == "otx")["configured"] is False
    assert next(row for row in body["providers"] if row["id"] == "nvd")["configured"] is True
    assert json.loads(cti_settings.settings_path().read_text(encoding="utf-8")) == {
        "keys": {"nvd": "nvd-key"},
    }


@pytest.mark.parametrize(
    "keys",
    [
        {"unknown": "value"},
        {"otx": "bad\nvalue"},
        {"abuseipdb": ""},
        ["not", "an", "object"],
    ],
)
def test_invalid_key_updates_are_rejected_without_writing(client, keys):
    response = client.put("/api/threat-intelligence/apis", json={"keys": keys})

    assert response.status_code == 400
    assert not cti_settings.settings_path().exists()


def test_effective_config_preserves_existing_options_and_overlays_saved_keys(
    client, tmp_path, monkeypatch
):
    base = tmp_path / "external-cti.json"
    base.write_text(json.dumps({
        "keys": {"otx": "old-otx", "nvd": "external-nvd"},
        "endpoints": {"otx": "https://example.test"},
    }), encoding="utf-8")
    monkeypatch.setenv("CTI_CONFIG", str(base))
    client.put(
        "/api/threat-intelligence/apis",
        json={"keys": {"otx": "new-otx"}},
    )

    effective = cti_settings.analyzer_config_path()

    assert effective is not None
    loaded = json.loads(effective.read_text(encoding="utf-8"))
    assert loaded["keys"] == {"otx": "new-otx", "nvd": "external-nvd"}
    assert loaded["endpoints"] == {"otx": "https://example.test"}
    assert effective.parent == cti_settings.settings_path().parent
