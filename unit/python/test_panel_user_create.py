"""Tests for POST /api/threat-intelligence/users (the Add-a-user form).

The route must validate username/password/IP, hash the password with
cti_auth's bcrypt scheme, and create the user + ip_list rows through the
Supabase SDK. What it must never do is return or log the submitted password.
"""

from __future__ import annotations

import sys
import types
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("IA_APPDATA_DIR", str(tmp_path / "appdata"))
    repo = tmp_path / "repo"
    repo.mkdir()
    import importlib

    config = importlib.import_module("panel.core.config")
    monkeypatch.setattr(config, "REPO", repo)
    from panel.app import create_app

    return create_app().test_client()


class FakeUser:
    def __init__(self, id_user=7, username="op"):
        self.id_user = id_user
        self.username = username


class FakeEntry:
    def __init__(self, ip="10.0.0.5", decision=True):
        self.id_user = 7
        self.ip_address = ip
        self.decision = decision


class FakeClient:
    created = None
    existing = None

    def get_user_by_username(self, username):
        return FakeUser() if FakeClient.existing else None

    def add_user_and_ip(self, username, password, unique_peper, ip_address, decision):
        FakeClient.created = {
            "username": username,
            "password": password,
            "unique_peper": unique_peper,
            "ip_address": ip_address,
            "decision": decision,
        }
        return FakeUser(username=username), FakeEntry(ip_address, decision)


@pytest.fixture
def fake_sdk(monkeypatch):
    """The route imports stix-server modules by name; give it fakes."""
    FakeClient.created = None
    FakeClient.existing = None
    fake = types.ModuleType("User")
    fake.SupabaseClient = FakeClient
    monkeypatch.setitem(sys.modules, "User", fake)
    # cti_auth is real: the bcrypt digest it produces is what the login gate
    # checks, so the test asserts against the same primitive. Importing it
    # also puts stix-server on sys.path for the route itself.
    stix = str(REPO / "stix-server")
    if stix not in sys.path:
        sys.path.insert(0, stix)
    import importlib

    module = importlib.import_module("cti_auth")
    monkeypatch.setitem(sys.modules, "cti_auth", module)
    return fake


def _post(client, **overrides):
    body = {
        "username": "operator1",
        "password": "s3cret-pass",
        "ip": "10.0.0.5",
        "decision": "allow",
    }
    body.update(overrides)
    body = {k: v for k, v in body.items() if v is not None}
    return client.post("/api/threat-intelligence/users", json=body)


class TestValidation:
    def test_a_missing_password_is_refused(self, client, fake_sdk):
        assert _post(client, password=None).status_code == 400
        assert FakeClient.created is None

    def test_a_missing_ip_is_refused(self, client, fake_sdk):
        assert _post(client, ip=None).status_code == 400
        assert FakeClient.created is None

    def test_an_invalid_ip_is_refused(self, client, fake_sdk):
        response = _post(client, ip="not-an-ip")
        assert response.status_code == 400
        assert "not a valid IP" in response.get_json()["error"]
        assert FakeClient.created is None

    def test_an_invalid_cidr_is_refused(self, client, fake_sdk):
        response = _post(client, ip="10.0.0.0/99")
        assert response.status_code == 400
        assert FakeClient.created is None

    def test_an_invalid_decision_is_refused(self, client, fake_sdk):
        assert _post(client, decision="maybe").status_code == 400
        assert FakeClient.created is None

    def test_an_empty_username_is_refused(self, client, fake_sdk):
        assert _post(client, username="   ").status_code == 400
        assert FakeClient.created is None


class TestCreation:
    def test_a_valid_user_is_created_without_returning_the_password(
        self, client, fake_sdk
    ):
        response = _post(client)

        assert response.status_code == 201
        body = response.get_json()
        assert body["username"] == "operator1"
        assert body["ip_address"] == "10.0.0.5"
        assert body["decision"] is True
        # Neither the plaintext password nor the digest leaves the server.
        assert "password" not in body
        text = response.get_data(as_text=True)
        assert "s3cret-pass" not in text

    def test_the_stored_digest_is_bcrypt_with_a_pepper(self, client, fake_sdk):
        _post(client)

        created = FakeClient.created
        assert created is not None
        assert created["password"].startswith("$2")
        assert len(created["password"]) == 60
        assert created["unique_peper"].startswith("#")

    def test_a_cidr_grant_is_normalised(self, client, fake_sdk):
        _post(client, ip="10.0.0.9/24")

        assert FakeClient.created["ip_address"] == "10.0.0.0/24"

    def test_unset_blocks_by_default_semantics(self, client, fake_sdk):
        _post(client, decision="unset")

        assert FakeClient.created["decision"] is None

    def test_a_duplicate_username_is_a_conflict(self, client, fake_sdk):
        FakeClient.existing = True
        response = _post(client)

        assert response.status_code == 409
        assert FakeClient.created is None
