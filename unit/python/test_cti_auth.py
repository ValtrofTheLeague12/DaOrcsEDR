"""Unit tests for the generated CTI server's auth primitives."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
STIX = REPO / "stix-server"
if str(STIX) not in sys.path:
    sys.path.insert(0, str(STIX))

import cti_auth  # noqa: E402

SECRET = "test-session-secret"


# ---------------------------------------------------------------------------
# Passwords
# ---------------------------------------------------------------------------

def test_hash_and_verify_roundtrip():
    record = cti_auth.hash_password("correct horse battery staple")
    assert cti_auth.is_bcrypt_hash(record["password"])
    assert record["unique_peper"].startswith("#")
    assert cti_auth.verify_password(
        "correct horse battery staple",
        record["password"],
        record["unique_peper"],
    )


def test_verify_rejects_wrong_password_and_pepper():
    record = cti_auth.hash_password("hunter2", pepper="#abc123")
    assert not cti_auth.verify_password(
        "hunter3", record["password"], record["unique_peper"])
    assert not cti_auth.verify_password(
        "hunter2", record["password"], "#different")


def test_verify_rejects_malformed_or_legacy_input():
    assert not cti_auth.verify_password("x", "", "")
    assert not cti_auth.verify_password("x", "not-a-bcrypt-digest", "#e80be")
    assert not cti_auth.verify_password(None, "$2b$12$" + "x" * 53, "")
    assert not cti_auth.verify_password("x", None, None)


def test_hash_password_rejects_empty():
    with pytest.raises(ValueError):
        cti_auth.hash_password("")


def test_hash_password_keeps_supplied_pepper():
    record = cti_auth.hash_password("pw", pepper="#keepme")
    assert record["unique_peper"] == "#keepme"
    assert cti_auth.verify_password("pw", record["password"], "#keepme")


def test_burn_password_check_never_raises():
    cti_auth.burn_password_check("whatever")
    cti_auth.burn_password_check(None)


# ---------------------------------------------------------------------------
# IP handling
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(("raw", "expected"), [
    ("127.0.0.1", "127.0.0.1"),
    ("  10.0.0.5  ", "10.0.0.5"),
    ("::ffff:127.0.0.1", "127.0.0.1"),
    ("[2001:db8::1]:443", "2001:db8::1"),
    ("1.2.3.4:5678", "1.2.3.4"),
    ("", None),
    ("not-an-ip", None),
    (None, None),
])
def test_normalise_ip(raw, expected):
    assert cti_auth.normalise_ip(raw) == expected


def test_client_ip_ignores_forwarded_for_by_default():
    assert cti_auth.client_ip("10.0.0.5", "1.2.3.4") == "10.0.0.5"


def test_client_ip_uses_first_forwarded_address_when_trusted():
    assert cti_auth.client_ip(
        "10.0.0.5", "1.2.3.4, 10.0.0.1", trust_proxy=True) == "1.2.3.4"


def test_client_ip_rejects_garbage_forwarded_header():
    assert cti_auth.client_ip(
        "10.0.0.5", "unknown", trust_proxy=True) == "10.0.0.5"


def test_ip_matches_exact_and_cidr():
    assert cti_auth.ip_matches("10.0.0.5", "10.0.0.5")
    assert cti_auth.ip_matches("10.0.0.5", "10.0.0.0/24")
    assert not cti_auth.ip_matches("10.0.1.5", "10.0.0.0/24")
    assert not cti_auth.ip_matches("10.0.0.5", "")
    assert not cti_auth.ip_matches(None, "10.0.0.5")


def test_check_access_matrix():
    assert cti_auth.check_access(
        {"decision": True, "ip_address": "10.0.0.5"}, "10.0.0.5") == (True, "ok")

    allowed, reason = cti_auth.check_access(None, "10.0.0.5")
    assert not allowed and "No access record" in reason

    allowed, reason = cti_auth.check_access(
        {"decision": False, "ip_address": "10.0.0.5"}, "10.0.0.5")
    assert not allowed and "not allowed" in reason

    allowed, reason = cti_auth.check_access(
        {"decision": None, "ip_address": "10.0.0.5"}, "10.0.0.5")
    assert not allowed and "not allowed" in reason

    allowed, reason = cti_auth.check_access(
        {"decision": True, "ip_address": None}, "10.0.0.5")
    assert not allowed and "No IP address" in reason

    allowed, reason = cti_auth.check_access(
        {"decision": True, "ip_address": "10.0.0.0/24"}, "10.0.0.99")
    assert allowed

    allowed, reason = cti_auth.check_access(
        {"decision": True, "ip_address": "10.0.0.5"}, "10.0.0.6")
    assert not allowed and "This IP address" in reason


def test_check_access_loopback_bypass_requires_allow_decision():
    allowed, _ = cti_auth.check_access(
        {"decision": True, "ip_address": "10.0.0.5"}, "127.0.0.1",
        allow_loopback=True)
    assert allowed

    allowed, _ = cti_auth.check_access(
        {"decision": False, "ip_address": "10.0.0.5"}, "127.0.0.1",
        allow_loopback=True)
    assert not allowed

    allowed, _ = cti_auth.check_access(
        {"decision": True, "ip_address": "10.0.0.5"}, "10.0.0.6",
        allow_loopback=True)
    assert not allowed


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------

def test_session_roundtrip_and_ip_binding():
    signer = cti_auth.SessionSigner(SECRET)
    token = signer.issue(14, "alice", "10.0.0.5")
    payload = signer.read(token, "10.0.0.5")
    assert payload is not None
    assert payload["uid"] == 14
    assert payload["username"] == "alice"
    assert signer.read(token, "10.0.0.6") is None
    assert signer.read(token, None) is None
    assert signer.read("garbage", "10.0.0.5") is None
    assert signer.read(token[:-2] + "xx", "10.0.0.5") is None


def test_session_rejects_other_secret():
    token = cti_auth.SessionSigner(SECRET).issue(1, "alice", "10.0.0.5")
    assert cti_auth.SessionSigner("other-secret").read(token, "10.0.0.5") is None


def test_session_expiry():
    signer = cti_auth.SessionSigner(SECRET, max_age_seconds=1)
    token = signer.issue(1, "alice", "10.0.0.5")
    signer.max_age_seconds = -1  # force every signed payload to be stale
    assert signer.read(token, "10.0.0.5") is None


def test_session_requires_valid_ip():
    signer = cti_auth.SessionSigner(SECRET)
    with pytest.raises(ValueError):
        signer.issue(1, "alice", "not-an-ip")


def test_read_with_reason_explains_each_rejection():
    signer = cti_auth.SessionSigner(SECRET)
    token = signer.issue(14, "alice", "10.0.0.5")

    payload, reason = signer.read_with_reason(token, "10.0.0.5")
    assert payload is not None and reason == "ok"

    assert signer.read_with_reason(None, "10.0.0.5") == (
        None, "no session cookie")
    assert signer.read_with_reason("", "10.0.0.5") == (
        None, "no session cookie")
    assert signer.read_with_reason("garbage", "10.0.0.5")[1] == "bad signature"
    assert signer.read_with_reason(token, None)[1] == (
        "request address is not a valid IP")

    payload, reason = signer.read_with_reason(token, "10.0.0.6")
    assert payload is None and "session is bound to" in reason

    expired = cti_auth.SessionSigner(SECRET, max_age_seconds=1)
    stale = expired.issue(14, "alice", "10.0.0.5")
    expired.max_age_seconds = -1
    assert expired.read_with_reason(stale, "10.0.0.5") == (
        None, "session expired")

    # The silent variant must never leak the reason.
    assert signer.read(token, "10.0.0.6") is None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(("raw", "expected"), [
    ("/", "/"),
    ("/artifact/x?tab=asm", "/artifact/x?tab=asm"),
    ("//evil.example", "/"),
    ("https://evil.example", "/"),
    ("/\\evil", "/"),
    ("/\r\nSet-Cookie: x", "/"),
    (None, "/"),
    ("", "/"),
])
def test_safe_next_path(raw, expected):
    assert cti_auth.safe_next_path(raw) == expected


def test_failure_tracker_blocks_after_limit():
    tracker = cti_auth.FailureTracker(max_attempts=2, window_seconds=60)
    assert not tracker.blocked("alice|10.0.0.5")
    tracker.record_failure("alice|10.0.0.5")
    assert not tracker.blocked("alice|10.0.0.5")
    tracker.record_failure("alice|10.0.0.5")
    assert tracker.blocked("alice|10.0.0.5")
    assert tracker.retry_after("alice|10.0.0.5") > 0
    tracker.reset("alice|10.0.0.5")
    assert not tracker.blocked("alice|10.0.0.5")


def test_session_key_is_persisted_and_env_overrides(tmp_path, monkeypatch):
    monkeypatch.delenv("CTI_SESSION_KEY", raising=False)
    path = tmp_path / "config" / ".session-key"

    first = cti_auth.load_session_key(path)
    assert first
    assert path.is_file()
    assert cti_auth.load_session_key(path) == first

    monkeypatch.setenv("CTI_SESSION_KEY", "from-environment")
    assert cti_auth.load_session_key(path) == "from-environment"
