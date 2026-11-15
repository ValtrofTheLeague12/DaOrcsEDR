"""Unit tests for the Supabase user list join.

``allowed_users`` embeds ``ip_list`` through a unique foreign key, so PostgREST
returns the relation as an object. The reader used to accept only a list, which
made every user look decision-less ("block (default)") even when the row said
``decision = true``. These tests pin both shapes.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
SUPABASE = REPO / "supabase"
if str(SUPABASE) not in sys.path:
    sys.path.insert(0, str(SUPABASE))

from supabase_sdk.users import SupabaseClient  # noqa: E402


class _Response:
    def __init__(self, data):
        self.data = data


class _Query:
    def __init__(self, data):
        self._data = data

    def select(self, *_args, **_kwargs):
        return self

    def order(self, *_args, **_kwargs):
        return self

    def execute(self):
        return _Response(self._data)


class _Client:
    def __init__(self, rows):
        self._rows = rows

    def table(self, name):
        assert name == "allowed_users"
        return _Query(self._rows)


def _reader(rows):
    # Bypass __init__: it decrypts live credentials, which a unit test must not
    # need. get_all_users only touches self.client.
    client = object.__new__(SupabaseClient)
    client.client = _Client(rows)
    return client


def _row(id_user: int, ip_list):
    return {
        "id_user": id_user,
        "username": f"user{id_user}",
        "password": "digest",
        "unique_peper": "#pepper",
        "created_at": "2026-01-01T00:00:00+00:00",
        "ip_list": ip_list,
    }


def test_to_one_embed_is_a_dict_and_keeps_the_decision():
    client = _reader([
        _row(15, {
            "id_user": 15,
            "ip_address": "192.168.56.105",
            "decision": True,
            "created_at": "2026-01-01T00:00:00+00:00",
        }),
    ])

    users = client.get_all_users()

    assert len(users) == 1
    assert users[0].id_user == 15
    assert users[0].ip_address == "192.168.56.105"
    assert users[0].decision is True
    assert users[0].allowed is True


def test_to_many_embed_is_a_list_and_uses_the_first_row():
    client = _reader([
        _row(14, [{
            "id_user": 14,
            "ip_address": "10.0.0.5",
            "decision": False,
            "created_at": "2026-01-01T00:00:00+00:00",
        }]),
    ])

    users = client.get_all_users()

    assert users[0].ip_address == "10.0.0.5"
    assert users[0].decision is False
    assert users[0].allowed is False


def test_missing_ip_row_is_unset_not_allowed():
    client = _reader([_row(13, None)])

    users = client.get_all_users()

    assert users[0].ip_address is None
    assert users[0].decision is None
    assert users[0].allowed is False


# ---------------------------------------------------------------------------
# Uniqueness: one username per account, one IP address per grant.
#
# A duplicate username lets two operators collide on one login; a duplicated
# IP grant means two accounts can sign in from the same machine. Both are
# checked before an insert happens, so a rejected create leaves no partial
# user row behind.
# ---------------------------------------------------------------------------

class _InsertClient:
    """A fake that answers table queries by name with canned rows."""

    def __init__(self, allowed_rows=(), ip_rows=(), inserted=None):
        self._allowed = list(allowed_rows)
        self._ip = list(ip_rows)
        self.inserted = inserted

    def table(self, name):
        return _InsertQuery(self, name)


class _InsertQuery:
    def __init__(self, owner, name):
        self._owner = owner
        self._name = name
        self._row = None

    def select(self, *_args, **_kwargs):
        return self

    def eq(self, _column, value):
        # The only eq() the uniqueness checks make is username/ip_address.
        if self._name == "allowed_users":
            self._rows = [r for r in self._owner._allowed
                          if r.get("username") == value]
        else:
            self._rows = [r for r in self._owner._ip
                          if r.get("ip_address") == value]
        return self

    def insert(self, row):
        self._row = row
        return self

    def execute(self):
        if self._row is not None:
            self._owner.inserted = self._row
            return _Response([dict(self._row, id_user=99,
                                   created_at="2026-01-01T00:00:00+00:00")])
        return _Response(getattr(self, "_rows", []))


def _make_writer(allowed_rows=(), ip_rows=()):
    client = object.__new__(SupabaseClient)
    client.client = _InsertClient(allowed_rows, ip_rows)
    return client


def test_add_user_refuses_a_duplicate_username():
    client = _make_writer(allowed_rows=[
        {"id_user": 5, "username": "vmtest", "password": "d",
         "unique_peper": "#p", "created_at": "x"}])

    with pytest.raises(Exception) as excinfo:
        client.add_user("vmtest", "digest", "#pepper")

    assert "username must be unique" in str(excinfo.value)
    assert client.client.inserted is None


def test_add_user_and_ip_refuses_an_ip_granted_to_someone_else():
    client = _make_writer(ip_rows=[
        {"id_user": 5, "ip_address": "192.168.56.105", "decision": True,
         "created_at": "x"}])

    with pytest.raises(Exception) as excinfo:
        client.add_user_and_ip("newuser", "digest", "#pepper",
                               "192.168.56.105", True)

    assert "ip_address must be unique" in str(excinfo.value)
    assert "id_user 5" in str(excinfo.value)
    # Nothing was written: the user row does not exist either.
    assert client.client.inserted is None


def test_add_user_and_ip_allows_a_fresh_username_and_ip():
    client = _make_writer()

    user, _entry = client.add_user_and_ip(
        "newuser", "digest", "#pepper", "192.168.56.105", True)

    assert user.username == "newuser"
    assert client.client.inserted["ip_address"] == "192.168.56.105"


def test_add_ip_entry_ignores_unset_addresses():
    # A user whose own row has no address yet is not in conflict with anyone.
    client = _make_writer(ip_rows=[
        {"id_user": 5, "ip_address": None, "decision": None,
         "created_at": "x"}])

    entry = client.add_ip_entry(5, "10.0.0.5", True)

    assert entry.ip_address == "10.0.0.5"
