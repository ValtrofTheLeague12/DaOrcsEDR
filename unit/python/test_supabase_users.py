"""Unit tests for the Supabase user list join.

``allowed_users`` embeds ``ip_list`` through a unique foreign key, so PostgREST
returns the relation as an object. The reader used to accept only a list, which
made every user look decision-less ("block (default)") even when the row said
``decision = true``. These tests pin both shapes.
"""

from __future__ import annotations

import sys
from pathlib import Path

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
