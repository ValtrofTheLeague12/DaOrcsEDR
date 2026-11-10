#!/usr/bin/env python3
"""Provision CTI dashboard users, passwords and IP rights.

The generated Flask dashboard checks Supabase ``allowed_users`` + ``ip_list``.
This CLI is the supported way to create those rows without hand-writing a
bcrypt digest. It uses the same ``cti_auth`` primitives as the server, so a
password set here is verifiably the password the server expects.

Examples
--------
    python stix-server/manage_users.py list

    # Create an operator allowed only from 10.0.0.5; prints a generated
    # password once.
    python stix-server/manage_users.py create --username alice --ip 10.0.0.5 --allow

    python stix-server/manage_users.py set-password --username alice
    python stix-server/manage_users.py set-ip --username alice --ip 10.0.0.9 --allow
    python stix-server/manage_users.py delete --username alice --yes

Exit codes: 0 success, 1 failure, 2 usage/target error.
"""

from __future__ import annotations

import argparse
import ipaddress
import secrets
import string
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
SUPABASE_DIR = BASE_DIR.parent / "supabase"
for _path in (BASE_DIR, SUPABASE_DIR):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

import cti_auth  # noqa: E402


def _client():
    try:
        import User
    except ImportError as exc:  # pragma: no cover - depends on local install
        raise SystemExit(f"Supabase SDK unavailable: {exc}") from exc
    return User.SupabaseClient()


def _normalise_target(value: str) -> str:
    text = (value or "").strip()
    if not text:
        raise SystemExit("an IP address (or CIDR) is required")
    if "/" in text:
        try:
            return str(ipaddress.ip_network(text, strict=False))
        except ValueError as exc:
            raise SystemExit(f"not a valid CIDR network: {text}") from exc
    resolved = cti_auth.normalise_ip(text)
    if resolved is None:
        raise SystemExit(f"not a valid IP address: {text}")
    return resolved


def _decision(kind: str) -> bool | None:
    return {"allow": True, "block": False, "unset": None}[kind]


def _generate_password(length: int = 20) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*-_=+"
    while True:
        value = "".join(secrets.choice(alphabet) for _ in range(length))
        if (
            any(c.islower() for c in value)
            and any(c.isupper() for c in value)
            and sum(c.isdigit() for c in value) >= 3
        ):
            return value


def _find_user(client, username: str):
    user = client.get_user_by_username(username)
    if user is None:
        raise SystemExit(f"user not found: {username}")
    return user


def _describe(user, entry) -> str:
    address = getattr(entry, "ip_address", None) if entry is not None else None
    decision = getattr(entry, "decision", None) if entry is not None else None
    state = "allow" if decision is True else "block" if decision is False else "unset"
    return (
        f"id_user={user.id_user:<5} username={user.username!r:<42} "
        f"ip={address or '-':<20} decision={state}"
    )


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def command_list(client, args) -> int:
    users = client.get_all_users()
    if not users:
        print("no users")
        return 0
    for user in users:
        print(_describe(user, user if user.ip_address or user.decision is not None else None))
    return 0


def command_create(client, args) -> int:
    address = _normalise_target(args.ip)
    password = args.password or _generate_password()
    record = cti_auth.hash_password(password, pepper=args.pepper or None)
    user, entry = client.add_user_and_ip(
        username=args.username,
        password=record["password"],
        unique_peper=record["unique_peper"],
        ip_address=address,
        decision=_decision(args.decision),
    )
    print(f"created {_describe(user, entry)}")
    if args.password is None:
        print(f"password (shown once): {password}")
    return 0


def command_set_password(client, args) -> int:
    user = _find_user(client, args.username)
    password = args.password or _generate_password()
    record = cti_auth.hash_password(password, pepper=user.unique_peper or None)
    response = client.client.table("allowed_users").update({
        "password": record["password"],
        "unique_peper": record["unique_peper"],
    }).eq("id_user", user.id_user).execute()
    if not response.data:
        raise SystemExit(f"password update returned no row for {args.username}")
    print(f"password updated for {user.username!r} (id_user={user.id_user})")
    if args.password is None:
        print(f"password (shown once): {password}")
    return 0


def command_set_ip(client, args) -> int:
    user = _find_user(client, args.username)
    address = _normalise_target(args.ip)
    decision = _decision(args.decision)
    entry = client.get_ip_entry(user.id_user)
    if entry is None:
        entry = client.add_ip_entry(user.id_user, address, decision)
    else:
        response = client.client.table("ip_list").update({
            "ip_address": address,
            "decision": decision,
        }).eq("id_user", user.id_user).execute()
        if not response.data:
            raise SystemExit(f"ip update returned no row for {args.username}")
        row = response.data[0]
        entry = type(entry)(
            id_user=row["id_user"],
            ip_address=row.get("ip_address"),
            decision=row.get("decision"),
            created_at=row["created_at"],
        )
    print(f"updated {_describe(user, entry)}")
    return 0


def command_delete(client, args) -> int:
    user = _find_user(client, args.username)
    if not args.yes:
        raise SystemExit(
            f"refusing to delete {user.username!r} without --yes")
    client.client.table("ip_list").delete().eq("id_user", user.id_user).execute()
    response = client.client.table("allowed_users").delete().eq(
        "id_user", user.id_user).execute()
    if not response.data:
        raise SystemExit(f"delete returned no row for {args.username}")
    print(f"deleted {user.username!r} (id_user={user.id_user}) and its ip_list row")
    return 0


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def _add_decision_flags(parser: argparse.ArgumentParser) -> None:
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--allow", dest="decision", action="store_const", const="allow",
        help="grant access (default)")
    group.add_argument(
        "--block", dest="decision", action="store_const", const="block",
        help="deny access")
    group.add_argument(
        "--unset", dest="decision", action="store_const", const="unset",
        help="leave the decision unset (also denies access)")
    parser.set_defaults(decision="allow")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Provision CTI dashboard users, passwords and IP rights.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("list", help="list users and their IP decisions")

    create = sub.add_parser("create", help="create a user plus its IP entry")
    create.add_argument("--username", required=True)
    create.add_argument("--ip", required=True, help="address or CIDR network")
    create.add_argument("--password", default=None, help="omit to generate one")
    create.add_argument("--pepper", default=None, help="reuse a specific pepper")
    _add_decision_flags(create)

    set_password = sub.add_parser(
        "set-password", help="rotate a password (and reset an unverifiable one)")
    set_password.add_argument("--username", required=True)
    set_password.add_argument("--password", default=None, help="omit to generate one")

    set_ip = sub.add_parser("set-ip", help="set or replace a user's address/decision")
    set_ip.add_argument("--username", required=True)
    set_ip.add_argument("--ip", required=True, help="address or CIDR network")
    _add_decision_flags(set_ip)

    delete = sub.add_parser("delete", help="delete a user and its IP entry")
    delete.add_argument("--username", required=True)
    delete.add_argument("--yes", action="store_true", help="confirm deletion")

    return parser


_COMMANDS = {
    "list": command_list,
    "create": command_create,
    "set-password": command_set_password,
    "set-ip": command_set_ip,
    "delete": command_delete,
}


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        client = _client()
        return _COMMANDS[args.command](client, args)
    except SystemExit:
        raise
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
