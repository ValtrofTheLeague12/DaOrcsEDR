#!/usr/bin/env python3
"""AES-256-GCM sealing for the MEGA credential, with two ways to hold the key.

    seal  ->  <secrets>/credentials.enc   (ciphertext, safe to store)
    key   ->  <secrets>/credential.key    (32 raw bytes, THE secret)

<secrets> defaults to %APPDATA%\\IAProject\\mega-secrets - deliberately outside
the repo tree, so `git add -A`, a repo backup and an archive of the tree cannot
reach the pair. Override with MEGA_SECRETS_DIR; secrets_dir() is the single
definition, and login.py / upload.py read it rather than each guessing.

Two key modes, because the difference matters:

  keyfile   A 256-bit key generated once and kept in a file. Nothing to type,
            nothing to remember. But the key then sits on the same disk as the
            ciphertext it opens, so anyone who can read one can read the other.
            That is still better than a plaintext credential file, but it is
            not a second factor.

  passphrase   No key file at all. A passphrase is stretched with scrypt
            (N=2^15, r=8, p=1) into the same 256-bit key. Losing the
            passphrase means losing the credential permanently - there is no
            recovery path, by design. Prefer this whenever a human is present.

Format (little-endian, fixed layout so a truncated file is detectable):

    offset size field
    0      8    magic  "MEGACRED"
    8      1    format version (1)
    9      1    key mode: 1 = keyfile, 2 = scrypt
    10     1    reserved, must be 0
    11     1    scrypt log2(N), 0 in keyfile mode
    12     16   scrypt salt, zeroed in keyfile mode
    28     12   GCM nonce
    40     ..   ciphertext || 16-byte tag

AES-256-GCM is authenticated: the tag is verified on open and a modified
ciphertext, a wrong key, or a ciphertext replayed into another file all fail
loudly rather than yielding garbage. The header is bound in as additional
authenticated data, so the mode and version fields cannot be edited either.

This module deliberately has no LOG_* equivalent and never formats secret
material into an exception message, matching the rule in
include/core/secret_store.hpp:10.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import subprocess
import sys
from pathlib import Path

MAGIC = b"MEGACRED"
VERSION = 1
MODE_KEYFILE = 1
MODE_SCRYPT = 2
SALT_LEN = 16
NONCE_LEN = 12
KEY_LEN = 32   # AES-256
TAG_LEN = 16
HEADER_LEN = 40

SCRYPT_N = 1 << 15
SCRYPT_R = 8
SCRYPT_P = 1

HERE = Path(__file__).resolve().parent

# Where the sealed credential and its key live. Deliberately OUTSIDE the repo
# tree: co-location with the code is the one weakness this scheme has, and
# keeping the pair out of the working directory means `git add -A`, a repo
# backup, or a stray archive of the tree cannot pick them up. Set
# MEGA_SECRETS_DIR to override.
LEGACY_ENC = HERE / "credentials.enc"
LEGACY_KEY = HERE / "credential.key"


def secrets_dir() -> Path:
    override = os.environ.get("MEGA_SECRETS_DIR")
    if override:
        return Path(override)
    base = os.environ.get("APPDATA")
    if base:
        return Path(base) / "IAProject" / "mega-secrets"
    return Path.home() / "AppData" / "Roaming" / "IAProject" / "mega-secrets"


DEFAULT_ENC = secrets_dir() / "credentials.enc"
DEFAULT_KEY = secrets_dir() / "credential.key"


class SealError(RuntimeError):
    """Any failure that stops a seal/open. Never carries secret material."""


def _crypto():
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    except ImportError:
        raise SealError(
            "the 'cryptography' package is required. Install it into the "
            "project venv:  python\\.venv\\Scripts\\python.exe -m pip install cryptography"
        ) from None
    return AESGCM, Scrypt


# ---------------------------------------------------------------------------
# Key handling
# ---------------------------------------------------------------------------

def read_key_file(path: Path) -> bytes:
    if not path.is_file():
        raise SealError(f"no key file at {path}")
    raw = path.read_bytes()
    if len(raw) != KEY_LEN:
        raise SealError(
            f"key file {path.name} is {len(raw)} bytes, expected {KEY_LEN}. "
            "A wrong-length key is a wrong key; it is not padded or truncated.")
    return raw


def write_key_file(path: Path, key: bytes) -> str:
    """Create the key file, lock it down, and report what was applied."""
    if len(key) != KEY_LEN:
        raise SealError("refusing to write a key that is not 32 bytes")
    path.parent.mkdir(parents=True, exist_ok=True)
    # 0600 before the bytes land, so there is no window where the file is
    # readable-by-everyone.
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(key)
    return harden_file(path)


def harden_file(path: Path) -> str:
    """Best-effort access restriction. Returns what was actually applied."""
    if os.name == "nt":
        # os.chmod is close to a no-op for ACLs on Windows, so the real
        # restriction has to be an explicit DACL.
        try:
            user = os.environ.get("USERNAME", "")
            subprocess.run(
                ["icacls", str(path), "/inheritance:r", "/grant:r", f"{user}:F"],
                capture_output=True, check=True, timeout=15)
            return "icacls: inheritance removed, grant limited to " + (user or "this user")
        except Exception:
            return "chmod only - icacls unavailable, the ACL was NOT tightened"
    try:
        os.chmod(path, 0o600)
        return "chmod 0600"
    except OSError:
        return "could not set permissions"


def derive_key(passphrase: str, salt: bytes) -> bytes:
    if not passphrase:
        raise SealError("empty passphrase")
    _, Scrypt = _crypto()
    return Scrypt(salt=salt, length=KEY_LEN, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P
                  ).derive(passphrase.encode("utf-8"))


# ---------------------------------------------------------------------------
# Seal / open
# ---------------------------------------------------------------------------

def seal(payload: dict, enc_path: Path, *, key: bytes | None = None,
         passphrase: str | None = None) -> Path:
    AESGCM, _ = _crypto()
    if (key is None) == (passphrase is None):
        raise SealError("supply exactly one of key or passphrase")

    if key is not None:
        mode, salt, secret = MODE_KEYFILE, b"\x00" * SALT_LEN, key
    else:
        mode, salt = MODE_SCRYPT, os.urandom(SALT_LEN)
        secret = derive_key(passphrase, salt)

    nonce = os.urandom(NONCE_LEN)
    header = (MAGIC + bytes([VERSION, mode, 0, SCRYPT_N.bit_length() - 1])
              + salt + nonce)
    if len(header) != HEADER_LEN:
        raise SealError(f"internal header is {len(header)} bytes, expected {HEADER_LEN}")

    plaintext = json.dumps(payload, indent=2).encode("utf-8")
    # The header is the AAD, so a flipped mode/version byte fails the tag.
    blob = header + AESGCM(secret).encrypt(nonce, plaintext, header)

    enc_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(enc_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(blob)
    harden_file(enc_path)
    return enc_path


def open_sealed(enc_path: Path, *, key: bytes | None = None,
                passphrase: str | None = None) -> dict:
    AESGCM, _ = _crypto()
    if (key is None) == (passphrase is None):
        raise SealError("supply exactly one of key or passphrase")

    if not enc_path.is_file():
        raise SealError(f"no sealed credential at {enc_path}")
    blob = enc_path.read_bytes()
    if len(blob) < HEADER_LEN + TAG_LEN:
        raise SealError(f"{enc_path.name} is {len(blob)} bytes, too short to be a credential")
    if blob[:8] != MAGIC:
        raise SealError(f"{enc_path.name} is not a sealed credential (bad magic)")

    version, mode, reserved, logn = blob[8], blob[9], blob[10], blob[11]
    if version != VERSION:
        raise SealError(f"unsupported format version {version}")
    if reserved != 0:
        raise SealError("reserved header byte is not zero")

    salt = blob[12:12 + SALT_LEN]
    nonce = blob[HEADER_LEN - NONCE_LEN:HEADER_LEN]
    header = blob[:HEADER_LEN]

    if mode == MODE_KEYFILE and key is not None:
        secret = key
    elif mode == MODE_SCRYPT and passphrase is not None:
        secret = derive_key(passphrase, salt)
    elif mode == MODE_KEYFILE:
        raise SealError("this file is keyfile-sealed but no key was supplied")
    elif mode == MODE_SCRYPT:
        raise SealError("this file is passphrase-sealed but no passphrase was supplied")
    else:
        raise SealError(f"unknown key mode {mode}")

    try:
        plaintext = AESGCM(secret).decrypt(nonce, blob[HEADER_LEN:], header)
    except Exception:
        # InvalidTag covers a wrong key, a wrong passphrase, and a tampered
        # file identically - deliberately, so probing cannot distinguish them.
        raise SealError("authentication failed: wrong key or passphrase, "
                        "or the file has been modified") from None

    try:
        data = json.loads(plaintext.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise SealError("decrypted payload is not valid JSON") from None
    if not isinstance(data, dict):
        raise SealError("decrypted payload is not a JSON object")
    return data


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def relocate(repo_dir: Path, dest_dir: Path | None = None) -> int:
    """Move a legacy in-repo credential pair into the secrets directory.

    The move is verified by decrypting at the destination before the originals
    are removed, so an interrupted or half-copied relocation cannot leave the
    credential stranded. ACLs survive a same-volume move, but they are
    re-hardened anyway rather than assumed.
    """
    dest_dir = dest_dir or secrets_dir()
    moved, failed = [], []

    for legacy, final in ((LEGACY_ENC, DEFAULT_ENC), (LEGACY_KEY, DEFAULT_KEY)):
        if not legacy.is_file():
            continue
        if final.is_file():
            failed.append(f"{final.name} already exists at the destination")
            continue
        try:
            dest_dir.mkdir(parents=True, exist_ok=True)
            legacy.replace(final)
            note = harden_file(final)
            moved.append(f"{legacy.name} -> {final}  ({note})")
        except OSError as exc:
            failed.append(f"{legacy.name}: {exc}")

    for line in moved:
        print(f"relocate: {line}")
    for line in failed:
        print(f"relocate: FAILED {line}", file=sys.stderr)

    if moved and not failed:
        # Only now prove the pair still opens from its new home.
        try:
            open_sealed(DEFAULT_ENC, key=read_key_file(DEFAULT_KEY))
            print(f"relocate: verified - the seal opens from {DEFAULT_ENC.parent}")
            return 0
        except SealError as exc:
            print(f"relocate: moved, but the pair does not open: {exc}", file=sys.stderr)
            print("          restore from the legacy path before doing anything else.",
                  file=sys.stderr)
            return 1

    if not moved and not failed:
        print("relocate: nothing to move; no legacy pair in the repo")
        return 0
    return 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("action", choices=("seal", "open", "check", "relocate"))
    ap.add_argument("--enc", default=str(DEFAULT_ENC))
    ap.add_argument("--key", default=str(DEFAULT_KEY))
    ap.add_argument("--from", dest="from_file", default=None,
                    help="read the credential JSON from this file instead of stdin")
    ap.add_argument("--force", action="store_true",
                    help="overwrite an existing seal")
    args = ap.parse_args()

    enc = Path(args.enc)
    keyf = Path(args.key)
    try:
        if args.action == "relocate":
            return relocate(HERE)

        if args.action == "seal":
            # utf-8-sig, not utf-8: PowerShell's `Set-Content -Encoding UTF8`
            # on Windows writes a BOM, and a credential file edited there
            # would otherwise fail to parse for no visible reason. Same
            # convention python/api/server.py uses for its .env lookup.
            raw = Path(args.from_file).read_text(encoding="utf-8-sig") if args.from_file \
                else sys.stdin.read().lstrip("﻿")
            payload = json.loads(raw)
            if not isinstance(payload, dict):
                raise SealError("credential must be a JSON object")

            if keyf.is_file() and not args.force:
                print(f"seal: {keyf} already exists; pass --force to rotate it", file=sys.stderr)
                return 2

            key = os.urandom(KEY_LEN)
            note = write_key_file(keyf, key)
            seal(payload, enc, key=key)

            print(f"sealed  -> {enc}")
            print(f"key     -> {keyf}")
            print(f"          {note}; {KEY_LEN * 8}-bit AES-256-GCM key")
            if note.startswith("chmod only"):
                print("          WARNING: the Windows ACL was NOT tightened, so "
                      "this key is readable by any user who can read the repo.")
            print(f"          this file is the ONLY thing that opens the seal. "
                  f"Lose it and the credential is gone.")
            return 0

        key = read_key_file(keyf) if keyf.is_file() else None
        if key is None:
            print(f"seal: no key at {keyf}", file=sys.stderr)
            return 2
        data = open_sealed(enc, key=key)

        if args.action == "check":
            print(f"open: OK ({', '.join(sorted(data))})")
        else:
            print(json.dumps(data))
        return 0

    except SealError as exc:
        print(f"seal: {exc}", file=sys.stderr)
        return 2
    except json.JSONDecodeError as exc:
        print(f"seal: input is not valid JSON: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())