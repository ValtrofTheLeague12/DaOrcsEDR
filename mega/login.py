#!/usr/bin/env python3
"""Open the sealed MEGA credential and prove it is usable.

    mega/credentials.enc          ciphertext, AES-256-GCM (see credential.py)
    mega/credential.key           32 raw bytes - THE secret
    ------------------------------
    {"email": "...", "password": "..."}   what the plaintext must look like

    -> stdout / env     NEVER     -> a file on disk

The plaintext is held in memory for the lifetime of the process and is never
written anywhere. That is the whole point of sealing it: the only artefacts
that should ever touch the filesystem are the ciphertext and the key.

This opens AES-256-GCM sealed files, which is what credential.py writes. A
GPG-sealed file from the earlier design still opens, so an existing seal does
not have to be re-made:

    python mega/login.py --emit check
    python mega/login.py --emit json          # {"email": ..., "password": ...}
    python mega/login.py --emit env           # EMAIL=... / PASSWORD=...

Actual decryption lives in credential.py. Its scrypt mode derives the key from
a passphrase and needs no key file at all; see its --help.

With --mega this also establishes the MEGAcmd session, so upload.py and
recover.py have somewhere to talk to:

    python mega/login.py --emit check --mega

The session check comes first and is the common case: MEGAcmd persists its
session, so on a machine that is already signed in the password is never read,
let alone passed anywhere. Only an account with no session needs a login, and
MEGAcmd accepts a password only as a command-line argument, which is visible to
anyone who can read the process list. That step therefore needs an explicit
--allow-password, and MFA codes come from MEGA_AUTH_CODE rather than argv.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import credential  # noqa: E402
import megacmd  # noqa: E402

HERE = Path(__file__).resolve().parent

# Field names accepted in the plaintext.
REQUIRED = ("email", "password")
OPTIONAL = ("app_key", "root_node", "api_url")


class LoginError(RuntimeError):
    """Anything that stops us getting usable credentials out of the seal."""


def open_aes(enc: Path, keyf: Path, passphrase: str | None) -> dict:
    """AES-256-GCM path. Preferred; what credential.py writes."""
    if not enc.is_file():
        raise LoginError(f"no sealed credential at {enc}")
    try:
        if passphrase:
            return credential.open_sealed(enc, passphrase=passphrase)
        return credential.open_sealed(enc, key=credential.read_key_file(keyf))
    except credential.SealError as exc:
        raise LoginError(str(exc)) from None


def open_gpg(seal: Path, passphrase: str | None, passphrase_fd: int | None) -> dict:
    """Legacy GPG path, kept so an existing seal still opens."""
    if not seal.is_file():
        raise LoginError(f"no sealed credential at {seal}")
    exe = shutil.which("gpg") or shutil.which("gpg2")
    if not exe:
        raise LoginError("gpg is not on PATH")

    cmd = [exe, "--batch", "--yes", "--quiet", "--decrypt"]
    if passphrase_fd is not None:
        cmd += [f"--passphrase-fd", str(passphrase_fd)]
    else:
        cmd += ["--pinentry-mode", "loopback", "--passphrase-fd", "0"]

    proc = subprocess.run(
        cmd, input=(passphrase or "").encode() if passphrase_fd is None else None,
        capture_output=True)
    if proc.returncode != 0:
        err = proc.stderr.decode("utf-8", "replace")
        hint = "wrong passphrase, or the file is not sealed for this key"
        for marker in ("No pinentry", "Inappropriate ioctl"):
            if marker in err:
                hint = ("no passphrase available - set MEGA_GPG_PASSPHRASE "
                        "or pass --passphrase-fd")
        raise LoginError(f"gpg failed to decrypt {seal.name}: {hint}")
    if not proc.stdout:
        raise LoginError("gpg produced no plaintext")
    try:
        return json.loads(proc.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise LoginError("decrypted credential is not JSON") from None


def parse_credentials(data: dict) -> dict:
    """Shape check. Never logs or echoes a value."""
    if not isinstance(data, dict):
        raise LoginError("decrypted credential must be a JSON object")

    # Every value has to be a real string. Truthiness alone is not enough: a
    # numeric email is truthy, so {"email": 123} would sail through and then
    # fail much later as an opaque authentication failure.
    bad = [k for k, v in data.items() if not isinstance(v, str)]
    if bad:
        raise LoginError("credential value(s) must be strings: " +
                         ", ".join(f"{k}={data[k]!r}" for k in bad))

    missing = [k for k in REQUIRED if not str(data.get(k) or "").strip()]
    if missing:
        raise LoginError("decrypted credential is missing: " + ", ".join(missing))
    unknown = set(data) - set(REQUIRED) - set(OPTIONAL)
    if unknown:
        raise LoginError("unrecognised key(s) in credential: " + ", ".join(sorted(unknown)))
    return data


def ensure_mega_session(creds: dict, allow_password: bool,
                        auth_code: str | None, timeout: int) -> int:
    """Make sure MEGAcmd holds a session for this account. Never echoes secrets."""
    email = creds["email"]

    if not megacmd.available():
        print("login: " + megacmd.missing_message(), file=sys.stderr)
        return 3

    live = megacmd.whoami()
    if live and live.lower() == email.lower():
        print(f"login: MEGAcmd session OK ({live})")
        return 0
    if live:
        print(f"login: MEGAcmd is logged in as {live}, not {email}.", file=sys.stderr)
        print("        Refusing to act on the wrong account.", file=sys.stderr)
        return 1

    print(f"login: no MEGAcmd session for {email}.")
    if not allow_password:
        print("        MEGAcmd takes the password only as a command-line "
              "argument, which is readable from the process list.", file=sys.stderr)
        print("        Re-run with --allow-password if you accept that, or sign "
              "in once with mega-login.bat and re-run.", file=sys.stderr)
        return 2

    extra = [f"--auth-code={auth_code}"] if auth_code else []
    try:
        res = megacmd.run("login", *extra, email, creds["password"],
                          timeout=timeout, check=False)
    except megacmd.MegaError as exc:
        print(f"login: {exc}", file=sys.stderr)
        return 1

    # A login can report success and still not yield a usable session, so the
    # only thing that counts is whoami afterwards.
    if res.code != 0:
        print(f"login: MEGAcmd login failed (exit {res.code}):", file=sys.stderr)
        print("       " + (res.err or res.out or "(no output)"), file=sys.stderr)
        return 1

    live = megacmd.whoami()
    if live and live.lower() == email.lower():
        print(f"login: MEGAcmd session OK ({live})")
        return 0
    print("login: login returned success but MEGAcmd reports no usable session.",
          file=sys.stderr)
    if "auth" in res.text.lower() or "2fa" in res.text.lower() or "mfa" in res.text.lower():
        print("       This account looks like it needs MFA: set MEGA_AUTH_CODE "
              "and re-run.", file=sys.stderr)
    return 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--enc", default=str(credential.DEFAULT_ENC),
                    help="AES-256-GCM sealed credential")
    ap.add_argument("--key", default=str(credential.DEFAULT_KEY),
                    help="key file for a keyfile-sealed credential")
    ap.add_argument("--seal", default=str(HERE / "credentials.gpg"),
                    help="legacy GPG-sealed credential, used when --enc is absent")
    ap.add_argument("--passphrase", default=None,
                    help="unseal a scrypt-sealed credential (prefer the env var)")
    ap.add_argument("--passphrase-fd", type=int, default=None,
                    help="read a GPG passphrase from this fd instead of the env")
    ap.add_argument("--emit", choices=("json", "env", "check"), default="json",
                    help="json: raw object; env: KEY=VALUE lines; check: validate only")
    ap.add_argument("--mega", action="store_true",
                    help="also ensure a MEGAcmd session for this account")
    ap.add_argument("--allow-password", action="store_true",
                    help="permit passing the password to MEGAcmd's argv to log in")
    ap.add_argument("--auth-code", default=None,
                    help="MFA code (prefer the MEGA_AUTH_CODE env var)")
    ap.add_argument("--timeout", type=int, default=megacmd.DEFAULT_TIMEOUT,
                    help="seconds to allow a MEGAcmd login")
    args = ap.parse_args()

    enc = Path(args.enc)
    passphrase = (args.passphrase
                  or os.environ.get("MEGA_PASSPHRASE")
                  or os.environ.get("MEGA_GPG_PASSPHRASE"))

    try:
        if enc.is_file():
            data = open_aes(enc, Path(args.key), passphrase)
        elif Path(args.seal).is_file():
            data = open_gpg(Path(args.seal), passphrase, args.passphrase_fd)
        else:
            raise LoginError(
                f"no sealed credential: neither {enc.name} nor "
                f"{Path(args.seal).name} exists. Create one with "
                "python mega/credential.py seal --from cred.json")
        creds = parse_credentials(data)
    except LoginError as exc:
        print(f"login: {exc}", file=sys.stderr)
        return 2

    if args.emit == "check":
        print(f"login: credential OK ({creds['email']})")
    elif args.emit == "env":
        for k, v in creds.items():
            print(f"{k.upper()}={v}")
    else:
        print(json.dumps(creds))

    if not args.mega:
        return 0

    auth_code = args.auth_code or os.environ.get("MEGA_AUTH_CODE")
    return ensure_mega_session(creds, args.allow_password, auth_code, args.timeout)


if __name__ == "__main__":
    sys.exit(main())