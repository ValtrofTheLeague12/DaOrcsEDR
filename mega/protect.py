#!/usr/bin/env python3
"""Password protection for exported evidence bundles.

    protect zip <bundle.tar.gz> [--password-file X | --password-stdin]
        -> <bundle>.zip, one AES-encrypted member
    protect unzip <bundle>.zip [--password-file X | --password-stdin]
        -> recovers the archive
    protect status [--password-file X]
        -> whether a password is set, without printing it

Why this exists
---------------
The evidence bundle goes to a third-party cloud account. The old protection
sealed it to an X25519 public key, which meant a keypair - key generation,
every consumer needing the private half, and an admin key that had to be
sourced from the lab. The password scheme keeps the same guarantee with less
machinery: whoever holds the password can open what lands remotely, and
nobody who can only read the remote folder can.

Scheme
------
One ZIP member (the deterministic evidence archive), encrypted with the
ZIP format's strongest standard: WinZip AES-256 (`WZ_AES` in pyzipper, the
format's de-facto AES extension - not the legacy ZipCrypto, which is weak).
The AES extra field carries a random salt, a password-verification value and
an HMAC on every entry, so a truncated or retyped password fails closed.

The password
------------
Lives OUTSIDE the repository, in the operator profile, as raw UTF-8 bytes:
one trailing newline is tolerated and stripped on read, because editors
always add one; every other byte belongs to the password. It is never
written into a tracked repo config file and the panel never returns it from
a read. The standalone CTI catalog copies it into a git-ignored sidecar at
generation time and shows it to signed-in users, because they need it to
open the archive they downloaded. The panel offers to generate one (shown
once) or to take the operator's own.

    default location : %APPDATA%\\IAProject\\bundle-keys\\upload.password
    override         : IA_BUNDLE_PASSWORD_FILE environment variable

Per-bundle passwords
-------------------
The shared password means one leak opens every bundle. When the analyzer or
panel is told to generate a password per bundle (MEGA_PER_BUNDLE_PASSWORD),
each export instead gets its own freshly generated password, one file per
artifact under the same profile directory, and the CTI catalog shows each
bundle's value on that artifact's page - never in the manifest, the README
or any tracked file.

    default location : %APPDATA%\\IAProject\\bundle-keys\\bundles\\<artifact>.password
    override         : IA_BUNDLE_PASSWORDS_DIR (the directory)

A lost password is a lost bundle - there is no recovery path, by design.
Generating one and copying the only showing of it is how that risk is
managed: the panel copies it to the clipboard and shows it, once, exactly
as long as the operator needs to store it somewhere real.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import secrets
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import credential  # noqa: E402 - the profile-root helper this repo already has

try:
    import pyzipper
except ImportError:  # pragma: no cover - dependency matters, message matters more
    pyzipper = None

# Legacy environments may not have pyzipper; seal.py keeps working, and the
# error below is what an operator sees if they select protection meanwhile.
ABOUT = ("pyzipper is not installed - run "
         "'pip install pyzipper' (or add it to python/requirements.txt) "
         "to enable password protection")


def password_file(override: str | Path | None = None) -> Path:
    """The password file: explicit argument, env override, or the default.

    Resolution order mirrors the admin key's: an explicit path wins, then
    IA_BUNDLE_PASSWORD_FILE, then the profile default the keypairs live
    beside. The default REUSES the bundle-keys directory so everything that
    protects a bundle sits in one place outside the repo.
    """
    if override:
        return Path(override)
    env = os.environ.get("IA_BUNDLE_PASSWORD_FILE")
    if env:
        return Path(env)
    return credential.secrets_dir() / "bundle-keys" / "upload.password"


def password_present(pfile: Path | None = None) -> bool:
    """Whether a non-empty password file actually exists."""
    try:
        text = (pfile or password_file()).read_bytes()
    except OSError:
        return False
    return _decode(text) != b""


def _decode(raw: bytes) -> bytes:
    """File bytes as the password: strip exactly one trailing newline.

    Editors append one; hand-typing into the panel pastes without. Both must
    produce the same password, so at most one LF or CRLF is dropped and every
    other byte - spaces, quotes, anything - is preserved.
    """
    if raw.endswith(b"\r\n"):
        return raw[:-2]
    if raw.endswith(b"\n"):
        return raw[:-1]
    return raw


def read_password(pfile: Path | None = None) -> bytes:
    """The password as bytes, or PasswordError naming the file to fix."""
    path = pfile or password_file()
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        raise PasswordError(
            f"no bundle password is set: {path} does not exist") from None
    except OSError as exc:
        raise PasswordError(f"cannot read {path}: {exc}") from None
    password = _decode(raw)
    if not password:
        raise PasswordError(f"{path} exists but is empty - set a password first")
    return password


def set_password(value: str | bytes, pfile: Path | None = None) -> Path:
    """Write the operator's own password, byte-exact. Returns the file."""
    if isinstance(value, str):
        value = value.encode("utf-8")
    if not value:
        raise PasswordError("a password cannot be empty")
    if len(value) < 8:
        raise PasswordError(
            "a password shorter than 8 bytes is not a protection - refused "
            "rather than shrug at the weak lock")
    path = pfile or password_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    # No trailing newline: the bytes written are the password, so a read of
    # the file is the password whether or not anyone edited it by hand later.
    path.write_bytes(value)
    return path


def generate_password(length: int = 24, pfile: Path | None = None) -> tuple[str, Path]:
    """Generate and store a URL-safe random password; return it once.

    token_urlsafe gives ~5.7 bits per character, all of them printable and
    shell-safe; 24 characters puts a generated password far past anything a
    brute-force reader could surface. The caller shows the return value to
    the operator exactly once - nothing here or in upload.py prints it again.
    """
    if pfile is None:
        pfile = password_file()
    if not 12 <= length <= 128:
        raise PasswordError("length must be between 12 and 128")
    value = secrets.token_urlsafe(((length * 6) // 8))[ :length]
    set_password(value, pfile)
    return value, pfile


def clear_password(pfile: Path | None = None) -> bool:
    return (pfile or password_file()).unlink(missing_ok=True) or True


# --- per-bundle passwords ----------------------------------------------------
#
# The operator password is ONE value for every bundle. That is simple, but it
# means one leaked password opens every archive ever shipped. The per-bundle
# scheme is the compartmentalised alternative: every exported bundle gets its
# own freshly generated password, stored as one file per artifact under the
# same profile directory the operator password lives in:
#
#     %APPDATA%\IAProject\bundle-keys\bundles\<artifact>.password
#     override: IA_BUNDLE_PASSWORDS_DIR (the directory)
#
# The same invariants as the shared password: raw UTF-8 bytes, one trailing
# newline tolerated, never in a tracked repo file, never printed. The CTI
# catalog shows each bundle's value to signed-in users on that artifact's
# page, because a password nobody can look up is a bundle nobody can open.


def bundle_passwords_dir(override: str | Path | None = None) -> Path:
    """The directory holding one password file per exported bundle."""
    if override:
        return Path(override)
    env = os.environ.get("IA_BUNDLE_PASSWORDS_DIR")
    if env:
        return Path(env)
    return credential.secrets_dir() / "bundle-keys" / "bundles"


def bundle_password_file(artifact: str, override_dir: str | Path | None = None) -> Path:
    """The password file for one artifact's bundle.

    Artifact names are plain file names upstream (the uploader refuses `/`,
    `\\` and a leading dot before it ever gets here), but this is the boundary
    that turns a name into a path, so the same rules are enforced again
    rather than trusted.
    """
    if (not isinstance(artifact, str) or not artifact
            or artifact.startswith(".")
            or "/" in artifact or "\\" in artifact):
        raise PasswordError("artifact name must be a plain file name")
    return bundle_passwords_dir(override_dir) / f"{artifact}.password"


def set_bundle_password(artifact: str, value: str | bytes) -> Path:
    """Store this bundle's own password; returns the file it landed in."""
    return set_password(value, bundle_password_file(artifact))


def read_bundle_password(artifact: str) -> bytes:
    """This bundle's password as bytes, or PasswordError naming the file."""
    return read_password(bundle_password_file(artifact))


def bundle_password_present(artifact: str) -> bool:
    try:
        return password_present(bundle_password_file(artifact))
    except PasswordError:
        return False


def clear_bundle_password(artifact: str) -> bool:
    """Drop this bundle's password file; a missing one is the wanted state.

    Called when a bundle is re-exported under the shared password, so a stale
    per-bundle value can never outlive the zip it belonged to.
    """
    return bundle_password_file(artifact).unlink(missing_ok=True) or True


def generate_bundle_password(artifact: str, length: int = 24) -> tuple[bytes, Path]:
    """Generate and store a per-bundle password; return it exactly once.

    Same generator and length rules as the operator password, so a per-bundle
    value is exactly as strong as a shared one - the compartmentalisation is
    the point, not a weaker lock.
    """
    if not 12 <= length <= 128:
        raise PasswordError("length must be between 12 and 128")
    value = secrets.token_urlsafe(((length * 6) // 8))[:length].encode("utf-8")
    path = set_bundle_password(artifact, value)
    return value, path


def list_bundle_passwords() -> dict[str, bytes]:
    """Every stored per-bundle password, as {artifact: password}.

    For the CTI catalog generator, which copies the values into its
    git-ignored sidecar so a deployed server can show them to signed-in
    users. A directory that cannot be read is an empty mapping, not an
    error: no per-bundle passwords having been generated yet is a normal
    state for a checkout that never turned the option on.
    """
    directory = bundle_passwords_dir()
    out: dict[str, bytes] = {}
    try:
        files = sorted(directory.glob("*.password"))
    except OSError:
        return out
    for path in files:
        try:
            out[path.stem] = read_password(path)
        except PasswordError:
            continue
    return out


class PasswordError(RuntimeError):
    pass


def zip_bundle(archive: Path, out_zip: Path, password: bytes) -> dict:
    """Zip one archive under a password; returns the manifest fragment.

    The evidence archive is the member; bundle paperwork (manifest, README)
    travels in the staged folder beside it, as the sealed scheme did. Entries
    are written with a fixed timestamp and the archive's own bytes, so two
    runs zipping the same evidence with the same password produce the same
    ORDER and structure - the ciphertext salt makes the bytes differ per run,
    which is why the sidecar .sha256 describes the ZIP, not the archive, and
    the archive's own digest inside the manifest is the verification anchor.
    """
    if pyzipper is None:
        raise PasswordError(ABOUT)
    if not archive.is_file():
        raise PasswordError(f"nothing to protect: {archive} does not exist")
    out_zip.parent.mkdir(parents=True, exist_ok=True)
    data = archive.read_bytes()
    with pyzipper.AESZipFile(out_zip, "w",
                             compression=pyzipper.ZIP_DEFLATED,
                             compresslevel=6,
                             encryption=pyzipper.WZ_AES) as zf:
        zf.setpassword(password)
        # Build the entry header through the archive's own ZipInfo class:
        # AESZipFile.writestr re-creates the header from a bare name, which
        # would stamp the current wall-clock time in and break the fixed
        # timestamp the deterministic bundle story promises.
        info = zf.zipinfo_cls(archive.name, date_time=(1980, 1, 1, 0, 0, 0))
        info.compress_type = pyzipper.ZIP_DEFLATED
        info.external_attr = 0o600 << 16
        zf.writestr(info, data)
    size = out_zip.stat().st_size
    # Seconds, not ms: pyzipper writes DOS time and we want the manifest not
    # to imply precision the format cannot hold.
    seconds = int(time.time())
    return {
        "algorithm": "AES-256 (WinZip WZ_AES)",
        "format": "password-protected ZIP",
        "password_file": str(out_zip and password_file()),
        "sealed_file": out_zip.name,
        "sealed_bytes": size,
        "sealed_sha256": hashlib.sha256(out_zip.read_bytes()).hexdigest(),
        "chunks": 1,
        "chunk_bytes": size,
        "library": "python-pyzipper",
        "seconds": seconds,
    }


def unzip_bundle(zip_path: Path, out_dir: Path, password: bytes) -> Path:
    """Recover the archive; wrong or missing password fails closed."""
    if pyzipper is None:
        raise PasswordError(ABOUT)
    out_dir.mkdir(parents=True, exist_ok=True)
    with pyzipper.AESZipFile(zip_path, "r") as zf:
        names = zf.namelist()
        if len(names) != 1:
            raise PasswordError(f"expected exactly one member, found {len(names)}")
        zf.setpassword(password)
        target = out_dir / names[0]
        target.write_bytes(zf.read(names[0]))
    return target


def get_password_from_cli(args) -> bytes:
    """CLI password source: --password-file, --password-stdin, or the default.

    stdin reads raw and closes the world after: a password pasted into a
    terminal prompt is not echoed, so nothing leaks into a shell history.
    """
    if getattr(args, "password_stdin", False):
        raw = sys.stdin.buffer.read()
        text = _decode(raw)
        if not text:
            raise PasswordError("no password arrived on stdin")
        return text
    return read_password(Path(args.password_file) if args.password_file else None)


def main() -> int:
    if pyzipper is None:
        print(f"protect: {ABOUT}", file=sys.stderr)
        return 2
    ap = argparse.ArgumentParser(
        description="password protection for evidence bundles",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="command", required=True)

    def add_source(p):
        p.add_argument("--password-file", default=None,
                       help="password file (default: the profile dir's"
                            "bundle-keys/upload.password, or "
                            "IA_BUNDLE_PASSWORD_FILE)")
        p.add_argument("--password-stdin", action="store_true",
                       help="read the password from stdin instead of a file")
        return p

    p_zip = add_source(sub.add_parser("zip", help="zip a bundle under a password"))
    p_zip.add_argument("source", help="the evidence archive (.tar.gz)")
    p_zip.add_argument("--out", default=None,
                       help="zip path (default: beside the source, .zip)")

    p_unzip = add_source(sub.add_parser("unzip", help="recover the archive"))
    p_unzip.add_argument("zip_path")
    p_unzip.add_argument("--out-dir", default=".",
                         help="where the archive is written")

    add_source(sub.add_parser("status", help="whether a password is set (no echo)"))
    args = ap.parse_args()

    try:
        if args.command == "status":
            path = Path(args.password_file) if args.password_file else password_file()
            print(f"password file : {path}")
            print(f"password set  : {'yes' if password_present(path) else 'no'}")
            return 0
        if args.command == "zip":
            source = Path(args.source)
            out = Path(args.out) if args.out else source.with_suffix(".zip")
            password = get_password_from_cli(args)
            info = zip_bundle(source, out, password)
            print(f"[+] protected {info['sealed_file']} ({info['sealed_bytes']} bytes, "
                  f"{info['algorithm']})")
            return 0
        if args.command == "unzip":
            password = get_password_from_cli(args)
            target = unzip_bundle(Path(args.zip_path), Path(args.out_dir), password)
            print(f"[+] recovered {target}")
            return 0
    except PasswordError as exc:
        print(f"protect: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
