#!/usr/bin/env python3
"""Public-key encryption for exported evidence bundles, with no subprocess.

    seal keygen user            -> generates the operator keypair
    seal encrypt <bundle> ...   -> <bundle>.enc + a sidecar envelope
    seal decrypt <bundle>.enc   -> recovers the original bundle
    seal whoami                 -> prints the recipient key id

Why this exists
---------------
An evidence bundle is uploaded to a third-party cloud account. Until now the
tarball went up exactly as the analyzer wrote it, so anyone who could read the
remote folder - the provider, a leaked session, a shared link - could read the
sample-derived evidence. Encryption closes that: only the holder of a private
key can open what lands remotely, and the operator chooses which key that is.

Scheme
------
A hybrid envelope, the standard construction for "encrypt a big file to a
public key":

    content key   32 random bytes (AES-256), fresh per bundle
    content       AES-256-GCM over the bundle, chunked
    wrap          AES-256-GCM over the content key
    wrapping key  HKDF-SHA256(ECDH(ephemeral X25519, recipient X25519))

X25519 rather than RSA because it is the modern default, needs no key-size
choice to be safe, and both halves are available in `cryptography`. HKDF is
what turns the raw ECDH output - which is uniformly random but not a key -
into a key. AES-256-GCM is authenticated in both places, so a bundle that was
truncated, reordered or altered on the far end fails to open instead of
yielding garbage.

Recipients
----------
Two, and the operator picks per export:

    user    a keypair generated on this machine by `seal keygen user`
    admin   a public key supplied by whoever runs the lab. Only the PUBLIC half
            is needed to encrypt, so the admin private key never has to exist
            on the machine that produces evidence.

Both are X25519. A private key that cannot decrypt is a permanently lost
bundle, which is why the private key is generated once, stored outside the repo
tree, and its fingerprint is recorded in the manifest next to the ciphertext.

Chunking
--------
`cryptography` has no streaming AEAD, so the whole plaintext would have to sit
in memory. Evidence bundles carry disassembly and hexdumps and can reach
hundreds of megabytes, so the content is encrypted in 1 MiB chunks. Each chunk
gets its own nonce, derived from the base nonce by XOR with its index (the
counter cannot repeat without reusing a (key, nonce) pair, which would be
catastrophic for GCM), and binds the header plus its own index and length as
associated data so chunks cannot be swapped, dropped or replayed.

Container
---------
Fixed layout, magic first, little-endian, so a truncated file is detectable
and a wrong file is refused rather than misparsed:

    offset size field
    0      8    magic  "IABUNDLE"
    8      1    format version (1)
    9      1    algorithm id (1 = X25519 + HKDF-SHA256 + AES-256-GCM)
    10     2    header length (the chunked format is self-delimiting)
    12     16   recipient key id (SHA-256 of the recipient public key, first 16)
    28     1    chunk size exponent (log2 of the chunk size, default 20)
    29     3    reserved, must be zero
    32     32   ephemeral X25519 public key
    64     16   HKDF salt
    80     12   wrap nonce
    92     4    wrapped key length
    96     ..   wrapped key (content key + content nonce + original name + digest)
    ..     12   base content nonce
    ..     ..   chunk records: nonce(12) | length(4) | ciphertext+tag

The wrapped key blob carries the ORIGINAL FILENAME and the SHA-256 of the
plaintext. The name is needed to write the recovered file back with a sensible
name; the digest lets `decrypt` prove it reconstructed what was sealed rather
than merely something that decrypts.

No subprocess
-------------
Everything here is `cryptography` in-process. There is no `gpg`, no `openssl`,
no shelling out. The one exception in this file is `harden_private_key`, which
runs `icacls` on Windows to strip inherited ACLs from the key file - that is
filesystem hardening, not cryptography, and it is best-effort. Windows
`os.chmod` only toggles a read-only flag, so without it the private key would
inherit whatever the directory allows; pass --no-acl to skip it.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import getpass
import hashlib
import json
import os
import secrets
import sys
from dataclasses import dataclass
from pathlib import Path

MAGIC = b"IABUNDLE"
VERSION = 1
ALG_X25519_AESGCM = 1

KEY_ID_LEN = 16
EPH_LEN = 32
SALT_LEN = 16
NONCE_LEN = 12
CONTENT_KEY_LEN = 32
CHUNK_EXP = 20                      # 1 MiB
CHUNK_LEN = 1 << CHUNK_EXP
CHUNK_NONCE = 12 + 4                # nonce(12) | length(4) per record
WRAP_OVERHEAD = 4 + 16              # u32 length prefix + GCM tag
TAG_LEN = 16
FOOTER_NONCE_LEN = 12
HEADER_FIXED = 96


class SealError(RuntimeError):
    """Any failure to seal, open or authenticate. Never carries key material."""


# ---------------------------------------------------------------------------
# Key material
# ---------------------------------------------------------------------------

def keys_dir() -> Path:
    """Where bundle keys live. OUTSIDE the repo tree, by the same reasoning as
    mega/credential.py: co-location with the code is the one weakness this
    scheme has, and an ignored-but-present private key is still a private key
    that a `git add -A` or a backup of the tree can pick up."""
    override = os.environ.get("IA_BUNDLE_KEYS_DIR")
    if override:
        return Path(override)
    base = os.environ.get("APPDATA")
    if base:
        return Path(base) / "IAProject" / "bundle-keys"
    return Path.home() / ".config" / "iaproject" / "bundle-keys"


def _require(what: str, original: Exception | None = None):
    """Raise a legible error when the crypto library is missing.

    The imports below are lazy on purpose: seal.py is imported by upload.py,
    which the analyzer runs on machines that may never seal anything, and a hard
    import at module scope would make the uploader fail for a feature it is not
    using. Only the code path that actually needs the library checks for it.

    The original ImportError text is kept because "cryptography is missing" and
    "cryptography is installed but its C extension will not load" are different
    problems with different fixes, and the second one hides behind the first.
    """
    detail = f"\n        underlying error: {original}" if original else ""
    raise SealError(
        f"{what} is unavailable: the 'cryptography' package could not be loaded."
        f"{detail}\n        install it with: python -m pip install cryptography")


def _x25519():
    try:
        from cryptography.hazmat.primitives.asymmetric import x25519
    except ImportError as exc:
        _require("X25519 key exchange", exc)
    return x25519


def _aead():
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError as exc:
        _require("AES-256-GCM", exc)
    return AESGCM


def _hkdf():
    try:
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    except ImportError as exc:
        _require("HKDF", exc)
    return HKDF


def _sha256():
    try:
        from cryptography.hazmat.primitives import hashes
    except ImportError as exc:
        _require("SHA-256", exc)
    return hashes.SHA256


def key_id(public_bytes: bytes) -> bytes:
    """16-byte fingerprint of a public key, recorded in every envelope.

    Truncated SHA-256 is used as an identifier, not as a security control: it
    only has to make "which key was this sealed to" answerable by eye, and
    every real security property comes from the ECDH exchange."""
    return hashlib.sha256(b"IA-BUNDLE-KEY-ID\x00" + public_bytes).digest()[:KEY_ID_LEN]


def key_id_hex(public_bytes: bytes) -> str:
    return key_id(public_bytes).hex()


def generate_keypair() -> tuple[bytes, bytes]:
    x25519 = _x25519()
    priv = x25519.X25519PrivateKey.generate()
    return priv.private_bytes_raw(), priv.public_key().public_bytes_raw()


def harden_private_key(path: Path) -> str:
    """Best-effort ACL restriction. Returns what was actually applied."""
    if os.name == "nt":
        if os.environ.get("IA_BUNDLE_KEYS_NO_ACL"):
            return "skipped (IA_BUNDLE_KEYS_NO_ACL set)"
        import subprocess                      # filesystem hardening only
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


@dataclass
class Recipient:
    """A public key plus the identity that goes in the envelope."""
    public: bytes
    name: str

    @property
    def key_id(self) -> bytes:
        return key_id(self.public)


def user_recipient() -> Recipient:
    path = keys_dir() / "user.pub"
    if not path.is_file():
        raise SealError(
            f"no operator keypair at {path}. Create one with: seal keygen user")
    try:
        public = base64.b64decode(path.read_text(encoding="ascii").strip())
    except (ValueError, binascii.Error) as exc:
        raise SealError(f"{path} is not valid base64: {exc}") from None
    if len(public) != EPH_LEN:
        raise SealError(f"{path} is {len(public)} bytes, expected {EPH_LEN}")
    return Recipient(public=public, name="user")


def admin_recipient(config_path: Path | None = None) -> Recipient:
    """The lab's public key. Only the public half is needed to encrypt."""
    candidates: list[Path] = []
    if config_path:
        candidates.append(Path(config_path))
    env = os.environ.get("IA_BUNDLE_ADMIN_PUBKEY")
    if env:
        candidates.append(Path(env))
    candidates.append(keys_dir() / "admin.pub")

    for cand in candidates:
        if cand.is_file():
            text = cand.read_text(encoding="ascii").strip()
            # Accept the raw base64 the tool writes, or a PEM public key, so an
            # operator can hand over a key generated by any tool they trust.
            if "BEGIN" in text:
                public = _public_from_pem(cand)
            else:
                try:
                    public = base64.b64decode(text)
                except (ValueError, binascii.Error) as exc:
                    raise SealError(f"{cand} is neither base64 nor PEM: {exc}") from None
            if len(public) != EPH_LEN:
                raise SealError(
                    f"{cand} holds a {len(public)}-byte key; this scheme is X25519 (32 bytes)")
            return Recipient(public=public, name="admin")
    raise SealError(
        "no admin public key. Put a base64 X25519 public key at "
        f"{keys_dir() / 'admin.pub'}, or set IA_BUNDLE_ADMIN_PUBKEY")


def _public_from_pem(path: Path) -> bytes:
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    key = load_pem_public_key(path.read_bytes())
    x25519 = _x25519()
    if not isinstance(key, x25519.X25519PublicKey):
        raise SealError(f"{path} is not an X25519 public key")
    return key.public_bytes_raw()


# ---------------------------------------------------------------------------
# Envelope
# ---------------------------------------------------------------------------

def _derive_wrapping_key(ephemeral_private_raw: bytes, recipient_public: bytes,
                          salt: bytes) -> bytes:
    """ECDH, then HKDF. The ECDH output is not a key until HKDF says so."""
    x25519 = _x25519()
    HKDF = _hkdf()
    hashes = _sha256()
    shared = x25519.X25519PrivateKey.from_private_bytes(
        ephemeral_private_raw).exchange(x25519.X25519PublicKey.from_public_bytes(recipient_public))
    return HKDF(
        algorithm=hashes(), length=CONTENT_KEY_LEN, salt=salt,
        info=b"IABUNDLE v1 content-wrap key",
    ).derive(shared)


def _chunk_nonce(base: bytes, index: int) -> bytes:
    """base XOR counter. Never repeats a (key, nonce) pair, which for GCM is
    the one unrecoverable mistake."""
    n = int.from_bytes(base, "big")
    return (n ^ (index + 1)).to_bytes(len(base), "big")


def build_header(recipient: Recipient, ephemeral_public: bytes, salt: bytes,
                 wrap_nonce: bytes, wrapped: bytes) -> bytes:
    header = bytearray()
    header += MAGIC
    header.append(VERSION)
    header.append(ALG_X25519_AESGCM)
    # Offset 10 is the HEADER length, not the wrapped-key length, and it is only
    # known once the rest is laid out - it is what lets a reader find the body
    # without having to trust the wrapped-key length on its own. Assembled back
    # to front so the real value is what gets written.
    header += (HEADER_FIXED + len(wrapped)).to_bytes(2, "little")
    header += recipient.key_id
    header.append(CHUNK_EXP)
    header += b"\x00\x00\x00"
    header += ephemeral_public
    header += salt
    header += wrap_nonce
    header += len(wrapped).to_bytes(4, "little")
    header += wrapped
    assert len(header) == HEADER_FIXED + len(wrapped), (len(header), len(wrapped))
    return bytes(header)


def parse_header(blob: bytes) -> dict:
    if len(blob) < HEADER_FIXED:
        raise SealError("file is shorter than a bundle header - truncated or not a sealed bundle")
    if blob[:8] != MAGIC:
        raise SealError("not a sealed bundle (bad magic)")
    version = blob[8]
    if version != VERSION:
        raise SealError(f"bundle format version {version}, this tool writes {VERSION}")
    alg = blob[9]
    if alg != ALG_X25519_AESGCM:
        raise SealError(f"unknown algorithm id {alg}")
    declared = int.from_bytes(blob[10:12], "little")
    if declared > len(blob):
        raise SealError("header length runs past the end of the file - truncated")
    # `declared` is the total header size measured from offset 0, magic included.
    hdr = blob[:declared]
    # The wrapped-key length sits in the LAST four fixed bytes, immediately before
    # the ciphertext, so it is read at HEADER_FIXED-4 and not at HEADER_FIXED.
    len_at = HEADER_FIXED - 4
    if len(hdr) < HEADER_FIXED:
        raise SealError("header is missing the wrapped-key length")
    wrapped_len = int.from_bytes(hdr[len_at:len_at + 4], "little")
    if len(hdr) != HEADER_FIXED + wrapped_len:
        raise SealError("header length disagrees with the wrapped key size")
    off = HEADER_FIXED
    return {
        # The raw header is kept because it is the AAD for every content chunk.
        # Re-deriving it field by field would risk a mismatch that silently
        # fails authentication on every chunk.
        "header": hdr,
        "recipient_key_id": hdr[12:12 + KEY_ID_LEN],
        "chunk_exp": hdr[12 + KEY_ID_LEN],
        "ephemeral": hdr[12 + KEY_ID_LEN + 4:12 + KEY_ID_LEN + 4 + EPH_LEN],
        "salt": hdr[12 + KEY_ID_LEN + 4 + EPH_LEN:12 + KEY_ID_LEN + 4 + EPH_LEN + SALT_LEN],
        "wrap_nonce": hdr[12 + KEY_ID_LEN + 4 + EPH_LEN + SALT_LEN:
                          12 + KEY_ID_LEN + 4 + EPH_LEN + SALT_LEN + NONCE_LEN],
        "wrapped": hdr[off:off + wrapped_len],
        "body": blob[declared:],
    }


def _wrap_blob(content_key: bytes, content_nonce: bytes, name: str, digest: bytes) -> bytes:
    """What actually gets encrypted to the recipient: the content key, the
    content nonce, and the metadata needed to put the file back and prove it."""
    name_bytes = name.encode("utf-8")
    if len(name_bytes) > 512:
        raise SealError(f"filename is too long to seal: {name[:40]}...")
    inner = len(content_key).to_bytes(2, "little") + content_key + content_nonce \
        + len(name_bytes).to_bytes(2, "little") + name_bytes + digest
    return inner


def seal_file(source: Path, recipient: Recipient, out_path: Path | None = None) -> dict:
    """Encrypt `source` to `recipient`. Returns the manifest fragment."""
    if not source.is_file():
        raise SealError(f"nothing to seal at {source}")
    AESGCM = _aead()

    content_key = secrets.token_bytes(CONTENT_KEY_LEN)
    content_nonce = secrets.token_bytes(FOOTER_NONCE_LEN)
    eph_priv_raw, eph_pub = generate_keypair()
    salt = secrets.token_bytes(SALT_LEN)
    wrap_nonce = secrets.token_bytes(NONCE_LEN)
    digest = _sha256_file(source)

    wrapping = _derive_wrapping_key(eph_priv_raw, recipient.public, salt)
    inner = _wrap_blob(content_key, content_nonce, source.name, digest)
    wrapped = AESGCM(wrapping).encrypt(wrap_nonce, inner, b"IABUNDLE-wrap")
    header = build_header(recipient, eph_pub, salt, wrap_nonce, wrapped)

    cipher = AESGCM(content_key)
    base_nonce = content_nonce

    out_path = out_path or source.with_suffix(source.suffix + ".enc")
    tmp = out_path.with_suffix(out_path.suffix + ".tmp")
    try:
        with source.open("rb") as fh, tmp.open("wb") as out:
            out.write(header)
            out.write(base_nonce)
            index = 0
            while True:
                chunk = fh.read(CHUNK_LEN)
                if not chunk:
                    break
                nonce = _chunk_nonce(base_nonce, index)
                aad = header + index.to_bytes(4, "little") + len(chunk).to_bytes(4, "little")
                out.write(nonce)
                out.write(len(chunk).to_bytes(4, "little"))
                out.write(cipher.encrypt(nonce, chunk, aad))
                index += 1
            out.flush()
            os.fsync(out.fileno())
        os.replace(tmp, out_path)
    finally:
        if tmp.exists():
            tmp.unlink(missing_ok=True)

    return {
        "encrypted": True,
        "algorithm": "X25519+HKDF-SHA256+AES-256-GCM",
        "format": "IABUNDLE/1",
        "recipient": recipient.name,
        "recipient_key_id": key_id_hex(recipient.public),
        "sealed_file": out_path.name,
        "sealed_bytes": out_path.stat().st_size,
        "source_bytes": source.stat().st_size,
        "source_sha256": digest.hex(),
        "chunks": index,
        "chunk_bytes": CHUNK_LEN,
    }


def open_file(sealed: Path, out_path: Path | None = None,
              private_raw: bytes | None = None) -> dict:
    """Decrypt with the operator private key, then prove the plaintext digest.

    Returns {path, name, sha256, bytes, chunks}. Raises SealError rather than
    writing anything partial: a bundle that fails to authenticate must not leave
    a half-written file that looks like a successful recovery.
    """
    blob = sealed.read_bytes()
    head = parse_header(blob)
    header = head["header"]
    if private_raw is None:
        private_raw = load_user_private()
    if key_id(_public_of(private_raw)) != head["recipient_key_id"]:
        raise SealError(
            "this bundle was sealed to a different key than the one on this machine "
            f"(sealed to {head['recipient_key_id'].hex()}, local key "
            f"{key_id_hex(_public_of(private_raw))})")

    AESGCM = _aead()
    wrapping = _derive_wrapping_key(private_raw, head["ephemeral"], head["salt"])
    try:
        inner = AESGCM(wrapping).decrypt(head["wrap_nonce"], head["wrapped"], b"IABUNDLE-wrap")
    except Exception:
        raise SealError("could not unwrap the content key - wrong private key, "
                        "or the envelope was altered") from None

    off = 0
    key_len = int.from_bytes(inner[off:off + 2], "little"); off += 2
    content_key = inner[off:off + key_len]; off += key_len
    content_nonce = inner[off:off + FOOTER_NONCE_LEN]; off += FOOTER_NONCE_LEN
    name_len = int.from_bytes(inner[off:off + 2], "little"); off += 2
    name = inner[off:off + name_len].decode("utf-8", "replace"); off += name_len
    want_digest = inner[off:off + 32]

    body = head["body"]
    if len(body) < FOOTER_NONCE_LEN:
        raise SealError("bundle body is truncated")
    if body[:FOOTER_NONCE_LEN] != content_nonce:
        raise SealError("content nonce does not match the wrapped key - envelope altered")
    data = body[FOOTER_NONCE_LEN:]

    out_path = out_path or sealed.with_suffix("")
    if out_path.is_dir():
        out_path = out_path / name
    tmp = out_path.with_suffix(out_path.suffix + ".part")

    cipher = AESGCM(content_key)
    running = hashlib.sha256()
    written = 0
    index = 0
    try:
        with tmp.open("wb") as out:
            while data:
                if len(data) < CHUNK_NONCE:
                    raise SealError(f"chunk {index} is truncated")
                nonce = data[:NONCE_LEN]
                length = int.from_bytes(data[NONCE_LEN:CHUNK_NONCE], "little")
                data = data[CHUNK_NONCE:]
                if len(data) < length + TAG_LEN:
                    raise SealError(
                        f"chunk {index} claims {length} bytes but the file ends first")
                sealed_chunk = data[:length + TAG_LEN]
                data = data[length + TAG_LEN:]
                # Same AAD the sealer bound: the header, then this chunk's index
                # and length. Swapping, dropping or reordering chunks breaks it.
                aad = header + index.to_bytes(4, "little") + length.to_bytes(4, "little")
                try:
                    plain = cipher.decrypt(nonce, sealed_chunk, aad)
                except Exception:
                    raise SealError(
                        f"chunk {index} failed authentication - the sealed file was "
                        "altered, truncated, or sealed with a different key") from None
                out.write(plain)
                running.update(plain)
                written += len(plain)
                index += 1
            out.flush()
            os.fsync(out.fileno())

        got = running.digest()
        if got != want_digest:
            tmp.unlink(missing_ok=True)
            raise SealError(
                "recovered bundle does not match the digest recorded when it was sealed "
                f"(got {got.hex()}, expected {want_digest.hex()})")
        os.replace(tmp, out_path)
    finally:
        if tmp.exists():
            tmp.unlink(missing_ok=True)

    return {"path": out_path, "name": name, "sha256": got.hex(),
            "bytes": written, "chunks": index}


def _sha256_file(path: Path, chunk: int = 1 << 20) -> bytes:
    """Raw digest, not hex: the bytes go straight into the wrapped key, which
    is itself ciphertext, so a hex round trip would only add a way to get it
    wrong."""
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(chunk), b""):
            h.update(block)
    return h.digest()


def _public_of(private_raw: bytes) -> bytes:
    x25519 = _x25519()
    return x25519.X25519PrivateKey.from_private_bytes(private_raw).public_key().public_bytes_raw()


def load_user_private() -> bytes:
    path = keys_dir() / "user.key"
    if not path.is_file():
        raise SealError(
            f"no operator private key at {path}. The bundle was sealed to a key this "
            "machine does not hold.")
    raw = base64.b64decode(path.read_text(encoding="ascii").strip())
    if len(raw) != EPH_LEN:
        raise SealError(f"{path} is {len(raw)} bytes, expected {EPH_LEN}")
    return raw


# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------

def keygen(name: str, force: bool = False) -> dict:
    directory = keys_dir()
    directory.mkdir(parents=True, exist_ok=True)
    priv_path = directory / f"{name}.key"
    pub_path = directory / f"{name}.pub"
    if priv_path.exists() and not force:
        raise SealError(
            f"{priv_path} already exists. Overwriting a private key would make every "
            "bundle already sealed to it unrecoverable, so this refuses unless --force.")
    priv, pub = generate_keypair()
    priv_path.write_text(base64.b64encode(priv).decode("ascii") + "\n", encoding="ascii")
    pub_path.write_text(base64.b64encode(pub).decode("ascii") + "\n", encoding="ascii")
    applied = harden_private_key(priv_path)
    return {"name": name, "private": priv_path, "public": pub_path,
            "key_id": key_id_hex(pub), "hardening": applied}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def cmd_keygen(args: argparse.Namespace) -> int:
    if args.name == "admin":
        print("The admin key is NOT generated here: encrypting needs only its PUBLIC "
              "half, and the private half belongs with whoever administers the lab.",
              file=sys.stderr)
        print("Ask them for a base64 X25519 public key and save it to "
              f"{keys_dir() / 'admin.pub'}, or set IA_BUNDLE_ADMIN_PUBKEY.", file=sys.stderr)
        return 2
    try:
        info = keygen(args.name, force=args.force)
    except SealError as exc:
        print(f"seal: {exc}", file=sys.stderr)
        return 1
    print(f"[+] {info['name']} keypair")
    print(f"    private : {info['private']}  ({info['hardening']})")
    print(f"    public  : {info['public']}")
    print(f"    key id  : {info['key_id']}")
    print()
    print("Hand the public half to whoever should receive bundles. The private half")
    print("never leaves this machine and cannot be recovered if lost.")
    return 0


def cmd_whoami(args: argparse.Namespace) -> int:
    try:
        rec = user_recipient()
    except SealError as exc:
        print(f"seal: {exc}", file=sys.stderr)
        return 1
    print(f"user key id : {key_id_hex(rec.public)}")
    print(f"public      : {base64.b64encode(rec.public).decode('ascii')}")
    return 0


def cmd_encrypt(args: argparse.Namespace) -> int:
    try:
        recipient = admin_recipient(Path(args.admin_key)) if args.to == "admin" \
            else user_recipient()
        source = Path(args.bundle)
        out = seal_file(source, recipient, Path(args.out) if args.out else None)
    except SealError as exc:
        print(f"seal: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(out, indent=2))
    return 0


def cmd_decrypt(args: argparse.Namespace) -> int:
    try:
        if args.private:
            private_raw = base64.b64decode(
                getpass.getpass("private key (base64): ").strip())
        else:
            private_raw = None
        result = open_file(Path(args.sealed), Path(args.out) if args.out else None,
                           private_raw)
    except SealError as exc:
        print(f"seal: {exc}", file=sys.stderr)
        return 1
    print(f"[+] recovered {result['name']}")
    print(f"    path   : {result['path']}")
    print(f"    bytes  : {result['bytes']} in {result['chunks']} chunk(s)")
    print(f"    sha256 : {result['sha256']}  (matches the digest recorded at seal time)")
    return 0


def cmd_inspect(args: argparse.Namespace) -> int:
    """Header only - no key needed, so it can be read by anyone holding the file."""
    try:
        head = parse_header(Path(args.sealed).read_bytes()[:1 << 20])
    except SealError as exc:
        print(f"seal: {exc}", file=sys.stderr)
        return 1
    print(f"format      : IABUNDLE/{VERSION} (alg {ALG_X25519_AESGCM} = "
          "X25519 + HKDF-SHA256 + AES-256-GCM)")
    print(f"recipient   : {head['recipient_key_id'].hex()}")
    print(f"chunk size  : {1 << head['chunk_exp']} bytes")
    print("private key required to open this")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="seal", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    k = sub.add_parser("keygen", help="generate the operator keypair")
    k.add_argument("name", nargs="?", default="user", choices=["user"])
    k.add_argument("--force", action="store_true",
                   help="overwrite an existing private key (orphans older bundles)")
    k.set_defaults(fn=cmd_keygen)

    sub.add_parser("whoami", help="show this machine's operator key id").set_defaults(fn=cmd_whoami)

    e = sub.add_parser("encrypt", help="seal a bundle to a recipient's public key")
    e.add_argument("bundle")
    e.add_argument("--to", choices=["user", "admin"], default="user")
    e.add_argument("--admin-key", help="path to the admin public key (PEM or base64)")
    e.add_argument("--out")
    e.set_defaults(fn=cmd_encrypt)

    d = sub.add_parser("decrypt", help="open a sealed bundle with the operator private key")
    d.add_argument("sealed")
    d.add_argument("--out")
    d.add_argument("--private", action="store_true",
                   help="read the private key interactively instead of from disk")
    d.set_defaults(fn=cmd_decrypt)

    i = sub.add_parser("inspect", help="read the header without any key")
    i.add_argument("sealed")
    i.set_defaults(fn=cmd_inspect)

    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())