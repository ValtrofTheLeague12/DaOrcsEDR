"""Round-trip and tamper tests for mega/seal.py.

Every negative case matters more than the happy path here: a sealing scheme
that fails to REJECT an altered bundle is worse than no sealing, because the
operator believes the evidence is protected when it is not.
"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
os.environ["IA_BUNDLE_KEYS_NO_ACL"] = "1"        # no icacls in a test
import seal  # noqa: E402

PASS, FAIL = [], []


def check(name: str, ok: bool, detail: str = "") -> None:
    (PASS if ok else FAIL).append(name)
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"  -- {detail}" if detail and not ok else ""))


def expect_seal_error(name: str, fn, *a, **kw) -> None:
    try:
        fn(*a, **kw)
    except seal.SealError as exc:
        check(name, True)
        print(f"        refused: {exc}")
        return
    except Exception as exc:                                  # noqa: BLE001
        check(name, False, f"raised {type(exc).__name__} instead of SealError: {exc}")
        return
    check(name, False, "it accepted something it should have refused")


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="seal-test-"))
    os.environ["IA_BUNDLE_KEYS_DIR"] = str(tmp / "keys")

    print("key generation")
    info = seal.keygen("user")
    check("keygen produces a 32-byte public key", len(base64_len(info)) == 32)
    check("keygen key id is 16 bytes / 32 hex", len(info["key_id"]) == 32)
    expect_seal_error("keygen refuses to overwrite a private key",
                      seal.keygen, "user")
    again = seal.keygen("user", force=True)
    check("--force mints a different key", again["key_id"] != info["key_id"])

    print("\nhappy path, small")
    small = tmp / "tiny.tar.gz"
    small.write_bytes(b"evidence" * 10)
    rec = seal.user_recipient()
    sealed = small.with_suffix(".tar.gz.enc")
    out = seal.seal_file(small, rec, sealed)
    check("sealed file exists", sealed.is_file())
    check("sealed is larger than plaintext (header + tags)", sealed.stat().st_size > small.stat().st_size)
    check("manifest records the recipient key id", out["recipient_key_id"] == seal.key_id_hex(rec.public))
    got = seal.open_file(sealed, tmp / "restored-small")
    check("round trip reproduces the bytes", (tmp / "restored-small").read_bytes() == small.read_bytes())
    check("recovered name is the original filename", got["name"] == small.name)
    check("recovered digest matches", got["sha256"] == seal._sha256_file(small).hex())

    print("\nhappy path, multi-chunk (forces the chunked path)")
    big = tmp / "big.bin"
    payload = os.urandom(3 * 1024 * 1024)          # 3 MiB -> 4 chunks
    big.write_bytes(payload)
    sealed_big = big.with_suffix(".enc")
    bigrec = seal.seal_file(big, rec, sealed_big)
    check("chunk count is ceil(size/1MiB)", bigrec["chunks"] == 3, str(bigrec["chunks"]))
    got = seal.open_file(sealed_big, tmp / "restored-big")
    check("multi-chunk round trip is byte-identical",
          (tmp / "restored-big").read_bytes() == payload)

    print("\nexact chunk boundary")
    exact = tmp / "exact.bin"
    exact.write_bytes(b"A" * seal.CHUNK_LEN)
    sealed_exact = exact.with_suffix(".enc")
    erec = seal.seal_file(exact, rec, sealed_exact)
    check("exact multiple of the chunk size is 1 chunk", erec["chunks"] == 1, str(erec["chunks"]))
    seal.open_file(sealed_exact, tmp / "restored-exact")
    check("exact-boundary round trip", (tmp / "restored-exact").read_bytes() == b"A" * seal.CHUNK_LEN)

    print("\nempty file")
    empty = tmp / "empty.bin"
    empty.write_bytes(b"")
    sealed_empty = empty.with_suffix(".enc")
    seal.seal_file(empty, rec, sealed_empty)
    seal.open_file(sealed_empty, tmp / "restored-empty")
    check("empty file round trip", (tmp / "restored-empty").read_bytes() == b"")

    print("\ntamper: content bit flip must be refused")
    raw = bytearray(sealed_big.read_bytes())
    mid = len(raw) // 2
    raw[mid] ^= 0x01
    tampered = tmp / "tampered.enc"
    tampered.write_bytes(bytes(raw))
    expect_seal_error("flipped a content bit", seal.open_file, tampered, tmp / "x1")

    print("\ntamper: truncated must be refused")
    trunc = tmp / "truncated.enc"
    trunc.write_bytes(sealed_big.read_bytes()[:len(sealed_big.read_bytes()) // 2])
    expect_seal_error("truncated file", seal.open_file, trunc, tmp / "x2")

    print("\ntamper: header field edit must be refused")
    raw = bytearray(small.with_suffix(".tar.gz.enc").read_bytes())
    raw[9] = 7                       # algorithm id
    bad_alg = tmp / "badalg.enc"
    bad_alg.write_bytes(bytes(raw))
    expect_seal_error("edited algorithm id", seal.open_file, bad_alg, tmp / "x3")

    print("\ntamper: swapped chunk order must be refused")
    raw = bytearray(sealed_big.read_bytes())
    # swap the first two chunk records wholesale
    hdr_len = seal.parse_header(bytes(raw))["header"]
    header_len = len(hdr_len) + seal.FOOTER_NONCE_LEN
    rec_size = (seal.CHUNK_NONCE + seal.CHUNK_LEN + seal.TAG_LEN)
    a = raw[header_len:header_len + rec_size]
    b = raw[header_len + rec_size:header_len + 2 * rec_size]
    raw[header_len:header_len + rec_size] = b
    raw[header_len + rec_size:header_len + 2 * rec_size] = a
    swapped = tmp / "swapped.enc"
    swapped.write_bytes(bytes(raw))
    expect_seal_error("chunk reorder", seal.open_file, swapped, tmp / "x4")

    print("\nwrong key must be refused")
    seal.keygen("user", force=True)               # rotate the local key
    expect_seal_error("bundle sealed to the previous key",
                      seal.open_file, sealed_big, tmp / "x5")
    check("no partial output left behind by a failed open",
          not (tmp / "x5").exists())

    print("\nadmin recipient")
    seal.keygen("user", force=True)
    rec2 = seal.user_recipient()
    tmpkeys = Path(os.environ["IA_BUNDLE_KEYS_DIR"])
    admin_priv, admin_pub = seal.generate_keypair()
    (tmpkeys / "admin.pub").write_text(
        __import__("base64").b64encode(admin_pub).decode() + "\n", encoding="ascii")
    adm = seal.admin_recipient()
    check("admin recipient loads", adm.key_id == seal.key_id(admin_pub))
    sealed_admin = tmp / "admin-sealed.bin"
    sealed_admin.write_bytes(b"for the lab owner")
    seal.seal_file(sealed_admin, adm, tmp / "admin-sealed.bin.enc")
    try:
        seal.open_file(tmp / "admin-sealed.bin.enc", tmp / "x6")
        check("wrong recipient is refused", False, "it opened it")
    except seal.SealError as exc:
        check("wrong recipient is refused", True)
        print(f"        refused: {exc}")
    # The whole point of a public-key recipient: the machine that ENCYPTS never
    # holds the private key, and the admin half opens it elsewhere.
    got = seal.open_file(tmp / "admin-sealed.bin.enc", tmp / "x7", admin_priv)
    check("admin private key opens it, and only the public half was needed to seal",
          (tmp / "x7").read_bytes() == b"for the lab owner")
    # A fresh, empty key directory is the only way to reach "no admin key
    # anywhere" - admin_recipient deliberately falls back through the explicit
    # path, the env var and keys_dir() before giving up.
    empty_keys = tmp / "empty-keys"
    empty_keys.mkdir()
    os.environ["IA_BUNDLE_KEYS_DIR"] = str(empty_keys)
    expect_seal_error("no admin key anywhere is reported clearly",
                      seal.admin_recipient)
    expect_seal_error("no operator keypair is reported clearly",
                      seal.user_recipient)
    os.environ["IA_BUNDLE_KEYS_DIR"] = str(tmpkeys)

    print()
    print(f"{len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("FAILED: " + ", ".join(FAIL))
    return 1 if FAIL else 0


def base64_len(info: dict) -> bytes:
    import base64
    return base64.b64decode(Path(info["public"]).read_text(encoding="ascii").strip())


if __name__ == "__main__":
    sys.exit(main())