#!/usr/bin/env python3
"""Seal one analysis run into <artifact>_artifact/ and upload it.

    mega/upload.py --artifact quick_test
      -> exports/quick_test_analysis/           (evidence source, default)
      -> exports/quick_test_artifact/
             quick_test_evidence.tar.gz
             quick_test_evidence.tar.gz.sha256
             manifest.json
             README.txt
      -> remote folder: quick_test_artifact/

On zlib: zlib is deflate, not tar. It cannot write an archive on its own - it
is a compression codec. The archive structure comes from tarfile and the
compression from zlib underneath it, which is what `tarfile.open(mode="w:gz")`
does (verified: gzip magic 1f8b, zlib-ng 1.3.1 in this venv). So the archive is
a real .tar.gz, and zlib is genuinely the thing doing the deflating.

Two properties this script goes out of its way to keep:

  * The checksum is taken over the finished file on disk, not over a stream
    being generated. The tar is written, closed, then hashed, then uploaded, so
    the SHA-256 in the README is provably the hash of the bytes MEGA received.
  * The archive is deterministic. uid/gid/uname/gname/mtime are normalised and
    members are sorted, so re-running produces a byte-identical tar and the same
    checksum. For evidence that means a rebuild can be *verified*, not just
    repeated.

Uploads go through the MEGAcmd CLI. When it is not installed, the bundle is
still built and verified locally and the script says exactly what is missing -
the archive half of the job does not depend on MEGA being reachable.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import platform
import sys
import tarfile
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import megacmd  # noqa: E402

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent

# Never let a credential end up inside an evidence bundle.
EXCLUDE_NAMES = {"credentials.gpg", "credentials.json", ".env", "cookies.txt"}
EXCLUDE_SUFFIXES = {".gpg", ".key", ".pem"}
# megacmd is POSIX-flavoured; keep it out of the tree so a bundle is portable.
EXCLUDE_TOP = {"mega", ".git", ".venv", "node_modules", "__pycache__"}


class BundleError(RuntimeError):
    pass


def sha256_file(path: Path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(chunk), b""):
            h.update(block)
    return h.hexdigest()


def _excluded(rel: Path) -> bool:
    if rel.name in EXCLUDE_NAMES or rel.suffix in EXCLUDE_SUFFIXES:
        return True
    return bool(rel.parts) and rel.parts[0] in EXCLUDE_TOP


def collect(source: Path) -> list[tuple[Path, Path]]:
    """(source_path, path_relative_to_source) for everything that ships."""
    out = []
    for root, dirs, files in os.walk(source):
        rel_root = Path(root).relative_to(source)
        dirs[:] = sorted(d for d in dirs if not _excluded(rel_root / d))
        for name in sorted(files):
            rel = rel_root / name
            if _excluded(rel):
                continue
            p = Path(root) / name
            if p.is_symlink() or not p.is_file():
                continue
            out.append((p, rel))
    return sorted(out, key=lambda t: str(t[1]).replace("\\", "/"))


def build_archive(source: Path, archive: Path) -> tuple[int, int, int]:
    """Write a deterministic .tar.gz.

    Returns (file_count, raw source bytes, archive bytes). The raw total is
    summed from the members rather than reported as the archive size - those
    are different numbers and conflating them makes the bundle's own README
    misstate how much evidence it holds.
    """
    members = collect(source)
    if not members:
        raise BundleError(f"nothing to archive under {source}")

    archive.parent.mkdir(parents=True, exist_ok=True)
    if archive.exists():
        archive.unlink()

    # A fixed epoch and empty owner fields: identical inputs must give an
    # identical archive, or the checksum cannot be used to prove anything.
    epoch = 0
    with archive.open("wb") as raw:
        # gzip is driven directly rather than through tarfile's "w:gz", because
        # that shorthand stamps the current wall-clock time into the gzip header
        # and a repo path into its name field - both of which change the digest
        # on every run and make the checksum worthless for verification.
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw,
                           compresslevel=6, mtime=0) as gz:
            with tarfile.open(fileobj=gz, mode="w", format=tarfile.PAX_FORMAT) as tar:
                for path, rel in members:
                    info = tar.gettarinfo(str(path), arcname=str(rel).replace("\\", "/"))
                    info.uid = info.gid = 0
                    info.uname = info.gname = ""
                    info.mtime = epoch
                    info.mode = 0o755 if info.isdir() else 0o644
                    with path.open("rb") as fh:
                        tar.addfile(info, fh)
    raw_bytes = sum(p.stat().st_size for p, _ in members)
    return len(members), raw_bytes, archive.stat().st_size


def write_readme(out_dir: Path, artifact: str, source: Path, archive: Path,
                 digest: str, files: int, raw_bytes: int, archive_bytes: int) -> Path:
    now = datetime.now(timezone.utc).astimezone()
    readme = out_dir / "README.txt"
    readme.write_text(
        f"""Evidence bundle - {artifact}
{'=' * (18 + len(artifact))}

generated at      : {now.isoformat(timespec='seconds')}
generated at (utc): {now.astimezone(timezone.utc).isoformat(timespec='seconds')}
host              : {platform.node()}
platform          : {platform.system()} {platform.release()} ({platform.machine()})
python            : {platform.python_version()}

source            : {source}
archive           : {archive.name}
archive algorithm : tar + gzip (zlib {__import__('zlib').ZLIB_VERSION})
files archived    : {files}
source bytes      : {raw_bytes}
archive bytes     : {archive_bytes}

SHA-256           : {digest}
                   {archive.name}.sha256 holds the same digest in
                   `<digest>  <filename>` form, so `sha256sum -c` verifies it.

Restore
-------
    sha256sum -c {archive.name}.sha256
    tar -xzf {archive.name}

The archive is deterministic: member order is sorted and uid/gid/uname/gname/
mtime are normalised, so rebuilding it from the same evidence yields the same
SHA-256. A mismatch means the evidence changed, not that the tooling drifted.
""", encoding="utf-8")
    return readme


def write_manifest(out_dir: Path, artifact: str, source: Path, archive: Path,
                   digest: str, members: list[tuple[str, int]]) -> Path:
    now = datetime.now(timezone.utc).astimezone()
    manifest = {
        "artifact": artifact,
        "generated_at": now.isoformat(timespec="seconds"),
        "generated_at_utc": now.astimezone(timezone.utc).isoformat(timespec="seconds"),
        "source": str(source),
        "archive": archive.name,
        "archive_sha256": digest,
        "archive_bytes": archive.stat().st_size,
        "file_count": len(members),
        "files": [{"path": p, "size": s} for p, s in members],
        "tool": "mega/upload.py",
    }
    path = out_dir / "manifest.json"
    path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return path


def find_megacmd() -> bool:
    """True when the MEGAcmd CLI can be invoked.

    Not `shutil.which("megacmd")` - that is the POSIX binary name and returns
    None on Windows, where the CLI is MEGAclient.exe and the shims are
    mega-*.bat. megacmd.available() knows about both; see megacmd.py.
    """
    return megacmd.available()


def upload_megacmd(local_dir: Path, remote_root: str, timeout: int) -> str:
    """Upload the bundle folder. Returns the remote path it landed at.

    Three MEGAcmd behaviours set the sequence, all confirmed against a live
    account rather than taken from the docs:

      * The destination must already exist. If `put -c` is allowed to create
        it, MEGAcmd treats it as a container and writes the bundle's *contents*
        in flat - `Upload finished: /<dest>` - with no <artifact>_artifact/
        wrapper. So `mkdir -p` runs first and the upload is then reliably a
        nest. The two paths differ only in whether the folder was already
        there, which is exactly the sort of thing a checksum cannot catch and
        a post-upload listing can.
      * `put <folder> <dest>` nests into <dest>/<foldername>, so the
        destination is the PARENT of the artifact folder.
      * `mkdir` is silent on success, so its exit status alone does not prove
        much - which is why remote_exists() re-checks afterwards.
    """
    dest = remote_root.rstrip("/") or "/"
    megacmd.run("mkdir", "-p", dest, timeout=megacmd.QUICK_TIMEOUT)
    megacmd.run("put", str(local_dir), dest, timeout=timeout)
    return f"{dest}/{local_dir.name}".replace("//", "/")


def remote_exists(remote_path: str) -> bool:
    return megacmd.run("ls", remote_path, check=False,
                       timeout=megacmd.QUICK_TIMEOUT).code == 0


def sealed_email() -> str | None:
    """The account email held in the local seal, or None if unavailable.

    Deliberately best-effort: an unreadable or absent seal must not stop an
    upload, it just means the wrong-account guard cannot be armed by default.
    Only the address is returned, never the password.
    """
    try:
        import credential
        enc, key = credential.DEFAULT_ENC, credential.DEFAULT_KEY
        if not (enc.is_file() and key.is_file()):
            return None
        return credential.open_sealed(
            enc, key=credential.read_key_file(key)).get("email")
    except Exception:
        return None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--artifact", required=True,
                    help="artifact name; the bundle is <artifact>_artifact")
    ap.add_argument("--source", default=None,
                    help="evidence directory (default: exports/<artifact>_analysis)")
    ap.add_argument("--out-root", default=str(REPO_ROOT / "exports"),
                    help="where the bundle directory is written")
    ap.add_argument("--remote-root", default=None,
                    help="MEGA root folder; the bundle lands in <remote>/<artifact>_artifact")
    ap.add_argument("--no-upload", action="store_true",
                    help="build and verify the bundle only")
    ap.add_argument("--dry-run", action="store_true",
                    help="also build a second bundle and prove the checksum reproduces")
    ap.add_argument("--timeout", type=int, default=megacmd.DEFAULT_TIMEOUT,
                    help="seconds to allow the MEGAcmd upload")
    ap.add_argument("--expect-account", default=None,
                    help="refuse to upload unless MEGAcmd is logged in as this "
                         "address (default: the email in the sealed credential)")
    args = ap.parse_args()

    artifact = args.artifact.strip()
    if not artifact or "/" in artifact or "\\" in artifact or artifact.startswith("."):
        print("upload: --artifact must be a plain name", file=sys.stderr)
        return 2

    source = Path(args.source) if args.source else REPO_ROOT / "exports" / f"{artifact}_analysis"
    if not source.is_dir():
        print(f"upload: no evidence directory at {source}", file=sys.stderr)
        return 2

    out_dir = Path(args.out_root) / f"{artifact}_artifact"
    archive = out_dir / f"{artifact}_evidence.tar.gz"

    try:
        print(f"[+] archiving {source}")
        files, raw_bytes, archive_bytes = build_archive(source, archive)
        print(f"[+] {archive.name}: {files} files, {raw_bytes} bytes source -> {archive_bytes} bytes")

        digest = sha256_file(archive)
        (out_dir / f"{archive.name}.sha256").write_text(
            f"{digest}  {archive.name}\n", encoding="ascii")

        members = [(str(rel).replace("\\", "/"), p.stat().st_size)
                   for p, rel in collect(source)]
        readme = write_readme(out_dir, artifact, source, archive, digest, files, raw_bytes, archive_bytes)
        manifest = write_manifest(out_dir, artifact, source, archive, digest, members)

        print(f"[+] sha256  {digest}")
        print(f"[+] wrote   {readme.name}, {manifest.name}, {archive.name}.sha256")

        if args.dry_run:
            again = out_dir / f"{artifact}_evidence.recheck.tar.gz"
            build_archive(source, again)
            again_digest = sha256_file(again)
            again.unlink()
            if again_digest != digest:
                print(f"upload: NOT deterministic ({again_digest} != {digest})", file=sys.stderr)
                return 1
            print("[+] reproducible: rebuild produced the identical sha256")
    except BundleError as exc:
        print(f"upload: {exc}", file=sys.stderr)
        return 1

    if args.no_upload:
        print("[+] --no-upload: bundle is local only")
        return 0

    remote_root = args.remote_root or "/"
    if not find_megacmd():
        print("", file=sys.stderr)
        print("upload: the MEGAcmd CLI is not available, so the bundle was NOT "
              "uploaded.", file=sys.stderr)
        print("        The bundle above is complete and verified; nothing was lost.",
              file=sys.stderr)
        for line in megacmd.missing_message().splitlines():
            print("        " + line, file=sys.stderr)
        return 3

    # A wrong-account upload would file evidence under the wrong MEGA. The
    # expected address defaults to the one in the sealed credential, so the
    # guard is on by default rather than something you remember to pass.
    expected = args.expect_account or sealed_email()
    if expected:
        live = megacmd.whoami()
        if live is None:
            print("upload: MEGAcmd has no usable session. Run: python mega/login.py --mega",
                  file=sys.stderr)
            return 1
        if live.lower() != expected.lower():
            print(f"upload: MEGAcmd is logged in as {live}, not {expected}.",
                  file=sys.stderr)
            print("        Refusing to upload. Fix the session and re-run.",
                  file=sys.stderr)
            return 1
        print(f"[+] session {live}")

    expected_remote = f"{remote_root.rstrip('/')}/{artifact}_artifact".replace("//", "/")
    try:
        print(f"[+] uploading {out_dir.name}/ -> {expected_remote}")
        landed = upload_megacmd(out_dir, remote_root, args.timeout)
        if not remote_exists(landed):
            print(f"upload: MEGAcmd reported success but {landed} is not there.",
                  file=sys.stderr)
            return 1
        print(f"[+] uploaded: {landed}")
        return 0
    except megacmd.MegaError as exc:
        print(f"upload: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())