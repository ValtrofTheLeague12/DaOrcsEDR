#!/usr/bin/env python3
"""Package one analysis run into <artifact>_artifact/ and upload it.

    mega/upload.py --artifact quick_test
      -> exports/quick_test_analysis/           (evidence source, default)
      -> exports/quick_test_artifact/
             quick_test_evidence.tar.gz
             quick_test_evidence.tar.gz.sha256
             manifest.json
             README.txt
             [quick_test_evidence.zip           when --encrypt is given]
             [quick_test_evidence.zip.sha256    along with it]
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

Protection is the password zip in mega/protect.py: when --encrypt is given the
archive is wrapped in a WinZip AES-256 encrypted zip whose password comes from
the operator profile (never the repo), and only the zip is a candidate for
upload - the plaintext archive stays local. see protect.py for the scheme and
the password file's location.

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
import shutil
import sys
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import megacmd  # noqa: E402
import protect  # noqa: E402

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent

# Never let a credential end up inside an evidence bundle.
EXCLUDE_NAMES = {"credentials.gpg", "credentials.json", ".env", "cookies.txt"}
EXCLUDE_SUFFIXES = {".gpg", ".key", ".pem"}
# megacmd is POSIX-flavoured; keep it out of the tree so a bundle is portable.
EXCLUDE_TOP = {"mega", ".git", ".venv", "node_modules", "__pycache__"}


class BundleError(RuntimeError):
    pass


# ---------------------------------------------------------------------------
# Colour
#
# The analyzer prints ANSI colour on every path, including when stdout is a
# pipe: the console log in the admin panel parses those escapes and paints the
# line, and a run redirected to a file keeps the same bytes a terminal showed.
# The uploader is the last thing a run does, so its narration being the only
# grey block at the end of a coloured log looked like a failure to report - not
# a deliberate style. It follows the same rule, with the standard opt-outs:
# NO_COLOR (any value) and --color never turn it off, --color always forces it.
# ---------------------------------------------------------------------------
_ANSI = {
    "reset": "\x1b[0m",
    "bold": "\x1b[1m",
    "red": "\x1b[31m",
    "green": "\x1b[32m",
    "yellow": "\x1b[33m",
    "cyan": "\x1b[36m",
    "grey": "\x1b[90m",
}

_color_enabled = True


def _resolve_color(mode: str) -> bool:
    """Whether narration should carry ANSI, from --color and the environment."""
    if mode == "never" or os.environ.get("NO_COLOR") is not None:
        return False
    if mode == "always":
        return True
    force = os.environ.get("FORCE_COLOR")
    if force is not None and force.strip().lower() not in ("", "0", "false", "no", "off"):
        return True
    if os.environ.get("TERM", "").lower() == "dumb":
        return False
    return sys.stdout.isatty()


def paint(text: str, *names: str) -> str:
    if not _color_enabled or not names:
        return text
    prefix = "".join(_ANSI.get(name, "") for name in names)
    return f"{prefix}{text}{_ANSI['reset']}"


def _enable_windows_vt() -> None:
    """Turn on virtual-terminal processing for a real Windows console.

    A pipe or a redirected file needs no help; this is only for the operator
    running the uploader directly in cmd.exe, where ANSI would otherwise be
    printed as literal ``[32m`` text. Best-effort: a console that refuses the
    mode still gets plain output rather than an exception.
    """
    if os.name != "nt" or not _color_enabled:
        return
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        for device in (-11, -12):  # STD_OUTPUT_HANDLE, STD_ERROR_HANDLE
            handle = kernel32.GetStdHandle(device)
            mode = ctypes.c_uint32()
            if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                kernel32.SetConsoleMode(handle, mode.value | 0x0004)
    except Exception:  # noqa: BLE001 - colour must never break an upload
        pass


def step(message: str) -> None:
    print(f"{paint('[+]', 'green')} {message}")


def note(message: str) -> None:
    print(f"{paint('[*]', 'cyan')} {message}")


def warn(message: str) -> None:
    print(paint(message, "yellow"), file=sys.stderr)


def fail(message: str) -> None:
    print(paint(message, "red"), file=sys.stderr)


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
                 digest: str, files: int, raw_bytes: int, archive_bytes: int,
                 encryption: dict | None = None) -> Path:
    now = datetime.now(timezone.utc).astimezone()
    readme = out_dir / "README.txt"
    if encryption:
        crypto = f"""
Protection
----------
This bundle was password-protected before upload. Only the
`{encryption['sealed_file']}` file went to remote storage; the archive above
never left this host.

    algorithm        : {encryption['algorithm']}
    format           : {encryption['format']}
    protected file   : {encryption['sealed_file']} ({encryption['sealed_bytes']} bytes)
    protected sha256 : {sha256_file(out_dir / encryption['sealed_file'])}
    library          : python 'pyzipper' - WinZip AES-256 (WZ_AES), entirely
                       in-process (no gpg/openssl)

To open the protected file, on any machine that holds the PASSWORD:

    python mega/protect.py unzip {encryption['sealed_file']} --out-dir .
    (accepting a --password-file/-stdin override; the default reads the
    operator password file outside the repo)

A password that is lost is a bundle that is gone. There is no recovery path,
by design.
"""
    else:
        crypto = """
Protection
----------
NOT protected. The archive above was uploaded as-is.
"""
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
{crypto}
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
                   digest: str, members: list[tuple[str, int]],
                   encryption: dict | None = None) -> Path:
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
        # Machine-readable counterpart of the README's Protection section: a
        # consumer that has the manifest can tell whether the remote copy is
        # readable by anyone or only by whoever holds the password.
        "encrypted": bool(encryption),
    }
    if encryption:
        # The operator's password file path is deliberately NOT mirrored into
        # a manifest that itself travels to remote storage: the remote folder
        # does not need insight into the local profile.
        manifest["encryption"] = {
            "algorithm": encryption["algorithm"],
            "format": encryption["format"],
            "sealed_file": encryption["sealed_file"],
            "sealed_bytes": encryption["sealed_bytes"],
            "sealed_sha256": sha256_file(out_dir / encryption["sealed_file"]),
            "library": encryption["library"],
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
      * `mkdir -p` exits 54 ("Folder already exists") when the parent is
        already there. That wording reads like an error but reports the very
        state this sequence needs, so the exit alone decides nothing: the
        result is ARBITRATED by a listing, and only a folder that is absent
        after a failed mkdir is an error. Without this, rerunning a pipeline
        whose root survived the first run marked the whole bundle FAILED at
        upload time.
    """
    dest = remote_root.rstrip("/") or "/"
    made = megacmd.run("mkdir", "-p", dest, check=False,
                       timeout=megacmd.QUICK_TIMEOUT)
    if made.code != 0 and not remote_exists(dest):
        raise megacmd.MegaError(
            f"megacmd mkdir failed (exit {made.code}) and {dest} does not "
            f"exist: {made.err or made.out or '(no output)'}")
    megacmd.run("put", str(local_dir), dest, timeout=timeout)
    return f"{dest}/{local_dir.name}".replace("//", "/")


def stage_for_upload(out_dir: Path, artifact: str, shipped: Path,
                     shipped_name: str, encryption: dict | None):
    """The folder to actually hand to MEGAcmd, and the temp root to clean up.

    `put <folder>` uploads EVERYTHING in the folder. When the bundle is protected
    that folder still holds the plaintext archive, so uploading it as-is would
    put the evidence on a third-party account in the clear next to the
    encrypted zip - the protection would be decorative. So when protecting, only
    the shippable files are staged and the plaintext is left behind on local
    disk.

    The staged folder MUST be called `<artifact>_artifact`: MEGAcmd nests the
    upload on the folder NAME, so the remote path is derived from it. That is
    also why the staging root is a temp directory rather than exports/ - a
    differently-named sibling would land remotely as `.quick_test_artifact.upload`
    and break every consumer that expects `quick_test_artifact`.

    Returns (path, temp_root_or_None).
    """
    if not encryption:
        return out_dir, None

    root = Path(tempfile.mkdtemp(prefix="ia-bundle-upload-"))
    stage = root / f"{artifact}_artifact"
    stage.mkdir()
    for name in (shipped_name, f"{shipped_name}.sha256", "manifest.json", "README.txt"):
        src = out_dir / name
        if not src.is_file():
            raise BundleError(f"refusing to upload: {name} is missing from {out_dir}")
        # copy2 rather than a link: the stage has to be deletable afterwards
        # without any chance of touching the real bundle.
        shutil.copy2(src, stage / name)
    return stage, root


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


def build_parser() -> argparse.ArgumentParser:
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
    ap.add_argument("--encrypt", dest="encrypt", action="store_true", default=None,
                    help="wrap the archive in a password-protected zip before upload "
                         "(WinZip AES-256, in-process)")
    ap.add_argument("--no-encrypt", dest="encrypt", action="store_false",
                    help="upload the archive as-is, even when config asks for protection")
    ap.add_argument("--password-file", default=None,
                    help="password file for the zip (default: the operator password "
                         "file outside the repo, or IA_BUNDLE_PASSWORD_FILE)")
    ap.add_argument("--expect-account", default=None,
                    help="refuse to upload unless MEGAcmd is logged in as this "
                         "address (default: the email in the sealed credential)")
    ap.add_argument("--color", choices=("auto", "always", "never"), default="always",
                    help="colour the uploader's narration (default: always, so a "
                         "captured pipeline log keeps its colour; NO_COLOR also "
                         "turns it off)")

    # Compatibility with an analyzer built before protection became a password
    # zip: that binary passes --recipient/--admin-key because the bundle used to
    # be sealed to an X25519 key. The flags no longer describe anything, but
    # rejecting them turned every upload from such a binary into a usage error
    # after the bundle had already been built. Accept and ignore them here; the
    # scheme is decided by --encrypt/--no-encrypt and the operator password file.
    ap.add_argument("--recipient", choices=("user", "admin"), default=None,
                    help=argparse.SUPPRESS)
    ap.add_argument("--admin-key", default=None, help=argparse.SUPPRESS)
    return ap


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    return build_parser().parse_args(argv)


def main() -> int:
    args = parse_args()

    global _color_enabled
    _color_enabled = _resolve_color(args.color)
    _enable_windows_vt()

    artifact = args.artifact.strip()
    if not artifact or "/" in artifact or "\\" in artifact or artifact.startswith("."):
        fail("upload: --artifact must be a plain name")
        return 2

    if args.encrypt and (args.recipient is not None or args.admin_key is not None):
        # Only when protection is actually selected: an older analyzer also
        # passes --recipient on plain uploads, where it is equally inert and
        # saying so would be noise.
        note("legacy --recipient/--admin-key accepted but ignored: bundles are "
             "password-protected, not sealed to a key")

    source = Path(args.source) if args.source else REPO_ROOT / "exports" / f"{artifact}_analysis"
    if not source.is_dir():
        fail(f"upload: no evidence directory at {source}")
        return 2

    out_dir = Path(args.out_root) / f"{artifact}_artifact"
    archive = out_dir / f"{artifact}_evidence.tar.gz"

    try:
        step(f"archiving {source}")
        files, raw_bytes, archive_bytes = build_archive(source, archive)
        step(f"{archive.name}: {files} files, {raw_bytes} bytes source -> {archive_bytes} bytes")

        digest = sha256_file(archive)
        members = [(str(rel).replace("\\", "/"), p.stat().st_size)
                   for p, rel in collect(source)]

        step(f"sha256  {digest}")

        # Protection happens before the manifest and README are written, because
        # both have to record what the protected bytes hash to. Writing them
        # first would produce a bundle whose own paperwork says it is plaintext.
        encryption = None
        if args.encrypt:
            # Protect BEFORE anything leaves the machine. The plaintext archive
            # stays local; only the zip is a candidate for upload.
            out_zip = out_dir / f"{artifact}_evidence.zip"
            try:
                password = protect.read_password(
                    Path(args.password_file) if args.password_file else None)
            except protect.PasswordError as exc:
                fail(f"upload: could not protect the bundle: {exc}")
                warn("        Refusing to upload the unprotected archive.")
                return 4
            password_file_hint = (Path(args.password_file)
                                  if args.password_file else protect.password_file())
            step(f"zipping {archive.name} under a password "
                 f"(password file: {password_file_hint})")
            try:
                encryption = protect.zip_bundle(archive, out_zip, password)
            except protect.PasswordError as exc:
                # A failed protection must stop the upload. Falling through to
                # "upload the plaintext anyway" is the one outcome that would
                # silently undo the protection the operator asked for.
                fail(f"upload: could not protect the bundle: {exc}")
                warn("        Refusing to upload the unprotected archive.")
                return 4
            step(f"protected  {encryption['sealed_file']} "
                 f"({encryption['sealed_bytes']} bytes, {encryption['algorithm']})")

        # What actually goes to the remote, and the digest that describes it.
        if encryption:
            shipped = out_dir / encryption["sealed_file"]
            shipped_name = encryption["sealed_file"]
            shipped_digest = sha256_file(shipped)
        else:
            shipped = archive
            shipped_name = archive.name
            shipped_digest = digest
        # The local bundle's paperwork must match its own contents, so the
        # archive's sidecar always exists - and when the bundle is protected
        # the shipped zip gets its own, because THAT is the copy's checksum.
        (out_dir / f"{archive.name}.sha256").write_text(
            f"{digest}  {archive.name}\n", encoding="ascii")
        if shipped_name != archive.name:
            (out_dir / f"{shipped_name}.sha256").write_text(
                f"{shipped_digest}  {shipped_name}\n", encoding="ascii")

        readme = write_readme(out_dir, artifact, source, archive, digest, files,
                              raw_bytes, archive_bytes, encryption)
        manifest = write_manifest(out_dir, artifact, source, archive, digest,
                                  members, encryption)
        step(f"wrote   {readme.name}, {manifest.name}, {shipped_name}.sha256")

        if args.dry_run:
            again = out_dir / f"{artifact}_evidence.recheck.tar.gz"
            build_archive(source, again)
            again_digest = sha256_file(again)
            again.unlink()
            if again_digest != digest:
                fail(f"upload: NOT deterministic ({again_digest} != {digest})")
                return 1
            step("reproducible: rebuild produced the identical sha256")
    except BundleError as exc:
        fail(f"upload: {exc}")
        return 1

    if args.no_upload:
        step("--no-upload: bundle is local only"
             + (f" (protected as {encryption['sealed_file']})" if encryption else ""))
        return 0

    remote_root = args.remote_root or "/"
    if not find_megacmd():
        print("", file=sys.stderr)
        fail("upload: the MEGAcmd CLI is not available, so the bundle was NOT "
             "uploaded.")
        warn("        The bundle above is complete and verified; nothing was lost.")
        for line in megacmd.missing_message().splitlines():
            print(paint("        " + line, "grey"), file=sys.stderr)
        return 3

    # A wrong-account upload would file evidence under the wrong MEGA. The
    # expected address defaults to the one in the sealed credential, so the
    # guard is on by default rather than something you remember to pass.
    expected = args.expect_account or sealed_email()
    if expected:
        live = megacmd.whoami()
        if live is None:
            fail("upload: MEGAcmd has no usable session. Run: python mega/login.py --mega")
            return 1
        if live.lower() != expected.lower():
            fail(f"upload: MEGAcmd is logged in as {live}, not {expected}.")
            warn("        Refusing to upload. Fix the session and re-run.")
            return 1
        step(f"session {live}")

    expected_remote = f"{remote_root.rstrip('/')}/{artifact}_artifact".replace("//", "/")
    stage = None
    try:
        step(f"uploading {out_dir.name}/ -> {expected_remote}"
             + (f"  (protected: {shipped_name})" if encryption else ""))
        to_send, stage = stage_for_upload(out_dir, artifact, shipped, shipped_name, encryption)
        landed = upload_megacmd(to_send, remote_root, args.timeout)
        if not remote_exists(landed):
            fail(f"upload: MEGAcmd reported success but {landed} is not there.")
            return 1
        step(f"uploaded: {landed}")
        if encryption:
            step(f"protected: {encryption['sealed_file']} goes to remote; "
                 f"{archive.name} never left this host")
        return 0
    except megacmd.MegaError as exc:
        fail(f"upload: {exc}")
        return 1
    except BundleError as exc:
        fail(f"upload: {exc}")
        return 1
    finally:
        if stage is not None:
            shutil.rmtree(stage, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())