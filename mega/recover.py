#!/usr/bin/env python3
"""Fetch an evidence bundle back off MEGA and prove it is intact.

    mega/recover.py --artifact quick_test
      -> <out-root>/quick_test_artifact/
      -> re-hashes the archive and compares it to the .sha256 that travelled
         with it, and cross-checks the manifest

Why the checksum is the point
----------------------------
`get` exiting 0 only means MEGA finished moving bytes. It does not mean the
bundle is the bundle that was uploaded. The bundle carries its own digest, so
recovery re-derives it and compares. A mismatch means the evidence changed in
transit or on disk, and the recovered copy should not be trusted.

Exit codes: 0 ok, 1 MEGAcmd failed, 2 no usable session, 3 MEGAcmd missing,
4 checksum mismatch (downloaded, but not what was sent), 5 not found remotely.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import megacmd  # noqa: E402

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent
SUFFIX = "_artifact"


def sha256_file(path: Path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(chunk), b""):
            h.update(block)
    return h.hexdigest()


def read_sidecar(bundle: Path, archive: Path) -> str | None:
    """The digest recorded alongside the archive, if it is there."""
    side = bundle / f"{archive.name}.sha256"
    if not side.is_file():
        return None
    try:
        return side.read_text(encoding="ascii").split()[0].strip().lower()
    except (OSError, IndexError):
        return None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--artifact", required=True,
                    help="artifact name; the remote bundle is <artifact>_artifact")
    ap.add_argument("--remote-root", default="/",
                    help="remote folder holding the bundle (default: MEGA root)")
    ap.add_argument("--out-root", default=None,
                    help=f"where to write it (default: {REPO_ROOT / 'exports'})")
    ap.add_argument("--timeout", type=int, default=megacmd.DEFAULT_TIMEOUT)
    ap.add_argument("--force", action="store_true",
                    help="overwrite an existing local copy")
    args = ap.parse_args()

    artifact = args.artifact.strip()
    if not artifact or "/" in artifact or "\\" in artifact or artifact.startswith("."):
        print("recover: --artifact must be a plain name", file=sys.stderr)
        return 2

    if not megacmd.available():
        print("recover: " + megacmd.missing_message(), file=sys.stderr)
        return 3
    who = megacmd.whoami()
    if not who:
        print("recover: no MEGAcmd session. Run: python mega/login.py --mega",
              file=sys.stderr)
        return 2

    root = args.remote_root.rstrip("/") or "/"
    remote = f"{root}/{artifact}{SUFFIX}".replace("//", "/")
    out_root = Path(args.out_root) if args.out_root else REPO_ROOT / "exports"
    local = out_root / f"{artifact}{SUFFIX}"

    print(f"[+] account {who}")
    print(f"[+] remote  {remote}")

    probe = megacmd.run("ls", remote, check=False, timeout=megacmd.QUICK_TIMEOUT)
    if probe.code != 0:
        print(f"recover: no bundle at {remote}", file=sys.stderr)
        return 5

    if local.exists() and not args.force:
        print(f"recover: {local} already exists; pass --force to merge into it.",
              file=sys.stderr)
        return 2

    out_root.mkdir(parents=True, exist_ok=True)
    # Two MEGAcmd `get` behaviours, both confirmed against a live account:
    #
    #   * The destination directory must already exist. Handed a path that does
    #     not, MEGAcmd fails with exit 55 and "is not a valid Download Folder"
    #     rather than creating it.
    #   * Without -m the bundle nests as <out_root>/<artifact>_artifact/, which
    #     is what the verification below expects. With -m the contents are
    #     merged flat into <out_root> and the wrapper folder never appears, so
    #     the checksum path below would silently look for the archive in the
    #     wrong place. -m is deliberately not used.
    print(f"[+] downloading to {out_root}")
    try:
        res = megacmd.run("get", remote, str(out_root), timeout=args.timeout)
    except megacmd.MegaError as exc:
        print(f"recover: {exc}", file=sys.stderr)
        return 1
    if res.code != 0:
        print(f"recover: get failed (exit {res.code}): "
              f"{res.err or res.out or '(no output)'}", file=sys.stderr)
        return 1

    if not local.is_dir():
        print(f"recover: download finished but {local} is missing.", file=sys.stderr)
        return 1

    # MEGAcmd will not overwrite a destination folder whose contents differ; it
    # writes a sibling suffixed " (1)" instead. So the directory that just
    # arrived is not necessarily `local`, and verifying the stale one would
    # report on the wrong bytes. Pick the most recently written match.
    candidates = [d for d in out_root.glob(f"{artifact}{SUFFIX}*") if d.is_dir()]
    if not candidates:
        print(f"recover: download finished but nothing landed in {out_root}",
              file=sys.stderr)
        return 1
    landed = max(candidates, key=lambda d: d.stat().st_mtime)
    if landed != local:
        print(f"[+] MEGAcmd wrote {landed.name} rather than replacing "
              f"{local.name}; verifying the copy it just wrote")
    local = landed

    print(f"[+] verifying {local}")
    archives = sorted(local.glob("*_evidence.tar.gz"))
    if not archives:
        print(f"recover: no *_evidence.tar.gz inside {local}", file=sys.stderr)
        return 1
    archive = archives[0]

    actual = sha256_file(archive)
    expected = read_sidecar(local, archive)
    manifest = local / "manifest.json"
    manifest_digest = None
    if manifest.is_file():
        try:
            manifest_digest = json.loads(
                manifest.read_text(encoding="utf-8")).get("archive_sha256")
        except (OSError, json.JSONDecodeError):
            manifest_digest = None

    print(f"    archive : {archive.name}  ({archive.stat().st_size} bytes)")
    print(f"    sha256  : {actual}")

    if expected is None:
        print("    sidecar : MISSING - there is no .sha256 to verify against.",
              file=sys.stderr)
        return 1
    print(f"    sidecar : {expected}")

    if manifest_digest:
        state = "match" if manifest_digest.lower() == actual else "MISMATCH"
        print(f"    manifest: {manifest_digest}  ({state})")

    if expected != actual:
        print("recover: CHECKSUM MISMATCH - this copy is not what was uploaded.",
              file=sys.stderr)
        print("        Do not trust the recovered evidence.", file=sys.stderr)
        return 4

    print("[+] OK: recovered bundle matches its recorded checksum")
    return 0


if __name__ == "__main__":
    sys.exit(main())