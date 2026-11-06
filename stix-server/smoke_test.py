#!/usr/bin/env python3
"""Self-contained smoke test for stix-server/mega_client.py.

Local-only by default: it builds a tiny evidence folder, protects it, decrypts
it, and runs the safe restore/verify path in a temporary directory. No MEGA
upload and no network.

    python stix-server/smoke_test.py
    python stix-server/smoke_test.py --remote     # also read the live listing
    python stix-server/smoke_test.py --keep       # leave the temp bundle

Exit code 0 means every local assertion passed.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from mega_client import MegaArgumentError, MegaClient  # noqa: E402


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)
    print(f"PASS  {message}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--remote", action="store_true",
                    help="also exercise the live listing/link read path")
    ap.add_argument("--remote-root", default="/",
                    help="MEGA folder to list with --remote (e.g. /evidence)")
    ap.add_argument("--keep", action="store_true",
                    help="keep the temporary directory for inspection")
    args = ap.parse_args(argv)

    client = MegaClient(remote_root=args.remote_root)
    print(f"repo   : {client.repo_root}")
    print(f"remote : {client.remote_root}")
    status = client.status()
    print(f"status : available={status['available']} "
          f"session={status['session_ok']} password={status['password_present']}")

    root = Path(tempfile.mkdtemp(prefix="mega-sdk-smoke-"))
    try:
        source = root / "analysis"
        (source / "stix").mkdir(parents=True)
        (source / "stix" / "bundle.json").write_text(json.dumps({
            "type": "bundle",
            "id": "bundle--00000000-0000-4000-8000-000000000000",
            "objects": [],
        }), encoding="utf-8")
        (source / "notes.txt").write_text("smoke evidence\n", encoding="utf-8")
        (source / ".env").write_text("SECRET=must-not-ship\n", encoding="utf-8")

        password_file = root / "upload.password"
        client.set_password("sdk-smoke-password", password_file)
        check(client.password_present(password_file), "temporary password is readable")

        # 1. blocking build + protection, no upload
        out_root = root / "out"
        result = client.export(
            "sdk_smoke",
            source=source,
            out_root=out_root,
            encrypt=True,
            password_file=password_file,
            no_upload=True,
        )
        check(result.ok, f"export(no_upload=True) exit {result.returncode}")

        bundle = out_root / "sdk_smoke_artifact"
        check(bundle.is_dir(), "bundle directory exists")
        check((bundle / "sdk_smoke_evidence.tar.gz").is_file(), "archive exists")
        check((bundle / "sdk_smoke_evidence.tar.gz.sha256").is_file(), "sidecar exists")
        check((bundle / "sdk_smoke_evidence.zip").is_file(), "protected zip exists")
        check((bundle / "manifest.json").is_file(), "manifest exists")

        manifest = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
        check(manifest["encrypted"] is True, "manifest records protection")
        check(manifest["file_count"] == 2, "manifest counts 2 shipped files")
        check(all(".env" not in f["path"] for f in manifest["files"]),
              ".env was excluded")

        # 2. decrypt the zip back to the archive
        decrypted = client.decrypt_archive(
            bundle / "sdk_smoke_evidence.zip",
            root / "decrypted",
            password_file=password_file,
        )
        check(decrypted.is_file(), "decrypt_archive recovered the tar.gz")
        check(decrypted.name == "sdk_smoke_evidence.tar.gz", "recovered file name is right")

        # 3. safe restore/verify from the local bundle (no network)
        restored = root / "restored"
        verified = client.retrieve(
            "sdk_smoke",
            verify_only=True,
            bundle=bundle,
            dest=restored,
        )
        check(verified.ok, f"retrieve(verify_only=True) exit {verified.returncode}")
        check((restored / "stix" / "bundle.json").is_file(),
              "restored STIX bundle is present")
        check(not (restored / ".env").exists(), ".env did not reach the restore")

        remote_command, remote_data, _ = client._retrieve_command(
            "/evidence/sdk_smoke_artifact")
        check(remote_command[2:] == [
            str(client.mega_dir / "restore.py"),
            "--artifact", "sdk_smoke",
            "--remote-root", "/evidence",
        ], "full remote bundle path resolves to artifact and parent")
        check(remote_data["remote_path"] == "/evidence/sdk_smoke_artifact",
              "full remote path is preserved in result data")

        restored_from_path = root / "restored-from-path"
        verified_from_path = client.retrieve_bundle(
            "/evidence/sdk_smoke_artifact",
            verify_only=True,
            bundle=bundle,
            dest=restored_from_path,
        )
        check(verified_from_path.ok, "retrieve_bundle accepts a full remote path")
        check((restored_from_path / "stix" / "bundle.json").is_file(),
              "retrieve_bundle restores to the requested destination")

        # 4. Job wrapper for the same build
        job_out = root / "job-out"
        job = client.start_export(
            "sdk_smoke_job",
            source=source,
            out_root=job_out,
            encrypt=False,
            no_upload=True,
        )
        check(job.poll() is None or job.poll() == 0, "job started")
        job_result = job.wait(timeout=120)
        check(job_result.ok, f"Job wait exit {job_result.returncode}")
        check("archiving" in job_result.stdout.lower(), "job captured narration")
        check((job_out / "sdk_smoke_job_artifact" / "manifest.json").is_file(),
              "job built its manifest")

        # 5. argument validation
        for bad in ("", "../x", "a/b", "quick_test_artifact"):
            try:
                client.bundle_path(bad)
            except MegaArgumentError:
                pass
            else:
                raise AssertionError(f"accepted invalid name {bad!r}")
        check(True, "invalid names are rejected")

        if args.remote:
            bundles = client.list_bundles()
            print(f"remote : {len(bundles)} bundle(s) under {client.remote_root}")
            for bundle_row in bundles[:5]:
                print(f"        {bundle_row.remote_path}  {bundle_row.date}")
            if not bundles:
                raise AssertionError(
                    f"no *_artifact folders under {client.remote_root}; "
                    "check --remote-root or the MEGA session")
            link = client.exported_link(bundles[0].artifact)
            print(f"        link for {bundles[0].artifact}: "
                  f"{'present' if link else 'none (read-only)'}")

        print("\nOK: mega_client SDK smoke test passed")
        return 0
    finally:
        if args.keep:
            print(f"kept  : {root}")
        else:
            import shutil
            shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
