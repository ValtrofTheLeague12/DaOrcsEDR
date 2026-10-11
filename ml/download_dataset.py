#!/usr/bin/env python3
"""
Download the EMBER2024 malware feature dataset from HuggingFace.

EMBER2024 ships *precomputed thrember feature vectors plus labels* -- not raw
binaries -- so this is safe on an isolated training VM: nothing is executed and
no samples are unpacked to disk.

Source:  https://huggingface.co/datasets/joyce8/EMBER2024
License: Apache-2.0 (training and redistribution of derived models permitted)

    python download_dataset.py --subset Win64
    python download_dataset.py --subset Win64 --include-challenge
    python download_dataset.py --list
"""

from __future__ import annotations

import argparse
import logging
import os
import shutil
import sys
import zipfile
from pathlib import Path

import mllog

log = logging.getLogger("ml.download")  # handlers attached in main() by mllog.setup

REPO_ID = "joyce8/EMBER2024"

SUBSETS: dict[str, dict[str, object]] = {
    "Win32": {"train": "Win32_train.zip", "test": "Win32_test.zip", "size": "~15 GB"},
    "Win64": {"train": "Win64_train.zip", "test": "Win64_test.zip", "size": "~7 GB"},
    "Dot_Net": {"train": "Dot_Net_train.zip", "test": "Dot_Net_test.zip", "size": "~1.2 GB"},
    "APK": {"train": "APK_train.zip", "test": "APK_test.zip", "size": "~1 GB"},
    "PDF": {"train": "PDF_train.zip", "test": "PDF_test.zip", "size": "~150 MB"},
    "ELF": {"train": "ELF_train.zip", "test": "ELF_test.zip", "size": "~85 MB"},
    "challenge": {"train": "challenge.zip", "test": None, "size": "~32 MB"},
}

# Lower bounds (MB) so a truncated download fails loudly instead of training on
# half a corpus. Published sizes; anything smaller is a bad fetch.
EXPECTED_MIN_MB = {
    "Win32_train.zip": 10_000, "Win32_test.zip": 2_000,
    "Win64_train.zip": 4_500, "Win64_test.zip": 900,
    "Dot_Net_train.zip": 700, "Dot_Net_test.zip": 150,
    "APK_train.zip": 600, "APK_test.zip": 130,
    "PDF_train.zip": 90, "PDF_test.zip": 20,
    "ELF_train.zip": 50, "ELF_test.zip": 12,
    "challenge.zip": 25,
}


def human(nbytes: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if nbytes < 1024 or unit == "GB":
            return f"{nbytes:.1f} {unit}"
        nbytes /= 1024
    return f"{nbytes:.1f} GB"


def free_mb(path: Path) -> float:
    try:
        return shutil.disk_usage(str(Path(path).resolve())).free / (1024 * 1024)
    except OSError:
        return float("inf")


def verify_zip(zpath: Path, expect_mb: int) -> None:
    """Fail loudly on a truncated or corrupt download."""
    size_mb = zpath.stat().st_size / (1024 * 1024)
    if size_mb < expect_mb:
        log.error("%s is only %.0f MB, expected >= %d MB. "
                  "Re-run the download (it resumes).",
                  zpath.name, size_mb, expect_mb)
        raise SystemExit(1)
    log.info("[*] verifying %s (%s) ...", zpath.name, human(zpath.stat().st_size))
    with zipfile.ZipFile(zpath) as zf:
        bad = zf.testzip()  # CRC-checks every member
        if bad is not None:
            log.error("%s corrupt at member %r. Re-download.", zpath.name, bad)
            raise SystemExit(1)
        n = len(zf.namelist())
    log.info("[+] %s OK (%d members)", zpath.name, n)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Download EMBER2024 subsets from HuggingFace.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument("--subset", "-s", action="append", choices=sorted(SUBSETS),
                    help="Subset to fetch (repeatable). Default: Win64.")
    ap.add_argument("--out", "-o", default="data", type=Path,
                    help="Destination directory. Default: ./data")
    ap.add_argument("--splits", default="train,test",
                    help="Comma-separated: train,test. Default: train,test")
    ap.add_argument("--include-challenge", action="store_true",
                    help="Also fetch challenge.zip (6,315 evasive files; the real test).")
    ap.add_argument("--extract", action="store_true",
                    help="Unzip after verification (needs ~2x the zip size free).")
    ap.add_argument("--list", action="store_true", help="List subsets and exit.")
    ap.add_argument("--verify-only", action="store_true",
                    help="Skip downloading; only verify already-present zips.")
    args = ap.parse_args(argv)

    mllog.setup("download")
    log.debug("args: %s", args)

    if args.list:
        print(f"{'subset':<10} {'train zip':<22} {'test zip':<22} size")
        for name, meta in SUBSETS.items():
            print(f"{name:<10} {str(meta['train']):<22} "
                  f"{str(meta['test'] or '-'):<22} {meta['size']}")
        print("\nchallenge: 6,315 malicious files ~70 AV engines initially missed.")
        return 0

    subsets = args.subset or ["Win64"]
    splits = {s.strip() for s in args.splits.split(",") if s.strip()}
    out = args.out
    out.mkdir(parents=True, exist_ok=True)

    wanted: list[str] = []
    for sub in subsets:
        meta = SUBSETS[sub]
        if sub == "challenge":
            wanted.append(str(meta["train"]))
            continue
        if "train" in splits and meta["train"]:
            wanted.append(str(meta["train"]))
        if "test" in splits and meta["test"]:
            wanted.append(str(meta["test"]))
    if args.include_challenge:
        wanted.append("challenge.zip")

    seen: set[str] = set()
    wanted = [w for w in wanted if not (w in seen or seen.add(w))]

    need_mb = sum(EXPECTED_MIN_MB.get(w, 0) for w in wanted)
    have_mb = free_mb(out)
    log.info("[*] target     : %s", out)
    log.info("[*] files      : %s", ", ".join(wanted))
    log.info("[*] free space : %.1f GB (need ~%.1f GB%s)", have_mb / 1024,
              need_mb / 1024, ", ~2x more to extract" if args.extract else "")
    if have_mb < need_mb:
        log.error("not enough free space. Free some or narrow --subset.")
        raise SystemExit(1)

    if not args.verify_only:
        try:
            from huggingface_hub import hf_hub_download
        except ImportError:
            log.error("huggingface_hub not installed. "
                      "Run: python -m pip install 'huggingface_hub[hf_xet]'")
            raise SystemExit(1)
        # Public dataset; HF_TOKEN only helps with rate limits.
        token = os.environ.get("HF_TOKEN") or None
        for name in wanted:
            log.info("[*] downloading %s ...", name)
            hf_hub_download(repo_id=REPO_ID, filename=name, repo_type="dataset",
                            local_dir=str(out), token=token)  # resumes automatically

    for name in wanted:
        zpath = out / name
        if not zpath.exists():
            log.error("expected %s but it is missing.", zpath)
            raise SystemExit(1)
        verify_zip(zpath, EXPECTED_MIN_MB.get(name, 0))
        if args.extract:
            dest = out / zpath.stem
            if dest.exists() and any(dest.iterdir()):
                log.info("[*] %s already populated, skipping extract", dest)
                continue
            log.info("[*] extracting %s -> %s ...", name, dest)
            with zipfile.ZipFile(zpath) as zf:
                zf.extractall(dest)
            log.info("[+] extracted %s", dest)

    log.info("\n[+] done. Next:")
    log.info("    python vectorize.py --data data --out data/vectors")
    log.info("    python train.py --vectors data/vectors --model model.txt")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001
        mllog.setup("download")  # idempotent: covers crashes before main() set it up
        log.exception("download crashed: %s", exc)
        sys.exit(1)

