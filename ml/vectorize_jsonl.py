#!/usr/bin/env python3
"""
Stream EMBER2024 JSONL chunks out of the downloaded zip into .npy matrices.

Why this exists alongside vectorize.py: the HuggingFace release
(joyce8/EMBER2024) ships ONE zip per subset containing weekly *.jsonl chunks --
52 members for Win64, ~20,000 records each, ~570 MB uncompressed apiece, so
~30 GB if actually extracted. vectorize.py was written for a one-pickle-per-
file layout and cannot read that release. Reading the members as a stream
straight out of the archive avoids both problems: nothing is materialised and
peak RAM stays flat.

Column order is imported from vectorize.py (FEATURE_DIM / FEATURE_GROUPS /
to_vector / label_of) so the two can never drift apart.

    # the 6,315-file evasion set (all malicious)
    python vectorize_jsonl.py --zip data/challenge.zip --split challenge

    # a bounded slice of Win64, sampled across the whole year
    python vectorize_jsonl.py --zip data/Win64_train.zip --split train \
        --limit 150000 --member-stride 6

Vectors are staged to a raw float32 file and only then written as a correctly
shaped .npy, so RAM does not scale with --limit. A free-space guard refuses to
start rather than filling the drive.
"""

from __future__ import annotations

import argparse
import json
import logging
import shutil
import sys
import time
import zipfile
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).parent))
import mllog  # noqa: E402
from vectorize import (  # noqa: E402
    FEATURE_DIM,
    FEATURE_GROUPS,
    build_extractor,
    label_of,
    to_vector,
)

log = logging.getLogger("ml.vectorize_jsonl")  # handlers attached in main()

CHUNK = 10_000  # rows per staging -> .npy copy


def free_gb(path: Path) -> float:
    try:
        return shutil.disk_usage(str(Path(path).resolve())).free / (1024 ** 3)
    except OSError:
        return float("inf")


def write_feature_names(out: Path) -> None:
    (out / "feature_names.json").write_text(json.dumps(
        {"dim": FEATURE_DIM,
         "groups": [{"name": n, "dim": d} for n, d in FEATURE_GROUPS],
         "order": "EMBER v3 thrember PEFeatureExtractor"},
        indent=2), encoding="utf-8")


def stream_split(zpath: Path, out: Path, split: str, extractor,
                 limit: int | None, member_stride: int, record_stride: int,
                 meta_fields: list[str]) -> int:
    """Flatten one archive into X_<split>.npy / y_<split>.npy / meta_<split>.jsonl."""
    if member_stride < 1 or record_stride < 1:
        log.error("--member-stride and --record-stride must be >= 1")
        raise SystemExit(1)

    written = 0
    n_skip = 0
    labels: list[int] = []
    staging = out / f"X_{split}.raw"
    started = time.time()

    with zipfile.ZipFile(zpath) as zf, \
            staging.open("wb") as stage, \
            (out / f"meta_{split}.jsonl").open("w", encoding="utf-8") as metaf:
        members = sorted(n for n in zf.namelist() if not n.endswith("/"))
        chosen = members[::member_stride]
        log.info("[*] %s: %d chunk(s) in archive, reading %d (stride %d)",
                 zpath.name, len(members), len(chosen), member_stride)

        for m_i, name in enumerate(chosen):
            if limit is not None and written >= limit:
                break
            seen = kept = 0
            with zf.open(name) as fh:
                for line in fh:
                    if not line.strip():
                        continue
                    seen += 1
                    if (seen - 1) % record_stride:
                        continue
                    try:
                        rec = json.loads(line)
                    except json.JSONDecodeError:
                        n_skip += 1
                        continue
                    vec = to_vector(rec, extractor)
                    if vec is None:
                        n_skip += 1
                        continue
                    vec.astype(np.float32, copy=False).tofile(stage)
                    label = label_of(rec)
                    labels.append(label)
                    rec_meta = {"source": name, "label": label}
                    if isinstance(rec, dict):
                        for field in meta_fields:
                            if field in rec:
                                rec_meta[field] = rec[field]
                    metaf.write(json.dumps(rec_meta, default=str) + "\n")
                    kept += 1
                    written += 1
                    if written % CHUNK == 0:
                        rate = written / max(time.time() - started, 1e-9)
                        log.info("    %s kept, %s skipped, %.0f rec/s",
                                 f"{written:,}", f"{n_skip:,}", rate)
                    if limit is not None and written >= limit:
                        break
            log.info("    [%d/%d] %s: %s read, %s kept",
                     m_i + 1, len(chosen), name, f"{seen:,}", f"{kept:,}")

    if written == 0:
        log.error("no usable vectors in %s (%d records skipped)", zpath.name, n_skip)
        raise SystemExit(1)

    # Staging -> correctly shaped .npy, never holding the whole matrix in RAM.
    final = out / f"X_{split}.npy"
    X = np.lib.format.open_memmap(final, mode="w+", dtype=np.float32,
                                  shape=(written, FEATURE_DIM))
    with staging.open("rb") as src:
        for start in range(0, written, CHUNK):
            stop = min(start + CHUNK, written)
            X[start:stop] = np.fromfile(
                src, dtype=np.float32, count=(stop - start) * FEATURE_DIM
            ).reshape(stop - start, FEATURE_DIM)
    X.flush()
    del X
    staging.unlink()

    y = np.asarray(labels, dtype=np.int8)
    np.save(out / f"y_{split}.npy", y)
    pos = int(y.sum())
    log.info("[+] %s: X=(%s, %s)  malicious=%s benign=%s  skipped=%s  (%.1f min)",
             split, f"{written:,}", FEATURE_DIM, f"{pos:,}",
             f"{written - pos:,}", f"{n_skip:,}", (time.time() - started) / 60)
    return written


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Flatten EMBER2024 JSONL chunks from a zip into .npy matrices.",
        formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    ap.add_argument("--zip", dest="zip_path", type=Path, required=True,
                    help="Downloaded subset zip, e.g. data/Win64_train.zip")
    ap.add_argument("--out", type=Path, default=Path("data/vectors"),
                    help="Output directory for the .npy matrices")
    ap.add_argument("--split", default="train",
                    help="Split name used in the output file names")
    ap.add_argument("--limit", type=int, default=None,
                    help="Stop after this many usable vectors")
    ap.add_argument("--member-stride", type=int, default=1,
                    help="Read every Nth weekly chunk (spreads the sample over time)")
    ap.add_argument("--record-stride", type=int, default=1,
                    help="Keep every Nth record inside a chunk")
    ap.add_argument("--meta-fields",
                    default="family,tags,sha256,first_submission_date",
                    help="Label-adjacent fields to keep in the .jsonl sidecar")
    ap.add_argument("--min-free-gb", type=float, default=5.0,
                    help="Refuse to start unless this much disk is free")
    args = ap.parse_args(argv)

    mllog.setup("vectorize_jsonl")
    log.debug("args: %s", args)

    if not args.zip_path.is_file():
        log.error("%s not found. Run download_dataset.py first.", args.zip_path)
        raise SystemExit(1)

    out = args.out
    out.mkdir(parents=True, exist_ok=True)

    row_bytes = FEATURE_DIM * 4
    if args.limit is not None:
        # Staging file and final .npy coexist briefly, hence 2x.
        need_gb = args.limit * row_bytes * 2 / (1024 ** 3)
        have_gb = free_gb(out)
        log.info("[*] planning %s vectors: %.2f GB kept, ~%.2f GB peak "
                 "(staging + final), %.2f GB free",
                 f"{args.limit:,}", args.limit * row_bytes / (1024 ** 3),
                 need_gb, have_gb)
        if have_gb < need_gb + args.min_free_gb:
            log.error("need ~%.2f GB plus %.1f GB headroom, only %.2f GB free. "
                      "Lower --limit or free some space.", need_gb,
                      args.min_free_gb, have_gb)
            raise SystemExit(1)

    write_feature_names(out)
    extractor = build_extractor()
    log.info("[*] feature dim = %d", FEATURE_DIM)

    stream_split(args.zip_path, out, args.split, extractor, args.limit,
                 args.member_stride, args.record_stride,
                 [f.strip() for f in args.meta_fields.split(",") if f.strip()])
    log.info("\n[+] next: python train.py --vectors %s", out)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
    except SystemExit:
        raise
    except Exception:  # noqa: BLE001
        logging.getLogger("ml.vectorize_jsonl").exception("vectorize_jsonl crashed")
        sys.exit(1)