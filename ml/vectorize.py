#!/usr/bin/env python3
"""
Convert the downloaded EMBER2024 pickles into a dense float32 matrix for LightGBM.

EMBER2024 stores one pickle per file, each holding thrember's raw feature groups
plus labels. This flattens them into the exact 2,568-d float32 vector that
thrember's process_raw_features() produces, so a model trained here sees the same
layout the analyzer's C++ exporter must reproduce.

Output (plain .npy, memory-mapped later so the trainer never loads 5 GB at once):
    <out>/X_train.npy  y_train.npy  meta_train.jsonl   (+ the test equivalents)

    python vectorize.py --data data --out data/vectors
    python vectorize.py --data data --out data/vectors --limit 2000   # smoke test

Column order is EMBER v3 ('thrember') and is recorded in feature_names.json so the
trainer and any C++ consumer agree on indices.
"""

from __future__ import annotations

import argparse
import json
import logging
import pickle
import sys
from pathlib import Path

import numpy as np

import mllog

log = logging.getLogger("ml.vectorize")  # handlers attached in main() by mllog.setup

# EMBER v3 group order and dimensions. Must match thrember.PEFeatureExtractor.
FEATURE_GROUPS: list[tuple[str, int]] = [
    ("general", 7),
    ("histogram", 256),
    ("byteentropy", 256),
    ("strings", 177),
    ("header", 74),
    ("section", 224),
    ("imports", 1282),
    ("exports", 129),
    ("datadirectories", 34),
    ("richheader", 33),
    ("authenticode", 8),
    ("pefilewarnings", 88),
]
FEATURE_DIM = sum(d for _, d in FEATURE_GROUPS)


def build_extractor():
    """Return a thrember PEFeatureExtractor, or None if it is unavailable."""
    try:
        from thrember.features import PEFeatureExtractor
    except Exception as exc:  # noqa: BLE001 - surface the real import problem
        log.warning("[!] thrember import failed: %s", exc)
        log.warning("    pip install -e /path/to/EMBER2024  (or: pip install thrember)")
        return None
    return PEFeatureExtractor()




def to_vector(obj, extractor) -> np.ndarray | None:
    """Flatten one EMBER record to the 2,568-d float32 vector.

    Prefers the record's own precomputed vector when present; otherwise re-runs
    thrember's process_raw_features on the stored raw groups. A record of the
    wrong width is rejected rather than zero-padded, because a silently
    misaligned column would corrupt training with no visible error.
    """
    if isinstance(obj, np.ndarray):
        vec = obj.astype(np.float32, copy=False)
    elif isinstance(obj, dict):
        vec = None
        for key in ("vector", "features", "X"):
            if key in obj and isinstance(obj[key], (np.ndarray, list, tuple)):
                vec = np.asarray(obj[key], dtype=np.float32)
                break
        if vec is None:
            if extractor is None:
                return None
            try:
                vec = np.asarray(extractor.process_raw_features(obj), dtype=np.float32)
            except Exception:  # noqa: BLE001
                return None
    else:
        return None
    if vec.ndim != 1 or vec.shape[0] != FEATURE_DIM:
        return None
    return vec


def label_of(obj) -> int:
    """Binary label. EMBER uses 1 = malicious, 0 = benign, -1 = unlabeled."""
    if isinstance(obj, dict):
        for key in ("label", "y", "target"):
            if key in obj:
                try:
                    return int(obj[key])
                except (TypeError, ValueError):
                    continue
    return -1


def vectorize_split(src: Path, out_dir: Path, split: str, extractor,
                    limit: int | None, meta_fields: list[str]) -> tuple[int, int, int]:
    rows: list[np.ndarray] = []
    labels: list[int] = []
    n_skip = n_bad = 0
    log.info("[*] %s: reading %s", split, src)
    with (out_dir / f"meta_{split}.jsonl").open("w", encoding="utf-8") as mf:
        for i, (p, obj) in enumerate(iter_pickles(src)):
            if limit is not None and i >= limit:
                break
            y = label_of(obj)
            if y not in (0, 1):
                n_skip += 1          # unlabeled (challenge entries) or missing
                continue
            vec = to_vector(obj, extractor)
            if vec is None:
                n_bad += 1
                if n_bad <= 5:
                    log.warning("[!] bad vector, skipping: %s", p.name)
                continue
            rows.append(vec)
            labels.append(y)
            rec = {"source": p.name, "label": y}
            if isinstance(obj, dict):
                for f in meta_fields:
                    if f in obj:
                        rec[f] = obj[f]
            mf.write(json.dumps(rec, default=str) + "\n")
            if (i + 1) % 50_000 == 0:
                log.info("    %s read, %s kept", f"{i + 1:,}", f"{len(rows):,}")
    if not rows:
        log.error("no usable vectors in %s. Check the split extracted.", src)
        raise SystemExit(1)
    X = np.vstack(rows).astype(np.float32, copy=False)
    y = np.asarray(labels, dtype=np.int8)
    np.save(out_dir / f"X_{split}.npy", X)
    np.save(out_dir / f"y_{split}.npy", y)
    pos = int(y.sum())
    log.info("[+] %s: X=%s y=%s malicious=%s benign=%s skipped=%s bad=%s",
             split, X.shape, y.shape, f"{pos:,}", f"{len(y) - pos:,}",
             f"{n_skip:,}", f"{n_bad:,}")
    return X.shape[0], pos, n_bad


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Flatten EMBER2024 pickles into float32 matrices.",
        formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    ap.add_argument("--data", type=Path, default=Path("data"),
                    help="Directory holding the extracted <Subset>_train/ folders.")
    ap.add_argument("--out", type=Path, default=Path("data/vectors"),
                    help="Output directory for the .npy matrices.")
    ap.add_argument("--splits", default="train,test", help="Comma-separated splits.")
    ap.add_argument("--subset", "-s", default="Win64",
                    help="Subset folder prefix to look for. Default: Win64.")
    ap.add_argument("--limit", type=int, default=None,
                    help="Read at most N pickles per split (smoke tests).")
    ap.add_argument("--meta-fields", default="family,tags,sha256,first_seen",
                    help="Label-adjacent fields to keep in the .jsonl sidecar.")
    args = ap.parse_args(argv)

    mllog.setup("vectorize")
    log.debug("args: %s", args)

    out = args.out
    out.mkdir(parents=True, exist_ok=True)
    extractor = build_extractor()

    (out / "feature_names.json").write_text(json.dumps(
        {"dim": FEATURE_DIM,
         "groups": [{"name": n, "dim": d} for n, d in FEATURE_GROUPS],
         "order": "EMBER v3 thrember PEFeatureExtractor"}, indent=2), encoding="utf-8")
    log.info("[*] feature dim = %d", FEATURE_DIM)

    done = False
    for split in [s.strip() for s in args.splits.split(",") if s.strip()]:
        src = args.data / f"{args.subset}_{split}"
        if not src.exists():
            alt = args.data / split
            if alt.exists():
                src = alt
            else:
                log.warning("[!] missing %s, skipping", src)
                continue
        vectorize_split(src, out, split, extractor, args.limit,
                        [f.strip() for f in args.meta_fields.split(",") if f.strip()])
        done = True
    if not done:
        log.error("no splits found. Did you pass --extract to the downloader?")
        raise SystemExit(1)
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
        logging.getLogger("ml.vectorize").exception("vectorize crashed")
        sys.exit(1)


