#!/usr/bin/env python3
"""
Build data/known_pe_hashes.jsonl: the roster of known PE hashes the analyzer
looks a sample up against (include/file/known_pe_hashes.hpp).

The roster is the deduplicated union of the EMBER2024 Win64 metadata that
vectorize.py / vectorize_jsonl.py already write next to the vectors:

    data/vectors/meta_train.jsonl      300,000 rows
    data/vectors/meta_test.jsonl       120,000 rows
    data/vectors/meta_challenge.jsonl    6,315 rows

Those row counts are NOT the hash count. The corpus lists each file more than
once -- evaluate_report.py notes the same thing when it explains why it scores
against the official test split instead of a random 10% holdout of train ("the
corpus lists each file roughly twice (150,000 unique sha256 across 300,000
train rows)"). So 426,315 rows collapse to 216,310 distinct hashes. The splits
themselves stay disjoint, which is the property that actually matters: deduping
here removes intra-file repetition, it never merges train into test.

    python ml/build_known_pe_hashes.py                 # rebuild the roster
    python ml/build_known_pe_hashes.py --check         # verify, write nothing
    python ml/build_known_pe_hashes.py --out data/other.jsonl

Output is sorted by sha256 so the file is stable across runs and diffs cleanly
when the corpus grows. One JSON object per line:

    {"sha256":"...","label":1,"family":"expiro","split":"train"}

`split` is a single name, or a JSON array when a hash somehow appears in more
than one subset (the loader accepts both). `family` is null when the corpus
recorded none.

Writes atomically via a temporary file, so an interrupted run cannot leave a
half-written roster that the C++ loader would then report as malformed lines.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

try:
    import mllog
except ImportError:  # running the file directly, not as ml/build_known_pe_hashes
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import mllog

# Bit values mirror known_pe::split_bit in include/file/known_pe_hashes.hpp.
SPLIT_BITS = {"train": 1, "test": 2, "challenge": 4}
BIT_NAMES = {bit: name for name, bit in SPLIT_BITS.items()}


def split_names(mask: int) -> list[str]:
    return [BIT_NAMES[bit] for bit in sorted(BIT_NAMES) if mask & bit]


def collect(vectors_dir: Path, splits: list[str], log) -> tuple[dict, list, Counter]:
    """Merge the per-split metadata into one sha256 -> record map.

    Returns (order, records, stats) where `order` maps sha256 to an index into
    `records` and each record is [label, family, split_mask]. Indices rather
    than a dict of dicts because 216k tiny dicts is a lot of overhead for
    something we only ever index and merge.
    """
    order: dict[str, int] = {}
    records: list[list] = []
    stats = Counter()

    for split in splits:
        path = vectors_dir / f"meta_{split}.jsonl"
        if not path.exists():
            log.error("[!] missing metadata: %s (run vectorize_jsonl.py first)", path)
            continue

        rows = 0
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    stats["malformed"] += 1
                    continue

                sha = str(rec.get("sha256") or "").strip().lower()
                if len(sha) != 64 or any(c not in "0123456789abcdef" for c in sha):
                    stats["bad_sha256"] += 1
                    continue

                label = 1 if rec.get("label") else 0
                family = rec.get("family") or None

                idx = order.get(sha)
                if idx is None:
                    order[sha] = len(records)
                    records.append([label, family, SPLIT_BITS[split]])
                else:
                    # Same file listed twice. The corpus is internally
                    # consistent about the label, but never let a later row
                    # downgrade a hash the corpus already called malicious.
                    records[idx][2] |= SPLIT_BITS[split]
                    if records[idx][1] is None and family:
                        records[idx][1] = family
                    records[idx][0] |= label
                    stats["duplicate"] += 1
                rows += 1
        stats[f"rows_{split}"] = rows
        log.info("[*] %-9s %7d rows", split, rows)

    return order, records, stats


def render(rows: list[tuple[str, list]]) -> str:
    out = []
    for sha, (label, family, mask) in rows:
        names = split_names(mask)
        out.append(json.dumps({
            "sha256": sha,
            "label": label,
            "family": family,
            "split": names if len(names) > 1 else names[0],
        }, separators=(",", ":"), ensure_ascii=False))
    return "\n".join(out) + "\n"

def summarize(rows: list[tuple[str, list]], stats: Counter, log) -> None:
    malicious = sum(1 for _, (label, _, _) in rows if label)
    families = {f for _, (_, f, _) in rows if f}
    multi = sum(1 for _, (_, _, m) in rows if bin(m).count("1") > 1)
    log.info("[+] %d distinct hashes", len(rows))
    log.info("[+]   malicious %d / benign %d", malicious, len(rows) - malicious)
    log.info("[+]   families %d", len(families))
    log.info("[+]   multi-split %d", multi)
    log.info("[*] duplicates collapsed %d", stats["duplicate"])
    if stats["malformed"] or stats["bad_sha256"]:
        log.warning("[!] skipped %d malformed line(s), %d unusable sha256",
                    stats["malformed"], stats["bad_sha256"])


def main(argv=None) -> int:
    repo = Path(__file__).resolve().parents[1]
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--vectors", default=str(repo / "data" / "vectors"),
                    help="directory holding meta_<split>.jsonl")
    ap.add_argument("--out", default=str(repo / "data" / "known_pe_hashes.jsonl"),
                    help="roster to write")
    ap.add_argument("--splits", default="train,test,challenge",
                    help="comma-separated subsets to merge")
    ap.add_argument("--check", action="store_true",
                    help="report what would be written, without writing")
    args = ap.parse_args(argv)

    log = mllog.setup("build_known_pe_hashes")
    splits = [s.strip() for s in args.splits.split(",") if s.strip()]
    vectors_dir = Path(args.vectors)

    order, records, stats = collect(vectors_dir, splits, log)
    if not order:
        log.error("[!] no hashes collected - is %s populated?", vectors_dir)
        return 1

    rows = sorted(zip(order.keys(), records))
    summarize(rows, stats, log)

    if args.check:
        log.info("[*] --check: wrote nothing")
        return 0

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = out_path.with_suffix(out_path.suffix + ".tmp")
    tmp_path.write_text(render(rows), encoding="utf-8", newline="\n")
    tmp_path.replace(out_path)  # atomic on both POSIX and Windows
    log.info("[+] wrote %s (%.1f MiB)", out_path, out_path.stat().st_size / (1 << 20))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
# Bit values mirror known_pe::split_bit in include/file/known_pe_hashes.hpp.
SPLIT_BITS = {"train": 1, "test": 2, "challenge": 4}
BIT_NAMES = {bit: name for name, bit in SPLIT_BITS.items()}


def split_names(mask: int) -> list[str]:
    return [BIT_NAMES[bit] for bit in sorted(BIT_NAMES) if mask & bit]