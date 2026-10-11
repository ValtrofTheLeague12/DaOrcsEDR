#!/usr/bin/env python3
"""
Model evaluation report: charts + CSV for accuracy, error ("hallucination")
analysis and corpus composition.

Interpretation: nothing in this pipeline is generative, so "hallucination"
means the model's errors -- false positives (benign called malicious) and
false negatives (malicious missed). If you meant hallucinated *text* from the
analyzer's narrative output, this is the wrong report.

Evaluation set is the OFFICIAL EMBER2024 Win64 *test* split, which is disjoint
from train by sha256 (verified: 0 overlap, and different week ranges). The
random 10% holdout inside train.py is deliberately NOT used for headline
numbers: the corpus lists each file roughly twice (150,000 unique sha256 across
300,000 train rows), so a random slice leaks duplicates across the split and
inflates the score. That duplication is measured into data_quality.csv instead.

    python ml/evaluate_report.py                  # everything
    python ml/evaluate_report.py --skip-train     # skip the 300k-row CSVs

Outputs ml/report/*.png and ml/report/*.csv. Every figure is a rendering of a
CSV written by the same run, so the numbers never have to be re-derived.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import logging
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

import matplotlib
matplotlib.use("Agg")  # headless: no display on a build box
import matplotlib.pyplot as plt
import numpy as np
import lightgbm as lgb
from sklearn.metrics import (average_precision_score, precision_recall_curve,
                             roc_auc_score, roc_curve)

sys.path.insert(0, str(Path(__file__).parent))
import mllog  # noqa: E402
from vectorize import FEATURE_GROUPS  # noqa: E402

log = logging.getLogger("ml.evaluate_report")  # handlers attached in main()

# ml/README.md: the C++ exporter implements 2 of the 12 EMBER groups (512 of
# 2,568 dims), so predict.py --analysis still needs thrember for the rest.
ANALYZER_GROUPS = {"histogram", "byteentropy"}

GROUP_SLICES: list[tuple[str, int, int]] = []
_off = 0
for _name, _dim in FEATURE_GROUPS:
    GROUP_SLICES.append((_name, _off, _off + _dim))
    _off += _dim
FEATURE_DIM = _off
PROFILE_SAMPLE_SIZE = 20_000

SPLITS = ("train", "test", "challenge")
VECTORS = Path("data/vectors")


def group_of(index: int) -> str:
    for name, lo, hi in GROUP_SLICES:
        if lo <= index < hi:
            return name
    return "unknown"


def week_of(source: str) -> str:
    """'2024-09-22_2024-09-28_Win64_test.jsonl' -> '2024-09-22'."""
    return (source or "").split("_")[0] or "unknown"


def load_meta(split: str) -> list[dict]:
    path = VECTORS / f"meta_{split}.jsonl"
    if not path.exists():
        return []
    with path.open(encoding="utf-8") as fh:
        return [json.loads(line) for line in fh]


def audit_duplicates(meta: list[dict], label: str) -> dict:
    """Row count vs unique file count, and whether labels disagree per file."""
    counts: Counter = Counter()
    labels: dict = {}
    conflicts = 0
    for r in meta:
        sha = r.get("sha256")
        counts[sha] += 1
        y = r.get("label")
        if sha in labels and labels[sha] != y:
            conflicts += 1
        labels[sha] = y
    rows = len(meta)
    unique = len(counts)
    dupes = sum(c - 1 for c in counts.values())
    log.info("[*] %s: %s rows / %s unique sha256 (%s duplicate rows, %s "
             "label conflicts)", label, f"{rows:,}", f"{unique:,}", f"{dupes:,}", conflicts)
    return {"split": label, "rows": rows, "unique_sha256": unique,
            "duplicate_rows": dupes, "label_conflicts": conflicts,
            "malicious_rows": sum(1 for r in meta if r.get("label") == 1),
            "benign_rows": sum(1 for r in meta if r.get("label") == 0),
            "chunks": len({r.get("source") for r in meta})}


def predict_split(booster, split: str, limit: int | None = None) -> tuple[np.ndarray, np.ndarray]:
    X = np.load(VECTORS / f"X_{split}.npy", mmap_mode="r")
    y = np.load(VECTORS / f"y_{split}.npy").astype(np.int8)
    n = len(y) if limit is None else min(limit, len(y))
    scores = booster.predict(np.asarray(X[:n], dtype=np.float32))
    log.info("[*] %s: scored %s rows", split, f"{n:,}")
    del X
    return scores, y[:n]
def operating_point(scores: np.ndarray, y: np.ndarray, max_fpr: float) -> dict:
    """The deployed threshold: the highest TPR whose FPR stays within budget."""
    fpr, tpr, thr = roc_curve(y, scores)
    # fpr[0] is always 0, so a non-empty budget always has at least one candidate.
    idx = np.where(fpr <= max_fpr)[0][-1]
    return {"threshold": float(thr[idx]), "tpr": float(tpr[idx]), "fpr": float(fpr[idx])}


def sweep(scores: np.ndarray, y: np.ndarray, chal: np.ndarray,
          points: int = 400) -> list[dict]:
    """Recall/precision/FPR/confusion + evasion catch-rate across thresholds.

    `chal` may be empty, in which case evasion_caught is NaN for every row: an
    absent challenge split must read as "not measured", never as a perfect 1.0
    catch rate that would silently flatter the model.
    """
    P = int((y == 1).sum())
    N = int((y == 0).sum())
    have_chal = len(chal) > 0
    rows: list[dict] = []
    for t in np.unique(np.concatenate([np.linspace(0.0, 1.0, points),
                                       [0.5, 0.95, 0.99]])):
        pred = scores >= t
        tp = int((pred & (y == 1)).sum())
        fp = int((pred & (y == 0)).sum())
        fn, tn = P - tp, N - fp
        rows.append({
            "threshold": round(float(t), 6),
            "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "recall": tp / P if P else 0.0,
            "precision": tp / (tp + fp) if (tp + fp) else 0.0,
            "fpr": fp / N if N else 0.0,
            "accuracy": (tp + tn) / len(y),
            "f1": (2 * tp / (2 * tp + fp + fn)) if (2 * tp + fp + fn) else 0.0,
            "evasion_caught": float((chal >= t).mean()) if have_chal else float("nan"),
        })
    return rows


def _save(fig, out: Path, name: str) -> None:
    fig.tight_layout()
    fig.savefig(out / name, dpi=160)
    plt.close(fig)
    log.info("[+] chart -> %s", name)


def chart_roc(fpr, tpr, auc: float, op: dict, max_fpr: float, n: int,
              out: Path) -> None:
    fig, ax = plt.subplots(figsize=(6, 5))
    ax.plot(fpr, tpr, label=f"ROC (AUC = {auc:.5f})", lw=2)
    ax.axvline(max_fpr, ls="--", c="grey", lw=1, label=f"FPR budget {max_fpr:g}")
    ax.plot([op["fpr"]], [op["tpr"]], "o", c="crimson",
            label=f"operating point: FPR={op['fpr']:.4f} TPR={op['tpr']:.4f} @ thr={op['threshold']:.4g}")
    ax.set_xlabel("false positive rate"); ax.set_ylabel("true positive rate")
    # n comes from the split that was actually scored, so the title cannot drift
    # away from the data when the evaluation set changes.
    ax.set_title(f"ROC - EMBER2024 Win64 test split ({n // 1000}k samples)")
    ax.legend(loc="lower right", fontsize=8); ax.grid(alpha=.3)
    _save(fig, out, "01_roc_curve.png")


def chart_pr(precision, recall, ap: float, baseline: float, out: Path) -> None:
    fig, ax = plt.subplots(figsize=(6, 5))
    # The report's caption promises this dashed line, so draw it: precision
    # equals the positive class rate for a no-skill random classifier. That rate
    # is the measured prevalence, not a hardcoded 0.5.
    ax.axhline(baseline, ls="--", c="grey", lw=1,
               label=f"no-skill baseline (prevalence = {baseline:.2f})")
    ax.plot(recall, precision, label=f"PR (AP = {ap:.5f})", lw=2)
    ax.set_xlabel("recall"); ax.set_ylabel("precision")
    ax.set_title("Precision-Recall - test split")
    ax.set_ylim(0, 1.02)
    ax.legend(loc="lower left", fontsize=8); ax.grid(alpha=.3)
    _save(fig, out, "02_pr_curve.png")


def chart_scores(scores: np.ndarray, y: np.ndarray, op: dict,
                 thr_def: float, out: Path) -> None:
    fig, ax = plt.subplots(figsize=(7, 4.5))
    bins = np.linspace(0, 1, 101)
    ax.hist(scores[y == 0], bins=bins, alpha=.65, label="benign (label 0)", color="#4c72b0")
    ax.hist(scores[y == 1], bins=bins, alpha=.65, label="malicious (label 1)", color="#c44e52")
    ax.axvline(thr_def, ls="--", c="k", lw=1, label=f"thr {thr_def:g}")
    ax.axvline(op["threshold"], ls=":", c="crimson", lw=1.5,
               label=f"operating thr {op['threshold']:.4g}")
    ax.set_yscale("log")
    ax.set_xlabel("p(malicious)"); ax.set_ylabel("count (log)")
    # The two populations overlap through the mid-range: the errors are the tails
    # that survive either threshold, not a clean gap between the modes.
    ax.set_title("Score separation - both thresholds sit inside the overlap")
    ax.legend(fontsize=8); ax.grid(alpha=.3)
    _save(fig, out, "03_score_distribution.png")


def chart_tradeoff(rows: list[dict], op_thr: float, out: Path) -> None:
    t = np.array([r["threshold"] for r in rows])
    fig, ax = plt.subplots(figsize=(8, 5))
    ax.plot(t, [r["recall"] for r in rows], label="recall (test)", lw=2)
    ax.plot(t, [r["precision"] for r in rows], label="precision (test)", lw=2)
    ax.plot(t, [r["fpr"] * 20 for r in rows], label="FPR (test, x20)", lw=1.5, ls=":")
    ax.axvline(op_thr, ls="--", c="grey", lw=1, label=f"operating thr {op_thr:.4g}")
    ax2 = ax.twinx()
    # An all-NaN series (no challenge split) would silently draw nothing while the
    # legend still promised a curve, so only add the axis when there is data.
    if any(np.isfinite(r["evasion_caught"]) for r in rows):
        ax2.plot(t, [r["evasion_caught"] for r in rows], color="crimson", lw=2.5,
                 label="evasion caught (challenge)")
        ax2.set_ylabel("evasion catch-rate", color="crimson")
        ax2.set_ylim(0, 1); ax2.tick_params(axis="y", colors="crimson")
    ax.set_xscale("log"); ax.set_xlim(1e-4, 1)
    ax.set_yscale("log"); ax.set_ylim(1e-4, 1.05)
    ax.set_xlabel("decision threshold (log scale)")
    ax.set_title("Threshold trade-off: evasion falls off a cliff as you tighten")
    h1, l1 = ax.get_legend_handles_labels(); h2, l2 = ax2.get_legend_handles_labels()
    ax.legend(h1 + h2, l1 + l2, loc="center left", fontsize=8); ax.grid(alpha=.3)
    _save(fig, out, "04_threshold_tradeoff.png")


def _thin_date_axis(ax, labels: list[str], every: int = 8) -> None:
    """Show only every Nth date label.

    The challenge split spans ~64 weekly chunks; one tick per chunk overplots
    into an unreadable smear, and matplotlib's own date locator does not know
    these are categorical week starts.
    """
    step = max(1, every)
    ticks = list(range(0, len(labels), step))
    ax.set_xticks(ticks)
    ax.set_xticklabels([labels[i] for i in ticks], rotation=45, ha="right")


def chart_by_week(meta: list[dict], scores: np.ndarray, y: np.ndarray,
                  thr_def: float, thr_op: float,
                  chal_meta: list[dict], chal: np.ndarray,
                  out: Path) -> None:
    """Drift check: FP/FN rate per weekly chunk, and evasion catch-rate per week.

    Rates are per *class*, not per row: the false-positive rate is a fraction of
    the benign rows in that week and the false-negative rate a fraction of the
    malicious ones. Dividing either by the week's total row count halves it,
    because this split is balanced 50/50, so the two denominators are counted
    separately. Both thresholds are drawn so this chart agrees with the
    confusion matrix and the rest of the report, which are about the
    FPR-constrained operating point rather than only the 0.5 default.
    """
    # week -> [benign, malicious, fp@def, fn@def, fp@op, fn@op]
    agg: dict = defaultdict(lambda: [0, 0, 0, 0, 0, 0])
    for r, sc, lab in zip(meta, scores, y):
        a = agg[week_of(r.get("source", ""))]
        if lab == 1:
            a[1] += 1
            if sc < thr_def:
                a[3] += 1
            if sc < thr_op:
                a[5] += 1
        else:
            a[0] += 1
            if sc >= thr_def:
                a[2] += 1
            if sc >= thr_op:
                a[4] += 1
    weeks = sorted(agg)

    def rate(num: int, den: int) -> float:
        return (num / den) if den else 0.0

    fpr_d = [rate(agg[w][2], agg[w][0]) for w in weeks]
    fnr_d = [rate(agg[w][3], agg[w][1]) for w in weeks]
    fpr_o = [rate(agg[w][4], agg[w][0]) for w in weeks]
    fnr_o = [rate(agg[w][5], agg[w][1]) for w in weeks]

    # The challenge split is all-malicious, so only recall exists there.
    cagg: dict = defaultdict(lambda: [0, 0])
    for r, sc in zip(chal_meta, chal):
        a = cagg[week_of(r.get("source", ""))]
        a[0] += 1
        if sc >= thr_op:
            a[1] += 1
    cweeks = sorted(cagg)
    ev = [rate(cagg[w][1], cagg[w][0]) for w in cweeks]

    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(10, 8))
    ax1.plot(weeks, fpr_d, "o--", color="#c44e52", alpha=.7,
             label=f"FP rate @ thr {thr_def:g} (default)")
    ax1.plot(weeks, fnr_d, "s--", color="#4c72b0", alpha=.7,
             label=f"FN rate @ thr {thr_def:g} (default)")
    ax1.plot(weeks, fpr_o, "o-", color="#c44e52",
             label=f"FP rate @ thr {thr_op:.4g} (operating)")
    ax1.plot(weeks, fnr_o, "s-", color="#4c72b0",
             label=f"FN rate @ thr {thr_op:.4g} (operating)")
    ax1.set_ylabel("rate")
    ax1.set_ylim(0, max(max(fpr_d + fnr_d + fpr_o + fnr_o + [0.01]) * 1.25, 0.02))
    ax1.set_title("Test-split error rate per weekly chunk")
    ax1.legend(fontsize=7, ncol=2); ax1.grid(alpha=.3)
    _thin_date_axis(ax1, weeks)

    ax2.plot(cweeks, ev, "o-", color="crimson")
    ax2.set_ylabel("evasion caught"); ax2.set_ylim(0, 1)
    ax2.set_title(f"Challenge evasion catch-rate per week @ thr {thr_op:.4g} "
                  f"(all-malicious, so only recall exists)")
    ax2.grid(alpha=.3); ax2.set_xlabel("week start")
    _thin_date_axis(ax2, cweeks)
    _save(fig, out, "05_errors_by_week.png")


def chart_groups(booster, out: Path) -> list[dict]:
    """Which EMBER feature groups drive decisions, vs what the C++ exporter makes."""
    gain = booster.feature_importance("gain")
    split = booster.feature_importance("split")
    by_group: dict = defaultdict(float)
    total = float(gain.sum()) or 1.0
    rows = []
    for idx, g in enumerate(gain):
        name = group_of(int(idx))
        by_group[name] += float(g)
        rows.append({"feature_index": int(idx), "group": name,
                     "gain": round(float(g), 4), "splits": int(split[idx]),
                     "analyzer_implemented": name in ANALYZER_GROUPS})
    rows.sort(key=lambda r: -r["gain"])

    names = [n for n, _ in FEATURE_GROUPS]
    vals = [by_group.get(n, 0.0) / total for n in names]
    dims = dict(FEATURE_GROUPS)
    colors = ["#c44e52" if n in ANALYZER_GROUPS else "#8c8c8c" for n in names]
    fig, ax = plt.subplots(figsize=(8, 5))
    bars = ax.bar(names, vals, color=colors)
    for b, n in zip(bars, names):
        # One line per bar: "34d". A trailing "\n" split the unit onto its own
        # line and the label read as a stray "d" above each bar.
        ax.text(b.get_x() + b.get_width() / 2, b.get_height() + .004,
                f"{dims[n]}d", ha="center", va="bottom", fontsize=7)
    ax.set_ylabel("share of total LightGBM gain")
    # The rotated tick labels need the headroom: a two-line title here used to
    # collide with them and clip the largest bars' labels.
    ax.set_title("Which EMBER feature groups drive the model", pad=26)
    # Counted from FEATURE_GROUPS rather than typed in, so the caption cannot
    # drift from the vector layout when the extractor changes.
    impl_dims = sum(d for n, d in FEATURE_GROUPS if n in ANALYZER_GROUPS)
    fig.text(0.5, 0.90, f"red = the {len(ANALYZER_GROUPS)} groups the C++ exporter "
             f"produces ({impl_dims} of {sum(d for _, d in FEATURE_GROUPS)} dims)",
             ha="center", fontsize=9, color="#444")
    ax.set_ylim(0, max(vals) * 1.18 if max(vals) else 1)
    ax.tick_params(axis="x", rotation=40)
    ax.grid(alpha=.3, axis="y")
    _save(fig, out, "06_feature_group_importance.png")
    return rows


def chart_confusion(scores: np.ndarray, y: np.ndarray, thr_a: float,
                    thr_b: float, out: Path) -> None:
    def counts(t):
        pred = scores >= t
        tp = int((pred & (y == 1)).sum()); fp = int((pred & (y == 0)).sum())
        fn = int((~pred & (y == 1)).sum()); tn = int((~pred & (y == 0)).sum())
        return np.array([[tn, fp], [fn, tp]], dtype=float)

    fig, axes = plt.subplots(1, 2, figsize=(10, 4.2))
    # Both panels share one colour scale: they are counts of the same 120k rows at
    # two thresholds, so two independently-fitted scales made equal cells look
    # different shades and invited false visual comparison.
    matrices = [counts(thr_a), counts(thr_b)]
    vmax = max(m.max() for m in matrices)
    panels = ((axes[0], matrices[0], f"threshold {thr_a:g}"),
              (axes[1], matrices[1], f"operating threshold {thr_b:.4g}"))
    for ax, cm, title in panels:
        im = ax.imshow(cm, cmap="Blues", vmin=0, vmax=vmax)
        ax.set_xticks([0, 1], ["predicted benign", "predicted malicious"])
        ax.set_yticks([0, 1], ["actual benign", "actual malicious"])
        ax.set_title(title)
        for i in range(2):
            for j in range(2):
                v = int(cm[i, j])
                ax.text(j, i, f"{v:,}", ha="center", va="center",
                        color="white" if v > vmax / 2 else "black")
        ax.grid(False)
        fig.colorbar(im, ax=ax, fraction=.046)
    fig.suptitle("Where the errors went: false positives (top-right) vs false negatives (bottom-left)")
    _save(fig, out, "07_confusion_matrix.png")


def chart_corpus(audits: list[dict], families: dict, out: Path) -> None:
    fig, (ax1, ax2, ax3) = plt.subplots(1, 3, figsize=(14, 4.2))
    names = [a["split"] for a in audits]
    mal = [a["malicious_rows"] for a in audits]
    ben = [a["benign_rows"] for a in audits]
    ax1.bar(names, mal, label="malicious", color="#c44e52")
    ax1.bar(names, ben, bottom=mal, label="benign", color="#4c72b0")
    ax1.set_ylabel("rows"); ax1.set_title("Class balance per split")
    ax1.legend(fontsize=8)

    ax2.bar([a["split"] for a in audits],
            [a["duplicate_rows"] / a["rows"] * 100 for a in audits], color="#dd8452")
    ax2.set_ylabel("% duplicate rows")
    # train/test list each file twice; the challenge set is deduplicated, so the
    # old blanket "~twice" title was wrong for one of the three bars.
    ax2.set_title("Duplicate listing per split\n(row count != file count)")

    top = families["test"].most_common(12)
    labels = [("unlabeled" if n in (None, "None") else n) for n, _ in top]
    ax3.barh(labels[::-1], [c for _, c in top][::-1], color="#55a868")
    ax3.set_xlabel("rows"); ax3.set_title("Top families in test split")
    ax3.tick_params(axis="y", labelsize=8)
    for i, (n, c) in enumerate(top[::-1]):
        ax3.text(c, i, f" {c:,}", va="center", fontsize=7)
    _save(fig, out, "08_corpus_composition.png")


def profile_dataset(vectors: Path, split: str, out: Path,
                    sample_size: int) -> list[dict]:
    """Write a pandas profile and readable label-correlation chart for one split."""
    import pandas as pd

    X_path, y_path = vectors / f"X_{split}.npy", vectors / f"y_{split}.npy"
    if not X_path.is_file() or not y_path.is_file():
        raise FileNotFoundError(f"missing dataset split files: {X_path} and/or {y_path}")

    X = np.load(X_path, mmap_mode="r")
    y = np.load(y_path, mmap_mode="r")
    if X.ndim != 2 or X.shape[1] != FEATURE_DIM:
        raise ValueError(f"{X_path} must have shape (rows, {FEATURE_DIM}), got {X.shape}")
    if y.ndim != 1:
        raise ValueError(f"{y_path} must be a one-dimensional label array, got {y.shape}")
    if len(X) != len(y):
        raise ValueError(f"{X_path} has {len(X)} rows but {y_path} has {len(y)} labels")
    if len(y) == 0:
        raise ValueError(f"{split} split is empty")
    if not np.isin(y, (0, 1)).all():
        raise ValueError(f"{y_path} contains labels outside the expected 0/1 range")
    if sample_size < 1:
        raise ValueError("--profile-sample-size must be >= 1")

    n = min(len(y), sample_size)
    rng = np.random.default_rng(0xE8B3)
    indices = np.sort(rng.choice(len(y), size=n, replace=False))
    values = np.asarray(X[indices], dtype=np.float32)
    labels = np.asarray(y[indices], dtype=np.int8)

    columns = []
    groups = []
    for name, dim in FEATURE_GROUPS:
        columns.extend(f"{name}[{i}]" for i in range(dim))
        groups.extend([name] * dim)
    frame = pd.DataFrame(values, columns=columns, copy=False)
    frame.insert(0, "label", labels)
    info = io.StringIO()
    frame.info(buf=info, memory_usage="deep")
    log.info("[*] pandas profile for %s split (%s rows sampled from %s):\n%s",
             split, f"{n:,}", f"{len(y):,}", info.getvalue())

    feature_frame = frame[columns]
    stats = feature_frame.describe().T
    correlations = feature_frame.corrwith(frame["label"])
    missing = feature_frame.isna().sum()
    unique = feature_frame.nunique(dropna=False)
    profile = []
    for index, feature in enumerate(columns):
        values_stats = stats.loc[feature]
        corr = float(correlations[feature])
        profile.append({
            "feature": feature,
            "group": groups[index],
            "dtype": str(feature_frame[feature].dtype),
            "missing_count": int(missing[feature]),
            "missing_pct": float(missing[feature]) / n,
            "unique_values": int(unique[feature]),
            "mean": float(values_stats["mean"]),
            "std": float(values_stats["std"]),
            "min": float(values_stats["min"]),
            "p25": float(values_stats["25%"]),
            "median": float(values_stats["50%"]),
            "p75": float(values_stats["75%"]),
            "max": float(values_stats["max"]),
            "label_correlation": corr,
        })

    _w(out / "dataset_profile.csv",
       ["feature", "group", "dtype", "missing_count", "missing_pct",
        "unique_values", "mean", "std", "min", "p25", "median", "p75",
        "max", "label_correlation"],
       ([r[k] for k in ("feature", "group", "dtype", "missing_count",
                        "missing_pct", "unique_values", "mean", "std", "min",
                        "p25", "median", "p75", "max", "label_correlation")]
        for r in profile))
    _w(out / "dataset_summary.csv",
       ["split", "total_rows", "sampled_rows", "feature_count", "matrix_dtype",
        "label_dtype", "malicious_rows", "benign_rows"],
       [[split, len(y), n, X.shape[1], str(X.dtype), str(y.dtype),
         int(np.count_nonzero(y == 1)), int(np.count_nonzero(y == 0))]])

    top = sorted(
        (r for r in profile if np.isfinite(r["label_correlation"])),
        key=lambda r: abs(r["label_correlation"]), reverse=True)[:20]
    import matplotlib.pyplot as plt

    fig, (ax1, ax2) = plt.subplots(
        1, 2, figsize=(15, max(6, len(top) * 0.34)),
        gridspec_kw={"width_ratios": [1, 1.35]})
    if top:
        names = [r["feature"] for r in top]
        corr = [r["label_correlation"] for r in top]
        colors = ["#c44e52" if value > 0 else "#4c72b0" for value in corr]
        ax1.barh(names[::-1], corr[::-1], color=colors[::-1])
        ax1.axvline(0, color="black", linewidth=0.8)
        ax1.set_xlabel("Pearson correlation with label (0 = benign, 1 = malicious)")
        ax1.set_title("Features most correlated with the label")
        ax1.tick_params(axis="y", labelsize=7)

        matrix = frame[names].corr().to_numpy()
        image = ax2.imshow(np.nan_to_num(matrix, nan=0.0), cmap="coolwarm",
                           vmin=-1, vmax=1, interpolation="nearest")
        ax2.set_xticks(range(len(names)), names, rotation=90, fontsize=6)
        ax2.set_yticks(range(len(names)), names, fontsize=6)
        ax2.set_title("Correlation between the top 20 features")
        fig.colorbar(image, ax=ax2, fraction=0.046, pad=0.04)
    else:
        ax1.text(0.5, 0.5, "No non-constant feature correlations available",
                 ha="center", va="center", transform=ax1.transAxes)
        ax1.set_axis_off()
        ax2.set_axis_off()
    fig.suptitle(f"Dataset profile: {split} split, {n:,}-row deterministic sample")
    _save(fig, out, "09_dataset_correlation.png")
    del X, y, values, frame
    return profile


def _w(path: Path, header: list[str], rows) -> int:
    n = 0
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(header)
        for r in rows:
            w.writerow(r)
            n += 1
    log.info("[+] csv -> %s (%s rows)", path.name, f"{n:,}")
    return n


PRED_HEADER = ["split", "row", "sha256", "week", "chunk", "label", "family",
               "p_malicious", "pred_default", "pred_operating",
               "is_fp_default", "is_fn_default", "first_submission_date"]


def _pred_rows(split, meta, scores, y, thr_def, op_thr):
    for i, (r, sc, lab) in enumerate(zip(meta, scores, y)):
        pred_d = sc >= thr_def
        pred_o = sc >= op_thr
        yield [split, i, r.get("sha256", ""), week_of(r.get("source", "")),
               r.get("source", ""), int(lab), r.get("family") or "",
               f"{sc:.6f}", int(pred_d), int(pred_o),
               int(pred_d and lab == 0), int((not pred_d) and lab == 1),
               r.get("first_submission_date", "")]


def write_errors(path, meta, scores, y, thr_def, op_thr) -> int:
    """The triage list: only the samples the model gets wrong."""
    rows = []
    for r, sc, lab in zip(meta, scores, y):
        pd_, po = sc >= thr_def, sc >= op_thr
        kind_d = "FP" if (pd_ and lab == 0) else ("FN" if (not pd_ and lab == 1) else "correct")
        kind_o = "FP" if (po and lab == 0) else ("FN" if (not po and lab == 1) else "correct")
        if kind_d != "correct" or kind_o != "correct":
            rows.append([week_of(r.get("source", "")), r.get("sha256", ""),
                         r.get("family") or "", int(lab), f"{sc:.6f}",
                         int(pd_), int(po), kind_d, kind_o])
    rows.sort(key=lambda x: float(x[4]))
    return _w(path, ["week", "sha256", "family", "label", "p_malicious",
                     "pred_default", "pred_operating", "error_default",
                     "error_operating"], rows)


def main(argv: list[str] | None = None) -> int:
    global VECTORS
    ap = argparse.ArgumentParser(
        description="Accuracy / error / corpus report for the EMBER2024 model.",
        formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    ap.add_argument("--vectors", type=Path, default=VECTORS)
    ap.add_argument("--model", type=Path, default=Path("ml/model.txt"))
    ap.add_argument("--out", type=Path, default=Path("ml/report"))
    ap.add_argument("--max-fpr", type=float, default=5e-3)
    ap.add_argument("--default-threshold", type=float, default=0.5)
    ap.add_argument("--skip-train", action="store_true",
                    help="Skip the 300k-row train predictions CSV")
    ap.add_argument("--profile-sample-size", type=int, default=PROFILE_SAMPLE_SIZE,
                    help=f"Rows used for pandas dataset profiling (default {PROFILE_SAMPLE_SIZE:,})")
    args = ap.parse_args(argv)
    if args.profile_sample_size < 1:
        ap.error("--profile-sample-size must be >= 1")

    mllog.setup("evaluate_report")
    log.debug("args: %s", args)
    VECTORS = args.vectors
    out = args.out
    out.mkdir(parents=True, exist_ok=True)

    booster = lgb.Booster(model_file=str(args.model))
    log.info("[*] model %s: %s trees, %s features", args.model,
             booster.num_trees(), booster.num_feature())

    # --skip-train must skip only the expensive part (scoring 300k rows and
    # writing the 49 MB predictions CSV). The train split is still audited, so
    # data_quality.csv keeps its train row and the report can state how many rows
    # the model was actually trained on; dropping it made the PDF claim
    # "Training used 0 rows".
    present = [s for s in SPLITS if (VECTORS / f"X_{s}.npy").exists()]
    wanted = [s for s in present if not (args.skip_train and s == "train")]
    if args.skip_train and "train" in present:
        log.info("[*] skipping train split scoring (--skip-train); still auditing it")
    # meta/audit/family need every present split (train included, since the audit
    # is cheap); only scoring and the predictions CSV are skipped.
    metas = {s: load_meta(s) for s in present}
    audits = [audit_duplicates(metas[s], s) for s in present]
    families = {s: Counter(str(r.get("family")) for r in metas[s]) for s in present}

    scored = {s: predict_split(booster, s) for s in wanted}
    s_test, y_test = scored["test"]
    s_chal, y_chal = scored.get("challenge", (np.array([]), np.array([])))
    s_train = scored.get("train", (None, None))

    # A skipped split leaves the previous predictions_train.csv in place, so its
    # staleness would silently disagree with the metrics computed this run. Remove
    # it rather than leave a file that looks current but is not.
    if "train" in present and "train" not in wanted:
        stale = out / "predictions_train.csv"
        if stale.is_file():
            stale.unlink()
            log.info("[*] removed stale %s (train not scored this run)", stale.name)

    auc = float(roc_auc_score(y_test, s_test))
    ap_ = float(average_precision_score(y_test, s_test))
    op = operating_point(s_test, y_test, args.max_fpr)
    log.info("[+] test ROC-AUC=%.6f AP=%.6f", auc, ap_)
    log.info("[+] operating point (FPR<=%g): thr=%.6g recall=%.6f FPR=%.6f",
             args.max_fpr, op["threshold"], op["tpr"], op["fpr"])

    # An absent challenge split stays empty so sweep() reports NaN rather than a
    # fabricated 1.0 catch rate.
    sweep_rows = sweep(s_test, y_test, s_chal)
    fpr, tpr, _ = roc_curve(y_test, s_test)
    prec, rec, _ = precision_recall_curve(y_test, s_test)

    chart_roc(fpr, tpr, auc, op, args.max_fpr, len(y_test), out)
    chart_pr(prec, rec, ap_, float((y_test == 1).mean()), out)
    chart_scores(s_test, y_test, op, args.default_threshold, out)
    chart_tradeoff(sweep_rows, op["threshold"], out)
    chart_by_week(metas["test"], s_test, y_test, args.default_threshold,
                  op["threshold"], metas.get("challenge", []), s_chal, out)
    fi_rows = chart_groups(booster, out)
    chart_confusion(s_test, y_test, args.default_threshold, op["threshold"], out)
    chart_corpus(audits, families, out)
    profile_dataset(VECTORS, "test", out, args.profile_sample_size)

    thr_d, thr_o = args.default_threshold, op["threshold"]
    _w(out / "predictions_test.csv", PRED_HEADER,
       _pred_rows("test", metas["test"], s_test, y_test, thr_d, thr_o))
    if len(s_chal):
        _w(out / "predictions_challenge.csv", PRED_HEADER,
           _pred_rows("challenge", metas.get("challenge", []), s_chal, y_chal, thr_d, thr_o))
    if s_train[0] is not None:
        _w(out / "predictions_train.csv", PRED_HEADER,
           _pred_rows("train", metas["train"], s_train[0], s_train[1], thr_d, thr_o))
    write_errors(out / "errors_test.csv", metas["test"], s_test, y_test, thr_d, thr_o)

    _w(out / "threshold_curve.csv",
       ["threshold", "tp", "fp", "fn", "tn", "recall", "precision", "fpr",
        "accuracy", "f1", "evasion_caught"],
       ([r["threshold"], r["tp"], r["fp"], r["fn"], r["tn"], f"{r['recall']:.6f}",
         f"{r['precision']:.6f}", f"{r['fpr']:.6f}", f"{r['accuracy']:.6f}",
         f"{r['f1']:.6f}", f"{r['evasion_caught']:.6f}"] for r in sweep_rows))
    _w(out / "roc_points.csv", ["fpr", "tpr"],
       ([f"{a:.8f}", f"{b:.8f}"] for a, b in zip(fpr, tpr)))
    _w(out / "pr_points.csv", ["recall", "precision"],
       ([f"{a:.8f}", f"{b:.8f}"] for a, b in zip(rec, prec)))
    _w(out / "feature_importance.csv",
       ["feature_index", "group", "gain", "splits", "analyzer_implemented"],
       ([r["feature_index"], r["group"], r["gain"], r["splits"],
         int(r["analyzer_implemented"])] for r in fi_rows))
    _w(out / "data_quality.csv",
       ["split", "rows", "unique_sha256", "duplicate_rows", "label_conflicts",
        "malicious_rows", "benign_rows", "chunks"],
       ([a["split"], a["rows"], a["unique_sha256"], a["duplicate_rows"],
         a["label_conflicts"], a["malicious_rows"], a["benign_rows"], a["chunks"]]
        for a in audits))

    summary = [
        ["evaluation_split", "test", "official EMBER2024 Win64 test; sha256-disjoint from train"],
        ["roc_auc", f"{auc:.6f}", ""],
        ["average_precision", f"{ap_:.6f}", ""],
        ["n_test", len(y_test), ""],
        ["default_threshold", thr_d, "predict.py default"],
        ["operating_threshold", f"{thr_o:.8f}", f"FPR <= {args.max_fpr:g}"],
        ["recall_at_operating", f"{op['tpr']:.6f}", ""],
        ["fpr_at_operating", f"{op['fpr']:.6f}", ""],
        ["trees", booster.num_trees(), ""],
        ["n_features", booster.num_feature(), ""],
        ["model_sha256", hashlib.sha256(Path(args.model).read_bytes()).hexdigest(), ""],
        ["generated_utc", datetime.now(timezone.utc).isoformat(timespec="seconds"), ""],
    ]
    _w(out / "metrics_summary.csv", ["metric", "value", "note"], summary)

    log.info("\n[+] report written to %s", out.resolve())
    for p in sorted(out.glob("*")):
        log.info("    %-30s %8.0f KB", p.name, p.stat().st_size / 1024)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
    except SystemExit:
        raise
    except Exception:  # noqa: BLE001
        logging.getLogger("ml.evaluate_report").exception("evaluate_report crashed")
        sys.exit(1)