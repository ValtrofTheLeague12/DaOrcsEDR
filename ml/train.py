#!/usr/bin/env python3
"""
Train a LightGBM binary classifier on the EMBER2024 feature vectors.

    python train.py --vectors data/vectors --model model.txt
    python train.py --vectors data/vectors --model model.txt \
        --challenge data/vectors/X_challenge.npy --challenge-train-frac 0.5

Reads the .npy matrices from vectorize.py / vectorize_jsonl.py, trains,
evaluates, and writes a model the analyzer can load for inference.

What this script guarantees (each one fixes a problem found in review):

  * Files are deduplicated by sha256 before anything is fitted. The corpus lists
    each file about twice, so a row-level random split leaks a file's twin into
    the training part.
  * Validation is a TIME split on whole weekly chunks (the newest chunks of
    train), never a random slice. Early stopping and the operating threshold
    come from that slice, so the official test split is scored once, untouched.
  * The operating threshold is chosen on validation and merely APPLIED to test
    and to the challenge set. (The old code took it from the single-class
    challenge result, where it was always None, so the evasion rate at the
    deployable threshold was never measured.)
  * bagging_fraction only takes effect together with bagging_freq >= 1; both
    are now set. Capacity is bounded (num_leaves, min_data_in_leaf, lambda_l2).
  * The 2,568-column EMBER v3 layout is never reordered or trimmed. The static
    analyzer supplies the `histogram` and `byteentropy` columns at inference
    (predict.py --analysis), so this script also measures how much the score
    moves when exactly those 512 columns carry the analyzer's tolerated error.

The headline number is ROC-AUC at max_fpr=5e-3 / TPR at that FPR, the metric the
EMBER paper reports. AUC alone hides operational failure, so every split also
gets TPR/FPR at the chosen operating threshold.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from collections import Counter
from pathlib import Path

import numpy as np

import mllog
from vectorize import FEATURE_DIM, FEATURE_GROUPS

log = logging.getLogger("ml.train")  # handlers attached in main() by mllog.setup

SEED = 0xE8B3

# Regularised defaults. num_iterations is a CEILING: early stopping on the
# time-based validation slice decides the real tree count. bagging_freq=1 is
# what actually switches bagging on.
DEFAULT_PARAMS: dict[str, object] = {
    "boosting_type": "gbdt",
    "objective": "binary",
    "metric": ["binary_logloss", "auc"],   # early stopping watches the first
    "num_iterations": 2000,
    "learning_rate": 0.05,
    "num_leaves": 127,
    "min_data_in_leaf": 100,
    "lambda_l2": 10.0,
    "feature_fraction": 0.5,
    "bagging_fraction": 0.8,
    "bagging_freq": 1,
    "seed": SEED,
    "deterministic": True,       # fully reproducible only with a fixed num_threads
    "force_row_wise": True,      # required by deterministic=True
    "verbose": -1,
    "device": "cpu",
    "num_threads": 0,            # 0 = every core
}

# Columns the C++ static analyzer reproduces itself. Keep in sync with
# serve.ANALYZER_GROUPS and predict.py's `--analysis` substitution.
ANALYZER_GROUPS = ("histogram", "byteentropy")
SKEW_TOLERANCE = 1e-6            # same value as serve.SKEW_TOLERANCE


# --------------------------------------------------------------------------- #
# Layout
# --------------------------------------------------------------------------- #

def layout() -> list[tuple[str, int, int]]:
    """[(group, offset, dim)] in EMBER v3 column order."""
    out, off = [], 0
    for name, dim in FEATURE_GROUPS:
        out.append((name, off, dim))
        off += dim
    return out


def analyzer_columns() -> np.ndarray:
    cols = [np.arange(o, o + d) for n, o, d in layout() if n in ANALYZER_GROUPS]
    return np.concatenate(cols)


def check_layout(X) -> None:
    """Refuse to train on a matrix whose width is not the EMBER v3 vector.

    A model trained on any other layout would load fine and then score the
    analyzer's histogram/byteentropy columns at the wrong indices.
    """
    if X.shape[1] != FEATURE_DIM:
        log.error("X has %d columns, expected %d (EMBER v3 layout). Re-run the "
                  "vectorizer.", X.shape[1], FEATURE_DIM)
        raise SystemExit(1)


# --------------------------------------------------------------------------- #
# Loading, dedup, splitting
# --------------------------------------------------------------------------- #

def load_split(vectors: Path, split: str) -> tuple[np.ndarray, np.ndarray]:
    Xp, yp = vectors / f"X_{split}.npy", vectors / f"y_{split}.npy"
    if not Xp.exists() or not yp.exists():
        log.error("missing %s or %s. Run vectorize.py first.", Xp, yp)
        raise SystemExit(1)
    # mmap keeps the matrix out of RAM on load; rows are copied out in chunks.
    X = np.load(Xp, mmap_mode="r")
    y = np.load(yp)
    check_layout(X)
    if len(y) != X.shape[0]:
        log.error("%s has %d rows but %s has %d labels", Xp.name, X.shape[0],
                  yp.name, len(y))
        raise SystemExit(1)
    bad = int(((y != 0) & (y != 1)).sum())
    if bad:
        log.error("%s: %d labels are not 0/1 (unlabeled -1 rows?). Re-vectorize "
                  "with the fixed vectorize_jsonl.py.", yp.name, bad)
        raise SystemExit(1)
    log.info("[*] %s: X=%s %s  y=%s  malicious=%s benign=%s",
             split, X.shape, X.dtype, y.shape,
             f"{int(y.sum()):,}", f"{len(y) - int(y.sum()):,}")
    return X, y


def load_meta(vectors: Path, split: str, n: int) -> list[dict] | None:
    """meta_<split>.jsonl rows, or None when absent / misaligned with X."""
    p = vectors / f"meta_{split}.jsonl"
    if not p.exists():
        return None
    meta = []
    with p.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if line.strip():
                meta.append(json.loads(line))
    if len(meta) != n:
        log.warning("[!] %s has %d rows but X_%s has %d; ignoring the sidecar",
                    p.name, len(meta), split, n)
        return None
    return meta


def take(X, rows: np.ndarray | None = None, chunk: int = 20_000) -> np.ndarray:
    """Copy rows of a (memory-mapped) matrix into RAM a chunk at a time."""
    if rows is None:
        rows = np.arange(X.shape[0])
    out = np.empty((len(rows), X.shape[1]), dtype=np.float32)
    for s in range(0, len(rows), chunk):
        out[s:s + chunk] = X[rows[s:s + chunk]]
    return out


def dedupe_rows(meta: list[dict] | None, y: np.ndarray,
                tag: str) -> tuple[np.ndarray, dict]:
    """Indices of one row per sha256; files whose duplicates disagree on the
    label are dropped entirely."""
    n = len(y)
    if meta is None:
        log.warning("[!] %s: no usable meta sidecar, cannot deduplicate "
                    "(every file may be counted twice)", tag)
        return np.arange(n), {"rows": n, "kept": n, "duplicate_rows": 0,
                              "label_conflicts": 0, "deduplicated": False}
    first: dict[str, int] = {}
    conflicts: set[str] = set()
    for i, m in enumerate(meta):
        sha = str(m.get("sha256") or "").strip().lower()
        if not sha:
            first[f"__row{i}"] = i      # no hash: cannot dedupe, keep the row
            continue
        j = first.get(sha)
        if j is None:
            first[sha] = i
        elif int(y[j]) != int(y[i]):
            conflicts.add(sha)
    keep = np.sort(np.fromiter((i for s, i in first.items() if s not in conflicts),
                               dtype=np.int64))
    stats = {"rows": n, "kept": int(len(keep)),
             "duplicate_rows": n - len(first), "label_conflicts": len(conflicts),
             "deduplicated": True}
    log.info("[*] %s dedup: %s rows -> %s unique files (%s duplicate rows, "
             "%s label conflicts dropped)", tag, f"{n:,}", f"{len(keep):,}",
             f"{stats['duplicate_rows']:,}", len(conflicts))
    return keep, stats


def time_split(meta: list[dict] | None, keep: np.ndarray,
               val_frac: float) -> tuple[np.ndarray, np.ndarray]:
    """Hold out the NEWEST whole weekly chunks as validation.

    Chunk names sort chronologically (vectorize_jsonl writes members in sorted
    order). Falls back to the tail of the row order, which is the same thing
    when the sidecar is missing.
    """
    def tail() -> tuple[np.ndarray, np.ndarray]:
        cut = int(len(keep) * (1.0 - val_frac))
        return keep[:cut], keep[cut:]

    if meta is None or "source" not in meta[int(keep[0])]:
        log.warning("[!] no chunk names in meta: validating on the last %.0f%% "
                    "of the row order instead of whole weeks", val_frac * 100)
        return tail()
    sources = [meta[int(i)].get("source", "") for i in keep]
    counts = Counter(sources)
    order = sorted(counts)
    if len(order) < 2:
        log.warning("[!] only one chunk in train; using a row-order tail split")
        return tail()
    target, acc, held = int(len(keep) * val_frac), 0, set()
    for s in reversed(order):
        if acc >= target:
            break
        held.add(s)
        acc += counts[s]
    mask = np.fromiter((s in held for s in sources), dtype=bool, count=len(keep))
    if mask.all() or not mask.any():
        return tail()
    log.info("[*] time split: %d older chunk(s) fit, newest %d chunk(s) validate "
             "(%s)", len(order) - len(held), len(held),
             ", ".join(sorted(held)[:3]) + (" ..." if len(held) > 3 else ""))
    return keep[~mask], keep[mask]


# --------------------------------------------------------------------------- #
# Scoring
# --------------------------------------------------------------------------- #

def score(booster, X, rows: np.ndarray | None = None,
          chunk: int = 50_000) -> np.ndarray:
    """P(malicious) for the rows, in chunks. Uses the best iteration only."""
    n = X.shape[0] if rows is None else len(rows)
    out = np.empty(n, dtype=np.float64)
    best = booster.best_iteration or None
    for s in range(0, n, chunk):
        sel = np.arange(s, min(s + chunk, n)) if rows is None else rows[s:s + chunk]
        out[s:s + chunk] = booster.predict(take(X, sel), num_iteration=best)
    return out


def pick_threshold(y, scores, max_fpr: float) -> float:
    """Smallest threshold whose FPR stays within the budget (TPR peaks there).

    drop_intermediate=False so the point is exact, not a collinear shortcut.
    """
    from sklearn.metrics import roc_curve
    fpr, _tpr, thr = roc_curve(y, scores, drop_intermediate=False)
    ok = np.where(fpr <= max_fpr)[0]
    t = float(thr[ok[-1]])
    if not np.isfinite(t):          # nothing can be flagged inside the budget
        t = float(np.nextafter(float(np.max(scores)), np.inf))
    return t


def rates_at(y, scores, thr: float) -> tuple[float | None, float | None]:
    pred = np.asarray(scores) >= thr
    pos, neg = (y == 1), (y == 0)
    tpr = float(pred[pos].mean()) if pos.any() else None
    fpr = float(pred[neg].mean()) if neg.any() else None
    return tpr, fpr


def _summarise(y, scores, tag: str, max_fpr: float, seconds: float = 0.0,
               op_threshold: float | None = None) -> dict[str, object]:
    """The one scoring function, so every caller computes the same thing.

    `op_threshold` is the threshold chosen on VALIDATION; it is applied here,
    never re-derived from the split being scored (that would be selecting and
    reporting on the same data).
    """
    from sklearn.metrics import average_precision_score, roc_auc_score

    y = np.asarray(y)
    scores = np.asarray(scores)
    res: dict[str, object] = {"n": int(len(y)), "max_fpr": max_fpr,
                              "seconds": round(seconds, 2)}
    if len(np.unique(y)) < 2:
        # All-malicious (challenge): AUC/AP/FPR are undefined; catch rates are
        # the TPR.
        res.update({"roc_auc": None, "average_precision": None,
                    "tpr_at_max_fpr": None,
                    "caught_at_0.5": float((scores >= 0.5).mean())})
        if op_threshold is not None:
            res["caught_at_operating_threshold"] = float(
                (scores >= op_threshold).mean())
        res["note"] = ("single-class split: ROC-AUC/AP undefined, only the "
                       "catch rates are meaningful")
        log.info("[+] %s: caught@0.5=%.1f%%  caught@operating=%s", tag,
                 res["caught_at_0.5"] * 100,
                 "n/a" if op_threshold is None
                 else f"{res['caught_at_operating_threshold'] * 100:.1f}%")
        return res

    own = pick_threshold(y, scores, max_fpr)
    tpr_own, fpr_own = rates_at(y, scores, own)
    tpr_05, fpr_05 = rates_at(y, scores, 0.5)
    res.update({"roc_auc": float(roc_auc_score(y, scores)),
                "average_precision": float(average_precision_score(y, scores)),
                "tpr_at_max_fpr": tpr_own, "fpr_at_max_fpr": fpr_own,
                "oracle_threshold": own,
                "tpr_at_0.5": tpr_05, "fpr_at_0.5": fpr_05})
    line = ("[+] %s: AUC=%.5f  AP=%.5f  TPR@FPR<=%g=%.4f (oracle thr=%.4f)"
            % (tag, res["roc_auc"], res["average_precision"], max_fpr,
               tpr_own, own))
    if op_threshold is not None:
        tpr_op, fpr_op = rates_at(y, scores, op_threshold)
        res.update({"operating_threshold": op_threshold,
                    "tpr_at_operating_threshold": tpr_op,
                    "fpr_at_operating_threshold": fpr_op})
        line += "  |  @validation thr %.4f: TPR=%.4f FPR=%.4f" % (
            op_threshold, tpr_op, fpr_op)
    log.info(line)
    return res


def evaluate(booster, X, y, tag: str, max_fpr: float,
             rows: np.ndarray | None = None,
             op_threshold: float | None = None) -> tuple[dict, np.ndarray]:
    t0 = time.time()
    s = score(booster, X, rows)
    yy = y if rows is None else y[rows]
    return _summarise(yy, s, tag, max_fpr, time.time() - t0, op_threshold), s


# --------------------------------------------------------------------------- #
# Fitting
# --------------------------------------------------------------------------- #

def fit_booster(params: dict, Xf: np.ndarray, yf: np.ndarray,
                Xv: np.ndarray, yv: np.ndarray, patience: int):
    import lightgbm as lgb

    dtr = lgb.Dataset(Xf, label=yf, free_raw_data=True)
    dva = lgb.Dataset(Xv, label=yv, reference=dtr, free_raw_data=True)
    cbs = [lgb.log_evaluation(50)]
    if patience > 0:
        cbs.append(lgb.early_stopping(patience, first_metric_only=True,
                                      verbose=False))
    return lgb.train(params, dtr, num_boost_round=int(params["num_iterations"]),
                     valid_sets=[dva], valid_names=["val"], callbacks=cbs)


def prepare(args, X, y, meta):
    """dedup -> time split -> RAM copies. Shared by the grid and the real run."""
    if args.no_dedup:
        keep, dstats = np.arange(len(y)), {"rows": len(y), "kept": len(y),
                                           "deduplicated": False}
        log.warning("[!] --no-dedup: duplicate files stay in train/validation")
    else:
        keep, dstats = dedupe_rows(meta, y, "train")
    fit_rows, val_rows = time_split(meta, keep, args.val_frac)
    if len(np.unique(y[val_rows])) < 2 or len(np.unique(y[fit_rows])) < 2:
        log.error("fit or validation slice is single-class; adjust --val-frac")
        raise SystemExit(1)
    return fit_rows, val_rows, dstats


def run_grid(args) -> int:
    """Train several candidates on the time split and rank them on validation.

    Same deduplicated, time-ordered split as the real run, so the comparison
    measures generalisation to NEWER weeks, not memorisation of a file's twin.
    The winner is then trained by a plain run and judged once on the test split.
    """
    plans = json.loads(args.grid_json.read_text(encoding="utf-8"))
    if not isinstance(plans, list) or not plans:
        log.error("--grid-json must be a non-empty JSON array of param dicts")
        return 1

    X, y = load_split(args.vectors, "train")
    meta = load_meta(args.vectors, "train", len(y))
    fit_rows, val_rows, _ = prepare(args, X, y, meta)
    cap = int(args.grid_max_rows or 0)
    if cap and len(fit_rows) > cap:
        rng = np.random.default_rng(SEED)
        fit_rows = np.sort(rng.choice(fit_rows, cap, replace=False))
        log.info("[*] grid sample: %d fit rows", cap)
    Xf, yf = take(X, fit_rows), y[fit_rows]
    Xv, yv = take(X, val_rows), y[val_rows]
    log.info("[*] grid split: %d fit / %d validation files", len(yf), len(yv))

    rows: list[dict] = []
    for i, over in enumerate(plans, 1):
        params = dict(DEFAULT_PARAMS)
        params.update(over)
        if args.num_iterations:
            params["num_iterations"] = args.num_iterations
        params["num_threads"] = args.num_threads
        tag = params.get("tag", f"cand{i}")
        params.pop("tag", None)
        log.info("[*] candidate %d/%d: %s %s", i, len(plans), tag, over)
        t0 = time.time()
        booster = fit_booster(params, Xf, yf, Xv, yv, args.early_stopping)
        secs = time.time() - t0
        res, _ = evaluate(booster, Xv, yv, f"validation[{tag}]", args.max_fpr)
        res.update({"tag": tag, "train_seconds": round(secs, 1),
                    "trees": int(booster.best_iteration or booster.num_trees()),
                    "params": params})
        rows.append(res)

    def key(r):  # highest TPR within the FPR budget wins; AUC breaks ties
        return (r.get("tpr_at_max_fpr") or 0.0, r.get("roc_auc") or 0.0)

    ranked = sorted(rows, key=key, reverse=True)
    for rank, r in enumerate(ranked, 1):
        log.info("[%d] %-14s TPR@FPR<=%g=%.4f AUC=%.5f trees=%d",
                 rank, r["tag"], args.max_fpr, r["tpr_at_max_fpr"],
                 r["roc_auc"], r["trees"])
    log.info("[+] winner: %s", ranked[0]["tag"])
    report = {"best_tag": ranked[0]["tag"], "max_fpr": args.max_fpr,
              "rows": rows, "ranked_tags": [r["tag"] for r in ranked],
              "note": ("time-split validation inside train on deduplicated "
                       "files; not the official test split")}
    out = args.grid_json.with_suffix(".report.json")
    out.write_text(json.dumps(report, indent=2, allow_nan=False, default=str),
                   encoding="utf-8")
    log.info("[+] grid report -> %s", out)
    return 0


# --------------------------------------------------------------------------- #
# Challenge set
# --------------------------------------------------------------------------- #

def split_challenge(args, Xc, known_hashes: set[str]):
    """-> (train_rows, eval_rows) over the challenge set.

    With --challenge-train-frac 0 everything is evaluation. Otherwise the
    OLDEST fraction (by first_submission_date, else chunk name) joins training
    and the newest stays held out, so the held-out evasion score is still a
    "newer weeks" number. Files already present in train/test are excluded from
    both parts.
    """
    n = Xc.shape[0]
    frac = float(args.challenge_train_frac)
    meta = load_meta(args.vectors, "challenge", n)
    idx = np.arange(n)
    if meta is not None:
        seen, rows = set(), []
        for i, m in enumerate(meta):
            sha = str(m.get("sha256") or "").strip().lower()
            if sha and (sha in seen or sha in known_hashes):
                continue
            seen.add(sha)
            rows.append(i)
        dropped = n - len(rows)
        if dropped:
            log.info("[*] challenge: %d rows dropped (duplicates or already in "
                     "train/test)", dropped)
        idx = np.asarray(rows, dtype=np.int64)
    if frac <= 0.0:
        return np.empty(0, dtype=np.int64), idx
    if meta is not None:
        def when(i):
            m = meta[int(i)]
            return str(m.get("first_submission_date") or m.get("first_seen")
                       or m.get("source") or "")
        idx = np.asarray(sorted(idx, key=when), dtype=np.int64)
    else:
        log.warning("[!] no challenge meta: splitting by row order")
    cut = int(len(idx) * frac)
    return np.sort(idx[:cut]), np.sort(idx[cut:])


# --------------------------------------------------------------------------- #
# Analyzer train/serve skew
# --------------------------------------------------------------------------- #

def analyzer_skew_check(booster, X, op_threshold: float, rows: int,
                        tol: float = SKEW_TOLERANCE) -> dict[str, object]:
    """Perturb ONLY the analyzer-supplied columns by the tolerated error.

    predict.py --analysis replaces the histogram/byteentropy columns with the
    C++ analyzer's values after checking they are within `tol` of thrember. This
    measures how far a score can move under exactly that substitution, so
    'within tolerance' is shown to be safe for the model rather than assumed.
    """
    cols = analyzer_columns()
    rng = np.random.default_rng(SEED)
    n = min(rows, X.shape[0])
    best = booster.best_iteration or None
    max_d, flip_05, flip_op = 0.0, 0, 0
    for s in range(0, n, 20_000):
        sel = np.arange(s, min(s + 20_000, n))
        base = take(X, sel)
        pert = base.copy()
        pert[:, cols] += rng.uniform(-tol, tol, size=(len(sel), len(cols))
                                     ).astype(np.float32)
        p0 = booster.predict(base, num_iteration=best)
        p1 = booster.predict(pert, num_iteration=best)
        max_d = max(max_d, float(np.abs(p0 - p1).max()))
        flip_05 += int(((p0 >= 0.5) != (p1 >= 0.5)).sum())
        flip_op += int(((p0 >= op_threshold) != (p1 >= op_threshold)).sum())
    res = {"columns_perturbed": int(len(cols)), "groups": list(ANALYZER_GROUPS),
           "tolerance": tol, "rows": n, "max_abs_score_change": max_d,
           "verdict_flips_at_0.5": flip_05,
           "verdict_flips_at_operating_threshold": flip_op}
    log.info("[+] analyzer skew (+/-%g on %d cols, %d rows): max |dp|=%.2e, "
             "flips@0.5=%d, flips@operating=%d", tol, len(cols), n, max_d,
             flip_05, flip_op)
    return res


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Train LightGBM on EMBER2024 vectors.",
        formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    ap.add_argument("--vectors", type=Path, default=Path("data/vectors"),
                    help="Directory with X_train.npy / y_train.npy (+ meta_*.jsonl).")
    ap.add_argument("--model", type=Path, default=Path("model.txt"),
                    help="Output LightGBM model file.")
    ap.add_argument("--metrics", type=Path, default=None,
                    help="Metrics JSON. Default: <model>.metrics.json")
    ap.add_argument("--challenge", type=Path, default=None,
                    help="Optional X_challenge.npy (6,315 evasive samples).")
    ap.add_argument("--challenge-train-frac", type=float, default=0.0,
                    help="Fraction (oldest first) of the challenge set to add to "
                         "TRAINING; the rest stays held out for the evasion "
                         "score. Default 0 = all held out (the evasion score "
                         "then measures a model that never saw evasive files).")
    ap.add_argument("--max-fpr", type=float, default=5e-3,
                    help="Target FPR for the operating point. Default: 0.005")
    ap.add_argument("--val-frac", type=float, default=0.15,
                    help="Share of (deduplicated) train, newest whole weeks, held "
                         "out for early stopping and the operating threshold.")
    ap.add_argument("--early-stopping", type=int, default=100,
                    help="Stop after N rounds without validation improvement. "
                         "0 disables it and trains all --num-iterations rounds.")
    ap.add_argument("--no-dedup", action="store_true",
                    help="Keep duplicate sha256 rows (not recommended).")
    ap.add_argument("--num-iterations", type=int, default=None,
                    help="Override the boosting-round ceiling.")
    ap.add_argument("--num-threads", type=int, default=0,
                    help="CPU threads. 0 = all cores (set a fixed number for "
                         "bit-for-bit reproducible runs).")
    ap.add_argument("--params-json", type=Path, default=None,
                    help="JSON of LightGBM params merged over the defaults.")
    ap.add_argument("--grid-json", type=Path, default=None,
                    help="JSON array of LightGBM param dicts. Each is trained on "
                         "the deduplicated time split and ranked by validation TPR "
                         "at the FPR budget.")
    ap.add_argument("--grid-max-rows", type=int, default=300_000,
                    help="Cap the fit rows a grid comparison uses. 0 = all.")
    ap.add_argument("--skew-rows", type=int, default=50_000,
                    help="Test rows used for the analyzer-column skew check. "
                         "0 skips it.")
    args = ap.parse_args(argv)

    mllog.setup("train")
    log.debug("args: %s", args)

    if args.grid_json:
        return run_grid(args)

    try:
        import lightgbm as lgb  # noqa: F401
    except ImportError:
        log.error("lightgbm not installed. Run: python -m pip install lightgbm")
        raise SystemExit(1)

    params = dict(DEFAULT_PARAMS)
    if args.params_json:
        params.update(json.loads(args.params_json.read_text(encoding="utf-8")))
    if args.num_iterations:
        params["num_iterations"] = args.num_iterations
    params["num_threads"] = args.num_threads
    params.pop("tag", None)

    X, y = load_split(args.vectors, "train")
    meta = load_meta(args.vectors, "train", len(y))
    fit_rows, val_rows, dstats = prepare(args, X, y, meta)

    Xte = yte = None
    if (args.vectors / "X_test.npy").exists():
        Xte, yte = load_split(args.vectors, "test")
    else:
        log.warning("[!] no test split: only validation metrics will be reported")

    # Optional: part of the challenge set joins training (oldest weeks first).
    Xc = c_train = c_eval = None
    if args.challenge:
        Xc = np.load(args.challenge, mmap_mode="r")
        check_layout(Xc)
        known: set[str] = set()
        for split, arr in (("train", y), ("test", yte)):
            if arr is None:
                continue
            m = load_meta(args.vectors, split, len(arr))
            if m:
                known.update(str(r.get("sha256") or "").lower() for r in m)
        known.discard("")
        c_train, c_eval = split_challenge(args, Xc, known)
        log.info("[*] challenge: %d rows join training, %d held out for evasion "
                 "scoring", len(c_train), len(c_eval))

    Xf, yf = take(X, fit_rows), y[fit_rows]
    if c_train is not None and len(c_train):
        Xf = np.vstack([Xf, take(Xc, c_train)])
        yf = np.concatenate([yf, np.ones(len(c_train), dtype=yf.dtype)])
    Xv, yv = take(X, val_rows), y[val_rows]
    log.info("[*] fit %s files (%s malicious) / validate %s files (%s malicious)",
             f"{len(yf):,}", f"{int(yf.sum()):,}", f"{len(yv):,}",
             f"{int(yv.sum()):,}")
    log.info("[*] training: %s", params)

    t0 = time.time()
    booster = fit_booster(params, Xf, yf, Xv, yv, args.early_stopping)
    train_s = time.time() - t0
    n_trees = int(booster.best_iteration or booster.num_trees())
    log.info("[+] trained in %.1fs, %d trees kept (best iteration %s of %d)",
             train_s, n_trees, booster.best_iteration or "n/a",
             booster.num_trees())

    args.model.parent.mkdir(parents=True, exist_ok=True)
    booster.save_model(str(args.model), num_iteration=n_trees)
    log.info("[+] model -> %s (%.1f MB)", args.model,
             args.model.stat().st_size / (1024 * 1024))

    metrics: dict[str, object] = {
        "params": {k: (list(v) if isinstance(v, (list, tuple)) else v)
                   for k, v in params.items()},
        "train_seconds": round(train_s, 2),
        "trees": n_trees,
        "best_iteration": int(booster.best_iteration or 0),
        "n_features": int(Xf.shape[1]),
        "feature_layout": [{"group": n, "offset": o, "dim": d,
                            "analyzer_supplied": n in ANALYZER_GROUPS}
                           for n, o, d in layout()],
        "max_fpr_target": args.max_fpr,
        "data": {"train_dedup": dstats, "fit_files": int(len(yf)),
                 "validation_files": int(len(yv)), "val_frac": args.val_frac,
                 "challenge_train_rows": int(len(c_train)) if c_train is not None else 0},
    }

    # Validation (newest unseen weeks) picks the operating threshold.
    val_res, val_scores = evaluate(booster, Xv, yv, "validation (newest weeks)",
                                   args.max_fpr)
    op_thr = pick_threshold(yv, val_scores, args.max_fpr)
    val_res["operating_threshold"] = op_thr
    metrics["validation"] = val_res
    metrics["operating_threshold"] = op_thr
    log.info("[+] operating threshold %.6f chosen on validation (FPR<=%g)",
             op_thr, args.max_fpr)

    if Xte is not None:
        metrics["test"], _ = evaluate(booster, Xte, yte, "test", args.max_fpr,
                                      op_threshold=op_thr)
        metrics["test"]["note"] = (
            "operating_threshold was chosen on validation and only applied "
            "here; oracle_threshold is the test-selected value (optimistic, "
            "kept for comparison with older reports)")
        if args.skew_rows:
            metrics["analyzer_skew"] = analyzer_skew_check(
                booster, Xte, op_thr, args.skew_rows)

    sub = fit_rows[:: max(1, len(fit_rows) // 100_000)]
    metrics["train_fit"], _ = evaluate(booster, X, y, "train (fit)",
                                       args.max_fpr, rows=sub)
    metrics["train_fit"]["note"] = ("fit statistic on a subsample of the "
                                    "training split, not a generalisation "
                                    "measure")

    if Xc is not None and len(c_eval):
        log.info("[*] challenge: %s held-out evasive samples", f"{len(c_eval):,}")
        yc = np.ones(Xc.shape[0], dtype=np.int8)   # indexed by row, like Xc
        res, _ = evaluate(booster, Xc, yc, "challenge (evasion)", args.max_fpr,
                          rows=c_eval, op_threshold=op_thr)
        res["held_out_fraction"] = round(
            len(c_eval) / max(1, len(c_eval) + len(c_train)), 4)
        metrics["challenge"] = res
        log.info("[+] evasion: %.1f%% caught at 0.5, %.1f%% at the operating "
                 "threshold", res["caught_at_0.5"] * 100,
                 res["caught_at_operating_threshold"] * 100)

    mpath = args.metrics or args.model.with_suffix(args.model.suffix + ".metrics.json")
    # allow_nan=False turns a stray NaN/Infinity into a hard failure here instead
    # of writing a file that jq / JSON.parse reject.
    mpath.write_text(json.dumps(metrics, indent=2, allow_nan=False),
                     encoding="utf-8")
    log.info("[+] metrics -> %s", mpath)
    log.info("\nNext: python predict.py --model %s --file <sample>", args.model)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001
        mllog.setup("train")  # idempotent: covers crashes before main() set it up
        log.exception("train crashed: %s", exc)
        sys.exit(1)
