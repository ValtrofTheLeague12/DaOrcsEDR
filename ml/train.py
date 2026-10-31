#!/usr/bin/env python3
"""
Train a LightGBM binary classifier on the EMBER2024 feature vectors.

    python train.py --vectors data/vectors --model model.txt

Reads the .npy matrices from vectorize.py, trains, evaluates, and writes a model
the analyzer can load for inference.

The headline number is ROC-AUC at max_fpr=5e-3, the metric the EMBER paper
reports. AUC alone hides operational failure, so this also prints TPR at that
point and, with --challenge, the evasion score over the 6,315 files that ~70 AV
engines initially missed -- the number that says whether the model sees modern
evasive malware at all.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from pathlib import Path

import numpy as np

import mllog

log = logging.getLogger("ml.train")  # handlers attached in main() by mllog.setup

# EMBER2024's own thrember training configuration, tuned for a 5e-3 FPR
# operating point rather than for raw accuracy.
DEFAULT_PARAMS: dict[str, object] = {
    "boosting_type": "gbdt",
    "objective": "binary",
    "num_iterations": 500,
    "learning_rate": 0.05,
    "num_leaves": 1024,
    "feature_fraction": 0.8,
    "bagging_fraction": 0.8,
    "verbose": -1,
    "device": "cpu",
    "num_threads": 0,   # 0 = every core
}


def load_split(vectors: Path, split: str) -> tuple[np.ndarray, np.ndarray]:
    Xp, yp = vectors / f"X_{split}.npy", vectors / f"y_{split}.npy"
    if not Xp.exists() or not yp.exists():
        log.error("missing %s or %s. Run vectorize.py first.", Xp, yp)
        raise SystemExit(1)
    # mmap keeps the 5 GB matrix out of RAM on load; LightGBM's Dataset then
    # builds its own binned copy, which is the real memory cost.
    X = np.load(Xp, mmap_mode="r")
    y = np.load(yp)
    log.info("[*] %s: X=%s %s  y=%s  malicious=%s benign=%s",
             split, X.shape, X.dtype, y.shape,
             f"{int(y.sum()):,}", f"{len(y) - int(y.sum()):,}")
    return X, y


def _summarise(y, scores, tag: str, max_fpr: float,
               seconds: float = 0.0) -> dict[str, object]:
    """The one scoring function, so two callers cannot drift apart.

    Returns ROC-AUC/AP, the TPR achieved at the FPR budget, and the operating
    threshold (smallest threshold on the official split whose FPR stays within
    the budget) - the number serve.py should score at instead of a fixed 0.5.
    """
    from sklearn.metrics import average_precision_score, roc_auc_score, roc_curve

    single_class = len(np.unique(y)) < 2
    auc = ap = float("nan")
    fpr = tpr = None
    if not single_class:
        auc = float(roc_auc_score(y, scores))
        ap = float(average_precision_score(y, scores))
        fpr, tpr, thr = roc_curve(y, scores)
    tpr_at = 0.0
    threshold = None
    if fpr is not None:
        ok = np.where(fpr <= max_fpr)[0]
        tpr_at = float(tpr[ok[-1]]) if len(ok) else 0.0
        # roc_curve's thresholds descend alongside (fpr, tpr): index ok[-1]
        # holds the smallest threshold that respects the budget, where TPR
        # peaks. Falls back to the strictest ceil if nothing lands under it.
        if len(ok):
            threshold = float(thr[ok[-1]])
        elif len(thr):
            threshold = float(thr[0])
    res = {"n": int(len(y)),
           "roc_auc": None if single_class else auc,
           "average_precision": None if single_class else ap,
           "tpr_at_max_fpr": None if single_class else tpr_at,
           "operating_threshold": threshold,
           "max_fpr": max_fpr,
           "seconds": round(seconds, 2)}
    if single_class:
        res["note"] = ("single-class split: ROC-AUC and average precision are "
                       "undefined, so only the catch rate below is meaningful")
        log.info("[!] %s: single-class split, AUC/AP undefined", tag)
    else:
        log.info("[+] %s: AUC=%.5f  AP=%.5f  TPR@FPR<=%g=%.4f  (thr=%.4f, %ss)",
                 tag, auc, ap, max_fpr, tpr_at, threshold or 0.0, res["seconds"])
    return res


def evaluate(model, X, y, tag: str, max_fpr: float) -> dict[str, object]:
    """ROC-AUC plus the TPR achieved at the chosen max-FPR point."""
    t0 = time.time()
    # lgb.Booster exposes predict(); predict_proba() only exists on the
    # sklearn wrapper (LGBMClassifier). For a binary objective predict()
    # already returns P(class 1).
    scores = model.predict(np.asarray(X, dtype=np.float32))
    return _summarise(y, scores, tag=tag, max_fpr=max_fpr,
                      seconds=time.time() - t0)


def evalThreshold(model, X, y, threshold: float) -> float:
    """The catch rate at a fixed operating threshold: the fraction scored
    over it. deployment bookkeeping, not split-dependent FPR math."""
    scores = model.predict(np.asarray(X, dtype=np.float32))
    return float((scores >= threshold).mean())


def run_grid(args) -> int:
    """Train several candidates on a train holdout, compare, report, exit.

    Not the final training: each candidate sees 80% of the train rows and is
    scored on the untouched 20%, so the comparison measures generalisation, not
    memorisation. The winner still gets trained on ALL rows by a plain run,
    and officially judged on the untouched test split.
    """
    import lightgbm as lgb

    plans = json.loads(args.grid_json.read_text(encoding="utf-8"))
    if not isinstance(plans, list) or not plans:
        log.error("--grid-json must be a non-empty JSON array of param dicts")
        return 1

    X, y = load_split(args.vectors, "train")
    rng = np.random.default_rng(0xE8B3)
    n = len(y)
    cap = int(getattr(args, "grid_max_rows", 0) or 0)
    if cap and n > cap:
        idx = rng.permutation(n)[:cap]
        log.info("[*] grid sample: %d of %d train rows", cap, n)
    else:
        idx = rng.permutation(n)
    cut = int(len(idx) * 0.8)
    tr, ho = idx[:cut], idx[cut:]
    Xtr = np.asarray(X[tr], dtype=np.float32); ytr = y[tr]
    Xho = np.asarray(X[ho], dtype=np.float32); yho = y[ho]
    log.info("[*] grid holdout: %d train / %d holdout rows", len(ytr), len(yho))

    rows: list[dict] = []
    for i, over in enumerate(plans, 1):
        params = dict(DEFAULT_PARAMS)
        params.update(over)
        tag = params.get("tag", f"cand{i}")
        log.info("[*] candidate %d/%d: %s %s", i, len(plans), tag,
                 {k: v for k, v in over.items() if k != "tag"})
        ds = lgb.Dataset(Xtr, label=ytr, free_raw_data=True)
        t0 = time.time()
        booster = lgb.train(params, ds, num_boost_round=int(params["num_iterations"]))
        secs = time.time() - t0
        res = evaluate(booster, Xho, yho, f"holdout[{tag}]",
                       args.max_fpr)
        res["tag"] = tag
        res["train_seconds"] = round(secs, 1)
        res["trees"] = booster.num_trees()
        res["params"] = {k: v for k, v in params.items() if k != "tag"}
        rows.append(res)

    def key(r):
        # Highest TPR within the FPR budget wins; AUC breaks ties.
        return (r.get("tpr_at_max_fpr") or 0.0, r.get("roc_auc") or 0.0)

    ranked = sorted(rows, key=key, reverse=True)
    best = ranked[0]
    for rank, r in enumerate(ranked, 1):
        log.info("[%d] %-14s TPR@<=g=%.4f AUC=%.5f  (%s)",
                 rank, r["tag"], r["tpr_at_max_fpr"], r["roc_auc"],
                 r["params"])
    log.info("[+] winner: %s", best["tag"])

    report = {"best_tag": best["tag"], "max_fpr": args.max_fpr,
              "rows": rows, "ranked_tags": [r["tag"] for r in ranked],
              "note": ("holdout comparison inside the train split; not the "
                       "official test split")}
    out = args.grid_json.with_suffix(".report.json")
    out.write_text(json.dumps(report, indent=2, allow_nan=False),
                   encoding="utf-8")
    log.info("[+] grid report -> %s", out)
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Train LightGBM on EMBER2024 vectors.",
        formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    ap.add_argument("--vectors", type=Path, default=Path("data/vectors"),
                    help="Directory with X_train.npy / y_train.npy.")
    ap.add_argument("--model", type=Path, default=Path("model.txt"),
                    help="Output LightGBM model file.")
    ap.add_argument("--metrics", type=Path, default=None,
                    help="Metrics JSON. Default: <model>.metrics.json")
    ap.add_argument("--challenge", type=Path, default=None,
                    help="Optional X_challenge.npy (6,315 evasive samples).")
    ap.add_argument("--max-fpr", type=float, default=5e-3,
                    help="Target FPR for the operating point. Default: 0.005")
    ap.add_argument("--num-iterations", type=int, default=None,
                    help="Override boosting rounds (default 500).")
    ap.add_argument("--num-threads", type=int, default=0,
                    help="CPU threads. 0 = all cores.")
    ap.add_argument("--params-json", type=Path, default=None,
                    help="JSON of LightGBM params merged over the defaults.")
    ap.add_argument("--grid-json", type=Path, default=None,
                    help="JSON array of LightGBM param dicts. Each is trained on "
                         "a holdout split of train, scored once, and compared by "
                         "TPR at the FPR budget - the report names the winner and "
                         "why. much faster than re-running train.py per candidate.")
    ap.add_argument("--grid-max-rows", type=int, default=300_000,
                    help="Cap the rows a grid comparison samples from train, so a "
                         "multi-million-row corpus cannot exhaust RAM while five "
                         "candidates are being ranked. 0 = use every row. The "
                         "winner is still retrained on the whole split.")
    args = ap.parse_args(argv)

    mllog.setup("train")
    log.debug("args: %s", args)

    if args.grid_json:
        return run_grid(args)

    try:
        import lightgbm as lgb
    except ImportError:
        log.error("lightgbm not installed. Run: python -m pip install lightgbm")
        raise SystemExit(1)

    params = dict(DEFAULT_PARAMS)
    if args.params_json:
        params.update(json.loads(args.params_json.read_text(encoding="utf-8")))
    if args.num_iterations:
        params["num_iterations"] = args.num_iterations
    params["num_threads"] = args.num_threads

    Xtr, ytr = load_split(args.vectors, "train")
    Xte = yte = None
    if (args.vectors / "X_test.npy").exists():
        Xte, yte = load_split(args.vectors, "test")
    else:
        log.warning("[!] no test split; holding out 10% of train for evaluation")
        rng = np.random.default_rng(0xE8B3)
        idx = rng.permutation(len(ytr))
        cut = int(len(idx) * 0.9)
        tr, te = idx[:cut], idx[cut:]
        Xte = np.asarray(Xtr[te], dtype=np.float32)
        yte = ytr[te]
        Xtr = np.asarray(Xtr[tr], dtype=np.float32)
        ytr = ytr[tr]  # y must follow X: LightGBM rejects a length mismatch

    log.info("[*] training: %s", params)
    ds = lgb.Dataset(np.asarray(Xtr, dtype=np.float32), label=ytr, free_raw_data=True)
    t0 = time.time()
    booster = lgb.train(params, ds, num_boost_round=int(params["num_iterations"]))
    train_s = time.time() - t0
    log.info("[+] trained in %.1fs, %d trees", train_s, booster.num_trees())

    args.model.parent.mkdir(parents=True, exist_ok=True)
    booster.save_model(str(args.model), num_iteration=booster.num_trees())
    log.info("[+] model -> %s (%.1f MB)", args.model,
             args.model.stat().st_size / (1024 * 1024))

    metrics: dict[str, object] = {
        "params": dict(params),
        "train_seconds": round(train_s, 2),
        "trees": booster.num_trees(),
        "n_features": int(Xtr.shape[1]),
        "max_fpr_target": args.max_fpr,
    }
    if yte is not None:
        metrics["test"] = evaluate(booster, Xte, yte, "test", args.max_fpr)
    metrics["train_fit"] = evaluate(booster, Xtr, ytr, "train (fit)", args.max_fpr)

    if args.challenge:
        Xc = np.load(args.challenge, mmap_mode="r")
        # Every challenge sample is malicious, so the catch rate is the evasion
        # score: the fraction of evasive malware the model actually flags.
        yc = np.ones(len(Xc), dtype=np.int8)
        log.info("[*] challenge: %s evasive samples", f"{len(Xc):,}")
        res = evaluate(booster, Xc, yc, "challenge (evasion)", args.max_fpr)
        res["caught_at_0.5"] = float((booster.predict(
            np.asarray(Xc, dtype=np.float32)) >= 0.5).mean())
        # And at the operating threshold the official test split earned: FPR
        # specialised deployment, applied to the evasive set untouched in
        # training.
        if res.get("operating_threshold") is not None:
            res["caught_at_operating_threshold"] = evalThreshold(
                booster, Xc, yc, res["operating_threshold"])
        metrics["challenge"] = res
        log.info("[+] evasion: %.1f%% caught at 0.5, %.1f%% at the operating "
                 "threshold", res["caught_at_0.5"] * 100,
                 (res.get("caught_at_operating_threshold") or 0.0) * 100)

    mpath = args.metrics or args.model.with_suffix(args.model.suffix + ".metrics.json")
    # allow_nan=False turns a stray NaN/Infinity into a hard failure here instead
    # of writing a file that Python can read but jq, JSON.parse and most other
    # consumers reject as malformed.
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
