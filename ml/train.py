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


def evaluate(model, X, y, tag: str, max_fpr: float) -> dict[str, object]:
    """ROC-AUC plus the TPR achieved at the chosen max-FPR point."""
    from sklearn.metrics import average_precision_score, roc_auc_score, roc_curve

    t0 = time.time()
    # lgb.Booster exposes predict(); predict_proba() only exists on the
    # sklearn wrapper (LGBMClassifier). For a binary objective predict()
    # already returns P(class 1).
    scores = model.predict(np.asarray(X, dtype=np.float32))
    # AUC/AP are undefined when the split holds a single class (the challenge set
    # is all-malicious), and sklearn returns NaN with a warning rather than
    # raising. Report that as null: NaN is not valid JSON and strict parsers
    # reject the whole metrics file over one meaningless number.
    single_class = len(np.unique(y)) < 2
    auc = ap = float("nan")
    fpr = tpr = None
    if not single_class:
        auc = float(roc_auc_score(y, scores))
        ap = float(average_precision_score(y, scores))
        fpr, tpr, _ = roc_curve(y, scores)
    # Highest TPR whose FPR stays within budget: the deployment operating point.
    tpr_at = 0.0
    if fpr is not None:
        ok = np.where(fpr <= max_fpr)[0]
        tpr_at = float(tpr[ok[-1]]) if len(ok) else 0.0
    res = {"n": int(len(y)),
           "roc_auc": None if single_class else auc,
           "average_precision": None if single_class else ap,
           "tpr_at_max_fpr": None if single_class else tpr_at,
           "max_fpr": max_fpr,
           "seconds": round(time.time() - t0, 2)}
    if single_class:
        res["note"] = ("single-class split: ROC-AUC and average precision are "
                       "undefined, so only the catch rate below is meaningful")
        log.info("[!] %s: single-class split, AUC/AP undefined", tag)
    else:
        log.info("[+] %s: AUC=%.5f  AP=%.5f  TPR@FPR<=%g=%.4f  (%ss)",
                 tag, auc, ap, max_fpr, tpr_at, res["seconds"])
    return res


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
    args = ap.parse_args(argv)

    mllog.setup("train")
    log.debug("args: %s", args)

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
        caught = float((booster.predict(
            np.asarray(Xc, dtype=np.float32)) >= 0.5).mean())
        res["caught_at_0.5"] = caught
        metrics["challenge"] = res
        log.info("[+] evasion: %.1f%% caught at threshold 0.5", caught * 100)

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
