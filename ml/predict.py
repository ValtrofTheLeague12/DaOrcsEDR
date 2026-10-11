#!/usr/bin/env python3
"""
Score a file with a trained EMBER2024 model, optionally using the analyzer's
validated byte-statistic features, or cross-check those features against thrember.

Modes:

  --file <path>                 score a binary using thrember's full feature vector

  --analysis <extraction.json>  score using the analyzer's two EMBER-compatible
                                vectors after validating them against thrember

  --check <extraction.json>     compare the analyzer's two vectors against
                                thrember without loading a model

    python predict.py --model model.txt --file sample.exe
    python predict.py --model model.txt --file sample.exe --analysis sample_extraction.json
    python predict.py --check ../exports/<stem>_analysis/extraction/sample_extraction.json --file sample.exe
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).parent))
import mllog  # noqa: E402
from vectorize import FEATURE_DIM, FEATURE_GROUPS  # noqa: E402

log = logging.getLogger("ml.predict")  # handlers attached in main() by mllog.setup


def _group_slice(group_name: str) -> slice:
    offset = 0
    for name, dimension in FEATURE_GROUPS:
        if name == group_name:
            return slice(offset, offset + dimension)
        offset += dimension
    raise ValueError(f"unknown EMBER feature group: {group_name}")


def _load_analyzer_vectors(json_path: Path, target: Path, raw: bytes) -> tuple[np.ndarray, np.ndarray]:
    data = json.loads(json_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{json_path} must contain a JSON object")

    hist = data.get("byte_histogram")
    if not isinstance(hist, dict):
        raise ValueError(f"{json_path} has no byte_histogram section")

    total_bytes = hist.get("total_bytes")
    if total_bytes != len(raw):
        raise ValueError(
            f"{json_path} describes {total_bytes!r} bytes but {target} "
            f"contains {len(raw)} bytes; use the report for this exact file")

    metadata = data.get("raw")
    expected_sha256 = metadata.get("sha256") if isinstance(metadata, dict) else None
    if expected_sha256:
        actual_sha256 = hashlib.sha256(raw).hexdigest()
        if not isinstance(expected_sha256, str) or expected_sha256.lower() != actual_sha256:
            raise ValueError(
                f"{json_path} SHA-256 does not match {target}; rerun the analyzer "
                "on this exact file")
    else:
        log.warning(
            "%s has no raw SHA-256; file pairing is checked by size and "
            "EMBER byte vectors only", json_path)

    vectors = []
    for name in ("ember_histogram", "ember_byteentropy"):
        values = hist.get(name)
        try:
            vector = np.asarray(values, dtype=np.float32)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{json_path} has an invalid {name} vector") from exc
        if vector.shape != (256,) or not np.isfinite(vector).all():
            raise ValueError(
                f"{json_path} {name} must contain 256 finite values, "
                f"got shape {vector.shape}")
        vectors.append(vector)
    return vectors[0], vectors[1]


def _compare_analyzer_vectors(
    reference: tuple[np.ndarray, np.ndarray],
    analyzer: tuple[np.ndarray, np.ndarray],
) -> bool:
    ok = True
    for name, ref, mine in zip(
            ("ember_histogram", "ember_byteentropy"), reference, analyzer):
        diff = np.abs(np.asarray(ref, dtype=np.float64) -
                      np.asarray(mine, dtype=np.float64))
        worst = float(diff.max())
        idx = int(diff.argmax())
        status = "PASS" if worst == 0.0 else ("PASS (fp)" if worst < 1e-6 else "FAIL")
        if worst >= 1e-6:
            ok = False
        line = (f"[{status}] {name}: max abs diff {worst:.3e} at index {idx} "
                f"(thrember {ref[idx]:.8f} vs analyzer {mine[idx]:.8f})")
        sums = f"        sum: thrember {ref.sum():.6f} vs analyzer {mine.sum():.6f}"
        if status == "FAIL":
            log.error(line)
            log.error(sums)
        else:
            log.info(line)
            log.info(sums)
    return ok


def score_file(
    model_path: Path,
    target: Path,
    threshold: float,
    analysis_path: Path | None = None,
    explain_top_k: int | None = None,
) -> dict[str, object]:
    import lightgbm as lgb
    from thrember.features import PEFeatureExtractor

    raw = target.read_bytes()
    extractor = PEFeatureExtractor()
    # One parse feeds both the vector and --explain: raw_features() yields the
    # named groups (imports/exports) that hashed columns can be resolved back to.
    groups = extractor.raw_features(raw)
    vec = np.asarray(extractor.process_raw_features(groups), dtype=np.float32)
    if vec.shape[0] != FEATURE_DIM:
        log.error("thrember produced %d dims, expected %d", vec.shape[0], FEATURE_DIM)
        raise SystemExit(1)
    feature_source = "thrember"
    if analysis_path is not None:
        analyzer = _load_analyzer_vectors(analysis_path, target, raw)
        histogram_slice = _group_slice("histogram")
        entropy_slice = _group_slice("byteentropy")
        reference = (vec[histogram_slice], vec[entropy_slice])
        if not _compare_analyzer_vectors(reference, analyzer):
            raise ValueError(
                "static-analyzer EMBER vectors do not match thrember; "
                "refusing to score mismatched features")
        vec[histogram_slice], vec[entropy_slice] = analyzer
        feature_source = "thrember + static analyzer byte statistics"

    booster = lgb.Booster(model_file=str(model_path))
    prob = float(booster.predict(vec[None, :])[0])
    out: dict[str, object] = {
        "file": target.name, "malicious_probability": round(prob, 6),
        "verdict": "malicious" if prob >= threshold else "benign",
        "threshold": threshold, "feature_source": feature_source}
    if explain_top_k is not None:
        # Imported lazily so plain scoring does not pull in Flask.
        from serve import explain
        out["explanation"] = explain(booster, vec, groups, explain_top_k)
    return out


def check_against_thrember(json_path: Path, target: Path) -> int:
    """Diff the analyzer's two EMBER vectors against thrember's, element-wise."""
    from thrember.features import ByteEntropyHistogram, ByteHistogram

    raw = target.read_bytes()
    mine_h, mine_b = _load_analyzer_vectors(json_path, target, raw)
    ref_h = np.asarray(ByteHistogram().process_raw_features(
        ByteHistogram().raw_features(raw, None)), dtype=np.float64)
    be = ByteEntropyHistogram()
    ref_b = np.asarray(be.process_raw_features(be.raw_features(raw, None)), dtype=np.float64)

    ok = _compare_analyzer_vectors((ref_h, ref_b), (mine_h, mine_b))
    if ok:
        log.info("\n[+] vectors match; the C++ exporter is EMBER-compatible.")
    else:
        log.error("\n[-] MISMATCH: do not use these vectors to train or score.")
    return 0 if ok else 1


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Score a file, or verify the analyzer's EMBER vectors.",
        formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    ap.add_argument("--model", type=Path, help="Trained LightGBM model file.")
    ap.add_argument("--file", "-f", type=Path, required=True,
                    help="Binary to score (or whose vectors to verify).")
    ap.add_argument("--analysis", type=Path, default=None,
                    help="Analyzer extraction JSON to use and validate while scoring.")
    ap.add_argument("--check", type=Path, default=None,
                    help="Analyzer extraction JSON to diff against thrember.")
    ap.add_argument("--threshold", type=float, default=0.5,
                    help="Malicious if probability >= this. Default: 0.5")
    ap.add_argument("--explain", action="store_true",
                    help="Add TreeSHAP attribution: what pushed this score, "
                         "with named imports/exports where possible.")
    ap.add_argument("--top-k", type=int, default=8,
                    help="How many top features to explain. Default: 8")
    ap.add_argument("--json", action="store_true", help="Print JSON only.")
    args = ap.parse_args(argv)

    # --json must keep stdout machine-readable: no console INFO lines there.
    mllog.setup("predict", stdout=not args.json)
    log.debug("args: %s", args)

    if not args.file.is_file():
        log.error("%s is not a file", args.file)
        raise SystemExit(1)

    if args.check:
        return check_against_thrember(args.check, args.file)

    if not args.model:
        log.error("pass --model to score, or --check to verify vectors.")
        raise SystemExit(1)
    top_k = max(1, min(args.top_k, 50))
    res = score_file(args.model, args.file, args.threshold, args.analysis,
                     top_k if args.explain else None)
    if args.json:
        print(json.dumps(res))
    else:
        log.info("file     : %s", res["file"])
        log.info("p(malicious): %.6f", res["malicious_probability"])
        log.info("verdict  : %s  (threshold %s)", res["verdict"], res["threshold"])
        log.info("features : %s", res["feature_source"])
        ex = res.get("explanation")
        if ex:
            log.info("why      : base %+.3f -> %+.3f log-odds (SHAP sum %+.3f)",
                     ex["base_log_odds"], ex["prediction_log_odds"], ex["sum_shap"])
            for f in ex["top_features"]:
                log.info("          %+7.3f  %-42s %s", f["shap_log_odds"],
                         f["evidence"] or f"column {f['feature_index']}",
                         f["direction"])
            for g in ex["group_rollup"][:5]:
                log.info("          group %-16s %+7.3f%s", g["group"],
                         g["shap_log_odds"],
                         "" if g["analyzer_implemented"]
                         else "  (not produced by the C++ exporter)")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001
        mllog.setup("predict")  # idempotent: covers crashes before main() set it up
        log.exception("predict crashed: %s", exc)
        sys.exit(1)
