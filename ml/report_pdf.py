#!/usr/bin/env python3
"""
Render the EMBER2024 evaluation report to PDF.

Reads the artifacts produced by evaluate_report.py (ml/report/*.csv, *.png) plus
the two metric JSONs, feeds them to templates/report.html.j2, and prints the HTML
to PDF with a headless Chromium-family browser.

Integrity design
----------------
A file cannot contain its own SHA-256: writing the digest into the document
changes the bytes, so the digest would no longer match. The QR code therefore
encodes sha256(manifest.json), where the manifest is a canonical JSON listing
every input artifact (model, metrics, charts) with its own digest. That digest is
stable, independently recomputable, and covers all the evidence.

The PDF's own digest is written to a sidecar, report.pdf.sha256, in the format
sha256sum -c accepts.

Output layout
-------------
Shared inputs stay flat in ml/report/ (evaluate_report.py output). Every
generated report gets its own directory holding the PDF and everything derived
alongside it, so a report is one self-contained unit that can be moved,
archived or deleted together:

    ml/report/default/report.pdf          # corpus-wide report
    ml/report/default/manifest.json
    ml/report/default/report.pdf.sha256
    ml/report/a/report.pdf                # --sample a.exe
    ml/report/a/report.vector.csv
    ml/report/a/manifest.json

    python report_pdf.py                     # build the PDF
    python report_pdf.py --verify-only       # rebuild manifest, compare
    python report_pdf.py --sample a.exe      # -> ml/report/a/report.pdf
    python report_pdf.py --engine chrome     # pick a different browser
"""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import jinja2

sys.path.insert(0, str(Path(__file__).parent))
import mllog  # noqa: E402
from vectorize import FEATURE_GROUPS  # noqa: E402

log = logging.getLogger("ml.report_pdf")  # handlers attached in main() by mllog.setup

ROOT = Path(__file__).resolve().parent
# Shared inputs (evaluate_report.py output) live flat in here; every generated
# report gets its own subdirectory so a report and everything derived from it
# stay together and can be deleted or archived as one unit.
REPORT_DIR = ROOT / "report"
TEMPLATE = ROOT / "templates" / "report.html.j2"
DEFAULT_REPORT_NAME = "default"
DEFAULT_OUT = REPORT_DIR / DEFAULT_REPORT_NAME / "report.pdf"
OUTPUT_SUFFIX = ".pdf"
MANIFEST_NAME = "manifest.json"
GENERATOR = "ml/report_pdf.py"


def slug(text: str) -> str:
    """Filesystem-safe directory name for a sample.

    Sample names come from disk and may contain spaces, dots or characters the
    filesystem or a shell will not accept, so reduce to a conservative set.
    """
    safe = "".join(c if c.isalnum() or c in "-_" else "-" for c in text).strip("-")
    return safe or "report"


def default_output_for(sample: Path | None) -> Path:
    """Where a report goes when --output is not given.

    <report>/default/report.pdf for the corpus-wide report, and
    <report>/<sample>/report.pdf for a per-sample one, so each report owns a
    directory containing its PDF, sidecar, manifest, HTML and vector CSV.
    """
    name = DEFAULT_REPORT_NAME if sample is None else slug(sample.stem)
    return REPORT_DIR / name / f"report{OUTPUT_SUFFIX}"

# Human-readable descriptions for the EMBER feature groups, so the feature-space
# table explains what each block of numbers actually is.
GROUP_DESCRIPTIONS = {
    "general": "file size, byte entropy, is_pe, first 4 bytes",
    "histogram": "byte-value histogram, 256 bins",
    "byteentropy": "byte-entropy histogram, 256 bins",
    "strings": "ASCII/Unicode string statistics and printable ratios",
    "header": "DOS/COFF/optional header fields and characteristics",
    "section": "per-section sizes, entropy, names, characteristics",
    "imports": "hashed libraries and fully-qualified imported functions",
    "exports": "export count and hashed export names",
    "datadirectories": "size/VA of each PE data directory, reloc flags",
    "richheader": "Rich header checksum and tool records",
    "authenticode": "signature presence, signer and timestamp fields",
    "pefilewarnings": "pefile parse warnings and anomalous structures",
}

# Chart files grouped by the section that presents them, each with a caption.
CHART_SECTIONS = {
    "diagnostics": [
        ("01_roc_curve.png", "ROC curve",
         "Ranking quality across all thresholds. The marked point is the "
         "FPR-constrained operating point used in section 1."),
        ("02_pr_curve.png", "Precision-recall curve",
         "The dashed line is the no-skill baseline (prevalence), so the "
         "vertical gap is the real gain over chance."),
        ("03_score_distribution.png", "Score distribution",
         "Malicious and benign scores, with the default and FPR-constrained "
         "thresholds marked. The two populations overlap through the mid-range, "
         "so every error is a sample the score alone could not separate."),
        ("04_threshold_tradeoff.png", "Threshold trade-off",
         "The operational chart. Left axis: recall, precision and false-positive "
         "rate. Right axis: evasion catch-rate, which collapses far faster."),
    ],
    "errors": [
        ("07_confusion_matrix.png", "Confusion matrices",
         "Counts at the default and FPR-constrained thresholds side by side, "
         "making the cost of tightening explicit."),
        ("05_errors_by_week.png", "Error drift by week",
         "False-positive and false-negative rates per weekly chunk, at both the "
         "default and FPR-constrained thresholds, with per-week evasion "
         "catch-rate. Rates are per class within each week. Flatness is evidence "
         "the model is not merely tracking a shifting corpus."),
    ],
    "attribution": [
        ("06_feature_group_importance.png", "Feature-group importance",
         "Share of total model gain per EMBER group. This is what justifies "
         "the integration decision in section 2."),
        ("08_corpus_composition.png", "Corpus composition",
         "Composition of the audited splits and challenge families, so the "
         "evaluation set can be judged for representativeness."),
    ],
    "dataset": [
        ("09_dataset_correlation.png", "Dataset profile and feature correlations",
         "Pandas profile of a deterministic sample from the held-out split. The "
         "left panel ranks feature-to-label Pearson correlations; the right panel "
         "shows correlations among the top 20 features. Correlation is descriptive, "
         "not causal."),
    ],
}

# Document order of the chart sections, used to number figures monotonically.
# Kept as an explicit list rather than read off CHART_SECTIONS so that reordering
# CHART_SECTIONS alone cannot silently renumber the report: build_context asserts
# that this list covers exactly the sections that exist.
_CHART_ORDER = ("extra", "diagnostics", "errors", "attribution", "dataset")

def figure_bases(charts: dict) -> dict:
    """How many figures precede each chart section, in document order.

    The template used hardcoded `loop.index + N` offsets per section. Those drift
    the moment a figure is added or removed -- an extra chart in one section
    silently renumbers every figure after it -- and the section 12 dataset figure
    had no number at all. Deriving the offsets from the charts actually being
    rendered cannot drift.

    Called from main() rather than build_context(), because `charts["extra"] is
    filled in *after* build_context returns (extra_charts() plus the prevalence
    and calibration figures). Computing here would see an empty list and hand the
    first five figures a base of 0, which is exactly the collision this replaces.

    Counted from rendered figures, not from CHART_SECTIONS: a chart whose PNG is
    missing is skipped at render time, so counting it would leave a gap.

    "extra" is deliberately absent from CHART_SECTIONS -- its figures are
    generated at render time (extra_charts(), prevalence_chart(),
    calibration_chart()) and injected into the context by main() -- but it takes
    part in the same numbering sequence, so it is expected here too.
    """
    expected = set(CHART_SECTIONS) | {"extra"}
    if set(charts) != expected:
        raise RuntimeError(
            f"chart sections disagree: chart keys {sorted(charts)}, "
            f"expected {sorted(expected)} (CHART_SECTIONS {sorted(CHART_SECTIONS)} "
            f"+ the generated 'extra')")
    base: dict = {}
    total = 0
    for name in _CHART_ORDER:
        base[name] = total
        total += len(charts.get(name, ()))
    return base


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def read_csv(path: Path) -> list[dict]:
    with path.open(newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def data_uri(path: Path) -> str:
    """Inline an image so the rendered HTML has no external references."""
    mime = "image/png" if path.suffix.lower() == ".png" else "image/jpeg"
    return f"data:{mime};base64," + base64.b64encode(path.read_bytes()).decode("ascii")


def confusion(scores, labels, threshold: float) -> dict:
    """Counts and rates at one threshold. scores/labels are numpy arrays."""
    pred = scores >= threshold
    pos = labels == 1
    tp = int((pred & pos).sum())
    fp = int((pred & ~pos).sum())
    fn = int((~pred & pos).sum())
    tn = int((~pred & ~pos).sum())
    return {
        "threshold": threshold, "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "accuracy": (tp + tn) / len(labels),
        "precision": tp / (tp + fp) if tp + fp else 0.0,
        "recall": tp / (tp + fn) if tp + fn else 0.0,
        "fpr": fp / (fp + tn) if fp + tn else 0.0,
        "f1": (2 * tp / (2 * tp + fp + fn)) if tp else 0.0,
    }


def browser_candidates() -> dict[str, list[Path]]:
    """Every place a Chromium-family browser is commonly installed.

    Including per-user installs, the Beta/Dev/Canary channels, and the Chromium
    that `playwright install chromium` drops in ms-playwright, so the tool works
    on machines without a system-wide Edge or Chrome.
    """
    local = Path(os.environ.get("LOCALAPPDATA", "")) if os.environ.get("LOCALAPPDATA") else None
    prog = [Path(os.environ.get("ProgramFiles", r"C:\Program Files")),
            Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"))]

    def in_prog(*rel: str) -> list[Path]:
        return [base / r for base in prog for r in rel]

    def in_local(*rel: str) -> list[Path]:
        return [local / r for r in rel] if local else []

    edge = (in_prog(r"Microsoft\Edge\Application\msedge.exe")
            + in_local(r"Microsoft\Edge\Application\msedge.exe"))
    chrome = (in_prog(r"Google\Chrome\Application\chrome.exe")
              + in_local(r"Google\Chrome\Application\chrome.exe"))
    # Side-by-side channels (Beta/Dev/Canary) for both browsers.
    for channel in ("Beta", "Dev", "Canary"):
        edge += in_prog(rf"Microsoft\Edge {channel}\Application\msedge.exe")
        chrome += (in_prog(rf"Google\Chrome-{channel}\Application\chrome.exe")
                   + in_local(rf"Google\Chrome-{channel}\Application\chrome.exe"))
    # Playwright's bundled Chromium.
    if local:
        for hit in sorted((local / "ms-playwright").glob("chromium*/chrome-win/chrome.exe"),
                          reverse=True):
            chrome.append(hit)
    return {"edge": edge, "chrome": chrome}


def find_browser(engine: str, override: str | None = None) -> Path | None:
    """Locate a Chromium-family browser for headless printing.

    An explicit path (REPORT_PDF_BROWSER or --browser) always wins, so an
    unusual install can be pointed at directly.
    """
    if override:
        p = Path(override).expanduser()
        return p if p.is_file() else None

    candidates = browser_candidates()
    order = ["edge", "chrome"] if engine == "auto" else [engine]
    for name in order:
        for cand in candidates.get(name, []):
            if cand.is_file():
                return cand
    # PATH last, so a system install wins over a side-channel.
    for exe in ("msedge", "chrome", "chromium", "chromium-browser"):
        found = shutil.which(exe)
        if found:
            return Path(found)
    return None
def build_manifest(paths: list[Path], root: Path | None = None) -> dict:
    """Canonical manifest of every input artifact, plus its own digest.

    The digest covers the artifact names and their digests only -- not sizes,
    paths outside ml/, or timestamps -- so it is reproducible across machines
    and checkouts. `root` is accepted for call-site compatibility and ignored:
    names are always relative to ml/.
    """
    entries = []
    for p in sorted(set(paths)):
        if not p.is_file():
            continue
        # Resolve before naming: the same artifact arrives as a relative path
        # from a relative -o and as an absolute one from the default output, and
        # the manifest must record one stable name either way.
        p = p.resolve()
        # Paths are relative to ml/ when the file lives there, so a reader who
        # follows the QR can resolve the entry from the ml directory. A --sample
        # outside ml/ is recorded by absolute path instead, since no relative
        # path would resolve.
        try:
            name = p.relative_to(ROOT).as_posix()
        except ValueError:
            name = p.as_posix()
        entries.append({"name": name,
                        "bytes": p.stat().st_size,
                        "sha256": sha256_file(p)})
    entries.sort(key=lambda e: e["name"])
    canonical = json.dumps(
        {"generator": GENERATOR, "entries": entries},
        sort_keys=True, separators=(",", ":")).encode("utf-8")
    return {"name": MANIFEST_NAME, "entries": entries,
            "sha256": hashlib.sha256(canonical).hexdigest()}


def gain_shares() -> dict[str, float]:
    """Share of total model gain per EMBER group, from feature_importance.csv."""
    rows = read_csv(REPORT_DIR / "feature_importance.csv")
    totals: dict[str, float] = {}
    for r in rows:
        totals[r["group"]] = totals.get(r["group"], 0.0) + float(r["gain"])
    grand = sum(totals.values()) or 1.0
    return {g: v / grand for g, v in totals.items()}


def weekly_errors(preds: list[dict], default_t: float, operating_t: float) -> list[dict]:
    """Per-week row counts, FP/FN counts and error rates at both thresholds.

    Computed from predictions_test.csv rather than errors_test.csv: the latter
    holds only error rows, so it cannot supply the per-week denominator. Grouping
    every prediction by week gives both sides of the rate.
    """
    agg: dict[str, dict] = {}
    for r in preds:
        week = r.get("week") or "unknown"
        w = agg.setdefault(week, {"week": week, "rows": 0, "fp_default": 0,
                                  "fn_default": 0, "fp_operating": 0,
                                  "fn_operating": 0})
        label = int(r["label"])
        w["rows"] += 1
        p = float(r["p_malicious"])
        if p >= default_t:
            if label == 0:
                w["fp_default"] += 1
        elif label == 1:
            w["fn_default"] += 1
        if p >= operating_t:
            if label == 0:
                w["fp_operating"] += 1
        elif label == 1:
            w["fn_operating"] += 1
    for w in agg.values():
        n = w["rows"] or 1
        w["err_default"] = (w["fp_default"] + w["fn_default"]) / n
        w["err_operating"] = (w["fp_operating"] + w["fn_operating"]) / n
    return [agg[k] for k in sorted(agg)]
def build_context(manifest: dict, sample: dict | None = None) -> dict:
    """Assemble every value the template needs, straight from the artifacts."""
    import numpy as np

    test_metrics = json.loads((ROOT / "test_metrics.json").read_text(encoding="utf-8"))
    model_metrics = json.loads(
        (ROOT / "model.txt.metrics.json").read_text(encoding="utf-8"))

    preds = read_csv(REPORT_DIR / "predictions_test.csv")
    y = np.array([int(r["label"]) for r in preds])
    p = np.array([float(r["p_malicious"]) for r in preds])
    chal_rows = read_csv(REPORT_DIR / "predictions_challenge.csv")
    pc = np.array([float(r["p_malicious"]) for r in chal_rows])

    max_fpr = float(model_metrics.get("max_fpr_target", 0.005))
    op_thr = float(test_metrics["operating_threshold"])
    default_point = confusion(p, y, 0.5)
    operating_point = confusion(p, y, op_thr)

    splits = []
    for r in read_csv(REPORT_DIR / "data_quality.csv"):
        splits.append({
            "split": r["split"], "rows": int(r["rows"]),
            "unique_sha256": int(r["unique_sha256"]),
            "malicious_rows": int(r["malicious_rows"]),
            "benign_rows": int(r["benign_rows"]),
            "duplicate_rows": int(r["duplicate_rows"]),
            "label_conflicts": int(r["label_conflicts"]),
            "chunks": int(r["chunks"]),
        })
    by_split = {s["split"]: s for s in splits}
    # These two are written by evaluate_report.py's profile_dataset() step. A run
    # that predates that step leaves them absent, and a hard read here made the
    # whole PDF unbuildable, so treat them as optional and let the template's
    # dataset section fall back to the split totals from data_quality.csv.
    def optional_csv(name: str) -> list[dict]:
        path = REPORT_DIR / name
        if not path.is_file():
            log.warning("optional artifact missing, dataset profile omitted: %s", name)
            return []
        return read_csv(path)

    profile_summary_rows = optional_csv("dataset_summary.csv")
    profile_rows = optional_csv("dataset_profile.csv")
    profile_summary = profile_summary_rows[0] if profile_summary_rows else {}
    top_correlations = sorted(
        (r for r in profile_rows
         if r.get("label_correlation")
         and np.isfinite(float(r["label_correlation"]))),
        key=lambda r: abs(float(r["label_correlation"])), reverse=True)[:12]

    weekly = weekly_errors(preds, 0.5, op_thr)

    shares = gain_shares()
    implemented = {"histogram", "byteentropy"}
    offset = 0
    feature_groups = []
    for name, dim in FEATURE_GROUPS:
        feature_groups.append({
            "name": name, "dim": dim, "offset": offset,
            "gain_share": shares.get(name, 0.0),
            "analyzer_implemented": name in implemented,
            "description": GROUP_DESCRIPTIONS.get(name, ""),
        })
        offset += dim
    total_dim = offset
    analyzer_groups = [g for g in feature_groups if g["analyzer_implemented"]]
    analyzer_dim_share = sum(g["dim"] for g in analyzer_groups) / total_dim
    analyzer_gain_share = sum(g["gain_share"] for g in analyzer_groups)
    top_group = max(feature_groups, key=lambda g: g["gain_share"])

    # Top families among errors, for the triage table.
    fam: dict[str, int] = {}
    for r in read_csv(REPORT_DIR / "errors_test.csv"):
        if r.get("family"):
            fam[r["family"]] = fam.get(r["family"], 0) + 1
    total_errors = sum(fam.values()) or 1
    top_families = [{"family": k, "count": v, "share": v / total_errors}
                    for k, v in sorted(fam.items(), key=lambda kv: -kv[1])[:8]]

    caught = {t: float((pc >= t).mean()) for t in (0.5, 0.9, 0.99, op_thr)}
    challenge = {
        "rows": len(chal_rows),
        "median_p": float(np.median(pc)),
        "caught_default": caught[0.5],
        "caught_operating": caught[op_thr],
        "rows_at": [
            {"threshold": "0.5 (default)", "caught": caught[0.5],
             "note": "balanced catch and evasion coverage"},
            {"threshold": "0.9", "caught": caught[0.9],
             "note": "first real loss of evasion coverage"},
            {"threshold": "0.99", "caught": caught[0.99],
             "note": "roughly a third of evasions still seen"},
            {"threshold": f"{op_thr:.8f} (FPR-constrained)",
             "caught": caught[op_thr],
             "note": "tuned on benign false positives, not on evasions"},
        ],
    }

    charts = {}
    for section, items in CHART_SECTIONS.items():
        rendered = []
        for fname, title, caption in items:
            path = REPORT_DIR / fname
            if path.is_file():
                rendered.append({"title": title, "caption": caption,
                                 "file": fname, "data_uri": data_uri(path)})
            else:
                log.warning("chart missing, skipped: %s", fname)
        charts[section] = rendered

    train_rows = by_split.get("train", {}).get("rows", 0)
    return {
        "generator": GENERATOR,
        "template_name": TEMPLATE.name,
        "sample": sample,
        "has_sample": sample is not None,
        "generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "manifest": manifest,
        "verify_command": "sha256sum -c report.pdf.sha256   # Linux/macOS\n"
                          "certutil -hashfile report.pdf SHA256   # Windows",
        "manifest_command": f"python {GENERATOR} --verify-only",
        "corpus": {
            "name": "EMBER2024",
            "family": "EMBER (Evolution of Malware Benchmark) 2024 release",
            "scope": "Windows PE (Win64) binaries, plus a separate obfuscated "
                     "challenge set",
            "format": "weekly JSONL chunks, streamed directly from the release "
                      "archives without unpickling",
            "labels": "binary malware / benign, supplied by the corpus",
            "vectorizer": "thrember (the EMBER v3 feature extractor), producing "
                          "the same 2,568-dimension float32 vector at training "
                          "and at inference",
            "selection": "member-stride sampling across weekly chunks with "
                         "exactly balanced labels",
            "available_rows": 1040000,
            "license": "distributed for research use; see the EMBER2024 release",
        },
        "dataset": {
            "train_unique_sha256": by_split.get("train", {}).get("unique_sha256", 0),
        "train_rows": train_rows,
            "train_duplicate_rows": by_split.get("train", {}).get("duplicate_rows", 0),
            "test_duplicate_rows": by_split.get("test", {}).get("duplicate_rows", 0),
            "challenge_rows": len(chal_rows),
            "eval_split": "test",
            "eval_rows": int(len(y)),
        },
        "eval_rows": int(len(y)),
        "eval_positives": int(y.sum()),
        "eval_negatives": int((y == 0).sum()),
        "metrics": test_metrics,
        "max_fpr": max_fpr,
        "default_point": default_point,
        "operating_point": operating_point,
        "fp_reduction": 100.0 * (1 - operating_point["fp"] / default_point["fp"]),
        "fn_increase": 100.0 * (operating_point["fn"] / default_point["fn"] - 1),
        "overall_err_default": (default_point["fp"] + default_point["fn"]) / len(y),
        "overall_err_operating": (operating_point["fp"] + operating_point["fn"]) / len(y),
        "model": {
            "path": "ml/model.txt",
            "sha256": model_metrics.get("model_sha256") or sha256_file(ROOT / "model.txt"),
            "trees": model_metrics.get("trees", 0),
            "n_features": model_metrics.get("n_features", total_dim),
            "params": model_metrics.get("params", {}),
        },
        # Only the train_fit stage is a fit statistic. model_metrics["test"] is a
        # second, redundant copy of the held-out split and rendered alongside
        # eval_rows it printed two different "test" rows side by side; it is
        # dropped here so the table shows the training fit and the one held-out
        # figure the template adds from test_metrics.json.
        "fit_rows": [
            {"stage": "train (fit)", "n": v["n"], "roc_auc": v["roc_auc"],
             "average_precision": v["average_precision"]}
            for stage, v in model_metrics.items()
            if stage == "train_fit" and isinstance(v, dict)
            and {"n", "roc_auc", "average_precision"} <= set(v)
        ],
        "splits": splits,
        "dataset_profile": {
            "split": profile_summary.get("split", "test"),
            "total_rows": int(profile_summary.get("total_rows", 0)),
            "sampled_rows": int(profile_summary.get("sampled_rows", 0)),
            "feature_count": int(profile_summary.get("feature_count", 0)),
            "matrix_dtype": profile_summary.get("matrix_dtype", "unknown"),
            "label_dtype": profile_summary.get("label_dtype", "unknown"),
            "malicious_rows": int(profile_summary.get("malicious_rows", 0)),
            "benign_rows": int(profile_summary.get("benign_rows", 0)),
            "top_correlations": top_correlations,
        },
        "feature_groups": feature_groups,
        "analyzer_groups": analyzer_groups,
        "analyzer_dim_share": analyzer_dim_share,
        "analyzer_gain_share": analyzer_gain_share,
        "top_group_share": top_group["gain_share"],
        # Monotonic figure numbering. The template used hardcoded `loop.index + N`
        # offsets per section, which silently renumbered every later figure as
        # soon as one was added or removed (and left the section 12 dataset figure
        # with no number at all). figure_base[name] is how many charts precede
        # that section in document order, so the template can render
        # `figure_base[section] + loop.index` and stay correct. It is counted from
        # the *rendered* charts dict, not from CHART_SECTIONS: a chart whose PNG
        # is missing is skipped at render time, so counting it here would leave a
        # gap in the sequence.
        "chart_order": _CHART_ORDER,
        # Ranked, not hardcoded. The limitations prose used to name
        # "datadirectories, authenticode, exports" as the shortcut-heavy fields,
        # but `strings` actually carries more gain than `authenticode` (14.7% vs
        # 13.3%) and is at least as cheap to perturb, so the sentence had drifted
        # from feature_importance.csv -- in a caveat that exists precisely to warn
        # about shortcuts. Ranking the real top three here keeps prose and data in
        # step. Only groups the model actually gives gain to are listed.
        "shortcut_groups": [g["name"] for g in
                            sorted(feature_groups, key=lambda g: -g["gain_share"])[:3]],
        "weekly": weekly,
        "top_families": top_families,
        "challenge": challenge,
        "charts": charts,
        "limitations": [
            "Single model, single corpus. Every number here is EMBER2024 Win64. "
            "Nothing in this report establishes performance on other corpora, "
            "other file formats, or adversarially trained inputs.",
            f"The model is trained on {train_rows:,} of roughly 1.04M available "
            "Win64 rows. It is reduced relative to the full corpus, so these "
            "metrics are not the ceiling of the approach.",
            "Training and evaluation splits contain duplicate files by hash. The "
            "official test split is file-disjoint from training, which protects "
            "the headline metrics, but within-split duplicates mean distinct-file "
            "counts are lower than row counts.",
            f"Evasion is not solved: the challenge set is caught "
            f"{caught[0.5]:.1%} at the default threshold and "
            f"{caught[op_thr]:.1%} at the FPR-constrained threshold. A low score "
            "is weak evidence of benignity, never a clearance.",
            "The threshold is a deployment decision, not a property of the model. "
            "Accuracy, precision and recall are all threshold-bound; section 4 "
            "shows the full trade-off.",
            "Feature-group importance is gain-based and correlated features share "
            "credit. The group shares in section 2 rank groups for investment "
            "purposes; they are not independent causal attributions.",
            "The scoring API has no authentication and will parse any readable "
            "path. It is loopback-only and must not be exposed as-is.",
        ],
    }
def vector_audit(vec, groups: dict, shap, max_named: int = 120) -> dict:
    """Describe exactly what was passed to the model.

    Three views, because they answer different questions:
      per_group  - shape of each EMBER block: how many columns are non-zero
                   ("flagged"), and their magnitude
      named      - the non-zero hashed columns resolved to actual import,
                   library and export names, with their SHAP contribution
      structural - the human-readable PE facts hiding in the numeric blocks
    """
    import numpy as np
    from serve import layout, named_map

    dim = int(vec.shape[0])

    # ---- per group -------------------------------------------------------
    per_group = []
    for name, off, size in layout():
        block = vec[off:off + size]
        nz = int(np.count_nonzero(block))
        per_group.append({
            "name": name, "offset": off, "dim": size, "nonzero": nz,
            "flagged_pct": 100.0 * nz / size if size else 0.0,
            "min": float(block.min()), "max": float(block.max()),
            "sum": float(block.sum()), "mean": float(block.mean()),
        })

    # ---- named (hashed) columns that are actually set --------------------
    names = named_map(groups)
    named_rows = []
    for col, items in names.items():
        value = float(vec[col])
        if value == 0.0:
            continue                      # bucket empty in this file
        named_rows.append({
            "column": col, "value": value, "shap": float(shap[col]),
            "occupancy": len(items), "names": items,
        })
    named_rows.sort(key=lambda r: -abs(r["shap"]))

    # ---- structural facts ------------------------------------------------
    off_map = {name: o for name, o, _ in layout()}
    dim_map = {name: d for name, _, d in layout()}

    def block(name):
        o = off_map[name]
        return vec[o:o + dim_map[name]]

    structural = []
    gen = block("general")
    structural.append({"label": "file size", "value": f"{int(gen[0]):,} bytes"})
    structural.append({"label": "byte entropy", "value": f"{float(gen[1]):.4f}"})
    structural.append({"label": "is a PE file", "value": bool(gen[2])})
    structural.append({"label": "first four bytes",
                       "value": " ".join(f"{int(b):02x}" for b in gen[3:7])})

    dd = block("datadirectories")
    # Take the authoritative 16-entry list from serve rather than repeating a
    # shortened copy here: a 14-entry version silently mislabels every directory
    # from DEBUG onwards, because the sizes occupy even indices and a missing
    # name shifts the rest.
    from serve import DIR_NAMES
    present = [f"{DIR_NAMES[i // 2]}={int(dd[i]):,}b"
               for i in range(0, 32, 2) if dd[i] > 0]
    structural.append({"label": "data directories present",
                       "value": ", ".join(present) if present else "none"})
    structural.append({"label": "has relocations", "value": bool(dd[32])})
    structural.append({"label": "has dynamic relocations", "value": bool(dd[33])})

    imp = block("imports")
    structural.append({"label": "imported functions", "value": f"{int(imp[0]):,}"})
    structural.append({"label": "imported libraries", "value": f"{int(imp[1]):,}"})
    structural.append({"label": "exported functions (non-empty buckets)",
                       "value": f"{int(block('exports')[0]):,}"})
    structural.append({"label": "sections", "value": f"{int(block('section')[0]):,}"})
    structural.append({"label": "Rich header present",
                       "value": bool(block("richheader")[0])})
    auth = block("authenticode")
    structural.append({"label": "Authenticode signature",
                       "value": "present" if bool(np.any(auth != 0))
                                else "absent (unsigned)"})
    warn = block("pefilewarnings")
    structural.append({"label": "pefile warnings raised",
                       "value": f"{int(np.count_nonzero(warn)):,} of {warn.size}"})

    is_pe = bool(gen[2])
    return {
        "per_group": per_group,
        "named_rows": named_rows[:max_named],
        "named_total": len(named_rows),
        "structural": structural,
        "dim": dim,
        "nonzero": int(np.count_nonzero(vec)),
        "dtype": "float32",
        "is_pe": is_pe,
        # The model was trained exclusively on Win64 PE files. On anything else
        # it still emits a number, but that number is an extrapolation, so the
        # report must not present it as a finding.
        "applicable": is_pe,
        "caveat": ("" if is_pe else
                   "This file is not a PE image. The model was trained only on "
                   "Win64 PE binaries, so the score below is an extrapolation "
                   "into a region of the input space it never saw and must not "
                   "be read as a detection."),
        "order": "concatenated in EMBER v3 group order; the offset column in "
                 "the per-group table indexes this vector directly",
    }


def vector_csv(path: Path, vec, shap, groups: dict, top_k: int = 8) -> int:
    """Write the full vector beside the report so the input can be audited.

    2,568 rows is too much to read in a PDF but trivial in a spreadsheet; this
    is the machine-readable half of the input record.
    """
    from serve import group_of, label_of, named_map
    names = named_map(groups)
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["column_index", "group", "label", "named_items",
                    "value", "shap_log_odds", "bucket_occupancy", "in_top_k"])
        top = {int(i) for i in __import__("numpy").argsort(-__import__("numpy").abs(shap))[:top_k]}
        for i in range(int(vec.shape[0])):
            items = names.get(i, [])
            w.writerow([i, group_of(i), label_of(i) or "",
                        "|".join(items), f"{float(vec[i]):.6g}",
                        f"{float(shap[i]):.6f}", len(items), int(i in top)])
    return int(vec.shape[0])


def metrics_at(threshold: float) -> dict:
    """Metrics recomputed from every test prediction at an arbitrary threshold.

    The stored threshold_curve.csv is on a fixed grid, so the FPR-constrained
    operating point usually falls between two of its rows. Recomputing here keeps
    the comparison chart exact instead of reading off a nearest neighbour.
    """
    tp = fp = fn = tn = 0
    for r in read_csv(REPORT_DIR / "predictions_test.csv"):
        pred = float(r["p_malicious"]) >= threshold
        if pred and int(r["label"]) == 1:
            tp += 1
        elif pred:
            fp += 1
        elif int(r["label"]) == 1:
            fn += 1
        else:
            tn += 1
    total = tp + fp + fn + tn or 1
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    return {"threshold": threshold, "accuracy": (tp + tn) / total,
            "precision": prec, "recall": rec,
            "f1": 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0,
            "fpr": fp / (fp + tn) if (fp + tn) else 0.0}


def _style(ax, title: str, xlabel: str = "", ylabel: str = "") -> None:
    ax.set_title(title, fontsize=11, fontweight="bold", pad=10)
    if xlabel:
        ax.set_xlabel(xlabel, fontsize=9)
    if ylabel:
        ax.set_ylabel(ylabel, fontsize=9)
    ax.tick_params(labelsize=8)
    ax.grid(True, alpha=0.25, linewidth=0.6)
    ax.set_axisbelow(True)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)


def test_metrics_global() -> dict:
    return json.loads((ROOT / "test_metrics.json").read_text(encoding="utf-8"))


def weekly_errors_global(op_thr: float) -> list[dict]:
    """Per-week FP/FN and error rates, computed from every test prediction."""
    preds = read_csv(REPORT_DIR / "predictions_test.csv")
    agg: dict[str, dict] = {}
    for r in preds:
        week = r.get("week") or "unknown"
        w = agg.setdefault(week, {"week": week, "rows": 0, "fp_default": 0,
                                  "fn_default": 0, "fp_operating": 0,
                                  "fn_operating": 0})
        label = int(r["label"])
        p = float(r["p_malicious"])
        w["rows"] += 1
        if p >= 0.5:
            if label == 0:
                w["fp_default"] += 1
        elif label == 1:
            w["fn_default"] += 1
        if p >= op_thr:
            if label == 0:
                w["fp_operating"] += 1
        elif label == 1:
            w["fn_operating"] += 1
    out = []
    for key in sorted(agg):
        w = agg[key]
        n = w["rows"] or 1
        w["err_default"] = (w["fp_default"] + w["fn_default"]) / n
        w["err_operating"] = (w["fp_operating"] + w["fn_operating"]) / n
        out.append(w)
    return out


def extra_charts(out_dir: Path) -> list[dict]:
    """Analysis charts drawn for this report from the evaluation artifacts.

    The eight PNGs in ml/report/ come from evaluate_report.py. These are the
    views that were missing: metrics side by side at both thresholds, error
    rate per week as bars, and the whole threshold sweep including the evasion
    catch-rate on the same axes.
    """
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    made: list[dict] = []

    def emit(fig, name: str, title: str, caption: str) -> None:
        path = out_dir / name
        fig.tight_layout()
        fig.savefig(path, dpi=150, facecolor="white")
        plt.close(fig)
        made.append({"title": title, "caption": caption, "file": name,
                     "data_uri": data_uri(path)})

    curve = read_csv(REPORT_DIR / "threshold_curve.csv")
    op_thr = float(test_metrics_global()["operating_threshold"])
    n_test = int(test_metrics_global()["n_test"])
# --- metrics side by side at both operating points --------------------
    # Recomputed rather than read from the grid: the FPR-constrained threshold
    # generally sits between two stored rows.
    picked = [("default 0.5", metrics_at(0.5)),
              ("FPR-constrained", metrics_at(op_thr))]
    keys = ["accuracy", "precision", "recall", "f1", "fpr"]
    fig, ax = plt.subplots(figsize=(7.4, 3.6))
    xs = list(range(len(keys)))
    w = 0.36
    for k, (label, r) in enumerate(picked):
        vals = [r[m] for m in keys]
        bars = ax.bar([x + (k - 0.5) * w for x in xs], vals, w, label=label,
                      color=["#b3261e", "#1f3a68"][k],
                      edgecolor="white", linewidth=0.6)
        ax.bar_label(bars, fmt="%.3f", fontsize=6.5, padding=2)
    ax.set_xticks(xs)
    ax.set_xticklabels([m.capitalize() for m in keys])
    ax.set_ylim(0, 1.12)
    ax.legend(fontsize=8, frameon=False)
    _style(ax, "Metric comparison at both operating points", ylabel="rate")
    base, tight = picked[0][1], picked[1][1]
    fp_ratio = (base["fpr"] / tight["fpr"]) if tight["fpr"] else float("inf")
    recall_cost = 100.0 * (base["recall"] - tight["recall"])
    emit(fig, "gen_metric_comparison.png",
         "Metric comparison at both thresholds",
         f"Recomputed over all {n_test:,} test rows. Moving from t=0.5 to the "
         f"0.5%-FPR point (t={op_thr:.5f}) cuts the false-positive rate "
         f"{fp_ratio:.1f}x, from {base['fpr']:.4f} to {tight['fpr']:.4f}, and lifts "
         f"precision from {base['precision']:.4f} to {tight['precision']:.4f} - "
         f"and costs {recall_cost:.1f} points of recall. Neither column is 'the "
         f"right one'; the choice depends on the cost of a missed detection "
         f"versus a false alarm.")

    # --- error rate per week ----------------------------------------------
    weekly = weekly_errors_global(op_thr)
    if weekly:
        fig, ax = plt.subplots(figsize=(7.6, 3.2))
        xs = list(range(len(weekly)))
        w = 0.36
        for k, (key, label, color) in enumerate((
                ("err_default", "error rate @ 0.5", "#b3261e"),
                ("err_operating", "error rate @ FPR-constrained", "#1f3a68"))):
            vals = [row[key] for row in weekly]
            bars = ax.bar([x + (k - 0.5) * w for x in xs], vals, w, label=label,
                          color=color, edgecolor="white", linewidth=0.6)
            ax.bar_label(bars, fmt="%.4f", fontsize=6, padding=2)
        ax.set_xticks(xs)
        ax.set_xticklabels([row["week"] for row in weekly], rotation=30, ha="right")
        ax.legend(fontsize=8, frameon=False)
        _style(ax, "Error rate per weekly corpus chunk (test split)",
               ylabel="(FP + FN) / rows")
        emit(fig, "gen_error_rate_by_week.png",
             "Error rate by week",
             "Flat bars are the useful signal: if the model were tracking "
             "recency instead of content, the newest chunks would stand out. "
             "They do not.")

    # --- threshold sweep: two panels ---------------------------------------
    # Recall/precision/FPR share a 0-1 linear scale and are legible there; on a
    # log axis they all pin to 1.0 and the differences vanish. Evasion gets its
    # own axis because it is the curve that actually decides deployment value.
    ts = [float(r["threshold"]) for r in curve]
    keep = [(t, r) for t, r in zip(ts, curve) if t >= 0.5]
    kt = [t for t, _ in keep]
    fig, (ax, ax2) = plt.subplots(1, 2, figsize=(7.6, 3.4))
    for key, label, color in (
            ("recall", "recall", "#0b6b5b"),
            ("precision", "precision", "#1f3a68"),
            ("fpr", "false-positive rate", "#b3261e")):
        ax.plot(kt, [float(r[key]) for _, r in keep], lw=2, label=label,
                color=color)
    ax.axvline(op_thr, color="#5b6472", lw=0.8, ls=":")
    ax.set_ylim(0, 1.03)
    ax.legend(fontsize=7.5, frameon=False)
    _style(ax, "Test metrics above 0.5", xlabel="threshold", ylabel="rate")
    ax2.plot(kt, [float(r["evasion_caught"]) for _, r in keep], lw=2.4,
             color="#7a3fa0", label="evasion caught")
    ax2.axvline(0.5, color="#5b6472", lw=0.8, ls=":")
    ax2.axvline(op_thr, color="#5b6472", lw=0.8, ls=":")
    ax2.set_ylim(0, 1.03)
    ax2.legend(fontsize=7.5, frameon=False)
    _style(ax2, "Challenge-set evasion caught", xlabel="threshold",
           ylabel="fraction caught")
    emit(fig, "gen_threshold_sweep.png",
         "The threshold sweep, above the default",
         "Dotted lines mark the two operating points. Read the purple panel "
         "first: evasion catch-rate falls off a cliff well before recall does, "
         "which is why the FPR-constrained point looks attractive on benign "
         "false positives yet is the weaker choice against an adversarial "
         "corpus.")

    return made


def sample_charts(out_dir: Path, vec, shap, per_group: list[dict],
                  name: str) -> list[dict]:
    """Charts describing this executable's own input vector."""
    import matplotlib
    matplotlib.use("Agg")
    import numpy as np
    import matplotlib.pyplot as plt

    made: list[dict] = []

    def emit(fig, filename: str, title: str, caption: str) -> None:
        path = out_dir / filename
        fig.tight_layout()
        fig.savefig(path, dpi=150, facecolor="white")
        plt.close(fig)
        made.append({"title": title, "caption": caption, "file": filename,
                     "data_uri": data_uri(path)})

    # --- how much of each EMBER block is set -------------------------------
    fig, ax = plt.subplots(figsize=(7.6, 3.2))
    names = [g["name"] for g in per_group]
    pct = [g["flagged_pct"] for g in per_group]
    colors = ["#1f3a68" if g["analyzer_implemented"] else "#9aa7bd"
              for g in per_group]
    bars = ax.bar(names, pct, color=colors, edgecolor="white", linewidth=0.6)
    for bar, g in zip(bars, per_group):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 1.5,
                f"{g['nonzero']}/{g['dim']}", ha="center", fontsize=6.5)
    ax.set_ylim(0, 115)
    ax.tick_params(axis="x", rotation=35, labelsize=7.5)
    _style(ax, f"Input vector: how much of each group is set - {name}",
           ylabel="columns non-zero (%)")
    handles = [plt.Rectangle((0, 0), 1, 1, color="#1f3a68"),
               plt.Rectangle((0, 0), 1, 1, color="#9aa7bd")]
    ax.legend(handles, ["C++ exporter can produce", "not yet exported"],
              fontsize=7.5, frameon=False, loc="upper right")
    emit(fig, "gen_sample_group_flags.png",
         "Input vector coverage by group",
         "Each bar is one EMBER block: how many of its columns are non-zero for "
         "this file, out of that block's width. Dark bars are the only groups the "
         "C++ analyzer emits today, which is the 512-of-2,568 gap in section 2.")

    # --- where the model's attention went ----------------------------------
    fig, ax = plt.subplots(figsize=(7.6, 3.4))
    order = np.argsort(-np.abs(shap))[:20]
    vals = [float(shap[i]) for i in order][::-1]
    ypos = list(range(len(vals)))
    ax.barh(ypos, vals,
            color=["#b3261e" if v > 0 else "#0b6b5b" for v in vals],
            edgecolor="white", linewidth=0.5)
    ax.set_yticks(ypos)
    ax.set_yticklabels([f"column {int(i)}" for i in order][::-1], fontsize=7)
    ax.axvline(0, color="#5b6472", lw=0.8)
    _style(ax, f"Top 20 columns by contribution - {name}",
           xlabel="contribution to log-odds (right = towards malicious)")
    emit(fig, "gen_sample_shap_top.png",
         "Top 20 columns by contribution",
         "The columns that actually moved this file's score. Bars right of zero "
         "pushed it towards malicious, bars left pulled it towards benign; the "
         "table earlier in this section names what each one is.")

    return made


def prevalence_table(rows: list[dict], thresholds: list[float]) -> list[dict]:
    """Precision re-weighted to realistic malware prevalence.

    The test split is 50/50 by construction, which flatters precision badly: a
    deployed scanner sees far fewer malicious files than benign ones. For a base
    rate pi, precision becomes pi*TPR / (pi*TPR + (1-pi)*FPR), which is the
    number that reflects what an operator would actually experience.

    Works on deduplicated files so the duplicate rows in the corpus cannot
    weight the result.
    """
    import numpy as np
    seen: set[str] = set()
    uniq = []
    for r in rows:
        if r["sha256"] in seen:
            continue
        seen.add(r["sha256"])
        uniq.append(r)
    y = np.array([int(r["label"]) for r in uniq])
    s = np.array([float(r["p_malicious"]) for r in uniq])
    pos, neg = int((y == 1).sum()), int((y == 0).sum())
    out = []
    for t in thresholds:
        pred = s >= t
        tp = int((pred & (y == 1)).sum())
        fp = int((pred & (y == 0)).sum())
        fn = int(((~pred) & (y == 1)).sum())
        tn = int(((~pred) & (y == 0)).sum())
        tpr = tp / (tp + fn) if (tp + fn) else 0.0
        fpr = fp / (fp + tn) if (fp + tn) else 0.0
        row = {"threshold": t, "recall": tpr, "fpr": fpr,
               "tp": tp, "fp": fp, "fn": fn, "tn": tn,
               "precision_pct_50": tp / (tp + fp) if (tp + fp) else 0.0}
        # "{:g}".format(0.01) is "0.01", not "1", so the key would not match the
        # lookup below. Spell the percentages out instead of formatting them,
        # and avoid a dot in the key: Jinja reads "precision_0.1pct" as an
        # attribute access and fails to parse.
        for key, pi in (("50", 0.5), ("10", 0.1), ("1", 0.01),
                        ("01", 0.001)):
            row[f"precision_pct_{key}"] = (
                pi * tpr / (pi * tpr + (1 - pi) * fpr)
                if (pi * tpr + (1 - pi) * fpr) else 0.0)
        # How many benign files must be examined per true detection at 1%.
        pp = row["precision_pct_1"]
        row["benign_scanned_per_detection_1pct"] = (
            int(round((1 - pp) / pp)) if pp > 0 else None)
        out.append(row)
    return out


def calibration_table(rows: list[dict], bins: int = 15) -> list[dict]:
    """Observed malware rate per score bin, against the score itself.

    A calibrated model has observed == predicted in every bin. The gap is the
    honest answer to "is 0.55 a probability?", and it is why the report uses
    three bands instead of calling 0.55 malicious.
    """
    import numpy as np
    seen: set[str] = set()
    uniq = []
    for r in rows:
        if r["sha256"] in seen:
            continue
        seen.add(r["sha256"])
        uniq.append(r)
    y = np.array([int(r["label"]) for r in uniq], dtype=float)
    s = np.array([float(r["p_malicious"]) for r in uniq])
    edges = np.linspace(0.0, 1.0, bins + 1)
    idx = np.clip(np.digitize(s, edges) - 1, 0, bins - 1)
    out = []
    for b in range(bins):
        m = idx == b
        n = int(m.sum())
        if not n:
            continue
        mean_pred = float(s[m].mean())
        observed = float(y[m].mean())
        out.append({"bin_low": float(edges[b]), "bin_high": float(edges[b + 1]),
                    "n": n, "mean_predicted": mean_pred,
                    "observed_rate": observed,
                    "gap": observed - mean_pred})
    return out


def bootstrap_auc(rows: list[dict], n_boot: int = 200, seed: int = 20240610) -> dict:
    """Percentile CI for ROC-AUC over deduplicated files.

    Resamples files with replacement. Duplicate corpus rows would otherwise make
    the interval look tighter than one file's worth of evidence justifies.
    """
    import numpy as np
    from sklearn.metrics import roc_auc_score
    seen: set[str] = set()
    uniq = []
    for r in rows:
        if r["sha256"] in seen:
            continue
        seen.add(r["sha256"])
        uniq.append(r)
    y = np.array([int(r["label"]) for r in uniq])
    s = np.array([float(r["p_malicious"]) for r in uniq])
    point = float(roc_auc_score(y, s))
    rng = np.random.default_rng(seed)
    n = len(y)
    draws = []
    for _ in range(n_boot):
        i = rng.integers(0, n, n)
        if len(np.unique(y[i])) < 2:
            continue
        draws.append(roc_auc_score(y[i], s[i]))
    lo, hi = (float(np.percentile(draws, 2.5)), float(np.percentile(draws, 97.5))) \
        if draws else (float("nan"), float("nan"))
    return {"auc": point, "ci_low": lo, "ci_high": hi, "n_files": n,
            "n_boot": len(draws)}


def prevalence_chart(out_dir: Path) -> dict | None:
    """Precision against realistic base rates -- the chart that reframes the model.

    Precision on the 50/50 test split is not a number a deployed scanner will
    ever see, so this plots the same threshold at four base rates.
    """
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    rows = read_csv(REPORT_DIR / "predictions_test.csv")
    if not rows:
        return None
    op = float(test_metrics_global()["operating_threshold"])
    table = prevalence_table(rows, [0.5, op])
    base, tight = table[0], table[1]

    fig, ax = plt.subplots(figsize=(7.4, 3.4))
    rates = ["50", "10", "1", "01"]
    pretty = ["50%\n(test set)", "10%", "1%", "0.1%"]
    xs = list(range(len(rates)))
    w = 0.36
    for k, (label, r, color) in enumerate((
            ("threshold 0.5", base, "#b3261e"),
            ("FPR-constrained", tight, "#1f3a68"))):
        vals = [r[f"precision_pct_{x}"] for x in rates]
        bars = ax.bar([x + (k - 0.5) * w for x in xs], vals, w, label=label,
                      color=color, edgecolor="white", linewidth=0.6)
        ax.bar_label(bars, fmt="%.3f", fontsize=7, padding=2)
    ax.set_xticks(xs)
    ax.set_xticklabels(pretty)
    ax.set_ylim(0, 1.12)
    ax.legend(fontsize=8, frameon=False)
    _style(ax, "Precision falls as malware becomes rare",
           ylabel="precision (true-positive rate among detections)")
    path = out_dir / "gen_prevalence.png"
    fig.tight_layout()
    fig.savefig(path, dpi=150, facecolor="white")
    plt.close(fig)
    return {"title": "Precision at realistic prevalence",
            "caption": (
                f"The test split is 50/50 malware by construction, which is not "
                f"what a scanner meets. At a 1% base rate precision drops from "
                f"{base['precision_pct_50']:.3f} to {base['precision_pct_1']:.3f} at "
                f"t=0.5, and at 0.1% it reaches only "
                f"{base['precision_pct_01']:.3f}. Ranking quality is high; the "
                f"absolute numbers are only meaningful once the base rate is "
                f"stated."),
            "file": path.name, "data_uri": data_uri(path)}


def calibration_chart(out_dir: Path) -> dict | None:
    """Reliability diagram: is the score actually a probability?"""
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    rows = read_csv(REPORT_DIR / "predictions_test.csv")
    if not rows:
        return None
    table = calibration_table(rows, bins=20)
    if not table:
        return None
    fig, ax = plt.subplots(figsize=(5.6, 4.2))
    ax.plot([0, 1], [0, 1], ls="--", lw=1, color="#5b6472",
            label="perfectly calibrated")
    ax.plot([r["mean_predicted"] for r in table],
            [r["observed_rate"] for r in table], "o-", lw=2,
            color="#1f3a68", label="this model")
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.legend(fontsize=8, frameon=False, loc="upper left")
    _style(ax, "Reliability: predicted score vs observed rate",
           xlabel="mean predicted score in bin",
           ylabel="observed malware rate in bin")
    path = out_dir / "gen_calibration.png"
    fig.tight_layout()
    fig.savefig(path, dpi=150, facecolor="white")
    plt.close(fig)
    empty = [r for r in table if r["n"] < 50]
    return {"title": "Calibration: the score is not a probability",
            "caption": (
                "Points on the dashed line would mean the score can be read as a "
                "probability. The model is strongly bimodal, so very few files "
                "land in the middle: that is precisely why a score of 0.55 is "
                "reported as INCONCLUSIVE rather than MALICIOUS, and why "
                "calibration on a held-out slice is required before any "
                "probability claim is made."),
            "file": path.name, "data_uri": data_uri(path)}


def split_timeframes() -> dict:
    """Week ranges per split, and how much of the challenge set predates the test.

    An ML reviewer will ask whether the split is temporal before anything else.
    Answer it from the data: the train/test week ranges and their overlap are
    facts, not claims, and the challenge set turns out NOT to be time-disjoint
    even though the test split is.
    """
    def weeks(name: str) -> list[str]:
        path = REPORT_DIR / f"predictions_{name}.csv"
        if not path.is_file():
            return []
        return sorted({r["week"] for r in read_csv(path) if r.get("week")})

    out: dict = {}
    for name in ("train", "test", "challenge"):
        w = weeks(name)
        if not w:
            continue
        out[f"{name}_first_week"] = w[0]
        out[f"{name}_last_week"] = w[-1]
        out[f"{name}_weeks"] = len(w)
        out[f"{name}_rows"] = sum(1 for _ in read_csv(
            REPORT_DIR / f"predictions_{name}.csv"))
    tr, te, ch = weeks("train"), weeks("test"), weeks("challenge")
    out["train_test_week_overlap"] = len(set(tr) & set(te))
    out["challenge_in_window"] = (
        sum(1 for r in read_csv(REPORT_DIR / "predictions_challenge.csv")
            if r.get("week") in set(tr)) if ch and tr else 0)
    return out


def impactful_fields_csv(path: Path, vec, shap, gain_by_index: dict[int, float],
                         splits_by_index: dict[int, int],
                         names_by_index: dict[int, list[str]],
                         total_gain: float) -> int:
    """Write the model's input fields, ranked by how much they actually matter.

    Two independent notions of impact are reported side by side, because they
    answer different questions:

    * ``gain_pct`` is model-wide: how much this column contributed across the
      whole training set. It is what the model relies on in general.
    * ``shap_log_odds`` is this file: how much this column moved *this* score.

    A column can be globally important yet irrelevant for one sample, and the
    reverse; collapsing them into one number would hide exactly the interesting
    cases. Every column with non-zero gain or non-zero SHAP is listed, so the
    CSV is a complete audit of what was passed in, not just a top-N.
    """
    from serve import (OFFSETS, bucket_name, column_type, group_of,
                       header_value_label, label_of)
    dims = dict(FEATURE_GROUPS)

    # Columns the C++ analyzer can reproduce: only these two groups (512 dims).
    analyzer_cols = {i for name in ("histogram", "byteentropy")
                     for i in range(OFFSETS[name], OFFSETS[name] + dims[name])}

    rows = []
    for i in range(int(vec.shape[0])):
        g = float(gain_by_index.get(i, 0.0))
        s = float(shap[i])
        if g <= 0.0 and s == 0.0:
            continue
        value = float(vec[i])
        grp = group_of(i)
        k = i - OFFSETS.get(grp, 0)
        label = label_of(i) or header_value_label(k, value)
        rows.append({
            "column_index": i,
            "group": grp,
            "field_name": (label or bucket_name(i)
                           or f"unnamed ({grp} offset {k})"),
            "data_type": column_type(i),
            "value": repr(value),
            "shap_log_odds": f"{s:+.6f}",
            "direction": ("towards malicious" if s > 0
                          else "towards benign" if s < 0 else "no effect"),
            "gain_pct": f"{(100.0 * g / total_gain) if total_gain else 0.0:.4f}",
            "tree_splits": int(splits_by_index.get(i, 0)),
            "analyzer_exports": int(i in analyzer_cols),
            "hashed_names": "; ".join(names_by_index.get(i, [])),
        })
    rows.sort(key=lambda r: (-abs(float(r["shap_log_odds"])),
                             -float(r["gain_pct"])))
    for rank, r in enumerate(rows, 1):
        r["rank"] = rank

    fields = ["rank", "column_index", "group", "field_name", "data_type",
              "value", "shap_log_odds", "direction", "gain_pct",
              "tree_splits", "analyzer_exports", "hashed_names"]
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        for r in rows:
            w.writerow(r)
    return len(rows)


def load_gain() -> tuple[dict[int, float], dict[int, int], float]:
    """Per-column gain and split counts, from the retained importance CSV."""
    gain: dict[int, float] = {}
    splits: dict[int, int] = {}
    total = 0.0
    for r in read_csv(REPORT_DIR / "feature_importance.csv"):
        try:
            g = float(r.get("gain", 0.0))
            i = int(r["feature_index"])
        except (ValueError, KeyError):
            continue
        gain[i] = gain.get(i, 0.0) + g
        splits[i] = splits.get(i, 0) + int(r.get("splits", 0) or 0)
        total += g
    return gain, splits, total


def analyze_sample(path: Path, threshold: float, top_k: int = 6,
                   chart_dir: Path | None = None) -> dict:
    """Score one executable and explain it, so the report names its subject.

    Imports the ML stack lazily: without --sample the tool must still run on a
    machine that only has jinja2 and segno.
    """
    import lightgbm as lgb
    import numpy as np
    from thrember.features import PEFeatureExtractor
    from serve import explain, band_of  # Flask-free attribution helper

    raw = path.read_bytes()
    pe = PEFeatureExtractor()
    groups = pe.raw_features(raw)
    vec = np.asarray(pe.process_raw_features(groups), dtype=np.float32)
    booster = lgb.Booster(model_file=str(ROOT / "model.txt"))
    prob = float(booster.predict(vec[None, :])[0])
    ex = explain(booster, vec, groups, top_k)
    shap = np.asarray(
        booster.predict(vec[None, :], pred_contrib=True)[0][:-1], dtype=np.float64)

    audit = vector_audit(vec, groups, shap)
    for g in audit["per_group"]:
        g["analyzer_implemented"] = g["name"] in {"histogram", "byteentropy"}

    charts = []
    if chart_dir is not None:
        charts = sample_charts(chart_dir, vec, shap, audit["per_group"], path.name)

    return {
        "name": path.name,
        "path": str(path.resolve()),
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "malicious_probability": prob,
        "verdict": ("not_applicable" if not audit["applicable"] else band_of(prob)),
        "threshold": threshold,
        "model_sha256": sha256_file(ROOT / "model.txt"),
        "imports": len(groups.get("imports") or {}),
        "exported_functions": len(groups.get("exports") or []),
        "base_log_odds": ex["base_log_odds"],
        "prediction_log_odds": ex["prediction_log_odds"],
        "consistency_error": ex["consistency_error"],
        "top_features": ex["top_features"],
        "group_rollup": ex["group_rollup"][:5],
        "audit": audit,
        "charts": charts,
        "libraries": sorted({d.lower() for d in (groups.get("imports") or {})}),
    }


def artifact_paths(extra: list[Path] | None = None,
                   extra_outputs: list[Path] | None = None) -> list[Path]:
    """Every file the report is derived from, for the integrity manifest.

    Only the shared inputs sitting directly in ml/report/ are wildcards; each
    report's own outputs are added back individually. Scanning recursively would
    let one report's manifest absorb another report's generated files, and would
    make a report go STALE whenever an unrelated report was rebuilt.
    """
    paths = [ROOT / "test_metrics.json", ROOT / "model.txt.metrics.json",
             ROOT / "model.txt", TEMPLATE]
    # Top level only: a sample report's directory must never contribute here.
    paths.extend(sorted(p for p in REPORT_DIR.glob("*.png") if p.is_file()))
    paths.extend(sorted(p for p in REPORT_DIR.glob("*.csv") if p.is_file()))
    if extra:
        paths.extend(p for p in extra if p.is_file())
    if extra_outputs:
        paths.extend(p for p in extra_outputs if p.is_file())
    return paths


def make_qr(payload: str) -> tuple[str, str]:
    """Render payload as an inline PNG QR. Returns (data_uri, version)."""
    import segno
    qr = segno.make(payload, error="m", micro=False)
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "qr.png"
        qr.save(out, scale=6, border=2, dark="#14181f", light="#ffffff")
        return data_uri(out), str(qr.version)


def print_pdf(html: Path, pdf: Path, browser: Path, timeout: int = 180) -> None:
    """Print HTML to PDF with a headless Chromium-family browser."""
    cmd = [
        str(browser),
        "--headless=new",
        "--disable-gpu",
        "--no-sandbox",
        "--no-pdf-header-footer",
        "--run-all-compositor-stages-before-draw",
        "--virtual-time-budget=10000",
        f"--print-to-pdf={pdf.resolve()}",
        html.resolve().as_uri(),
    ]
    log.info("printing PDF with %s", browser.name)
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if not pdf.is_file() or pdf.stat().st_size == 0:
        raise RuntimeError(
            f"browser did not produce a PDF (exit {proc.returncode})\n"
            f"{proc.stderr[-800:]}")


def report_dir_for(pdf: Path) -> Path:
    """The directory owning a report and everything derived alongside it.

    Every per-report artifact is a sibling of the PDF, so one directory is a
    complete, self-contained report that can be moved, archived or deleted as a
    unit. The PDF's own stem is kept so an explicit --output with a different
    filename still gets unambiguously named companions.
    """
    return pdf.parent


def manifest_path_for(pdf: Path) -> Path:
    """The manifest that belongs to a given PDF.

    Each report directory holds exactly one, so this is always a sibling of the
    PDF and no name-collision special-casing is needed.
    """
    return report_dir_for(pdf) / MANIFEST_NAME


def vector_csv_path_for(pdf: Path) -> Path:
    """Where the full input-vector CSV for this report belongs."""
    return report_dir_for(pdf) / f"{pdf.stem}.vector.csv"


def entry_path(name: str) -> Path:
    """Resolve a manifest entry name.

    Entries are relative to ml/ when they live there; a --sample from outside
    ml/ is recorded as an absolute path, so try ml/ first and fall back to the
    name as-is.
    """
    candidate = ROOT / name
    if candidate.is_file():
        return candidate
    direct = Path(name)
    return direct if direct.is_file() else candidate


def verify(manifest: dict, pdf: Path, sample: Path | None = None) -> int:
    """Verify recorded digests against the files on disk.

    The comparison baseline is the digest recorded when the report was built,
    read back from manifest.json / the PDF sidecar. Recomputing the manifest and
    comparing it with itself would always succeed and detect nothing.
    """
    ok = True

    # 1. Manifest: compare the stored manifest with a fresh rebuild.
    stored = manifest_path_for(pdf)
    # The rebuild must cover exactly the inputs the report was built from,
    # including this report's own generated vector CSV. Omitting it would
    # shorten the entry list and make every artifact look changed.
    csv_path = vector_csv_path_for(pdf)
    fields_csv = pdf.parent / f"{pdf.stem}.fields.csv"
    fresh = build_manifest(
        artifact_paths([sample] if sample else None,
                       extra_outputs=[p for p in (csv_path, fields_csv)
                                      if p.is_file()]),
        ROOT)
    if stored.is_file():
        saved = json.loads(stored.read_text(encoding="utf-8"))
        recomputed = hashlib.sha256(json.dumps(
            saved, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
        log.info("stored manifest : %s", recomputed)
        log.info("rebuilt manifest: %s", fresh["sha256"])
        if recomputed == fresh["sha256"]:
            log.info("[+] manifest matches the %d artifacts on disk", len(fresh["entries"]))
        else:
            log.error("[-] manifest MISMATCH: an input artifact changed since "
                      "the report was built")
            # Compare by name, not by position: a differing artifact set would
            # otherwise report every later entry as changed.
            before = {e.get("name"): e.get("sha256")
                      for e in saved.get("entries", [])}
            after = {e.get("name"): e.get("sha256") for e in fresh["entries"]}
            for name in sorted(after.keys() - before.keys()):
                log.error("    added: %s", name)
            for name in sorted(before.keys() - after.keys()):
                log.error("    removed: %s", name)
            for name in sorted(before.keys() & after.keys()):
                if before[name] != after[name]:
                    log.error("    changed: %s", name)
            ok = False
    else:
        log.error("[-] no %s beside the PDF; cannot check the recorded digest. "
                  "Rebuild with --save-manifest.", MANIFEST_NAME)
        ok = False

    # 2. PDF bytes: compare the sidecar against the PDF on disk.
    if pdf.is_file():
        digest = sha256_file(pdf)
        sidecar = pdf.with_suffix(pdf.suffix + ".sha256")
        log.info("pdf sha256: %s", digest)
        if not sidecar.is_file():
            log.error("[-] no sidecar %s", sidecar.name)
            ok = False
        else:
            want = sidecar.read_text(encoding="utf-8").split()[0]
            if want == digest:
                log.info("[+] PDF sidecar matches the PDF on disk")
            else:
                log.error("[-] PDF MISMATCH: bytes are %s, sidecar says %s",
                          digest, want)
                ok = False
    else:
        log.error("[-] %s not found", pdf)
        ok = False

    # 3. Staleness: a rebuilt artifact newer than the PDF means the PDF no longer
    # reflects the current evidence, even though every recorded digest matches.
    if pdf.is_file():
        pdf_mtime = pdf.stat().st_mtime
        newer = sorted(
            (entry_path(e["name"]) for e in manifest["entries"]
             if entry_path(e["name"]).is_file()
             and entry_path(e["name"]).stat().st_mtime > pdf_mtime + 1)
        )
        if newer:
            log.error("[-] STALE: %d artifact(s) are newer than the PDF; the "
                      "report no longer reflects current evidence. Rebuild with "
                      "python %s", len(newer), GENERATOR)
            for p in newer[:6]:
                log.error("    newer: %s", p.relative_to(ROOT).as_posix())
            if len(newer) > 6:
                log.error("    ... and %d more", len(newer) - 6)
            ok = False
        else:
            log.info("[+] no artifact is newer than the PDF")

    if ok:
        log.info("[+] integrity verified")
    return 0 if ok else 1
def self_test(pdf: Path, manifest: dict, qr_payload: str,
              sample: dict | None = None) -> int:
    """Prove the output is usable, not merely present.

    Decodes the QR back out of the rendered HTML and opens the PDF to confirm it
    paginated and carries the figures. This is the difference between "a file was
    written" and "a person can scan the code and read the report".
    """
    ok = True
    try:
        from pyzbar.pyzbar import decode
        from PIL import Image
        import io as _io
    except ImportError:
        log.warning("--self-test needs pyzbar and pillow: "
                    "pip install pyzbar pillow")
        return 0

    html = pdf.with_suffix(".html")
    if not html.is_file():
        log.warning("[i] no intermediate HTML to scan; rebuild with --keep-html")
    else:
        import re as _re
        blob = html.read_text(encoding="utf-8")
        m = _re.search(r'<div class="integrity">\s*<img src="data:image/png;base64,([^"]+)"', blob)
        if not m:
            log.error("[-] no embedded QR image found in the HTML")
            ok = False
        else:
            found = decode(Image.open(_io.BytesIO(base64.b64decode(m.group(1)))))
            if not found:
                log.error("[-] QR did not decode: the code would not scan")
                ok = False
            else:
                text = found[0].data.decode("utf-8", "replace")
                if manifest["sha256"] in text:
                    log.info("[+] QR decodes and carries the manifest digest")
                else:
                    log.error("[-] QR decodes but does not carry the digest")
                    ok = False

    try:
        import pymupdf
    except ImportError:
        log.warning("[i] pymupdf not installed; skipping PDF checks "
                    "(pip install pymupdf)")
        return 0 if ok else 1

    doc = pymupdf.open(pdf)
    log.info("[+] PDF has %d pages, %.1f KB", doc.page_count, pdf.stat().st_size / 1024)
    imgs = sum(len(p.get_images(full=True)) for p in doc)
    text = "".join(p.get_text() for p in doc)
    if doc.page_count < 2:
        log.error("[-] only %d page(s): layout did not paginate", doc.page_count)
        ok = False
    if imgs < 8:
        log.error("[-] only %d image(s) embedded, expected the 8 charts", imgs)
        ok = False
    for probe in ("Integrity", "Headline results", "Limitations"):
        if probe not in text:
            log.error("[-] section %r missing from the PDF text", probe)
            ok = False
    # Integrity must be the final section: the QR and manifest belong at the
    # end, not competing with the headline on the cover.
    last = doc[-1].get_text() + doc[-2].get_text() if doc.page_count >= 2 else ""
    if "scan to verify" not in last:
        log.error("[-] integrity section is not at the end of the report")
        ok = False

    # The input-vector audit is the reason this report exists, so assert it
    # rather than trusting that the template still renders.
    if sample:
        audit_probes = ("What was actually passed into the model",
                        "Per-group shape of the input",
                        "Named columns flagged in this file",
                        "Which fields actually drove this score")
        for probe in audit_probes:
            if probe not in text:
                log.error("[-] input-vector section %r missing from the PDF", probe)
                ok = False
        # Both derived CSVs must exist AND be covered by the manifest, or the
        # report would be making claims about inputs it does not pin down.
        for key in ("vector_csv", "fields_csv"):
            csv_name = sample.get(key)
            if not csv_name or not (pdf.parent / csv_name).is_file():
                log.error("[-] %s %r was not written", key, csv_name)
                ok = False
            elif not any(csv_name in str(e.get("name", ""))
                          for e in manifest["entries"]):
                log.error("[-] %s is missing from the integrity manifest", csv_name)
                ok = False
            else:
                log.info("[+] %s covered by the manifest", csv_name)

    if ok:
        log.info("[+] self-test passed: QR scans, %d pages, %d figures, "
                 "all sections present", doc.page_count, imgs)
    doc.close()
    return 0 if ok else 1


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Render the EMBER2024 evaluation report to PDF.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    ap.add_argument("--output", "-o", type=Path, default=DEFAULT_OUT,
                    help="PDF path to write. Defaults to a per-report "
                         "directory: ml/report/default/report.pdf, or "
                         "ml/report/<sample>/report.pdf with --sample. The "
                         "sidecar, manifest, HTML and vector CSV are written "
                         "into the same directory.")
    ap.add_argument("--engine", choices=["edge", "chrome", "auto"], default="auto",
                    help="Which browser to print with.")
    ap.add_argument("--verify-only", action="store_true",
                    help="Recompute the manifest and verify the PDF sidecar.")
    ap.add_argument("--save-manifest", type=Path, default=None,
                    help="Write the canonical manifest JSON here. Defaults to "
                         "<output dir>/manifest.json; --no-save-manifest disables.")
    ap.add_argument("--no-save-manifest", action="store_true",
                    help="Do not write manifest.json (verification will then fail).")
    ap.add_argument("--browser", default=None,
                    help="Explicit browser executable. Overrides --engine and "
                         "the REPORT_PDF_BROWSER environment variable.")
    ap.add_argument("--html-only", action="store_true",
                    help="Render the HTML and stop, without printing a PDF. "
                         "Use this when no Chromium browser is available.")
    ap.add_argument("--keep-html", action="store_true",
                    help="Keep the intermediate HTML next to the PDF instead of "
                         "rendering it to a temporary directory.")
    ap.add_argument("--self-test", action="store_true",
                    help="After building, prove the QR decodes and the PDF "
                         "paginates (needs pymupdf and pyzbar).")
    ap.add_argument("--sample", type=Path, default=None,
                    help="Executable to score and describe in the report. Its "
                         "name, SHA-256, verdict and top reasons appear on the "
                         "cover, it enters the integrity manifest, and the PDF "
                         "is named after it unless --output is given.")
    ap.add_argument("--sample-threshold", type=float, default=0.5,
                    help="Threshold for the sample's verdict. Default: 0.5")
    args = ap.parse_args(argv)

    mllog.setup("report_pdf")
    log.debug("args: %s", args)

    for required in (TEMPLATE, ROOT / "test_metrics.json", REPORT_DIR):
        if not required.exists():
            log.error("missing %s; run evaluate_report.py first", required)
            return 1

    # Analyse the executable first: its digest has to be inside the manifest, and
    # its name decides the default output filename. Charts are drawn into a temp
    # directory because they are derived from the manifest-covered artifacts.
    chart_tmp = Path(tempfile.mkdtemp(prefix="report_charts_"))
    sample = None
    if args.sample:
        if not args.sample.is_file():
            log.error("--sample %s is not a file", args.sample)
            return 1
        if not 0.0 <= args.sample_threshold <= 1.0:
            log.error("--sample-threshold must be between 0 and 1")
            return 1
        log.info("[*] scoring sample %s", args.sample)
        sample = analyze_sample(args.sample, args.sample_threshold,
                                chart_dir=chart_tmp)
        log.info("[+] %s: p=%.6f %s (%d imports, %d exports)",
                 sample["name"], sample["malicious_probability"],
                 sample["verdict"], sample["imports"],
                 sample["exported_functions"])
        log.info("[+] input vector: %d of %d columns non-zero across %d groups; "
                 "%d named columns flagged", sample["audit"]["nonzero"],
                 sample["audit"]["dim"],
                 len(sample["audit"]["per_group"]),
                 sample["audit"]["named_total"])
        if args.output == DEFAULT_OUT:
            # Each report owns a directory named after its subject, so the PDF,
            # sidecar, manifest, HTML and vector CSV travel together.
            args.output = default_output_for(args.sample)

    # The full 2,568-column input lives next to the report so the numbers can be
    # audited in a spreadsheet rather than read off a page. It is derived, so it
    # is only rewritten on a real build: --verify-only must not mutate the very
    # artifacts it is checking, or every run would falsely report STALE.
    csv_path = (vector_csv_path_for(args.output) if sample else None)
    fields_csv = (args.output.parent / f"{args.output.stem}.fields.csv"
                  if sample else None)
    # Create the report's directory up front: the vector CSV and the manifest are
    # both written before the PDF, so waiting for the render step is too late.
    args.output.parent.mkdir(parents=True, exist_ok=True)
    if sample and not args.verify_only:
        import numpy as np
        import lightgbm as lgb
        from thrember.features import PEFeatureExtractor
        raw = args.sample.read_bytes()
        pe = PEFeatureExtractor()
        groups = pe.raw_features(raw)
        vec = np.asarray(pe.process_raw_features(groups), dtype=np.float32)
        booster = lgb.Booster(model_file=str(ROOT / "model.txt"))
        shap = booster.predict(vec[None, :], pred_contrib=True)[0][:-1]
        rows_written = vector_csv(csv_path, vec, shap, groups)
        sample["vector_csv"] = csv_path.name
        log.info("[+] wrote %s (%d columns, full input vector)",
                 csv_path, rows_written)

        # A second CSV: the fields that actually mattered, with resolved names
        # and data types, so "column 739" becomes a readable PE field.
        from serve import named_map
        gain, splits, total_gain = load_gain()
        fields_path = args.output.parent / f"{args.output.stem}.fields.csv"
        n_fields = impactful_fields_csv(fields_path, vec, shap, gain, splits,
                                         named_map(groups), total_gain)
        sample["fields_csv"] = fields_path.name
        sample["fields_total"] = n_fields
        # Top rows for the in-PDF table, read back so the page and the CSV can
        # never disagree about what the top fields are.
        sample["top_impact"] = [
            {"column_index": int(r["column_index"]),
             "field_name": r["field_name"],
             "data_type": r["data_type"],
             "value": r["value"],
             "shap": float(r["shap_log_odds"]),
             "gain_pct": float(r["gain_pct"]),
             "tree_splits": int(r["tree_splits"])}
            for r in list(csv.DictReader(fields_path.open(encoding="utf-8")))[:20]
        ]
        log.info("[+] wrote %s (%d impactful fields, named and typed)",
                 fields_path, n_fields)

    manifest = build_manifest(
        artifact_paths([args.sample] if sample else None,
                       extra_outputs=[p for p in (csv_path, fields_csv)
                                      if p is not None]), ROOT)
    # Verification must never rewrite the baseline it is checking against, so
    # --verify-only returns before this block.
    if args.verify_only:
        return verify(manifest, args.output, args.sample)

    manifest_baseline = None
    if not args.no_save_manifest:
        # One manifest per report directory: a shared file would be overwritten by
        # the next build, so verifying the previous PDF would then fail.
        target = args.save_manifest or manifest_path_for(args.output)
        canonical = {"generator": GENERATOR, "entries": manifest["entries"]}
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            json.dumps(canonical, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        log.info("[+] wrote %s (verification baseline)", target)
        manifest_baseline = target
    manifest_name = manifest_baseline.name if manifest_baseline else MANIFEST_NAME
    # Spell the report's location relative to ml/ so the printed command is
    # copy-pasteable from the repository root, whichever directory was chosen.
    try:
        shown_out = args.output.resolve().relative_to(ROOT).as_posix()
    except ValueError:
        shown_out = str(args.output)

    # The QR carries the manifest digest, not the PDF's: a file cannot contain
    # its own hash. The payload is human-readable so a scan is self-explanatory.
    qr_payload = (
        "SHA256 manifest -- verifies the EVIDENCE, not this PDF's own bytes\n"
        f"report  : {shown_out}\n"
        f"manifest: {shown_out.rsplit('/', 1)[0] + '/' + manifest_name}\n"
        f"sha256  : {manifest['sha256']}\n"
        f"base dir: ml/   (entry paths are relative to it)\n"
        f"verify  : python {GENERATOR} --verify-only -o {shown_out}\n"
        f"pdf hash: {args.output.name}.sha256 (sidecar, sha256sum -c)"
    )
    manifest = dict(manifest, name=manifest_name)
    qr_uri, qr_version = make_qr(qr_payload)
    log.info("QR encodes sha256(%s) = %s (QR version %s)",
             MANIFEST_NAME, manifest["sha256"], qr_version)

    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(str(TEMPLATE.parent)),
        autoescape=jinja2.select_autoescape(["html", "xml", "j2"]),
        trim_blocks=True, lstrip_blocks=True)
    extra = extra_charts(chart_tmp)
    context = build_context(manifest, sample)
    context["charts"]["extra"] = extra
    context.update(split_timeframes())
    # Honest-performance figures, computed from the retained predictions.
    pred_rows = read_csv(REPORT_DIR / "predictions_test.csv")
    if pred_rows:
        op_thr = float(test_metrics_global()["operating_threshold"])
        context["prevalence"] = prevalence_table(pred_rows, [0.5, op_thr])
        context["calibration"] = calibration_table(pred_rows)
        context["auc_ci"] = bootstrap_auc(pred_rows, n_boot=200)
        for maker in (prevalence_chart, calibration_chart):
            fig = maker(chart_tmp)
            if fig:
                context["charts"]["extra"].append(fig)
    # Figure numbers, assigned only once every chart exists -- see figure_bases().
    context["figure_base"] = figure_bases(context["charts"])
    # The reader is looking at this PDF, so the printed commands must name the
    # directory it actually lives in rather than a flat filename.
    context["verify_command"] = (
        f"cd {args.output.parent.as_posix()}\n"
        f"sha256sum -c {args.output.name}.sha256   # Linux/macOS\n"
        f"certutil -hashfile {args.output.name} SHA256   # Windows")
    context["manifest_command"] = (
        f"python {GENERATOR} --verify-only -o {shown_out}")
    context["qr"] = {"data_uri": qr_uri, "version": qr_version,
                     "payload": qr_payload}
    html_text = env.get_template(TEMPLATE.name).render(**context)

    if args.html_only or args.keep_html or args.self_test:
        # --self-test needs the HTML afterwards to decode the QR out of it.
        html_out = args.output.with_suffix(".html")
        html_out.write_text(html_text, encoding="utf-8")
        log.info("[+] rendered %s (%.1f KB HTML, %d figures)",
                 html_out, len(html_text) / 1024,
                 sum(len(v) for v in context["charts"].values()))
        if args.html_only:
            log.info("[+] --html-only: no PDF written")
            return 0
    else:
        # Render into a temp dir so an 800 KB intermediate is not left behind.
        html_out = Path(tempfile.mkdtemp(prefix="report_pdf_")) / "report.html"
        html_out.write_text(html_text, encoding="utf-8")
        log.info("[+] rendered HTML (%.1f KB, %d figures) in a temp dir",
                 len(html_text) / 1024,
                 sum(len(v) for v in context["charts"].values()))

    browser = find_browser("auto" if args.engine == "auto" else args.engine,
                           args.browser or os.environ.get("REPORT_PDF_BROWSER"))
    if browser is None:
        log.error("no Chromium-family browser found for headless printing.")
        log.error("  searched: %s", ", ".join(
            str(p) for p in browser_candidates()["edge"][:3]))
        log.error("  fix: install Edge or Chrome, or `playwright install chromium`,")
        log.error("       or set REPORT_PDF_BROWSER=/path/to/browser, or use "
                  "--browser <path>.")
        log.error("  to skip printing entirely: --html-only")
        if not args.keep_html:
            log.info("[+] HTML kept for you: %s", html_out)
        return 1

    print_pdf(html_out, args.output, browser)
    if not (args.keep_html or args.self_test):
        shutil.rmtree(html_out.parent, ignore_errors=True)

    digest = sha256_file(args.output)
    sidecar = args.output.with_suffix(args.output.suffix + ".sha256")
    sidecar.write_text(f"{digest}  {args.output.name}\n", encoding="utf-8")
    log.info("[+] wrote %s (%.1f KB) via %s", args.output,
             args.output.stat().st_size / 1024, browser.name)
    log.info("[+] wrote %s", sidecar)
    log.info("    pdf sha256          : %s", digest)
    log.info("    manifest sha256(%s): %s", MANIFEST_NAME, manifest["sha256"])

    if args.self_test:
        return self_test(args.output, manifest, qr_payload, sample)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001
        mllog.setup("report_pdf")  # idempotent: covers crashes before main()
        log.exception("report_pdf crashed: %s", exc)
        sys.exit(1)