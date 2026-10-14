#!/usr/bin/env python3
"""
Local ML scoring service for the EMBER2024 LightGBM model.

Runs inside its own virtualenv (ml/_t/venv) so the ML stack -- thrember and
its polars/matplotlib/sklearn tree, plus the signify==0.7.1 pin -- stays out of
the main interpreter. Mirrors the conventions of python/api/server.py (Flask,
jsonify, the same error envelope) so the analyzer's local-API client can talk to
either service the same way.

Endpoints
    GET  /health          liveness + which model is loaded
    GET  /model           model metadata and the EMBER feature-group layout
    POST /score           {"path": "<binary>"}       -> thrember vectorise + score
    POST /score/vector    {"vector": [2568 floats]} -> score a supplied vector
    POST /score/batch     {"vectors": [[...], ...]} -> score many vectors

Every score response carries the model sha256 and the threshold actually used,
so a verdict can always be traced back to the exact model and decision point.
That matters here: the threshold is not cosmetic -- evasion catch-rate on the
challenge set swings from ~87% to ~5% across the usable range.

Bind to loopback by default. `/score` takes a filesystem path, which makes it
an arbitrary-file parser for whoever can reach the port, so do not expose it
without a token and a `--root` sandbox (see "Running as a server" below).
A token only guards the off-loopback callers: requests that arrive over
loopback are exempt, which is what keeps the analyzer's own client working
when the admin terminal exposes the port on a routable address.

    ml/_t/venv/Scripts/python ml/serve.py --port 60010
    ml/_t/venv/Scripts/python ml/serve.py --root C:/samples --token "%ML_SERVE_TOKEN%"
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import logging
import math
import os
import sys
import time
from collections import defaultdict
from pathlib import Path

import numpy as np
import lightgbm as lgb
from flask import Flask, jsonify, request
from sklearn.feature_extraction import FeatureHasher

sys.path.insert(0, str(Path(__file__).parent))
import mllog  # noqa: E402
from vectorize import FEATURE_DIM, FEATURE_GROUPS  # noqa: E402

log = logging.getLogger("ml.serve")
# Resolved against this file, not the current directory: the old
# Path("ml/model.txt") only worked when launched from the repository root and
# failed with "Could not open ml/model.txt" from anywhere else, including the
# documented `python ml/serve.py` run from inside ml/.
HERE = Path(__file__).resolve().parent
DEFAULT_MODEL = HERE / "model.txt"
DEFAULT_THRESHOLD = 0.5
# Ceiling on files /score will read. The 256 MB MAX_CONTENT_LENGTH only bounds
# the request body, not a file named inside it. Real Win64 PEs are far smaller,
# so this only ever rejects pathological inputs.
MAX_FILE_BYTES = 256 * 1024 * 1024
# ml/README.md: the C++ exporter produces only these 2 of the 12 groups.
ANALYZER_GROUPS = {"histogram", "byteentropy"}
# Train/serve skew tolerance. The C++ extractor and thrember have been
# verified to agree to ~7e-09 on these groups (ml/README.md, "parity"); anything
# above 1e-6 means the two feature paths have drifted and the C++-exported
# values can no longer stand in for the vector that was actually scored.
SKEW_TOLERANCE = 1e-6


def layout() -> list[tuple[str, int, int]]:
    out, off = [], 0
    for name, dim in FEATURE_GROUPS:
        out.append((name, off, dim))
        off += dim
    return out


class Model:
    """Holds the booster so it loads once, not per request."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.booster = lgb.Booster(model_file=str(path))
        self.sha256 = hashlib.sha256(path.read_bytes()).hexdigest()
        self.trees = self.booster.num_trees()
        self.features = self.booster.num_feature()
        if self.features != FEATURE_DIM:
            raise SystemExit(f"model wants {self.features} features, "
                             f"vectorizer produces {FEATURE_DIM}")
        log.info("[*] loaded %s: %s trees, %s features, sha256=%s",
                 path, self.trees, self.features, self.sha256[:12])

    def score(self, vec: np.ndarray, threshold: float) -> float:
        return float(self.booster.predict(vec[None, :])[0])


# ---------------------------------------------------------------------------
# "What matched?" -- turning SHAP buckets back into names
#
# Most EMBER columns are FeatureHasher buckets, so raw SHAP only says "index
# 2405 pushed +1.4". thrember's own hasher configuration is reproduced here
# (verified against the installed thrember source) so a named import/export can
# be hashed to the exact column it occupies, and then reported when that column
# is among the top contributors.
#   imports group: [n_funcs, n_libs, 256 library buckets, 1024 function buckets]
#   exports group: [count, 128 export buckets]
# ---------------------------------------------------------------------------
OFFSETS = {name: off for name, off, _ in layout()}
IMPORT_OFF = OFFSETS["imports"]
EXPORT_OFF = OFFSETS["exports"]
LIB_BASE = IMPORT_OFF + 2          # after n_funcs and n_libs
FUNC_BASE = IMPORT_OFF + 258       # after the 256 library buckets
EXPORT_BASE = EXPORT_OFF + 1       # after the count slot


def _buckets(hasher: FeatureHasher, names: list[str], base: int):
    """Yield (global column, names hashing there) for one hashed group.

    Each name is hashed on its own on purpose: FeatureHasher turns one document
    into a single sparse row, so the matrix cannot say which of its columns
    belongs to which of its values. Hashing in bulk silently attributes every
    column to the first name.
    """
    by_col: dict[int, list[str]] = defaultdict(list)
    for name in names:
        by_col[int(hasher.transform([[name]]).tocoo().col[0])].append(name)
    for col, vals in by_col.items():
        yield base + col, vals


def named_map(raw_groups: dict | None) -> dict[int, list[str]]:
    """Map vector column -> named items, for the hashed EMBER groups."""
    out: dict[int, list[str]] = defaultdict(list)
    if not raw_groups:
        return out
    imports = raw_groups.get("imports") or {}
    if isinstance(imports, dict):
        libs = sorted({d.lower() for d in imports})
        funcs = [f"{d.lower()}:{f}" for d, el in imports.items() for f in el]
        for col, vals in _buckets(FeatureHasher(256, input_type="string",
                                               alternate_sign=False), libs, LIB_BASE):
            out[col].extend(f"library:{v}" for v in vals)
        for col, vals in _buckets(FeatureHasher(1024, input_type="string",
                                               alternate_sign=False), funcs, FUNC_BASE):
            out[col].extend(vals)
    exports = raw_groups.get("exports") or []
    if isinstance(exports, (list, tuple)):
        for col, vals in _buckets(FeatureHasher(128, input_type="string"),
                                  [str(e) for e in exports], EXPORT_BASE):
            out[col].extend(f"export:{v}" for v in vals)
    return out


def explain(booster: lgb.Booster, vec: np.ndarray, raw_groups: dict | None,
            top_k: int = 8) -> dict:
    """Per-feature TreeSHAP attribution plus named evidence and a group rollup.

    Takes a bare booster, not Model, so predict.py can explain offline results
    without importing Flask.
    """
    contrib = booster.predict(vec[None, :], pred_contrib=True)[0]
    shap = np.asarray(contrib[:-1], dtype=np.float64)
    base = float(contrib[-1])
    names = named_map(raw_groups)
    p = float(booster.predict(vec[None, :])[0])
    logit = math.log(p / (1.0 - p)) if 0.0 < p < 1.0 else float("inf")

    rows = []
    for idx in np.argsort(-np.abs(shap))[:top_k]:
        i = int(idx)
        all_names = names.get(i, [])
        named = sorted(all_names)[:3]
        label = label_of(i)
        if label is None:
            # Header categoricals encode an index; the value names it.
            label = header_value_label(i - OFFSETS.get(group_of(i), 0),
                                       vec[i])
        if label is None:
            # A hashed bucket has no inherent name, but the kind of thing it
            # hashes is knowable, which beats reporting a bare column index.
            label = bucket_name(i)
        rows.append({
            "feature_index": i,
            "group": group_of(i),
            "label": label,
            "named": named or None,
            # A bucket can hold several names (1,697 exports share 128 buckets),
            # and then the SHAP value is their combined contribution, not one
            # name's. Report the occupancy so the number is not misread.
            "bucket_occupancy": len(all_names),
            "shared_bucket": len(all_names) > 1,
            "evidence": (", ".join(named) if named else label) or None,
            "value": round(float(vec[i]), 6),
            "shap_log_odds": round(float(shap[i]), 6),
            "direction": "towards malicious" if shap[i] > 0 else "towards benign",
            "analyzer_implemented": group_of(i) in ANALYZER_GROUPS,
        })

    groups = []
    for name, off, dim in layout():
        g = float(shap[off:off + dim].sum())
        if abs(g) > 1e-9:
            groups.append({"group": name, "dim": dim,
                           "shap_log_odds": round(g, 6),
                           "analyzer_implemented": name in ANALYZER_GROUPS})
    groups.sort(key=lambda d: -abs(d["shap_log_odds"]))

    return {"space": "log-odds (binary objective)",
            "base_log_odds": round(base, 6),
            "prediction_log_odds": round(logit, 6),
            "sum_shap": round(float(shap.sum()), 6),
            "consistency_error": round(abs(base + float(shap.sum()) - logit), 6),
            "named_evidence_available": bool(names),
            "top_features": rows,
            "group_rollup": groups[:8]}


def is_pe_flag(vec: np.ndarray) -> bool:
    """Whether the vector came from a real PE image.

    Column 2 of the 'general' group is thrember's is_pe field, verified against
    the installed extractor. Used to refuse to call a non-PE score a verdict.
    """
    off = dict((n, o) for n, o, _ in layout())["general"]
    return bool(vec[off + 2])


def feature_skew(vec: np.ndarray, raw) -> dict | None:
    """Diff caller-supplied analyzer groups against the scored vector.

    `raw` is the request's `analyzer_groups` object ({group: [floats]}) - the
    EMBER dimensions the C++ extractor reproduces itself. Returns None when the
    caller sent no groups (the check is opt-in), otherwise a report with
    per-group max_abs_diff / first_diff_index and an overall `ok` verdict
    against SKEW_TOLERANCE. This is the automated train/serve skew check: it
    catches the exporter's histogram/byteentropy drifting away from thrember,
    which would silently misrepresent what the C++ report claims the model saw.
    """
    if raw is None:
        return None
    if not isinstance(raw, dict):
        return {"ok": False, "tolerance": SKEW_TOLERANCE,
                "error": "analyzer_groups must be an object of {group: [floats]}",}
    dims = {n: (o, d) for n, o, d in layout()}
    out_groups: dict[str, dict] = {}
    ok = True
    for name in sorted(ANALYZER_GROUPS):
        if name not in raw:
            continue
        if name not in dims:
            continue
        off, dim = dims[name]
        arr = raw[name]
        if not isinstance(arr, (list, tuple)) or len(arr) != dim:
            ok = False
            out_groups[name] = {
                "ok": False,
                "n": len(arr) if isinstance(arr, (list, tuple)) else -1,
                "max_abs_diff": float("inf"),
                "first_diff_index": -1,
                "error": f"expected {dim} values",
            }
            continue
        try:
            theirs = np.asarray(arr, dtype=np.float64)
        except (TypeError, ValueError) as exc:
            ok = False
            out_groups[name] = {"ok": False, "n": dim,
                                "max_abs_diff": float("inf"),
                                "first_diff_index": -1,
                                "error": f"non-numeric value: {exc}"}
            continue
        diff = np.abs(theirs - np.float64(vec[off:off + dim]))
        if not np.isfinite(diff).all():
            ok = False
            out_groups[name] = {"ok": False, "n": dim,
                                "max_abs_diff": float("inf"),
                                "first_diff_index": int(np.argmax(~np.isfinite(diff))),
                                "error": "NaN/Inf in caller group"}
            continue
        maxd = float(diff.max()) if diff.size else 0.0
        group_ok = bool(maxd <= SKEW_TOLERANCE)
        ok = ok and group_ok
        # first_diff_index is a GLOBAL vector column so it lines up with the
        # feature_index used by the SHAP rows; -1 when within tolerance.
        first = off + int(np.argmax(diff)) if not group_ok else -1
        out_groups[name] = {"max_abs_diff": maxd, "n": int(dim),
                            "first_diff_index": first, "ok": group_ok}
    if not out_groups:
        return {"ok": True, "tolerance": SKEW_TOLERANCE, "groups": {},
                "note": "no analyzer groups supplied"}
    return {"ok": bool(ok), "tolerance": SKEW_TOLERANCE, "groups": out_groups}


def group_of(index: int) -> str:
    """Group owning a column. layout() yields (name, offset, dim)."""
    for name, off, dim in layout():
        if off <= index < off + dim:
            return name
    return "unknown"


# Directory order verified against thrember.features.DataDirectories._name_order.
# Each entry contributes two columns: [size, virtual_address].
DIR_NAMES = ["EXPORT", "IMPORT", "RESOURCE", "EXCEPTION", "SECURITY", "BASERELOC",
             "DEBUG", "COPYRIGHT", "GLOBALPTR", "TLS", "LOAD_CONFIG",
             "BOUND_IMPORT", "IAT", "DELAY_IMPORT", "COM_DESCRIPTOR", "RESERVED"]

# Header layout, derived from thrember at import time rather than transcribed.
#
# The previous version hardcoded these lists and silently mislabelled columns:
# a hand-copied list omitted IMAGE_FILE_MACHINE_AMD64, shifting every name after
# it, so column 739 was reported as a subsystem when it is a machine type.
# Reading them out of the installed extractor makes that class of bug
# impossible, and keeps the labels correct across thrember versions.
def _thrember_list(attr: str, cls: str = "HeaderFileInfo") -> list[str]:
    """Pull a constant list off thrember's HeaderFileInfo via AST, safely.

    Importing the class and reading a private attribute would tie us to runtime
    state; parsing the literal keeps this to a static, side-effect-free read.
    Returns [] if anything is unexpected, and callers then emit no label.
    """
    import ast
    import inspect
    try:
        from thrember.features import HeaderFileInfo
        source = inspect.getsource(HeaderFileInfo.__init__)
        tree = ast.parse(textwrap.dedent(source))
    except Exception:  # noqa: BLE001 - never let naming break scoring
        return []
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for tgt in node.targets:
                if isinstance(tgt, ast.Attribute) and tgt.attr == attr:
                    try:
                        return list(ast.literal_eval(node.value))
                    except (ValueError, TypeError):
                        return []
    return []


import textwrap  # noqa: E402  (used only by _thrember_list)


def _header_layout() -> dict[str, list[str]]:
    """Ordered vocabulary for the 'header' categorical columns.

    Mirrors thrember's process_raw_features hstack. Note these categoricals are
    stored as a single integer INDEX, not one-hot: column 5 holds 32 to mean
    IMAGE_FILE_MACHINE_AMD64. So the machine/subsystem columns are two scalars
    whose names must be resolved by looking the value up in the vocabulary --
    label_of() cannot map them by position.
    """
    machines = _thrember_list("_machine_types")
    subsystems = _thrember_list("_subsystem_types")
    image_chars = _thrember_list("_image_characteristics")
    dll_chars = _thrember_list("_dll_characteristics")
    if not (machines and subsystems and image_chars):
        return {}
    scalars = ["COFF TimeDateStamp", "COFF NumberOfSections", "COFF NumberOfSymbols",
               "COFF SizeOfOptionalHeader", "COFF PointerToSymbolTable"]
    # thrember's hstack lists these in this exact order. BaseOfData is in
    # raw_obj but is NOT concatenated, so including it shifted every later name
    # by one and left the DOS fields unlabelled.
    optional = ["optional header: " + k for k in (
        "MajorImageVersion", "MinorImageVersion", "MajorLinkerVersion",
        "MinorLinkerVersion", "MajorOperatingSystemVersion",
        "MinorOperatingSystemVersion", "MajorSubsystemVersion",
        "MinorSubsystemVersion", "SizeOfCode", "SizeOfHeaders", "SizeOfImage",
        "SizeOfInitializedData", "SizeOfUninitializedData",
        "SizeOfStackReserve", "SizeOfStackCommit", "SizeOfHeapReserve",
        "SizeOfHeapCommit", "AddressOfEntryPoint", "BaseOfCode",
        "ImageBase", "SectionAlignment", "CheckSum", "NumberOfRvaAndSizes")]
    # thrember concatenates IMAGE_FILE characteristics first, then the DLL ones.
    # Reversing these silently relabels 16 flags and 11 others.
    names = (scalars
             + ["COFF machine (index into IMAGE_FILE_MACHINE_*)",
                "OPTIONAL subsystem (index into IMAGE_SUBSYSTEM_*)"]
             + optional
             + [f"IMAGE_FILE_CHARACTERISTICS: {c}" for c in image_chars]
             + [f"DLL characteristics: {c}" for c in dll_chars]
             + [f"DOS header: {m}" for m in _thrember_list("_dos_members")])
    return {"names": names, "machines": machines, "subsystems": subsystems}


HEADER_LAYOUT: dict[str, list[str]] = _header_layout()
HEADER_LABELS: list[str] = HEADER_LAYOUT.get("names", [])
HEADER_MACHINES: list[str] = HEADER_LAYOUT.get("machines", [])
HEADER_SUBSYSTEMS: list[str] = HEADER_LAYOUT.get("subsystems", [])


def header_value_label(index: int, value: float) -> str | None:
    """Resolve a header categorical's VALUE into its real constant name.

    These columns store an ordinal index, not a one-hot, so the name depends on
    the number in the vector and not only on the column. Column 5 holding 32
    means IMAGE_FILE_MACHINE_AMD64, which is how a report can say "this file is
    AMD64" rather than "column 739".
    """
    for offset, vocab in ((5, HEADER_MACHINES), (6, HEADER_SUBSYSTEMS)):
        if index == offset and vocab:
            i = int(round(float(value)))
            if 0 <= i < len(vocab):
                return vocab[i]
    return None


# Three operating bands, so a score near the boundary is not reported as a
# detection. The middle band is deliberately wide: this model's scores are a
# ranking signal, not calibrated probabilities (see the calibration section of
# the report), so 0.55 is not meaningfully "more than half likely to be malware".
BANDS = (("benign", 0.0, 0.3), ("inconclusive", 0.3, 0.8), ("malicious", 0.8, 1.0))


def band_of(p: float) -> str:
    """Classify a score into benign / inconclusive / malicious.

    Deliberately not a threshold test at 0.5: an uncalibrated score near 0.5
    carries very little information, and calling it MALICIOUS overstates what
    the model knows.
    """
    for name, lo, hi in BANDS:
        if lo <= p < hi or (name == "malicious" and p >= hi):
            return name
    return "benign"


def _pefile_warnings() -> list[str]:
    """thrember's ordered pefile warning strings, index -> message.

    Read the same way the extractor builds its own id map, so column k here
    names the same warning column k does there. Without this the
    `pefilewarnings` group is 88 anonymous booleans, and it carries ~1.6% of
    the model's gain.
    """
    try:
        import thrember
        path = (Path(thrember.__file__).parent / "pefile_warnings.txt")
        out: list[str] = []
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            out.append(line[3:] if line.startswith("...") else line)
        return out
    except Exception:  # noqa: BLE001 - naming must never break scoring
        return []


PEFILE_WARNINGS: list[str] = _pefile_warnings()


def bucket_name(index: int) -> str | None:
    """Descriptive name for a hashed column, when no concrete name is recoverable.

    A FeatureHasher bucket has no inherent meaning: it stands for "some string
    hashed into this slot". Calling these columns "unnamed" is honest but
    useless, so name the *kind* of thing the bucket represents, which is
    knowable from the group layout even when the specific value is not.
    """
    grp = group_of(index)
    k = index - OFFSETS.get(grp, 0)
    if grp == "imports":
        return ("hashed library-name bucket" if 2 <= k < 258
                else "hashed imported-function bucket")
    if grp == "exports":
        return "hashed export-name bucket"
    if grp == "richheader":
        return "hashed Rich-header tool-record bucket"
    if grp == "section":
        if 11 <= k < 61:
            return "hashed section size bucket"
        if 61 <= k < 111:
            return "hashed section virtual-size bucket"
        if 111 <= k < 161:
            return "hashed section entropy bucket"
        if 161 <= k < 211:
            return "hashed section characteristics bucket"
        if 211 <= k < 221:
            return "hashed entry-point section-name bucket"
    if grp == "strings" and k >= 100:
        return "hashed string-regex bucket"
    return None


def column_type(index: int) -> str:
    """Data type of a column, as a short human-readable string.

    Read off thrember's own process_raw_features for each group so the CSV can
    say what a number actually is. "float (fraction 0-1)" and
    "hashed bucket (signed integer)" are genuinely different things to a reader
    auditing a score, and guessing between them would be worse than saying
    nothing.
    """
    grp = group_of(index)
    k = index - OFFSETS.get(grp, 0)

    if grp == "general":
        return {0: "integer (bytes, file size)", 1: "float (entropy 0-8)",
                2: "boolean flag"}.get(k, "integer (byte value 0-255)")
    if grp in ("histogram", "byteentropy"):
        return "float (fraction 0-1)"
    if grp == "strings":
        if k == 0:
            return "integer (count of strings)"
        if k == 1:
            return "float (mean string length)"
        if k == 2:
            return "integer (count of printable chars)"
        if k < 100:
            return "float (fraction of printables)"
        if k == 99:
            return "float (entropy 0-8)"
        return "hashed bucket (integer match count)"
    if grp == "header":
        if k in (5, 6):
            return "categorical (enum index)"
        if k < 31:
            return "integer (COFF/OPTIONAL header field)"
        return "boolean flag"
    if grp == "section":
        if k < 5:
            return "integer (count)"
        if k < 11:
            return "float (max/min entropy or ratio)"
        if k < 221:
            return "hashed bucket (signed integer)"
        if k == 221:
            return "integer (bytes, overlay size)"
        if k == 222:
            return "float (fraction 0-1, overlay size ratio)"
        return "float (entropy 0-8, overlay)"
    if grp == "imports":
        if k < 2:
            return "integer (count)"
        return "hashed bucket (0/1 flag)"
    if grp == "exports":
        return "integer (count)" if k == 0 else "hashed bucket (signed integer)"
    if grp == "datadirectories":
        if k < 32:
            return "integer (bytes, size)" if k % 2 == 0 else "integer (RVA)"
        return "boolean flag"
    if grp == "richheader":
        return "integer (count of pairs)" if k == 0 else "hashed bucket (signed integer)"
    if grp == "authenticode":
        if k in (1, 2, 3, 4):
            return "boolean flag"
        if k in (6, 7):
            return "integer (unix timestamp)"
        return "integer (count)"
    if grp == "pefilewarnings":
        return "boolean flag" if k < 87 else "integer (count of warnings)"
    return "unknown"


def label_of(index: int) -> str | None:
    """Name the non-hashed columns, but only where the layout is verified.

    Verified against the installed thrember source for the datadirectories,
    general, imports and exports groups. Every other group returns None rather
    than a guessed label.
    """
    grp = group_of(index)
    k = index - OFFSETS.get(grp, 0)
    if grp == "datadirectories":
        if k < 32:
            return f"IMAGE_DIRECTORY_ENTRY_{DIR_NAMES[k // 2]} " + \
                   ("size" if k % 2 == 0 else "virtual address")
        return "has_relocs" if k == 32 else "has_dynamic_relocs"
    if grp == "general":
        return ["file size", "byte entropy", "is_pe", "byte[0] (MZ magic)",
                "byte[1]", "byte[2]", "byte[3]"][k]
    if grp == "imports":
        return {0: "number of imported functions",
                1: "number of imported libraries"}.get(k)
    if grp == "exports":
        return "number of non-empty export buckets" if k == 0 else None
    if grp == "header":
        return HEADER_LABELS[k] if 0 <= k < len(HEADER_LABELS) else None
    if grp == "histogram":
        return f"frequency of byte 0x{k:02X}"
    if grp == "byteentropy":
        return f"entropy of byte 0x{k:02X}"
    if grp == "strings":
        if k == 0:
            return "number of strings"
        if k == 1:
            return "average string length"
        if k == 2:
            return "number of printable characters"
        if k < 99:
            return f"printable-character distribution, bin {k - 3}"
        if k == 99:
            return "string entropy"
        return "hashed regex-match bucket"
    if grp == "section":
        return {0: "number of sections",
                1: "number of zero-size sections",
                2: "number of unnamed sections",
                3: "number of read+execute sections",
                4: "number of writable sections",
                5: "maximum section entropy",
                6: "minimum section entropy",
                7: "maximum section size ratio",
                8: "minimum section size ratio",
                9: "maximum section virtual size ratio",
                10: "minimum section virtual size ratio",
                221: "overlay size (bytes)",
                222: "overlay size ratio",
                223: "overlay entropy"}.get(k)
    if grp == "authenticode":
        return {0: "number of certificates", 1: "self signed",
                2: "empty program name", 3: "no countersigner",
                4: "parse error", 5: "maximum chain depth",
                6: "latest signing time", 7: "signing time difference"}.get(k)
    if grp == "richheader":
        return "number of Rich header pairs" if k == 0 else None
    if grp == "pefilewarnings":
        if k == 87:
            return "count of pefile warnings"
        if 0 <= k < len(PEFILE_WARNINGS):
            return f"pefile warning: {PEFILE_WARNINGS[k]}"
        return None
    return None


def _is_loopback(addr: str | None) -> bool:
    """True for a request that arrived over the loopback interface."""
    if not addr:
        return False
    try:
        return ipaddress.ip_address(addr.split("%", 1)[0]).is_loopback
    except ValueError:
        return False


def _authorised(token: str | None, remote_addr: str | None,
                header: str) -> bool:
    """Whether a caller may score.

    A set token protects the port from everyone who is not this machine: the
    analyzer's pipeline dials 127.0.0.1 without ever sending the header, so
    loopback callers are exempt while remote ones must match it exactly
    (constant-time, so the token cannot be recovered by timing).
    """
    if not token:
        return True
    if _is_loopback(remote_addr):
        return True
    import hmac
    return hmac.compare_digest(header, f"Bearer {token}")


def make_app(model_path: Path, root: Path | None = None,
             token: str | None = None) -> Flask:
    """Build the Flask app.

    root   if set, /score only accepts paths inside this directory. Without it
           the service will read and parse any file the process can open.
    token  if set, every request from off-loopback must carry
           `Authorization: Bearer <token>` (local callers are exempt).
           Without it the service is unauthenticated: anyone who can reach the
           port can score arbitrary files.
    """
    app = Flask(__name__)
    # Loopback by default. Refuse oversized bodies before parsing them, which is
    # what keeps /score/batch from being a memory-exhaustion vector.
    app.config["MAX_CONTENT_LENGTH"] = 256 * 1024 * 1024
    model = Model(model_path)
    app.config["MODEL"] = model
    root = root.resolve() if root else None

    # OpenAPI for this service, so the admin panel can document the scorer the
    # same way it documents everything else instead of parsing this file. The
    # UI assets are served from flasgger's own static directory, not a CDN.
    #
    # `headers` must be an empty list: flasgger iterates it in an after_request
    # hook on every response, and a missing key turns every route into a 500.
    # `/apidocs/` and `/apispec_1.json` are exempt from the token check below -
    # a spec that required a bearer token could not be read by the very tool
    # that documents it.
    try:
        from flasgger import Swagger

        Swagger(app, config={
            "title": "Malware ML scorer",
            "version": "1.0",
            "description": (
                "EMBER2024 LightGBM scorer. Scores a PE file, or a feature "
                "vector the caller has already extracted, and returns the "
                "malicious probability with an optional feature attribution."
            ),
            "headers": [],
            "specs": [{
                "endpoint": "apispec_1",
                "route": "/apispec_1.json",
                "rule_filter": lambda rule: True,
                "model_filter": lambda tag: True,
            }],
            "swagger_ui": True,
            "specs_route": "/apidocs/",
            "static_url_path": "/flasgger_static",
        })
    except ImportError:  # pragma: no cover - optional dependency
        log.info("[*] flasgger not installed; /apidocs unavailable")

    @app.before_request
    def _require_token():
        if request.method == "OPTIONS" or request.endpoint == "static":
            return None
        # The spec and the Swagger UI describe this service; requiring a bearer
        # token for them would make the documentation unreadable by the panel
        # that consumes it. They expose no sample data and no scoring ability.
        if request.path in ("/apidocs/", "/apispec_1.json") or \
                request.path.startswith("/flasgger_static/"):
            return None
        if _authorised(token, request.remote_addr,
                       request.headers.get("Authorization", "")):
            return None
        log.warning("[!] rejected unauthorised %s from %s",
                    request.path, request.remote_addr)
        return jsonify({"error": "unauthorised",
                        "detail": "send Authorization: Bearer <token>"}), 401

    @app.after_request
    def _harden(resp):
        # Scores derive from potentially sensitive files; keep them out of caches.
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        return resp

    def meta() -> dict:
        return {"model": str(model.path), "model_sha256": model.sha256,
                "trees": model.trees, "features": model.features,
                "default_threshold": DEFAULT_THRESHOLD,
                "max_file_bytes": MAX_FILE_BYTES,
                "sandbox_root": str(root) if root else None}

    def bad(msg: str, detail: str = "", code: int = 400):
        log.warning("[!] %s (%s)", msg, detail)
        return jsonify({"error": msg, "detail": detail}), code

    def parse_threshold():
        body = request.get_json(silent=True) or {}
        t = body.get("threshold", DEFAULT_THRESHOLD)
        if isinstance(t, bool) or not isinstance(t, (int, float)):
            return None, bad("threshold must be a number", repr(t))
        if not 0.0 <= float(t) <= 1.0:
            return None, bad("threshold out of range", repr(t))
        return float(t), None

    def parse_vector(raw):
        if not isinstance(raw, (list, tuple)):
            return None, f"expected a list of {FEATURE_DIM} numbers, got {type(raw).__name__}"
        if len(raw) != FEATURE_DIM:
            return None, f"expected {FEATURE_DIM} values, got {len(raw)}"
        try:
            vec = np.asarray(raw, dtype=np.float32)
        except (TypeError, ValueError) as exc:
            return None, f"non-numeric value: {exc}"
        finite = np.isfinite(vec)
        if not finite.all():
            return None, f"non-finite value at index {int(np.argmax(~finite))} (NaN/Inf)"
        return vec, ""

    def vector_from_file(path: Path):
        """One parse yields both the vector and the named groups behind it."""
        from thrember.features import PEFeatureExtractor
        try:
            raw = path.read_bytes()
        except OSError as exc:
            return None, None, f"cannot read file: {exc}"
        try:
            pe = PEFeatureExtractor()
            groups = pe.raw_features(raw)
            vec = np.asarray(pe.process_raw_features(groups), dtype=np.float32)
        except Exception as exc:  # noqa: BLE001 - thrember raises many types
            return None, None, f"thrember could not vectorise this file: {exc}"
        if vec.shape != (FEATURE_DIM,):
            return None, None, f"thrember returned {vec.shape}, expected ({FEATURE_DIM},)"
        return vec, groups, ""

    def explain_requested() -> tuple[bool, int]:
        body = request.get_json(silent=True) or {}
        top_k = body.get("top_k", 8)
        if isinstance(top_k, bool) or not isinstance(top_k, int) or not 1 <= top_k <= 50:
            top_k = 8
        return bool(body.get("explain", False)), top_k

    def verdict(p: float, threshold: float, is_pe: bool | None = None) -> dict:
        out = {"malicious_probability": round(p, 6),
               # Three-band classification, not a 0.5 test: the score is an
               # uncalibrated ranking signal, so 0.55 is not "malicious".
               "verdict": band_of(p),
               "band": band_of(p),
               # Retained so a caller that genuinely wants the old hard
               # threshold can still get it during the transition.
               "verdict_at_threshold": "malicious" if p >= threshold else "benign",
               "threshold": threshold}
        # The model only ever saw Win64 PE images. On anything else the number is
        # an extrapolation, so it is reported but explicitly not called a verdict.
        # Callers that switch on "verdict" must not treat this as a detection.
        if is_pe is not None:
            out["is_pe"] = is_pe
            if not is_pe:
                out["verdict"] = "not_applicable"
                out["verdict_note"] = (
                    "not a PE image; the model was trained only on Win64 PE "
                    "binaries, so this score is an extrapolation and not a "
                    "detection")
        out.update(meta())
        return out

    def resolve_scannable(raw_path: str):
        """Resolve a caller-supplied path, enforcing the --root sandbox.

        Returns (path, error_response). Without --root the service will happily
        open any path, which is why it must not be exposed off-loopback.
        """
        p = Path(raw_path)
        if not p.is_absolute():
            p = (root / p) if root else p.resolve()
        try:
            resolved = p.resolve()
        except OSError as exc:
            return None, bad("cannot resolve path", str(exc))
        if root is not None:
            # Compare resolved paths so ../ traversal cannot escape the root.
            # is_relative_to needs 3.9+; do it by hand for clarity.
            try:
                resolved.relative_to(root)
            except ValueError:
                log.warning("[!] refused path outside --root: %s", resolved)
                return None, bad("path outside allowed root", str(resolved), 403)
        if not resolved.is_file():
            return None, bad("not a file", str(resolved), 404)
        # The 256 MB request-body cap does nothing here: /score reads the file
        # from disk, so an arbitrarily large file would be read into memory and
        # handed to pefile regardless of how small the request was.
        size = resolved.stat().st_size
        if size > MAX_FILE_BYTES:
            log.warning("[!] refused oversized file: %s (%d bytes)",
                        resolved, size)
            return None, bad(
                "file too large",
                f"{size:,} bytes exceeds the {MAX_FILE_BYTES:,}-byte limit",
                413)
        return resolved, None

    @app.get("/health")
    def health():
        """Liveness, plus the model's identity and metrics
        ---
        tags: [ml]
        responses:
          200:
            description: Service is up, with model metadata
        """
        return jsonify({"status": "ok", **meta()}), 200

    @app.get("/model")
    def model_info():
        """Model card: feature layout, training metrics and version
        ---
        tags: [ml]
        responses:
          200:
            description: Feature layout plus metrics
        description: >
          Offsets index the EMBER v3 thrember vector. Use this to build a
          vector yourself and call POST /score/vector instead of shipping the
          file.
        """
        return jsonify({**meta(),
                        "feature_layout": [{"name": n, "offset": o, "dim": d}
                                           for n, o, d in layout()],
                        "note": "offsets index the EMBER v3 thrember vector"}), 200

    @app.post("/score")
    def score():
        """Score a PE file and return its malicious probability
        ---
        tags: [ml]
        parameters:
          - name: body
            in: body
            required: true
            schema:
              type: object
              properties:
                path:
                  type: string
                  description: Path to the file to score, on this host
                threshold:
                  type: number
                  description: Decision threshold, 0-1
                explain:
                  type: integer
                  description: Return the top N contributing features
                analyzer_groups:
                  type: object
                  description: Optional train/serve skew check by group
            description: JSON body naming the file on disk
        responses:
          200:
            description: Verdict, probability and optional attribution
          401:
            description: Token required
          422:
            description: File could not be vectorised
        description: >
          The path is resolved on THIS host and must be inside the configured
          root when one is set; a client-supplied path is never forwarded
          anywhere else.
        """
        body = request.get_json(silent=True) or {}
        threshold, err = parse_threshold()
        if err:
            return err
        path = body.get("path")
        if not isinstance(path, str) or not path:
            return bad("path is required", 'POST {"path": "<binary>"}')
        p, err = resolve_scannable(path)
        if err:
            return err
        t0 = time.time()
        want, top_k = explain_requested()
        vec, groups, why = vector_from_file(p)
        if vec is None:
            return bad("cannot vectorise", why, 422)
        out = verdict(model.score(vec, threshold), threshold,
                    is_pe=is_pe_flag(vec))
        out.update({"file": p.name, "feature_source": "thrember",
                    "bytes": p.stat().st_size,
                    "seconds": round(time.time() - t0, 3)})
        # Train/serve skew check: opt-in via analyzer_groups in the request.
        skew = feature_skew(vec, body.get("analyzer_groups"))
        if skew is not None:
            out["feature_skew"] = skew
        if want:
            out["explanation"] = explain(model.booster, vec, groups, top_k)
        return jsonify(out), 200

    @app.post("/score/vector")
    def score_vector():
        """Score an already-extracted feature vector
        ---
        tags: [ml]
        parameters:
          - name: body
            in: body
            required: true
            schema:
              type: object
              properties:
                vector:
                  type: array
                  description: Feature vector, one float per EMBER v3 column
                threshold:
                  type: number
                explain:
                  type: integer
            description: JSON body carrying the vector
        responses:
          200:
            description: Verdict with vector_sha256 for reproducibility
          400:
            description: vector missing or malformed
        description: >
          Skips file parsing entirely. The response carries the SHA-256 of the
          exact bytes scored, so a verdict can be tied to the vector that
          produced it.
        """
        body = request.get_json(silent=True) or {}
        threshold, err = parse_threshold()
        if err:
            return err
        if "vector" not in body:
            return bad("vector is required",
                       f'POST {{"vector": [{FEATURE_DIM} floats]}}')
        vec, why = parse_vector(body["vector"])
        if vec is None:
            return bad("invalid vector", why)
        out = verdict(model.score(vec, threshold), threshold,
                        is_pe=is_pe_flag(vec))
        out["feature_source"] = "caller-vector"
        out["vector_sha256"] = hashlib.sha256(
            np.ascontiguousarray(vec, dtype=np.float32).tobytes()).hexdigest()
        want, top_k = explain_requested()
        if want:
            # No named groups here: the caller sent a vector, not a file, so the
            # attribution is by column and group only.
            out["explanation"] = explain(model.booster, vec, None, top_k)
        return jsonify(out), 200

    @app.post("/score/batch")
    def score_batch():
        """Score many feature vectors in one call
        ---
        tags: [ml]
        parameters:
          - name: body
            in: body
            required: true
            schema:
              type: object
              properties:
                vectors:
                  type: array
                  description: Array of feature vectors, max 10000
                threshold:
                  type: number
            description: JSON body carrying the vectors
        responses:
          200:
            description: One verdict per vector, in request order
          400:
            description: vectors empty, malformed, or over the limit
        description: >
          Capped at 10000 vectors. Results correspond positionally to the
          input, so a caller can keep its own labels aligned.
        """
        body = request.get_json(silent=True) or {}
        threshold, err = parse_threshold()
        if err:
            return err
        raw = body.get("vectors")
        if not isinstance(raw, (list, tuple)) or not raw:
            return bad("vectors must be a non-empty list")
        if len(raw) > 10_000:
            return bad("batch too large", f"{len(raw)} > 10000")
        results = []
        for i, item in enumerate(raw):
            vec, why = parse_vector(item)
            if vec is None:
                results.append({"index": i, "error": why})
                continue
            results.append({"index": i,
                          **verdict(model.score(vec, threshold), threshold,
                                    is_pe=is_pe_flag(vec))})
        return jsonify({"count": len(results), "results": results, **meta()}), 200

    @app.errorhandler(404)
    def not_found(_e):
        return jsonify({"error": "no such endpoint",
                        "detail": "GET /health | GET /model | POST /score | "
                                  "POST /score/vector | POST /score/batch"}), 404

    return app


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Local EMBER2024 ML scoring service.")
    ap.add_argument("--model", type=Path, default=DEFAULT_MODEL)
    ap.add_argument("--host", default="127.0.0.1",
                    help="Bind address; loopback by default because /score parses files")
    ap.add_argument("--port", type=int, default=60010)
    ap.add_argument("--root", type=Path, default=None,
                    help="Restrict /score to files under this directory. "
                         "Strongly recommended for any non-loopback bind.")
    ap.add_argument("--token", default=os.environ.get("ML_SERVE_TOKEN"),
                    help="Require 'Authorization: Bearer <token>' from "
                         "off-loopback callers (loopback is always exempt). "
                         "Defaults to $ML_SERVE_TOKEN. Unset means NO "
                         "authentication.")
    ap.add_argument("--debug", action="store_true",
                    help="Flask debug mode: NEVER enable on a reachable port, "
                         "the Werkzeug debugger allows code execution.")
    args = ap.parse_args(argv)

    mllog.setup("serve")

    loopback = args.host in ("127.0.0.1", "::1", "localhost")
    if not loopback:
        log.error("[!] binding %s, which is NOT loopback", args.host)
        if not args.token:
            log.error("[!] refusing to start: no --token and no $ML_SERVE_TOKEN, so "
                      "anyone who can reach this port can read and parse arbitrary "
                      "files. Set a token, or bind 127.0.0.1 and tunnel.")
            return 2
        if args.root is None:
            log.warning("[!] no --root set: /score will accept any readable path "
                        "on this host. Pass --root to confine it.")
        log.warning("[!] Flask's development server is in use. It is single-threaded "
                    "per request and has no TLS; put it behind a reverse proxy "
                    "(nginx/Caddy) for anything beyond a trusted network.")

    if args.debug and not loopback:
        log.error("[!] refusing --debug on a non-loopback bind: the Werkzeug "
                  "debugger permits remote code execution")
        return 2

    log.info("[*] serving %s on http://%s:%s", args.model, args.host, args.port)
    if args.root:
        log.info("[*] /score restricted to %s", args.root.resolve())
    log.info("[*] authentication: %s",
             "bearer token" if args.token else "NONE (loopback only)")
    make_app(args.model, root=args.root, token=args.token).run(
        host=args.host, port=args.port, debug=args.debug, threaded=True)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
    except SystemExit:
        raise
    except Exception:  # noqa: BLE001
        logging.getLogger("ml.serve").exception("serve crashed")
        sys.exit(1)