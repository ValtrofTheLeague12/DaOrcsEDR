#!python3
"""MITRE D3FEND countermeasures for the ATT&CK tactics capa recovered.

The dashboard asks one question per detected technique: *which D3FEND
defensive technique defeats it, and under which defensive tactic?*  D3FEND
ships no pip package and its repo cannot even be checked out on Windows
(several paths contain ':'), so the data comes from the d3fend.mitre.org API:

    https://d3fend.mitre.org/api/offensive-technique/attack/T1059.json

which answers with a SPARQL-shaped result set naming every defensive
technique related to that offensive technique, its D3FEND tactic
(Detect / Isolate / Harden / ...) and the artifact relation that links them
(analyzes / filters / monitors / ...).

Answers are cached in cti-cache/knowledge/d3fend.json next to the ATT&CK
bundle, so an offline run renders whatever was fetched before and only the
missing techniques are a gap - never an error.

stdlib only, same rule as stix_graph.py: this must import anywhere the
dashboard does, and a failure here disables only the D3FEND tab.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

# The fetched knowledge cache is regenerable machine state, so it lives under
# the AppData root rather than in cti-cache/ inside the working tree. The
# resolver is imported, not reimplemented, so the analyzer, the panel and this
# script cannot drift apart on where that is.
from panel.core.config import cache_dir as appdata_cache  # noqa: E402

# Tactic shortnames and normalise_tactic() come from the same table the STIX
# section uses, so the two views of one capa run always agree on names.
try:
    import stix_graph
except Exception:  # pragma: no cover - stix_graph is stdlib-only too
    stix_graph = None

API_URL = "https://d3fend.mitre.org/api/offensive-technique/attack/{tid}.json"
CACHE_PATH = appdata_cache() / "knowledge" / "d3fend.json"
TECHNIQUE_RE = re.compile(r"T\d{4}(?:\.\d{3})?")
FETCH_TIMEOUT = 8.0
FETCH_WORKERS = 8


# ---------------------------------------------------------------------------
# cache
# ---------------------------------------------------------------------------

def load_cache(path: Path = CACHE_PATH) -> dict:
    """{technique_id: [countermeasure row, ...]} - empty dict when absent."""
    try:
        with Path(path).open("r", encoding="utf-8") as fh:
            doc = json.load(fh)
    except Exception:
        return {}
    techs = doc.get("techniques")
    return techs if isinstance(techs, dict) else {}


def save_cache(techniques: dict, path: Path = CACHE_PATH) -> None:
    """Atomic replace: a dashboard run killed mid-write must not corrupt it."""
    p = Path(path)
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_name(p.name + ".tmp")
        tmp.write_text(
            json.dumps({"cached_at": datetime.now(timezone.utc)
                        .isoformat(timespec="seconds"),
                        "techniques": techniques},
                       ensure_ascii=False, indent=1, sort_keys=True),
            encoding="utf-8")
        tmp.replace(p)
    except Exception as exc:
        print(f"warn: d3fend: cannot write {p}: {exc}", file=sys.stderr)


# ---------------------------------------------------------------------------
# fetch
# ---------------------------------------------------------------------------

def _v(binding: dict, key: str) -> str:
    """SPARQL binding cell -> literal value ('' when the var is unbound)."""
    cell = binding.get(key)
    return cell.get("value", "") if isinstance(cell, dict) else ""


def _parse(doc: dict, tid: str) -> list[dict]:
    """API document -> deduped countermeasure rows for ``tid``.

    The page for a technique also lists rows for its parent / sub-techniques;
    only the rows that really belong to ``tid`` are kept so a capa match on
    T1059.001 does not silently report T1140's mappings.
    """
    try:
        bindings = doc["off_to_def"]["results"]["bindings"]
    except Exception:
        return []
    rows: list[dict] = []
    seen: set[tuple] = set()
    for b in bindings:
        if not isinstance(b, dict):
            continue
        off = _v(b, "off_tech_id")
        if off and off != tid:
            continue
        row = {
            "id": _v(b, "def_tech_id"),
            "name": _v(b, "def_tech_label"),
            "cat": _v(b, "def_tactic_label"),
            "rel": _v(b, "def_artifact_rel_label"),
            "art": _v(b, "def_artifact_label"),
        }
        if not row["id"]:
            continue
        key = (row["id"], row["rel"], row["art"])
        if key in seen:
            continue
        seen.add(key)
        rows.append(row)
    rows.sort(key=lambda r: (r["id"], r["art"], r["rel"]))
    return rows


def _fetch(tid: str, timeout: float):
    """Countermeasure rows for ``tid``.

    None = could not reach the API (keep whatever the cache holds);
    []    = the API answered "this technique has no D3FEND mapping" - a real
            answer, and one worth caching so it is never re-requested.
    """
    req = urllib.request.Request(
        API_URL.format(tid=tid),
        headers={"User-Agent": "static-analyzer/1.0 (D3FEND cache)"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            doc = json.loads(resp.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as exc:
        return [] if exc.code == 404 else None
    except Exception:
        return None
    return _parse(doc, tid)


def _fetch_with_fallback(tid: str, timeout: float):
    """A sub-technique page with no rows falls back to its parent, flagged.

    D3FEND links most mappings at parent granularity, so T1555.004 would come
    back empty while T1555 is rich.  The rows are then attributed with
    ``via`` so the UI can say the mapping was inherited.
    """
    rows = _fetch(tid, timeout)
    if rows:
        return rows
    if "." in tid:
        parent = tid.split(".", 1)[0]
        prows = _fetch(parent, timeout)
        if prows:
            return [dict(r, via=parent) for r in prows]
    return rows


def resolve(tids, *, offline: bool = False, refresh: bool = False,
            timeout: float = FETCH_TIMEOUT, path: Path = CACHE_PATH):
    """Look up ``tids``, fetching only what the cache is missing.

    Returns ``(mapping, meta)`` where ``mapping`` is ``{tid: [row, ...]}``
    (a tid is absent only when neither cache nor network could answer) and
    ``meta`` reports where the answers came from.
    """
    wanted = [t for t in dict.fromkeys(tids) if TECHNIQUE_RE.fullmatch(t)]
    cache = {} if refresh else load_cache(path)

    mapping: dict[str, list] = {}
    pending: list[str] = []
    for tid in wanted:
        hit = cache.get(tid)
        if isinstance(hit, list):
            mapping[tid] = hit
        else:
            pending.append(tid)

    meta = {"fetched": 0, "failed": 0, "from_cache": len(mapping)}

    if pending and not offline:
        def fetch_one(tid: str):
            return tid, _fetch_with_fallback(tid, timeout)

        with ThreadPoolExecutor(max_workers=FETCH_WORKERS) as pool:
            for tid, rows in pool.map(fetch_one, pending):
                if rows is None:
                    meta["failed"] += 1
                    continue
                mapping[tid] = rows
                cache[tid] = rows
                meta["fetched"] += 1
        if meta["fetched"]:
            save_cache(cache, path)
    elif pending and offline:
        meta["failed"] = len(pending)

    return mapping, meta


# ---------------------------------------------------------------------------
# capa -> section
# ---------------------------------------------------------------------------

def collect_from_capa(capa: dict) -> dict:
    """Techniques capa matched, keyed by ID.

    ``{tid: {"name", "sub", "tactics": [shortname, ...]}}`` - read exactly the
    way stix_graph.graph_from_capa() reads it, so the D3FEND tab and the STIX
    graph always show the same set of techniques and tactics for one run.
    """
    found: dict[str, dict] = {}
    if not isinstance(capa, dict):
        return found

    for cap in capa.get("capabilities") or []:
        if not isinstance(cap, dict):
            continue
        for att in cap.get("attack") or []:
            if not isinstance(att, dict):
                continue
            tid = str(att.get("id") or "").strip().upper()
            if not TECHNIQUE_RE.fullmatch(tid):
                continue
            info = found.setdefault(tid, {
                "name": str(att.get("technique") or tid),
                "sub": str(att.get("subtechnique") or ""),
                "tactics": [],
            })
            tactic = (stix_graph.normalise_tactic(att.get("tactic"))
                      if stix_graph else "")
            if tactic and tactic not in info["tactics"]:
                info["tactics"].append(tactic)

    # A capa export may carry the flat attack_ids list with no per-capability
    # entry (old cache format). Keep those techniques, just without a tactic.
    for raw in capa.get("attack_ids") or []:
        tid = str(raw or "").strip().upper()
        if TECHNIQUE_RE.fullmatch(tid) and tid not in found:
            found[tid] = {"name": tid, "sub": "", "tactics": []}
    return found


def build_section(capa: dict, *, offline: bool | None = None) -> dict:
    """Dashboard payload for the D3FEND tab, grouped by capa-recovered tactic."""
    empty = {"available": False, "reason": "", "source": "",
             "generated_at": "",
             "totals": {"techniques": 0, "covered": 0, "countermeasures": 0},
             "tactics": []}
    if stix_graph is None:
        empty["reason"] = "python/stix_graph.py could not be imported"
        return empty

    found = collect_from_capa(capa)
    if not found:
        empty["reason"] = "capa matched no ATT&CK techniques for this sample"
        return empty

    if offline is None:
        offline = os.environ.get("D3FEND_OFFLINE", "").strip() in ("1", "true", "yes")

    mapping, meta = resolve(found, offline=offline)
    if not mapping:
        empty["reason"] = ("no D3FEND cache on disk and the d3fend.mitre.org "
                           "API was unreachable" if meta["failed"]
                           else "no D3FEND mapping for the matched techniques")
        return empty

    # One entry per technique, listed under every capa tactic it belongs to.
    groups: dict[str, list] = {}
    for tid in sorted(found):
        info = found[tid]
        entry = {"id": tid, "name": info["name"], "sub": info["sub"],
                 "defenses": mapping.get(tid) or []}
        for short in info["tactics"] or [""]:
            groups.setdefault(short, []).append(entry)

    known = [s for s, _ in stix_graph.TACTICS]
    order = known + sorted(k for k in groups if k not in set(known))
    tactics = []
    for short in order:
        if short not in groups:
            continue
        tactics.append({
            "short": short,
            "name": stix_graph.TACTIC_NAMES.get(short)
                    or (short.title() if short else "Uncategorized"),
            "techniques": groups[short],
        })

    unique_countermeasures = {r["id"] for rows in mapping.values() for r in rows}
    covered = sum(1 for rows in mapping.values() if rows)
    if meta["fetched"] and meta["from_cache"]:
        source = "cache + live"
    elif meta["fetched"]:
        source = "d3fend.mitre.org"
    else:
        source = "cti-cache/knowledge/d3fend.json"

    missing = [t for t in found if t not in mapping]
    reason = ""
    if missing:
        reason = (f"{len(missing)} technique(s) could not be resolved "
                  f"({', '.join(sorted(missing)[:6])})")

    return {
        "available": True,
        "reason": reason,
        "source": source,
        "generated_at": datetime.now(timezone.utc)
                        .isoformat(timespec="seconds"),
        "totals": {
            "techniques": len(found),
            "covered": covered,
            "countermeasures": len(unique_countermeasures),
        },
        "tactics": tactics,
    }


# ---------------------------------------------------------------------------
# CLI: cache warmer / sanity check
# ---------------------------------------------------------------------------

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="MITRE D3FEND countermeasure lookup and cache warmer")
    ap.add_argument("--capa", help="capa JSON export to warm for")
    ap.add_argument("--tids", help="comma-separated technique IDs (T1059,T1055)")
    ap.add_argument("--offline", action="store_true",
                    help="never touch the network; cache only")
    ap.add_argument("--refresh", action="store_true",
                    help="re-fetch techniques already in the cache")
    ap.add_argument("--section", action="store_true",
                    help="print the full dashboard section JSON")
    args = ap.parse_args(argv)

    tids: list[str] = []
    capa: dict = {}
    if args.capa:
        capa = json.loads(Path(args.capa).read_text(encoding="utf-8"))
        tids = list(collect_from_capa(capa))
    if args.tids:
        tids += [t.strip().upper() for t in args.tids.split(",") if t.strip()]

    if not tids:
        cache = load_cache()
        with_rows = sum(1 for rows in cache.values() if rows)
        print(f"cache: {CACHE_PATH}\n"
              f"  techniques: {len(cache)} ({with_rows} with mappings)")
        return 0

    mapping, meta = resolve(tids, offline=args.offline, refresh=args.refresh)
    print(f"looked up {len(tids)} technique(s): "
          f"{meta['from_cache']} cached, {meta['fetched']} fetched, "
          f"{meta['failed']} unresolved")
    for tid in sorted(mapping):
        rows = mapping[tid]
        cats = ", ".join(sorted({r["cat"] for r in rows if r["cat"]})) or "-"
        print(f"  {tid}: {len(rows)} countermeasure(s) [{cats}]")

    if args.section:
        section = build_section(capa or {"attack_ids": tids},
                                offline=args.offline)
        print(json.dumps(section, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
