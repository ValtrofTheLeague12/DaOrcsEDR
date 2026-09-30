#!python3
"""Recover STIX 2.1 objects for MITRE ATT&CK technique IDs (e.g. from capa).

Usage:
    python/_extract_stix.py T1129 T1497.001 [--out <file>] [--capa <capa.json>]
    python/_extract_stix.py --capa exports/capa/suspicious_sample_capa.json

Technique IDs come as plain argv params (space and/or comma separated,
case-insensitive, with or without a leading 'T'). Alternatively --capa reads
the "attack_ids" list straight out of a capa export (the field the capa
runner already writes), so the IDs recovered from capa need no retyping.

Source bundle (offline first):
    cti-cache/knowledge/enterprise-attack.json   <- written by the CTI phase
    (same STIX 2.1 bundle src/net/cti.cpp fetches via urls.attack_stix).
With --refresh (or when the cache file is missing) it is fetched from the
official MITRE CTI repo and --cache-to can point elsewhere.

The official `stix2` lib (already in python/.venv) rebuilds the objects:
each requested technique becomes its genuine attack-pattern object and, by
default, the tactics (x-mitre-tactic) it executes under, its mitigations
(course-of-action) and the relationships binding them -- the edges ATT&CK
Navigator draws.

Output is a STIX 2.1 Bundle JSON file; its path is printed on the last stdout
line (same contract as _create_dashboard.py, so visualizer-style wrappers can
read it back). Also understands --out-dir/--out-name like the dashboard
generator.

Exit codes: 0 ok, 1 usage/lookup error, 2 missing dependency or unreadable
source bundle.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

try:
    import stix2
except Exception as exc:  # pragma: no cover
    print(f"error: the official stix2 lib is required: {exc}", file=sys.stderr)
    sys.exit(2)

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
try:
    import stix_graph
except Exception as exc:  # pragma: no cover
    print(f"error: cannot import python/stix_graph.py: {exc}", file=sys.stderr)
    sys.exit(2)

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
DEFAULT_CACHE = ROOT / "cti-cache" / "knowledge" / "enterprise-attack.json"
MITRE_CTI_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack.json"
)

TID_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.IGNORECASE)


def normalise_tid(raw: str) -> str:
    tid = raw.strip().upper().replace("_", ".")
    if tid and not tid.startswith("T"):
        tid = "T" + tid
    return tid


def split_ids(values: list[str]) -> list[str]:
    out: list[str] = []
    for chunk in values:
        for part in re.split(r"[,\s;]+", chunk):
            if part:
                out.append(normalise_tid(part))
    seen: set[str] = set()
    uniq = [t for t in out if not (t in seen or seen.add(t))]
    return uniq


def load_source_bundle(path: Path) -> list[dict]:
    try:
        with path.open("r", encoding="utf-8") as fh:
            doc = json.load(fh)
    except FileNotFoundError:
        print(f"error: STIX source bundle not found: {path}", file=sys.stderr)
        print("hint: run the analyzer once (CTI knowledge caches it there),",
              f"or re-run with --refresh to fetch {MITRE_CTI_URL}", file=sys.stderr)
        sys.exit(2)
    except Exception as exc:
        print(f"error: cannot parse {path}: {exc}", file=sys.stderr)
        sys.exit(2)
    objs = doc.get("objects") if isinstance(doc, dict) else None
    if not isinstance(objs, list):
        print(f"error: {path} is not a STIX bundle (no 'objects' list)", file=sys.stderr)
        sys.exit(2)
    return objs


def refresh_bundle(url: str, dest: Path) -> list[dict]:
    import urllib.request
    print(f"[*] fetching {url}", file=sys.stderr)
    try:
        with urllib.request.urlopen(url, timeout=60) as resp:
            raw = resp.read()
    except Exception as exc:
        print(f"error: download failed: {exc}", file=sys.stderr)
        sys.exit(2)
    try:
        doc = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        print(f"error: downloaded bundle is not JSON: {exc}", file=sys.stderr)
        sys.exit(2)
    objs = doc.get("objects") if isinstance(doc, dict) else None
    if not isinstance(objs, list):
        print("error: downloaded file is not a STIX bundle", file=sys.stderr)
        sys.exit(2)
    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
        with dest.open("w", encoding="utf-8") as fh:
            json.dump(doc, fh)
        print(f"[*] cached {len(objs)} objects -> {dest}", file=sys.stderr)
    except Exception as exc:
        print(f"warn: cannot write cache {dest}: {exc}", file=sys.stderr)
    return objs


def index_attack_patterns(objs: list[dict]) -> dict[str, dict]:
    by_tid: dict[str, dict] = {}
    for o in objs:
        if not isinstance(o, dict) or o.get("type") != "attack-pattern":
            continue
        for ref in o.get("external_references") or []:
            if (isinstance(ref, dict) and ref.get("source_name") == "mitre-attack"
                    and isinstance(ref.get("external_id"), str)):
                by_tid.setdefault(ref["external_id"].upper(), o)
    return by_tid


def tactic_shortnames(pattern: dict) -> list[str]:
    shorts: list[str] = []
    for phase in pattern.get("kill_chain_phases") or []:
        if (isinstance(phase, dict) and phase.get("kill_chain_name") == "mitre-attack"
                and isinstance(phase.get("phase_name"), str)):
            shorts.append(phase["phase_name"])
    return shorts


def build_bundle(objs, tids, include_related=True):
    by_tid = index_attack_patterns(objs)
    missing = [t for t in tids if t not in by_tid]
    if missing:
        print("error: unknown technique ID(s): " + ", ".join(missing)
              + f" ({len(by_tid)} techniques in source bundle)", file=sys.stderr)
        sys.exit(1)
    wanted = {}
    for t in tids:
        raw = by_tid[t]
        wanted[raw["id"]] = raw
    for t in tids:
        print(f"[*] {t} -> {by_tid[t].get('name')}", file=sys.stderr)
    stats = {"techniques": len(wanted), "tactics": 0,
             "mitigations": 0, "relationships": 0}
    if include_related:
        tactics = [o for o in objs
                   if isinstance(o, dict) and o.get("type") == "x-mitre-tactic"]
        short_to_tactic = {str(o.get("x_mitre_shortname")).lower(): o
                           for o in tactics if o.get("x_mitre_shortname")}
        phases = set()
        for raw in wanted.values():
            phases.update(tactic_shortnames(raw))
        for phase in sorted(phases):
            tac = short_to_tactic.get(phase)
            if tac is not None and tac["id"] not in wanted:
                wanted[tac["id"]] = tac
                stats["tactics"] += 1
        wanted_ids = set(wanted)
        by_id = {o["id"]: o for o in objs
                 if isinstance(o, dict) and isinstance(o.get("id"), str)}
        for o in objs:
            if not isinstance(o, dict) or o.get("type") != "relationship":
                continue
            src, dst = o.get("source_ref"), o.get("target_ref")
            if o.get("relationship_type") == "mitigates" and dst in wanted_ids:
                if o["id"] not in wanted:
                    wanted[o["id"]] = o
                    stats["relationships"] += 1
                coa = by_id.get(src) if isinstance(src, str) else None
                if coa is not None and coa["id"] not in wanted:
                    wanted[coa["id"]] = coa
                    stats["mitigations"] += 1
    parsed = [stix2.parse(raw, allow_custom=True, version="2.1")
              for raw in wanted.values()]
    bundle = stix2.v21.Bundle(objects=parsed, allow_custom=True)
    return bundle, stats


def main():
    ap = argparse.ArgumentParser(
        description="Recover STIX 2.1 objects for MITRE ATT&CK technique IDs "
                    "(e.g. the attack_ids recovered from capa).")
    ap.add_argument("technique", nargs="*",
                    help="technique ID(s): T1129 T1497.001 ... (comma/space separated ok)")
    ap.add_argument("--capa", default="",
                    help="read technique IDs from a capa export's attack_ids field")
    ap.add_argument("--source", default=str(DEFAULT_CACHE),
                    help="STIX bundle to recover from (default: cti-cache knowledge copy)")
    ap.add_argument("--refresh", action="store_true",
                    help="re-fetch the source bundle from the official MITRE CTI repo")
    ap.add_argument("--cache-to", default="",
                    help="where --refresh writes the bundle (default: --source)")
    ap.add_argument("--no-related", action="store_true",
                    help="only emit the attack-pattern objects, no tactics/mitigations")
    ap.add_argument("--out", default="",
                    help="output bundle path (default: <out-dir>/<out-name>.stix21.json)")
    ap.add_argument("--out-dir", default="exports/stix",
                    help="output directory (default: exports/stix)")
    ap.add_argument("--out-name", default="",
                    help="output stem (default: joined technique IDs)")
    ap.add_argument("--full-navigator", action="store_true",
                    help="also write a COMPLETE ATT&CK Navigator layer with ALL "
                         "enterprise techniques from the source bundle")
    ap.add_argument("--full-navigator-only", action="store_true",
                    help="write only the full ATT&CK Navigator layer, no STIX bundle")
    args = ap.parse_args()

    tids = split_ids(args.technique)

    if args.capa:
        try:
            with open(args.capa, "r", encoding="utf-8") as fh:
                capa = json.load(fh)
        except Exception as exc:
            print(f"error: cannot read capa file {args.capa}: {exc}", file=sys.stderr)
            return 1
        ids = capa.get("attack_ids") if isinstance(capa, dict) else None
        if not ids:
            print(f"error: {args.capa} has no attack_ids (nothing recovered)",
                  file=sys.stderr)
            return 1
        tids = split_ids([str(i) for i in ids] + tids)
        print(f"[*] capa {args.capa}: {', '.join(tids)}", file=sys.stderr)

    bad = [t for t in tids if not TID_RE.match(t)]
    if bad:
        print("error: not technique IDs: " + ", ".join(bad)
              + " (want T#### or T####.###)", file=sys.stderr)
        return 1
    if not tids:
        ap.print_usage(sys.stderr)
        print("error: pass at least one technique ID or --capa <capa.json>",
              file=sys.stderr)
        return 1


    if args.refresh:
        objs = refresh_bundle(MITRE_CTI_URL, Path(args.cache_to or args.source))
    else:
        objs = load_source_bundle(Path(args.source))

    bundle, stats = build_bundle(objs, tids, not args.no_related)

    # Full ATT&CK Navigator layer (all techniques from the source bundle)
    if args.full_navigator or args.full_navigator_only:
        # Use the already-loaded source bundle to build the full matrix
        full_layer, full_note = build_full_navigator_from_objects(objs, args.source)
        if not full_layer:
            print(f"[!] no full Navigator layer written: {full_note}", file=sys.stderr)
            if args.full_navigator_only:
                return 1
        else:
            if full_note:
                print(f"[!] {full_note}", file=sys.stderr)
            try:
                out_dir = Path(args.out_dir)
                out_dir.mkdir(parents=True, exist_ok=True)
                full_nav_path = out_dir / "mitre_attack_enterprise_full_matrix.navigator.json"
                full_nav_path.write_text(json.dumps(full_layer, indent=2), encoding="utf-8")
            except Exception as exc:
                print(f"error: cannot write full Navigator layer: {exc}", file=sys.stderr)
                return 2
            print(f"[+] Full ATT&CK Matrix Navigator layer -> {full_nav_path}", file=sys.stderr)

    if args.full_navigator_only:
        return 0

    stem = args.out_name or "_".join(tids).replace(".", "p")
    out = Path(args.out) if args.out else Path(args.out_dir) / f"{stem}.stix21.json"
    try:
        out.parent.mkdir(parents=True, exist_ok=True)
        with out.open("w", encoding="utf-8") as fh:
            fh.write(bundle.serialize(pretty=True))
    except Exception as exc:
        print(f"error: cannot write {out}: {exc}", file=sys.stderr)
        return 1

    rel = ""
    if stats["tactics"] or stats["mitigations"]:
        rel = (f" + {stats['tactics']} tactic(s), {stats['mitigations']} "
               f"mitigation(s), {stats['relationships']} relationship(s)")
    print(f"[+] {stats['techniques']} technique(s){rel} -> {out}", file=sys.stderr)
    print(str(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
