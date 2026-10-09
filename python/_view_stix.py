#!python3
"""Render a STIX 2.1 bundle as a self-contained interactive HTML page.

Usage:
    python/_view_stix.py <bundle.json> [--out-dir DIR] [--out-name X]
                         [--navigator] [--navigator-only] [--attack-version 14]

Opens **any** STIX 2.1 file, not just the ones this project writes: bundles
produced by src/net/cti.cpp (exports/<stem>_analysis/stix/<stem>_stix21.json), by
python/_extract_stix.py (<stem>.stix21.json next to its input), or downloaded
from OTX / MISP / the MITRE CTI repo.  Parsing is deliberately lenient, so
partial bundles with dangling references still render.

The page has two views:
    ATT&CK Coverage   techniques grouped into their tactics, kill-chain order
    Object Graph      force-directed graph of every object and relationship

and can export an ATT&CK Navigator layer (layer format 4.5) for the techniques
it found, either from the button in the page or with --navigator.

Output is ONE self-contained .html file - d3 and the payload are inlined, so it
works when opened by double-clicking (file:// blocks fetch()).

The HTML path is printed on the last stdout line (same contract as
_create_dashboard.py and _extract_stix.py, so wrappers can read it back).

Exit codes: 0 ok, 1 usage error, 2 unreadable / unparseable input.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

try:
    import stix_graph
except Exception as exc:  # pragma: no cover
    print(f"error: cannot import python/stix_graph.py: {exc}", file=sys.stderr)
    sys.exit(2)

DEFAULT_TEMPLATE = HERE / "templates" / "stix.html"
D3_PATH = HERE / "d3.min.js"


def load_d3() -> str:
    """The vendored d3 build, inlined. Empty only if the asset is missing."""
    try:
        return D3_PATH.read_text(encoding="utf-8")
    except Exception as exc:
        print(f"warn: cannot read {D3_PATH}: {exc}", file=sys.stderr)
        return ""


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Render a STIX 2.1 bundle as a self-contained HTML page "
                    "(ATT&CK coverage matrix + object graph).")
    ap.add_argument("bundle", nargs="?", default="",
                    help="STIX 2.1 bundle (or bare array of objects) to render")
    ap.add_argument("--out-dir", default="",
                    help="output directory (default: the bundle's own directory)")
    ap.add_argument("--out-name", default="",
                    help="output stem (default: the bundle file stem)")
    ap.add_argument("--navigator", action="store_true",
                    help="also write <stem>.navigator.json next to the HTML")
    ap.add_argument("--navigator-only", action="store_true",
                    help="write only the ATT&CK Navigator layer, no HTML")
    ap.add_argument("--attack-version", default="",
                    help="ATT&CK version for the Navigator layer (default: 14)")
    ap.add_argument("--attack-cache", default="",
                    help="MITRE ATT&CK bundle used to fill in technique names, "
                         "descriptions and tactics (default: the CTI knowledge "
                         "cache, if the analyzer has fetched it)")
    ap.add_argument("--no-enrich", action="store_true",
                    help="render the bundle exactly as it is, without looking "
                         "anything up in the ATT&CK cache")
    ap.add_argument("--full-navigator", action="store_true",
                    help="write a COMPLETE ATT&CK Navigator layer with ALL "
                         "enterprise techniques (from the MITRE cache), "
                         "not just the ones in the bundle")
    ap.add_argument("--full-navigator-only", action="store_true",
                    help="write only the full ATT&CK Navigator layer, no HTML")
    args = ap.parse_args()

    if not args.bundle:
        ap.print_usage(sys.stderr)
        print("error: pass a STIX bundle path", file=sys.stderr)
        return 1

    src = Path(args.bundle)
    objects, error = stix_graph.load_bundle(src)
    if error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    if not objects:
        print(f"error: {src} contains no STIX objects", file=sys.stderr)
        return 2

    stem = args.out_name or src.stem.replace(".stix21", "") or "stix"
    # Default next to the bundle: the analyzer writes bundles under
    # exports/<stem>_analysis/stix/, so the rendered page stays with its run.
    out_dir = Path(args.out_dir) if args.out_dir else src.parent

    tactic_knowledge: dict = {}
    if not args.no_enrich:
        want = {t for obj in objects for t in stix_graph.technique_ids(obj)}
        if want:
            knowledge = stix_graph.load_attack_knowledge(args.attack_cache or None, want)
            if knowledge:
                filled = stix_graph.enrich_objects(objects, knowledge)
                print(f"[*] enriched {filled} technique(s) from the ATT&CK cache",
                      file=sys.stderr)

        # Read unfiltered: a bundle holds ~15 tactics, and a tactic has to show
        # ATT&CK's prose for the tactic itself, which a technique lookup never
        # supplies.
        tactic_knowledge = stix_graph.load_tactic_knowledge(args.attack_cache or None)
        if tactic_knowledge:
            filled_tactics = stix_graph.enrich_tactics(objects, tactic_knowledge)
            print(f"[*] enriched {filled_tactics} tactic(s) from the ATT&CK cache",
                  file=sys.stderr)

    meta = {
        "name": src.name,
        "source": str(src),
        "stem": stem,
        "attack_version": args.attack_version,
    }
    payload = stix_graph.build_payload(objects, meta, tactic_knowledge)
    stats = payload["graph"]["stats"]

    print(f"[*] {src.name}: {stats['objects']} object(s), {stats['nodes']} node(s), "
          f"{stats['edges']} edge(s)", file=sys.stderr)
    print(f"[*] {stats['techniques']} technique(s) across {stats['tactics']} tactic(s)",
          file=sys.stderr)
    if stats["dropped_edges"]:
        print(f"[!] {stats['dropped_edges']} relationship(s) dropped: endpoint not in bundle",
              file=sys.stderr)

    written: list[Path] = []

    if args.navigator or args.navigator_only:
        layer, note = stix_graph.to_navigator_layer(
            objects, name=stem, attack_version=args.attack_version)
        if not layer:
            print(f"[!] no Navigator layer written: {note}", file=sys.stderr)
            if args.navigator_only:
                return 1
        else:
            if note:
                print(f"[!] {note}", file=sys.stderr)
            try:
                out_dir.mkdir(parents=True, exist_ok=True)
                nav_path = out_dir / f"{stem}.navigator.json"
                nav_path.write_text(json.dumps(layer, indent=2), encoding="utf-8")
            except Exception as exc:
                print(f"error: cannot write Navigator layer: {exc}", file=sys.stderr)
                return 2
            written.append(nav_path)
            print(f"[+] Navigator layer -> {nav_path}", file=sys.stderr)

    # Full ATT&CK Navigator layer (all techniques from the MITRE cache)
    if args.full_navigator or args.full_navigator_only:
        attack_version = args.attack_version
        full_layer, full_note = stix_graph.build_full_navigator_layer(attack_version)
        if not full_layer:
            print(f"[!] no full Navigator layer written: {full_note}", file=sys.stderr)
            if args.full_navigator_only:
                return 1
        else:
            if full_note:
                print(f"[!] {full_note}", file=sys.stderr)
            try:
                out_dir.mkdir(parents=True, exist_ok=True)
                full_nav_path = out_dir / f"{stem}_full_matrix.navigator.json"
                full_nav_path.write_text(json.dumps(full_layer, indent=2), encoding="utf-8")
            except Exception as exc:
                print(f"error: cannot write full Navigator layer: {exc}", file=sys.stderr)
                return 2
            written.append(full_nav_path)
            print(f"[+] Full ATT&CK Matrix Navigator layer -> {full_nav_path}", file=sys.stderr)

    if args.navigator_only or args.full_navigator_only:
        # No HTML was asked for: the last stdout line is the layer path.
        if written:
            print(str(written[-1]))
            return 0
        return 1

    if not DEFAULT_TEMPLATE.is_file():
        print(f"error: template not found: {DEFAULT_TEMPLATE}", file=sys.stderr)
        return 2

    try:
        html = stix_graph.html_document(payload, load_d3(), DEFAULT_TEMPLATE)
    except Exception as exc:
        print(f"error: cannot render the page: {exc}", file=sys.stderr)
        return 2

    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        html_path = out_dir / f"{stem}.html"
        html_path.write_text(html, encoding="utf-8")
    except Exception as exc:
        print(f"error: cannot write {out_dir}: {exc}", file=sys.stderr)
        return 2

    print(f"[+] {len(html) / 1024:.0f} KB -> {html_path}", file=sys.stderr)
    for path in written:
        print(str(path))
    print(str(html_path))          # last stdout line: the contract
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
