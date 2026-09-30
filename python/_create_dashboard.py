#!python3
"""Generate a self-contained HTML threat dashboard from exported artifacts.

Invoked by src/visualizer.cpp via proc::run (same subprocess plumbing as
capa / radare2). Reads the JSON artifacts produced by the exporter, builds a
single normalized payload, and renders python/templates/dashboard.html.j2.

The output is ONE self-contained .html file (no CDN, no fetch): all CSS/JS is
inlined and the data is embedded, so it works when opened by double-clicking
(file:// blocks fetch()).

Prints the path of the generated HTML on its last stdout line.

The interpreter comes from the shebang above: the "py" launcher used by
src/visualizer.cpp resolves the PEP 397 virtual command "python3" through its
own registered Python 3 instead of searching PATH. A "/usr/bin/env python3"
shebang would instead pick the first python3 on PATH — which may be the MSYS2
Python that build.ps1 prepends, and that one has no jinja2.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    from jinja2 import Environment, FileSystemLoader, select_autoescape
except Exception as exc:  # pragma: no cover
    print(f"error: jinja2 is required: {exc}", file=sys.stderr)
    sys.exit(2)

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

# Shared with python/_view_stix.py so the STIX graph is built one way. A
# failure here disables only the ATT&CK / STIX section - the rest of the
# dashboard is still worth generating.
try:
    import stix_graph
except Exception as exc:  # pragma: no cover
    stix_graph = None
    STIX_IMPORT_ERROR = f"cannot import python/stix_graph.py: {exc}"
else:
    STIX_IMPORT_ERROR = ""


def load_json(path: str):
    if not path:
        return None
    p = Path(path)
    if not p.is_file():
        return None
    try:
        with p.open("r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception as exc:
        print(f"warn: cannot parse {path}: {exc}", file=sys.stderr)
        return None


def parse_dot(text: str) -> dict:
    """Fallback DOT parser: returns {nodes:[{id,label}], edges:[[a,b]]}.

    Only used when the cgraph-produced graphs.json is absent. It is known to
    be less accurate than cgraph - it cannot tell a node statement from an edge
    attribute block, and it treats "->" inside a quoted label (e.g. the
    demangled C++ name "this->size()") as an edge. See load_graphs_json() for
    the preferred path.
    """
    nodes: dict[str, str] = {}
    edges: list[list[str]] = []
    if not text:
        return {"nodes": [], "edges": []}

    for m in re.finditer(r'"?([A-Za-z0-9_.:x]+)"?\s*\[([^\]]*)\]', text):
        nid, attrs = m.group(1), m.group(2)
        if nid in ("digraph", "graph", "node", "edge"):
            continue
        if "label" not in attrs:
            continue  # edge attribute block, not a node definition
        lm = re.search(r'label\s*=\s*"((?:[^"\\]|\\.)*)"', attrs)
        label = lm.group(1) if lm else nid
        label = label.replace("\\l", " ").replace("\\n", " ").replace('\\"', '"')
        nodes[nid] = label.strip()

    for m in re.finditer(r'"?([A-Za-z0-9_.:x]+)"?\s*->\s*"?([A-Za-z0-9_.:x]+)"?', text):
        a, b = m.group(1), m.group(2)
        edges.append([a, b])
        nodes.setdefault(a, a)
        nodes.setdefault(b, b)

    return {"nodes": [{"id": k, "label": v} for k, v in nodes.items()],
            "edges": edges}


def load_graphs_json(path: str, stem: str = "") -> dict:
    """Load the cgraph-normalized graphs.json written by dot2json.

    `stem` is the analyzed sample's stem (e.g. "suspicious_sample"). It is used
    to select only that sample's graphs from a file that may cover many.

    Returns {"callgraph": <graph>, "section": <graph>, "source": "cgraph"} on
    success, or {} when the file is absent/unreadable so the caller can fall
    back to parse_dot(). Each graph keeps only the node/edge keys the dashboard
    template already consumes; the extra fields (name, self_loops, multi_edges,
    per-node url) are passed through because they are additive and unused keys
    are ignored by the template.
    """
    if not path:
        return {}
    p = Path(path)
    if not p.is_file():
        return {}
    try:
        with p.open("r", encoding="utf-8") as fh:
            doc = json.load(fh)
    except Exception as exc:
        print(f"warn: cannot parse {path}: {exc}", file=sys.stderr)
        return {}

    graphs = doc.get("graphs")
    if not isinstance(graphs, dict):
        print(f"warn: {path} has no 'graphs' object", file=sys.stderr)
        return {}

    # Keys are FILE STEMS (<stem>_callgraph, <stem>_section_<name>), not digraph
    # names. Every r2 callgraph is called "digraph code", so selecting by graph
    # name would mix samples. When a stem is given, only that sample's graphs
    # are eligible.
    def owned(stem_key: str) -> bool:
        if not stem:
            return True
        return stem_key == stem or stem_key.startswith(stem + "_")

    def pick(kind: str):
        # r2 writes section graphs as <stem>_section_<section>, so the key has
        # the section name appended (e.g. suspicious_sample_section__text).
        # An exact <stem>_<kind> match wins; otherwise take the largest
        # <stem>_section* graph, which is the main text CFG in practice.
        exact = stem + "_" + kind if stem else None
        if exact and exact in graphs and isinstance(graphs[exact], dict):
            return graphs[exact]
        candidates = [(k, g) for k, g in graphs.items()
                      if isinstance(g, dict) and owned(k)
                      and k.startswith((stem + "_" if stem else "") + kind)]
        if not candidates:
            return None
        candidates.sort(key=lambda kv: len(kv[1].get("nodes") or []), reverse=True)
        return candidates[0][1]

    callgraph = pick("callgraph")
    section = pick("section")

    out = {"source": doc.get("parser", "cgraph")}
    if callgraph:
        out["callgraph"] = callgraph
    if section:
        out["section"] = section

    # A graphs.json that parsed cleanly but yielded nothing usable is treated
    # as a miss so the regex fallback still runs.
    return out if ("callgraph" in out or "section" in out) else {}


def short_hash(h: str, n: int = 16) -> str:
    if not h:
        return ""
    return h[:n] + ("..." if len(h) > n else "")


def clamp_bytes(obj, limit: int):
    try:
        size = len(json.dumps(obj, separators=(",", ":")))
    except Exception:
        return obj, 0
    if size > limit:
        return None, size
    return obj, size


def read_text(path: str) -> str:
    if not path:
        return ""
    p = Path(path)
    if not p.is_file():
        return ""
    try:
        return p.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""


def build_file_catalog(root: str, budget: int = 2 * 1024 * 1024) -> list[dict]:
    """Build a bounded, read-only preview catalog for the dashboard Files panel."""
    if not root:
        return []
    base = Path(root).resolve()
    if not base.is_dir():
        return []
    entries = []
    used = 0
    for path in sorted(p for p in base.rglob("*") if p.is_file()):
        try:
            rel = path.relative_to(base).as_posix()
            size = path.stat().st_size
        except OSError:
            continue
        if len(entries) >= 250 or used >= budget:
            entries.append({"path": rel, "size": size, "kind": "truncated",
                            "content": "", "truncated": True})
            break
        suffix = path.suffix.lower()
        text_like = suffix in {".json", ".txt", ".asm", ".dot", ".csv", ".yaml", ".yml", ".md", ".log"}
        content = ""
        truncated = False
        if text_like and size <= 512 * 1024:
            try:
                content = path.read_text(encoding="utf-8", errors="replace")
                if len(content.encode("utf-8")) > 256 * 1024:
                    content = content[:256 * 1024]
                    truncated = True
                used += len(content.encode("utf-8"))
            except OSError:
                content = ""
        elif text_like:
            truncated = True
        entries.append({"path": rel, "size": size,
                        "kind": "text" if text_like else "binary",
                        "content": content, "truncated": truncated})
    return entries



def load_json_maybe_wrapped(path: str):
    """load_json(), transparently unwrapping a double-encoded document.

    <stem>_cti.json used to be written as a JSON *string* holding JSON text
    (the exporter handed textual JSON to a json-object writer). That is fixed,
    but exports produced before the fix must still render, so unwrap once.
    """
    doc = load_json(path)
    if isinstance(doc, str):
        try:
            return json.loads(doc)
        except Exception as exc:
            print(f"warn: cannot decode wrapped JSON in {path}: {exc}", file=sys.stderr)
            return None
    return doc


# ---------------------------------------------------------------------------
# Geolocation support for the threat map
# ---------------------------------------------------------------------------
# ccTLD -> ISO 3166-1 alpha-2. Only a *fallback* for domains/URLs/e-mails the
# CTI providers could not geolocate; every such hit is flagged source="tld" in
# the payload so the dashboard can render it as inferred rather than reported.
_CC_TLD = {
    "ru": "RU", "su": "RU", "cn": "CN", "ir": "IR", "kp": "KP", "br": "BR",
    "in": "IN", "ua": "UA", "tr": "TR", "vn": "VN", "kr": "KR", "jp": "JP",
    "tw": "TW", "hk": "HK", "sg": "SG", "th": "TH", "id": "ID", "my": "MY",
    "ph": "PH", "pk": "PK", "bd": "BD", "ae": "AE", "sa": "SA", "il": "IL",
    "eg": "EG", "za": "ZA", "ng": "NG", "ke": "KE", "ma": "MA", "mx": "MX",
    "ar": "AR", "cl": "CL", "co": "CO", "pe": "PE", "ve": "VE", "ca": "CA",
    "au": "AU", "nz": "NZ", "pl": "PL", "de": "DE", "fr": "FR", "nl": "NL",
    "be": "BE", "ch": "CH", "at": "AT", "se": "SE", "no": "NO", "fi": "FI",
    "dk": "DK", "ie": "IE", "it": "IT", "es": "ES", "pt": "PT", "gr": "GR",
    "ro": "RO", "cz": "CZ", "hu": "HU", "bg": "BG", "rs": "RS", "lt": "LT",
    "lv": "LV", "ee": "EE", "sk": "SK", "si": "SI", "hr": "HR", "by": "BY",
    "kz": "KZ", "ge": "GE", "am": "AM", "az": "AZ", "uz": "UZ", "md": "MD",
    "is": "IS", "lu": "LU", "mt": "MT", "cy": "CY", "al": "AL", "mk": "MK",
    "ba": "BA", "me": "ME", "io": "IO", "cc": "CC", "tk": "TK", "ml": "ML",
    "cf": "CF", "gq": "GQ", "pw": "PW", "to": "TO", "ws": "WS", "vu": "VU",
}

_VERDICT_RANK = {"malicious": 3, "suspicious": 2, "unknown": 1, "benign": 0,
                 "informational": 0, "": 1}


def load_country_aliases() -> dict:
    """alpha-3 -> alpha-2 aliases from the vendored country-codes.json."""
    doc = load_json(str(Path(__file__).resolve().parent / "country-codes.json"))
    if not isinstance(doc, dict):
        return {}
    aliases = doc.get("aliases")
    return aliases if isinstance(aliases, dict) else {}


def normalize_cc(raw, aliases: dict) -> str:
    """Provider country string -> ISO alpha-2 (accepts alpha-2 or alpha-3)."""
    if not raw or not isinstance(raw, str):
        return ""
    cc = raw.strip().upper()
    if len(cc) == 2 and cc.isalpha():
        return cc
    if len(cc) == 3 and cc.isalpha():
        return str(aliases.get(cc) or "")
    return ""


def host_of(value: str, kind: str) -> str:
    """Best-effort host extraction for url / email values."""
    v = value or ""
    if kind == "email":
        return v.split("@")[-1]
    if kind == "url":
        rest = v.split("//", 1)[-1]
        return rest.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    return v


def build_cti_index(cti_doc) -> dict:
    """value -> compact CTI enrichment record (verdict, findings, network)."""
    index: dict[str, dict] = {}
    artifacts = cti_doc.get("artifacts") if isinstance(cti_doc, dict) else None
    for a in (artifacts or []):
        if not isinstance(a, dict):
            continue
        value = a.get("value") or ""
        if not value:
            continue
        net = a.get("network") if isinstance(a.get("network"), dict) else {}
        findings = []
        for f in (a.get("findings") or [])[:4]:
            if not isinstance(f, dict):
                continue
            findings.append({"provider": f.get("provider") or "",
                             "summary": str(f.get("summary") or "")[:150],
                             "verdict": f.get("verdict") or ""})
        index[value] = {
            "artifact_type": a.get("type") or "",
            "verdict": a.get("verdict") or "unknown",
            "score": a.get("score") or 0,
            "families": (a.get("families") or [])[:5],
            "skipped": bool(a.get("skipped")),
            "skip_reason": a.get("skip_reason") or "",
            "reason": str(a.get("reason") or "")[:120],
            "findings": findings,
            "country": net.get("country") or "",
            "asn": net.get("asn") or "",
            "asn_name": net.get("asn_name") or "",
            "org": net.get("org") or "",
            "registrar": net.get("registrar") or "",
            "resolved_ips": (net.get("resolved_ips") or [])[:6],
            "hostnames": (net.get("hostnames") or [])[:6],
        }
    return index


def build_geo(ioc: dict, cti_index: dict, aliases: dict) -> dict:
    """Aggregate every extracted IOC into map-ready records.

    ``items``    — IOCs with a country (source="cti" reported, "tld" inferred)
    ``unmapped`` — IOCs with no country at all (still listed, never silently
                   dropped, so an analyst always sees the full IOC set)
    """
    items: list[dict] = []
    unmapped: list[dict] = []
    seen: set = set()

    def add(kind: str, value: str) -> None:
        if not value or (kind, value) in seen:
            return
        seen.add((kind, value))
        rec = cti_index.get(value) or {}
        cc = normalize_cc(rec.get("country"), aliases)
        source = "cti" if cc else ""
        if not cc and kind in ("domain", "url", "email"):
            tld = host_of(value, kind).rsplit(".", 1)[-1].lower()
            cc2 = _CC_TLD.get(tld)
            if cc2:
                cc, source = cc2, "tld"
        row = {
            "kind": kind, "value": value, "cc": cc, "source": source,
            "verdict": rec.get("verdict") or "unknown",
            "score": rec.get("score") or 0,
            "asn": rec.get("asn") or "", "asn_name": rec.get("asn_name") or "",
            "org": rec.get("org") or "", "registrar": rec.get("registrar") or "",
            "families": rec.get("families") or [],
            "findings": rec.get("findings") or [],
            "resolved_ips": rec.get("resolved_ips") or [],
            "reason": rec.get("reason") or "",
            "skipped": rec.get("skipped") or False,
            "skip_reason": rec.get("skip_reason") or "",
        }
        (items if cc else unmapped).append(row)

    for ip in (ioc.get("ips") or []):
        add("ip", ip)
    for d in (ioc.get("domains") or []):
        add("domain", d)
    for u in (ioc.get("urls") or []):
        add("url", u)
    for e in (ioc.get("emails") or []):
        add("email", e)
    # CTI can know IOCs the extractor missed (resolved hosts, related IPs, …).
    for value, rec in cti_index.items():
        if (rec.get("artifact_type") or "") in ("ip", "domain", "url", "email"):
            add(rec["artifact_type"], value)

    countries: dict[str, dict] = {}
    for it in items:
        c = countries.setdefault(it["cc"], {"cc": it["cc"], "count": 0, "kinds": {},
                                            "worst": "unknown", "asns": []})
        c["count"] += 1
        c["kinds"][it["kind"]] = c["kinds"].get(it["kind"], 0) + 1
        if _VERDICT_RANK.get(it["verdict"], 1) > _VERDICT_RANK.get(c["worst"], 1):
            c["worst"] = it["verdict"]
        key = (it["asn"] + " " + it["asn_name"]).strip()
        if it["asn"] and len(c["asns"]) < 4 and key not in c["asns"]:
            c["asns"].append(key)

    verdicts: dict[str, int] = {}
    for it in items + unmapped:
        verdicts[it["verdict"]] = verdicts.get(it["verdict"], 0) + 1

    return {
        "items": items[:400],
        "unmapped": unmapped[:150],
        "countries": sorted(countries.values(), key=lambda c: (-c["count"], c["cc"])),
        "stats": {
            "geolocated": len(items),
            "countries": len(countries),
            "unmapped": len(unmapped),
            "with_asn": sum(1 for i in items + unmapped if i["asn"]),
            "sources": {"cti": sum(1 for i in items if i["source"] == "cti"),
                        "tld": sum(1 for i in items if i["source"] == "tld")},
            "verdicts": verdicts,
            "truncated": max(0, len(items) - 400) + max(0, len(unmapped) - 150),
        },
    }


# The raw `xxd` dump is ~1.1 MB for a typical PE. Inlining all of it would
# roughly double the dashboard size for no analytical gain, so the payload keeps
# a bounded prefix and records the true size plus a truncation flag.
XXD_PREVIEW_CHARS = 8000


def clip_xxd(xxd: dict) -> dict:
    if not xxd:
        return {}
    out = dict(xxd)
    text = out.get("output") or ""
    out["output_full_bytes"] = len(text)
    if len(text) > XXD_PREVIEW_CHARS:
        cut = text[:XXD_PREVIEW_CHARS]
        # keep whole lines only, so the preview never ends mid-row
        nl = cut.rfind("\n")
        out["output"] = cut[:nl + 1] if nl > 0 else cut
        out["truncated"] = True
    else:
        out["truncated"] = False
    return out


# A DLL can export tens of thousands of symbols; rendering them all would lock up
# the browser. Keep the first N entries but always report the true total.
EAT_PREVIEW_ENTRIES = 2000


def clip_eat(eat: dict) -> dict:
    if not eat:
        return {}
    out = dict(eat)
    entries = out.get("entries") or []
    out["entries_total"] = len(entries)
    if len(entries) > EAT_PREVIEW_ENTRIES:
        out["entries"] = entries[:EAT_PREVIEW_ENTRIES]
        out["entries_truncated"] = True
    else:
        out["entries_truncated"] = False
    return out


def build_stix_section(args, capa: dict, cti_summary: dict) -> dict:
    """The "ATT&CK / STIX" section: object graph + Navigator layer.

    Prefers the bundle the analyzer wrote (exports/stix/<stem>_stix21.json), so
    the panel shows the layer that will actually be shared with other tools.
    When that file is missing - an older run, a skipped export - the techniques
    capa matched are turned into real STIX attack-pattern / x-mitre-tactic
    objects instead, so a sample with TTPs never renders an empty section.
    """
    empty = {"available": False, "source": "", "synthesized": False,
             "graph": {"nodes": [], "edges": [], "details": {},
                       "stats": {"objects": 0, "nodes": 0, "edges": 0,
                                 "techniques": 0, "tactics": 0}},
             "layer": {}, "layer_note": "", "tactics": []}

    if stix_graph is None:
        empty["reason"] = STIX_IMPORT_ERROR
        return empty

    empty["tactics"] = [{"short": s, "name": n} for s, n in stix_graph.TACTICS]

    objects: list[dict] = []
    source = ""
    # The analyzer passes these paths unconditionally, so a run with nothing to
    # export (no techniques, no indicators) simply leaves the file absent -
    # that is not worth a warning. A file that IS there but will not parse is.
    if args.stix and Path(args.stix).is_file():
        objects, error = stix_graph.load_bundle(args.stix)
        if error:
            print(f"warn: stix: {error}", file=sys.stderr)
            objects = []
        elif objects:
            source = Path(args.stix).name

    synthesized = False
    if not objects:
        objects = stix_graph.graph_from_capa(capa)
        if objects:
            synthesized = True
            source = "capa"

    if not objects:
        empty["reason"] = ("no STIX bundle was supplied and capa matched no ATT&CK "
                           "techniques for this sample")
        return empty

    # The analyzer's own bundle carries technique IDs and little else; the CTI
    # phase has already cached the MITRE bundle, so fill in the real names,
    # descriptions and tactics from it when it is available.
    knowledge: dict = {}
    want = {t for obj in objects for t in stix_graph.technique_ids(obj)}
    if want:
        knowledge = stix_graph.load_attack_knowledge(want=want)
        if knowledge:
            filled = stix_graph.enrich_objects(objects, knowledge)
            if filled:
                print(f"[*] stix: enriched {filled} technique(s) from the ATT&CK cache",
                      file=sys.stderr)

    # Tactics are looked up unfiltered: there are ~15 of them, and without this
    # a tactic node has no prose to show, only its own name.
    tactic_knowledge = stix_graph.load_tactic_knowledge()
    if tactic_knowledge:
        filled_tactics = stix_graph.enrich_tactics(objects, tactic_knowledge)
        if filled_tactics:
            print(f"[*] stix: enriched {filled_tactics} tactic(s) from the ATT&CK cache",
                  file=sys.stderr)

    meta = {
        "name": Path(args.stix).name if args.stix else (args.out_name or "sample"),
        "source": args.stix or "",
        "stem": args.out_name or "sample",
        "attack_version": str((cti_summary.get("versions") or {}).get("mitre_attack") or ""),
        "synthesized_from": "capa" if synthesized else "",
    }
    section = stix_graph.build_payload(objects, meta, tactic_knowledge)
    section["available"] = True
    section["source"] = source
    section["synthesized"] = synthesized

    # The analyzer's own layer is authoritative when present: it carries the
    # ATT&CK version the CTI phase resolved and is the file on disk.
    nav = load_json(args.navigator)
    if isinstance(nav, dict) and nav.get("techniques"):
        section["layer"] = nav
        section["layer_note"] = ""
    # The layer is used verbatim, but a comment that is just the technique ID
    # means the CTI lookup found nothing - the cache can still name it.
    stix_graph.enrich_layer(section["layer"], knowledge)

    # Build the FULL ATT&CK Navigator layer with ALL techniques from the MITRE
    # knowledge base. This provides a complete reference matrix independent of
    # the sample's findings.
    attack_version = str((cti_summary.get("versions") or {}).get("mitre_attack") or "")
    full_layer, full_layer_error = stix_graph.build_full_navigator_layer(attack_version)
    if full_layer:
        section["full_layer"] = full_layer
        section["full_layer_note"] = full_layer_error or ""
    else:
        section["full_layer"] = {}
        section["full_layer_note"] = full_layer_error or "Could not load full ATT&CK matrix"

    return section


def build_payload(args) -> dict:
    fileinfo = load_json(args.fileinfo) or {}
    hashj = load_json(args.hash) or {}
    ioc = load_json(args.ioc) or {}
    extraction = load_json(args.extraction) or {}
    capa = load_json(args.capa) or {}
    iat = load_json(args.iat) or {}
    got = load_json(args.got) or {}
    radare2 = load_json(args.radare2) or {}
    malapi = load_json(args.malapi) or []
    asm = load_json(args.asm_json) or []
    cti_doc = load_json_maybe_wrapped(getattr(args, "cti", ""))
    cti_index = build_cti_index(cti_doc)
    geo = build_geo(ioc, cti_index, load_country_aliases())
    files = build_file_catalog(getattr(args, "files_root", ""),
                               max(256 * 1024, args.max_embed_bytes // 8))

    dlls: dict[str, list] = {}
    for e in (iat.get("entries") or []):
        name = e.get("name") or (f"#{e.get('ordinal')}" if e.get("ordinal") else "")
        if not name:
            continue
        dlls.setdefault(e.get("dll") or "(unknown)", []).append({
            "name": name,
            "is_delay": bool(e.get("is_delay")),
            "is_ordinal": bool(e.get("is_ordinal")),
        })

    flagged = set()
    mal_rows = []
    for h in (malapi if isinstance(malapi, list) else []):
        fn = h.get("function", "")
        flagged.add(fn)
        data = h.get("data") or {}
        mal_rows.append({"function": fn,
                         "data": data if isinstance(data, (dict, list)) else {"raw": str(data)}})

    # Prefer the cgraph-normalized graphs.json when it is present: it is the
    # reference parser and gets edges right, where the regex fallback below
    # undercounts and misreads "->" inside labels. Fall back automatically.
    graphs_json = load_graphs_json(getattr(args, "graphs_json", ""),
                                   getattr(args, "out_name", ""))
    if graphs_json:
        callgraph = graphs_json.get("callgraph") or {"nodes": [], "edges": []}
        section_graph = graphs_json.get("section") or {"nodes": [], "edges": []}
        # Only regex-parse what the JSON did not supply.
        if not graphs_json.get("callgraph"):
            callgraph = parse_dot(read_text(args.callgraph))
        if not graphs_json.get("section"):
            section_graph = parse_dot(read_text(args.section_dot))
    else:
        callgraph = parse_dot(read_text(args.callgraph))
        section_graph = parse_dot(read_text(args.section_dot))

    # VT-style threat graph (info blocks connected to the sample).
    t_nodes = []
    t_links = []
    root = "root"

    def add_node(nid, label, ntype, sub="", results=None):
        node = {"id": nid, "label": label, "type": ntype, "sub": sub}
        if results is not None:
            node["results"] = results
        t_nodes.append(node)
        t_links.append({"source": root, "target": nid})

    def add_link(a, b, kind=""):
        if a and b:
            t_links.append({"source": a, "target": b, "kind": kind})

    sha = hashj.get("sha256", "")
    sample_results = [
        {"type": "hash", "value": sha},
        {"type": "tlsh", "value": hashj.get("tlsh", "")},
        {"type": "fileinfo", "entry": {
            "filename": fileinfo.get("filename"),
            "size_human": fileinfo.get("size_human"),
            "size": fileinfo.get("size"),
            "file_magic": fileinfo.get("file_magic"),
            "format": fileinfo.get("format"),
            "is_executable": fileinfo.get("is_executable"),
        }},
        {"type": "extraction_summary", "entry": extraction.get("summary") or {}},
    ]
    t_nodes.append({"id": root, "label": fileinfo.get("filename") or "sample",
                    "type": "sample", "sub": short_hash(sha, 24),
                    "results": sample_results})

    # radare2 analysis info block (rabin2-style binary analysis)
    r2_counts = radare2.get("counts") or {}
    add_node("r2:analysis", "radare2 / rabin2", "analysis",
             f"{r2_counts.get('functions', 0)} functions, {r2_counts.get('files', 0)} files",
             [{"type": "analysis", "entry": r2_counts},
              {"type": "files", "entry": radare2.get("files") or []},
              {"type": "entrypoint", "value": (extraction.get("summary") or {}).get("entrypoint", "")}])

    # top functions as info blocks
    fns_sorted = sorted((radare2.get("functions") or []),
                        key=lambda x: -(x.get("size") or 0))
    for fn in fns_sorted[:20]:
        off = fn.get("offset") or 0
        blk = fn.get("blocks")
        blk_n = blk if isinstance(blk, int) else (len(blk) if isinstance(blk, list) else 0)
        add_node(f"fn:{off}", fn.get("name") or f"fn_{off:x}", "function",
                 f"{fn.get('size', 0)} B · {blk_n} blocks",
                 [{"type": "function", "entry": {
                     "name": fn.get("name"), "offset": off,
                     "size": fn.get("size"), "blocks": blk_n,
                     "is_pure": fn.get("is_pure")}}])

    sec_details = extraction.get("sections", {}).get("details") or []
    for s in sec_details[:24]:
        add_node("sec:" + (s.get("name") or "?"),
                 s.get("name") or "?", "section",
                 f"H={s.get('entropy', 0):.2f}",
                 [{"type": "section", "entry": s}])

    dll_ids = {}
    for dll, imps in list(dlls.items())[:24]:
        nid = "dll:" + dll
        hits = [i for i in imps if i["name"] in flagged]
        add_node(nid, dll, "dll",
                 f"{len(imps)} imports" + (f", {len(hits)} flagged" if hits else ""),
                 [{"type": "import_list", "dll": dll,
                   "imports": [{"name": i["name"],
                                "flagged": i["name"] in flagged,
                                "delay": i.get("is_delay"),
                                "ordinal": i.get("is_ordinal")} for i in imps]}])
        dll_ids[dll] = nid

    for cap in (capa.get("capabilities") or [])[:40]:
        ns = cap.get("namespace") or "misc"
        add_node("cap:" + ns + ":" + (cap.get("name") or ""),
                 cap.get("name") or "?", "capability", ns,
                 [{"type": "capability", "entry": cap}])

    ioc_nodes = {"domain": {}, "ip": {}, "url": {}}
    for d in (ioc.get("domains") or [])[:40]:
        nid = "ioc:domain:" + d
        add_node(nid, d, "ioc", "domain",
                 [{"type": "ioc", "kind": "domain", "value": d}])
        ioc_nodes["domain"][d] = nid
    for ip in (ioc.get("ips") or [])[:40]:
        nid = "ioc:ip:" + ip
        add_node(nid, ip, "ioc", "ip",
                 [{"type": "ioc", "kind": "ip", "value": ip}])
        ioc_nodes["ip"][ip] = nid
    for u in (ioc.get("urls") or [])[:40]:
        nid = "ioc:url:" + u[:70]
        add_node(nid, u[:70], "ioc", "url",
                 [{"type": "ioc", "kind": "url", "value": u}])
        ioc_nodes["url"][u[:70]] = nid
    for e in (ioc.get("emails") or [])[:20]:
        nid = "ioc:email:" + e
        add_node(nid, e, "ioc", "email",
                 [{"type": "ioc", "kind": "email", "value": e}])

    fam_node_ids = {}
    for fh in (ioc.get("family_hits") or [])[:40]:
        kw = fh.get("keyword") or "?"
        if kw in fam_node_ids:
            continue
        nid = "fam:" + kw
        add_node(nid, kw, "family", fh.get("classification") or "",
                 [{"type": "family", "entry": fh}])
        fam_node_ids[kw] = nid

    for row in mal_rows[:60]:
        nid = "mal:" + row["function"]
        data = row.get("data") or {}
        attacks = data.get("attacks") or []
        add_node(nid, row["function"], "malicious",
                 ", ".join(attacks[:3]) if attacks else "malapi hit",
                 [{"type": "malapi", "entry": row}])
        for dll, imps in dlls.items():
            if row["function"] in {i["name"] for i in imps}:
                add_link(nid, dll_ids.get(dll), "import")
                break

    for kw, fid in fam_node_ids.items():
        kwl = kw.lower()
        if not kwl:
            continue
        for kind, mapping in ioc_nodes.items():
            for val, nid in mapping.items():
                if kwl in val.lower():
                    add_link(fid, nid, "found in")

    # ----------------------------------------------------------------------
    # Pre-aggregated chart data for the inline canvas chart library.
    # ----------------------------------------------------------------------
    charts = {}
    hist = extraction.get("opcodes", {}).get("histogram") or {}
    counts = hist.get("counts") or []
    op_pairs = [("0x%02x" % i, c) for i, c in enumerate(counts) if c > 0]
    op_pairs.sort(key=lambda x: x[1], reverse=True)
    charts["opcodes"] = {"labels": [p[0] for p in op_pairs[:16]],
                         "values": [p[1] for p in op_pairs[:16]]}

    sec_ent = extraction.get("sections", {}).get("entropy") or {}
    charts["section_entropy"] = {
        "labels": sec_ent.get("labels", []),
        "values": [round(v, 2) for v in (sec_ent.get("values") or [])]}
    sec_sz = extraction.get("sections", {}).get("size") or {}
    charts["section_size"] = {
        "labels": sec_sz.get("labels", []),
        "values": sec_sz.get("values") or []}

    isum = ioc.get("summary") or {}
    ioc_pairs = []
    for label, key in [("URLs", "urls"), ("Domains", "domains"), ("IPs", "ips"),
                       ("Emails", "emails"), ("MD5", "md5"), ("SHA-1", "sha1"),
                       ("SHA-256", "sha256")]:
        v = isum.get(key, 0)
        if v:
            ioc_pairs.append((label, v))
    charts["ioc_counts"] = {"labels": [p[0] for p in ioc_pairs],
                            "values": [p[1] for p in ioc_pairs]}

    scope_counts = {}
    for c in (capa.get("capabilities") or []):
        s = c.get("scope") or "unknown"
        scope_counts[s] = scope_counts.get(s, 0) + 1
    charts["capability_scope"] = {"labels": list(scope_counts),
                                  "values": list(scope_counts.values())}

    imp_pairs = sorted(((dll, len(imps)) for dll, imps in dlls.items()),
                       key=lambda x: x[1], reverse=True)
    charts["imports_per_dll"] = {
        "labels": [p[0] for p in imp_pairs[:15]],
        "values": [p[1] for p in imp_pairs[:15]]}

    # mnemonic "opcodes" from disassembly (mov/call/lea…) — what analysts expect
    mn_counts: dict[str, int] = {}
    for fn in (asm or []):
        for o in (fn.get("ops") or []):
            dis = (o.get("disasm") or "").split()
            if dis:
                mn_counts[dis[0]] = mn_counts.get(dis[0], 0) + 1
    mn_pairs = sorted(mn_counts.items(), key=lambda x: x[1], reverse=True)
    charts["mnemonics"] = {"labels": [p[0] for p in mn_pairs[:16]],
                           "values": [p[1] for p in mn_pairs[:16]]}

    # largest functions (size)
    fn_pairs = sorted(((f.get("name") or "?", f.get("size") or 0)
                       for f in (asm or [])), key=lambda x: -x[1])
    fn_pairs = [p for p in fn_pairs if p[1] > 0][:12]
    charts["functions"] = {"labels": [p[0] for p in fn_pairs],
                           "values": [p[1] for p in fn_pairs]}

    cti_summary = {}
    if isinstance(cti_doc, dict):
        csum = cti_doc.get("summary") or {}
        corr = cti_doc.get("correlation") or {}
        raw_providers = cti_doc.get("providers")
        providers = []
        if isinstance(raw_providers, list):
            for p in raw_providers[:40]:
                if isinstance(p, dict):
                    providers.append({"provider": p.get("provider") or "?",
                                      "queries": p.get("queries") or 0,
                                      "answers": p.get("answers") or 0,
                                      "errors": p.get("errors") or 0,
                                      "malicious": p.get("malicious") or 0,
                                      "suspicious": p.get("suspicious") or 0,
                                      "cache_hits": p.get("cache_hits") or 0})
                else:
                    providers.append({"provider": str(p)[:40]})
        elif isinstance(raw_providers, dict):
            providers = [{"provider": str(k)[:40]} for k in sorted(raw_providers.keys())[:40]]
        cti_summary = {
            "generated_at": cti_doc.get("generated_at") or "",
            "seconds": cti_doc.get("seconds") or 0,
            "artifacts": csum.get("artifacts") or 0,
            "by_type": csum.get("by_type") or {},
            "by_verdict": csum.get("by_verdict") or {},
            "provider_errors": csum.get("provider_errors") or 0,
            "providers": providers,
            "versions": cti_doc.get("versions") or {},
            "warnings": (cti_doc.get("warnings") or [])[:12],
            "kev_cves": (cti_doc.get("kev_cves") or corr.get("cisa_kev") or [])[:24],
            "asn_clusters": (cti_doc.get("asn_clusters") or corr.get("asn_clusters") or [])[:12],
            "shared_hosting": (cti_doc.get("shared_hosting") or corr.get("shared_hosting") or [])[:12],
            "likely_groups": (cti_doc.get("likely_groups") or corr.get("likely_groups") or [])[:8],
            "malware_families": (cti_doc.get("malware_families")
                                 or corr.get("malware_families") or [])[:12],
        }

    packed = bool(extraction.get("packing", {}).get("packed"))
    score = 0
    score += 30 if packed else 0
    score += min(40, 4 * len(mal_rows))
    score += min(20, 2 * len(ioc.get("domains") or []) + 2 * len(ioc.get("ips") or []))
    score += min(10, 2 * len(ioc.get("family_hits") or []))
    score = min(100, score)
    verdict = ("malicious" if score >= 60 else
               "suspicious" if score >= 25 else "clean")

    embed_budget = args.max_embed_bytes
    asm_embed, asm_size = clamp_bytes(asm, max(1024, embed_budget // 2))
    asm_truncated = asm_embed is None

    return {
        "meta": {
            "generated_at": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
            "stem": args.out_name or "sample",
        },
        "verdict": {"score": score, "label": verdict, "packed": packed},
        "fileinfo": fileinfo,
        "hash": hashj,
        "ioc": ioc,
        "capa": {
            "capa": capa.get("capa") or {},
            "counts": capa.get("counts") or {},
            "capabilities": capa.get("capabilities") or [],
            "attack_ids": capa.get("attack_ids") or [],
            "mbc_ids": capa.get("mbc_ids") or [],
        },
        "imports": {"dlls": dlls, "summary": iat.get("summary") or {}},
        "got": got,
        "extraction": {
            "summary": extraction.get("summary") or {},
            "sections": extraction.get("sections") or {},
            "guards": extraction.get("guards") or {},
            "packing": extraction.get("packing") or {},
            "signature": extraction.get("signature") or {},
            "debug": extraction.get("debug") or {},
            "opcodes": extraction.get("opcodes") or {},
            "yara": extraction.get("yara") or {},
            "cminer": extraction.get("cminer") or {},
            "xxd": clip_xxd(extraction.get("xxd") or {}),
            # The EAT lives at raw.pe.export_table in the extraction JSON.
            "export_table": clip_eat(
                ((extraction.get("raw") or {}).get("pe") or {}).get("export_table") or {}),
        },
        "radare2": {
            "functions": radare2.get("functions") or [],
            "files": radare2.get("files") or [],
            "counts": radare2.get("counts") or {},
        },
        "malapi": mal_rows,
        "asm": asm_embed or [],
        "asm_truncated": asm_truncated,
        "asm_bytes": asm_size,
        "graphs": {"callgraph": callgraph, "section": section_graph},
        "threat_graph": {"nodes": t_nodes, "links": t_links},
        "cti": cti_summary,
        "geo": geo,
        "stix": build_stix_section(args, capa, cti_summary),
        "charts": charts,
        "files": files,
    }


def verify_mappings(args, payload) -> list[str]:
    """Verify that all non-empty artifacts are mapped into the dashboard payload.

    Returns a list of human-readable issue strings (empty list = all good).
    """
    issues = []

    def has_data(obj):
        return obj is not None and obj != "" and obj != [] and obj != {}

    mappings = [
        ("fileinfo", lambda: payload.get("fileinfo"), "payload.fileinfo"),
        ("hash", lambda: payload.get("hash"), "payload.hash"),
        ("ioc", lambda: payload.get("ioc"), "payload.ioc"),
        ("extraction", lambda: payload.get("extraction"), "payload.extraction"),
        ("capa", lambda: payload.get("capa"), "payload.capa"),
        ("iat", lambda: payload.get("imports", {}).get("summary"), "payload.imports.summary"),
        ("got", lambda: payload.get("got"), "payload.got"),
        ("radare2", lambda: payload.get("radare2"), "payload.radare2"),
        ("malapi", lambda: payload.get("malapi"), "payload.malapi"),
        ("callgraph", lambda: payload.get("graphs", {}).get("callgraph"), "payload.graphs.callgraph"),
        ("section_dot", lambda: payload.get("graphs", {}).get("section"), "payload.graphs.section"),
        ("threat_graph", lambda: payload.get("threat_graph"), "payload.threat_graph"),
        ("cti", lambda: payload.get("geo", {}).get("items") or payload.get("cti"),
         "payload.geo / payload.cti"),
        ("stix", lambda: payload.get("stix", {}).get("graph", {}).get("nodes"),
         "payload.stix.graph.nodes"),
        ("navigator", lambda: payload.get("stix", {}).get("layer", {}).get("techniques"),
         "payload.stix.layer.techniques"),
    ]

    # When graphs.json supplies a graph, the .dot file for it is optional, so
    # don't demand raw data that the caller deliberately did not pass.
    from_json = load_graphs_json(getattr(args, "graphs_json", ""),
                                 getattr(args, "out_name", ""))

    for flag_name, accessor, payload_path in mappings:
        # A graph satisfied from graphs.json needs no corresponding .dot.
        if flag_name == "callgraph" and from_json.get("callgraph"):
            continue
        if flag_name == "section_dot" and from_json.get("section"):
            continue
        raw = (read_text(getattr(args, flag_name, ""))
               if flag_name in ("callgraph", "section_dot")
               else load_json(getattr(args, flag_name, "")))
        mapped = accessor()
        if has_data(raw) and not has_data(mapped):
            issues.append(f"{flag_name}: data exists but {payload_path} is empty or missing")

    # Assembly is special: it may be intentionally truncated.
    asm_raw = load_json(args.asm_json)
    if has_data(asm_raw) and not payload.get("asm") and not payload.get("asm_truncated"):
        issues.append(f"asm_json: data exists but payload.asm is empty and asm_truncated=False")

    return issues


def main() -> int:
    ap = argparse.ArgumentParser(add_help=True)
    for flag in ("fileinfo", "hash", "ioc", "extraction", "capa", "iat", "got",
                 "radare2", "malapi", "cti", "stix", "navigator",
                 "out-dir", "out-name"):
        ap.add_argument("--" + flag, default="")
    ap.add_argument("--asm-json", default="")
    ap.add_argument("--callgraph", default="")
    ap.add_argument("--section-dot", default="")
    ap.add_argument("--graphs-json", default="",
                    help="cgraph-normalized graphs.json from dot2json; "
                         "falls back to regex parsing of the .dot files")
    ap.add_argument("--files-root", default="")
    ap.add_argument("--max-embed-bytes", type=int, default=24 * 1024 * 1024)
    ap.add_argument("--verify", action="store_true",
                    help="Verify that all non-empty artifacts are mapped into the payload")
    args = ap.parse_args()

    here = Path(__file__).resolve().parent
    template_dir = here / "templates"
    template_name = "dashboard.html.j2"
    if not (template_dir / template_name).is_file():
        print(f"error: template not found: {template_dir / template_name}", file=sys.stderr)
        return 2

    payload = build_payload(args)

    if args.verify:
        issues = verify_mappings(args, payload)
        if issues:
            print("VERIFICATION FAILED:", file=sys.stderr)
            for msg in issues:
                print(f"  - {msg}", file=sys.stderr)
            print(f"\n{len(issues)} mapping issue(s)", file=sys.stderr)
        else:
            print("VERIFICATION OK: all artifact mappings present")

    d3_path = here / "d3.min.js"
    d3_src = ""
    if d3_path.is_file():
        try:
            d3_src = d3_path.read_text(encoding="utf-8")
        except Exception:
            d3_src = ""

    def json_asset(name: str) -> str:
        """Inline a vendored JSON asset as text for a <script type="application/json">.

        ``<`` is escaped because the payload must never terminate its script tag
        early; the files are JSON, so \\u003c stays valid inside strings.
        """
        p = here / name
        if not p.is_file():
            print(f"warn: asset missing: {p}", file=sys.stderr)
            return ""
        try:
            return p.read_text(encoding="utf-8").replace("<", "\\u003c")
        except Exception as exc:
            print(f"warn: cannot read {p}: {exc}", file=sys.stderr)
            return ""

    env = Environment(
        loader=FileSystemLoader(str(template_dir)),
        autoescape=select_autoescape(enabled_extensions=("html",), default=False),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    template = env.get_template(template_name)
    html = template.render(payload=payload,
                           payload_json=json.dumps(payload, separators=(",", ":"))
                                            .replace("<", "\\u003c"),
                           d3_src=d3_src,
                           world_json=json_asset("world-110m.json"),
                           country_json=json_asset("country-codes.json"))

    out_dir = Path(args.out_dir or "exports/dashboard")
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{(args.out_name or 'sample')}.html"
    out_path.write_text(html, encoding="utf-8")

    print(str(out_path))
    return 0


if __name__ == "__main__":
    sys.exit(main())