#!python3
"""Shared STIX 2.1 payload builder: objects -> graph + ATT&CK Navigator layer.

Used by two entry points so the graph logic exists exactly once:

    python/_view_stix.py      standalone viewer, any STIX 2.1 bundle
    python/_create_dashboard.py   the "ATT&CK / STIX" section of the dashboard

Deliberately **stdlib only** (no stix2, no jinja2).  The viewer has to open
arbitrary bundles - hand-written ones, OTX / MISP / MITRE exports, partial
files whose references dangle - so objects are read leniently as plain dicts
instead of being validated into typed classes.  Nothing here raises on an odd
object; anything unrecognised is skipped and counted.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

# ---------------------------------------------------------------------------
# ATT&CK enterprise tactics, in kill-chain order.
# ---------------------------------------------------------------------------

TACTICS: list[tuple[str, str]] = [
    ("reconnaissance",       "Reconnaissance"),
    ("resource-development", "Resource Development"),
    ("initial-access",       "Initial Access"),
    ("execution",            "Execution"),
    ("persistence",          "Persistence"),
    ("privilege-escalation", "Privilege Escalation"),
    ("stealth",              "Stealth"),
    ("defense-impairment",   "Defense Impairment"),
    ("credential-access",    "Credential Access"),
    ("discovery",            "Discovery"),
    ("lateral-movement",     "Lateral Movement"),
    ("collection",           "Collection"),
    ("command-and-control",  "Command and Control"),
    ("exfiltration",         "Exfiltration"),
    ("impact",               "Impact"),
]
TACTIC_ORDER = {short: i for i, (short, _) in enumerate(TACTICS)}
TACTIC_NAMES = dict(TACTICS)

# Spellings seen in the wild that are not just a case/space variation of the
# shortname.  capa emits the display name ("Defense Evasion"); some tools emit
# "C2" or "Command & Control".  ATT&CK v19 renamed "defense-evasion" to
# "stealth", but every capa rule still tags the old name, so fold it across
# instead of dropping those techniques.
TACTIC_ALIASES = {
    "c2": "command-and-control",
    "c2-command-and-control": "command-and-control",
    "command-and-control-c2": "command-and-control",
    "recon": "reconnaissance",
    "resource-development-and-prep": "resource-development",
    "privilege-escalation-and-defense-evasion": "privilege-escalation",
    "defense-evasion": "stealth",
    "defense-evasion-and-privilege-escalation": "stealth",
    "command-and-control-and-exfiltration": "command-and-control",
    "exploit-public-facing-application": "initial-access",
    "unassigned": "",
}

# STIX object types worth giving a friendly group label in the UI.
TYPE_LABELS = {
    "attack-pattern":    "ATT&CK Technique",
    "x-mitre-tactic":    "ATT&CK Tactic",
    "course-of-action":  "Mitigation",
    "indicator":         "Indicator",
    "malware":           "Malware",
    "tool":              "Tool",
    "vulnerability":     "Vulnerability",
    "identity":          "Identity",
    "relationship":      "Relationship",
    "report":            "Report",
    "intrusion-set":     "Intrusion Set",
    "campaign":          "Campaign",
    "infrastructure":    "Infrastructure",
    "observed-data":     "Observed Data",
    "file":              "File",
    "domain-name":       "Domain",
    "ipv4-addr":         "IPv4 Address",
    "ipv6-addr":         "IPv6 Address",
    "url":               "URL",
    "email-addr":        "E-mail",
    "user-account":      "User Account",
    "process":           "Process",
    "x-mitre-collection": "ATT&CK Collection",
}

MAX_LABEL = 68
MAX_DETAIL_STRING = 2500

# The analyzer's own bundle (src/net/cti.cpp) carries a technique's ID and
# nothing else, and the CTI phase already caches the full MITRE bundle.  When
# that cache is on disk the viewer enriches from it so a technique shows its
# real name, description and tactics instead of a bare "T1129".
DEFAULT_ATTACK_CACHE = (Path(__file__).resolve().parent.parent
                        / "cti-cache" / "knowledge" / "enterprise-attack.json")

# Which objects survive build_graph()'s node cap, lowest value first. An
# analysis bundle is mostly identities and marking-definitions; the ATT&CK
# structure is what a reader came for.
NODE_PRIORITY = {
    "attack-pattern": 0,
    "x-mitre-tactic": 0,
    "malware": 1,
    "indicator": 1,
    "vulnerability": 1,
    "course-of-action": 2,
    "tool": 2,
    "intrusion-set": 2,
    "campaign": 2,
    "identity": 4,
    "marking-definition": 9,
}


def type_label(stix_type: str) -> str:
    return TYPE_LABELS.get(stix_type, stix_type.replace("-", " ").title())


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------

def load_bundle(path: str | Path) -> tuple[list[dict], str]:
    """Read a STIX file and return (objects, error).

    Accepts a bundle, a bare list, or a single object.  ``error`` is "" on
    success; the caller decides how loudly to complain.
    """
    p = Path(path)
    if not p.is_file():
        return [], f"not found: {p}"
    try:
        with p.open("r", encoding="utf-8") as fh:
            doc = json.load(fh)
    except Exception as exc:
        return [], f"cannot parse {p}: {exc}"

    if isinstance(doc, list):
        return [o for o in doc if isinstance(o, dict)], ""
    if isinstance(doc, dict):
        objs = doc.get("objects")
        if isinstance(objs, list):
            return [o for o in objs if isinstance(o, dict)], ""
        if isinstance(doc.get("type"), str):
            return [doc], ""
        return [], f"{p} has no 'objects' list (not a STIX bundle)"
    return [], f"{p} is not a STIX bundle"


# ---------------------------------------------------------------------------
# Small accessors - every one tolerates a malformed object
# ---------------------------------------------------------------------------

def _trim(text: str, limit: int = MAX_LABEL) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def external_id(obj: dict) -> str:
    """The MITRE ATT&CK id (T####/T####.###), or any other external id."""
    for ref in obj.get("external_references") or []:
        if not isinstance(ref, dict):
            continue
        eid = ref.get("external_id")
        if isinstance(eid, str) and eid:
            if ref.get("source_name") == "mitre-attack":
                return eid.upper()
    for ref in obj.get("external_references") or []:
        if isinstance(ref, dict) and isinstance(ref.get("external_id"), str):
            return ref["external_id"]
    return ""


def technique_ids(obj: dict) -> list[str]:
    """Every ATT&CK id referenced by an object (usually zero or one)."""
    out: list[str] = []
    for ref in obj.get("external_references") or []:
        if not isinstance(ref, dict):
            continue
        eid = ref.get("external_id")
        if isinstance(eid, str) and re.fullmatch(r"T\d{4}(?:\.\d{3})?", eid.strip(), re.I):
            out.append(eid.strip().upper())
    return out


def normalise_tactic(raw) -> str:
    """Any tactic spelling -> the lowercase-hyphen shortname ("" if unknown)."""
    if not isinstance(raw, str) or not raw.strip():
        return ""
    key = raw.strip().lower()
    key = re.sub(r"[\s_]+", "-", key)
    key = re.sub(r"-+", "-", key).strip("-")
    key = key.replace("&", "and")
    key = re.sub(r"-+", "-", key).strip("-")
    if key in TACTIC_ALIASES:
        return TACTIC_ALIASES[key]
    return key if key in TACTIC_ORDER else ""


def phases_of(obj: dict) -> list[str]:
    """mitre-attack kill-chain phases of an object, normalised, order kept."""
    out: list[str] = []
    for phase in obj.get("kill_chain_phases") or []:
        if not isinstance(phase, dict):
            continue
        if phase.get("kill_chain_name") not in (None, "", "mitre-attack"):
            continue
        short = normalise_tactic(phase.get("phase_name"))
        if short and short not in out:
            out.append(short)
    return out


# ---------------------------------------------------------------------------
# ATT&CK knowledge enrichment
# ---------------------------------------------------------------------------

def _ref_url(obj: dict, source: str = "mitre-attack") -> str:
    for ref in obj.get("external_references") or []:
        if isinstance(ref, dict) and ref.get("source_name") == source:
            url = ref.get("url")
            if isinstance(url, str) and url:
                return url
    return ""


def load_attack_knowledge(path=None, want: set[str] | None = None) -> dict[str, dict]:
    """Index a MITRE ATT&CK bundle by technique ID.

    Returns ``{tid: {name, description, tactics, platforms, url, detection,
    mitigations}}``.  ``want`` restricts the index to the technique IDs the
    caller actually holds, so a 50 MB enterprise bundle does not become a 50 MB
    python dict.  A missing or unreadable cache is not an error - the caller
    simply gets no knowledge and renders the objects exactly as they came in.
    """
    p = Path(path) if path else DEFAULT_ATTACK_CACHE
    try:
        if not p.is_file():
            return {}
        with p.open("r", encoding="utf-8") as fh:
            doc = json.load(fh)
    except Exception:
        return {}
    objs = doc.get("objects") if isinstance(doc, dict) else doc
    if not isinstance(objs, list):
        return {}

    by_id: dict[str, dict] = {}
    id_to_tid: dict[str, str] = {}
    for obj in objs:
        if not isinstance(obj, dict):
            continue
        oid = obj.get("id")
        stix_type = obj.get("type")
        if not isinstance(oid, str):
            continue
        # Only these two types are ever looked up again.  Retaining the other
        # ~30k objects would mean holding the whole enterprise bundle in
        # memory for a handful of techniques.
        if stix_type == "attack-pattern":
            tid = external_id(obj)
            if tid:
                id_to_tid[oid] = tid
                by_id[oid] = obj
        elif stix_type == "course-of-action":
            by_id[oid] = obj

    index: dict[str, dict] = {}
    for oid, tid in id_to_tid.items():
        if want is not None and tid not in want:
            continue
        obj = by_id[oid]
        info: dict = {
            "name": str(obj.get("name") or tid),
            "tactics": phases_of(obj),
            "mitigations": [],
        }
        desc = obj.get("description")
        if isinstance(desc, str) and desc.strip():
            info["description"] = desc.strip()[:MAX_DETAIL_STRING]
        platforms = obj.get("x_mitre_platforms")
        if isinstance(platforms, list):
            info["platforms"] = [str(x) for x in platforms if isinstance(x, str)]
        detection = obj.get("x_mitre_detection")
        if isinstance(detection, str) and detection.strip():
            info["detection"] = detection.strip()[:MAX_DETAIL_STRING]
        url = _ref_url(obj)
        if url:
            info["url"] = url
        index[tid] = info

    # "mitigates" lives in relationship objects, one hop away from the
    # technique, so it needs its own pass.
    for obj in objs:
        if not isinstance(obj, dict) or obj.get("type") != "relationship":
            continue
        if obj.get("relationship_type") != "mitigates":
            continue
        tid = id_to_tid.get(obj.get("target_ref") or "")
        info = index.get(tid) if tid else None
        coa = by_id.get(obj.get("source_ref") or "")
        if info is None or not isinstance(coa, dict):
            continue
        mid = external_id(coa)
        mname = coa.get("name")
        text = f"{mid} {mname}".strip() if isinstance(mname, str) and mname else mid
        if text and text not in info["mitigations"]:
            info["mitigations"].append(text)
    return index


def enrich_objects(objects: list[dict], knowledge: dict[str, dict]) -> int:
    """Fill name / description / tactics on attack-patterns from ATT&CK knowledge.

    Only *missing* fields are filled, so a bundle that already carries real
    content (a MITRE export, a bundle from _extract_stix.py) is never
    overwritten.  Returns the number of objects touched.
    """
    if not knowledge:
        return 0
    filled = 0
    for obj in objects:
        if not isinstance(obj, dict) or obj.get("type") != "attack-pattern":
            continue
        tid = external_id(obj)
        info = knowledge.get(tid)
        if not info:
            continue
        touched = False

        name = obj.get("name")
        # The analyzer writes the technique ID into `name`, which is not a name.
        if not isinstance(name, str) or not name.strip() or name.strip().upper() == tid:
            obj["name"] = info.get("name") or tid
            touched = True
        if not obj.get("description") and info.get("description"):
            obj["description"] = info["description"]
            touched = True
        if not phases_of(obj) and info.get("tactics"):
            obj["kill_chain_phases"] = [
                {"kill_chain_name": "mitre-attack", "phase_name": short}
                for short in info["tactics"]]
            touched = True
        if not obj.get("x_mitre_platforms") and info.get("platforms"):
            obj["x_mitre_platforms"] = list(info["platforms"])
            touched = True
        if not obj.get("x_mitre_detection") and info.get("detection"):
            obj["x_mitre_detection"] = info["detection"]
            touched = True
        if info.get("mitigations"):
            obj["x_mitre_mitigations"] = list(info["mitigations"])
            touched = True
        if info.get("url"):
            for ref in obj.get("external_references") or []:
                if isinstance(ref, dict) and ref.get("source_name") == "mitre-attack":
                    ref["url"] = info["url"]
                    break

        if touched:
            filled += 1
    return filled


def enrich_layer(layer: dict, knowledge: dict[str, dict]) -> int:
    """Swap a technique-ID placeholder comment for the real technique name.

    The analyzer's Navigator layer is authoritative and is used verbatim, but
    when the CTI lookup found nothing it writes the ID into the comment, which
    leaves the coverage matrix reading "T1129".  Returns the number of entries
    rewritten.
    """
    if not knowledge or not isinstance(layer, dict):
        return 0
    changed = 0
    for tech in layer.get("techniques") or []:
        if not isinstance(tech, dict):
            continue
        tid = str(tech.get("techniqueID") or "").strip().upper()
        info = knowledge.get(tid)
        if not info:
            continue
        comment = tech.get("comment")
        if not isinstance(comment, str) or not comment.strip() or comment.strip().upper() == tid:
            tech["comment"] = info.get("name") or tid
            changed += 1
    return changed


def label_of(obj: dict) -> tuple[str, str]:
    """(primary label, secondary label) for a node."""
    stix_type = str(obj.get("type") or "unknown")
    name = obj.get("name")

    if stix_type == "attack-pattern":
        tid = external_id(obj)
        title = name if isinstance(name, str) and name else tid or "technique"
        return _trim(title), tid

    if stix_type == "x-mitre-tactic":
        short = normalise_tactic(obj.get("x_mitre_shortname"))
        title = name if isinstance(name, str) and name else TACTIC_NAMES.get(short, short)
        return _trim(title), short

    if stix_type == "indicator":
        if isinstance(name, str) and name:
            return _trim(name), external_id(obj)
        pattern = obj.get("pattern")
        return (_trim(pattern) if isinstance(pattern, str) else "indicator"), external_id(obj)

    if stix_type == "vulnerability":
        return _trim(name if isinstance(name, str) and name else external_id(obj) or "vulnerability"), ""

    if stix_type == "relationship":
        return str(obj.get("relationship_type") or "relationship"), ""

    if stix_type == "identity":
        return _trim(obj.get("name") or "identity"), obj.get("identity_class") or ""

    if isinstance(name, str) and name:
        return _trim(name), ""
    return stix_type, external_id(obj)


def _detail_of(obj: dict) -> dict:
    """A trimmed copy of an object, for the click-to-detail panel."""
    out: dict = {}
    for key, value in obj.items():
        if key in ("id", "type", "spec_version", "created", "modified",
                   "created_by_ref", "object_marking_refs"):
            continue
        if isinstance(value, str):
            out[key] = value if len(value) <= MAX_DETAIL_STRING else value[:MAX_DETAIL_STRING] + "…"
        elif isinstance(value, (int, float, bool)) or value is None:
            out[key] = value
        elif isinstance(value, list):
            kept = value[:12]
            out[key] = kept
            if len(value) > len(kept):
                out[f"{key}__more"] = len(value) - len(kept)
        elif isinstance(value, dict):
            out[key] = value
    return out


# ---------------------------------------------------------------------------
# Graph
# ---------------------------------------------------------------------------

def build_graph(objects: list[dict], max_nodes: int = 3000) -> dict:
    """objects -> {nodes, edges, details, stats}.

    ``max_nodes`` bounds the embedded payload: the full MITRE enterprise
    bundle is ~25k objects and would otherwise produce an unusable page.
    The cap keeps the types that carry meaning for an analysis (techniques,
    tactics, malware, indicators) ahead of the long tail.
    """
    nodes: list[dict] = []
    details: dict[str, dict] = {}
    node_ids: set[str] = set()
    by_type: dict[str, int] = {}
    tactic_nodes: dict[str, str] = {}     # shortname -> node id

    candidates = [o for o in objects
                  if isinstance(o.get("id"), str) and o.get("id")
                  and isinstance(o.get("type"), str)
                  and o.get("type") != "relationship"]
    truncated = max(0, len(candidates) - max_nodes)
    if truncated:
        candidates.sort(key=lambda o: NODE_PRIORITY.get(str(o.get("type")), 3))

    for obj in candidates:
        if len(nodes) >= max_nodes:
            break
        oid = obj["id"]
        stix_type = obj["type"]
        if oid in node_ids:
            continue

        label, sub = label_of(obj)
        node = {"id": oid, "type": stix_type, "group": stix_type,
                "label": label, "sub": sub}
        if stix_type == "attack-pattern":
            node["tactics"] = phases_of(obj)
            node["technique_id"] = external_id(obj)
            if isinstance(obj.get("x_mitre_is_subtechnique"), bool):
                node["subtechnique"] = obj["x_mitre_is_subtechnique"]
        elif stix_type == "x-mitre-tactic":
            short = normalise_tactic(obj.get("x_mitre_shortname"))
            if short:
                node["tactic"] = short
                tactic_nodes[short] = oid
        elif stix_type == "indicator":
            node["pattern"] = obj.get("pattern") if isinstance(obj.get("pattern"), str) else ""
            node["confidence"] = obj.get("confidence") if isinstance(obj.get("confidence"), int) else None
        if stix_type == "vulnerability":
            node["vulnerability"] = external_id(obj) or str(obj.get("name") or "")

        node_ids.add(oid)
        nodes.append(node)
        details[oid] = _detail_of(obj)
        by_type[stix_type] = by_type.get(stix_type, 0) + 1

    # Explicit relationships.
    edges: list[dict] = []
    seen_edges: set[tuple] = set()
    dropped = 0
    dropped_truncated = 0
    candidate_ids = {o["id"] for o in candidates}
    for obj in objects:
        if obj.get("type") != "relationship":
            continue
        src, dst = obj.get("source_ref"), obj.get("target_ref")
        if not isinstance(src, str) or not isinstance(dst, str):
            dropped += 1
            continue
        if src not in node_ids or dst not in node_ids:
            # An endpoint that exists in the bundle but has no node was cut by
            # the node cap - a different problem from a dangling reference, and
            # worth saying differently in the UI.
            if src in candidate_ids and dst in candidate_ids:
                dropped_truncated += 1
            else:
                dropped += 1
            continue
        key = (src, dst, obj.get("relationship_type"))
        if key in seen_edges:
            continue
        seen_edges.add(key)
        edges.append({"source": src, "target": dst,
                      "label": str(obj.get("relationship_type") or "related-to")})

    # Reference properties.  STIX stores plenty of links as bare id fields
    # rather than relationship objects - a report lists its techniques in
    # object_refs - and the analyzer's own bundle has no relationship objects
    # at all.  Without these the graph renders as a cloud of disconnected dots
    # even though the links are right there in the JSON.
    #
    # created_by_ref is deliberately not followed: in a MITRE-size bundle every
    # object points at the same identity, which is one huge unreadable hairball
    # and no analysis value.
    for obj in objects:
        oid = obj.get("id")
        if not isinstance(oid, str) or oid not in node_ids:
            continue
        for ref in obj.get("object_refs") or []:
            if not isinstance(ref, str) or ref not in node_ids:
                continue
            edge_key = (oid, ref, "object_refs")
            if edge_key in seen_edges:
                continue
            seen_edges.add(edge_key)
            edges.append({"source": oid, "target": ref, "label": "object_refs"})

    # Tactic links.  ATT&CK does not model technique->tactic as a relationship
    # object (it lives in kill_chain_phases), so without this the graph would
    # have no edges at all for a technique-only bundle - which is exactly what
    # `_extract_stix.py` and the analyzer's own bundle look like.
    synthetic = 0
    for node in nodes:
        if node["type"] != "attack-pattern":
            continue
        for short in node.get("tactics") or []:
            target = tactic_nodes.get(short)
            if target is None:
                target = f"x-tactic:{short}"
                if target not in node_ids:
                    node_ids.add(target)
                    nodes.append({"id": target, "type": "x-mitre-tactic",
                                  "group": "x-mitre-tactic",
                                  "label": TACTIC_NAMES.get(short, short),
                                  "sub": short, "tactic": short,
                                  "synthetic": True})
                    details[target] = {"note": "tactic inferred from kill_chain_phases",
                                       "x_mitre_shortname": short}
                    by_type["x-mitre-tactic"] = by_type.get("x-mitre-tactic", 0) + 1
                    synthetic += 1
                tactic_nodes[short] = target
            key = (node["id"], target, "kill-chain-phase")
            if key not in seen_edges:
                seen_edges.add(key)
                edges.append({"source": node["id"], "target": target,
                              "label": "kill-chain-phase"})

    techniques = sum(1 for n in nodes if n["type"] == "attack-pattern")
    return {
        "nodes": nodes,
        "edges": edges,
        "details": details,
        "stats": {
            "objects": len(objects),
            "nodes": len(nodes),
            "edges": len(edges),
            "relationships": sum(1 for o in objects if o.get("type") == "relationship"),
            "dropped_edges": dropped,
            "dropped_truncated": dropped_truncated,
            "techniques": techniques,
            "tactics": len([t for t in tactic_nodes if t]),
            "synthetic_tactics": synthetic,
            "truncated_nodes": truncated,
            "by_type": by_type,
        },
    }


# ---------------------------------------------------------------------------
# ATT&CK Navigator layer
# ---------------------------------------------------------------------------

def navigator_techniques(objects: list[dict]) -> list[dict]:
    """One entry per attack-pattern, expanded once per tactic it belongs to."""
    out: list[dict] = []
    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        tid = external_id(obj)
        if not tid:
            continue
        name = obj.get("name")
        phases = phases_of(obj) or [""]
        for short in phases:
            entry = {
                "techniqueID": tid,
                "tactic": short,
                "enabled": True,
            }
            if isinstance(name, str) and name:
                entry["comment"] = name
            if obj.get("x_mitre_is_subtechnique") is True:
                entry["showSubtechniques"] = True
            out.append(entry)
    return out


def to_navigator_layer(objects: list[dict],
                       name: str = "static_analyzer",
                       description: str = "",
                       attack_version: str = "") -> tuple[dict, str]:
    """Build an ATT&CK Navigator layer (layer format 4.5). Returns (layer, error)."""
    techniques = navigator_techniques(objects)
    if not techniques:
        return {}, "no ATT&CK techniques found in the bundle"

    unassigned = sum(1 for t in techniques if not t["tactic"])
    layer = {
        "name": name,
        # v19 is the oldest release whose matrix uses "stealth" and
        # "defense-impairment"; declaring 14 would hide every such column.
        "versions": {"attack": attack_version or "19", "navigator": "4.9.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": description or
                       "Techniques observed by static_analyzer (capa / CTI enrichment).",
        "techniques": techniques,
        "gradient": {"colors": ["#ffffff", "#ffd166", "#ff9f43", "#ff4d5e"],
                     "minValue": 0, "maxValue": 3},
        "legendItems": [
            {"label": "Observed in this sample", "color": "#ff9f43"},
        ],
        "sorting": 3,
        "layout": {"layout": "side", "showID": True, "showName": True},
        "hideDisabled": True,
    }
    note = ""
    if unassigned:
        note = (f"{unassigned} technique(s) have no kill-chain phase and will appear "
                f"unassigned in the Navigator")
    return layer, note


def build_full_navigator_layer(attack_version: str = "") -> tuple[dict, str]:
    """Build a COMPLETE ATT&CK Navigator layer with ALL enterprise techniques.

    Loads the full MITRE ATT&CK bundle from the cache and creates a layer
    showing every technique organized by tactic. This is useful as a reference
    matrix showing the entire ATT&CK framework, not just the sample's findings.

    Returns (layer, error).
    """
    knowledge = load_attack_knowledge(want=None)  # Load all techniques
    if not knowledge:
        return {}, "MITRE ATT&CK cache not found or unreadable. Run the analyzer with CTI enabled to populate the cache, or place enterprise-attack.json at cti-cache/knowledge/enterprise-attack.json"

    techniques = []
    for tid, info in knowledge.items():
        tactics = info.get("tactics") or [""]
        for short in tactics:
            entry = {
                "techniqueID": tid,
                "tactic": short,
                "enabled": True,
                "comment": info.get("name") or tid,
            }
            # Determine if sub-technique
            if "." in tid:
                entry["showSubtechniques"] = True
            techniques.append(entry)

    if not techniques:
        return {}, "no techniques found in ATT&CK knowledge base"

    unassigned = sum(1 for t in techniques if not t["tactic"])
    layer = {
        "name": "MITRE ATT&CK Enterprise - Full Matrix",
        "versions": {"attack": attack_version or "19", "navigator": "4.9.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "Complete MITRE ATT&CK Enterprise matrix with all techniques and sub-techniques, organized by tactic. Generated from the cached ATT&CK STIX bundle.",
        "techniques": techniques,
        "gradient": {"colors": ["#ffffff", "#e8f5e9", "#a5d6a7", "#4caf50"],
                     "minValue": 0, "maxValue": 1},
        "legendItems": [
            {"label": "All ATT&CK Enterprise Techniques", "color": "#4caf50"},
        ],
        "sorting": 3,
        "layout": {"layout": "side", "showID": True, "showName": True},
        "hideDisabled": True,
    }
    note = ""
    if unassigned:
        note = (f"{unassigned} technique(s) have no kill-chain phase and will appear "
                f"unassigned in the Navigator")
    return layer, note


def build_full_navigator_from_objects(objs: list[dict],
                                       attack_version: str = "") -> tuple[dict, str]:
    """Build a COMPLETE ATT&CK Navigator layer from already-loaded STIX objects.

    This is used when the caller has already loaded the MITRE ATT&CK bundle
    (e.g. _extract_stix.py) and wants to avoid re-reading the file.

    Returns (layer, error).
    """
    # Index attack-pattern objects by technique ID
    by_tid: dict[str, dict] = {}
    for o in objs:
        if not isinstance(o, dict) or o.get("type") != "attack-pattern":
            continue
        for ref in o.get("external_references") or []:
            if (isinstance(ref, dict) and ref.get("source_name") == "mitre-attack"
                    and isinstance(ref.get("external_id"), str)):
                tid = ref["external_id"].upper()
                by_tid[tid] = o
                break

    if not by_tid:
        return {}, "no attack-pattern objects found in the source bundle"

    techniques = []
    for tid, obj in by_tid.items():
        name = obj.get("name") or tid
        phases = phases_of(obj) or [""]
        for short in phases:
            entry = {
                "techniqueID": tid,
                "tactic": short,
                "enabled": True,
                "comment": name,
            }
            if obj.get("x_mitre_is_subtechnique") is True:
                entry["showSubtechniques"] = True
            techniques.append(entry)

    if not techniques:
        return {}, "no techniques found in ATT&CK knowledge base"

    unassigned = sum(1 for t in techniques if not t["tactic"])
    layer = {
        "name": "MITRE ATT&CK Enterprise - Full Matrix",
        "versions": {"attack": attack_version or "19", "navigator": "4.9.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "Complete MITRE ATT&CK Enterprise matrix with all techniques and sub-techniques, organized by tactic. Generated from the provided STIX bundle.",
        "techniques": techniques,
        "gradient": {"colors": ["#ffffff", "#e8f5e9", "#a5d6a7", "#4caf50"],
                     "minValue": 0, "maxValue": 1},
        "legendItems": [
            {"label": "All ATT&CK Enterprise Techniques", "color": "#4caf50"},
        ],
        "sorting": 3,
        "layout": {"layout": "side", "showID": True, "showName": True},
        "hideDisabled": True,
    }
    note = ""
    if unassigned:
        note = (f"{unassigned} technique(s) have no kill-chain phase and will appear "
                f"unassigned in the Navigator")
    return layer, note


# ---------------------------------------------------------------------------
# Fallback: synthesise objects from a capa export
# ---------------------------------------------------------------------------

def graph_from_capa(capa: dict) -> list[dict]:
    """capa JSON -> STIX-shaped attack-pattern / x-mitre-tactic objects.

    Used when no STIX bundle is supplied but capa found techniques, so the
    dashboard section is never empty on a run that has TTPs.  Only real STIX
    object types are produced (nothing invented), and each carries a
    ``x-synthesized`` marker so the UI can say where it came from.
    """
    if not isinstance(capa, dict):
        return []

    seen: dict[str, dict] = {}
    tactics_used: set[str] = set()

    for cap in capa.get("capabilities") or []:
        if not isinstance(cap, dict):
            continue
        for att in cap.get("attack") or []:
            if not isinstance(att, dict):
                continue
            tid = str(att.get("id") or "").strip().upper()
            if not re.fullmatch(r"T\d{4}(?:\.\d{3})?", tid):
                continue
            tactic = normalise_tactic(att.get("tactic"))

            obj = seen.get(tid)
            if obj is None:
                technique = str(att.get("technique") or tid)
                subtech = str(att.get("subtechnique") or "")
                display = f"{technique}: {subtech}" if subtech else technique
                obj = {
                    "type": "attack-pattern",
                    "spec_version": "2.1",
                    "id": f"attack-pattern--capa-{tid.replace('.', '-')}",
                    "name": display,
                    "external_references": [{
                        "source_name": "mitre-attack",
                        "external_id": tid,
                        "url": "https://attack.mitre.org/techniques/" + tid.replace(".", "/"),
                    }],
                    "x_mitre_is_subtechnique": "." in tid,
                    "x-synthesized": "capa",
                }
                seen[tid] = obj
            if tactic and tactic not in {p.get("phase_name") for p in obj.get("kill_chain_phases") or []}:
                obj.setdefault("kill_chain_phases", []).append(
                    {"kill_chain_name": "mitre-attack", "phase_name": tactic})
                tactics_used.add(tactic)

    objects: list[dict] = list(seen.values())
    for short in sorted(tactics_used, key=lambda s: TACTIC_ORDER.get(s, 99)):
        objects.append({
            "type": "x-mitre-tactic",
            "spec_version": "2.1",
            "id": f"x-mitre-tactic--capa-{short}",
            "name": TACTIC_NAMES.get(short, short),
            "x_mitre_shortname": short,
            "x-synthesized": "capa",
        })
    return objects


# ---------------------------------------------------------------------------
# Payload + HTML
# ---------------------------------------------------------------------------

def build_payload(objects: list[dict], meta: dict | None = None) -> dict:
    graph = build_graph(objects)
    layer, layer_note = to_navigator_layer(
        objects,
        name=(meta or {}).get("name") or "static_analyzer",
        description=(meta or {}).get("description", ""),
        attack_version=str((meta or {}).get("attack_version") or ""),
    )
    return {
        "meta": meta or {},
        "graph": graph,
        "layer": layer,
        "layer_note": layer_note,
        "tactics": [{"short": s, "name": n} for s, n in TACTICS],
    }


D3_PLACEHOLDER = "/*__D3__*/"
PAYLOAD_PLACEHOLDER = "/*__PAYLOAD__*/"


def html_document(payload: dict, d3_src: str, template_path: str | Path) -> str:
    """Fill the static HTML shell. Placeholders are replaced literally."""
    shell = Path(template_path).read_text(encoding="utf-8")
    payload_json = json.dumps(payload, separators=(",", ":")).replace("<", "\\u003c")
    if D3_PLACEHOLDER not in shell or PAYLOAD_PLACEHOLDER not in shell:
        raise ValueError(f"template {template_path} is missing its placeholders")
    return (shell
            .replace(D3_PLACEHOLDER, d3_src)
            .replace(PAYLOAD_PLACEHOLDER, payload_json))
