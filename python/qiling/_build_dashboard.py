"""Build a static HTML dashboard from Qiling analysis summaries.

Reads summary.json (standalone files or inside *_qiling_out.zip artifacts),
enriches every detected ATT&CK technique with mitigations + D3FEND
countermeasures via mitre/mitre_integration.py, and writes a self-contained
dashboard.html with:
  - ATT&CK <-> D3FEND bipartite graph (inline SVG, no external deps)
  - full ATT&CK tactic matrix heatmap with detected techniques highlighted
  - per-sample MITRE ATT&CK Navigator layer JSON (open in navigator.mitre.org)
  - MITRE CAR analytics coverage table + bar chart (mittre_car/)

Usage:
  python python/qiling/_build_dashboard.py <artifacts_dir | summary.json | zip> [...]
  python python/qiling/_build_dashboard.py -o report.html <inputs...>
"""
import html
import json
import pathlib
import re
import sys
import zipfile
from datetime import datetime

# This script lives in python/qiling/, so the repo root is two levels up
# (python/qiling -> python -> repo). Spelled out rather than chained through
# parent.parent so the intent survives another move.
_HERE = pathlib.Path(__file__).resolve().parent
REPO_ROOT = _HERE.parent.parent

DEFAULT_ARTIFACTS = REPO_ROOT / "config" / "systemd" / "qilin-service" / "artifacts"
CAR_DIR = REPO_ROOT / "mittre_car"

# kill-chain order (current ATT&CK renamed defense-evasion -> stealth and
# added defense-impairment; unknown future phases are appended at the end)
PHASE_ORDER = [
    "reconnaissance", "resource-development", "initial-access", "execution",
    "persistence", "privilege-escalation", "stealth", "defense-evasion",
    "defense-impairment", "credential-access", "discovery", "lateral-movement",
    "collection", "command-and-control", "exfiltration", "impact",
]


# ---------------------------------------------------------------- loading
def load_summaries(paths):
    """Collect (label, summary_dict) from zips, summary.json files or dirs."""
    out = []
    for p in paths:
        path = pathlib.Path(p)
        if path.is_dir():
            for sub in sorted(path.rglob("*")):
                if sub.is_file():
                    out.extend(load_summaries([sub]))
        elif path.suffix == ".zip":
            try:
                with zipfile.ZipFile(path) as z:
                    data = json.loads(z.read("summary.json"))
                out.append((path.stem.replace("_qiling_out", ""), data))
            except Exception as e:
                print("[!] {}: cannot read summary.json ({})".format(path, e))
        elif path.name == "summary.json":
            try:
                out.append((path.parent.name or "sample",
                            json.loads(path.read_text(encoding="utf-8"))))
            except Exception as e:
                print("[!] {}: {}".format(path, e))
    return out


def load_mitre():
    """Import the repo's MitreIntegration or return None."""
    mitre_dir = REPO_ROOT / "mitre"
    sys.path.insert(0, str(mitre_dir))
    try:
        from mitre_integration import MitreIntegration
        m = MitreIntegration()
        _ = m.attack_data  # force cache build now
        return m
    except Exception as e:
        print("[!] mitre integration unavailable: {}".format(e))
        return None


def collect_technique_ids(summary):
    """All ATT&CK technique ids hinted or tagged by the harness."""
    ids = []
    hints = summary.get("attack_hints") or {}
    if isinstance(hints, dict):
        for v in hints.values():
            tid = str(v).split()[0]
            if tid.startswith("T") and tid not in ids:
                ids.append(tid)
    return ids


def hint_scores(summary):
    """technique id -> score (how many harness tags mapped to it)."""
    scores = {}
    hints = summary.get("attack_hints") or {}
    if isinstance(hints, dict):
        for tid in hints.values():
            tid = str(tid).split()[0]
            scores[tid] = scores.get(tid, 0) + 1
    return scores


def enrich(tech_id, mitre):
    """One technique -> dict for the template."""
    info = {"id": tech_id, "name": "", "tactics": [], "description": "",
            "detection": "", "mitigations": [], "d3fend": [], "found": False}
    if not mitre:
        return info
    try:
        full = mitre.get_technique_with_mitigations(tech_id)
    except Exception as e:
        print("[!] enrich {} failed: {}".format(tech_id, e))
        return info
    if not full:
        return info
    tech = full["technique"]
    info.update(
        found=True,
        name=tech.get("name", ""),
        tactics=tech.get("tactics", []),
        description=tech.get("description", ""),
        detection=tech.get("detection", ""),
        mitigations=full.get("attack_mitigations", []),
        d3fend=full.get("d3fend_mitigations", []),
    )
    return info


# ------------------------------------------------------------------- CAR
_RE_CAR_ID = re.compile(r"^id:\s*(CAR-[\d-]+)\s*$", re.M)
_RE_CAR_TITLE = re.compile(r"^title:\s*(.+?)\s*$", re.M)
_RE_COV_TECH = re.compile(r"^\s*-\s*technique:\s*(T[\d.]+)\s*$", re.M)
_RE_COV_LEVEL = re.compile(r"^\s*cov(?:erage):\s*(\w+)\s*$", re.M)


def load_car_analytics(car_dir=CAR_DIR):
    """Parse CAR analytics yamls -> {technique_id: [{id, title, level}]}."""
    out = {}
    analytics_dir = pathlib.Path(car_dir) / "analytics"
    if not analytics_dir.is_dir():
        return out
    for yml in sorted(analytics_dir.glob("*.y*ml")):
        try:
            text = yml.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        cid = (_RE_CAR_ID.search(text) or [None, yml.stem])[1] if \
            _RE_CAR_ID.search(text) else yml.stem
        mtitle = _RE_CAR_TITLE.search(text)
        title = mtitle.group(1) if mtitle else yml.stem
        # walk the coverage: blocks - technique line then nearest coverage level
        entries = []
        for m in _RE_COV_TECH.finditer(text):
            tail = text[m.end():m.end() + 200]
            lm = _RE_COV_LEVEL.search(tail)
            entries.append((m.group(1), lm.group(1) if lm else ""))
        for tid, level in entries:
            out.setdefault(tid, []).append(
                {"id": cid, "title": title, "level": level})
    return out


def load_car_coverage_layer(car_dir=CAR_DIR):
    """Newest CAR coverage navigator-layer json -> {technique_id: count}."""
    cov_dir = pathlib.Path(car_dir) / "docs" / "coverage"
    if not cov_dir.is_dir():
        return {}
    files = sorted(cov_dir.glob("car_analytic_coverage_*.json"))
    if not files:
        return {}
    try:
        layer = json.loads(files[-1].read_text(encoding="utf-8"))
    except Exception as e:
        print("[!] cannot read {}: {}".format(files[-1], e))
        return {}
    counts = {}
    for t in layer.get("techniques", []):
        tid = t.get("techniqueID")
        if not tid:
            continue
        n = 1
        for md in t.get("metadata", []):
            if md.get("name") == "Analytic Count":
                try:
                    n = int(md.get("value", 1))
                except ValueError:
                    n = 1
        counts[tid] = counts.get(tid, 0) + n
    return counts


def load_cti(label, out_dir):
    """Load <label>_cti_intel.json written by _cti_intel.py (or None)."""
    name = "{}_cti_intel.json".format(label)
    out_dir = pathlib.Path(out_dir)
    candidates = [out_dir / name] + sorted(out_dir.rglob(name))
    for p in candidates:
        if p.is_file():
            try:
                return json.loads(p.read_text(encoding="utf-8"))
            except Exception as e:
                print("[!] cannot read {}: {}".format(p, e))
                return None
    return None


# --------------------------------------------------------- visualizations
def build_graph_svg(techs):
    """Bipartite SVG: ATT&CK techniques (left) -> D3FEND (right)."""
    d3_nodes = []
    edges = []
    for i, t in enumerate(techs):
        for d in t["d3fend"]:
            key = d.get("id")
            if key not in [n["id"] for n in d3_nodes]:
                d3_nodes.append(d)
            edges.append((i, [n["id"] for n in d3_nodes].index(key)))
    if not techs:
        return ""
    n_left, n_right = len(techs), len(d3_nodes)
    row_h = 64
    height = max(n_left, n_right, 1) * row_h + 40
    lx, rx, bw, bh = 20, 560, 220, 40
    parts = ['<svg viewBox="0 0 800 {}" width="100%" height="{}" '
             'xmlns="http://www.w3.org/2000/svg" style="max-height:{}px">'
             .format(height, height, height)]
    parts.append('<text x="120" y="18" fill="#8b949e" font-size="11" '
                 'text-anchor="middle">ATT&amp;CK</text>')
    parts.append('<text x="670" y="18" fill="#8b949e" font-size="11" '
                 'text-anchor="middle">D3FEND</text>')

    def cy(i, n):
        return 40 + (i + 0.5) * (height - 50) / max(n, 1)

    for li, ri in edges:
        y1, y2 = cy(li, n_left), cy(ri, n_right)
        parts.append(
            '<path d="M {},{} C {},{} {},{} {},{}" stroke="#30363d" '
            'stroke-width="1.5" fill="none"/>'.format(
                lx + bw, y1, lx + bw + 120, y1, rx - 120, y2, rx, y2))
    for i, t in enumerate(techs):
        y = cy(i, n_left) - bh / 2
        label = "{} {}".format(t["id"], t["name"] or "")
        parts.append(
            '<rect x="{}" y="{}" width="{}" height="{}" rx="6" fill="#1f6feb" '
            'fill-opacity="0.25" stroke="#58a6ff"/>'.format(lx, y, bw, bh))
        parts.append(
            '<text x="{}" y="{}" fill="#e6edf3" font-size="12" '
            'font-weight="600">{}</text>'.format(
                lx + 10, y + bh / 2 + 4, esc(truncate(label, 34))))
    for i, d in enumerate(d3_nodes):
        y = cy(i, n_right) - bh / 2
        label = "{} {}".format(d.get("id", ""), d.get("name", ""))
        parts.append(
            '<rect x="{}" y="{}" width="{}" height="{}" rx="6" fill="#238636" '
            'fill-opacity="0.25" stroke="#3fb950"/>'.format(rx, y, bw, bh))
        parts.append(
            '<text x="{}" y="{}" fill="#e6edf3" font-size="12" '
            'font-weight="600">{}</text>'.format(
                rx + 10, y + bh / 2 + 4, esc(truncate(label, 34))))
    parts.append("</svg>")
    return "".join(parts)


def matrix_columns(mitre):
    """[(phase, [parent technique dicts sorted])] using live ATT&CK phases."""
    by_phase = {}
    parents = []
    if mitre:
        parents = [t for t in mitre._techniques_cache.values()
                   if not t.is_subtechnique and t.id]
    for t in parents:
        for phase in t.tactics:
            by_phase.setdefault(phase, []).append(t)
    ordered = [p for p in PHASE_ORDER if p in by_phase]
    ordered += sorted(p for p in by_phase if p not in PHASE_ORDER)

    def sort_key(t):
        parts = t.id.split(".")[0][1:].split("0")
        try:
            return int(t.id.split(".")[0][1:])
        except ValueError:
            return 999999

    return [(p, sorted(by_phase[p], key=sort_key)) for p in ordered]


def build_matrix_html(detected, mitre):
    """Full tactic matrix; detected = {tid: [sample labels]}."""
    cols = matrix_columns(mitre)
    parts = ['<div class="matrix">']
    for phase, techs in cols:
        parts.append('<div class="mcol"><h5>{}</h5>'.format(esc(phase)))
        for t in techs:
            if t.id in detected:
                title = "detected in: " + ", ".join(detected[t.id])
                parts.append('<div class="cell hit" title="{}">{} '
                             "<b>&#9679;</b></div>".format(
                                 esc(title), esc(t.id)))
            else:
                parts.append('<div class="cell">{}</div>'.format(esc(t.id)))
        parts.append("</div>")
    parts.append("</div>")
    return "".join(parts)


def navigator_layer(label, summary, techs, scores):
    """ATT&CK Navigator layer dict for one sample."""
    techniques = []
    for t in techs:
        techniques.append({
            "techniqueID": t["id"],
            "score": scores.get(t["id"], 1),
            "comment": "{}: {}".format(label, t["name"] or t["id"]),
            "enabled": True,
            "showSubtechniques": False,
        })
    return {
        "name": "Qiling: {}".format(label),
        "versions": {"attack": "enterprise", "navigator": "4.9.1",
                     "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": ("Techniques detected by the qiling CPU-emulation "
                        "harness for {} (elapsed {}s, end {}).").format(
                            summary.get("sample", label),
                            summary.get("elapsed_s", "?"),
                            summary.get("end", "?")),
        "filters": {"platforms": ["Windows"]},
        "sorting": 0,
        "layout": {"layout": "side", "showID": True, "showName": True},
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {"colors": ["#ff6666", "#ffe766", "#8ec843"],
                     "minValue": 0, "maxValue": max(
                         [scores.get(t["id"], 1) for t in techs] or [1])},
        "legendItems": [{
            "label": "detected by qiling harness",
            "color": "#ff6666"}],
        "metadata": [{"name": "generated_by", "value": "_build_dashboard.py"},
                     {"name": "sample_sha256",
                      "value": (summary.get("sample_hashes") or {}).get(
                          "sha256", "")}],
        "showTacticRowBackground": False,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
    }


# ---------------------------------------------------------------- render
def esc(s):
    return html.escape(str(s or ""))


def truncate(text, n=600):
    text = str(text or "").strip()
    if len(text) <= n:
        return text
    return text[:n].rsplit(" ", 1)[0] + " ..."


CSS = """
:root{--bg:#0d1117;--panel:#161b22;--panel2:#1c2330;--border:#30363d;
--text:#e6edf3;--muted:#8b949e;--accent:#58a6ff;--red:#f85149;--green:#3fb950;--yellow:#d29922}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);
font:14px/1.55 "Segoe UI",system-ui,sans-serif;padding:28px 4vw 80px}
h1{font-size:22px;margin:0 0 4px} h1 span{color:var(--accent)}
.sub{color:var(--muted);margin:0 0 22px;font-size:12.5px}
nav{position:sticky;top:0;background:var(--bg);padding:10px 0;z-index:5;
border-bottom:1px solid var(--border);margin-bottom:18px}
nav a{color:var(--muted);text-decoration:none;margin-right:14px;font-size:12.5px}
nav a:hover{color:var(--accent)}
.sample{background:var(--panel);border:1px solid var(--border);border-radius:10px;
padding:20px 22px;margin-bottom:26px}
.sample h2{margin:0 0 2px;font-size:17px}
.meta{color:var(--muted);font-size:12px;margin-bottom:12px;word-break:break-all}
.chips{margin:8px 0 14px}
.chip{display:inline-block;padding:2px 9px;border-radius:20px;font-size:11px;
margin:2px 4px 2px 0;border:1px solid var(--border);color:var(--muted)}
.chip.tag{border-color:var(--yellow);color:var(--yellow)}
.chip.tac{border-color:var(--accent);color:var(--accent)}
.tech{background:var(--panel2);border:1px solid var(--border);border-radius:8px;
padding:14px 16px;margin:12px 0}
.tech header{display:flex;align-items:baseline;gap:10px;flex-wrap:wrap}
.tid{font-weight:700;color:var(--accent);font-family:Consolas,monospace}
.tname{font-weight:600}
.badge{font-size:10.5px;padding:1px 8px;border-radius:10px;border:1px solid var(--green);
color:var(--green)}
.muted{color:var(--muted)}
h3{margin:26px 0 8px;font-size:15px;border-top:1px solid var(--border);padding-top:18px}
h4{margin:12px 0 6px;font-size:12px;text-transform:uppercase;letter-spacing:.6px;
color:var(--muted)}
ul{margin:4px 0 0 18px;padding:0} li{margin:2px 0}
.d3{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:10px}
.d3 .card{background:#111820;border:1px solid var(--border);border-radius:6px;padding:10px 12px}
.d3 .card b{color:var(--green);font-family:Consolas,monospace;font-size:12px}
.d3 .card .cat{color:var(--muted);font-size:11px;display:block;margin:2px 0 6px}
.d3 .card p{margin:0;font-size:12px;color:#c9d1d9}
.warn{background:#2d1a1a;border:1px solid var(--red);border-radius:6px;
padding:8px 12px;color:var(--red);font-size:12.5px;margin:10px 0}
.matrix{display:flex;gap:8px;overflow-x:auto;padding:12px;background:var(--panel2);
border:1px solid var(--border);border-radius:8px}
.mcol{min-width:108px;flex:1}
.mcol h5{margin:0 0 8px;font-size:10px;text-transform:uppercase;color:var(--muted);
letter-spacing:.4px;text-align:center;border-bottom:1px solid var(--border);padding-bottom:4px}
.cell{font:10px/1.5 Consolas,monospace;padding:2px 5px;border-radius:3px;margin:2px 0;
background:#21262d;color:#8b949e}
.cell.hit{background:#1f6feb;color:#fff;font-weight:700}
.cell.hit b{color:#ffd33d}
.bar{display:flex;align-items:center;gap:8px;margin:4px 0}
.bar .lbl{width:90px;font:11px Consolas,monospace;color:var(--muted);text-align:right}
.bar .track{flex:1;background:#21262d;border-radius:4px;height:14px;position:relative}
.bar .fill{height:100%;border-radius:4px;background:linear-gradient(90deg,#1f6feb,#3fb950)}
.bar .val{width:110px;font-size:11px;color:var(--muted)}
table.car{border-collapse:collapse;width:100%;font-size:12.5px;margin:8px 0}
table.car th,table.car td{border:1px solid var(--border);padding:6px 10px;text-align:left}
table.car th{background:var(--panel2);color:var(--muted);font-size:11px}
.lv-High{color:#3fb950}.lv-Medium{color:#d29922}.lv-Low{color:#f85149}
.cti-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:10px}
.cti-src{background:var(--panel2);border:1px solid var(--border);border-radius:8px;padding:12px 14px}
.cti-src h5{margin:0 0 6px;font-size:12.5px;display:flex;justify-content:space-between}
.st-found{color:var(--green)} .st-nohit{color:var(--yellow)}
.st-error{color:var(--red)} .st-skipped{color:var(--muted)}
.cti-src p{margin:4px 0;font-size:12px;color:#c9d1d9}
.cti-src .kv{color:var(--muted);font-size:11.5px}
.verdict{background:#111820;border:1px solid var(--yellow);border-radius:6px;
padding:8px 12px;color:var(--yellow);font-size:13px;margin:8px 0}
.vtbar{display:flex;height:10px;border-radius:5px;overflow:hidden;margin:6px 0}
.vtbar .m{background:var(--red)} .vtbar .s{background:var(--yellow)}
.vtbar .h{background:var(--green)} .vtbar .u{background:#30363d}
a.layer{display:inline-block;margin:6px 0;padding:6px 12px;border:1px solid var(--accent);
border-radius:6px;color:var(--accent);text-decoration:none;font-size:12.5px}
a.layer:hover{background:#1f6feb22}
footer{color:var(--muted);font-size:11.5px;margin-top:30px;border-top:1px solid var(--border);
padding-top:12px}
"""


def render_cti_panel(cti):
    """HTML for one sample's CTI intel (or '' when no intel file)."""
    if not cti:
        return ""
    parts = ["<h3>CTI intelligence (sha256)</h3>"]
    parts.append('<p class="meta">sha256 {} &middot; collected {} &middot; '
                 "per-source hard limit {:g}s</p>".format(
                     esc(cti.get("sha256", "")), esc(cti.get("collected_at", "")),
                     float(cti.get("source_time_limit_s") or 0)))
    verdict = cti.get("verdict", "")
    if verdict:
        parts.append('<div class="verdict">{}</div>'.format(esc(verdict)))
    parts.append('<div class="cti-grid">')
    for s in cti.get("sources", []):
        name = s.get("source", "?")
        if s.get("timed_out"):
            state, cls = "timeout", "st-error"
        elif s.get("found"):
            state, cls = "found", "st-found"
        elif s.get("skipped"):
            state, cls = "skipped", "st-skipped"
        elif s.get("ok"):
            state, cls = "no hit", "st-nohit"
        else:
            state, cls = "error", "st-error"
        parts.append('<div class="cti-src"><h5>{} <span class="{}">{}</span>'
                     "</h5>".format(esc(name), cls, esc(state)))
        if s.get("error"):
            parts.append("<p>{}</p>".format(esc(truncate(s["error"], 200))))
        if s.get("detail"):
            parts.append('<p class="kv">{}</p>'.format(esc(s["detail"])))
        if name == "MalwareBazaar" and s.get("found"):
            parts.append('<p><b>{}</b></p>'.format(esc(s.get("signature", ""))))
            if s.get("tags"):
                parts.append('<p class="kv">tags: {}</p>'.format(
                    esc(", ".join(s["tags"][:12]))))
            parts.append('<p class="kv">first seen {} &middot; {} &middot; {}'
                         "</p>".format(esc(s.get("first_seen", "")),
                                       esc(s.get("file_type", "")),
                                       esc(s.get("delivery_method", ""))))
        if name == "ThreatFox" and s.get("found"):
            for m in (s.get("matches") or [])[:5]:
                parts.append("<p><b>{}</b> <span class='kv'>({}, {})</span>"
                             "</p>".format(esc(m.get("malware", "")),
                                           esc(m.get("threat_type", "")),
                                           esc(m.get("first_seen", ""))))
        if name == "VirusTotal" and s.get("found"):
            mal, sus, har, und = (s.get("malicious", 0), s.get("suspicious", 0),
                                  s.get("harmless", 0), s.get("undetected", 0))
            tot = max(1, mal + sus + har + und)
            parts.append(
                '<div class="vtbar">'
                '<span class="m" style="width:{}%"></span>'
                '<span class="s" style="width:{}%"></span>'
                '<span class="h" style="width:{}%"></span>'
                '<span class="u" style="width:{}%"></span></div>'.format(
                    mal * 100 / tot, sus * 100 / tot, har * 100 / tot,
                    und * 100 / tot))
            parts.append('<p class="kv">{} malicious &middot; {} suspicious '
                         "&middot; {} harmless &middot; {} undetected</p>".format(
                             mal, sus, har, und))
            if s.get("popular_threat"):
                parts.append("<p><b>{}</b></p>".format(
                    esc(s["popular_threat"])))
            if s.get("names"):
                parts.append('<p class="kv">names: {}</p>'.format(
                    esc(", ".join(s["names"][:6]))))
        parts.append("</div>")
    parts.append("</div>")
    return "".join(parts)


def render_html(samples, mitre, car_analytics, car_counts, layer_files):
    """samples: (label, summary, techniques, scores, layer_name) tuples."""
    parts = ['<!doctype html>\n<html lang="en"><head><meta charset="utf-8">\n'
             '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
             "<title>Qiling Analysis Dashboard</title>\n<style>",
             CSS, "</style></head><body>\n"]
    parts.append("<h1>Qiling <span>Analysis Dashboard</span></h1>\n")
    parts.append('<p class="sub">CPU-emulation results with MITRE ATT&amp;CK, '
                 "D3FEND, Navigator layers and CAR coverage &middot; generated ")
    parts.append(esc(datetime.now().strftime("%Y-%m-%d %H:%M")))
    parts.append("</p>\n")

    if samples:
        parts.append("<nav>")
        for i, (label, _s, _t, _sc, _l, _c) in enumerate(samples):
            parts.append('<a href="#s{}">{}</a>'.format(i, esc(label)))
        parts.append('<a href="#matrix">matrix</a></nav>\n')
    else:
        parts.append('<div class="warn">no summaries found in given paths</div>')

    if not mitre:
        parts.append('<div class="warn">MITRE enrichment unavailable '
                     "(mitreattack-python / network) - showing raw harness hints only</div>")

    # ---- global matrix
    detected_union = {}
    for label, s, techs, _sc, _l, _c in samples:
        for t in techs:
            detected_union.setdefault(t["id"], []).append(label)
    parts.append('<div class="sample" id="matrix"><h2>ATT&amp;CK tactic matrix'
                 "</h2>")
    parts.append('<p class="meta">detected techniques are highlighted '
                 "(hover for sample names) &middot; {} parents across {} "
                 "tactics</p>".format(
                     sum(len(c[1]) for c in matrix_columns(mitre)),
                     len(matrix_columns(mitre))))
    parts.append(build_matrix_html(detected_union, mitre))
    parts.append("</div>")

    for i, (label, s, techs, scores, layer_name, cti) in enumerate(samples):
        parts.append('<div class="sample" id="s{}">'.format(i))
        parts.append("<h2>{}</h2>".format(esc(label)))
        hashes = s.get("sample_hashes") or {}
        parts.append('<div class="meta">{} &middot; sha256 {} &middot; arch {} '
                     "&middot; {:.1f}s &middot; end {}</div>".format(
                         esc(s.get("sample", "")), esc(hashes.get("sha256", "")),
                         esc(s.get("arch", "")), float(s.get("elapsed_s") or 0),
                         esc(s.get("end", ""))))
        parts.append('<div class="chips">')
        for tag in (s.get("behaviour_tags") or {}):
            parts.append('<span class="chip tag">{}</span>'.format(esc(tag)))
        for tid in collect_technique_ids(s):
            parts.append('<span class="chip">{}</span>'.format(esc(tid)))
        parts.append("</div>")

        # navigator layer download
        if layer_name:
            parts.append('<a class="layer" href="{}">&#8595; ATT&amp;CK '
                         "Navigator layer</a> ".format(esc(layer_name)))
            parts.append('<span class="muted">open at navigator.mitre.org '
                         "&rarr; Open Existing Layer &rarr; upload</span>")

        parts.append("<h3>MITRE ATT&amp;CK &amp; D3FEND</h3>")
        if techs:
            svg = build_graph_svg(techs)
            if svg:
                parts.append(svg)
        else:
            parts.append('<p class="muted">no ATT&amp;CK techniques detected '
                         "by the harness for this sample</p>")

        for t in techs:
            parts.append('<div class="tech"><header>')
            parts.append('<span class="tid">{}</span>'.format(esc(t["id"])))
            parts.append('<span class="tname">{}</span>'.format(esc(t["name"] or "(unknown)")))
            if t["found"]:
                parts.append('<span class="badge">in ATT&amp;CK</span>')
            parts.append("</header>")
            parts.append('<div class="chips">')
            for tac in t["tactics"]:
                parts.append('<span class="chip tac">{}</span>'.format(esc(tac)))
            parts.append("</div>")
            if t["description"]:
                parts.append("<p>{}</p>".format(esc(truncate(t["description"]))))
            if t["detection"]:
                parts.append("<h4>Detection</h4><p class='muted'>{}</p>".format(
                    esc(truncate(t["detection"], 400))))
            if t["mitigations"]:
                parts.append("<h4>ATT&amp;CK Mitigations</h4><ul>")
                for m in t["mitigations"]:
                    parts.append("<li>{}</li>".format(esc(m)))
                parts.append("</ul>")
            if t["d3fend"]:
                parts.append("<h4>D3FEND Countermeasures</h4><div class='d3'>")
                for d in t["d3fend"]:
                    parts.append('<div class="card"><b>{}</b> {}'
                                 '<span class="cat">{}</span><p>{}</p></div>'.format(
                                     esc(d.get("id", "")), esc(d.get("name", "")),
                                     esc(d.get("category", "")),
                                     esc(truncate(d.get("description", ""), 220))))
                parts.append("</div>")
            elif t["found"]:
                parts.append('<p class="muted">no D3FEND mapping for this technique</p>')
            parts.append("</div>")

        # ---- CTI intelligence (sha256 investigation)
        parts.append(render_cti_panel(cti))

        # ---- CAR coverage for this sample
        parts.append("<h3>MITRE CAR coverage</h3>")
        covered = uncovered = 0
        rows = []
        for t in techs:
            hits = car_analytics.get(t["id"], [])
            count = car_counts.get(t["id"], len(hits))
            if hits or count:
                covered += 1
            else:
                uncovered += 1
            rows.append((t, hits, count))
        total = covered + uncovered
        parts.append('<p class="meta">CAR analytics cover {} of {} detected '
                     "techniques</p>".format(covered, total))
        if total:
            parts.append('<div class="chart">')
            for t, hits, count in rows:
                pct = min(100, count * 20) if count else 0
                name = t["name"] or t["id"]
                parts.append(
                    '<div class="bar"><span class="lbl">{}</span>'
                    '<span class="track"><span class="fill" style="width:{}%">'
                    "</span></span>"
                    '<span class="val">{} &middot; {}</span></div>'.format(
                        esc(truncate("{} {}".format(t["id"], name), 22)),
                        pct, count, "covered" if hits or count else "no analytic"))
            parts.append("</div>")
        if any(r[1] for r in rows):
            parts.append('<table class="car"><tr><th>Technique</th>'
                         "<th>CAR analytic</th><th>Title</th><th>Coverage</th></tr>")
            for t, hits, _c in rows:
                if not hits:
                    continue
                for h in hits:
                    lvl = h.get("level") or "-"
                    parts.append(
                        "<tr><td>{} {}</td><td>{}</td><td>{}</td>"
                        '<td class="lv-{}">{}</td></tr>'.format(
                            esc(t["id"]), esc(t["name"] or ""), esc(h["id"]),
                            esc(h["title"]), esc(lvl or "-"),
                            esc(lvl)))
            parts.append("</table>")
        parts.append("</div>")

    parts.append("<footer>data: MITRE ATT&amp;CK enterprise + MITRE D3FEND "
                 "(mitre/mitre_integration.py) &middot; MITRE CAR "
                 "(mittre_car/) &middot; results: qiling harness summary.json"
                 "</footer></body></html>\n")
    return "".join(parts)


# -------------------------------------------------------------------- api
def build(paths, out_path=None):
    summaries = load_summaries(paths)
    if not summaries:
        print("[!] no summary.json found in: {}".format(
            ", ".join(str(p) for p in paths)))
        return None
    mitre = load_mitre()
    mitre_ok = mitre is not None
    car_analytics = load_car_analytics()
    car_counts = load_car_coverage_layer()
    print("[+] CAR: {} analytics mapped to techniques, coverage layer: {} "
          "techniques".format(len(car_analytics), len(car_counts)))

    out_dir = pathlib.Path(paths[0])
    if not out_dir.is_dir():
        out_dir = out_dir.parent

    samples = []
    used_names = set()
    for label, s in summaries:
        scores = hint_scores(s)
        techs = [enrich(tid, mitre) for tid in collect_technique_ids(s)]
        layer = navigator_layer(label, s, techs, scores)
        layer_name = "{}_attack_layer.json".format(label)
        n = 2
        while layer_name in used_names:
            layer_name = "{}_{}_attack_layer.json".format(label, n)
            n += 1
        used_names.add(layer_name)
        layer_path = out_dir / layer_name
        layer_path.write_text(json.dumps(layer, indent=2), encoding="utf-8")
        cti = load_cti(label, out_dir)
        samples.append((label, s, techs, scores, layer_name, cti))
        print("[+] {}: {} technique(s){} -> {}".format(
            label, len(techs),
            (" " + ", ".join(t["id"] for t in techs)) if techs else "",
            layer_name))

    if out_path is None:
        out_path = out_dir / "dashboard.html"
    out = pathlib.Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        render_html(samples, mitre, car_analytics, car_counts, used_names),
        encoding="utf-8")
    print("[+] dashboard written: {}".format(out))
    return out


def main():
    import argparse
    ap = argparse.ArgumentParser(
        description="build static HTML dashboard from qiling summaries")
    ap.add_argument("inputs", nargs="*",
                    help="artifacts dir, summary.json or *_qiling_out.zip "
                         "(default: {})".format(DEFAULT_ARTIFACTS))
    ap.add_argument("-o", "--out", help="output html path")
    a = ap.parse_args()
    paths = a.inputs or [str(DEFAULT_ARTIFACTS)]
    out = build(paths, a.out)
    sys.exit(0 if out else 1)


if __name__ == "__main__":
    main()
