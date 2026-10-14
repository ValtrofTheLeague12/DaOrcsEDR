"""CTI intel collection - investigate a PE's SHA256 against threat feeds.

Queries (all HTTP calls timeout-bounded via TIMEOUT seconds):
  - MalwareBazaar (abuse.ch)  : POST mb-api.abuse.ch  query=get_info
  - ThreatFox     (abuse.ch)  : POST threatfox-api.abuse.ch search_ioc
  - VirusTotal                : GET virustotal.com api/v3/files/<sha256>
    (only when VT_API_KEY is set in env, vm_info.json, or --vt-key)

Input is a summary.json / *_qiling_out.zip / artifacts dir (uses
sample_hashes.sha256) or a bare sha256 string. Results are written next to
the dashboard as <label>_cti_intel.json and shown in its CTI panel.

Usage:
  python python/qiling/_cti_intel.py <artifacts_dir>
  python python/qiling/_cti_intel.py 1d5087...e4249
"""
import concurrent.futures
import json
import os
import pathlib
import sys
import zipfile
from datetime import datetime

import requests

TIMEOUT = (5, 30)  # socket-level (connect, read) seconds - every HTTP call
SOURCE_TIME_LIMIT = 20  # hard wall-clock cap per source (avoids hangups)

# This script lives in python/qiling/, so the repo root is two levels up.
# vm_info.json is VM-payload, not script payload, so it stays in qiling_dlls/.
_HERE = pathlib.Path(__file__).resolve().parent
REPO_ROOT = _HERE.parent.parent
PAYLOAD_DIR = REPO_ROOT / "qiling_dlls"

DEFAULT_ARTIFACTS = REPO_ROOT / "config" / "systemd" / "qilin-service" / "artifacts"
USER_AGENT = "IAProject-CTI-Collector/1.0"
ABUSE_KEY_HINT = ("abuse.ch requires a free Auth-Key (register at "
                  "https://auth.abuse.ch) - set ABUSECH_AUTH_KEY in env or "
                  "vm_info.json")


def _abuse_key(cli_key=None):
    if cli_key:
        return cli_key
    if os.environ.get("ABUSECH_AUTH_KEY"):
        return os.environ["ABUSECH_AUTH_KEY"]
    try:
        info = json.loads((PAYLOAD_DIR / "vm_info.json").read_text(
            encoding="utf-8"))
        return info.get("ABUSECH_AUTH_KEY") or None
    except Exception:
        return None


def _abuse_headers(auth_key):
    h = {"User-Agent": USER_AGENT}
    if auth_key:
        h["Auth-Key"] = auth_key
    return h


def _vt_key(cli_key=None):
    if cli_key:
        return cli_key
    if os.environ.get("VT_API_KEY"):
        return os.environ["VT_API_KEY"]
    try:
        info = json.loads((PAYLOAD_DIR / "vm_info.json").read_text(
            encoding="utf-8"))
        return info.get("VT_API_KEY") or None
    except Exception:
        return None


def query_malwarebazaar(sha256, auth_key=None):
    """abuse.ch MalwareBazaar hash lookup. Returns dict."""
    try:
        r = requests.post(
            "https://mb-api.abuse.ch/api/v1/",
            data={"query": "get_info", "hash": sha256},
            headers=_abuse_headers(auth_key),
            timeout=TIMEOUT)
        if r.status_code == 401:
            return {"source": "MalwareBazaar", "ok": False,
                    "error": ABUSE_KEY_HINT}
        r.raise_for_status()
        data = r.json()
    except Exception as e:
        return {"source": "MalwareBazaar", "ok": False, "error": str(e)}
    if data.get("query_status") == "hash_not_found":
        return {"source": "MalwareBazaar", "ok": True, "found": False,
                "detail": "hash not known to MalwareBazaar"}
    if data.get("query_status") != "ok" or not data.get("data"):
        return {"source": "MalwareBazaar", "ok": False,
                "error": "unexpected status: {}".format(
                    data.get("query_status"))}
    d = data["data"][0]
    return {"source": "MalwareBazaar", "ok": True, "found": True,
            "signature": d.get("signature", ""),
            "tags": d.get("tags") or [],
            "file_type": d.get("file_type", ""),
            "delivery_method": d.get("delivery_method", ""),
            "first_seen": d.get("first_seen", ""),
            "sha256_hash": d.get("sha256_hash", "")}


def query_threatfox(sha256, auth_key=None):
    """abuse.ch ThreatFox IOC search. Returns dict."""
    try:
        r = requests.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            json={"query": "search_ioc", "search_term": sha256},
            headers=_abuse_headers(auth_key),
            timeout=TIMEOUT)
        if r.status_code == 401:
            return {"source": "ThreatFox", "ok": False,
                    "error": ABUSE_KEY_HINT}
        r.raise_for_status()
        data = r.json()
    except Exception as e:
        return {"source": "ThreatFox", "ok": False, "error": str(e)}
    status = data.get("query_status")
    if status == "no_result":
        return {"source": "ThreatFox", "ok": True, "found": False,
                "detail": "no ThreatFox IOC matches this hash"}
    if status != "ok":
        return {"source": "ThreatFox", "ok": False,
                "error": "unexpected status: {}".format(status)}
    entries = data.get("data") or []
    return {"source": "ThreatFox", "ok": True, "found": True,
            "matches": [
                {"malware": e.get("malware_printable", ""),
                 "malware_alias": e.get("malware_alias", ""),
                 "threat_type": e.get("threat_type", ""),
                 "first_seen": e.get("first_seen", ""),
                 "tags": e.get("tags") or []}
                for e in entries[:10]]}


def query_virustotal(sha256, api_key):
    """VirusTotal v3 file report. Returns dict."""
    if not api_key:
        return {"source": "VirusTotal", "ok": False, "skipped": True,
                "error": "no VT_API_KEY (env / vm_info.json / --vt-key)"}
    try:
        r = requests.get(
            "https://www.virustotal.com/api/v3/files/{}".format(sha256),
            headers={"x-apikey": api_key, "User-Agent": USER_AGENT},
            timeout=TIMEOUT)
        if r.status_code == 404:
            return {"source": "VirusTotal", "ok": True, "found": False,
                    "detail": "hash not known to VirusTotal"}
        r.raise_for_status()
        attrs = (r.json().get("data") or {}).get("attributes") or {}
    except Exception as e:
        return {"source": "VirusTotal", "ok": False, "error": str(e)}
    stats = attrs.get("last_analysis_stats") or {}
    names = attrs.get("names") or []
    tags = attrs.get("tags") or []
    tpc = attrs.get("popular_threat_classification") or {}
    return {"source": "VirusTotal", "ok": True, "found": True,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "reputation": attrs.get("reputation"),
            "names": names[:8],
            "tags": tags[:10],
            "popular_threat": tpc.get("suggested_threat_label", ""),
            "first_seen": attrs.get("first_submission_date"),
            "last_analysis": attrs.get("last_analysis_date")}


def _call_source(name, fn, *args, limit=SOURCE_TIME_LIMIT, **kwargs):
    """Run one source query in a worker thread with a hard time cap.

    Socket timeouts alone cannot stop a server that trickles bytes forever,
    so every source is also bounded by a wall-clock deadline. On timeout the
    worker is abandoned (daemon) and a structured timeout result is returned.
    """
    ex = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    fut = ex.submit(fn, *args, **kwargs)
    try:
        return fut.result(timeout=limit)
    except concurrent.futures.TimeoutError:
        return {"source": name, "ok": False, "timed_out": True,
                "error": "timed out after {:g}s (hard per-source limit)"
                         .format(limit)}
    finally:
        ex.shutdown(wait=False, cancel_futures=True)


def investigate(sha256, vt_key=None, abuse_key=None,
                source_time_limit=SOURCE_TIME_LIMIT):
    """Run every enabled source for one sha256. Returns result dict."""
    sha256 = sha256.lower().strip()
    if len(sha256) != 64 or any(c not in "0123456789abcdef" for c in sha256):
        raise ValueError("not a sha256 hex digest: {!r}".format(sha256))
    key = _vt_key(vt_key)
    akey = _abuse_key(abuse_key)
    limit = max(1, float(source_time_limit))
    results = {
        "sha256": sha256,
        "collected_at": datetime.now().isoformat(timespec="seconds"),
        "source_time_limit_s": limit,
        "sources": [
            _call_source("MalwareBazaar", query_malwarebazaar, sha256, akey,
                         limit=limit),
            _call_source("ThreatFox", query_threatfox, sha256, akey,
                         limit=limit),
            _call_source("VirusTotal", query_virustotal, sha256, key,
                         limit=limit),
        ],
    }
    # short human verdict for the dashboard header
    verdicts = []
    mb = next(s for s in results["sources"] if s["source"] == "MalwareBazaar")
    if mb.get("found"):
        verdicts.append("MB:{}".format(mb.get("signature") or "known-malicious"))
    tf = next(s for s in results["sources"] if s["source"] == "ThreatFox")
    if tf.get("found"):
        ms = {m["malware"] for m in tf.get("matches", []) if m.get("malware")}
        verdicts.append("ThreatFox:{}".format(",".join(sorted(ms)) or "listed"))
    vt = next(s for s in results["sources"] if s["source"] == "VirusTotal")
    if vt.get("found"):
        verdicts.append("VT:{}/{} malicious".format(
            vt.get("malicious", 0),
            (vt.get("malicious", 0) + vt.get("suspicious", 0) +
             vt.get("harmless", 0) + vt.get("undetected", 0))))
    results["verdict"] = " | ".join(verdicts) if verdicts else \
        "no hits on enabled feeds"
    return results


def _summaries_from(paths):
    """Yield (label, sha256_or_None, suggested_out_dir) tuples."""
    out = []
    for p in paths:
        path = pathlib.Path(p)
        raw = str(p)
        if len(raw.strip()) == 64 and all(c in "0123456789abcdefABCDEF"
                                          for c in raw.strip()):
            out.append((raw.strip()[:12], raw.strip().lower(), None))
        elif path.is_dir():
            for sub in sorted(path.rglob("*")):
                if sub.is_file():
                    out.extend(_summaries_from([sub]))
        elif path.suffix == ".zip":
            try:
                with zipfile.ZipFile(path) as z:
                    s = json.loads(z.read("summary.json"))
                sha = (s.get("sample_hashes") or {}).get("sha256")
                out.append((path.stem.replace("_qiling_out", ""), sha,
                            path.parent))
            except Exception as e:
                print("[!] {}: {}".format(path, e))
        elif path.name == "summary.json":
            try:
                s = json.loads(path.read_text(encoding="utf-8"))
                sha = (s.get("sample_hashes") or {}).get("sha256")
                out.append((path.parent.name or "sample", sha, path.parent))
            except Exception as e:
                print("[!] {}: {}".format(path, e))
    return out


def run(paths, out_dir=None, vt_key=None, abuse_key=None,
        source_time_limit=SOURCE_TIME_LIMIT):
    targets = _summaries_from(paths)
    if not targets:
        print("[!] no summary/sha256 found in: {}".format(
            ", ".join(str(p) for p in paths)))
        return []
    written = []
    seen = set()
    for label, sha, src_dir in targets:
        if not sha:
            print("[!] {}: no sample_hashes.sha256 in summary".format(label))
            continue
        if sha in seen:
            continue
        seen.add(sha)
        print("[+] investigating {} ({})".format(sha, label))
        res = investigate(sha, vt_key=vt_key, abuse_key=abuse_key,
                          source_time_limit=source_time_limit)
        for s in res["sources"]:
            state = ("timeout" if s.get("timed_out") else
                     "found" if s.get("found") else
                     "skipped" if s.get("skipped") else
                     "no hit" if s.get("ok") else "error")
            extra = s.get("signature") or s.get("detail") or s.get("error") or ""
            print("    {:<14} {:<8} {}".format(s["source"], state, extra))
        print("    verdict: {}".format(res["verdict"]))
        dest_dir = pathlib.Path(out_dir) if out_dir else (
            src_dir if src_dir else DEFAULT_ARTIFACTS)
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest = dest_dir / "{}_cti_intel.json".format(label)
        dest.write_text(json.dumps(res, indent=2, default=str),
                        encoding="utf-8")
        print("[+] wrote {}".format(dest))
        written.append(dest)
    return written


def main():
    import argparse
    ap = argparse.ArgumentParser(
        description="investigate collected PE sha256 against CTI feeds")
    ap.add_argument("inputs", nargs="*",
                    help="artifacts dir / summary.json / zip / bare sha256 "
                         "(default: {})".format(DEFAULT_ARTIFACTS))
    ap.add_argument("-o", "--out-dir", help="directory for *_cti_intel.json")
    ap.add_argument("--vt-key", help="VirusTotal API key "
                                     "(else VT_API_KEY env / vm_info.json)")
    ap.add_argument("--abuse-key", help="abuse.ch Auth-Key "
                                        "(else ABUSECH_AUTH_KEY env / vm_info.json)")
    ap.add_argument("--source-timeout", type=float, default=SOURCE_TIME_LIMIT,
                    help="hard wall-clock cap per CTI source in seconds "
                         "(default {:g}; socket timeouts are {}s)".format(
                             SOURCE_TIME_LIMIT, TIMEOUT[1]))
    a = ap.parse_args()
    paths = a.inputs or [str(DEFAULT_ARTIFACTS)]
    written = run(paths, out_dir=a.out_dir, vt_key=a.vt_key,
                  abuse_key=a.abuse_key,
                  source_time_limit=a.source_timeout)
    sys.exit(0 if written else 1)


if __name__ == "__main__":
    main()
