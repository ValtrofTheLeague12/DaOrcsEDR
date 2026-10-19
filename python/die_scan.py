#!/usr/bin/env python3
"""Detect It Easy (die) scan wrapper - human and machine modes.

Human mode (default), colored only on a TTY:

    python python/die_scan.py <file> [--deep] [--save-dir DIR] [--no-color]

Machine mode (the static analyzer's contract: one JSON document on stdout,
diagnostics on stderr, exit code carries the failure category):

    python python/die_scan.py --json <file> [--deep] [--out PATH]

Exit codes: 0 scan ok, 2 usage, 3 die module missing, 4 sample unreadable,
5 scan raised / produced unparseable output.

Classification is driven by each detection value's DIE "type" field, so a
compiler (MinGW, MSVC) is never reported as a packer - the mistake the
original prototype made by keying off name == "Unknown" alone.
"""

import argparse
import datetime
import json
import os
import pathlib
import sys
import time
import uuid

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_NO_DIE = 3
EXIT_BAD_SAMPLE = 4
EXIT_SCAN_FAILED = 5

PACKER_TYPES = {"packer", "cryptor", "protector"}
LINKER_TYPES = {"linker"}
COMPILER_TYPES = {"compiler", "tool"}

_ANSI = {
    "red": "\x1b[31m",
    "green": "\x1b[32m",
    "yellow": "\x1b[33m",
    "cyan": "\x1b[36m",
    "reset": "\x1b[0m",
}


def _color(text, name, enabled):
    if not enabled:
        return text
    return _ANSI.get(name, "") + text + _ANSI["reset"]


def fail(doc, code, message, json_mode):
    doc["ok"] = False
    doc["error"] = message
    if json_mode:
        print(json.dumps(doc, indent=2))
        print("[die_scan] " + message, file=sys.stderr)
    else:
        print(_color("[-] " + message, "red", True), file=sys.stderr)
    sys.exit(code)


def classify(values):
    packers, compilers, linkers, others = [], [], [], []
    unknown = 0
    for value in values:
        name = str(value.get("name") or "").strip()
        vtype = str(value.get("type") or "").strip()
        if not name or name == "Unknown" or vtype == "Unknown":
            unknown += 1
            continue
        entry = {
            "name": name,
            "version": str(value.get("version") or ""),
            "type": vtype,
            "info": str(value.get("info") or ""),
            "string": str(value.get("string") or ""),
        }
        low = vtype.lower()
        if low in PACKER_TYPES:
            packers.append(entry)
        elif low in LINKER_TYPES:
            linkers.append(entry)
        elif low in COMPILER_TYPES:
            compilers.append(entry)
        else:
            others.append(entry)
    return packers, compilers, linkers, others, unknown


def main():
    ap = argparse.ArgumentParser(description="Detect It Easy scan (human or --json machine mode)")
    ap.add_argument("sample", help="file to scan")
    ap.add_argument("--json", action="store_true", dest="json_mode",
                    help="emit one JSON document on stdout (analyzer contract)")
    ap.add_argument("--deep", action="store_true",
                    help="add DIE DEEP_SCAN (slower, more complete)")
    ap.add_argument("--out", default="",
                    help="also write the JSON document to this path")
    ap.add_argument("--save-dir", default="",
                    help="also write the JSON document under this directory "
                         "(named <stem>_<uuid6>.json, like the original prototype)")
    ap.add_argument("--no-color", action="store_true",
                    help="disable ANSI colors")
    args = ap.parse_args()

    json_mode = bool(args.json_mode)
    color_on = (not args.no_color) and sys.stdout.isatty() and not json_mode

    doc = {
        "ok": False,
        "error": "",
        "sample": "",
        "seconds": 0.0,
        "die_version": "",
        "databases": 0,
        "packed": False,
        "unknown_only": False,
        "unknown_count": 0,
        "packers": [],
        "compilers": [],
        "linkers": [],
        "others": [],
        "detects": [],
    }

    if json_mode:
        print("[die_scan] checking signature databases...", file=sys.stderr)
    else:
        print(_color("[+] Checking DIE signatures...", "cyan", color_on))

    try:
        import die
    except ImportError:
        fail(doc, EXIT_NO_DIE,
             "die module not installed (pip install die-python)",
             json_mode)

    doc["die_version"] = str(getattr(die, "die_version", ""))
    doc["sample"] = str(pathlib.Path(args.sample).resolve())

    try:
        databases = list(die.databases())
    except Exception as exc:  # noqa: BLE001 - report, never crash
        databases = []
        if not json_mode:
            print(_color("[-] database list failed: %s" % exc, "red", color_on),
                  file=sys.stderr)
    doc["databases"] = len(databases)

    sample_path = pathlib.Path(args.sample)
    if not sample_path.exists() or not sample_path.is_file():
        fail(doc, EXIT_BAD_SAMPLE, "file not found: %s" % args.sample, json_mode)
    if sample_path.stat().st_size == 0:
        fail(doc, EXIT_BAD_SAMPLE, "file is empty: %s" % args.sample, json_mode)
    if doc["databases"] == 0:
        fail(doc, EXIT_NO_DIE, "no DIE signature databases found", json_mode)

    if not json_mode:
        print(_color("[+] DIE %s, %d signature database path(s)"
                     % (doc["die_version"] or "?", doc["databases"]),
                     "cyan", color_on))
        print(_color("[+] Scanning %s%s..."
                     % (sample_path, " (deep)" if args.deep else ""),
                     "cyan", color_on))

    flags = die.ScanFlags.RESULT_AS_JSON
    if args.deep:
        flags |= die.ScanFlags.DEEP_SCAN

    started = time.perf_counter()
    try:
        raw = die.scan_file(str(sample_path.resolve()), flags)
    except Exception as exc:  # noqa: BLE001
        doc["seconds"] = round(time.perf_counter() - started, 3)
        fail(doc, EXIT_SCAN_FAILED, "die.scan_file raised: %s" % exc, json_mode)
    doc["seconds"] = round(time.perf_counter() - started, 3)

    if not raw:
        fail(doc, EXIT_SCAN_FAILED, "die returned no output", json_mode)
    try:
        payload = json.loads(raw) if isinstance(raw, (str, bytes, bytearray)) else raw
    except (ValueError, TypeError) as exc:
        fail(doc, EXIT_SCAN_FAILED, "die output is not valid JSON: %s" % exc, json_mode)
    if not isinstance(payload, dict):
        fail(doc, EXIT_SCAN_FAILED, "die output is not a JSON object", json_mode)

    detects = payload.get("detects") or []
    if not isinstance(detects, list):
        detects = []
    values = []
    for section in detects:
        if not isinstance(section, dict):
            continue
        for value in section.get("values") or []:
            if isinstance(value, dict):
                values.append(value)

    packers, compilers, linkers, others, unknown = classify(values)
    doc["packers"] = packers
    doc["compilers"] = compilers
    doc["linkers"] = linkers
    doc["others"] = others
    doc["unknown_count"] = unknown
    doc["detects"] = detects
    doc["packed"] = bool(packers)
    doc["unknown_only"] = not (packers or compilers or linkers or others)
    doc["ok"] = True

    if args.out:
        out_path = pathlib.Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    if args.save_dir:
        save_dir = pathlib.Path(args.save_dir)
        save_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.datetime.now().strftime("%Y%m%dT%H%M%S")
        save_path = save_dir.joinpath(
            "%s_%s_%s.json" % (sample_path.stem, stamp, uuid.uuid4().hex[:6]))
        save_doc = dict(doc)
        save_doc["date_of_analysis"] = datetime.datetime.now().isoformat(timespec="seconds")
        save_path.write_text(json.dumps(save_doc, indent=2), encoding="utf-8")
        if not json_mode:
            print(_color("[+] Results written to %s" % save_path.resolve(),
                         "green", color_on))

    if json_mode:
        print(json.dumps(doc, indent=2))
        return

    if doc["unknown_only"]:
        print(_color("[!] No packer/compiler matched (DIE reported Unknown)",
                     "yellow", color_on))
    for entry in doc["packers"]:
        detail = entry["version"] or entry["info"] or ""
        print(_color("    Packer   : %s%s" % (entry["name"],
                                              " " + detail if detail else ""),
                     "red", color_on))
    for entry in doc["compilers"]:
        detail = entry["version"] or entry["info"] or ""
        print(_color("    Compiler : %s%s" % (entry["name"],
                                              " " + detail if detail else ""),
                     "yellow", color_on))
    for entry in doc["linkers"]:
        detail = entry["version"] or entry["info"] or ""
        print(_color("    Linker   : %s%s" % (entry["name"],
                                              " " + detail if detail else ""),
                     "yellow", color_on))
    for entry in doc["others"]:
        detail = entry["version"] or entry["info"] or ""
        print("    Other    : %s%s" % (entry["name"],
                                       " " + detail if detail else ""))
    if doc["packed"]:
        print(_color("[!] Sample is packed (%d packer detection(s))"
                     % len(doc["packers"]), "red", color_on))
    elif not doc["unknown_only"]:
        print(_color("[+] Not packed", "green", color_on))
    print(_color("[+] Scan finished in %.3f s (%d detection value(s))"
                 % (doc["seconds"], len(values)), "cyan", color_on))


if __name__ == "__main__":
    main()
