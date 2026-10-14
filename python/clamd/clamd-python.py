#!/usr/bin/env python3
"""Clamd in-VM scanner (runs inside the analysis VM, CLI args only).

The host-side orchestrator (_configure_clamd.py) reads vm_info.json and passes
every path/endpoint here as arguments - this script never reads vm_info.

Usage:
    python3 clamd-python.py SAMPLE --results-dir DIR [--mode unix|tcp]
                                [--socket PATH | --host H --port P]
                                [--timeout S] [--json] [--check] [--out PATH]

Exit codes: 0 scan ok (clean OR infected - the scan itself succeeded),
2 usage, 3 clamd python module missing (pip install clamd), 4 sample not
found, 5 clamd connection failed, 6 scan failed.
"""

import argparse
import datetime
import hashlib
import json
import os
import pathlib
import sys
import time
import uuid

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_NO_MODULE = 3
EXIT_BAD_SAMPLE = 4
EXIT_CONNECT = 5
EXIT_SCAN = 6

_ANSI = {"red": "\x1b[31m", "green": "\x1b[32m", "yellow": "\x1b[33m",
         "cyan": "\x1b[36m", "reset": "\x1b[0m"}


def _color(text, name, enabled):
    if not enabled:
        return text
    return _ANSI.get(name, "") + text + _ANSI["reset"]


def fail(doc, code, message, json_mode):
    doc["ok"] = False
    doc["error"] = message
    if json_mode:
        print(json.dumps(doc, indent=2))
        print("[clamd] " + message, file=sys.stderr)
    else:
        print(_color("[-] " + message, "red", True), file=sys.stderr)
    sys.exit(code)


def make_client(args, clamd):
    if args.mode == "tcp":
        return clamd.ClamdNetworkSocket(host=args.host, port=args.port,
                                        timeout=args.timeout), \
               "tcp:%s:%d" % (args.host, args.port)
    return clamd.ClamdUnixSocket(path=args.socket, timeout=args.timeout), \
           "unix:%s" % args.socket


def main():
    ap = argparse.ArgumentParser(
        description="Detect It Easy-style ClamAV scan of one placed sample")
    ap.add_argument("sample", help="absolute path of the sample INSIDE the VM "
                                   "(the host placed it there)")
    ap.add_argument("--results-dir", default="",
                    help="directory for the result JSON (created if missing)")
    ap.add_argument("--out", default="",
                    help="write the result JSON to this exact path instead of "
                         "<results-dir>/<stem>_<uuid6>.json")
    ap.add_argument("--mode", choices=("unix", "tcp"), default="unix")
    ap.add_argument("--socket", default="/var/run/clamav/clamd.ctl",
                    help="clamd control socket (mode=unix)")
    ap.add_argument("--host", default="127.0.0.1", help="clamd host (mode=tcp)")
    ap.add_argument("--port", type=int, default=3310, help="clamd port (mode=tcp)")
    ap.add_argument("--timeout", type=float, default=60.0)
    ap.add_argument("--check", action="store_true",
                    help="connection test only (ping + version), no scan")
    ap.add_argument("--json", action="store_true", dest="json_mode",
                    help="emit one JSON document on stdout (host contract)")
    ap.add_argument("--no-color", action="store_true")
    args = ap.parse_args()

    json_mode = bool(args.json_mode)
    color_on = (not args.no_color) and sys.stdout.isatty() and not json_mode

    doc = {
        "ok": False,
        "error": "",
        "date_of_analysis": "",
        "sample": "",
        "filename": "",
        "sha256": "",
        "verdict": "",
        "status": "",
        "signature": "",
        "detail": "",
        "clamd_version": "",
        "endpoint": "",
        "seconds": 0.0,
    }

    if json_mode:
        print("[clamd] importing clamd...", file=sys.stderr)
    else:
        print(_color("[+] Importing clamd...", "cyan", color_on))

    try:
        import clamd
    except ImportError:
        fail(doc, EXIT_NO_MODULE,
             "clamd module not installed (pip install clamd)", json_mode)

    doc["endpoint"] = "%s:%s" % (args.mode,
                                 args.socket if args.mode == "unix"
                                 else "%s:%d" % (args.host, args.port))

    sample_path = pathlib.Path(args.sample).expanduser()
    if not sample_path.is_absolute():
        fail(doc, EXIT_USAGE,
             "sample path must be absolute inside the VM, got: %s" % args.sample,
             json_mode)
    if args.check:
        # --check: the sample argument is still required by the CLI (the host
        # always has one), but it does not have to exist for a ping.
        sample_path = None
    elif not sample_path.is_file():
        fail(doc, EXIT_BAD_SAMPLE,
             "sample not found at placement path: %s" % sample_path, json_mode)
    elif sample_path.stat().st_size == 0:
        fail(doc, EXIT_BAD_SAMPLE, "sample is empty: %s" % sample_path, json_mode)

    client, endpoint = make_client(args, clamd)
    doc["endpoint"] = endpoint

    if not json_mode:
        print(_color("[+] Connecting to clamd (%s)..." % endpoint, "cyan", color_on))

    started = time.perf_counter()
    try:
        pong = client.ping()
    except Exception as exc:  # noqa: BLE001 - clamd.ConnectionError and friends
        doc["seconds"] = round(time.perf_counter() - started, 3)
        fail(doc, EXIT_CONNECT, "clamd ping failed: %s" % exc, json_mode)
    if pong != "PONG":
        doc["seconds"] = round(time.perf_counter() - started, 3)
        fail(doc, EXIT_CONNECT, "clamd answered %r to PING (expected 'PONG')"
             % pong, json_mode)

    try:
        doc["clamd_version"] = str(client.version() or "")
    except Exception:  # noqa: BLE001 - version is informational only
        pass

    if not json_mode:
        print(_color("[+] PONG - clamd %s" % (doc["clamd_version"] or "?"),
                     "green", color_on))

    if args.check:
        doc["ok"] = True
        doc["verdict"] = "reachable"
        doc["date_of_analysis"] = datetime.datetime.now(
            datetime.timezone.utc).isoformat(timespec="seconds")
        doc["seconds"] = round(time.perf_counter() - started, 3)
        if json_mode:
            print(json.dumps(doc, indent=2))
        else:
            print(_color("[+] Connection OK", "green", color_on))
        sys.exit(EXIT_OK)

    assert sample_path is not None
    doc["sample"] = str(sample_path)
    doc["filename"] = sample_path.name
    try:
        digest = hashlib.sha256()
        with sample_path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                digest.update(chunk)
        doc["sha256"] = digest.hexdigest()
    except OSError as exc:
        fail(doc, EXIT_BAD_SAMPLE, "cannot read sample: %s" % exc, json_mode)

    if not json_mode:
        print(_color("[+] Scanning %s..." % sample_path, "cyan", color_on))

    try:
        results = client.scan(str(sample_path))
    except Exception as exc:  # noqa: BLE001
        doc["seconds"] = round(time.perf_counter() - started, 3)
        fail(doc, EXIT_SCAN, "clamd scan failed: %s" % exc, json_mode)
    doc["seconds"] = round(time.perf_counter() - started, 3)

    if not results:
        fail(doc, EXIT_SCAN, "clamd returned no results", json_mode)

    # clamd.scan() -> {path: (status, reason)}; status in FOUND/OK/ERROR and
    # reason is the signature name for FOUND, the error text for ERROR.
    entry = results.get(str(sample_path))
    if entry is None and results:
        entry = next(iter(results.values()))
    if not isinstance(entry, (tuple, list)) or len(entry) < 2:
        fail(doc, EXIT_SCAN, "unparseable clamd result: %r" % (entry,), json_mode)
    status, reason = str(entry[0]), str(entry[1] if len(entry) > 1 else "")

    doc["status"] = status
    if status == "FOUND":
        doc["ok"] = True
        doc["verdict"] = "infected"
        doc["signature"] = reason
    elif status == "OK":
        doc["ok"] = True
        doc["verdict"] = "clean"
    else:
        doc["verdict"] = "error"
        doc["detail"] = reason

    doc["date_of_analysis"] = datetime.datetime.now(
        datetime.timezone.utc).isoformat(timespec="seconds")

    if args.out:
        out_path = pathlib.Path(args.out).expanduser()
        out_path.parent.mkdir(parents=True, exist_ok=True)
    elif args.results_dir:
        results_dir = pathlib.Path(args.results_dir).expanduser()
        results_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.datetime.now().strftime("%Y%m%dT%H%M%S")
        out_path = results_dir.joinpath(
            "%s_%s_%s.json" % (sample_path.stem, stamp, uuid.uuid4().hex[:6]))
    else:
        out_path = None

    if out_path is not None:
        out_path.write_text(json.dumps(doc, indent=2), encoding="utf-8")
        try:
            os.chmod(out_path, 0o600)
        except OSError:
            pass
        if not json_mode:
            print(_color("[+] Result written to %s" % out_path, "green", color_on))

    if json_mode:
        print(json.dumps(doc, indent=2))
        return

    if doc["verdict"] == "infected":
        print(_color("[!] INFECTED: %s" % doc["signature"], "red", color_on))
    elif doc["verdict"] == "clean":
        print(_color("[+] Clean - no signature matched", "green", color_on))
    else:
        print(_color("[!] Scan error: %s" % doc["detail"], "yellow", color_on))
    print(_color("[+] Scan finished in %.3f s" % doc["seconds"], "cyan", color_on))


if __name__ == "__main__":
    main()
