#!/usr/bin/env python3
"""List the evidence bundles that exist on MEGA.

    mega/list.py
      -> every <name>_artifact/ folder at the MEGA root

    mega/list.py --remote-root /Cases/2026-10
      -> the bundles under that folder

    mega/list.py --details
      -> one row per bundle plus the files inside it

    mega/list.py --all
      -> every remote folder, not just the ones named like a bundle

    mega/list.py --json
      -> machine-readable

Exit codes: 0 ok, 1 MEGAcmd failed, 2 no usable session, 3 MEGAcmd missing.

How this reads MEGA
-------------------
MEGAcmd has no JSON output for `ls`, so the summary listing is parsed:

    FLAGS VERS      SIZE    DATE       NAME
    d     1          1234   2026-10-13  quick_test_artifact
    -     1        541106   2026-10-13  quick_test_evidence.tar.gz

FLAGS carries the node kind in its last character - d folder, - file, r root,
i inbox, b rubbish, x unsupported - so a bundle is recognised by a `d` row, not
by a name guess alone. --time-format=ISO6081 pins the date column, because the
default format is free to change between builds.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import megacmd  # noqa: E402

SUFFIX = "_artifact"


def human(n: int) -> str:
    step = float(n)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if step < 1024 or unit == "TiB":
            return f"{step:.0f} {unit}" if unit == "B" else f"{step:.1f} {unit}"
        step /= 1024
    return f"{n} B"


# A row is: FLAGS VERS SIZE DATE NAME. Two traps, both hit in practice.
#
#  * DATE can be one token ("2026-10-13") or two ("13Oct2026 15:53:11").
#    --time-format=ISO6081 is documented but this build ignores it and emits
#    the two-token SHORT form, so the shape has to be tolerated either way
#    rather than assumed.
#  * NAME may contain spaces, so it has to be whatever is left.
_ROW = re.compile(
    r"^(?P<flags>\S+)\s+(?P<vers>\S+)\s+(?P<size>\S+)\s+"
    r"(?P<date>(?:\d{4}-\d{2}-\d{2}(?:\s+\d{2}:\d{2}(?::\d{2})?)?)"
    r"|(?:\d{2}[A-Za-z]{3}\d{4}\s+\d{2}:\d{2}:\d{2}))\s+(?P<name>.+)$")


def parse_ls(text: str) -> list[dict]:
    rows = []
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("FLAGS"):
            continue
        m = _ROW.match(s)
        if not m:
            continue
        flags = m.group("flags")
        # `ls -l` FLAGS reads left to right: the TYPE is the leftmost char
        # (d folder, - file, r root, i inbox, b rubbish, x unsupported) and the
        # remaining three are sharing/export status. Reading the last char
        # instead makes every folder look like a file.
        kind = flags[0] if flags else "-"
        size = m.group("size")
        rows.append({
            "name": m.group("name").strip(),
            "kind": kind,
            "is_dir": kind == "d",
            # Folders report "-" for both VERS and SIZE.
            "size": int(size) if size.isdigit() else 0,
            "date": " ".join(m.group("date").split()),
        })
    return rows


def ls(remote: str, timeout: int) -> list[dict]:
    res = megacmd.run("ls", "-l", "--time-format=ISO6081", remote, timeout=timeout)
    return parse_ls(res.out)


def guard() -> int | None:
    """Returns an exit code if we cannot proceed, else None."""
    if not megacmd.available():
        print("list: " + megacmd.missing_message(), file=sys.stderr)
        return 3
    who = megacmd.whoami()
    if not who:
        print("list: no MEGAcmd session. Run: python mega/login.py --mega", file=sys.stderr)
        return 2
    return None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--remote-root", default="/",
                    help="remote folder to look in (default: the MEGA root)")
    ap.add_argument("--all", action="store_true",
                    help="list every folder, not just <name>_artifact bundles")
    ap.add_argument("--details", action="store_true",
                    help="also list the files inside each bundle")
    ap.add_argument("--json", dest="as_json", action="store_true",
                    help="machine-readable output")
    ap.add_argument("--timeout", type=int, default=megacmd.DEFAULT_TIMEOUT)
    args = ap.parse_args()

    stop = guard()
    if stop is not None:
        return stop

    root = args.remote_root.rstrip("/") or "/"
    try:
        rows = ls(root, args.timeout)
    except megacmd.MegaError as exc:
        print(f"list: {exc}", file=sys.stderr)
        return 1

    bundles = [r for r in rows if r["is_dir"] and (args.all or r["name"].endswith(SUFFIX))]

    if args.as_json:
        payload = {"remote_root": root, "account": megacmd.whoami(), "bundles": bundles}
        print(json.dumps(payload, indent=2))
        return 0

    account = megacmd.whoami()
    print(f"account : {account}")
    print(f"remote  : {root}")
    if not bundles:
        print(f"\nno {'folders' if args.all else SUFFIX + ' bundles'} here")
        return 0

    print(f"\n{len(bundles)} bundle(s)\n")
    for row in bundles:
        total = 0
        count = 0
        if args.details:
            try:
                inner = ls(f"{root}/{row['name']}".replace("//", "/"), megacmd.QUICK_TIMEOUT)
            except megacmd.MegaError:
                inner = []
            files = [r for r in inner if not r["is_dir"]]
            total = sum(r["size"] for r in files)
            count = len(files)
        print(f"  {row['name']}   {row['date']}")
        if args.details:
            for r in inner:
                if r["is_dir"]:
                    continue
                print(f"      {human(r['size']):>11}  {r['name']}")
            print(f"      {human(total):>11}  ({count} file(s))")
    return 0


if __name__ == "__main__":
    sys.exit(main())