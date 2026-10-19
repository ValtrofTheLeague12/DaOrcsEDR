#!/usr/bin/env python3
"""yarGen rule generation wrapper - human and machine modes.

yarGen-Go answers a question the analyzer's own YARA phase cannot: not "does
this sample match a known rule" but "what rule would have caught it". The rule
packs in yara-rules/ are the past; this is the future.

Human mode (default):

    python python/yara_gen.py <file> [--out PATH]

Machine mode - the static analyzer's contract, identical in shape to
die_scan.py: one JSON document on stdout, diagnostics on stderr, and the exit
code carries the failure category.

    python python/yara_gen.py --json <file> --out PATH

Exit codes: 0 rules generated, 2 usage, 3 yarGen-Go not present, 4 the sample
is unreadable, 5 yarGen ran and failed, 6 it produced nothing parseable.

Three things about yarGen are not obvious and are handled here rather than left
to the caller:

It resolves its database directory relative to the WORKING DIRECTORY, not to
its own location. Run it from anywhere else and it reports

    failed to read database directory ./dbs

with an error that reads like a missing download rather than the wrong cwd. The
cwd is pinned to the checkout for that reason.

It refuses to start without config/config.yaml, and only config.example.yml is
committed - because that file holds an LLM API key. So -no-llm is passed when
there is no config, which makes rule generation work with no credentials at
all. Only the LLM enrichment step is lost, and losing it degrades rule quality
rather than breaking the phase. That is the opposite trade from yargen's own
script, which treats the missing config as a fault to report; here it is a
documented downgrade, and `llm_used` says which happened.

Author and identifier are passed explicitly. Left to its defaults yarGen writes
"yarGen" as the author on every rule, and a rule set attributed to nobody is
one nobody will maintain.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import socket
import subprocess
import sys
import time
import urllib.parse
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
YARGEN_DIR = REPO / "yarGen-Go"
YARGEN_EXE = YARGEN_DIR / "yargen.exe"
CONFIG = YARGEN_DIR / "config" / "config.yaml"
DBS = YARGEN_DIR / "dbs"
EXAMPLE_CONFIG = YARGEN_DIR / "config" / "config.example.yml"

DEFAULT_TIMEOUT = 600


def _fail(status: str, message: str, **extra) -> dict:
    doc = {"ok": False, "status": status, "message": message}
    doc.update(extra)
    return doc


def _preflight() -> tuple[str | None, dict]:
    """(status, detail). status is None when yarGen can be attempted."""
    detail: dict = {}

    if not YARGEN_DIR.is_dir():
        return "yargen_missing", {"reason": "yarGen-Go/ is not present in this checkout"}
    if not YARGEN_EXE.is_file():
        return "yargen_missing", {
            "reason": "yargen.exe not found",
            "fix": "the binary is not committed; build it with the Go toolchain",
        }

    # The databases are generated and gitignored, so a fresh clone has none and
    # yarGen still starts - it just scores every string as unseen noise. Worth
    # calling out even though it does not stop us.
    if DBS.is_dir():
        entries = sum(1 for p in DBS.rglob("*") if p.is_file())
        detail["db_files"] = entries
        if entries == 0:
            detail["db_warning"] = "dbs/ is empty; rule quality will be poor"
    else:
        detail["db_warning"] = "dbs/ is missing; run the yarGen-Go update in the Utils page"

    detail["llm_configured"] = CONFIG.is_file()
    detail["example_config"] = EXAMPLE_CONFIG.is_file()
    return None, detail


def _count_rules(text: str) -> tuple[int, int]:
    """(simple rules, super rules) by parsing `rule X {` and `rule X : X1 {`.

    Counted rather than trusted: yarGen prints its own tally on stdout, and the
    rule file is the artifact that ships. If they ever disagree, the file wins.
    """
    simple = 0
    super_rules = 0
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped.startswith("rule "):
            continue
        head = stripped[len("rule "):]
        name = head.split("{", 1)[0].split(":", 1)[0].strip()
        if not name:
            continue
        # A super rule declares its members: `rule Super : a b c {`
        if ":" in head.split("{", 1)[0]:
            super_rules += 1
        else:
            simple += 1
    return simple, super_rules


def _config_provider_and_endpoint() -> tuple[str, str]:
    """(provider, endpoint) from config.yaml, defaults matching yarGen's own."""
    provider, endpoint = "openai", ""
    try:
        text = CONFIG.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return provider, endpoint
    in_llm = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if not in_llm:
            # crude but adequate: the `llm:` block is the only one with these keys
            if stripped.rstrip(":") == "llm" and stripped.endswith(":"):
                in_llm = True
            continue
        if stripped and not line.startswith((" ", "\t")):
            break  # left the llm block
        if ":" not in stripped:
            continue
        key, _, value = stripped.partition(":")
        value = value.strip().strip('"').strip("'")
        if key.strip() == "provider" and value:
            provider = value
        elif key.strip() == "endpoint":
            endpoint = value
    return provider, endpoint


def _port_open(url: str, timeout: float = 1.0) -> bool:
    """Whether something is listening at url's host and port."""
    try:
        parsed = urllib.parse.urlparse(url if "//" in url else f"http://{url}")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        with socket.create_connection((parsed.hostname or "localhost", port),
                                      timeout=timeout):
            return True
    except Exception:  # noqa: BLE001 - any failure means "not reachable"
        return False


def _llm_usable() -> tuple[bool, str]:
    """Whether the LLM pass can actually run, and why not when it cannot.

    Having config.yaml is NOT the same as being able to use it. The config
    carries `api_key: "${OPENAI_API_KEY}"`, so with the variable unset yarGen
    tries the API, gets "Incorrect API key provided: ${OPENAI...}", and then
    exits non-zero WITHOUT writing a rule file - verified, not assumed. The
    rules are fine on their own; it is the LLM refinement that kills the run.

    Which check applies depends on the provider, and assuming otherwise is how
    this goes wrong in both directions:

      * openai / anthropic / gemini need their key in the environment, so the
        `${VAR}` expansion is checked.
      * ollama needs NO key. It is a local server. Requiring OPENAI_API_KEY for
        it would refuse a perfectly working local setup, and the refusal would
        name a variable that has nothing to do with it. So the endpoint is
        probed instead - and "ollama is not running" is the honest reason, which
        is also the one the operator can actually act on.

    Returns (usable, reason). `reason` names what to do, not just what is
    missing.
    """
    if not CONFIG.is_file():
        return False, "no config.yaml"

    try:
        text = CONFIG.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return False, f"could not read config.yaml: {exc}"

    provider, endpoint = _config_provider_and_endpoint()

    if provider == "ollama":
        url = endpoint or "http://localhost:11434"
        if not _port_open(url):
            return False, f"ollama is not reachable at {url}"
        return True, ""

    # Only `${VAR}` expansion needs checking. A literal key was typed into the
    # file by a person, and whether it works is not something to second-guess.
    #
    # Comments are skipped. This file's own documentation writes `${VAR}` while
    # explaining the syntax, and a whole-file scan reads that as a variable the
    # operator forgot to set - which disables the LLM pass and reports the
    # wrong reason for it.
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        for match in re.finditer(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}", stripped):
            name = match.group(1)
            if not os.environ.get(name):
                return False, f"{name} is not set"
    return True, ""


def generate(sample: Path, out: Path, author: str, identifier: str | None,
             timeout: int, extra_args: list[str]) -> dict:
    status, detail = _preflight()
    if status:
        return _fail(status, detail.pop("reason", status), **detail)

    if not sample.is_file():
        return _fail("sample_unreadable", f"{sample} does not exist", **detail)

    identifier = identifier or sample.stem
    # Not "does the config exist" - "can the LLM actually run". A config whose
    # ${OPENAI_API_KEY} is unset makes yarGen fail the whole run, so the key is
    # what decides, and the reason travels into the output.
    llm, llm_reason = _llm_usable()
    detail["llm_usable"] = llm
    detail["llm_reason"] = llm_reason

    # Absolute output: yarGen resolves it relative to its cwd, and we are about
    # to change the cwd.
    out = out.resolve()
    try:
        out.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        return _fail("output_unwritable", f"could not create {out.parent}: {exc}",
                     **detail)
    if out.exists():
        try:
            out.unlink()
        except OSError as exc:
            return _fail("output_unwritable", f"could not replace {out}: {exc}",
                         **detail)

    argv = [str(YARGEN_EXE), "-f", str(sample.resolve()), "-o", str(out),
            "-a", author, "-b", identifier, *extra_args]
    if not llm:
        # Either there is no config, or the key it points at is not set. Either
        # way, do not hand yarGen a config it will fail on: skip the LLM pass
        # explicitly so the rules are still generated.
        argv.append("-no-llm")

    started = time.time()
    try:
        proc = subprocess.run(
            argv, cwd=str(YARGEN_DIR),           # <- the whole reason this wrapper exists
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=timeout, check=False,
        )
    except subprocess.TimeoutExpired:
        return _fail("timeout", f"yarGen did not finish within {timeout}s",
                     duration=round(time.time() - started, 2), **detail)
    except OSError as exc:
        return _fail("spawn_failed", f"could not run yargen.exe: {exc}", **detail)

    duration = round(time.time() - started, 2)
    combined = (proc.stdout or "") + (proc.stderr or "")

    if proc.returncode != 0 or not out.is_file():
        # yarGen prints an actionable numbered list on a config failure. The
        # first [E] line is the reason; keep the tail too, because the numbered
        # steps that follow it are the fix.
        errors = [ln.strip() for ln in combined.splitlines() if ln.strip().startswith("[E]")]
        hints = [ln.strip() for ln in combined.splitlines()
                 if re.match(r"^\s+\d+\.\s", ln)]
        message = errors[0] if errors else (
            f"yarGen exited {proc.returncode} without writing a rule file")
        return _fail("yargen_failed", message, duration=duration,
                     returncode=proc.returncode, hints=hints[:6],
                     log_tail=combined.splitlines()[-12:], **detail)

    text = out.read_text(encoding="utf-8", errors="replace")
    simple, super_rules = _count_rules(text)
    if simple == 0 and super_rules == 0:
        # A file with no `rule` in it is not a failure to yarGen but is useless
        # as a detection artifact, and shipping it would be worse than saying so.
        return _fail("no_rules", "yarGen wrote a file containing no rules",
                     duration=duration, rule_file=str(out),
                     rule_bytes=out.stat().st_size, **detail)

    return {
        "ok": True,
        "status": "ok",
        "message": f"{simple + super_rules} rule(s) generated",
        "rule_file": str(out),
        "rule_bytes": out.stat().st_size,
        "simple_rules": simple,
        "super_rules": super_rules,
        "identifier": identifier,
        "author": author,
        "llm_used": llm,
        "duration": duration,
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "yargen": str(YARGEN_EXE.relative_to(REPO)),
        "sample": str(sample),
        **detail,
    }


def _print_human(doc: dict) -> int:
    if doc.get("ok"):
        print(f"  {doc['message']}")
        print(f"  rules    : {doc['rule_file']} ({doc['rule_bytes']:,} bytes)")
        print(f"  llm      : {'used' if doc.get('llm_used') else 'skipped (' + (doc.get('llm_reason') or 'no config') + ')'}")
        if doc.get("db_warning"):
            print(f"  warning  : {doc['db_warning']}")
        return 0

    print(f"  yarGen failed: {doc.get('message')}", file=sys.stderr)
    for hint in doc.get("hints") or []:
        print(f"    {hint}", file=sys.stderr)
    if doc.get("fix"):
        print(f"    fix: {doc['fix']}", file=sys.stderr)
    if doc.get("reason"):
        print(f"    reason: {doc['reason']}", file=sys.stderr)
    return 5


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("sample", help="the analyzed sample to generate rules from")
    p.add_argument("--out", required=True, help="output .yar path")
    p.add_argument("--json", action="store_true",
                   help="machine mode: one JSON document on stdout")
    p.add_argument("--author", default="IAProject",
                   help="rule author (default: IAProject)")
    p.add_argument("--identifier", default=None,
                   help="rule identifier (default: the sample's stem)")
    p.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    p.add_argument("--nomagic", action="store_true",
                   help="omit the magic header condition")
    p.add_argument("--nofilesize", action="store_true",
                   help="omit the filesize condition")
    p.add_argument("--excludegood", action="store_true",
                   help="exclude goodware strings, using the databases")
    p.add_argument("--opcodes", type=int, default=None,
                   help="number of opcodes per rule (default: yarGen's own)")
    args = p.parse_args(argv)

    extra = []
    if args.nomagic:
        extra.append("-nomagic")
    if args.nofilesize:
        extra.append("-nofilesize")
    if args.excludegood:
        extra.append("-excludegood")
    if args.opcodes is not None:
        extra += ["-n", str(args.opcodes)]

    sample = Path(args.sample)
    if not sample.is_absolute():
        sample = (REPO / sample) if (REPO / sample).exists() else sample

    doc = generate(sample, Path(args.out), args.author, args.identifier,
                   args.timeout, extra)

    if args.json:
        print(json.dumps(doc, indent=2))
    else:
        _print_human(doc)

    if doc.get("ok"):
        return 0
    return {
        "yargen_missing": 3, "sample_unreadable": 4, "timeout": 5,
        "yargen_failed": 5, "no_rules": 6, "output_unwritable": 6,
        "spawn_failed": 3,
    }.get(doc.get("status", ""), 5)


if __name__ == "__main__":
    sys.exit(main())