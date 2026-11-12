#!/usr/bin/env python3
"""Regenerate the Unprotect.it rules and import the YARA delta.

`unprotect_it_scraper/scrape.py` mirrors unprotect.it's detection-rules table and
downloads the raw form of every rule it lists. The site publishes three kinds:

* **YARA** - imported into `yara-rules/unprotect_it/`, but only the part the
  analyzer does not already have. About 95% of the site's YARA is a copy of the
  PEiD pack already vendored under `Malekith_Rules/packers/peid.yar`; the
  remaining anti-debug / anti-VM / packer / crypter rules are the useful delta.
  The site stores fragments of a combined file, so a file that uses `pe.*`
  without `import "pe"` gets the import prepended - 21 of the 90 scraped files
  do not compile without it.

* **Sigma** - kept in the scraper's staging directory. There is no Sigma engine
  in this analyzer, so importing them would only make the tree look like it has
  coverage it cannot use.

* **CAPA** - deliberately ignored. The site publishes legacy syntax
  (`meta.scope`, `offset/x32`), and capa 9 rejects the whole rule set with
  "legacy rule detected" (exit code 12). One invalid file fails the analyzer's
  entire capa phase, so copying these in would remove coverage, not add it.

The target directory is regenerated wholesale, so a rule removed upstream
disappears on the next run. A failed scrape leaves the previous state alone:
the mirror and the staging directory are moved aside before the run and put
back if it produces no rules, and `yara-rules/unprotect_it/` is only touched
after the scraper exits successfully.
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

SCRIPT = Path(__file__).resolve()
REPO = SCRIPT.parents[3]

SCRAPER_DIR = REPO / "unprotect_it_scraper"
SCRAPER = SCRAPER_DIR / "scrape.py"
HTML_SRC = SCRAPER_DIR / "html_src"
STAGING = SCRAPER_DIR / "extracted_rules"
STAGED_YARA = STAGING / "yara"
STAGED_SIGMA = STAGING / "sigma"
STAGED_CAPA = STAGING / "capa"

YARA_RULES = REPO / "yara-rules"
TARGET = YARA_RULES / "unprotect_it"
MANIFEST = TARGET / "_manifest.json"

SOURCE_URL = "https://unprotect.it/detection-rules/"

# The scraper's own imports. Checked before the button is offered: a missing
# bs4/requests/colorama would otherwise be discovered as a traceback after the
# job had already started and rewritten the staging directory.
REQUIRED_MODULES = ("bs4", "requests", "colorama")

_RULE_RE = re.compile(
    r'^\s*(?:private\s+|global\s+)*rule\s+([A-Za-z_]\w*)', re.MULTILINE)


def _rel(path: Path) -> str:
    try:
        return str(path.relative_to(REPO))
    except ValueError:
        return str(path)


def _rule_ids(text: str) -> list[str]:
    return _RULE_RE.findall(text)


def _existing_rule_ids(exclude: Path | None = None) -> set[str]:
    """Every rule identifier already vendored under yara-rules/.

    The target collection is excluded so a regeneration compares the site
    against the OTHER packs rather than against its own previous output - a
    file that was imported once must still count as new next time.
    """
    excluded = TARGET if exclude is None else exclude
    ids: set[str] = set()
    if not YARA_RULES.is_dir():
        return ids
    for path in YARA_RULES.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in (".yar", ".yara"):
            continue
        try:
            if excluded in path.parents:
                continue
            ids.update(_rule_ids(path.read_text(encoding="utf-8", errors="replace")))
        except OSError:
            continue
    return ids


def _ensure_pe_import(text: str) -> tuple[str, bool]:
    """Add `import "pe"` when a fragment uses the module but never imports it."""
    if re.search(r'^\s*import\s+"pe"', text, re.MULTILINE):
        return text, False
    if re.search(r"\bpe\.", text):
        return 'import "pe"\n\n' + text, True
    return text, False


def _staging_aside(log) -> Path | None:
    """Move the last scrape's output aside so a failure can restore it.

    Clearing the staging files in place would lose the staged Sigma rules when
    the site is unreachable, even though the previous scrape was fine. Moving
    the directory gives the scraper a clean tree and gives us something to put
    back.
    """
    if not STAGING.is_dir():
        return None
    backup = STAGING.with_name(STAGING.name + ".previous")
    shutil.rmtree(backup, ignore_errors=True)
    try:
        os.replace(STAGING, backup)
    except OSError as exc:
        log(f"[-] could not move the previous scrape aside: {exc}")
        return None
    return backup


def _restore_staging(backup: Path | None) -> None:
    """Put the previous scrape back, or remove a partial new one."""
    shutil.rmtree(STAGING, ignore_errors=True)
    if backup is None:
        return
    try:
        os.replace(backup, STAGING)
    except OSError:
        pass


def _staged_count(directory: Path, suffixes: tuple[str, ...]) -> int:
    if not directory.is_dir():
        return 0
    return sum(1 for p in directory.iterdir()
               if p.is_file() and p.suffix.lower() in suffixes)


def _manifest() -> dict:
    try:
        data = json.loads(MANIFEST.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def state() -> dict:
    """What the card needs, without walking the rule corpus.

    Deliberately cheap: the Utils page polls this every 30s, and comparing the
    site against yara-rules/ is a job for the button, not for a status read.
    """
    missing = [name for name in REQUIRED_MODULES
               if importlib.util.find_spec(name) is None]
    scraper_present = SCRAPER.is_file()
    httrack = shutil.which("httrack")
    yara_files = sorted(TARGET.glob("*.yar")) if TARGET.is_dir() else []
    yara_bytes = 0
    for path in yara_files:
        try:
            yara_bytes += path.stat().st_size
        except OSError:
            pass

    manifest = _manifest()
    reason = None
    if not scraper_present:
        reason = f"{_rel(SCRAPER)} is missing"
    elif missing:
        reason = ("the scraper needs Python module(s) this interpreter does not "
                  "have: " + ", ".join(missing))
    elif not httrack:
        # The wrapper re-mirrors on every run, so the cached html_src/ is not a
        # fallback here: without httrack the scrape cannot see a new rule.
        reason = ("httrack is not installed; the scraper cannot mirror "
                  "unprotect.it")

    if not scraper_present:
        note = "the Unprotect.it scraper is not present"
    elif missing:
        note = "install the missing module(s) to enable the regeneration"
    elif not httrack:
        note = "install httrack to enable the regeneration"
    elif not yara_files:
        note = "no rules imported yet - press the button to scrape and import"
    else:
        note = (f"{len(yara_files)} YARA file(s) imported from the last scrape; "
                f"Sigma is staged, CAPA is ignored")

    return {
        "available": scraper_present and not missing and bool(httrack),
        "reason": reason,
        "note": note,
        "source": SOURCE_URL,
        "scraper_path": _rel(SCRAPER),
        "httrack": httrack,
        "html_src_present": HTML_SRC.is_dir(),
        "target_path": _rel(TARGET),
        "yara_files": len(yara_files),
        "yara_bytes": yara_bytes,
        "sigma_files": _staged_count(STAGED_SIGMA, (".yaml", ".yml")),
        "sigma_path": _rel(STAGED_SIGMA),
        "capa_files": _staged_count(STAGED_CAPA, (".capa",)),
        "generated_at": manifest.get("generated_at"),
        "last_import": manifest or None,
        "deps_missing": missing,
    }


def _mirror_aside(log) -> Path | None:
    """Move the cached HTTrack mirror aside so the scraper re-mirrors the site.

    `scrape.py` only runs httrack when `html_src/` is absent. Leaving the cache
    in place would re-download every rule already listed but never discover a
    rule added upstream, so "regenerate" would silently mean "re-fetch the old
    list". The old mirror is restored if the scrape fails.
    """
    if not HTML_SRC.is_dir():
        return None
    backup = HTML_SRC.with_name(HTML_SRC.name + ".previous")
    shutil.rmtree(backup, ignore_errors=True)
    try:
        os.replace(HTML_SRC, backup)
    except OSError as exc:
        log(f"[-] could not move the cached mirror aside: {exc}")
        return None
    log(f"[*] re-mirroring {SOURCE_URL} (the previous mirror is kept until the "
        f"scrape succeeds)")
    return backup


def _restore_mirror(backup: Path | None) -> None:
    """Put the previous mirror back, or remove a partial new one."""
    shutil.rmtree(HTML_SRC, ignore_errors=True)
    if backup is None:
        return
    try:
        os.replace(backup, HTML_SRC)
    except OSError:
        pass


def _run_scraper(log) -> int:
    env = dict(os.environ)
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUNBUFFERED"] = "1"
    try:
        proc = subprocess.Popen(
            [sys.executable, str(SCRAPER)],
            cwd=str(SCRAPER_DIR), env=env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding="utf-8", errors="replace", bufsize=1,
        )
    except OSError as exc:
        log(f"[-] could not start the scraper: {exc}")
        return 1
    assert proc.stdout is not None
    for line in proc.stdout:
        log(line.rstrip("\n"))
    return proc.wait()


def import_yara(log) -> dict:
    """Filter the staged YARA files and replace yara-rules/unprotect_it/."""
    if not STAGED_YARA.is_dir():
        raise FileNotFoundError(f"{_rel(STAGED_YARA)} does not exist")

    staged = sorted(STAGED_YARA.glob("*.yar"))
    if not staged:
        raise FileNotFoundError(f"the scrape produced no YARA files in {_rel(STAGED_YARA)}")

    existing = _existing_rule_ids()
    log(f"[*] comparing {len(staged)} scraped file(s) against "
        f"{len(existing):,} rule identifier(s) already in yara-rules/")

    kept = 0
    skipped_duplicate = 0
    without_rules = 0
    imports_added = 0
    new_ids: set[str] = set()
    kept_names: list[str] = []

    # Filter first, write second. The previous version cleared TARGET before it
    # knew whether anything survived the duplicate check, so a scrape that only
    # returned rules already vendored elsewhere wiped the collection and then
    # raised "the previous import was left in place" - which was not true.
    pending: list[tuple[str, str]] = []
    for path in staged:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            log(f"    could not read {path.name}: {exc}")
            continue
        ids = set(_rule_ids(text))
        if not ids:
            without_rules += 1
            continue
        fresh = ids - existing
        if not fresh:
            skipped_duplicate += 1
            continue
        text, added = _ensure_pe_import(text)
        pending.append((path.name, text))
        kept_names.append(path.name)
        new_ids |= fresh
        imports_added += int(added)

    if not pending:
        raise RuntimeError("every scraped YARA file duplicated an existing rule; "
                           "the previous import was left in place")

    # Build the replacement beside the target, then swap it in, so a write
    # failure cannot leave yara-rules/unprotect_it/ half-emptied.
    TARGET.parent.mkdir(parents=True, exist_ok=True)
    staging_out = Path(tempfile.mkdtemp(prefix=".unprotect_it-", dir=TARGET.parent))
    try:
        for name, text in pending:
            (staging_out / name).write_text(text, encoding="utf-8")
        TARGET.mkdir(parents=True, exist_ok=True)
        for path in TARGET.iterdir():
            if path.is_file():
                try:
                    path.unlink()
                except OSError:
                    pass
        for path in staging_out.iterdir():
            os.replace(path, TARGET / path.name)
        kept = len(pending)
    finally:
        shutil.rmtree(staging_out, ignore_errors=True)

    manifest = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "source": SOURCE_URL,
        "yara_files": kept,
        "new_rule_ids": len(new_ids),
        "skipped_duplicate_files": skipped_duplicate,
        "files_without_rules": without_rules,
        "pe_imports_added": imports_added,
        "sigma_files": _staged_count(STAGED_SIGMA, (".yaml", ".yml")),
        "capa_ignored": _staged_count(STAGED_CAPA, (".capa",)),
        "files": kept_names,
    }
    MANIFEST.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


def main() -> int:
    print(f"[*] Unprotect.it: scraping {SOURCE_URL}")
    mirror = _mirror_aside(print)
    staging = _staging_aside(print)
    code = _run_scraper(print)
    if code != 0:
        _restore_mirror(mirror)
        _restore_staging(staging)
        print(f"[-] the scraper exited {code}; the previous mirror, staging and "
              f"{_rel(TARGET)} were left unchanged")
        return code

    if _staged_count(STAGED_YARA, (".yar",)) == 0:
        _restore_mirror(mirror)
        _restore_staging(staging)
        print("[-] the scrape produced no YARA files (the site may be "
              "unreachable or httrack may not be installed); the previous "
              "mirror, staging and import were left unchanged")
        return 1

    try:
        manifest = import_yara(print)
    except Exception as exc:  # noqa: BLE001 - report, never vanish
        _restore_mirror(mirror)
        _restore_staging(staging)
        print(f"[-] import failed: {type(exc).__name__}: {exc}")
        return 1

    for backup in (mirror, staging):
        if backup is not None:
            shutil.rmtree(backup, ignore_errors=True)

    print(f"[+] YARA: {manifest['yara_files']} file(s) with "
          f"{manifest['new_rule_ids']} new rule id(s) -> {_rel(TARGET)}")
    if manifest["skipped_duplicate_files"]:
        print(f"    skipped {manifest['skipped_duplicate_files']} file(s) whose "
              f"rules are already vendored in yara-rules/")
    if manifest["pe_imports_added"]:
        print(f"    added import \"pe\" to {manifest['pe_imports_added']} file(s) "
              f"that used pe.* without importing it")
    print(f"[*] Sigma: {manifest['sigma_files']} rule(s) kept in "
          f"{_rel(STAGED_SIGMA)} (no Sigma engine in the analyzer yet)")
    print(f"[*] CAPA: {manifest['capa_ignored']} legacy rule(s) ignored "
          f"(capa 9 rejects meta.scope / offset-x32 syntax)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
