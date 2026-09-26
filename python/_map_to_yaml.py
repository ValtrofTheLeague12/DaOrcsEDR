# _map_to_yaml.py

from __future__ import annotations

import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import yaml
from loguru import logger
from selectolax.parser import HTMLParser

from _log_api import setup_logging

setup_logging(level="DEBUG", stderr_level="DEBUG", also_stderr=True)

OUT_MALAPI = Path("yaml/malapi")
OUT_LOTS   = Path("yaml/lots")
MAX_WORKERS = 8


def _log_exception(context: str, exc: Exception) -> None:
    tb = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
    logger.bind(traceback=tb).error("[-] {}: {}", context, exc)


# ---------------------------------------------------------------------------
# MalAPI root / page discovery
# ---------------------------------------------------------------------------

def _has_malapi_pages(root: Path) -> bool:
    try:
        for child in root.iterdir():
            if child.is_dir() and (child / "index.html").is_file():
                return True
            if child.is_file() and child.suffix.lower() in (".html", ".htm"):
                return True
    except OSError:
        return False
    return False


def _find_malapi_root() -> Path | None:
    candidates = [
        Path("malapi/malapi.io/winapi"),
        Path("malapi/winapi/malapi.io/winapi"),
        Path("malapi.io/winapi"),
        Path("malapi/winapi"),
    ]
    for c in candidates:
        if c.is_dir() and _has_malapi_pages(c):
            logger.info("[+] malapi root detected: {}", c)
            return c

    for p in Path(".").rglob("winapi"):
        if p.is_dir() and _has_malapi_pages(p):
            logger.info("[+] malapi root detected (rglob): {}", p)
            return p

    logger.error("[-] could not find malapi winapi directory under {}",
                 Path(".").resolve())
    return None


def _list_malapi_pages(root: Path) -> list[tuple[str, Path]]:
    pages: list[tuple[str, Path]] = []
    try:
        for child in sorted(root.iterdir(), key=lambda p: p.name.lower()):
            if child.is_dir():
                index = child / "index.html"
                if index.is_file():
                    pages.append((child.name, index))
            elif child.is_file() and child.suffix.lower() in (".html", ".htm"):
                if child.stem.lower() == "index":
                    continue
                pages.append((child.stem, child))
    except OSError as exc:
        _log_exception(f"listing malapi pages under {root}", exc)
    return pages


def _find_lots_root() -> Path | None:
    candidates = [
        Path("lots/lots-project.com/index.html"),
        Path("lots-project.com/index.html"),
        Path("lots/index.html"),
    ]
    for c in candidates:
        if c.is_file():
            logger.info("[+] lots root detected: {}", c)
            return c

    for p in Path(".").rglob("index.html"):
        if "lots" in str(p).lower():
            logger.info("[+] lots root detected (rglob): {}", p)
            return p

    logger.error("[-] could not find lots-project.com/index.html under {}",
                 Path(".").resolve())
    return None


MALAPI_ROOT = _find_malapi_root()
LOTS_ROOT   = _find_lots_root()

OUT_MALAPI.mkdir(parents=True, exist_ok=True)
OUT_LOTS.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# Progress
# ---------------------------------------------------------------------------

def _progress(done: int, total: int, label: str) -> None:
    if total <= 0:
        return
    pct = done * 100.0 / total
    logger.info("[*] {} {}/{} ({:.1f}%)", label, done, total, pct)


# ---------------------------------------------------------------------------
# MalAPI parser
# ---------------------------------------------------------------------------

def _value_after_heading(tree: HTMLParser, label: str) -> str:
    try:
        for node in tree.css("div.heading"):
            text = " ".join(node.text(strip=True).split())
            if text != label:
                continue
            sibling = node.next
            while sibling is not None:
                cls = sibling.attributes.get("class", "")
                if sibling.tag == "div" and "content" in cls.split():
                    return " ".join(sibling.text(strip=True).split())
                sibling = sibling.next
            return ""
        return ""
    except Exception as exc:
        _log_exception(f"css lookup for heading {label!r}", exc)
        return ""


def _attacks_after_heading(tree: HTMLParser, label: str) -> list[str]:
    try:
        for node in tree.css("div.heading"):
            text = " ".join(node.text(strip=True).split())
            if text != label:
                continue
            sibling = node.next
            while sibling is not None:
                cls = sibling.attributes.get("class", "")
                if sibling.tag == "div" and "content" in cls.split():
                    return [
                        " ".join(span.text(strip=True).split())
                        for span in sibling.css("span.attack-container")
                        if span.text(strip=True)
                    ]
                sibling = sibling.next
            return []
        return []
    except Exception as exc:
        _log_exception(f"css lookup for attacks under {label!r}", exc)
        return []


def parse_malapi_page(api_name: str, index: Path) -> dict | None:
    if not index.is_file():
        logger.debug("[!] no html at {}", index)
        return None

    try:
        tree = HTMLParser(index.read_bytes())
    except Exception as exc:
        _log_exception(f"parsing {index}", exc)
        return None

    name        = _value_after_heading(tree, "Function Name") or api_name
    description = _value_after_heading(tree, "Description")
    dll         = _value_after_heading(tree, "Library")
    attacks     = _attacks_after_heading(tree, "Associated Attacks")

    if not description:
        logger.debug("[!] no description for {}", api_name)
        return None

    return {
        "name":        name,
        "dll":         dll,
        "description": description,
        "attacks":     attacks,
        "source":      index.as_posix(),
    }


def _write_malapi_yaml(entry: dict) -> Path | None:
    target = OUT_MALAPI / f"{entry['name']}.yaml"
    try:
        with target.open("w", encoding="utf-8") as f:
            yaml.safe_dump(entry, f, sort_keys=False, allow_unicode=True,
                           default_flow_style=False)
        return target
    except Exception as exc:
        _log_exception(f"writing {target}", exc)
        return None


def build_malapi_yaml() -> int:
    if MALAPI_ROOT is None:
        logger.error("[-] skipping malapi — root not found")
        return 0

    pages = _list_malapi_pages(MALAPI_ROOT)
    total = len(pages)
    logger.info("[*] malapi: {} page(s) to parse under {}", total, MALAPI_ROOT)

    if total == 0:
        logger.error("[-] no malapi pages found under {}", MALAPI_ROOT)
        return 0

    written = 0
    skipped = 0
    failed = 0

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {
            pool.submit(parse_malapi_page, name, path): (name, path)
            for name, path in pages
        }

        for i, fut in enumerate(as_completed(futures), start=1):
            api_name, path = futures[fut]
            try:
                entry = fut.result()
            except Exception as exc:
                _log_exception(f"worker for {api_name}", exc)
                failed += 1
                continue

            if entry is None:
                skipped += 1
            elif _write_malapi_yaml(entry):
                written += 1
                logger.debug("[+] wrote {}.yaml", entry["name"])
            else:
                failed += 1

            if i % 50 == 0 or i == total:
                _progress(i, total, "malapi")

    logger.info(
        "[+] malapi done — written={} skipped={} failed={} → {}",
        written, skipped, failed, OUT_MALAPI,
    )
    return written


# ---------------------------------------------------------------------------
# LOTS parser
# ---------------------------------------------------------------------------

def parse_lots_page(path: Path) -> list[dict]:
    if not path.is_file():
        logger.error("[-] LOTS file not found: {}", path)
        return []

    try:
        tree = HTMLParser(path.read_bytes())
    except Exception as exc:
        _log_exception(f"parsing {path}", exc)
        return []

    entries: list[dict] = []
    seen: set[str] = set()

    try:
        rows = tree.css("table tr")
    except Exception as exc:
        _log_exception("css table rows", exc)
        return []

    logger.info("[*] lots: {} raw row(s) to inspect", len(rows))

    for row in rows:
        try:
            cells = row.css("td")
            if len(cells) < 3:
                continue

            host     = " ".join(cells[0].text(strip=True).split())
            tags_raw = " ".join(cells[1].text(strip=True).split())
            provider = " ".join(cells[2].text(strip=True).split())

            if not host or host.lower() in ("website", "host", "domain"):
                continue
            if host in seen:
                logger.debug("[!] duplicate host skipped: {}", host)
                continue
            seen.add(host)

            tags = [t.strip() for t in tags_raw.replace("|", " ").split() if t.strip()]
            entries.append({
                "host":     host,
                "provider": provider,
                "tags":     tags,
            })
        except Exception as exc:
            _log_exception("parsing LOTS row", exc)
            continue

    logger.info("[+] lots: parsed {} unique row(s) from {}", len(entries), path)
    return entries


def _write_lots_yaml(entry: dict) -> Path | None:
    safe = (
        entry["host"]
        .replace("*", "wildcard_")
        .replace("/", "_")
        .replace(":", "_")
    )
    target = OUT_LOTS / f"{safe}.yaml"
    try:
        with target.open("w", encoding="utf-8") as f:
            yaml.safe_dump(entry, f, sort_keys=False, allow_unicode=True,
                           default_flow_style=False)
        return target
    except Exception as exc:
        _log_exception(f"writing {target}", exc)
        return None


def build_lots_yaml() -> int:
    if LOTS_ROOT is None:
        logger.error("[-] skipping lots — root not found")
        return 0

    entries = parse_lots_page(LOTS_ROOT)
    if not entries:
        return 0

    total = len(entries)
    written = 0
    failed = 0

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {pool.submit(_write_lots_yaml, e): e["host"] for e in entries}

        for i, fut in enumerate(as_completed(futures), start=1):
            host = futures[fut]
            try:
                if fut.result() is not None:
                    written += 1
                    logger.debug("[+] wrote {}.yaml", host)
                else:
                    failed += 1
            except Exception as exc:
                _log_exception(f"worker for {host}", exc)
                failed += 1

            if i % 50 == 0 or i == total:
                _progress(i, total, "lots")

    logger.info(
        "[+] lots done — written={} failed={} → {}",
        written, failed, OUT_LOTS,
    )
    return written


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> int:
    try:
        logger.info("[*] parse start")

        n_malapi = build_malapi_yaml()
        n_lots   = build_lots_yaml()

        logger.info(
            "[+] parse done — malapi={} lots={} total={}",
            n_malapi, n_lots, n_malapi + n_lots,
        )
        return 0 if (n_malapi or n_lots) else 1

    except KeyboardInterrupt:
        logger.warning("[!] interrupted by user")
        return 130
    except Exception as exc:
        _log_exception("main()", exc)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())