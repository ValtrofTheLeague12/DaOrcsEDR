"""Generator resources - value pools the sample factory draws from.

The factory composes samples from its own fragments, and until now every bait
literal in them was either fixed text or drawn from built-in constants (a
TEST-NET-3 address, three well-known domains). That answers "does the analyzer
find an IP" but not "does it find THE IPs my feed is full of". This module is
where an admin integrates real value lists from anywhere - IPs, domains, URLs
and file hashes - so a generated sample carries values from the operator's own
corpus. How those sampled values are stored (plain, ROT13, XOR, Base64 or a
per-value mix) is the factory's encoding option; this module only supplies the
values.

What it is not
--------------
These are BAIT VALUES, not detection knowledge. Nothing here is loaded by the
analyzer as a rule, nothing is dialled, and nothing is trusted: the factory copies
a sampled value into a C string literal. The pages word it that way because a
list called "malicious IPs" invites exactly the wrong assumption.

Where things live
-----------------
  config/sample_resources.json      the admin's definitions (the panel owns it)
  ressources/<id>.txt               the dump exactly as the server served it
  ressources/<id>.json              parsed values + fetch bookkeeping

The definitions are in the tree because they are configuration an operator
deliberately added and might want to copy to another machine. The dumps are
kept in `ressources/` (the directory the repo already uses for downloaded
material), because the operator asked to be able to open the list the panel is
actually sampling from; both files stay out of git, since they are large,
regenerable, and stale the moment upstream moves. The definitions file is JSON
rather than YAML for the same reason config/yara_check.json is: the panel
rewrites it wholesale, and a hand-written YAML comment would be the first thing
a rewrite silently ate.

Fetching rules, because this is a browser button that makes the server dial out
------------------------------------------------------------------------------
  * any http(s) URL on any host: an operator keeps lists on GitHub, a gist, a
    CDN or their own server, and the panel is not the place to arbitrate that.
    A github.com file page is still rewritten to its raw URL, because that is
    what the admin meant by pasting it;

  * redirects are followed, but the DESTINATION must still be http(s) - a
    link cannot hand the fetcher a file:// path or another scheme;

  * 16 MiB and 200,000 values per resource, because community IOC dumps are
    routinely tens of thousands of lines; one bad list still cannot make the
    page slow or the cache unbounded;

  * the body must decode as UTF-8 text with no NUL bytes - a PDF, a tarball or
    an HTML error page is refused as a refusal, not parsed into nonsense;

  * every value is validated by kind: a real IP address or a syntactically
    valid hostname. Lines that do not fit are counted and reported, never
    guessed at.

A failed refresh never clears the previous good values. The resource keeps
serving its last good cache and the page shows both timestamps: "the list is
two days old AND the refresh an hour ago failed" is a fact an operator can act
on; an empty pool with no explanation is not.
"""

from __future__ import annotations

import ipaddress
import http.client
import json
import os
import re
import secrets
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from ..core import config

# The definitions and the fetched dumps, kept apart on purpose (see the module
# docstring).
RESOURCES_RELATIVE = Path("config") / "sample_resources.json"
DUMP_DIR = Path("ressources")

# One resource's fetch is bounded three ways: bytes, values, and seconds. All
# three are named in the UI from here, so the offer and the limit cannot drift.
MAX_BYTES = 16 * 1024 * 1024
MAX_ENTRIES = 200_000
MAX_RESOURCES = 32
FETCH_TIMEOUT = 30.0

MAX_LABEL = 80
MAX_NOTE = 280
MAX_ID = 48

# Per-value bound. It keeps a planted literal short enough to sit in a
# generated C string without a buffer of its own, and it is what a refusal
# quotes when a line is too long to be one.
MAX_VALUE = 512

# The pools, in the order the page renders them. `feature` is the factory
# checkbox a kind feeds. All of them feed Resource IOCs; how those sampled
# values are stored (plain, ROT13, XOR, Base64 or a per-value mix) is the
# factory's encoding option, not another pool.
KINDS: dict[str, dict[str, str]] = {
    "ip": {
        "label": "Malicious IPs",
        "detail": "IP literals planted as the resource IOC. Nothing is "
                  "dialled; the analyzer's IOC and CTI layers read them.",
        "format": "one IPv4 or IPv6 address first on each line "
                  "(a date or comment after a comma, space or semicolon is ignored)",
        "feature": "iocs",
    },
    "domain": {
        "label": "Domains",
        "detail": "Domains planted as the resource IOC, the other half of the "
                  "IP/domain pair. A leading '*.' is dropped.",
        "format": "one hostname per line, or a hosts-file line "
                  "('0.0.0.0 evil.example'), which is read as its hostname "
                  "(a leading '*.' is dropped)",
        "feature": "iocs",
    },
    "url": {
        "label": "URLs",
        "detail": "Whole http(s) URLs planted as the resource IOC. The "
                  "analyzer's IOC extractor reports these as URL strings.",
        "format": "one http:// or https:// URL per line, with no spaces",
        "feature": "iocs",
    },
    "hash": {
        "label": "File hashes",
        "detail": "SHA-1, SHA-256 and SHA-512 digests planted as the resource "
                  "IOC, the shape a file-hash feed publishes. The length says "
                  "which algorithm it is; all three are extracted.",
        "format": "one hex digest per line: 40 characters (SHA-1), 64 "
                  "(SHA-256) or 128 (SHA-512). A 'sha1:', 'sha256:' or "
                  "'sha512:' prefix and uppercase are accepted and normalised",
        "feature": "iocs",
    },
}
KIND_ORDER = tuple(KINDS)

# What each resource's values must look like; the noun is what a refusal says
# when a file parses to nothing usable ("no IP addresses in 400 lines").
_KIND_NOUN = {
    "ip": "IP addresses",
    "domain": "domain names",
    "url": "URLs",
    "hash": "file hashes",
}

# Which pools a feature needs before the factory may offer it.
_FEATURE_NEEDS: dict[str, tuple[str, ...]] = {
    "iocs": ("ip", "domain"),
}
_NEED_NOUN = {
    "ip": "an enabled malicious-IP resource",
    "domain": "an enabled domain resource",
}

_write_lock = threading.RLock()
# Parsed cache documents, keyed by path -> ((mtime_ns, size), doc).
_memo: dict[str, tuple[tuple[int, int], dict]] = {}
_memo_lock = threading.Lock()

# One indirection for the network, so tests exercise parsing, storage and
# refusals without ever leaving the machine. Same discipline as the factory's
# _POPEN.
_OPEN = urllib.request.urlopen


_DOMAIN_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_DOMAIN_TLD = r"(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})"
_DOMAIN_RE = re.compile(rf"^(?=.{{1,253}}$)(?:{_DOMAIN_LABEL}\.)+{_DOMAIN_TLD}$")
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,47}$")

# A digest feed may prefix the algorithm and may shout; both are the same
# value, so they normalise to one lowercase digest. The length is the algorithm
# (40 = SHA-1, 64 = SHA-256, 128 = SHA-512), which is how the analyzer's IOC
# extractor classifies them too.
_HASH_RE = re.compile(r"^(?:sha(?:1|256|512):)?([0-9a-f]{40}|[0-9a-f]{64}|[0-9a-f]{128})$")


# ---------------------------------------------------------------------------
# paths
# ---------------------------------------------------------------------------


def resources_path() -> Path:
    """Resolved per call, so tests can point config.REPO at a tmp tree."""
    return config.REPO / RESOURCES_RELATIVE


def dump_dir() -> Path:
    """Where the fetched dumps and their parsed form live, per the operator."""
    return config.REPO / DUMP_DIR


def _meta_path(resource_id: str) -> Path:
    return dump_dir() / f"{resource_id}.json"


def _dump_path(resource_id: str) -> Path:
    return dump_dir() / f"{resource_id}.txt"


# ---------------------------------------------------------------------------
# definitions file
# ---------------------------------------------------------------------------


def _read_records() -> tuple[list[dict], str | None]:
    """The definitions, and why they could not be read if they could not.

    Never raises for a bad file: the Resources card has to be able to SAY the
    file is broken. A collector that raised would turn the explanation into a
    500 and hide it behind the generic error banner.
    """
    path = resources_path()
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return [], None
    except OSError as exc:
        return [], f"could not read {RESOURCES_RELATIVE.as_posix()}: {exc}"

    if not raw.strip():
        return [], None
    try:
        doc = json.loads(raw)
    except ValueError as exc:
        return [], f"{RESOURCES_RELATIVE.as_posix()} is not valid JSON: {exc}"
    if not isinstance(doc, dict):
        return [], (f"{RESOURCES_RELATIVE.as_posix()} must be a JSON object "
                    "with a 'resources' list")
    records = doc.get("resources", [])
    if not isinstance(records, list):
        return [], (f"{RESOURCES_RELATIVE.as_posix()} must hold a 'resources' "
                    "list")

    for index, record in enumerate(records):
        bad = _shape_error(record, index)
        if bad:
            return [], bad
    return [dict(r) for r in records], None


def _shape_error(record: Any, index: int) -> str | None:
    """A loaded record must be usable as-is; the file is panel-owned, so a
    malformed one means someone edited it by hand and deserves to be told."""
    where = f"resource #{index + 1}"
    if not isinstance(record, dict):
        return f"{where} in {RESOURCES_RELATIVE.as_posix()} is not an object"
    for key in ("id", "label", "kind", "url"):
        if not isinstance(record.get(key), str) or not record[key].strip():
            return f"{where} has no {key}"
    if not _ID_RE.match(record["id"]):
        return f"{where} has an invalid id {record['id']!r}"
    if record["kind"] not in KINDS:
        return (f"{where} has an unknown kind {record['kind']!r} "
                f"(expected {', '.join(KIND_ORDER)})")
    if not isinstance(record.get("enabled"), bool):
        return f"{where} needs a boolean 'enabled'"
    parsed = urllib.parse.urlsplit(record["url"])
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return f"{where} has a URL that is not an http(s) URL"
    return None


def _save_records(records: list[dict]) -> None:
    """Panel-owned rewrite: temp file in the same directory, then os.replace.

    No partial file is ever visible to a concurrent snapshot request, and a
    crash mid-write leaves the previous definitions intact.
    """
    path = resources_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    payload = {"version": 1, "resources": records}
    tmp.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, path)


# ---------------------------------------------------------------------------
# validation
# ---------------------------------------------------------------------------


def _text(value: Any, field: str, limit: int, *, required: bool = True) -> str:
    if value is None and not required:
        return ""
    if not isinstance(value, str):
        raise ValueError(f"'{field}' must be a string")
    text = value.strip()
    if not text:
        if required:
            raise ValueError(f"'{field}' must not be empty")
        return ""
    if len(text) > limit:
        raise ValueError(f"'{field}' is longer than {limit} characters")
    if any(ord(ch) < 32 for ch in text):
        raise ValueError(f"'{field}' must not contain control characters")
    return text


def _slug(text: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return slug[:MAX_ID].strip("-")


def _clean_id(value: Any) -> str:
    if not isinstance(value, str):
        raise ValueError("'id' must be a string")
    rid = value.strip()
    if not _ID_RE.match(rid):
        raise ValueError("'id' must be lowercase letters, digits and dashes, "
                         "start with a letter or digit, and be at most "
                         f"{MAX_ID} characters")
    return rid


def _clean_url(value: Any) -> str:
    """Any http(s) URL, with a github.com file page normalised to its raw form.

    The panel does not choose the host: a list may live on GitHub, a gist, a
    CDN, a paste service or the operator's own server. What it does enforce is
    that the URL is one the fetcher can actually open (http or https, with a
    host) and that it carries no credentials, which would be written into the
    definitions file in clear text.

    Rewriting the github.com page rather than refusing it matters: the URL an
    admin copies from the browser is the /blob/ one, not the /raw/ one, and
    telling them to go find the Raw button when the panel already knows the
    translation is busywork. The snapshot always shows the normalised URL it
    will actually fetch, so nothing is hidden.
    """
    raw = _text(value, "url", 500)
    parsed = urllib.parse.urlsplit(raw)
    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        raise ValueError("resource URLs must use http or https")
    if parsed.username or parsed.password:
        raise ValueError("resource URLs must not carry credentials")
    host = (parsed.hostname or "").lower()
    if not host:
        raise ValueError("the URL has no host")

    if host == "github.com":
        parts = [p for p in parsed.path.split("/") if p]
        if len(parts) < 5 or parts[2] not in ("blob", "raw"):
            raise ValueError("a github.com URL must point at a file "
                             "(.../blob/<ref>/<path>) - or paste its Raw link")
        owner, repo_name, _mode, ref = parts[:4]
        rest = "/".join(parts[4:])
        return urllib.parse.urlunsplit(
            ("https", "raw.githubusercontent.com",
             f"/{owner}/{repo_name}/{ref}/{rest}", parsed.query, ""))
    return urllib.parse.urlunsplit(
        (scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))


def _clean_payload(payload: Any, *, allowed: set[str]) -> dict:
    if not isinstance(payload, dict):
        raise ValueError("resource must be a JSON object")
    unknown = sorted(set(payload) - allowed)
    if unknown:
        raise ValueError("unknown field(s): " + ", ".join(unknown))
    return payload


# ---------------------------------------------------------------------------
# cache
# ---------------------------------------------------------------------------


def _read_cache(resource_id: str) -> dict | None:
    """Parsed values for one resource, memoised by file stamp.

    A 131k-domain pool is ~4 MB of JSON; composing a preview asks for pool
    counts and then for one sampled value, and the catalogue does the same for
    each language. Re-parsing on every one of those would turn a debounced
    preview into a visible pause, so the parsed document is kept until the
    file's mtime or size changes. Only refresh() writes that file.
    """
    path = _meta_path(resource_id)
    try:
        stat = path.stat()
    except OSError:
        return None
    key = str(path)
    stamp = (stat.st_mtime_ns, stat.st_size)
    with _memo_lock:
        hit = _memo.get(key)
    if hit and hit[0] == stamp:
        return hit[1]

    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(doc, dict):
        return None
    entries = doc.get("entries")
    if not isinstance(entries, list) or not all(isinstance(e, str) for e in entries):
        return None
    with _memo_lock:
        _memo[key] = (stamp, doc)
        # Bound the memo: a machine that once had many large pools should not
        # keep every one of them resident.
        if len(_memo) > 8:
            _memo.pop(next(iter(_memo)))
    return doc


def _write_cache(resource_id: str, doc: dict) -> None:
    path = _meta_path(resource_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, path)
    with _memo_lock:
        _memo.pop(str(path), None)


def _write_dump(resource_id: str, data: bytes) -> None:
    """Keep the bytes the server served, under the resource's stable id.

    Written with the same replace dance as the definitions: a half-written
    dump that the page points at would be a worse lie than no dump.
    """
    path = _dump_path(resource_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_bytes(data)
    os.replace(tmp, path)


def _drop_cache(resource_id: str) -> None:
    for path in (_meta_path(resource_id), _dump_path(resource_id)):
        try:
            path.unlink(missing_ok=True)
        except OSError:
            # A dump that outlives its definition is harmless (nothing reads
            # it without a record); failing the removal over it is not.
            pass
    with _memo_lock:
        _memo.pop(str(_meta_path(resource_id)), None)


def _cache_matches(record: dict, cache: dict | None) -> bool:
    """Values only count when they were fetched for THIS url and kind.

    Editing a resource's URL must not leave yesterday's list answering for the
    new one. update() deletes the cache for exactly this reason; this check is
    the belt to that braces.
    """
    return bool(cache
                and cache.get("url") == record["url"]
                and cache.get("kind") == record["kind"])


# ---------------------------------------------------------------------------
# fetching and parsing
# ---------------------------------------------------------------------------


def _fetch(url: str) -> tuple[bytes, str]:
    """Download one URL. Raises ValueError with a sentence."""
    request = urllib.request.Request(url, headers={
        "User-Agent": "IAProject-admin-panel/1.0",
        "Accept": "text/plain, */*",
    })
    with _OPEN(request, timeout=FETCH_TIMEOUT) as response:
        final = response.geturl()
        parsed = urllib.parse.urlsplit(final)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ValueError(f"the download redirected to {final}, which is "
                             "not an http(s) URL")
        length = response.headers.get("Content-Length")
        if length and str(length).isdigit() and int(length) > MAX_BYTES:
            raise ValueError(f"the file is {int(length)} bytes; the cap is "
                             f"{MAX_BYTES} bytes")
        data = response.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError(f"the file is larger than the {MAX_BYTES // 1024} KiB cap")
    return data, final


def _decode(data: bytes) -> str:
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        raise ValueError("the file is UTF-16; save or export it as UTF-8")
    if b"\x00" in data:
        raise ValueError("the file contains NUL bytes - it is a binary file, "
                         "not a text list")
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValueError("the file is not UTF-8 text (it may be an HTML page "
                         "or a compressed archive)") from exc


def _looks_like_ip(token: str) -> bool:
    try:
        ipaddress.ip_address(token)
    except ValueError:
        return False
    return True


def _printable(token: str, limit: int) -> bool:
    """ASCII, no control characters, and short enough for a C string literal."""
    return (bool(token) and len(token) <= limit and token.isascii()
            and not any(ord(ch) < 0x20 or ord(ch) == 0x7f for ch in token))


def _url_value(token: str) -> str | None:
    """A whole http(s) URL, or None. The path and query are kept verbatim."""
    if not _printable(token, MAX_VALUE) or any(ch.isspace() for ch in token):
        return None
    try:
        parsed = urllib.parse.urlsplit(token)
        host = parsed.hostname or ""
    except ValueError:
        return None
    if parsed.scheme not in ("http", "https") or not host:
        return None
    # A hostname without a dot is a bare intranet name, not something a report
    # would quote; an address literal is fine either way.
    if "." not in host and not _looks_like_ip(host):
        return None
    return token


def _value_for(kind: str, line: str) -> str | None:
    """One line to one canonical value, or None when it does not fit the kind."""
    if kind not in KINDS:
        return None
    if kind == "url":
        # A URL is the whole line, not its first field: the path and query
        # are part of the value.
        return _url_value(line.strip().strip("'\""))

    parts = [p for p in re.split(r"[\s,;]+", line) if p]
    if not parts:
        return None
    if kind == "hash":
        # A feed may put the digest in any column ("<digest>,first seen",
        # "SHA256,<digest>"), so scan the fields instead of trusting the first.
        for part in parts:
            match = _HASH_RE.match(part.strip("'\"[](),").lower())
            if match:
                return match.group(1)
        return None
    token = parts[0].strip("'\"[](),")
    if kind == "ip":
        try:
            addr = ipaddress.ip_address(token)
        except ValueError:
            return None
        # A hosts-format blocklist's blocking addresses are not IOCs, and
        # neither are loopback or link-local ones: they would make a
        # "malicious IP" pool that no IOC phase could say anything about.
        if (addr.is_unspecified or addr.is_loopback
                or addr.is_link_local or addr.is_multicast):
            return None
        return str(addr)

    # Hosts files ("0.0.0.0 evil.example") are the most common shape of a
    # community domain list. The first field is the sink address, so the
    # hostname is the second one; treating the sink as the value would
    # cache a pool of zeroes.
    lowered = token.lower().rstrip(".")
    if _looks_like_ip(lowered):
        if len(parts) < 2:
            return None
        lowered = parts[1].strip("'\"[](),").lower().rstrip(".")
    if lowered.startswith("*."):
        lowered = lowered[2:]
    return lowered if _DOMAIN_RE.match(lowered) else None


def parse_entries(kind: str, text: str) -> dict:
    """Values, and the counts that make a partial parse auditable.

    `invalid` is not an error: real feeds carry headers, dates and the odd
    malformed line. It is reported so an admin can see that a 400-line file
    yielded 380 addresses and decide whether that is expected.
    """
    entries: list[str] = []
    seen: set[str] = set()
    invalid = duplicates = lines = 0
    truncated = False
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("//"):
            continue
        lines += 1
        value = _value_for(kind, line)
        if value is None:
            invalid += 1
            continue
        if value in seen:
            duplicates += 1
            continue
        if len(entries) >= MAX_ENTRIES:
            truncated = True
            continue
        seen.add(value)
        entries.append(value)
    return {"entries": entries, "invalid": invalid, "duplicates": duplicates,
            "lines": lines, "truncated": truncated}


# ---------------------------------------------------------------------------
# feature availability - the one answer the factory and the page share
# ---------------------------------------------------------------------------


def pool_counts() -> dict[str, int]:
    records, error = _read_records()
    if error:
        return {kind: 0 for kind in KIND_ORDER}
    counts = {kind: 0 for kind in KIND_ORDER}
    for record in records:
        if not record["enabled"]:
            continue
        cache = _read_cache(record["id"])
        if _cache_matches(record, cache):
            counts[record["kind"]] += len(cache["entries"])
    return counts


def feature_states(counts: dict[str, int] | None = None) -> dict[str, dict]:
    """Which factory features a pool can currently honour, and why not.

    One function so the checkbox list, the preview refusal and the page's dot
    cannot disagree about whether a feature is usable.
    """
    counts = counts if counts is not None else pool_counts()
    states: dict[str, dict] = {}
    for feature, needs in _FEATURE_NEEDS.items():
        missing = [kind for kind in needs if counts.get(kind, 0) == 0]
        states[feature] = {
            "available": not missing,
            "reason": None if not missing else (
                "needs " + " and ".join(_NEED_NOUN[kind] for kind in missing)
                + " with fetched values"),
            "needs": list(needs),
        }
    return states


def pick(kind: str, rng=None) -> dict | None:
    """One value and the resource it came from, or None for an empty pool.

    Weighted by source size, then chosen inside that source, rather than
    building a flat list of every value: a 131k-domain dump would otherwise
    allocate 131k dicts per sample composed, for one pick.

    `rng` is the factory's seeded Random when a preview and the artefact must
    draw the same value; with no rng the choice is system randomness.
    """
    if kind not in KINDS:
        return None
    records, error = _read_records()
    if error:
        return None
    sources: list[tuple[int, dict, dict]] = []
    total = 0
    for record in records:
        if record["kind"] != kind or not record["enabled"]:
            continue
        cache = _read_cache(record["id"])
        if not _cache_matches(record, cache):
            continue
        count = len(cache["entries"])
        if count:
            sources.append((count, record, cache))
            total += count
    if not sources:
        return None
    roll = rng.randrange(total) if rng is not None else secrets.randbelow(total)
    for count, record, cache in sources:
        if roll < count:
            return {"value": cache["entries"][roll], "id": record["id"],
                    "label": record["label"], "kind": kind}
        roll -= count
    return None  # pragma: no cover - roll < total by construction


# ---------------------------------------------------------------------------
# snapshot - the page's one read
# ---------------------------------------------------------------------------


def snapshot() -> dict:
    records, error = _read_records()
    counts = {kind: 0 for kind in KIND_ORDER}
    kinds = []
    for kind in KIND_ORDER:
        rows = []
        for record in records:
            if record["kind"] != kind:
                continue
            cache = _read_cache(record["id"])
            current = _cache_matches(record, cache)
            entries = cache["entries"] if cache else []
            if record["enabled"] and current:
                counts[kind] += len(entries)
            rows.append({
                "id": record["id"],
                "label": record["label"],
                "kind": kind,
                "url": record["url"],
                "enabled": record["enabled"],
                "note": record.get("note", ""),
                "added_at": record.get("added_at"),
                "fetched_at": cache.get("fetched_at") if cache else None,
                "count": len(entries),
                "preview": entries[:3],
                "invalid": cache.get("invalid", 0) if cache else 0,
                "duplicates": cache.get("duplicates", 0) if cache else 0,
                "truncated": bool(cache.get("truncated")) if cache else False,
                "bytes": cache.get("bytes", 0) if cache else 0,
                "current": current,
                "dump": (_dump_path(record["id"]).relative_to(config.REPO).as_posix()
                         if _dump_path(record["id"]).is_file() else None),
                "last_error": cache.get("last_error") if cache else None,
                "last_error_at": cache.get("last_error_at") if cache else None,
            })
        kinds.append({
            "kind": kind,
            **KINDS[kind],
            "pool_size": counts[kind],
            "resources": rows,
        })
    return {
        "path": RESOURCES_RELATIVE.as_posix(),
        "dump_dir": DUMP_DIR.as_posix(),
        "exists": resources_path().exists(),
        "error": error,
        "kinds": kinds,
        "pools": counts,
        "features": feature_states(counts),
        "limits": {
            "max_bytes": MAX_BYTES,
            "max_entries": MAX_ENTRIES,
            "max_resources": MAX_RESOURCES,
        },
    }


# ---------------------------------------------------------------------------
# mutations
# ---------------------------------------------------------------------------


def add(payload: dict) -> dict:
    payload = _clean_payload(payload, allowed={
        "id", "label", "kind", "url", "enabled", "note"})
    records, error = _read_records()
    if error:
        raise ValueError(error)
    if len(records) >= MAX_RESOURCES:
        raise ValueError(f"the cap is {MAX_RESOURCES} resources - remove one "
                         "before adding another")

    kind = payload.get("kind")
    if kind not in KINDS:
        raise ValueError(f"'kind' must be one of {', '.join(KIND_ORDER)}")
    label = _text(payload.get("label"), "label", MAX_LABEL)
    url = _clean_url(payload.get("url"))
    note = _text(payload.get("note"), "note", MAX_NOTE, required=False)
    enabled = payload.get("enabled", True)
    if not isinstance(enabled, bool):
        raise ValueError("'enabled' must be a boolean")

    rid = payload.get("id") or _slug(label)
    rid = _clean_id(rid)
    if any(record["id"] == rid for record in records):
        raise ValueError(f"a resource with id '{rid}' already exists")

    record = {
        "id": rid,
        "label": label,
        "kind": kind,
        "url": url,
        "enabled": enabled,
        "note": note,
        "added_at": time.time(),
    }
    with _write_lock:
        records.append(record)
        _save_records(records)
    return dict(record)


def update(resource_id: str, payload: dict) -> dict:
    payload = _clean_payload(payload, allowed={
        "label", "kind", "url", "enabled", "note"})
    with _write_lock:
        records, error = _read_records()
        if error:
            raise ValueError(error)
        index = next((i for i, r in enumerate(records)
                      if r["id"] == resource_id), None)
        if index is None:
            raise LookupError(f"no resource named '{resource_id}'")
        record = dict(records[index])

        if "label" in payload:
            record["label"] = _text(payload["label"], "label", MAX_LABEL)
        if "note" in payload:
            record["note"] = _text(payload["note"], "note", MAX_NOTE,
                                   required=False)
        if "enabled" in payload:
            if not isinstance(payload["enabled"], bool):
                raise ValueError("'enabled' must be a boolean")
            record["enabled"] = payload["enabled"]
        if "kind" in payload:
            if payload["kind"] not in KINDS:
                raise ValueError(f"'kind' must be one of {', '.join(KIND_ORDER)}")
            record["kind"] = payload["kind"]
        if "url" in payload:
            record["url"] = _clean_url(payload["url"])

        # A new URL or kind makes the old values answer a question nobody asked.
        if record["url"] != records[index]["url"] or \
                record["kind"] != records[index]["kind"]:
            _drop_cache(resource_id)

        records[index] = record
        _save_records(records)
    return dict(record)


def remove(resource_id: str) -> dict:
    with _write_lock:
        records, error = _read_records()
        if error:
            raise ValueError(error)
        remaining = [r for r in records if r["id"] != resource_id]
        if len(remaining) == len(records):
            raise LookupError(f"no resource named '{resource_id}'")
        _save_records(remaining)
        _drop_cache(resource_id)
        for record in records:
            if record["id"] == resource_id:
                return dict(record)
    raise LookupError(f"no resource named '{resource_id}'")  # pragma: no cover


def refresh(resource_id: str) -> dict:
    """Fetch one resource now and cache the parsed values.

    Failure is not an exception: it is a result the page shows next to the last
    good values. `ok` describes THIS fetch, not whether the resource exists.
    """
    records, error = _read_records()
    if error:
        return {"ok": False, "error": error}
    record = next((r for r in records if r["id"] == resource_id), None)
    if record is None:
        return {"ok": False, "error": f"no resource named '{resource_id}'"}

    url, kind = record["url"], record["kind"]
    host = urllib.parse.urlsplit(url).hostname or "the server"
    failure: str | None = None
    data = b""
    final = url
    try:
        data, final = _fetch(url)
        parsed = parse_entries(kind, _decode(data))
        if not parsed["entries"]:
            raise ValueError(
                f"no {_KIND_NOUN[kind]} in {parsed['lines']} line(s) - check "
                "the file and the resource kind")
    except urllib.error.HTTPError as exc:
        failure = f"{host} answered HTTP {exc.code} {exc.reason}"
    except urllib.error.URLError as exc:
        failure = f"could not reach {host}: {exc.reason}"
    except TimeoutError:
        failure = f"the download took longer than {int(FETCH_TIMEOUT)} s"
    except http.client.HTTPException as exc:
        # IncompleteRead and friends are not OSErrors: without this they would
        # escape refresh() as a 500 and lose the last-good-values sentence.
        failure = f"the connection failed mid-download ({type(exc).__name__})"
    except (ValueError, OSError) as exc:
        failure = str(exc)

    if failure is not None:
        with _write_lock:
            cache = _read_cache(resource_id) or {"entries": []}
            cache.update({
                "url": url,
                "kind": kind,
                "fetched_at": cache.get("fetched_at"),
                "last_error": failure,
                "last_error_at": time.time(),
            })
            _write_cache(resource_id, cache)
        return {"ok": False, "error": failure,
                "count": len(cache.get("entries", [])),
                "fetched_at": cache.get("fetched_at")}

    cache = {
        "url": url,
        "kind": kind,
        "source": final,
        "dump": _dump_path(resource_id).relative_to(config.REPO).as_posix(),
        "fetched_at": time.time(),
        "bytes": len(data),
        "entries": parsed["entries"],
        "invalid": parsed["invalid"],
        "duplicates": parsed["duplicates"],
        "lines": parsed["lines"],
        "truncated": parsed["truncated"],
        "last_error": None,
        "last_error_at": None,
    }
    with _write_lock:
        # Dump first: the metadata claims a dump exists, so the bytes must
        # already be there when it starts claiming it.
        _write_dump(resource_id, data)
        _write_cache(resource_id, cache)
    return {
        "ok": True,
        "count": len(parsed["entries"]),
        "invalid": parsed["invalid"],
        "duplicates": parsed["duplicates"],
        "truncated": parsed["truncated"],
        "fetched_at": cache["fetched_at"],
        "source": final,
    }
