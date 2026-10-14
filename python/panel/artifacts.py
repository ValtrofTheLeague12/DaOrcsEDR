"""Evidence bundles: the local tarballs, their MEGA copies, and the gap between.

`mega/` seals an analysis run into `exports/<artifact>_artifact/` - a
deterministic tar.gz, a `.sha256`, a `manifest.json` inventory and a README - and
then hands it to MEGA. This module reads both ends of that, and nothing else.

Two halves, deliberately separate:

  local()   enumerate `exports/*_artifact/` from the filesystem
  remote()  read the same bundles back off MEGA through mega/list.py

Remote is a THIRD-PARTY CALL. It shells out to MEGAcmd, which may be missing,
may have no session, or may be answering slowly. All three are ordinary states,
not errors, so remote() returns a structured `{available: false, reason: ...}`
and the panel shows that instead of an exception. A status page that fails
because a cloud client is logged out is useless precisely when it is needed.

Reuse over reimplementation, as everywhere else in this package: the MEGA
listing is mega/list.py's own `ls()` and `parse_ls()`, loaded by path, because
that parser already handles the two date shapes MEGAcmd emits (see its comment
on `_ROW`) and getting that wrong silently drops rows.

On "upload rate"
---------------
There is no upload start time anywhere in this project. MEGAcmd records when an
upload finished and nothing records when it began, so a true per-upload
duration is not knowable from the data that exists.

What IS knowable is the effective throughput between consecutive uploads: for
artifacts A then B, B's bytes divided by the seconds between their timestamps.
That is an upper bound on line rate, never a measurement of it - it is also
bounded by when a human chose to press upload. It is labelled as an estimate
everywhere it appears, because presenting it as a transfer speed would be
dressing a gap in the instrumentation up as a fact.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from . import config

BUNDLE_SUFFIX = "_artifact"
EVIDENCE_SUFFIX = "_evidence.tar.gz"

# ---------------------------------------------------------------------------
# persistent observation history
#
# The in-memory cache below is not enough for a chart to be continuous. It dies
# with the panel, and MEGA only reports bundles that exist right now - so
# deleting a case off MEGA would erase the point it contributed, and restarting
# the panel would reset every series to "no intervals". Both destroy history
# that already happened and cannot be recovered.
#
# So every successful remote read is appended to a history file in the appdata
# cache, and the transfer series is computed from THAT rather than from whatever
# MEGA happens to be holding. A bundle that is deleted remotely keeps its place
# on the timeline, marked as no longer present, because the upload still
# happened and the gap it left is real.
#
# Same location convention as mega/credential.py's secrets_dir(): outside the
# repo tree, because a cache that gets copied with the source is not a cache of
# the running system. Override with IA_PANEL_CACHE_DIR.
# ---------------------------------------------------------------------------
_HISTORY_VERSION = 1

# Cap on remembered bundles. A history file that grows without bound is a
# liability in a directory nobody is watching; the oldest points are the ones
# that stop being interesting first.
_HISTORY_LIMIT = 500


def cache_dir() -> Path:
    """Where the panel keeps state that should outlive a restart."""
    override = os.environ.get("IA_PANEL_CACHE_DIR")
    if override:
        return Path(override)
    base = os.environ.get("APPDATA")
    if base:
        return Path(base) / "IAProject" / "panel-cache"
    return Path.home() / "AppData" / "Roaming" / "IAProject" / "panel-cache"


def history_path() -> Path:
    return cache_dir() / "artifacts-history.json"

# Re-hashing budget.
#
# Integrity is worth having, but the panel polls this every 15s and a bundle is
# an evidence archive that can be hundreds of megabytes. Hashing is done only
# while the cumulative total stays under this, and skipped bundles say so rather
# than being quietly reported as fine. 64 MB reads in well under a second and
# covers the realistic case of a few small evidence bundles.
_HASH_BUDGET = 64 * 1024 * 1024

# How many remote bundles to open.
#
# Each one is another MEGAcmd process. Unbounded, a 500-case MEGA root would
# turn one poll into 500 subprocess spawns and the panel would simply stop
# answering. Past this the remainder is counted and reported as not examined.
_REMOTE_DETAIL_LIMIT = 25

# Per-bundle `ls` timeout, deliberately far below megacmd.QUICK_TIMEOUT (60s).
# The whole remote probe runs inside a Flask request that a browser is waiting
# on, so one slow bundle must cost seconds, not a minute.
_REMOTE_DETAIL_TIMEOUT = 8

# Overall budget for the entire remote probe.
#
# Per-call timeouts are not enough on their own. MEGAcmd's own QUICK_TIMEOUT is
# 60s, so a root with 25 bundles where the service is degrading could hold the
# request for the better part of half an hour and take the worker with it. This
# is a wall-clock deadline checked between bundles, so the endpoint has a hard
# ceiling and returns what it managed to read plus a note about what it did not.
_REMOTE_DEADLINE = 25.0

_REMOTE_TIMEOUT = 20
_remote_cache: dict = {"at": 0.0, "payload": None}
_local_cache: dict = {"at": 0.0, "payload": None}

# Local enumeration is a directory walk of exports/ plus a few small file reads.
# Cached briefly so opening the page twice does not re-walk the tree.
_LOCAL_TTL = 15.0

# Remote is a subprocess against a third-party service.
#
# This was 60s, which cost 60 MEGAcmd spawns an hour - roughly 12 seconds of
# subprocess work per hour - to notice a change that only ever happens when a
# human presses upload. Nothing writes to MEGA on a timer. Five minutes costs
# the same detection latency a person actually perceives (you upload, you want
# to see it; you do not sit watching for five minutes) at a tenth of the churn,
# and the Rescan button covers the case where you just uploaded and want it
# now rather than in five minutes.
_REMOTE_TTL = 300.0


# ---------------------------------------------------------------------------
# dates
# ---------------------------------------------------------------------------

# MEGAcmd's `ls -l` DATE is one of two shapes: ISO ("2026-10-13", optionally with
# a time) or the two-token short form ("13Oct2026 15:53:11"). Both are measured
# against a live account rather than assumed - see mega/list.py's _ROW comment,
# which hit the same two.
_MONTHS = {m: i for i, m in enumerate(
    ["jan", "feb", "mar", "apr", "may", "jun",
     "jul", "aug", "sep", "oct", "nov", "dec"], start=1)}

_SHORT_DATE = re.compile(
    r"^(?P<day>\d{2})(?P<mon>[A-Za-z]{3})(?P<year>\d{4})"
    r"(?:\s+(?P<h>\d{2}):(?P<min>\d{2}):(?P<s>\d{2}))?$")


def parse_date(text: str) -> float | None:
    """MEGAcmd date string -> epoch seconds, or None if it cannot be read.

    Naive timestamps are read as UTC because that is what MEGAcmd emits; the
    alternative is inventing a local offset, which would make two bundles
    recorded minutes apart in the same account look hours apart.
    """
    raw = " ".join(str(text or "").split())
    if not raw:
        return None

    m = _SHORT_DATE.match(raw)
    if m:
        mon = _MONTHS.get(m.group("mon").lower())
        if not mon:
            return None
        try:
            dt = datetime(
                int(m.group("year")), mon, int(m.group("day")),
                int(m.group("h") or 0), int(m.group("min") or 0),
                int(m.group("s") or 0), tzinfo=timezone.utc)
        except ValueError:
            return None
        return dt.timestamp()

    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%dT%H:%M", "%Y-%m-%d"):
        try:
            return datetime.strptime(raw, fmt).replace(tzinfo=timezone.utc).timestamp()
        except ValueError:
            continue

    # manifest.json carries a real ISO-8601 with an offset; let the parser do it.
    try:
        return datetime.fromisoformat(raw).timestamp()
    except ValueError:
        return None


def _iso(ts: float | None) -> str | None:
    if not ts:
        return None
    return datetime.fromtimestamp(ts, timezone.utc).isoformat(timespec="seconds")


# ---------------------------------------------------------------------------
# local
# ---------------------------------------------------------------------------

def _sha256(path: Path) -> str | None:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
    except OSError:
        return None
    return h.hexdigest()


def _read_json(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _read_sidecar(path: Path) -> str:
    """First whitespace-separated token of a `<digest>  <name>` sha256 file."""
    try:
        return path.read_text(encoding="utf-8", errors="replace").split()[0]
    except (OSError, IndexError):
        return ""


def _local_bundle(dirpath: Path) -> dict | None:
    """One `exports/<name>_artifact/` directory, or None if it is not one."""
    name = dirpath.name
    if not dirpath.is_dir() or not name.endswith(BUNDLE_SUFFIX):
        return None
    stem = name[: -len(BUNDLE_SUFFIX)]

    manifest = _read_json(dirpath / "manifest.json")
    tarball = dirpath / f"{stem}{EVIDENCE_SUFFIX}"

    stat = tarball.stat() if tarball.is_file() else None
    size = stat.st_size if stat else 0
    mtime = stat.st_mtime if stat else None

    manifest_bytes = manifest.get("archive_bytes")
    manifest_sha = str(manifest.get("archive_sha256") or "")
    sidecar = _read_sidecar(dirpath / f"{stem}{EVIDENCE_SUFFIX}.sha256")

    return {
        "name": stem,
        "dir": name,
        "present": tarball.is_file(),
        "archive": tarball.name if tarball.is_file() else None,
        "bytes": size,
        "modified": mtime,
        "generated_at": parse_date(manifest.get("generated_at_utc")
                                   or manifest.get("generated_at") or ""),
        "file_count": int(manifest.get("file_count") or 0),
        "source": str(manifest.get("source") or "") or None,
        "sha256": manifest_sha or sidecar or None,
        "sidecar_sha256": sidecar or None,
        # Does the bundle agree with itself? Recorded size vs on-disk size, and
        # the two independently-written digests vs each other. Cheaper than
        # re-hashing and catches a truncated or half-written archive.
        "size_matches": (int(manifest_bytes) == size) if manifest_bytes is not None else None,
        "digests_match": (manifest_sha == sidecar) if (manifest_sha and sidecar) else None,
        "verified": None,
        "verify_detail": "not hashed",
    }


def local(force: bool = False) -> list[dict]:
    """Every evidence bundle under `exports/`, newest first."""
    now = time.time()
    if (not force and _local_cache["payload"] is not None
            and now - _local_cache["at"] < _LOCAL_TTL):
        return _local_cache["payload"]

    root = config.REPO / "exports"
    bundles: list[dict] = []
    try:
        entries = sorted(root.iterdir())
    except OSError:
        entries = []

    budget = _HASH_BUDGET
    for entry in entries:
        try:
            bundle = _local_bundle(entry)
        except OSError:
            continue
        if bundle is None:
            continue
        # Hash only what fits the budget, and only a bundle that is actually
        # there to hash.
        if bundle["present"] and bundle["bytes"] <= budget:
            budget -= bundle["bytes"]
            actual = _sha256(entry / f"{bundle['name']}{EVIDENCE_SUFFIX}")
            bundle["verified"] = (
                actual is not None and bundle["sha256"] is not None
                and actual == bundle["sha256"]
            )
            bundle["verify_detail"] = "re-hashed" if actual else "unreadable"
        elif bundle["present"]:
            bundle["verify_detail"] = "larger than the re-hash budget"
        bundles.append(bundle)

    bundles.sort(key=lambda b: b["modified"] or 0, reverse=True)
    _local_cache.update(at=now, payload=bundles)
    return bundles


# ---------------------------------------------------------------------------
# remote (MEGA)
# ---------------------------------------------------------------------------

def _load_mega():
    """Load mega/list.py and mega/megacmd.py by path.

    By path rather than by sys.path import for the same reason the Qiling
    checker is: they are scripts that live outside this package, `list` would
    shadow the builtin if imported plainly, and mega/list.py rewrites sys.path
    as a side effect of being importable at all.
    """
    mega_dir = config.REPO / "mega"
    if not mega_dir.is_dir():
        return None, "mega/ not found"
    if str(mega_dir) not in sys.path:
        sys.path.insert(0, str(mega_dir))
    try:
        spec = importlib.util.spec_from_file_location(
            "mega_list", mega_dir / "list.py")
        if spec is None or spec.loader is None:
            return None, "mega/list.py could not be loaded"
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        import megacmd  # noqa: PLC0415 - resolved by the sys.path entry above
        return (module, megacmd), None
    except Exception as exc:  # noqa: BLE001 - a broken client is a state, not a crash
        return None, f"{type(exc).__name__}: {exc}"


def remote(remote_root: str = "/", force: bool = False) -> dict:
    """Bundles on MEGA, via mega/list.py's own listing.

    Never raises. Every failure mode a third-party client has - not installed,
    no session, network down - comes back as `available: false` with a reason
    the panel can show verbatim.

    `force` bypasses the cache. It exists for exactly one caller - the Rescan
    button - because a button that re-requests the same cached payload is a
    button that appears broken, and "you uploaded something, press Rescan" is
    the interaction this whole page is built around.
    """
    now = time.time()
    key = remote_root or "/"
    if not force:
        if (_remote_cache["payload"] is not None
                and now - _remote_cache["at"] < _REMOTE_TTL
                and _remote_cache["payload"].get("remote_root") == key):
            return _remote_cache["payload"]

    loaded, why = _load_mega()
    if loaded is None:
        payload = {"available": False, "reason": why, "account": None,
                   "remote_root": key, "bundles": [], "not_examined": 0, "truncated": None}
        _remote_cache.update(at=now, payload=payload)
        return payload

    listing, megacmd = loaded

    if not megacmd.available():
        payload = {"available": False,
                   "reason": f"MEGAcmd missing - {megacmd.missing_message()}",
                   "account": None, "remote_root": key,
                   "bundles": [], "not_examined": 0, "truncated": None}
        _remote_cache.update(at=now, payload=payload)
        return payload

    account = megacmd.whoami()
    if not account:
        payload = {"available": False,
                   "reason": "no MEGAcmd session - run: python mega/login.py --mega",
                   "account": None, "remote_root": key,
                   "bundles": [], "not_examined": 0, "truncated": None}
        _remote_cache.update(at=now, payload=payload)
        return payload

    root = key.rstrip("/") or "/"
    try:
        rows = listing.ls(root, _REMOTE_TIMEOUT)
    except Exception as exc:  # noqa: BLE001 - MEGAcmd refused or timed out
        payload = {"available": False, "reason": f"{type(exc).__name__}: {exc}",
                   "account": account, "remote_root": key,
                   "bundles": [], "not_examined": 0, "truncated": None}
        _remote_cache.update(at=now, payload=payload)
        return payload

    folders = [r for r in rows if r.get("is_dir") and
               r.get("name", "").endswith(BUNDLE_SUFFIX)]

    bundles: list[dict] = []
    not_examined = 0
    truncated = None
    deadline = time.monotonic() + _REMOTE_DEADLINE

    for row in folders:
        name = row["name"]
        stem = name[: -len(BUNDLE_SUFFIX)]

        # Stop on the wall clock, not just the count. A partial answer with a
        # reason beats an open request.
        if time.monotonic() >= deadline:
            truncated = ("stopped at the "
                         f"{_REMOTE_DEADLINE:.0f}s probe budget with "
                         f"{len(folders) - len(bundles)} bundle(s) unread")
            not_examined = len(folders) - len(bundles)
            break
        if len(bundles) >= _REMOTE_DETAIL_LIMIT:
            not_examined = len(folders) - len(bundles)
            truncated = (f"examined the first {_REMOTE_DETAIL_LIMIT} of "
                         f"{len(folders)} bundles")
            break

        # Folder rows report size 0 - only the files inside carry a size, and
        # the tarball is what the rate is computed from.
        files: list[dict] = []
        try:
            inner = listing.ls(f"{root}/{name}".replace("//", "/"),
                               _REMOTE_DETAIL_TIMEOUT)
        except Exception:  # noqa: BLE001 - one unreadable bundle, not the listing
            inner = []

        archive = None
        total = 0
        for r in inner:
            if r.get("is_dir"):
                continue
            entry = {"name": r.get("name"), "bytes": int(r.get("size") or 0),
                     "date": r.get("date")}
            files.append(entry)
            total += entry["bytes"]
            if entry["name"] == f"{stem}{EVIDENCE_SUFFIX}":
                archive = entry

        # Prefer the tarball's own timestamp; fall back to the folder's, which
        # is what is left if the bundle has no archive in it.
        stamp = parse_date((archive or {}).get("date")) or parse_date(row.get("date"))

        bundles.append({
            "name": stem,
            "dir": name,
            "present": archive is not None,
            "archive": (archive or {}).get("name"),
            "bytes": (archive or {}).get("bytes") or 0,
            "total_bytes": total,
            "modified": stamp,
            "date_text": row.get("date"),
            "file_count": len(files),
            "files": files,
        })

    bundles.sort(key=lambda b: b["modified"] or 0, reverse=True)
    payload = {"available": True, "reason": None, "account": account,
               "remote_root": key, "bundles": bundles,
               "not_examined": not_examined, "truncated": truncated}
    _remote_cache.update(at=now, payload=payload)
    return payload


# ---------------------------------------------------------------------------
# persistent history
# ---------------------------------------------------------------------------

def _read_history() -> dict:
    """Load the observation history, or a fresh one if it is missing or broken.

    A corrupt or truncated file must not take the page down, and must not be
    treated as "no history" either without saying so - so it is discarded and
    the caller is told the history was rebuilt rather than recovered.
    """
    path = history_path()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"version": _HISTORY_VERSION, "observations": {},
                "updated_at": None, "recovered": False, "present": False}
    if not isinstance(data, dict) or not isinstance(data.get("observations"), dict):
        return {"version": _HISTORY_VERSION, "observations": {},
                "updated_at": None, "recovered": False, "present": False}
    data.setdefault("version", _HISTORY_VERSION)
    data.setdefault("updated_at", None)
    data["present"] = True
    data["recovered"] = True
    return data


def _write_history(state: dict) -> str | None:
    """Atomically persist the history. Returns the path, or None if it failed.

    Write to a sibling temp file and rename, so a crash mid-write cannot leave
    a half-written history that the next read discards. Losing the file is
    survivable; losing it every time the panel is killed mid-poll is not.
    """
    path = history_path()
    payload = {
        "version": _HISTORY_VERSION,
        "updated_at": round(time.time(), 1),
        "observations": state["observations"],
    }
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        os.replace(tmp, path)
    except OSError:
        return None
    return str(path)


def record(bundles: list[dict], account: str | None,
           remote_root: str) -> dict:
    """Fold a successful remote read into the history and persist it.

    Keyed by name, and the timestamp kept is MEGA's upload time, not the time
    we looked. That distinction is the whole point: re-reading MEGA every 30
    seconds must not invent thirty new points on the timeline, and the upload
    timestamp is the one value that is stable and true across polls.

    A bundle that vanishes from MEGA keeps its entry. Deleting a case does not
    un-upload it, and the interval it formed is still part of the history.

    Only ever called on a successful read. A logged-out client must not be
    allowed to record "zero bundles", which would read as a wiped account.
    """
    state = _read_history()
    now = round(time.time(), 1)
    obs: dict = state["observations"]

    for b in bundles:
        if not b.get("modified"):
            continue
        prev = obs.get(b["name"]) or {}
        obs[b["name"]] = {
            "name": b["name"],
            "bytes": int(b.get("bytes") or 0),
            "total_bytes": int(b.get("total_bytes") or 0),
            "file_count": int(b.get("file_count") or 0),
            "modified": float(b["modified"]),
            "first_seen": float(prev.get("first_seen") or now),
            "last_seen": now,
        }

    if len(obs) > _HISTORY_LIMIT:
        keep = sorted(obs.values(), key=lambda o: o.get("modified") or 0,
                      reverse=True)[:_HISTORY_LIMIT]
        obs = {o["name"]: o for o in keep}
        state["observations"] = obs

    written = _write_history(state)
    return {
        "path": written,
        "known": len(obs),
        "pruned": max(0, len(obs) - _HISTORY_LIMIT) if len(obs) > _HISTORY_LIMIT else 0,
        "account": account,
        "remote_root": remote_root,
    }


def history() -> dict:
    """Every bundle ever seen, newest first, with whether it is still on MEGA.

    `last_success_at` is what the panel shows when MEGA is currently
    unreachable, so a logged-out client reads as "last seen 4 minutes ago"
    instead of as an empty account.
    """
    state = _read_history()
    return {
        "observations": list(state["observations"].values()),
        "count": len(state["observations"]),
        "updated_at": state.get("updated_at"),
        "path": str(history_path()),
        "present": state.get("present", False),
    }


def _merge_history(live: list[dict]) -> list[dict]:
    """Live remote bundles + remembered ones, newest first.

    Live wins on every field it actually has, because it is the truth right
    now. History supplies the bundles MEGA no longer lists and the timestamps
    it stopped reporting.
    """
    live_by_name = {b["name"]: b for b in live}
    seen: dict[str, dict] = {}
    for o in _read_history()["observations"].values():
        if not o.get("modified"):
            continue
        seen[o["name"]] = {
            "name": o["name"],
            "dir": f"{o['name']}{BUNDLE_SUFFIX}",
            "present": False,       # remembered, not confirmed this poll
            "archive": None,
            "bytes": int(o.get("bytes") or 0),
            "total_bytes": int(o.get("total_bytes") or 0),
            "modified": float(o["modified"]),
            "date_text": None,
            "file_count": int(o.get("file_count") or 0),
            "files": [],
            "first_seen": o.get("first_seen"),
            "last_seen": o.get("last_seen"),
        }
    for name, b in live_by_name.items():
        seen[name] = {**b, "present": True}
    return sorted(seen.values(), key=lambda b: b.get("modified") or 0, reverse=True)


# ---------------------------------------------------------------------------
# transfer rate between consecutive uploads
# ---------------------------------------------------------------------------

def transfer(bundles: list[dict]) -> dict:
    """Effective throughput between consecutive uploads, oldest interval first.

    For artifacts A then B (by timestamp): the interval is B.modified -
    A.modified, and the rate is B's bytes over that interval.

    Two honest limits, both of which the panel states next to the chart:

      * It is an upper bound, not a measurement. The gap includes however long
        the operator waited before starting the next upload, so the true line
        rate was always at least this fast.
      * MEGAcmd's date is minute- or day-granular, so a short interval rounds
        toward zero and the rate toward infinity. Intervals under a second are
        reported as `rate_bps: null` rather than as a very large number.

    A single bundle has no interval and therefore no rate. Returning an empty
    series is the correct answer, not a zero.
    """
    ordered = sorted(
        (b for b in bundles if b.get("modified")),
        key=lambda b: b["modified"])

    rows: list[dict] = []
    for prev, cur in zip(ordered, ordered[1:]):
        gap = cur["modified"] - prev["modified"]
        # Non-positive or sub-second gaps are granularity artefacts, not rates.
        usable = gap >= 1.0
        rows.append({
            "from": prev["name"],
            "to": cur["name"],
            "seconds": gap,
            "bytes": cur["bytes"] or 0,
            "size_delta": (cur["bytes"] or 0) - (prev["bytes"] or 0),
            "rate_bps": ((cur["bytes"] or 0) / gap) if usable else None,
        })

    rates = [r["rate_bps"] for r in rows if r["rate_bps"] is not None]
    gaps = [r["seconds"] for r in rows if r["seconds"] > 0]
    return {
        "intervals": rows,
        "count": len(rows),
        "mean_rate_bps": (sum(rates) / len(rates)) if rates else None,
        "max_rate_bps": max(rates) if rates else None,
        "median_gap_s": (sorted(gaps)[len(gaps) // 2]) if gaps else None,
        "total_bytes": sum(b.get("bytes") or 0 for b in bundles),
    }


# ---------------------------------------------------------------------------
# snapshot
# ---------------------------------------------------------------------------

def snapshot(remote_root: str = "/", force: bool = False) -> dict:
    """Both ends, plus the intervals between them.

    The transfer series is computed from the merged history, not from the live
    listing, so it survives a panel restart and keeps points for bundles that
    have since been deleted from MEGA.
    """
    local_bundles = local(force)
    remote_state = remote(remote_root, force)
    remote_bundles = remote_state["bundles"]

    # Only a successful read is allowed to touch history. A failed probe must
    # not be recorded as "the account is now empty".
    history_info = None
    if remote_state["available"]:
        history_info = record(remote_bundles, remote_state.get("account"),
                              remote_state.get("remote_root", "/"))

    # When MEGA is unavailable this still returns the remembered series, so the
    # charts keep their history instead of blanking. Every point is marked
    # present: false, which is accurate: none of them were confirmed this poll.
    hist = _merge_history(remote_bundles) if remote_state["available"] \
        else _merge_history([])

    live_names = {b["name"] for b in remote_bundles}
    series = [b for b in hist if b.get("modified")]

    local_names = {b["name"] for b in local_bundles}
    hist_names = {b["name"] for b in hist}

    # One timeline across both ends.
    #
    # Splitting this into a Local tab and a Remote tab is right for the two
    # questions, but it makes the Remote tab read as "no artifacts" whenever
    # the MEGA account is empty - which is the normal state of a lab that
    # bundles locally and has not uploaded yet. That is the single most
    # misleading thing this page could show, because the artifacts are right
    # there on disk. So the Remote tab lists both and marks where each one
    # lives.
    #
    # The charts do NOT get the same treatment. A local-only bundle was never
    # uploaded, so including it would invent an "upload" and an interval that
    # never happened. The rate series stays remote-only; only the list is
    # unified.
    unified: list[dict] = []
    for b in hist:
        name = b["name"]
        if b.get("present") and name in local_names:
            where = "both"
        elif b.get("present"):
            where = "remote"
        elif name in local_names:
            # On disk now, and remembered from an earlier remote read. Reported
            # as local rather than as "both": the entry in the cache is not
            # evidence that MEGA is listing it this second, and a chip that
            # claims MEGA presence it cannot back is worse than a narrower one.
            where = "local"
        else:
            where = "remembered"
        unified.append({**b, "where": where})

    for l in local_bundles:
        if l["name"] in hist_names:
            continue
        unified.append({
            "name": l["name"],
            "dir": l["dir"],
            "where": "local",
            "present": l["present"],
            "archive": l["archive"],
            "bytes": l["bytes"],
            "total_bytes": l["bytes"],
            # A local bundle has no upload time. Its archive mtime is the
            # honest stand-in and is labelled as such in the UI.
            "modified": l["modified"],
            "date_text": None,
            "file_count": l["file_count"],
            "files": [],
            "generated_at": l["generated_at"],
        })

    unified.sort(key=lambda b: b.get("modified") or 0, reverse=True)

    return {
        "generated_at": round(time.time(), 1),
        "local": {
            "bundles": local_bundles,
            "counts": {
                "total": len(local_bundles),
                "bytes": sum(b["bytes"] for b in local_bundles),
                "missing": sum(1 for b in local_bundles if not b["present"]),
            },
        },
        "remote": {
            **remote_state,
            "counts": {
                "total": len(remote_bundles) + remote_state.get("not_examined", 0),
                "listed": len(remote_bundles),
                "bytes": sum(b["bytes"] for b in remote_bundles),
            },
        },
        "history": {
            "bundles": hist,
            "count": len(hist),
            # Remembered but not on MEGA right now. The upload happened; the
            # bundle was deleted afterwards.
            "not_on_remote": sorted(hist_names - live_names),
            "path": history_info["path"] if history_info else str(history_path()),
            "written": bool(history_info and history_info["path"]),
            "updated_at": (_read_history().get("updated_at")),
        },
        # Every bundle from either end, with `where` saying which.
        "unified": unified,
        "unified_counts": {
            "both": sum(1 for u in unified if u["where"] == "both"),
            "local": sum(1 for u in unified if u["where"] == "local"),
            "remote": sum(1 for u in unified if u["where"] == "remote"),
            "remembered": sum(1 for u in unified if u["where"] == "remembered"),
        },
        "transfer": transfer(series),
        "diff": {
            "only_local": sorted(local_names - hist_names),
            "only_remote": sorted(hist_names - local_names),
            "both": sorted(local_names & hist_names),
        },
    }


if __name__ == "__main__":  # manual probe: `python -m python.panel.artifacts`
    print(json.dumps(snapshot(), indent=2))
