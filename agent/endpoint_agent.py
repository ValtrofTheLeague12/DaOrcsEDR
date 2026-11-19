from __future__ import annotations

import argparse
import getpass
import glob as glob_module
import hashlib
import json
import logging
import os
import platform
import sqlite3
import stat as stat_module
import sys
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Iterator

from flask import Flask, jsonify, request

# ---------------------------------------------------------------------------
# Optional / required third-party imports
# ---------------------------------------------------------------------------

try:
    import psutil  # optional: process metrics for the heartbeat
except ImportError:  # pragma: no cover
    psutil = None  # type: ignore[assignment]

try:
    import lief  # required: PE parsing
    LIEF_AVAILABLE = True
except ImportError:  # pragma: no cover
    lief = None  # type: ignore[assignment]
    LIEF_AVAILABLE = False

try:
    import magic  # optional: MIME pre-filter
    # Probe once so a missing libmagic DLL is surfaced here, not per file.
    try:
        _magic_probe = magic.Magic(mime=True)
        _magic_probe.from_buffer(b"MZ")
        _MAGIC_AVAILABLE = True
    except Exception:  # noqa: BLE001
        _MAGIC_AVAILABLE = False
        magic = None  # type: ignore[assignment]
except (ImportError, OSError):  # pragma: no cover
    magic = None  # type: ignore[assignment]
    _MAGIC_AVAILABLE = False

# Per-thread Magic handles: creating one Magic per call is slow, and libmagic
# cookies are not meant to be shared across threads.
_magic_local = threading.local()


def _magic_handle() -> "magic.Magic":
    handle = getattr(_magic_local, "handle", None)
    if handle is None:
        handle = magic.Magic(mime=True)
        _magic_local.handle = handle
    return handle


VERSION = "0.7.0"
LOG_DIR_ENV = "DAORCS_LOG_DIR"
PROGRAM_DATA = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData"))
DEFAULT_API_HOST = "127.0.0.1"
DEFAULT_API_PORT = 8787

DEFAULT_SCAN_WORKERS = 8
DEFAULT_DIR_WORKERS = 4
MAX_SCAN_WORKERS = 64
MAX_DIR_WORKERS = 16
MAX_CHUNK_BYTES = 256 * 1024
DEFAULT_FLUSH_TIMEOUT = 300.0

# MIME types that indicate a Windows executable. libmagic reports the first
# two; the third is what some older builds emit for raw DOS stubs.
PE_MIME_TYPES = frozenset({
    "application/x-dosexec",
    "application/vnd.microsoft.portable-executable",
    "application/x-msdownload",
})

# Built-in excludes applied to every watch root. These are directories that
# either ACL-deny reads (System Volume Information, $Recycle.Bin), are hardlink
# farms full of duplicates (WinSxS), or are churn-heavy scratch space
# (Temp). Operators can add more via watch_excludes in agent.json.
BUILTIN_EXCLUDES: tuple[str, ...] = (
    r"C:\System Volume Information",
    r"C:\$Recycle.Bin",
    r"C:\Windows\WinSxS",
    r"C:\Windows\System32\DriverStore",
    r"C:\Windows\Installer",
    r"C:\Windows\CSC",
    r"C:\ProgramData\Microsoft\Windows Defender",
    r"C:\ProgramData\Package Cache",
)

LOG = logging.getLogger("ia_endpoint_agent")
DETECTIONS = logging.getLogger("ia_endpoint_agent.detections")


# ---------------------------------------------------------------------------
# Paths and defaults
# ---------------------------------------------------------------------------


def default_log_dir() -> Path:
    override = os.environ.get(LOG_DIR_ENV)
    if override:
        return expand_path(override)
    appdata = os.environ.get("APPDATA")
    if appdata:
        return Path(appdata) / "DaOrcs" / "Agent" / "logs"
    return Path.home() / "AppData" / "Roaming" / "DaOrcs" / "Agent" / "logs"


DEFAULT_CONFIG = PROGRAM_DATA / "DaOrcs" / "Agent" / "agent.json"
DEFAULT_STATE = PROGRAM_DATA / "DaOrcs" / "Agent" / "state.sqlite3"
DEFAULT_LOG = default_log_dir() / "agent.log"
DEFAULT_SERVICE_LOG = default_log_dir() / "service.log"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def expand_path(value: str) -> Path:
    # pathlib has no equivalent of os.path.expandvars (needed for the
    # %PROGRAMDATA%-style tokens used in agent.json on Windows), so this
    # remains the one place we still need os.path. Path.expanduser() and
    # .resolve() replace the rest of the previous os.path chain.
    return Path(os.path.expandvars(value)).expanduser().resolve()


def _current_username() -> str:
    """Best-effort current user name, cross-platform."""
    try:
        return getpass.getuser() or ""
    except (KeyError, OSError):
        return ""


def _normalise_for_compare(path: Path) -> str:
    # Windows paths are case-insensitive; string comparison is not. Lower-cased
    # string form is used for dedupe keys and exclude prefix matching.
    return str(path).lower().replace("/", "\\")


def _is_excluded(path: Path, excludes: tuple[str, ...]) -> bool:
    candidate = _normalise_for_compare(path)
    for exclude in excludes:
        if candidate == exclude or candidate.startswith(exclude + "\\"):
            return True
    return False


def _expand_excludes(raw_patterns: list[str]) -> tuple[str, ...]:
    """Expand exclude patterns (literal or glob) into a lower-cased tuple.

    Glob expansion is applied here so a single ``C:/Users/*/AppData/Local/Temp``
    exclude covers every profile without re-globbing during the walk.
    """
    result: dict[str, None] = {}
    for raw in list(BUILTIN_EXCLUDES) + list(raw_patterns):
        expanded = expand_path(raw)
        if glob_module.has_magic(str(expanded)):
            for match in glob_module.glob(str(expanded), recursive=True):
                result[_normalise_for_compare(Path(match))] = None
        else:
            result[_normalise_for_compare(expanded)] = None
    return tuple(sorted(result))


def resolve_watch_patterns(patterns: list[str]) -> list[Path]:
    """Expand configured watch entries into concrete directories.

    Entries may be literal paths or glob patterns (e.g. ``C:/Users/*/``).
    Token expansion (%VAR%, ~) happens first via expand_path; if the result
    still contains glob metacharacters, glob.glob resolves it. The result is
    de-duplicated, sorted, and restricted to real, non-symlinked directories.
    """
    resolved: dict[str, Path] = {}
    for raw in patterns:
        expanded = expand_path(raw)
        if not glob_module.has_magic(str(expanded)):
            if expanded.is_dir() and not expanded.is_symlink():
                resolved[_normalise_for_compare(expanded)] = expanded
            continue
        for match in glob_module.glob(str(expanded), recursive=True):
            candidate = Path(match)
            if candidate.is_dir() and not candidate.is_symlink():
                resolved[_normalise_for_compare(candidate)] = candidate
    return [resolved[key] for key in sorted(resolved)]


# ---------------------------------------------------------------------------
# PE detection: MIME pre-filter + LIEF authoritative parse
# ---------------------------------------------------------------------------


def mime_is_pe(path: Path) -> bool | None:
    """Return True/False for MIME classification, or None when unavailable.

    ``None`` means "libmagic could not answer" (missing DLL, unreadable file,
    libmagic error). The caller should then defer entirely to LIEF rather than
    treating the file as non-PE.
    """
    if not _MAGIC_AVAILABLE:
        return None
    try:
        mime = _magic_handle().from_file(str(path))
    except Exception:  # noqa: BLE001 - libmagic failures must not stop the scan
        LOG.debug("libmagic failed on %s", path, exc_info=True)
        return None
    if not isinstance(mime, str) or not mime:
        return None
    return mime in PE_MIME_TYPES


def is_pe_file(path: Path) -> bool:
    """Authoritative PE check via LIEF."""
    if not LIEF_AVAILABLE:
        raise RuntimeError("LIEF is not available; cannot analyse PE files")
    try:
        binary = lief.PE.parse(str(path))
    except Exception:  # noqa: BLE001 - LIEF raises on some malformed samples
        LOG.debug("LIEF failed to parse %s", path, exc_info=True)
        return False
    if binary is None:
        return False
    if not isinstance(binary, lief.PE.Binary):
        return False

    for section in binary.sections:
        try:
            raw = bytes(section.content)
        except Exception:  # noqa: BLE001
            continue
        if not raw:
            continue
        LOG.debug(
            "PE section %s sha256=%s",
            getattr(section, "name", "?"),
            hashlib.sha256(raw).hexdigest(),
        )
    return True


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------


def _validate_watch_entries(watch_dirs: list[Any]) -> list[str]:
    """Validate watch_dirs entries. Each entry is a string (pattern or path)
    or an object {"path": str, "stable_seconds": number}."""
    if not isinstance(watch_dirs, list) or not watch_dirs:
        raise ValueError("watch_dirs must be a non-empty list")
    normalised: list[str] = []
    for entry in watch_dirs:
        if isinstance(entry, str):
            if not entry.strip():
                raise ValueError("Every watch_dirs entry must be non-empty")
            normalised.append(entry)
            continue
        if isinstance(entry, dict):
            path = entry.get("path")
            if not isinstance(path, str) or not path.strip():
                raise ValueError("watch_dirs entries must have a non-empty 'path'")
            stable = entry.get("stable_seconds", 0)
            if (not isinstance(stable, (int, float)) or isinstance(stable, bool)
                    or stable < 0):
                raise ValueError(
                    f"watch_dirs.stable_seconds must be >= 0 for {path!r}"
                )
            normalised.append(path)
            continue
        raise ValueError(
            "watch_dirs entries must be strings or {'path': ...} objects"
        )
    return normalised


def load_config(path: Path) -> dict[str, Any]:
    try:
        config = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Cannot read agent configuration {path}: {exc}") from exc
    if not isinstance(config, dict):
        raise ValueError("Agent configuration must be a JSON object")

    watch_dirs = config.get("watch_dirs")
    _validate_watch_entries(watch_dirs)

    excludes = config.get("watch_excludes", [])
    if excludes is None:
        excludes = []
    if not isinstance(excludes, list) or any(
        not isinstance(item, str) or not item.strip() for item in excludes
    ):
        raise ValueError("watch_excludes must be a list of non-empty strings")

    kafka = config.get("kafka")
    if not isinstance(kafka, dict):
        raise ValueError("kafka must be a configuration object")
    if not isinstance(kafka.get("bootstrap_servers"), str) or not kafka[
        "bootstrap_servers"
    ].strip():
        raise ValueError("kafka.bootstrap_servers must be configured")
    if not isinstance(kafka.get("topic"), str) or not kafka["topic"].strip():
        raise ValueError("kafka.topic must be configured")

    interval = config.get("scan_interval_seconds", 5)
    if not isinstance(interval, (int, float)) or isinstance(interval, bool) or interval < 1:
        raise ValueError("scan_interval_seconds must be at least 1")
    stable = config.get("stable_seconds", 2)
    if not isinstance(stable, (int, float)) or isinstance(stable, bool) or stable < 0:
        raise ValueError("stable_seconds cannot be negative")
    chunk_bytes = config.get("chunk_bytes", MAX_CHUNK_BYTES)
    if (not isinstance(chunk_bytes, int) or isinstance(chunk_bytes, bool)
            or not 1 <= chunk_bytes <= MAX_CHUNK_BYTES):
        raise ValueError(f"chunk_bytes must be between 1 and {MAX_CHUNK_BYTES}")

    scan_workers = config.get("scan_workers", DEFAULT_SCAN_WORKERS)
    if (not isinstance(scan_workers, int) or isinstance(scan_workers, bool)
            or not 1 <= scan_workers <= MAX_SCAN_WORKERS):
        raise ValueError(f"scan_workers must be between 1 and {MAX_SCAN_WORKERS}")
    dir_workers = config.get("dir_workers", DEFAULT_DIR_WORKERS)
    if (not isinstance(dir_workers, int) or isinstance(dir_workers, bool)
            or not 1 <= dir_workers <= MAX_DIR_WORKERS):
        raise ValueError(f"dir_workers must be between 1 and {MAX_DIR_WORKERS}")

    mime_prefilter = config.get("mime_prefilter", True)
    if not isinstance(mime_prefilter, bool):
        raise ValueError("mime_prefilter must be true or false")

    flush_timeout = config.get(
        "flush_timeout_seconds",
        kafka.get("flush_timeout_seconds", DEFAULT_FLUSH_TIMEOUT),
    )
    if (not isinstance(flush_timeout, (int, float)) or isinstance(flush_timeout, bool)
            or flush_timeout < 1):
        raise ValueError("flush_timeout_seconds must be a positive number")

    api = config.get("api", {})
    if not isinstance(api, dict):
        raise ValueError("api must be a configuration object")
    if not isinstance(api.get("enabled", True), bool):
        raise ValueError("api.enabled must be true or false")
    api_host = api.get("host", DEFAULT_API_HOST)
    if not isinstance(api_host, str) or not api_host.strip():
        raise ValueError("api.host must be a non-empty address")
    api_port = api.get("port", DEFAULT_API_PORT)
    if (not isinstance(api_port, int) or isinstance(api_port, bool)
            or not 1 <= api_port <= 65535):
        raise ValueError("api.port must be between 1 and 65535")
    return config


def _watch_entries_with_stable(
    config: dict[str, Any],
) -> list[tuple[str, float]]:
    """Return (pattern, stable_seconds) for every configured entry.

    A bare string inherits the top-level stable_seconds; an object can override
    it per-entry.
    """
    default_stable = float(config.get("stable_seconds", 0))
    result: list[tuple[str, float]] = []
    for entry in config["watch_dirs"]:
        if isinstance(entry, str):
            result.append((entry, default_stable))
        else:
            result.append((entry["path"], float(entry.get("stable_seconds", default_stable))))
    return result


# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------


class SampleState:
    """Persist hashes already delivered, and cache PE verdicts.

    Uses WAL mode so multiple worker threads can read concurrently while one
    writer commits. Each thread gets its own read-only connection via
    threading.local; the write connection is shared under a lock.

    Also caches "this (path, size, mtime_ns) has already been delivered", so
    the hot scan path can short-circuit before doing any hashing or PE work.
    """

    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self._path = path
        self._write_lock = threading.Lock()
        self._local = threading.local()
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=NORMAL")
        self._db.execute("PRAGMA temp_store=MEMORY")
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS sent_samples "
            "(sha256 TEXT PRIMARY KEY, sent_at TEXT NOT NULL)"
        )
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS pe_cache "
            "(path TEXT NOT NULL, size INTEGER NOT NULL, "
            "mtime_ns INTEGER NOT NULL, is_pe INTEGER NOT NULL, "
            "checked_at TEXT NOT NULL, PRIMARY KEY (path, size, mtime_ns))"
        )
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS sent_files "
            "(path TEXT NOT NULL, size INTEGER NOT NULL, "
            "mtime_ns INTEGER NOT NULL, sha256 TEXT NOT NULL, "
            "sent_at TEXT NOT NULL, PRIMARY KEY (path, size, mtime_ns))"
        )
        self._db.execute(
            "CREATE INDEX IF NOT EXISTS idx_sent_files_sha ON sent_files(sha256)"
        )
        self._db.commit()

    def _reader(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self._path, check_same_thread=False)
            conn.execute("PRAGMA query_only=ON")
            conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn = conn
        return conn

    def contains(self, sha256: str) -> bool:
        return self._reader().execute(
            "SELECT 1 FROM sent_samples WHERE sha256 = ?", (sha256,)
        ).fetchone() is not None

    def already_sent(self, path: Path, size: int, mtime_ns: int) -> bool:
        """Fast path: skip a file whose (path,size,mtime) has been delivered."""
        return self._reader().execute(
            "SELECT 1 FROM sent_files "
            "WHERE path = ? AND size = ? AND mtime_ns = ?",
            (str(path), size, mtime_ns),
        ).fetchone() is not None

    def mark_sent(
        self, sha256: str, path: Path, size: int, mtime_ns: int,
    ) -> None:
        with self._write_lock:
            now = _utc_now()
            self._db.execute(
                "INSERT OR IGNORE INTO sent_samples (sha256, sent_at) VALUES (?, ?)",
                (sha256, now),
            )
            self._db.execute(
                "INSERT OR REPLACE INTO sent_files "
                "(path, size, mtime_ns, sha256, sent_at) VALUES (?, ?, ?, ?, ?)",
                (str(path), size, mtime_ns, sha256, now),
            )
            self._db.commit()

    def cached_is_pe(self, path: Path, size: int, mtime_ns: int) -> bool | None:
        row = self._reader().execute(
            "SELECT is_pe FROM pe_cache "
            "WHERE path = ? AND size = ? AND mtime_ns = ?",
            (str(path), size, mtime_ns),
        ).fetchone()
        return None if row is None else bool(row[0])

    def cache_pe_result(
        self, path: Path, size: int, mtime_ns: int, is_pe: bool
    ) -> None:
        with self._write_lock:
            self._db.execute(
                "INSERT OR REPLACE INTO pe_cache "
                "(path, size, mtime_ns, is_pe, checked_at) VALUES (?, ?, ?, ?, ?)",
                (str(path), size, mtime_ns, 1 if is_pe else 0, _utc_now()),
            )
            cutoff = datetime.now(timezone.utc).timestamp() - 7 * 86400
            self._db.execute(
                "DELETE FROM pe_cache WHERE checked_at < ?", (cutoff,)
            )
            self._db.commit()

    def close(self) -> None:
        with self._write_lock:
            try:
                self._db.commit()
            finally:
                self._db.close()
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            conn.close()
            self._local.conn = None


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------


class AgentHealth:
    def __init__(
        self,
        config: dict[str, Any],
        config_path: Path,
        service_mode: bool = False,
    ):
        self._lock = threading.Lock()
        self._started_monotonic = time.monotonic()
        self._started_at = _utc_now()
        self._config_path = str(config_path)
        self._service_mode = bool(service_mode)
        self._watch_patterns = [str(item) if isinstance(item, str)
                                else str(item["path"])
                                for item in config["watch_dirs"]]
        self._watch_dirs = [str(p) for p in resolve_watch_patterns(self._watch_patterns)]
        self._watch_excludes = _expand_excludes(
            config.get("watch_excludes", [])
        )
        self._brokers = str(config["kafka"]["bootstrap_servers"])
        self._topic = str(config["kafka"]["topic"])
        self._scan_interval = float(config.get("scan_interval_seconds", 5))
        self._detections_file = str(detections_path(config))
        self._scan_workers = int(config.get("scan_workers", DEFAULT_SCAN_WORKERS))
        self._dir_workers = int(config.get("dir_workers", DEFAULT_DIR_WORKERS))
        api = config.get("api") or {}
        self._api = {
            "enabled": bool(api.get("enabled", True)),
            "host": str(api.get("host", DEFAULT_API_HOST)),
            "port": int(api.get("port", DEFAULT_API_PORT)),
        }
        self._state = "starting"
        # Scan pause switch, driven by POST /api/v1/control. Set = paused:
        # the scan loop skips its next scan and parks here until cleared.
        # An Event (not a bare bool) lets the loop wait on it with a timeout,
        # so a stopped service never hangs in the barrier.
        self._pause_requested = threading.Event()
        self._last_scan_started_at: str | None = None
        self._last_scan_finished_at: str | None = None
        self._last_scan_seconds: float | None = None
        self._last_scan_file_count = 0
        self._samples_published = 0
        self._publish_errors = 0
        self._records_logged = 0
        self._last_sample: dict[str, Any] | None = None
        self._last_error: str | None = None
        self._last_error_at: str | None = None
        self._last_publish_ok: bool | None = None
        self._last_publish_at: str | None = None
        self._engines = {
            "lief": LIEF_AVAILABLE,
            "libmagic": _MAGIC_AVAILABLE,
            "psutil": psutil is not None,
        }

    def set_state(self, state: str) -> None:
        with self._lock:
            self._state = state

    def set_watch_dirs(self, paths: list[Path]) -> None:
        with self._lock:
            self._watch_dirs = [str(p) for p in paths]

    def scan_started(self) -> None:
        with self._lock:
            self._state = "scanning"
            self._last_scan_started_at = _utc_now()

    def scan_finished(self, seconds: float, file_count: int) -> None:
        with self._lock:
            self._state = "idle"
            self._last_scan_finished_at = _utc_now()
            self._last_scan_seconds = round(max(0.0, seconds), 3)
            self._last_scan_file_count = file_count

    def sample_published(self, name: str, sha256: str, size: int) -> None:
        with self._lock:
            stamp = _utc_now()
            self._samples_published += 1
            self._records_logged += 1
            self._last_sample = {
                "detected_at": stamp,
                "file_name": name,
                "file_size": size,
                "sha256": sha256,
            }
            self._last_publish_ok = True
            self._last_publish_at = stamp

    def publish_failed(self, error: str) -> None:
        with self._lock:
            self._publish_errors += 1
            self._last_publish_ok = False
            self._last_error = str(error)[:500]
            self._last_error_at = _utc_now()

    def record_error(self, error: str) -> None:
        with self._lock:
            self._last_error = str(error)[:500]
            self._last_error_at = _utc_now()

    # -- scan pause / resume (remote control endpoint) --------------------

    def pause_scans(self) -> None:
        """Stop scanning after the current scan finishes; keep serving API."""
        self._pause_requested.set()

    def resume_scans(self) -> None:
        self._pause_requested.clear()

    def is_paused(self) -> bool:
        return self._pause_requested.is_set()

    def pause_barrier(self, stop_event: threading.Event | None = None) -> None:
        """Block inside the scan loop while scans are paused.

        Called once per loop iteration before ``scan_once()``. Returns as soon
        as scans resume, or immediately when ``stop_event`` fires so a stopping
        service never waits on the barrier. While parked, the health state
        reads ``paused``; on resume it goes back to ``running``.
        """
        if not self._pause_requested.is_set():
            return
        with self._lock:
            if self._state != "paused":
                self._state = "paused"
        LOG.info("Scans paused; agent idle until resume is requested")
        while self._pause_requested.is_set():
            if stop_event is not None:
                if stop_event.wait(1.0):
                    return
            else:
                time.sleep(1.0)
        with self._lock:
            if self._state == "paused":
                self._state = "running"
        LOG.info("Scans resumed")

    def _status_locked(self) -> str:
        if self._state == "starting":
            return "starting"
        if self._last_publish_ok is False:
            return "degraded"
        return "ok"

    def _process_metrics(self) -> dict[str, Any]:
        if psutil is None:
            return {"available": False}
        try:
            proc = psutil.Process(os.getpid())
            with proc.oneshot():
                mem = proc.memory_info()
                cpu = proc.cpu_percent(interval=None)
                threads = proc.num_threads()
                create = proc.create_time()
                try:
                    handles = (
                        proc.num_handles() if os.name == "nt" else proc.num_fds()
                    )
                except (AttributeError, psutil.Error):
                    handles = None
            return {
                "available": True,
                "rss_bytes": mem.rss,
                "vms_bytes": mem.vms,
                "cpu_percent": round(cpu, 2),
                "threads": threads,
                "open_handles": handles,
                "create_time": datetime.fromtimestamp(
                    create, tz=timezone.utc
                ).isoformat(),
            }
        except Exception:  # noqa: BLE001 - metrics must never break health
            LOG.debug("psutil metrics failed", exc_info=True)
            return {"available": False}

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            uptime = time.monotonic() - self._started_monotonic
            payload = {
                "status": self._status_locked(),
                "agent": {
                    "name": "DaOrcsEndpointAgent",
                    "version": VERSION,
                    "host": platform.node(),
                    "platform": platform.platform(),
                    "pid": os.getpid(),
                    "service": self._service_mode,
                    "started_at": self._started_at,
                    "uptime_seconds": round(uptime, 1),
                    "state": self._state,
                    "scan_paused": self._pause_requested.is_set(),
                },
                "config": {
                    "path": self._config_path,
                    "watch_patterns": list(self._watch_patterns),
                    "watch_dirs": list(self._watch_dirs),
                    "watch_dirs_resolved": len(self._watch_dirs),
                    "watch_excludes": list(self._watch_excludes),
                    "scan_interval_seconds": self._scan_interval,
                    "scan_workers": self._scan_workers,
                    "dir_workers": self._dir_workers,
                },
                "engines": dict(self._engines),
                "kafka": {
                    "bootstrap_servers": self._brokers,
                    "topic": self._topic,
                    "last_publish_ok": self._last_publish_ok,
                    "last_publish_at": self._last_publish_at,
                },
                "counters": {
                    "samples_published": self._samples_published,
                    "publish_errors": self._publish_errors,
                    "records_logged": self._records_logged,
                },
                "last_scan": {
                    "started_at": self._last_scan_started_at,
                    "finished_at": self._last_scan_finished_at,
                    "duration_seconds": self._last_scan_seconds,
                    "file_count": self._last_scan_file_count,
                },
                "last_sample": self._last_sample,
                "last_error": (
                    {"message": self._last_error, "at": self._last_error_at}
                    if self._last_error else None
                ),
                "detections": {"file": self._detections_file},
                "api": dict(self._api),
                "process": self._process_metrics(),
            }
        return payload


# ---------------------------------------------------------------------------
# Kafka publisher
# ---------------------------------------------------------------------------


class KafkaSamplePublisher:
    """Publish a sample-start marker, ordered chunks, then a completion marker.

    The scan loop flushes once per scan, not per sample, so librdkafka can
    batch across the whole scan. ``flush()`` is exposed for the caller.
    """

    def __init__(self, producer: Any, topic: str, chunk_bytes: int):
        self.producer = producer
        self.topic = topic
        self.chunk_bytes = chunk_bytes
        self._delivery_errors: list[str] = []
        self._errors_lock = threading.Lock()

    def _delivery_report(self, error: Any, _message: Any) -> None:
        if error is not None:
            with self._errors_lock:
                self._delivery_errors.append(str(error))

    def _produce(self, key: bytes, message: dict[str, Any]) -> None:
        encoded = json.dumps(message, separators=(",", ":")).encode("utf-8")
        while True:
            try:
                self.producer.produce(
                    self.topic, key=key, value=encoded,
                    callback=self._delivery_report,
                )
                self.producer.poll(0)
                return
            except BufferError:
                self.producer.poll(0.5)

    def publish(self, path: Path, sha256: str, size: int) -> None:
        with self._errors_lock:
            self._delivery_errors.clear()
        key = sha256.encode("ascii")
        initial_stat = path.stat()
        chunk_total = (size + self.chunk_bytes - 1) // self.chunk_bytes
        metadata = {
            "sha256": sha256,
            "file_name": path.name,
            "file_size": size,
            "chunk_total": chunk_total,
            "host": platform.node(),
            "username": _current_username(),
            "detected_at": _utc_now(),
            "agent_version": VERSION,
        }

        self._produce(key, {"event": "sample_start", **metadata})
        bytes_read = 0
        with path.open("rb") as sample:
            for chunk_num in range(chunk_total):
                data = sample.read(self.chunk_bytes)
                if not data:
                    raise OSError(f"Sample changed while reading: {path}")
                bytes_read += len(data)
                self._produce(key, {
                    "event": "sample_chunk",
                    "sha256": sha256,
                    "chunk_num": chunk_num,
                    "chunk_total": chunk_total,
                    "chunk_data": data.hex(),
                })
        final_stat = path.stat()
        if (bytes_read != size
                or final_stat.st_size != initial_stat.st_size
                or final_stat.st_mtime_ns != initial_stat.st_mtime_ns):
            raise OSError(f"Sample changed while publishing: {path}")
        self._produce(key, {
            "event": "sample_complete",
            "sha256": sha256,
            "chunk_total": chunk_total,
        })

    def flush(self, timeout: float) -> None:
        if self.producer.flush(timeout):
            raise TimeoutError(f"Timed out waiting for Kafka delivery ({timeout}s)")
        with self._errors_lock:
            errors = list(self._delivery_errors)
        if errors:
            raise RuntimeError("Kafka delivery failed: " + "; ".join(errors))


# ---------------------------------------------------------------------------
# Agent (multi-threaded, streaming walker)
# ---------------------------------------------------------------------------


class EndpointAgent:
    def __init__(
        self,
        config: dict[str, Any],
        producer: Any,
        state_path: Path,
        health: AgentHealth | None = None,
    ):
        self._watch_entries = _watch_entries_with_stable(config)
        self._watch_patterns = [pattern for pattern, _ in self._watch_entries]
        self._watch_stable = {pattern: stable for pattern, stable in self._watch_entries}
        self.watch_dirs = resolve_watch_patterns(self._watch_patterns)
        self.scan_interval = float(config.get("scan_interval_seconds", 5))
        self.stable_seconds = float(config.get("stable_seconds", 0))
        self.publisher = KafkaSamplePublisher(
            producer,
            config["kafka"]["topic"],
            config.get("chunk_bytes", MAX_CHUNK_BYTES),
        )
        self.state = SampleState(state_path)
        self.health = health
        self.scan_workers = int(config.get("scan_workers", DEFAULT_SCAN_WORKERS))
        self.dir_workers = int(config.get("dir_workers", DEFAULT_DIR_WORKERS))
        self.mime_prefilter = bool(config.get("mime_prefilter", True)) and _MAGIC_AVAILABLE
        self.flush_timeout = float(
            config.get(
                "flush_timeout_seconds",
                config["kafka"].get("flush_timeout_seconds", DEFAULT_FLUSH_TIMEOUT),
            )
        )
        self.excludes = _expand_excludes(config.get("watch_excludes", []))
        self._flush_lock = threading.Lock()

    def close(self) -> None:
        self.state.close()

    # -- per-file work (runs in worker threads) --------------------------

    def _stable_snapshot(
        self, path: Path, stable_seconds: float,
    ) -> tuple[int, int] | None:
        try:
            if path.is_symlink():
                return None
            before = path.stat()
            if not stat_module.S_ISREG(before.st_mode):
                return None
            if stable_seconds:
                time.sleep(stable_seconds)
            after = path.stat()
        except OSError:
            return None
        if (before.st_size != after.st_size
                or before.st_mtime_ns != after.st_mtime_ns
                or after.st_size == 0):
            return None
        return after.st_size, after.st_mtime_ns

    @staticmethod
    def _sha256(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as sample:
            for block in iter(lambda: sample.read(1024 * 1024), b""):
                digest.update(block)
        return digest.hexdigest()

    def _classify_pe(self, path: Path, size: int, mtime_ns: int) -> bool:
        """Return True when ``path`` is a PE, using cache → MIME → LIEF."""
        cached = self.state.cached_is_pe(path, size, mtime_ns)
        if cached is not None:
            return cached

        if self.mime_prefilter:
            mime_verdict = mime_is_pe(path)
            if mime_verdict is False:
                self.state.cache_pe_result(path, size, mtime_ns, False)
                return False

        result = is_pe_file(path)
        self.state.cache_pe_result(path, size, mtime_ns, result)
        return result

    def _stable_for(self, path: Path) -> float:
        for root, stable in self._watch_stable.items():
            expanded = expand_path(root)
            try:
                path.relative_to(expanded)
                return stable
            except ValueError:
                continue
        return self.stable_seconds

    def _process_file(self, path: Path) -> bool:
        """Return True if the file was published. Runs in a worker thread."""
        try:
            stat = path.stat()
        except OSError:
            return False
        if stat.st_size == 0:
            return False

        # Fast path: unchanged since last delivery → no sleep, no hash, no PE.
        if self.state.already_sent(path, stat.st_size, stat.st_mtime_ns):
            return False

        if not self._classify_pe(path, stat.st_size, stat.st_mtime_ns):
            return False

        stable_seconds = self._stable_for(path)
        snapshot = self._stable_snapshot(path, stable_seconds)
        if snapshot is None:
            return False
        size, mtime_ns = snapshot

        sha256 = self._sha256(path)
        try:
            current = path.stat()
        except OSError:
            return False
        if current.st_size != size or current.st_mtime_ns != mtime_ns:
            LOG.info("File changed during inspection; will retry: %s", path)
            return False
        if self.state.contains(sha256):
            return False

        self.publisher.publish(path, sha256, size)
        # Detection logged before mark_sent: a crash between them re-sends on
        # restart (idempotent at the consumer) instead of silently dropping.
        record_detection(path, sha256, size, self.publisher.topic)
        self.state.mark_sent(sha256, path, size, mtime_ns)
        if self.health is not None:
            self.health.sample_published(path.name, sha256, size)
        LOG.info(
            "Published PE sample %s (%s bytes, sha256=%s)",
            path.name, size, sha256,
        )
        return True

    # -- streaming directory walker -------------------------------------

    def _walk_root(self, root: Path) -> Iterator[Path]:
        if not root.is_dir():
            LOG.warning("Watch directory is unavailable: %s", root)
            return
        for current, dirs, names in os.walk(root, followlinks=False):
            current_path = Path(current)
            if _is_excluded(current_path, self.excludes):
                dirs[:] = []
                continue
            dirs[:] = [
                name for name in dirs
                if not (current_path / name).is_symlink()
                and not _is_excluded(current_path / name, self.excludes)
            ]
            for name in names:
                yield current_path / name

    def _refresh_watch_dirs(self) -> list[Path]:
        resolved = resolve_watch_patterns(self._watch_patterns)
        if resolved != self.watch_dirs:
            LOG.info(
                "Watch set changed: %s -> %s",
                ", ".join(str(p) for p in self.watch_dirs) or "<empty>",
                ", ".join(str(p) for p in resolved) or "<empty>",
            )
            self.watch_dirs = resolved
            if self.health is not None:
                self.health.set_watch_dirs(resolved)
        return resolved

    def _files(self) -> Iterator[Path]:
        """Stream candidates from every watch root in parallel.

        Each root has its own producer thread feeding a shared bounded queue.
        Consumers block when the queue is full, which gives backpressure to
        the walkers instead of buffering the whole tree.
        """
        import queue

        watch_dirs = self._refresh_watch_dirs()
        if not watch_dirs:
            LOG.warning(
                "No watch directories resolved from %s; nothing to scan",
                ", ".join(self._watch_patterns),
            )
            return

        max_queued = max(1024, self.scan_workers * 64)
        q: "queue.Queue[Path | None]" = queue.Queue(maxsize=max_queued)
        stop = threading.Event()

        def produce(root: Path) -> None:
            try:
                for path in self._walk_root(root):
                    if stop.is_set():
                        return
                    while not stop.is_set():
                        try:
                            q.put(path, timeout=0.5)
                            break
                        except queue.Full:
                            continue
            except Exception:  # noqa: BLE001
                LOG.exception("Walker for %s failed", root)
            finally:
                q.put(None)

        workers = min(self.dir_workers, max(1, len(watch_dirs)))
        producers = [
            threading.Thread(
                target=produce, args=(root,),
                name=f"daorcs-walk-{root.name}", daemon=True,
            )
            for root in watch_dirs
        ]
        # Cap concurrent producers; the queue bounds memory regardless.
        active = 0
        pending = list(producers)
        try:
            while pending or active > 0:
                while pending and active < workers:
                    thread = pending.pop(0)
                    thread.start()
                    active += 1
                item = q.get()
                if item is None:
                    active -= 1
                    continue
                yield item
        finally:
            stop.set()
            for thread in producers:
                thread.join(timeout=1)

    # -- scan loop ------------------------------------------------------

    def scan_once(self) -> None:
        started = time.monotonic()
        if self.health is not None:
            self.health.scan_started()

        file_count = 0
        published = 0
        with ThreadPoolExecutor(
            max_workers=self.scan_workers, thread_name_prefix="daorcs-scan",
        ) as pool:
            # Submit incrementally so the pool can start work while the walker
            # is still discovering files, and so a 300k-file tree does not
            # create 300k Future objects up front.
            in_flight: set = set()
            max_in_flight = self.scan_workers * 8
            for path in self._files():
                file_count += 1
                while len(in_flight) >= max_in_flight:
                    done, in_flight = _wait_some(in_flight, published)
                    published = done
                in_flight.add(pool.submit(self._process_file, path))
            for fut in as_completed(in_flight):
                try:
                    if fut.result():
                        published += 1
                except (OSError, RuntimeError, TimeoutError) as exc:
                    LOG.error("Could not publish: %s", exc)
                    if self.health is not None:
                        if isinstance(exc, (RuntimeError, TimeoutError)):
                            self.health.publish_failed(str(exc))
                        else:
                            self.health.record_error(str(exc))

        try:
            with self._flush_lock:
                self.publisher.flush(self.flush_timeout)
        except (RuntimeError, TimeoutError) as exc:
            LOG.error("Kafka flush failed: %s", exc)
            if self.health is not None:
                self.health.publish_failed(str(exc))

        if self.health is not None:
            self.health.scan_finished(time.monotonic() - started, file_count)
        LOG.debug(
            "Scan finished: %d candidate files, %d published",
            file_count, published,
        )

    def run(
        self,
        once: bool = False,
        stop_event: threading.Event | None = None,
    ) -> None:
        LOG.info(
            "Monitoring %s (patterns: %s); Kafka topic %s; scan_workers=%d "
            "dir_workers=%d mime_prefilter=%s",
            ", ".join(str(p) for p in self.watch_dirs) or "<none resolved>",
            ", ".join(self._watch_patterns),
            self.publisher.topic, self.scan_workers, self.dir_workers,
            self.mime_prefilter,
        )
        if self.health is not None:
            self.health.set_state("running")
        while True:
            if stop_event is not None and stop_event.is_set():
                return
            # Park here while scans are paused (POST /api/v1/control); the
            # API keeps serving health and detections the whole time.
            if self.health is not None:
                self.health.pause_barrier(stop_event)
            self.scan_once()
            if once:
                return
            if stop_event is None:
                time.sleep(self.scan_interval)
            elif stop_event.wait(self.scan_interval):
                return


def _wait_some(in_flight: set, published: int) -> tuple[int, set]:
    """Block until at least one future completes; drain any that are done.

    Returns (running_published_count, remaining_futures). This keeps the
    in-flight set bounded without ever blocking on the whole batch.
    """
    from concurrent.futures import wait, FIRST_COMPLETED
    done, not_done = wait(in_flight, return_when=FIRST_COMPLETED)
    for fut in done:
        try:
            if fut.result():
                published += 1
        except (OSError, RuntimeError, TimeoutError) as exc:
            LOG.error("Could not publish: %s", exc)
    return published, set(not_done)


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------


def _configure_bootstrap_logging(path: Path | None = None) -> Path:
    if path is None:
        path = default_log_dir() / "service.log"
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
    except OSError:
        path = (
            Path(os.environ.get("TEMP", r"C:\Windows\Temp")) / "daorcs-agent.log"
        )
        path.parent.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        handlers=[RotatingFileHandler(
            path, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8"
        )],
        force=True,
    )
    return path


def detections_path(config: dict[str, Any]) -> Path:
    configured = config.get("detections_file")
    if isinstance(configured, str) and configured.strip():
        return expand_path(configured)
    log_path = config.get("log_file")
    if isinstance(log_path, str) and log_path.strip():
        return expand_path(log_path).parent / "detections.log"
    return default_log_dir() / "detections.log"


def _configure_detections_logging(config: dict[str, Any]) -> None:
    for handler in list(DETECTIONS.handlers):
        DETECTIONS.removeHandler(handler)
        handler.close()
    try:
        path = detections_path(config)
        path.parent.mkdir(parents=True, exist_ok=True)
        handler: logging.Handler = RotatingFileHandler(
            path, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8"
        )
    except OSError:
        LOG.warning(
            "Could not open the detections log; detections will only appear "
            "in the agent log", exc_info=True,
        )
        return
    handler.setFormatter(logging.Formatter("%(message)s"))
    DETECTIONS.addHandler(handler)
    DETECTIONS.setLevel(logging.INFO)
    DETECTIONS.propagate = False


def record_detection(path: Path, sha256: str, size: int, topic: str) -> None:
    record = {
        "detected_at": _utc_now(),
        "event": "sample_detected",
        "file_name": path.name,
        "file_path": str(path),
        "file_size": size,
        "sha256": sha256,
        "host": platform.node(),
        "username": _current_username(),
        "kafka_topic": topic,
        "agent_version": VERSION,
    }
    DETECTIONS.info(json.dumps(record, separators=(",", ":")))


def _configure_logging(config: dict[str, Any]) -> None:
    handlers: list[logging.Handler] = [logging.StreamHandler()]
    log_path = config.get("log_file")
    if isinstance(log_path, str) and log_path:
        path = expand_path(log_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        handlers.append(RotatingFileHandler(
            path, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8"
        ))
    logging.basicConfig(
        level=getattr(logging, str(config.get("log_level", "INFO")).upper(), None)
        or logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        handlers=handlers,
        force=True,
    )
    _configure_detections_logging(config)


# ---------------------------------------------------------------------------
# Tail helper for the detections endpoint
# ---------------------------------------------------------------------------


def _tail_jsonl(path: Path, limit: int) -> list[dict[str, Any]]:
    try:
        with path.open("rb") as handle:
            handle.seek(0, os.SEEK_END)
            position = handle.tell()
            data = b""
            block = 64 * 1024
            while position > 0 and data.count(b"\n") <= limit:
                step = min(block, position)
                position -= step
                handle.seek(position)
                data = handle.read(step) + data
    except OSError:
        return []

    records: list[dict[str, Any]] = []
    for line in data.splitlines()[-limit:]:
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            records.append(item)
    return records


# ---------------------------------------------------------------------------
# Flask API
# ---------------------------------------------------------------------------


def build_flask_app(
    health: AgentHealth, detections_file: Path, max_limit: int = 500,
) -> Flask:
    app = Flask(__name__)
    app.config["JSON_SORT_KEYS"] = False

    @app.get("/health")
    @app.get("/api/v1/ping")
    def ping():
        return jsonify({
            "status": "ok",
            "service": "DaOrcsEndpointAgent",
            "version": VERSION,
            "host": platform.node(),
            "time": _utc_now(),
        })

    @app.get("/api/v1/health")
    @app.get("/api/v1/heartbeat")
    @app.get("/api/v1/agent")
    def heartbeat():
        return jsonify(health.snapshot())

    @app.get("/api/v1/detections")
    def detections():
        try:
            limit = int(request.args.get("limit", "20"))
        except ValueError:
            limit = 20
        limit = max(1, min(limit, max_limit))
        records = _tail_jsonl(detections_file, limit)
        return jsonify({
            "file": str(detections_file),
            "count": len(records),
            "detections": records,
        })

    @app.post("/api/v1/control")
    def control():
        """Scan pause / resume switch for the panel's Terminate/Start buttons.

        The agent ships as a Windows service, so a remote "start the service"
        is impossible (nothing listens once it is stopped). The symmetric,
        remote-controllable control is the scan loop: ``stop`` parks it after
        the current scan, ``start`` releases it. Heartbeat and detections keep
        answering in both states.
        """
        payload = request.get_json(silent=True) or {}
        action = str(payload.get("action") or "").strip().lower()
        if action == "stop":
            health.pause_scans()
        elif action == "start":
            health.resume_scans()
        else:
            return jsonify({
                "error": "unknown action",
                "detail": "expected {\"action\": \"stop\"} or {\"action\": \"start\"}",
            }), 400
        return jsonify({
            "ok": True,
            "action": action,
            "scan_paused": health.is_paused(),
        })

    @app.errorhandler(404)
    def not_found(_err):
        return jsonify({
            "error": "not found",
            "endpoints": [
                "GET /health",
                "GET /api/v1/health",
                "GET /api/v1/detections?limit=20",
                "POST /api/v1/control {\"action\": \"stop\"|\"start\"}",
            ],
        }), 404

    @app.errorhandler(405)
    def method_not_allowed(_err):
        return jsonify({
            "error": "method not allowed",
            "detail": "read-only GET, plus POST /api/v1/control",
        }), 405

    return app


class AgentApiServer:
    """Heartbeat HTTP server (Flask) inside the agent process.

    GET routes are read-only; POST /api/v1/control is the one deliberate
    write (scan pause / resume for the panel's Terminate/Start buttons).
    """

    def __init__(self, health: AgentHealth, config: dict[str, Any]):
        api = config.get("api") or {}
        self.health = health
        self.host = str(api.get("host") or DEFAULT_API_HOST)
        self.port = int(api.get("port") or DEFAULT_API_PORT)
        self.detections_file = detections_path(config)
        self._app = build_flask_app(self.health, self.detections_file)
        self._server = None
        self._thread: threading.Thread | None = None

    @staticmethod
    def _is_loopback(host: str) -> bool:
        import ipaddress
        if host.strip().lower() in ("localhost", "::1"):
            return True
        try:
            return ipaddress.ip_address(host).is_loopback
        except ValueError:
            return False

    def start(self) -> bool:
        if not self._is_loopback(self.host):
            LOG.warning(
                "Agent API is unauthenticated and listening beyond loopback (%s). "
                "Restrict port %s to the panel's subnet with a firewall rule.",
                self.host, self.port,
            )
        try:
            from werkzeug.serving import make_server
            self._server = make_server(
                self.host, self.port, self._app, threaded=True,
            )
        except OSError as exc:
            LOG.error(
                "Agent API could not bind %s:%s: %s", self.host, self.port, exc,
            )
            return False
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            name="daorcs-agent-api", daemon=True,
        )
        self._thread.start()
        LOG.info(
            "Agent API (Flask) listening on http://%s:%s (no auth)",
            self.host, self.port,
        )
        return True

    def stop(self) -> None:
        server, self._server = self._server, None
        if server is None:
            return
        try:
            server.shutdown()
            server.server_close()
        except OSError:
            LOG.debug("Agent API shutdown raised", exc_info=True)
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None


# ---------------------------------------------------------------------------
# Runner / self-test / service
# ---------------------------------------------------------------------------


def _run_agent(
    config_path: Path,
    stop_event: threading.Event | None = None,
    once: bool = False,
    service: bool = False,
) -> int:
    LOG.info(
        "DaOrcs endpoint agent %s starting (config %s)", VERSION, config_path,
    )
    if not LIEF_AVAILABLE:
        raise RuntimeError(
            "LIEF is required for PE analysis and is not importable. "
            "Reinstall the agent or fix the PyInstaller bundle."
        )
    config = load_config(config_path)
    _configure_logging(config)
    LOG.info("Configuration loaded from %s", config_path)

    from confluent_kafka import Producer

    kafka_settings = dict(config["kafka"].get("producer_config", {}))
    kafka_settings["bootstrap.servers"] = config["kafka"]["bootstrap_servers"]
    kafka_settings.setdefault(
        "client.id", f"daorcs-endpoint-agent-{platform.node()}",
    )
    kafka_settings.setdefault("enable.idempotence", True)
    producer = Producer(kafka_settings)

    state_path = expand_path(config.get("state_file", str(DEFAULT_STATE)))
    health = AgentHealth(config, config_path, service_mode=service)
    agent = EndpointAgent(config, producer, state_path, health=health)

    api = AgentApiServer(health, config)
    if (config.get("api") or {}).get("enabled", True):
        api.start()
    try:
        agent.run(once=once, stop_event=stop_event)
    finally:
        health.set_state("stopping")
        api.stop()
        try:
            producer.flush(60)
        except Exception:  # noqa: BLE001
            LOG.debug("Final producer flush raised", exc_info=True)
        agent.close()
    return 0


def _self_test(config_path: Path, produce_test: bool = False) -> int:
    print(f"DaOrcs endpoint agent {VERSION}")
    print(f"Python {platform.python_version()} on {platform.platform()}")
    print(f"Config: {config_path}")
    try:
        config = load_config(config_path)
    except (ValueError, OSError) as exc:
        print(f"FAIL config: {exc}")
        return 1

    print("OK   config is valid JSON and required keys are present")
    try:
        _configure_logging(config)
    except OSError as exc:
        print(f"WARN could not open log file: {exc}")

    print("     watch patterns and resolved directories:")
    for pattern, stable in _watch_entries_with_stable(config):
        expanded = expand_path(pattern)
        if glob_module.has_magic(str(expanded)):
            matches = resolve_watch_patterns([pattern])
            if matches:
                print(f"OK   {pattern}  (stable_seconds={stable})")
                for p in matches:
                    print(f"       -> {p}")
            else:
                print(f"WARN {pattern}  matched nothing yet (stable_seconds={stable})")
        else:
            if expanded.is_dir():
                print(f"OK   {expanded}  (stable_seconds={stable})")
            else:
                print(f"WARN {expanded} does not exist yet (stable_seconds={stable})")

    excludes = _expand_excludes(config.get("watch_excludes", []))
    print(f"OK   {len(excludes)} exclude path(s) active")
    for ex in excludes:
        print(f"       ! {ex}")

    print(
        f"OK   scan_workers={config.get('scan_workers', DEFAULT_SCAN_WORKERS)}, "
        f"dir_workers={config.get('dir_workers', DEFAULT_DIR_WORKERS)}, "
        f"flush_timeout={config.get('flush_timeout_seconds', DEFAULT_FLUSH_TIMEOUT)}s"
    )

    if not LIEF_AVAILABLE:
        print("FAIL LIEF is not importable; PE analysis cannot run")
        return 1
    try:
        print(f"OK   LIEF {lief.__version__}")
    except AttributeError:
        print("OK   LIEF (version unknown)")

    if _MAGIC_AVAILABLE:
        print("OK   python-magic (libmagic loaded)")
    elif magic is not None:
        print("WARN python-magic is installed but libmagic failed to load "
              "(on Windows install python-magic-bin)")
    else:
        print("WARN python-magic is not installed; MIME pre-filter disabled")

    if psutil is None:
        print("WARN psutil is not installed; process metrics unavailable")
    else:
        print(f"OK   psutil {psutil.__version__}")

    api_cfg = config.get("api") or {}
    if api_cfg.get("enabled", True):
        api_host = str(api_cfg.get("host", DEFAULT_API_HOST))
        api_port = int(api_cfg.get("port", DEFAULT_API_PORT))
        print(f"OK   agent API: http://{api_host}:{api_port} (read-only, no auth)")
        if not AgentApiServer._is_loopback(api_host):
            print(f"WARN the agent API is reachable beyond loopback ({api_host}); "
                  f"allow only the panel's address in the firewall")
    else:
        print("OK   agent API disabled")

    try:
        import confluent_kafka
        from confluent_kafka import Producer
        from confluent_kafka.admin import AdminClient
    except Exception as exc:  # noqa: BLE001
        print(f"FAIL confluent-kafka runtime: {exc}")
        LOG.exception("confluent-kafka runtime check failed")
        return 1
    print(
        f"OK   confluent-kafka {confluent_kafka.version()[0]} "
        f"(librdkafka {confluent_kafka.libversion()[0]})"
    )

    brokers = config["kafka"]["bootstrap_servers"]
    topic = config["kafka"]["topic"]
    print(f"     bootstrap servers: {brokers}")
    print(f"     topic: {topic}")

    kafka_settings = dict(config["kafka"].get("producer_config", {}))
    kafka_settings["bootstrap.servers"] = brokers
    kafka_settings.setdefault("client.id", f"daorcs-selftest-{platform.node()}")
    kafka_settings.setdefault("socket.timeout.ms", 5000)
    kafka_settings.setdefault("request.timeout.ms", 5000)
    try:
        producer = Producer(kafka_settings)
        admin = AdminClient(kafka_settings)
        metadata = admin.list_topics(timeout=6)
    except Exception as exc:  # noqa: BLE001
        print(f"WARN broker is not reachable: {exc}")
        print("     The agent will keep retrying. Start the broker, then rerun")
        print("     this check or restart the DaOrcsEndpointAgent service.")
        print("FAIL connection test (broker offline)")
        return 2

    broker_ids = sorted(metadata.brokers.keys())
    print(
        f"OK   broker answered: {len(broker_ids)} broker(s) "
        f"(id {', '.join(str(item) for item in broker_ids)})"
    )
    if topic in metadata.topics:
        partitions = len(metadata.topics[topic].partitions)
        print(f"OK   topic '{topic}' exists ({partitions} partition(s))")
    else:
        auto = config["kafka"].get("producer_config", {}).get(
            "allow.auto.create.topics", True
        )
        print(f"WARN topic '{topic}' does not exist yet; it will be created on "
              f"first publish (auto-create={auto})")

    if produce_test:
        try:
            producer.produce(
                topic,
                key=b"daorcs-selftest",
                value=json.dumps({
                    "event": "agent_selftest",
                    "agent_version": VERSION,
                    "host": platform.node(),
                    "checked_at": _utc_now(),
                }).encode("utf-8"),
            )
            remaining = producer.flush(10)
            if remaining:
                raise TimeoutError(f"{remaining} message(s) not delivered")
            print("OK   test message delivered to the topic")
        except Exception as exc:  # noqa: BLE001
            print(f"FAIL test message: {exc}")
            return 2

    print("OK   connection test passed")
    return 0


def _run_windows_service() -> int:
    log_path = _configure_bootstrap_logging()
    LOG.info(
        "DaOrcs endpoint agent %s service mode starting; log=%s",
        VERSION, log_path,
    )
    if os.name != "nt":
        raise RuntimeError("The Windows service mode is only available on Windows")

    import servicemanager
    import win32service
    import win32serviceutil

    class DaOrcsEndpointAgentService(win32serviceutil.ServiceFramework):
        _svc_name_ = "DaOrcsEndpointAgent"
        _svc_display_name_ = "DaOrcs Endpoint Agent"
        _svc_description_ = (
            "Monitors configured folders and publishes PE samples to Kafka."
        )

        def __init__(self, args):
            super().__init__(args)
            self.stop_event = threading.Event()

        def SvcStop(self):
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            self.stop_event.set()

        def SvcDoRun(self):
            try:
                _run_agent(DEFAULT_CONFIG, stop_event=self.stop_event,
                           service=True)
            except Exception as exc:  # noqa: BLE001
                LOG.error("Endpoint agent service stopped with an error: %s", exc)
                LOG.error("%s", traceback.format_exc())
                raise

    servicemanager.Initialize()
    servicemanager.PrepareToHostSingle(DaOrcsEndpointAgentService)
    servicemanager.StartServiceCtrlDispatcher()
    return 0


def main(argv: list[str] | None = None) -> int:
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    if raw_argv == ["--service"]:
        try:
            return _run_windows_service()
        except Exception as exc:  # noqa: BLE001
            _configure_bootstrap_logging()
            LOG.error("Could not run the Windows service: %s", exc)
            LOG.error("%s", traceback.format_exc())
            return 1

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--once", action="store_true",
                        help="scan once and exit; useful for VM validation")
    parser.add_argument("--self-test", action="store_true",
                        help="check config, runtime and broker reachability")
    parser.add_argument("--produce-test", action="store_true",
                        help="with --self-test, also publish one test record")
    args = parser.parse_args(raw_argv)
    if args.self_test:
        return _self_test(args.config, produce_test=args.produce_test)
    try:
        return _run_agent(args.config, once=args.once)
    except KeyboardInterrupt:
        LOG.info("Stopping endpoint agent")
        return 0
    except (ValueError, ImportError, OSError, RuntimeError) as exc:
        _configure_bootstrap_logging()
        LOG.error("%s", exc)
        LOG.error("%s", traceback.format_exc())
        return 1


if __name__ == "__main__":
    sys.exit(main())