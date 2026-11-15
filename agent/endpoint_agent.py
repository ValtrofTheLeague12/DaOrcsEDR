"""Watch configured folders for PE files and publish them to Kafka in chunks."""

from __future__ import annotations

import argparse
import hashlib
import http.server
import ipaddress
import json
import logging
import os
import platform
import sqlite3
import sys
import threading
import time
import traceback
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

VERSION = "0.4.1"
LOG_DIR_ENV = "DAORCS_LOG_DIR"
PROGRAM_DATA = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData"))
DEFAULT_API_HOST = "127.0.0.1"
DEFAULT_API_PORT = 8787


def default_log_dir() -> Path:
    """Return the AppData folder that holds every agent/installer log.

    The service runs as LocalSystem, whose own ``%APPDATA%`` is the system
    profile. The installer therefore sets ``DAORCS_LOG_DIR`` on the service to
    the installing user's ``%APPDATA%\\DaOrcs\\Agent\\logs``. Interactive runs
    use the current user's AppData.
    """
    override = os.environ.get(LOG_DIR_ENV)
    if override:
        return Path(os.path.expandvars(override)).expanduser()
    appdata = os.environ.get("APPDATA")
    if appdata:
        return Path(appdata) / "DaOrcs" / "Agent" / "logs"
    return Path.home() / "AppData" / "Roaming" / "DaOrcs" / "Agent" / "logs"


DEFAULT_CONFIG = PROGRAM_DATA / "DaOrcs" / "Agent" / "agent.json"
DEFAULT_STATE = PROGRAM_DATA / "DaOrcs" / "Agent" / "state.sqlite3"
DEFAULT_LOG = default_log_dir() / "agent.log"
DEFAULT_SERVICE_LOG = default_log_dir() / "service.log"
DETECTIONS_LOG_NAME = "ia_endpoint_agent.detections"
MAX_CHUNK_BYTES = 256 * 1024
PE_SIGNATURE = b"PE\0\0"
LOG = logging.getLogger("ia_endpoint_agent")
# Detections get their own logger so captured samples are never mixed into the
# runtime log: one JSON object per line in detections.log.
DETECTIONS = logging.getLogger(DETECTIONS_LOG_NAME)

# A PE has at most 96 sections; anything above that is a corrupt header, and
# reading it as a table would allocate on a number the file controls.
MAX_PE_SECTIONS = 96


def digest_section(section_content: bytes | bytearray | memoryview | str) -> str:
    """SHA-256 of a PE section's raw bytes, or '' when there is nothing to hash.

    Section contents from the file are bytes. ``str`` is accepted because the
    helper is also convenient for text, but a hash of the shipped bytes is the
    only useful answer for a sample, so bytes are the normal path.
    """
    if isinstance(section_content, str):
        data = section_content.encode("utf-8", errors="ignore")
    else:
        data = bytes(section_content or b"")
    if not data:
        return ""
    return hashlib.sha256(data).hexdigest()


def check_if_path_valid(path: Path) -> bool:
    """True when ``path`` is a readable, non-empty regular file."""
    try:
        return path.is_file() and path.stat().st_size > 0
    except OSError:
        return False


def _pe_sections(path: Path) -> list[tuple[str, str]]:
    """(name, sha256) for each section, parsed from the file itself.

    Deliberately dependency-free: the agent runs as a frozen Windows service,
    where a third-party PE library is another native DLL to ship and fail to
    load. The section table is a small, fixed struct in the header; walking it
    is enough for the digest this reports.
    """
    sections: list[tuple[str, str]] = []
    try:
        size = path.stat().st_size
        with path.open("rb") as sample:
            dos = sample.read(0x40)
            if len(dos) < 0x40:
                return sections
            pe_offset = int.from_bytes(dos[0x3C:0x40], "little")
            if pe_offset < 0x40 or pe_offset + 24 > size:
                return sections
            sample.seek(pe_offset)
            coff = sample.read(24)
            if len(coff) < 24:
                return sections
            count = int.from_bytes(coff[6:8], "little")
            optional_size = int.from_bytes(coff[20:22], "little")
            table = pe_offset + 24 + optional_size
            if (count <= 0 or count > MAX_PE_SECTIONS or
                    table + count * 40 > size):
                return sections
            sample.seek(table)
            entries = sample.read(count * 40)
            if len(entries) < count * 40:
                return sections
            for index in range(count):
                raw = entries[index * 40:(index + 1) * 40]
                name = raw[:8].rstrip(b"\0").decode("ascii", errors="replace")
                raw_size = int.from_bytes(raw[16:20], "little")
                raw_ptr = int.from_bytes(raw[20:24], "little")
                # A section may legitimately have no raw bytes (.bss is one);
                # it has nothing to hash, not an error.
                if not raw_size or raw_ptr + raw_size > size:
                    continue
                sample.seek(raw_ptr)
                digest = digest_section(sample.read(raw_size))
                if digest:
                    sections.append((name, digest))
    except OSError:
        LOG.debug("Cannot read PE sections from %s", path, exc_info=True)
    return sections


def is_pe_file(path: Path) -> bool:
    """True for a file with a valid DOS header and PE signature.

    The header is the answer. Section digests are logged when the table can be
    read, but a small or unusual (yet valid) PE must not be rejected because a
    parser could not walk its sections.
    """
    if not check_if_path_valid(path):
        return False
    try:
        with path.open("rb") as sample:
            if sample.read(2) != b"MZ":
                return False
            sample.seek(0x3C)
            offset_bytes = sample.read(4)
            if len(offset_bytes) != 4:
                return False
            pe_offset = int.from_bytes(offset_bytes, "little")
            if pe_offset < 64 or pe_offset > 16 * 1024 * 1024:
                return False
            sample.seek(pe_offset)
            if sample.read(4) != PE_SIGNATURE:
                return False
    except OSError:
        LOG.debug("Cannot inspect %s", path, exc_info=True)
        return False

    for name, digest in _pe_sections(path):
        LOG.debug("PE section %s sha256=%s", name, digest)
    return True

def load_config(path: Path) -> dict[str, Any]:
    try:
        # utf-8-sig tolerates a byte-order mark, which Windows editors and
        # PowerShell 5 add when an admin edits agent.json by hand.
        config = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Cannot read agent configuration {path}: {exc}") from exc
    if not isinstance(config, dict):
        raise ValueError("Agent configuration must be a JSON object")

    watch_dirs = config.get("watch_dirs")
    if not isinstance(watch_dirs, list) or not watch_dirs:
        raise ValueError("watch_dirs must be a non-empty list of directories")
    if any(not isinstance(item, str) or not item.strip() for item in watch_dirs):
        raise ValueError("Every watch_dirs entry must be a non-empty path")

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


def expand_path(value: str) -> Path:
    return Path(os.path.expandvars(os.path.expanduser(value))).resolve()


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class SampleState:
    """Persist hashes already delivered so restarts do not resend every file."""

    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(path)
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS sent_samples "
            "(sha256 TEXT PRIMARY KEY, sent_at TEXT NOT NULL)"
        )
        self._db.commit()

    def contains(self, sha256: str) -> bool:
        return self._db.execute(
            "SELECT 1 FROM sent_samples WHERE sha256 = ?", (sha256,)
        ).fetchone() is not None

    def mark_sent(self, sha256: str) -> None:
        self._db.execute(
            "INSERT OR IGNORE INTO sent_samples (sha256, sent_at) VALUES (?, ?)",
            (sha256, datetime.now(timezone.utc).isoformat()),
        )
        self._db.commit()

    def close(self) -> None:
        self._db.close()


class AgentHealth:
    """Thread-safe heartbeat shared by the scan loop and the REST API.

    The scan loop writes progress here; HTTP worker threads read snapshots.
    A lock rather than a queue keeps the newest value always available, which
    is what a health probe wants: it never queues behind old samples.
    """

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
        self._watch_dirs = [str(expand_path(item)) for item in config["watch_dirs"]]
        self._brokers = str(config["kafka"]["bootstrap_servers"])
        self._topic = str(config["kafka"]["topic"])
        self._scan_interval = float(config.get("scan_interval_seconds", 5))
        self._detections_file = str(detections_path(config))
        api = config.get("api") or {}
        self._api = {
            "enabled": bool(api.get("enabled", True)),
            "host": str(api.get("host", DEFAULT_API_HOST)),
            "port": int(api.get("port", DEFAULT_API_PORT)),
        }
        self._state = "starting"
        self._last_scan_started_at: str | None = None
        self._last_scan_finished_at: str | None = None
        self._last_scan_seconds: float | None = None
        self._samples_published = 0
        self._publish_errors = 0
        self._records_logged = 0
        self._last_sample: dict[str, Any] | None = None
        self._last_error: str | None = None
        self._last_error_at: str | None = None
        self._last_publish_ok: bool | None = None
        self._last_publish_at: str | None = None

    def set_state(self, state: str) -> None:
        with self._lock:
            self._state = state

    def scan_started(self) -> None:
        with self._lock:
            self._state = "scanning"
            self._last_scan_started_at = _utc_now()

    def scan_finished(self, seconds: float) -> None:
        with self._lock:
            self._state = "idle"
            self._last_scan_finished_at = _utc_now()
            self._last_scan_seconds = round(max(0.0, seconds), 3)

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

    def _status_locked(self) -> str:
        if self._state == "starting":
            return "starting"
        if self._last_publish_ok is False:
            return "degraded"
        return "ok"

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            uptime = time.monotonic() - self._started_monotonic
            return {
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
                },
                "config": {
                    "path": self._config_path,
                    "watch_dirs": list(self._watch_dirs),
                    "scan_interval_seconds": self._scan_interval,
                },
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
                },
                "last_sample": self._last_sample,
                "last_error": (
                    {"message": self._last_error, "at": self._last_error_at}
                    if self._last_error else None
                ),
                "detections": {"file": self._detections_file},
                "api": dict(self._api),
            }


class KafkaSamplePublisher:
    """Publish a sample-start marker, ordered chunks, then a completion marker."""

    def __init__(self, producer: Any, topic: str, chunk_bytes: int):
        self.producer = producer
        self.topic = topic
        self.chunk_bytes = chunk_bytes
        self._delivery_errors: list[str] = []

    def _delivery_report(self, error: Any, _message: Any) -> None:
        if error is not None:
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
                self.producer.poll(1)

    def publish(self, path: Path, sha256: str, size: int) -> None:
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
            "username": os.environ.get("USERNAME", ""),
            "detected_at": datetime.now(timezone.utc).isoformat(),
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
        if (bytes_read != size or final_stat.st_size != initial_stat.st_size
                or final_stat.st_mtime_ns != initial_stat.st_mtime_ns):
            raise OSError(f"Sample changed while publishing: {path}")
        if self.producer.flush(60):
            raise TimeoutError("Timed out waiting for Kafka chunk delivery")
        if self._delivery_errors:
            raise RuntimeError(
                "Kafka delivery failed: " + "; ".join(self._delivery_errors)
            )
        self._produce(key, {
            "event": "sample_complete",
            "sha256": sha256,
            "chunk_total": chunk_total,
        })
        if self.producer.flush(60):
            raise TimeoutError("Timed out waiting for Kafka completion marker")
        if self._delivery_errors:
            raise RuntimeError(
                "Kafka delivery failed: " + "; ".join(self._delivery_errors)
            )


class EndpointAgent:
    def __init__(
        self,
        config: dict[str, Any],
        producer: Any,
        state_path: Path,
        health: AgentHealth | None = None,
    ):
        self.watch_dirs = [expand_path(item) for item in config["watch_dirs"]]
        self.scan_interval = float(config.get("scan_interval_seconds", 5))
        self.stable_seconds = float(config.get("stable_seconds", 2))
        self.publisher = KafkaSamplePublisher(
            producer,
            config["kafka"]["topic"],
            config.get("chunk_bytes", MAX_CHUNK_BYTES),
        )
        self.state = SampleState(state_path)
        self.health = health

    def close(self) -> None:
        self.state.close()

    def _stable_snapshot(self, path: Path) -> tuple[int, int] | None:
        try:
            before = path.stat()
            if self.stable_seconds:
                time.sleep(self.stable_seconds)
            after = path.stat()
        except OSError:
            return None
        if (not path.is_file() or path.is_symlink()
                or before.st_size != after.st_size
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

    def _files(self):
        for root in self.watch_dirs:
            if not root.is_dir():
                LOG.warning("Watch directory is unavailable: %s", root)
                continue
            for current, dirs, names in os.walk(root, followlinks=False):
                dirs[:] = [
                    name for name in dirs
                    if not (Path(current) / name).is_symlink()
                ]
                for name in names:
                    yield Path(current) / name

    def scan_once(self) -> None:
        started = time.monotonic()
        if self.health is not None:
            self.health.scan_started()
        for path in self._files():
            if not is_pe_file(path):
                continue
            snapshot = self._stable_snapshot(path)
            if snapshot is None:
                continue
            size, mtime_ns = snapshot
            try:
                sha256 = self._sha256(path)
                current = path.stat()
                if current.st_size != size or current.st_mtime_ns != mtime_ns:
                    LOG.info("File changed during inspection; will retry: %s", path)
                    continue
                if self.state.contains(sha256):
                    continue
                self.publisher.publish(path, sha256, size)
                self.state.mark_sent(sha256)
                record_detection(path, sha256, size, self.publisher.topic)
                if self.health is not None:
                    self.health.sample_published(path.name, sha256, size)
                LOG.info("Published PE sample %s (%s bytes, sha256=%s)",
                         path.name, size, sha256)
            except (OSError, RuntimeError, TimeoutError) as exc:
                LOG.error("Could not publish %s: %s", path, exc)
                if self.health is not None:
                    if isinstance(exc, (RuntimeError, TimeoutError)):
                        # Kafka delivery problems are what make the heartbeat
                        # degraded; a locked file is not a broker failure.
                        self.health.publish_failed(str(exc))
                    else:
                        self.health.record_error(str(exc))
        if self.health is not None:
            self.health.scan_finished(time.monotonic() - started)

    def run(
        self,
        once: bool = False,
        stop_event: threading.Event | None = None,
    ) -> None:
        LOG.info("Monitoring %s; Kafka topic %s",
                 ", ".join(str(path) for path in self.watch_dirs),
                 self.publisher.topic)
        if self.health is not None:
            self.health.set_state("running")
        while True:
            if stop_event is not None and stop_event.is_set():
                return
            self.scan_once()
            if once:
                return
            if stop_event is None:
                time.sleep(self.scan_interval)
            elif stop_event.wait(self.scan_interval):
                return


def _configure_bootstrap_logging(
    path: Path | None = None,
) -> Path:
    """Log before the config is read, so a bad config is never silent.

    A Windows service has no console. Without this, a failure in
    ``load_config()`` reached the SCM as a bare 1067 and nothing was written
    anywhere - which is exactly the kind of failure the installer log has to
    be able to explain. The service inherits ``DAORCS_LOG_DIR`` from the
    installer, so this early log lands in AppData with the rest.
    """
    if path is None:
        path = default_log_dir() / "service.log"
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
    except OSError:
        path = Path(os.environ.get("TEMP", r"C:\Windows\Temp")) / "daorcs-agent.log"
        path.parent.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        handlers=[
            RotatingFileHandler(
                path, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8"
            )
        ],
        force=True,
    )
    return path


def detections_path(config: dict[str, Any]) -> Path:
    """Return the detections log path.

    Defaults to ``detections.log`` next to ``agent.log`` so captures never
    share the runtime log file.
    """
    configured = config.get("detections_file")
    if isinstance(configured, str) and configured.strip():
        return expand_path(configured)
    log_path = config.get("log_file")
    if isinstance(log_path, str) and log_path.strip():
        return expand_path(log_path).parent / "detections.log"
    return default_log_dir() / "detections.log"


def _configure_detections_logging(config: dict[str, Any]) -> None:
    """Send detection records to their own rotating file.

    The logger does not propagate, so ``detections.log`` holds exactly one JSON
    object per captured sample and ``agent.log`` stays free of them.
    """
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
    """Append one JSON Lines record for a sample captured from the endpoint."""
    record = {
        "detected_at": datetime.now(timezone.utc).isoformat(),
        "event": "sample_detected",
        "file_name": path.name,
        "file_path": str(path),
        "file_size": size,
        "sha256": sha256,
        "host": platform.node(),
        "username": os.environ.get("USERNAME", ""),
        "kafka_topic": topic,
        "agent_version": VERSION,
    }
    DETECTIONS.info(json.dumps(record, separators=(",", ":")))


def _tail_jsonl(path: Path, limit: int) -> list[dict[str, Any]]:
    """Return the last ``limit`` JSON objects from a JSON Lines file.

    Reads backwards in blocks so a 5 MB detections log never has to be loaded
    whole just to show the newest records.
    """
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


def _make_api_handler(
    health: AgentHealth,
    detections_file: Path,
    max_limit: int = 500,
):
    """Build the request handler with the agent state closed over."""

    class AgentRequestHandler(http.server.BaseHTTPRequestHandler):
        server_version = f"DaOrcsAgent/{VERSION}"
        sys_version = ""

        def do_GET(self) -> None:  # noqa: N802 - http.server API
            parsed = urlparse(self.path)
            path = parsed.path.rstrip("/") or "/"

            if path in ("/health", "/api/v1/ping"):
                self._json(200, {
                    "status": "ok",
                    "service": "DaOrcsEndpointAgent",
                    "version": VERSION,
                    "host": platform.node(),
                    "time": _utc_now(),
                })
                return

            if path in ("/api/v1/health", "/api/v1/heartbeat", "/api/v1/agent"):
                self._json(200, health.snapshot())
                return

            if path == "/api/v1/detections":
                try:
                    limit = int(parse_qs(parsed.query).get("limit", ["20"])[0])
                except ValueError:
                    limit = 20
                limit = max(1, min(limit, max_limit))
                records = _tail_jsonl(detections_file, limit)
                self._json(200, {
                    "file": str(detections_file),
                    "count": len(records),
                    "detections": records,
                })
                return

            self._json(404, {
                "error": "not found",
                "endpoints": [
                    "GET /health",
                    "GET /api/v1/health",
                    "GET /api/v1/detections?limit=20",
                ],
            })

        def do_POST(self) -> None:  # noqa: N802 - http.server API
            self._json(405, {"error": "method not allowed",
                             "detail": "this API is read-only (GET)"})

        def _json(self, code: int, payload: dict[str, Any]) -> None:
            body = json.dumps(payload, separators=(",", ":"),
                              default=str).encode("utf-8")
            try:
                self.send_response(code)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def log_message(self, fmt: str, *args: Any) -> None:
            LOG.debug("API %s - %s", self.address_string(), fmt % args)

    return AgentRequestHandler


class AgentApiServer:
    """Read-only heartbeat HTTP server running inside the agent process."""

    def __init__(self, health: AgentHealth, config: dict[str, Any]):
        api = config.get("api") or {}
        self.health = health
        self.host = str(api.get("host") or DEFAULT_API_HOST)
        self.port = int(api.get("port") or DEFAULT_API_PORT)
        self.detections_file = detections_path(config)
        self._server: http.server.ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    @staticmethod
    def _is_loopback(host: str) -> bool:
        if host.strip().lower() in ("localhost", "::1"):
            return True
        try:
            return ipaddress.ip_address(host).is_loopback
        except ValueError:
            return False

    def start(self) -> bool:
        """Start serving; a failure is logged and never stops the scan loop."""
        if not self._is_loopback(self.host):
            # The API is read-only and unauthenticated, so a widened bind is a
            # decision the operator made knowingly. Say it once in the log so the
            # posture is discoverable without reading agent.json.
            LOG.warning(
                "Agent API is unauthenticated and listening beyond loopback (%s). "
                "Restrict port %s to the panel's subnet with a firewall rule.",
                self.host, self.port,
            )
        try:
            server = http.server.ThreadingHTTPServer(
                (self.host, self.port),
                _make_api_handler(self.health, self.detections_file),
            )
        except OSError as exc:
            LOG.error("Agent API could not bind %s:%s: %s",
                      self.host, self.port, exc)
            return False
        server.daemon_threads = True
        self._server = server
        self._thread = threading.Thread(
            target=server.serve_forever, name="daorcs-agent-api", daemon=True
        )
        self._thread.start()
        LOG.info("Agent API listening on http://%s:%s (read-only, no auth)",
                 self.host, self.port)
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


def _run_agent(
    config_path: Path,
    stop_event: threading.Event | None = None,
    once: bool = False,
    service: bool = False,
) -> int:
    LOG.info("DaOrcs endpoint agent %s starting (config %s)", VERSION, config_path)
    config = load_config(config_path)
    _configure_logging(config)
    LOG.info("Configuration loaded from %s", config_path)
    from confluent_kafka import Producer

    kafka_settings = dict(config["kafka"].get("producer_config", {}))
    kafka_settings["bootstrap.servers"] = config["kafka"]["bootstrap_servers"]
    kafka_settings.setdefault("client.id", f"daorcs-endpoint-agent-{platform.node()}")
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
        producer.flush(60)
        agent.close()
    return 0


def _self_test(config_path: Path, produce_test: bool = False) -> int:
    """Validate the install and report whether the broker answers.

    Exit codes are part of the installer contract:

    * ``0`` - config, imports and broker metadata are all good;
    * ``1`` - the install itself is broken (missing config, bad JSON, missing
      runtime DLL) and the service must not be installed;
    * ``2`` - the install is good but the broker is unreachable/refusing. That
      is a warning: the agent retries on every scan, and a broker that is not
      running yet is a normal setup state.
    """
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

    for raw in config["watch_dirs"]:
        path = expand_path(raw)
        if path.is_dir():
            print(f"OK   watch directory: {path}")
        else:
            print(f"WARN watch directory does not exist yet: {path}")

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
    except Exception as exc:  # noqa: BLE001 - DLL load errors are not ImportError
        print(f"FAIL confluent-kafka runtime: {exc}")
        LOG.exception("confluent-kafka runtime check failed")
        return 1
    print(f"OK   confluent-kafka {confluent_kafka.version()[0]} "
          f"(librdkafka {confluent_kafka.libversion()[0]})")

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
        # Producer construction is also the check that the native librdkafka
        # DLLs bundled by PyInstaller can actually be loaded.
        producer = Producer(kafka_settings)
        admin = AdminClient(kafka_settings)
        metadata = admin.list_topics(timeout=6)
    except Exception as exc:  # noqa: BLE001 - KafkaException and friends
        print(f"WARN broker is not reachable: {exc}")
        print("     The agent will keep retrying. Start the broker, then rerun")
        print("     this check or restart the DaOrcsEndpointAgent service.")
        print("FAIL connection test (broker offline)")
        return 2

    broker_ids = sorted(metadata.brokers.keys())
    print(f"OK   broker answered: {len(broker_ids)} broker(s) "
          f"(id {', '.join(str(item) for item in broker_ids)})")
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
                    "checked_at": datetime.now(timezone.utc).isoformat(),
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
    LOG.info("DaOrcs endpoint agent %s service mode starting; log=%s",
             VERSION, log_path)
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
            except Exception as exc:  # noqa: BLE001 - must reach the log
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
        except Exception as exc:  # noqa: BLE001 - must reach the log
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
