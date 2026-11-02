"""Watch configured folders for PE files and publish them to Kafka in chunks."""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import platform
import sqlite3
import sys
import threading
import time
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any

VERSION = "0.1.0"
DEFAULT_CONFIG = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / (
    Path("DaOrcs") / "Agent" / "agent.json"
)
DEFAULT_STATE = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / (
    Path("DaOrcs") / "Agent" / "state.sqlite3"
)
MAX_CHUNK_BYTES = 256 * 1024
PE_SIGNATURE = b"PE\0\0"
LOG = logging.getLogger("ia_endpoint_agent")


def is_pe_file(path: Path) -> bool:
    """Return true for a file with a valid DOS header and PE signature."""
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
            return sample.read(4) == PE_SIGNATURE
    except OSError:
        LOG.debug("Cannot inspect %s", path, exc_info=True)
        return False


def load_config(path: Path) -> dict[str, Any]:
    try:
        config = json.loads(path.read_text(encoding="utf-8"))
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
    return config


def expand_path(value: str) -> Path:
    return Path(os.path.expandvars(os.path.expanduser(value))).resolve()


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
    def __init__(self, config: dict[str, Any], producer: Any, state_path: Path):
        self.watch_dirs = [expand_path(item) for item in config["watch_dirs"]]
        self.scan_interval = float(config.get("scan_interval_seconds", 5))
        self.stable_seconds = float(config.get("stable_seconds", 2))
        self.publisher = KafkaSamplePublisher(
            producer,
            config["kafka"]["topic"],
            config.get("chunk_bytes", MAX_CHUNK_BYTES),
        )
        self.state = SampleState(state_path)

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
                LOG.info("Published PE sample %s (%s bytes, sha256=%s)",
                         path.name, size, sha256)
            except (OSError, RuntimeError, TimeoutError) as exc:
                LOG.error("Could not publish %s: %s", path, exc)

    def run(
        self,
        once: bool = False,
        stop_event: threading.Event | None = None,
    ) -> None:
        LOG.info("Monitoring %s; Kafka topic %s",
                 ", ".join(str(path) for path in self.watch_dirs),
                 self.publisher.topic)
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


def _run_agent(
    config_path: Path,
    stop_event: threading.Event | None = None,
    once: bool = False,
) -> int:
    config = load_config(config_path)
    _configure_logging(config)
    from confluent_kafka import Producer

    kafka_settings = dict(config["kafka"].get("producer_config", {}))
    kafka_settings["bootstrap.servers"] = config["kafka"]["bootstrap_servers"]
    kafka_settings.setdefault("client.id", f"daorcs-endpoint-agent-{platform.node()}")
    kafka_settings.setdefault("enable.idempotence", True)
    producer = Producer(kafka_settings)
    state_path = expand_path(config.get("state_file", str(DEFAULT_STATE)))
    agent = EndpointAgent(config, producer, state_path)
    try:
        agent.run(once=once, stop_event=stop_event)
    finally:
        producer.flush(60)
        agent.close()
    return 0


def _run_windows_service() -> int:
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
                _run_agent(DEFAULT_CONFIG, stop_event=self.stop_event)
            except Exception:
                LOG.exception("Endpoint agent service stopped with an error")
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
        except Exception as exc:
            logging.basicConfig(level=logging.ERROR)
            LOG.exception("Could not run the Windows service: %s", exc)
            return 1

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--once", action="store_true",
                        help="scan once and exit; useful for VM validation")
    args = parser.parse_args(raw_argv)
    try:
        return _run_agent(args.config, once=args.once)
    except KeyboardInterrupt:
        LOG.info("Stopping endpoint agent")
        return 0
    except (ValueError, ImportError, OSError, RuntimeError) as exc:
        logging.basicConfig(level=logging.ERROR)
        LOG.error("%s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
