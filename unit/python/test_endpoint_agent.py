from __future__ import annotations

import hashlib
import json
import sys
import threading
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "agent"))

from endpoint_agent import (  # noqa: E402
    AgentHealth,
    EndpointAgent,
    KafkaSamplePublisher,
    SampleState,
    build_flask_app,
    is_pe_file,
    load_config,
)


def _pe_image(payload: bytes, section_name: bytes | None = None) -> bytes:
    """A minimal but LIEF-parseable PE: DOS header, COFF header, PE32
    optional header (0xe0), one section-table entry, then the payload.

    LIEF 1.x refuses the barebones MZ/PE image the old fixtures used
    ("SizeOfOptionalHeader seems invalid"), so the optional header is real.
    """
    pe_offset = 0x80
    optional_size = 0xE0
    coff = pe_offset + 4                 # after the PE\0\0 signature
    optional = coff + 20                 # after the COFF header
    sections = optional + optional_size  # section table
    raw_offset = sections + 40           # one 40-byte section entry
    image = bytearray(raw_offset)
    image[:2] = b"MZ"
    image[0x3C:0x40] = pe_offset.to_bytes(4, "little")
    image[pe_offset:pe_offset + 4] = b"PE\0\0"
    # COFF: i386, one section, optional header present, executable image.
    image[coff:coff + 2] = (0x014C).to_bytes(2, "little")
    image[coff + 2:coff + 4] = (1).to_bytes(2, "little")
    image[coff + 16:coff + 18] = optional_size.to_bytes(2, "little")
    image[coff + 18:coff + 20] = (0x0102).to_bytes(2, "little")
    # Optional header magic 0x010B = PE32; the zeros after it parse fine.
    image[optional:optional + 2] = (0x010B).to_bytes(2, "little")
    if section_name is not None:
        image[sections:sections + 8] = section_name.ljust(8, b"\0")
    image[sections + 16:sections + 20] = len(payload).to_bytes(4, "little")
    image[sections + 20:sections + 24] = raw_offset.to_bytes(4, "little")
    return bytes(image) + payload


def _pe_bytes(payload: bytes = b"sample") -> bytes:
    return _pe_image(payload)


def _pe_with_section(payload: bytes) -> bytes:
    """The same image with a named .text section covering the payload."""
    return _pe_image(payload, b".text")


class FakeProducer:
    def __init__(self):
        self.messages = []

    def produce(self, topic, key, value, callback):
        self.messages.append((topic, key, json.loads(value)))
        callback(None, None)

    def poll(self, _timeout):
        return 0

    def flush(self, _timeout):
        return 0


def test_detects_pe_signature_not_extension(tmp_path):
    executable = tmp_path / "not-named-exe.dat"
    executable.write_bytes(_pe_bytes())
    text = tmp_path / "fake.exe"
    text.write_bytes(b"not an executable")

    assert is_pe_file(executable)
    assert not is_pe_file(text)


def test_detects_a_pe_from_its_section_table(tmp_path):
    executable = tmp_path / "sample.exe"
    executable.write_bytes(_pe_with_section(b"section payload"))

    assert is_pe_file(executable)


def test_is_pe_file_rejects_missing_and_empty_files(tmp_path):
    assert not is_pe_file(tmp_path / "missing.exe")
    empty = tmp_path / "empty.exe"
    empty.write_bytes(b"")
    assert not is_pe_file(empty)
    assert not is_pe_file(tmp_path)


def test_publisher_sends_ordered_bounded_chunks_and_completion(tmp_path):
    sample = tmp_path / "sample.exe"
    sample.write_bytes(_pe_bytes(b"x" * 100))
    producer = FakeProducer()
    publisher = KafkaSamplePublisher(producer, "analysis-artifacts", 64)
    publisher.publish(sample, "a" * 64, sample.stat().st_size)

    events = [entry[2]["event"] for entry in producer.messages]
    assert events[0] == "sample_start"
    assert events[-1] == "sample_complete"
    chunks = [entry[2] for entry in producer.messages if entry[2]["event"] == "sample_chunk"]
    assert [chunk["chunk_num"] for chunk in chunks] == list(range(len(chunks)))
    assert all(len(bytes.fromhex(chunk["chunk_data"])) <= 64 for chunk in chunks)
    assert all(entry[1] == b"a" * 64 for entry in producer.messages)


def test_agent_scans_valid_pe_once_and_persists_sent_hash(tmp_path):
    watch = tmp_path / "watch"
    watch.mkdir()
    (watch / "sample.exe").write_bytes(_pe_bytes())
    producer = FakeProducer()
    agent = EndpointAgent(
        {
            "watch_dirs": [str(watch)],
            "stable_seconds": 0,
            "chunk_bytes": 128,
            "kafka": {"topic": "analysis-artifacts"},
        },
        producer,
        tmp_path / "state.sqlite3",
    )
    try:
        agent.scan_once()
        first_count = len(producer.messages)
        agent.scan_once()
        assert first_count > 0
        assert len(producer.messages) == first_count
    finally:
        agent.close()

    state = SampleState(tmp_path / "state.sqlite3")
    try:
        digest = hashlib.sha256((watch / "sample.exe").read_bytes()).hexdigest()
        assert state.contains(digest)
    finally:
        state.close()


def test_agent_stops_without_an_extra_scan_when_service_stop_is_requested(tmp_path):
    watch = tmp_path / "watch"
    watch.mkdir()
    (watch / "sample.exe").write_bytes(_pe_bytes())
    producer = FakeProducer()
    agent = EndpointAgent(
        {
            "watch_dirs": [str(watch)],
            "stable_seconds": 0,
            "kafka": {"topic": "analysis-artifacts"},
        },
        producer,
        tmp_path / "state.sqlite3",
    )
    stop_event = threading.Event()
    stop_event.set()
    try:
        agent.run(stop_event=stop_event)
        assert producer.messages == []
    finally:
        agent.close()


# --- scan pause / resume (POST /api/v1/control) -------------------------------

def _health(tmp_path):
    config = {
        "watch_dirs": [str(tmp_path)],
        "kafka": {"bootstrap_servers": "127.0.0.1:9092", "topic": "samples"},
    }
    return AgentHealth(config, tmp_path / "agent.json")


def test_pause_is_reported_in_the_heartbeat(tmp_path):
    health = _health(tmp_path)
    assert health.is_paused() is False
    assert health.snapshot()["agent"]["scan_paused"] is False
    health.pause_scans()
    assert health.is_paused() is True
    assert health.snapshot()["agent"]["scan_paused"] is True
    health.resume_scans()
    assert health.is_paused() is False
    assert health.snapshot()["agent"]["scan_paused"] is False


def test_pause_barrier_parks_until_resume(tmp_path):
    """The barrier must actually block the scan loop while paused, and let go
    when the panel sends start - the Start agent button depends on it."""
    health = _health(tmp_path)
    released = threading.Event()

    def barrier():
        health.pause_barrier()
        released.set()

    health.pause_scans()
    worker = threading.Thread(target=barrier, name="test-barrier")
    worker.start()
    assert not released.wait(0.3), "barrier returned while scans were paused"
    health.resume_scans()
    assert released.wait(5.0), "barrier never returned after resume"
    worker.join(5)
    assert health.snapshot()["agent"]["state"] == "running"


def test_pause_barrier_respects_stop_even_while_paused(tmp_path):
    """A stopping service must not hang in the barrier - SCM stop wins."""
    health = _health(tmp_path)
    health.pause_scans()
    stop_event = threading.Event()
    stop_event.set()
    health.pause_barrier(stop_event)  # returns, does not block
    # The pause request survives the stop: the next process decides.
    assert health.is_paused() is True


def test_control_endpoint_pauses_and_resumes(tmp_path):
    """POST /api/v1/control drives the pause switch the heartbeat reports."""
    health = _health(tmp_path)
    app = build_flask_app(health, tmp_path / "detections.log")
    client = app.test_client()

    stopped = client.post("/api/v1/control", json={"action": "stop"})
    assert stopped.status_code == 200
    assert stopped.get_json() == {
        "ok": True, "action": "stop", "scan_paused": True}
    assert health.snapshot()["agent"]["scan_paused"] is True

    started = client.post("/api/v1/control", json={"action": "start"})
    assert started.status_code == 200
    assert started.get_json()["scan_paused"] is False
    assert health.snapshot()["agent"]["scan_paused"] is False


def test_control_endpoint_rejects_unknown_actions(tmp_path):
    health = _health(tmp_path)
    app = build_flask_app(health, tmp_path / "detections.log")
    client = app.test_client()
    for payload in ({"action": "restart"}, {}, {"action": "  "}):
        response = client.post("/api/v1/control", json=payload)
        assert response.status_code == 400
        assert "unknown action" in response.get_json()["error"]
    # A wrong action must not have touched the switch.
    assert health.is_paused() is False


def test_config_rejects_chunk_sizes_that_exceed_safe_message_budget(tmp_path):
    config = {
        "watch_dirs": [str(tmp_path)],
        "kafka": {"bootstrap_servers": "127.0.0.1:9092", "topic": "samples"},
        "chunk_bytes": 256 * 1024 + 1,
    }
    config_path = tmp_path / "agent.json"
    config_path.write_text(json.dumps(config), encoding="utf-8")

    with pytest.raises(ValueError, match="chunk_bytes"):
        load_config(config_path)
