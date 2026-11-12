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
    EndpointAgent,
    KafkaSamplePublisher,
    SampleState,
    _pe_sections,
    digest_section,
    is_pe_file,
    load_config,
)


def _pe_bytes(payload: bytes = b"sample") -> bytes:
    header = bytearray(0x84)
    header[:2] = b"MZ"
    header[0x3C:0x40] = (0x80).to_bytes(4, "little")
    header[0x80:0x84] = b"PE\0\0"
    return bytes(header) + payload


def _pe_with_section(payload: bytes) -> bytes:
    """A minimal PE with one .text section, so the table walk can be checked."""
    pe_offset = 0x40
    section_table = pe_offset + 24          # SizeOfOptionalHeader = 0
    raw_offset = section_table + 40
    image = bytearray(raw_offset) + bytearray(payload)
    image[:2] = b"MZ"
    image[0x3C:0x40] = pe_offset.to_bytes(4, "little")
    image[pe_offset:pe_offset + 4] = b"PE\0\0"
    image[pe_offset + 6:pe_offset + 8] = (1).to_bytes(2, "little")
    entry = section_table
    image[entry:entry + 5] = b".text"
    image[entry + 16:entry + 20] = len(payload).to_bytes(4, "little")
    image[entry + 20:entry + 24] = raw_offset.to_bytes(4, "little")
    return bytes(image)


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


def test_section_digests_are_sha256_of_each_sections_bytes(tmp_path):
    executable = tmp_path / "sample.exe"
    executable.write_bytes(_pe_with_section(b"section payload"))

    assert _pe_sections(executable) == [
        (".text", hashlib.sha256(b"section payload").hexdigest())
    ]


def test_digest_section_accepts_bytes_and_rejects_empty_input():
    assert digest_section(b"abc") == hashlib.sha256(b"abc").hexdigest()
    assert digest_section("") == ""
    assert digest_section(b"") == ""


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
