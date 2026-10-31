"""The PE half of the sample factory's post-compile options, and the inspector.

`strip_iat` is the only code in the tree that edits a PE header, and it does so
for a deliberately destructive reason: a zeroed import directory is bait for
the static passes, not a runnable sample. These tests pin the exact offsets it
touches (PE32 and PE32+) and every refusal, because a header edited at the
wrong offset is a corrupted artefact with a confident success message.

The second half is `hardening()` - the read-only inspector the build-check
panel uses to answer "does this binary actually carry the protections the
settings asked for?". It shares the layout parser with the stripper on
purpose, so the two cannot disagree about where the optional header is; what
it needs pinning is that the three DllCharacteristics bits are read at the
offset Windows reads them, and that the canary scan cannot miss a marker
because of how the file was chunked.
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "python"))

from panel import pe_tools  # noqa: E402


def pe_image(*, magic=0x10B, import_entry=(0x1000, 0x28),
             iat_entry=(0x2000, 0x10), directory_count=16,
             optional_size=240, dll_characteristics=0,
             trailing=b"") -> bytes:
    data = bytearray(0x400)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    coff = 0x84
    struct.pack_into("<H", data, coff, 0x8664 if magic == 0x20B else 0x14C)
    struct.pack_into("<H", data, coff + 2, 3)
    struct.pack_into("<H", data, coff + 16, optional_size)
    opt = coff + 20
    struct.pack_into("<H", data, opt, magic)
    # DllCharacteristics sits at the same offset in both formats - 70 bytes
    # into the optional header - which is the fact the inspector's whole
    # reading of the word depends on.
    struct.pack_into("<H", data, opt + 70, dll_characteristics)
    if magic == 0x10B:
        count_offset, directory = opt + 92, opt + 96
    else:
        count_offset, directory = opt + 108, opt + 112
    struct.pack_into("<I", data, count_offset, directory_count)
    struct.pack_into("<II", data, directory + 1 * 8, *import_entry)
    struct.pack_into("<II", data, directory + 12 * 8, *iat_entry)
    return bytes(data) + trailing


def entry(data: bytes, index: int, *, magic=0x10B) -> tuple[int, int]:
    opt = 0x84 + 20
    directory = opt + (96 if magic == 0x10B else 112)
    off = directory + index * 8
    return struct.unpack_from("<II", data, off)


@pytest.mark.parametrize("magic", [0x10B, 0x20B])
def test_both_pe_formats_have_their_import_and_iat_zeroed(tmp_path, magic):
    path = tmp_path / "sample.exe"
    path.write_bytes(pe_image(magic=magic))

    result = pe_tools.strip_iat(path)

    assert result == {"ok": True, "zeroed": ["import", "IAT"],
                      "already": False, "format": "PE32" if magic == 0x10B
                      else "PE32+", "sections": 3}
    data = path.read_bytes()
    assert entry(data, 1, magic=magic) == (0, 0)
    assert entry(data, 12, magic=magic) == (0, 0)
    # Only the two directory entries move: the file is not resized.
    assert len(data) == len(pe_image(magic=magic))


def test_a_second_pass_reports_that_nothing_moved(tmp_path):
    path = tmp_path / "sample.exe"
    path.write_bytes(pe_image())
    pe_tools.strip_iat(path)

    result = pe_tools.strip_iat(path)

    assert result["ok"] is True
    assert result["already"] is True
    assert result["zeroed"] == []


def test_other_directories_are_left_alone(tmp_path):
    image = bytearray(pe_image())
    path = tmp_path / "sample.exe"
    path.write_bytes(image)
    opt = 0x84 + 20
    directory = opt + 96
    # entry 0 (exports) and entry 5 (relocations) must survive.
    struct.pack_into("<II", image, directory + 0 * 8, 0x3000, 0x20)
    struct.pack_into("<II", image, directory + 5 * 8, 0x4000, 0x30)
    path.write_bytes(image)

    pe_tools.strip_iat(path)

    data = path.read_bytes()
    assert entry(data, 0) == (0x3000, 0x20)
    assert entry(data, 5) == (0x4000, 0x30)


def test_a_directory_that_declares_too_few_entries_is_skipped(tmp_path):
    path = tmp_path / "sample.exe"
    path.write_bytes(pe_image(directory_count=1))

    result = pe_tools.strip_iat(path)

    assert result["zeroed"] == []
    assert result["already"] is True
    assert entry(path.read_bytes(), 1) == (0x1000, 0x28)


def test_non_pe_inputs_are_sentences_not_traces(tmp_path):
    cases = {
        "not-mz.exe": b"hello",
        "no-signature.exe": b"MZ" + b"\0" * 200,
        "short.exe": b"MZ",
    }
    for name, body in cases.items():
        path = tmp_path / name
        path.write_bytes(body)
        with pytest.raises(ValueError):
            pe_tools.strip_iat(path)

    bad_magic = bytearray(pe_image())
    struct.pack_into("<H", bad_magic, 0x84 + 20, 0x123)
    path = tmp_path / "bad-magic.exe"
    path.write_bytes(bad_magic)
    with pytest.raises(ValueError, match="magic"):
        pe_tools.strip_iat(path)

    truncated = tmp_path / "truncated.exe"
    truncated.write_bytes(pe_image()[:0x98])
    with pytest.raises(ValueError, match="optional header"):
        pe_tools.strip_iat(truncated)


def test_no_temporary_file_survives_a_successful_strip(tmp_path):
    path = tmp_path / "sample.exe"
    path.write_bytes(pe_image())

    pe_tools.strip_iat(path)

    assert sorted(p.name for p in tmp_path.iterdir()) == ["sample.exe"]


class TestHardeningInspection:
    """`hardening()`: what the finished binary actually carries.

    The build-check panel compares this against config/hardening.json, so a
    wrong answer here is a report that certifies a binary the settings do not
    describe. The three header bits are pinned at the offset Windows reads
    them (the same one in PE32 and PE32+); the canary is pinned against the
    failure its chunked scan was written to prevent.
    """

    @pytest.mark.parametrize("magic", [0x10B, 0x20B])
    def test_the_three_bits_are_read_from_either_format(self, tmp_path, magic):
        path = tmp_path / "sample.exe"
        # 0x0160 = HIGH_ENTROPY_VA | DYNAMIC_BASE | NX_COMPAT
        path.write_bytes(pe_image(magic=magic, dll_characteristics=0x0160))

        got = pe_tools.hardening(path)

        assert got["format"] == ("PE32" if magic == 0x10B else "PE32+")
        assert got["dll_characteristics"] == 0x0160
        assert got["aslr"] is True
        assert got["high_entropy_va"] is True
        assert got["dep_nx"] is True

    def test_a_binary_with_no_protection_reports_every_bit_clear(self, tmp_path):
        path = tmp_path / "sample.exe"
        path.write_bytes(pe_image())

        got = pe_tools.hardening(path)

        assert got["dll_characteristics"] == 0
        assert got["aslr"] is False
        assert got["high_entropy_va"] is False
        assert got["dep_nx"] is False
        assert got["stack_protector"] is False

    def test_the_canary_runtime_is_found_when_it_is_linked_in(self, tmp_path):
        path = tmp_path / "sample.exe"
        path.write_bytes(pe_image(trailing=b"\x00__stack_chk_fail\x00"))

        got = pe_tools.hardening(path)

        assert got["stack_protector"] is True
        # The evidence string is the point: it says HOW the answer was
        # determined, because the canary is an inference and the header bits
        # are not.
        assert "present" in got["stack_protector_evidence"]

    def test_either_canary_symbol_is_enough(self, tmp_path):
        # A protected function references the cookie and the abort; a vendored
        # object can pull in either spelling, so either is evidence.
        path = tmp_path / "sample.exe"
        path.write_bytes(pe_image(trailing=b"xx__stack_chk_guard\x00"))
        assert pe_tools.hardening(path)["stack_protector"] is True

    def test_a_binary_without_the_canary_says_so(self, tmp_path):
        path = tmp_path / "sample.exe"
        path.write_bytes(pe_image())

        got = pe_tools.hardening(path)

        assert got["stack_protector"] is False
        assert "no canary" in got["stack_protector_evidence"]

    def test_a_marker_straddling_a_chunk_boundary_is_still_found(self, tmp_path, monkeypatch):
        # The scan reads the file in chunks, and the analyzer is ~196 MB - so
        # this is not theoretical. With a tiny chunk the marker begins in one
        # chunk and ends in the next; a naive scan would report a protected
        # binary as unprotected, and the panel would tell the operator to
        # rebuild for a protection that is already there.
        monkeypatch.setattr(pe_tools, "_SCAN_CHUNK", 8)
        path = tmp_path / "sample.exe"
        path.write_bytes(pe_image(trailing=b"xxxx__stack_chk_guard"))

        assert pe_tools.hardening(path)["stack_protector"] is True

    def test_a_non_pe_is_a_sentence_not_a_trace(self, tmp_path):
        path = tmp_path / "sample.exe"
        path.write_bytes(b"hello")

        with pytest.raises(ValueError, match="MZ"):
            pe_tools.hardening(path)


class TestPackVerdict:
    """The run gate's packed detector: offline, cheap, and never executing the
    file. UPX markers are a fact; the entropy path is the same threshold the
    analyzer's own tripwire stops a run at, so the two cannot disagree."""

    def test_upx_markers_in_the_file_read_as_packed_upx(self, tmp_path):
        path = tmp_path / "packed.exe"
        path.write_bytes(b"MZ" + b"\0" * 100 + b"UPX0" + b"\0" * 100 + b"UPX1")

        got = pe_tools.pack_verdict(path)

        assert got["packed"] is True
        assert got["method"] == "upx"
        assert "UPX0" in got["evidence"] and "UPX1" in got["evidence"]

    def test_a_marker_straddling_a_chunk_boundary_is_still_found(
            self, tmp_path, monkeypatch):
        # Same straddle discipline as the canary scan, asserted the same way:
        # with a tiny chunk the marker spans two reads, and a naive scan would
        # let a packed sample through the gate.
        monkeypatch.setattr(pe_tools, "_SCAN_CHUNK", 8)
        path = tmp_path / "packed.exe"
        path.write_bytes(b"MZ" + b"\0" * 20 + b"xxUPX2" + b"\0" * 20)

        assert pe_tools.pack_verdict(path)["method"] == "upx"

    def test_high_entropy_reads_as_packed_by_entropy(self, tmp_path):
        import os
        path = tmp_path / "random.exe"
        path.write_bytes(os.urandom(1 << 16))

        got = pe_tools.pack_verdict(path)

        assert got["packed"] is True
        assert got["method"] == "entropy"
        assert got["entropy"] >= pe_tools.ENTROPY_PACKED

    def test_plain_low_entropy_bytes_are_clean(self, tmp_path):
        path = tmp_path / "plain.exe"
        path.write_bytes(b"MZ" * 512)

        got = pe_tools.pack_verdict(path)

        assert got["packed"] is False
        assert got["method"] is None

    def test_an_empty_file_is_clean_not_an_error(self, tmp_path):
        path = tmp_path / "empty.exe"
        path.write_bytes(b"")

        got = pe_tools.pack_verdict(path)

        assert got["packed"] is False
        assert "error" not in got

    def test_an_unreadable_file_reports_the_read_error_not_a_verdict(
            self, tmp_path):
        got = pe_tools.pack_verdict(tmp_path / "nope.exe")

        assert got["packed"] is False
        assert "could not be read" in got["error"]
