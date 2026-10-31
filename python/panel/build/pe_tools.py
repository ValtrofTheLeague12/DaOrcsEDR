"""Two post-compile transformations the sample factory offers, plus the
offline packed-ness verdict the pipeline-run gate enforces.

Both exist because the analyzer's PE and import passes need bait that a plain
gcc.exe cannot produce: a packed binary (UPX) and a binary whose import
directory has been zeroed. UPX is an external tool in upx/; this module is the
small, auditable part that touches the PE header for the second one, and -
at the bottom - reads a file to say whether it is packed, without ever
executing it.

Stripping the import directory is DESTRUCTIVE BY DESIGN. Windows resolves a
process's imports before any of its code runs; with the IMPORT directory entry
zeroed there is nothing to resolve, so the file will not start. It is a static
artefact - something for the parser and the YARA rules to chew on - not a
sample to run. The factory's answer says that in as many words, because a
checkbox labelled "strip IAT" could otherwise be mistaken for a hardening step.

What is touched is exactly two data-directory entries in the optional header:

    index 1   IMPORT   the import directory
    index 12  IAT      the import address table's directory

Their RVA and size are set to zero. Section contents are left alone: the bytes
are still there for a parser to find, which is the point of the exercise. The
file's checksum is not recomputed; Windows does not require it for images.
"""

from __future__ import annotations

import math
import os
import struct
from pathlib import Path

PE32 = 0x10B
PE32_PLUS = 0x20B

# Data-directory index -> the name the result reports. 1 is the import
# directory; 12 is the IAT copy Windows uses for bound imports.
_ENTRIES = {1: "import", 12: "IAT"}


def _u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def _put_u32(data: bytearray, offset: int, value: int) -> None:
    struct.pack_into("<I", data, offset, value)


def _pe_layout(data: bytes) -> dict:
    """Parse a PE image far enough to reach the optional header.

    Shared by the IAT stripper and the hardening inspector so the two cannot
    disagree about where the optional header is, or about what counts as a
    malformed image. Every refusal is a sentence: both callers turn one into
    text an operator reads.
    """
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise ValueError("the file is not a DOS/PE executable (no MZ header)")

    pe = _u32(data, 0x3C)
    if pe + 24 > len(data) or data[pe:pe + 4] != b"PE\0\0":
        raise ValueError("the file has no PE signature at e_lfanew")

    coff = pe + 4
    sections = _u16(data, coff + 2)
    opt_size = _u16(data, coff + 16)
    opt = coff + 20
    if opt_size < 2 or opt + opt_size > len(data):
        raise ValueError("the optional header is truncated or missing")

    magic = _u16(data, opt)
    if magic == PE32:
        format_name = "PE32"
        count_offset = opt + 92
        directory_offset = opt + 96
    elif magic == PE32_PLUS:
        format_name = "PE32+"
        count_offset = opt + 108
        directory_offset = opt + 112
    else:
        raise ValueError(f"unknown optional-header magic 0x{magic:04x}")

    if count_offset + 4 > opt + opt_size:
        raise ValueError("the optional header is too small for a data directory")
    # A sanity clamp: no real image declares more than 16, and a corrupt count
    # must not walk the zeroing loop outside the header.
    count = min(_u32(data, count_offset), 16)

    return {
        "format": format_name,
        "sections": sections,
        "opt": opt,
        "opt_size": opt_size,
        "directory_offset": directory_offset,
        "directory_count": count,
        # DllCharacteristics sits at the same offset in PE32 and PE32+:
        # 70 bytes past the start of the optional header.
        "dll_characteristics": _u16(data, opt + 70),
    }


def strip_iat(path: Path) -> dict:
    """Zero the import and IAT directory entries of a PE file, in place.

    Returns what was found and zeroed. Raises ValueError with a sentence for
    anything that is not a PE image this parser understands - the caller turns
    that into the Generate refusal, so the wording matters.
    """
    data = bytearray(path.read_bytes())
    layout = _pe_layout(bytes(data))
    format_name = layout["format"]
    sections = layout["sections"]
    directory_offset = layout["directory_offset"]
    count = layout["directory_count"]

    zeroed: list[str] = []
    for index, name in _ENTRIES.items():
        if index >= count:
            continue
        entry = directory_offset + index * 8
        if entry + 8 > layout["opt"] + layout["opt_size"] or entry + 8 > len(data):
            raise ValueError(
                f"the {name} data-directory entry lies outside the optional header")
        rva, size = _u32(data, entry), _u32(data, entry + 4)
        if rva or size:
            _put_u32(data, entry, 0)
            _put_u32(data, entry + 4, 0)
            zeroed.append(name)

    if not zeroed:
        return {"ok": True, "zeroed": [], "already": True, "format": format_name,
                "sections": sections}

    tmp = path.with_name(path.name + ".tmp")
    tmp.write_bytes(bytes(data))
    os.replace(tmp, path)
    return {"ok": True, "zeroed": zeroed, "already": False,
            "format": format_name, "sections": sections}


# ---------------------------------------------------------------------------
# Hardening inspection
# ---------------------------------------------------------------------------
#
# What the build turns on is a promise made in the CMakeLists; what the
# finished binary carries is the fact. These two can disagree - a stale binary,
# a link line that did not take, a flag ignored by the toolchain - and only the
# second one is worth reporting. So the panel reads the binary.
#
# Three of the four are single bits in DllCharacteristics (IMAGE_DLLCHARACTERISTICS_*),
# which is the authoritative record of what Windows itself will honour.
#
#   0x0020  HIGH_ENTROPY_VA   64-bit ASLR, the strong form
#   0x0040  DYNAMIC_BASE      ASLR at all
#   0x0100  NX_COMPAT         DEP: the stack and heap are non-executable
#
# Stack protection is not in that word. It is a compiler feature, so it is
# detected by the presence of the canary runtime the compiler pulls in
# (__stack_chk_fail / __stack_chk_guard) rather than by a header bit. That is a
# weaker signal than the other three, and deliberately reported as such: a
# vendored library can pull the canary in on its own, so finding the symbol
# proves the binary CAN detect an overflow, not that the project's own frames
# are the ones protected.

IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA = 0x0020
IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040
IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x0100

# The canary runtime's symbols. Both are referenced by a protected function:
# __stack_chk_guard holds the cookie, __stack_chk_fail is called when it does
# not match. Either one is enough evidence that the protection is linked in.
_STACK_CANARY_MARKERS = (b"__stack_chk_fail", b"__stack_chk_guard")

# The scanner reads the file in chunks of this size. The analyzer is ~196 MB
# and the symbols live in the import/export tables near the front, but a
# chunked scan keeps the memory cost flat regardless of the binary's size.
_SCAN_CHUNK = 4 * 1024 * 1024


def _scan_for_canary(path: Path) -> bool:
    """True if the canary runtime appears anywhere in the file.

    Chunked, and the overlap matters: a marker that straddles a chunk
    boundary would be missed by a naive chunk scan, and the answer would flip
    to "not protected" for a binary that is protected.
    """
    overlap = max(len(m) for m in _STACK_CANARY_MARKERS) - 1
    tail = b""
    try:
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(_SCAN_CHUNK)
                if not chunk:
                    break
                window = tail + chunk
                if any(marker in window for marker in _STACK_CANARY_MARKERS):
                    return True
                tail = window[-overlap:] if overlap else b""
    except OSError:
        return False
    return False


def _read_pe_layout(path: Path) -> dict:
    """The layout of a PE file, reading only the header region.

    The analyzer is ~196 MB. The optional header lives in the first few
    kilobytes, so this reads a kilobyte and a half rather than the whole file -
    the canary scan streams separately, and the two together cost the same as
    reading a few kilobytes.

    The buffer is assembled so the offsets the layout parser computes are the
    file's real offsets: the DOS header is kept at 0 and the PE header is
    placed at the e_lfanew the DOS header points at.
    """
    try:
        with path.open("rb") as handle:
            head = handle.read(0x40)
            if len(head) < 0x40 or head[:2] != b"MZ":
                raise ValueError("the file is not a DOS/PE executable (no MZ header)")
            pe = _u32(head, 0x3C)
            handle.seek(pe)
            chunk = handle.read(0x1000)
    except OSError as exc:
        raise ValueError(f"the file could not be read: {exc}") from exc

    if len(chunk) < 24:
        raise ValueError("the file has no PE signature at e_lfanew")

    buf = bytearray(pe + max(len(chunk), 0x1000))
    buf[0:len(head)] = head
    buf[pe:pe + len(chunk)] = chunk
    return _pe_layout(bytes(buf))


def hardening(path: Path) -> dict:
    """What hardening the PE image actually carries.

    Returns the three header bits, whether the stack canary is linked in, and
    the raw DllCharacteristics word so a report can show what it said rather
    than only the interpretation.

    Raises ValueError with a sentence for anything that is not a PE image this
    parser understands - the same contract as `strip_iat`, so the caller has
    one way to report a broken artefact.
    """
    layout = _read_pe_layout(path)
    characteristics = layout["dll_characteristics"]
    canary = _scan_for_canary(path)

    return {
        "format": layout["format"],
        "dll_characteristics": characteristics,
        "aslr": bool(characteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE),
        "high_entropy_va": bool(characteristics & IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA),
        "dep_nx": bool(characteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT),
        # "unknown" would be the honest word here, but the binary either has the
        # canary runtime linked in or it does not, and the report says how that
        # was determined so the reader knows what it means.
        "stack_protector": canary,
        "stack_protector_evidence": "canary runtime symbols present" if canary else
                                   "no canary runtime symbols found",
    }


# ---------------------------------------------------------------------------
# Packed-ness detection
# ---------------------------------------------------------------------------
#
# The run gate needs to answer "is this executable packed" BEFORE spawning the
# analyzer, because a packed sample spent in a run is a run spent in unpacking
# loops whose later phases cannot be trusted. Two offline signals, strongest
# first:
#
#   * UPX leaves its own markers in the file - the section names UPX0/UPX1 and
#     the packer's magic. Finding one is a fact, not a heuristic.
#   * A packed file's bytes are compressed, so whole-file entropy at or above
#     ENTROPY_PACKED reads as packed. The threshold is deliberately the SAME
#     number src/main/phase_extract.cpp:239 stops a run at (IA_INTERRUPT_
#     ENTROPY's default), so the panel's gate and the analyzer's tripwire
#     cannot disagree about the same file.
#
# The file is never executed and never fully parsed; the scan streams in the
# same chunks, with the same marker-straddle overlap, as the canary scan above.

# Section names and packer magic UPX writes into the file.
UPX_MARKERS = (b"UPX0", b"UPX1", b"UPX2", b"UPX!")

# The entropy threshold, in bits/byte, at or above which a file reads as
# packed. Mirrors k_default_packed_entropy in phase_extract.cpp.
ENTROPY_PACKED = 7.5

# Entropy is measured over at most this many bytes from the front of the file.
# UPX compresses the whole file, so the front of it answers for the rest, and
# the cap keeps a large file in exports/ from costing a full re-read on every
# run start. The verdict says when the cap applied.
_PROBE_HISTOGRAM_MAX = 32 * 1024 * 1024


def pack_verdict(path: Path) -> dict:
    """Offline packed-ness verdict for one file. Never executes it.

    Returns {packed, method, evidence, entropy}: `method` is "upx" when a
    packer marker was found, "entropy" when only the entropy threshold fired,
    None when the file reads as unpacked; `evidence` is the sentence the page
    shows; `entropy` is the measured whole-file entropy in bits/byte. An
    unreadable file is NOT packed as far as this function knows - it reports
    the read error instead, and the caller decides what a missing verdict
    means (the run gate lets the analyzer's own failure speak).
    """
    overlap = max(len(m) for m in UPX_MARKERS) - 1
    tail = b""
    found: list[bytes] = []
    counts = [0] * 256
    total = 0
    try:
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(_SCAN_CHUNK)
                if not chunk:
                    break
                # The overlap window is what keeps a marker straddling a chunk
                # boundary from reading as "not packed" - same discipline as
                # _scan_for_canary, for the same reason.
                window = tail + chunk
                for marker in UPX_MARKERS:
                    if marker in window and marker not in found:
                        found.append(marker)
                tail = window[-overlap:] if overlap else b""
                if total < _PROBE_HISTOGRAM_MAX:
                    take = chunk[:_PROBE_HISTOGRAM_MAX - total]
                    for value in range(256):
                        n = take.count(value)
                        if n:
                            counts[value] += n
                    total += len(take)
    except OSError as exc:
        return {"packed": False, "method": None, "evidence": "",
                "error": f"the file could not be read: {exc}"}

    entropy = 0.0
    if total:
        for n in counts:
            if n:
                p = n / total
                entropy -= p * math.log2(p)

    if found:
        names = ", ".join(m.decode("ascii") for m in found)
        return {"packed": True, "method": "upx",
                "evidence": f"UPX markers ({names}) in the file",
                "entropy": round(entropy, 4)}
    if entropy >= ENTROPY_PACKED:
        return {"packed": True, "method": "entropy",
                "evidence": (f"whole-file entropy {entropy:.4f} bits/byte is at "
                             f"or above the packed threshold {ENTROPY_PACKED}"),
                "entropy": round(entropy, 4)}
    return {"packed": False, "method": None, "evidence": "",
            "entropy": round(entropy, 4)}
