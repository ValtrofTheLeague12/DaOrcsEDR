#!/usr/bin/env python3
"""Create a defensive PE overlay/signature test fixture.

This does not create a valid digital signature. It creates a synthetic
WIN_CERTIFICATE-shaped range solely to exercise PE range parsing.
"""
from __future__ import annotations

import argparse
import struct
from pathlib import Path

FILE_ALIGNMENT = 0x200
SECTION_ALIGNMENT = 0x1000
SECTION_NAME = b".signature"
CERTIFICATE_SIZE = 0x120
CERTIFICATE_REVISION = 0x0200
CERTIFICATE_TYPE_PKCS = 0x0002


def align_up(value: int, alignment: int) -> int:
    return (value + alignment - 1) // alignment * alignment


def make_certificate_payload() -> bytes:
    cert = bytearray(CERTIFICATE_SIZE)
    struct.pack_into("<I", cert, 0, CERTIFICATE_SIZE)
    struct.pack_into("<H", cert, 4, CERTIFICATE_REVISION)
    struct.pack_into("<H", cert, 6, CERTIFICATE_TYPE_PKCS)
    marker = b"IA-SIGN-TEST\x00\x00\x00\x00\x00"
    cert[8:8 + len(marker)] = marker
    cert[0x40:0x40 + 10] = b"TEST-CERT\x00"
    return bytes(cert)


def create_fixture(source: Path, output: Path, overlay_marker: bytes) -> None:
    data = bytearray(source.read_bytes())
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    coff = e_lfanew + 4
    section_count = struct.unpack_from("<H", data, coff + 2)[0]
    optional_size = struct.unpack_from("<H", data, coff + 16)[0]
    optional = coff + 20
    section_table = optional + optional_size
    if section_count >= 32:
        raise ValueError("PE already has the maximum supported section count")
    if section_table + (section_count + 1) * 40 > 0x600:
        raise ValueError("PE headers do not have room for another section")

    file_alignment = struct.unpack_from("<I", data, optional + 36)[0]
    section_alignment = struct.unpack_from("<I", data, optional + 32)[0]
    if file_alignment == 0 or section_alignment == 0:
        raise ValueError("invalid PE alignment values")

    next_va = 0
    for index in range(section_count):
        section = section_table + index * 40
        virtual_size = struct.unpack_from("<I", data, section + 8)[0]
        virtual_address = struct.unpack_from("<I", data, section + 12)[0]
        next_va = max(next_va, align_up(virtual_address + virtual_size,
                                         section_alignment))

    raw_offset = align_up(len(data), file_alignment)
    raw_size = align_up(CERTIFICATE_SIZE, file_alignment)
    if len(data) < raw_offset:
        data.extend(b"\0" * (raw_offset - len(data)))
    data[raw_offset:raw_offset + raw_size] = make_certificate_payload()

    # Keep the PE Security Directory in the real overlay, after the
    # .signature section. This exercises certificate/overlay classification
    # without pretending that an in-section certificate is a normal Authenticode
    # layout.
    security_offset = align_up(raw_offset + raw_size, file_alignment)
    if len(data) < security_offset:
        data.extend(b"\0" * (security_offset - len(data)))
    data[security_offset:security_offset + CERTIFICATE_SIZE] = make_certificate_payload()

    section = bytearray(40)
    section[:len(SECTION_NAME)] = SECTION_NAME
    struct.pack_into("<I", section, 8, CERTIFICATE_SIZE)
    struct.pack_into("<I", section, 12, next_va)
    struct.pack_into("<I", section, 16, raw_size)
    struct.pack_into("<I", section, 20, raw_offset)
    struct.pack_into("<I", section, 36, 0x40000040)
    section_offset = section_table + section_count * 40
    data[section_offset:section_offset + 40] = section
    struct.pack_into("<H", data, coff + 2, section_count + 1)

    security_directory = optional + 112 + 4 * 8
    struct.pack_into("<II", data, security_directory, security_offset, CERTIFICATE_SIZE)
    struct.pack_into("<I", data, optional + 56, next_va + raw_size)
    data.extend(overlay_marker)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(data)

    print(f"created: {output}")
    print(f"sections: {section_count} -> {section_count + 1}")
    print(f"signature section: offset=0x{raw_offset:x}, size=0x{raw_size:x}")
    print(f"security directory: offset=0x{security_offset:x}, size=0x{CERTIFICATE_SIZE:x}")
    print(f"overlay marker: offset=0x{security_offset + CERTIFICATE_SIZE:x}, size={len(overlay_marker)}")
    print(f"file size: {len(data)}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="input PE file")
    parser.add_argument("output", type=Path, help="generated fixture path")
    parser.add_argument("--marker", default="IA_OVERLAY_AFTER_SIGNATURE",
                        help="trailing overlay marker text")
    args = parser.parse_args()
    marker = (args.marker.encode("ascii") + b"\0") * 8
    create_fixture(args.source, args.output, marker)


if __name__ == "__main__":
    main()
