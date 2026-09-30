#!/usr/bin/env python3
"""Regression test for PE section bounds, Security Directory, and overlay data."""
from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


def load_generator():
    path = Path(__file__).parent / "fixtures" / "generate_overlay_signature.py"
    spec = importlib.util.spec_from_file_location("overlay_fixture", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load fixture generator: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> int:
    if len(sys.argv) not in (3, 4):
        print("usage: test_pe_overlay.py <static-analyzer-executable> <source-pe> [phase]", file=sys.stderr)
        return 2
    phase = int(sys.argv[3]) if len(sys.argv) == 4 else 1
    if phase not in (1, 2, 3, 4):
        print("phase must be 1, 2, 3, or 4", file=sys.stderr)
        return 2
    analyzer = Path(sys.argv[1]).resolve()
    source_pe = Path(sys.argv[2]).resolve()
    if not analyzer.is_file():
        print(f"analyzer not found: {analyzer}", file=sys.stderr)
        return 2
    if not source_pe.is_file():
        print(f"source PE not found: {source_pe}", file=sys.stderr)
        return 2

    generator = load_generator()
    with tempfile.TemporaryDirectory(prefix="static-analyzer-pe-overlay-") as temp:
        root = Path(temp)
        fixture = root / "overlay_signature_fixture.exe"
        rules = root / "rules"
        rules.mkdir()
        (rules / "empty.yar").write_text(
            'rule Overlay_Test_No_Match { strings: $a = "not-present" condition: $a }\n',
            encoding="ascii",
        )
        generator.create_fixture(source_pe, fixture, b"IA_OVERLAY_AFTER_SIGNATURE\x00" * 8)

        env = os.environ.copy()
        env["CTI_SKIP"] = "1"
        env["YARA_RULES_DIR"] = str(rules)
        run = subprocess.run(
            [str(analyzer), str(fixture)], cwd=root, env=env, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120,
        )
        if run.returncode != 0:
            print(run.stdout)
            print(f"analyzer failed with exit code {run.returncode}", file=sys.stderr)
            return 1

        # These strings must match the section headings the analyzer actually
        # prints. print_section() emits "  -- <text>" with no trailing dashes,
        # and the generic "Sections:" table is deliberately skipped for PE/ELF/
        # Mach-O (phase 1 prints a format-specific table instead), so the PE
        # section table is asserted via its own heading.
        required_markers = {
            1: ("-- PE section end / overlay", "Inside section overlay:yes"),
            2: ("-- NOP statistics by section",),
            3: ("-- IOC extraction",),
            4: ("-- IAT/GOT call-site assembly", "DLL:"),
        }[phase]
        for marker in required_markers:
            if marker not in run.stdout:
                print(run.stdout)
                print(f"phase {phase} missing output marker: {marker}", file=sys.stderr)
                return 1

        extraction = root / "exports" / "extraction" / "overlay_signature_fixture_extraction.json"
        if not extraction.is_file():
            print(f"missing extraction output: {extraction}", file=sys.stderr)
            return 1
        payload = json.loads(extraction.read_text(encoding="utf-8"))
        if phase == 1:
            pe = payload["raw"]["pe"]
            security = pe["security_directory"]
            assert security["present"] is True
            assert security["valid_range"] is True
            assert security["overlaps_section"] is False
            assert security["inside_section_overlay"] is True
            assert security["certificate_count"] == 1
            assert pe["has_overlay_after_security"] is True
            assert pe["overlay_after_security_size"] > 0
        elif phase == 2:
            assert payload["sections"]["count"] > 0
        elif phase == 3:
            ioc_path = root / "exports" / "ioc" / "overlay_signature_fixture_ioc.json"
            assert ioc_path.is_file()
        elif phase == 4:
            iat_path = root / "exports" / "iat" / "overlay_signature_fixture_iat.json"
            assert iat_path.is_file()
            iat = json.loads(iat_path.read_text(encoding="utf-8"))
            assert iat["entries"]

    print("PE overlay/security regression test passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
