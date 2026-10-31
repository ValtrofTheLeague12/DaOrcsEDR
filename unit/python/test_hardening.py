"""Build hardening: the settings file, the flags, and the comparison.

The feature is a chain of four halves that have to agree about one thing -
which Windows protections the analyzer is built with:

    python/panel/hardening.py  reads and writes config/hardening.json, turns
                               it into CMake/build.ps1 flags, and compares the
                               result against the finished PE
    CMakeLists.txt             four STATIC_ANALYZER_HARDENING_* options that
                               add the real /GS and link flags
    build.ps1                  reads the same JSON, takes Enable/Disable
                               overrides, passes the options to CMake
    the binary itself          DllCharacteristics for three of them, the
                               canary runtime for the fourth

These tests pin the panel half and the cross-file contract. The defaults are
ON - MinGW's linker already defaults the first three on - so the switches
exist to record a deliberate OFF, and "compliant" therefore means "the binary
matches the settings", never "everything is on". A test that only ever turned
protections on would miss the one case the file exists for.

The binary-reading half (pe_tools.hardening) is pinned in
test_pe_tools.py, next to the stripper that shares its layout parser; what
belongs here is the comparison, including its failure modes: no binary, a
binary that is not a PE, and a settings file that will not parse.
"""

from __future__ import annotations

import json
import struct
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "python"))

from panel import hardening  # noqa: E402


ALL_BITS = 0x0160  # HIGH_ENTROPY_VA | DYNAMIC_BASE | NX_COMPAT
CANARY = b"\x00__stack_chk_guard\x00"


def pe_image(*, dll_characteristics=0, trailing=b"") -> bytes:
    """The smallest PE the layout parser accepts, with a chosen word.

    PE32+ only: the parser reads DllCharacteristics at the same offset in both
    formats (70 bytes into the optional header), and test_pe_tools.py already
    pins that for both, so what matters here is the comparison, not the
    layout.
    """
    data = bytearray(0x200)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    coff = 0x84
    struct.pack_into("<H", data, coff, 0x8664)
    struct.pack_into("<H", data, coff + 2, 3)
    struct.pack_into("<H", data, coff + 16, 240)
    opt = coff + 20
    struct.pack_into("<H", data, opt, 0x20B)
    struct.pack_into("<H", data, opt + 70, dll_characteristics)
    return bytes(data) + trailing


def _write_raw(repo: Path, text: str) -> None:
    path = hardening.config_path(repo)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _write(repo: Path, patch: dict) -> None:
    """The file as a write() would have left it, without going through write()."""
    settings = hardening.defaults()
    settings.update(patch)
    _write_raw(repo, json.dumps(settings))


def _binary(repo: Path, *, dll_characteristics=ALL_BITS, trailing=CANARY) -> Path:
    path = repo / "static_analyzer.exe"
    path.write_bytes(pe_image(dll_characteristics=dll_characteristics,
                              trailing=trailing))
    return path


class TestSettings:
    """config/hardening.json, read and written.

    A missing file is not an error - the defaults are the settings. A file
    that is present but wrong IS an error, and it is raised rather than
    ignored: a typo must not silently produce an unhardened binary that the
    file claims to describe.
    """

    def test_no_file_means_the_defaults(self, tmp_path):
        assert hardening.load(tmp_path) == hardening.defaults()

    def test_every_default_is_on(self):
        # The premise the whole feature is built on: the switches exist to
        # turn a protection OFF deliberately, not to turn one on.
        assert hardening.defaults() == {
            "aslr": True, "high_entropy_va": True,
            "dep_nx": True, "stack_protector": True}

    def test_an_empty_file_means_the_defaults(self, tmp_path):
        _write_raw(tmp_path, "   \n")
        assert hardening.load(tmp_path) == hardening.defaults()

    def test_a_partial_file_fills_the_rest_from_the_defaults(self, tmp_path):
        _write(tmp_path, {"aslr": False})

        settings = hardening.load(tmp_path)

        assert settings["aslr"] is False
        assert settings["high_entropy_va"] is True

    def test_a_malformed_file_is_refused_with_where_it_lives(self, tmp_path):
        _write_raw(tmp_path, "{ not json")

        with pytest.raises(ValueError, match="hardening.json"):
            hardening.load(tmp_path)

    def test_a_non_object_file_is_refused(self, tmp_path):
        _write_raw(tmp_path, "[true, false]")

        with pytest.raises(ValueError, match="JSON object"):
            hardening.load(tmp_path)

    def test_an_unknown_key_is_refused_and_the_known_ones_named(self, tmp_path):
        # A key this version does not know means the file was written by a
        # different one; the operator's intent is not being honoured, and the
        # refusal says which settings do exist.
        _write_raw(tmp_path, json.dumps({"aslr": True, "cfg": True}))

        with pytest.raises(ValueError) as exc:
            hardening.load(tmp_path)
        assert "cfg" in str(exc.value)
        assert "stack_protector" in str(exc.value)

    def test_a_stringified_boolean_is_refused(self, tmp_path):
        # The accident this mechanism exists to prevent: `"false"` is a
        # string, and accepting it means a client that stringified its
        # payload silently flipped a protection OFF.
        _write_raw(tmp_path, json.dumps({"dep_nx": "false"}))

        with pytest.raises(ValueError, match="true or false"):
            hardening.load(tmp_path)


class TestWrite:
    """The panel's write path: partial, atomic, and strict."""

    def test_a_partial_patch_keeps_the_settings_it_does_not_mention(self, tmp_path):
        hardening.write(tmp_path, {"aslr": False})

        settings = hardening.load(tmp_path)

        assert settings["aslr"] is False
        assert settings["high_entropy_va"] is True
        assert settings["dep_nx"] is True

    def test_the_result_is_returned_as_well_as_written(self, tmp_path):
        result = hardening.write(tmp_path, {"stack_protector": False})

        assert result == hardening.load(tmp_path)
        assert result["stack_protector"] is False

    def test_an_unknown_key_is_refused_and_the_file_is_left_alone(self, tmp_path):
        hardening.write(tmp_path, {"aslr": False})
        before = hardening.config_path(tmp_path).read_bytes()

        with pytest.raises(ValueError, match="not a hardening setting"):
            hardening.write(tmp_path, {"nonsense": True})

        assert hardening.config_path(tmp_path).read_bytes() == before

    def test_a_non_boolean_is_refused_and_the_file_is_left_alone(self, tmp_path):
        hardening.write(tmp_path, {"aslr": False})
        before = hardening.config_path(tmp_path).read_bytes()

        with pytest.raises(ValueError, match="true or false"):
            hardening.write(tmp_path, {"aslr": "yes"})

        assert hardening.config_path(tmp_path).read_bytes() == before

    def test_a_non_object_patch_is_refused(self, tmp_path):
        with pytest.raises(ValueError, match="JSON object"):
            hardening.write(tmp_path, ["aslr"])

    def test_the_file_is_written_whole_and_no_temporary_survives(self, tmp_path):
        hardening.write(tmp_path, {"aslr": False})

        # temp + rename, so a crash mid-write leaves the old file rather than
        # a half-written one the next build reads as truth.
        assert sorted(p.name for p in hardening.config_path(tmp_path)
                      .parent.iterdir()) == ["hardening.json"]

    def test_the_written_file_carries_the_four_keys_and_nothing_else(self, tmp_path):
        # build.ps1 reads this file too. A build from a terminal must not
        # depend on any panel-only scaffolding being present in it.
        hardening.write(tmp_path, {"dep_nx": False})

        raw = json.loads(hardening.config_path(tmp_path).read_text(encoding="utf-8"))

        assert set(raw) == set(hardening.OPTION_KEYS)
        assert raw["dep_nx"] is False


class TestSnapshot:
    """What the panel shows: the effective value AND the default.

    "ASLR is on" and "ASLR is on because the file says so" are different
    statements, and only the second survives the file being deleted - so both
    travel together.
    """

    def test_the_defaults_are_reported_beside_the_effective_value(self, tmp_path):
        snap = hardening.snapshot(tmp_path)

        assert snap["exists"] is False
        assert snap["error"] is None
        by_key = {o["key"]: o for o in snap["options"]}
        assert by_key["aslr"]["default"] is True
        assert by_key["aslr"]["enabled"] is True

    def test_a_deliberate_off_is_reported_as_off(self, tmp_path):
        _write(tmp_path, {"stack_protector": False})

        by_key = {o["key"]: o for o in hardening.snapshot(tmp_path)["options"]}

        assert by_key["stack_protector"]["enabled"] is False
        # The default is still reported as on: the reason the switch exists is
        # that the two facts are not the same fact.
        assert by_key["stack_protector"]["default"] is True

    def test_every_option_says_what_it_is_and_what_carries_it(self, tmp_path):
        for option in hardening.snapshot(tmp_path)["options"]:
            assert option["label"]
            assert option["summary"]
            assert option["cmake"].startswith("STATIC_ANALYZER_HARDENING_")
            assert option["pe_label"]

    def test_a_broken_file_is_reported_not_raised(self, tmp_path):
        _write_raw(tmp_path, "nonsense")

        snap = hardening.snapshot(tmp_path)

        # Shown, not raised: the page still renders the toggles (against the
        # defaults) and the reason saving is blocked.
        assert "not valid JSON" in snap["error"]
        assert snap["settings"] == hardening.defaults()


class TestFlags:
    """The same intent as CMake options and as build.ps1 switches.

    PowerShell switches are presence-based, so a boolean needs two forms and
    exactly one of them must ever be emitted - a wrong pairing silently
    passed would be the failure the whole mechanism exists to prevent.
    """

    def test_every_option_gets_exactly_one_cmake_definition(self):
        on = hardening.cmake_definitions(hardening.defaults())
        off = hardening.cmake_definitions(
            {key: False for key in hardening.OPTION_KEYS})

        assert on == [f"-D{o['cmake']}=ON" for o in hardening.OPTIONS]
        assert off == [f"-D{o['cmake']}=OFF" for o in hardening.OPTIONS]

    def test_every_option_gets_exactly_one_build_switch(self):
        on = hardening.build_flags(hardening.defaults())
        off = hardening.build_flags({key: False for key in hardening.OPTION_KEYS})

        assert on == [o["enable_build_flag"] for o in hardening.OPTIONS]
        assert off == [o["disable_build_flag"] for o in hardening.OPTIONS]

    def test_the_two_build_switch_forms_are_always_distinct(self):
        for option in hardening.OPTIONS:
            assert option["enable_build_flag"] != option["disable_build_flag"]


class TestCompliance:
    """The settings against the binary. This is the whole point of the feature.

    The build makes a promise; the finished binary carries the fact. They can
    disagree - a stale binary, a link line that did not take, a flag the
    toolchain ignored - and only the second one is worth reporting.
    """

    def test_no_binary_is_reported_not_raised(self, tmp_path):
        report = hardening.compliance(tmp_path, tmp_path / "static_analyzer.exe")

        assert report["available"] is False
        assert "not built" in report["reason"]
        assert report["compliant"] is None
        assert report["rows"] == []

    def test_a_binary_that_carries_every_requested_bit_is_compliant(self, tmp_path):
        report = hardening.compliance(tmp_path, _binary(tmp_path))

        assert report["available"] is True
        assert report["compliant"] is True
        assert all(row["ok"] for row in report["rows"])
        assert report["dll_characteristics"] == ALL_BITS
        assert report["format"] == "PE32+"

    def test_a_missing_protection_breaks_compliance_and_names_the_bit(self, tmp_path):
        # NX and the canary are missing; the other two are there.
        path = _binary(tmp_path, dll_characteristics=0x0060, trailing=b"")

        report = hardening.compliance(tmp_path, path)

        assert report["compliant"] is False
        rows = {row["key"]: row for row in report["rows"]}
        assert rows["aslr"]["ok"] is True
        assert rows["dep_nx"]["present"] is False
        assert rows["dep_nx"]["ok"] is False
        assert "NX_COMPAT" in rows["dep_nx"]["detail"]
        assert rows["stack_protector"]["present"] is False
        # The answer is an instruction, not just a verdict.
        assert "rebuild" in report["note"]

    def test_a_deliberately_off_protection_is_compliance_too(self, tmp_path):
        # The case the file exists for. Every setting off, a binary carrying
        # nothing: they agree, and that is a passing report - not a demand to
        # turn everything back on.
        off = {key: False for key in hardening.OPTION_KEYS}
        hardening.write(tmp_path, off)

        report = hardening.compliance(
            tmp_path, _binary(tmp_path, dll_characteristics=0, trailing=b""))

        assert report["compliant"] is True
        assert all(row["ok"] for row in report["rows"])

    def test_one_off_setting_against_one_absent_bit_is_one_mismatch(self, tmp_path):
        hardening.write(tmp_path, {"aslr": False})
        # The binary carries DYNAMIC_BASE anyway - built before the setting
        # was turned off. Everything else agrees.
        path = _binary(tmp_path, dll_characteristics=ALL_BITS)

        report = hardening.compliance(tmp_path, path)

        assert report["compliant"] is False
        bad = [row for row in report["rows"] if not row["ok"]]
        assert [row["key"] for row in bad] == ["aslr"]
        assert bad[0]["requested"] is False
        assert bad[0]["present"] is True

    def test_the_stack_protector_row_admits_it_is_an_inference(self, tmp_path):
        # The other three are header facts read from DllCharacteristics; the
        # canary is inferred from the runtime being linked in. The row must
        # not present the inference as a header bit.
        rows = {row["key"]: row
                for row in hardening.compliance(tmp_path, _binary(tmp_path))["rows"]}

        assert rows["stack_protector"]["pe_label"] == "stack canary runtime"
        assert rows["aslr"]["pe_label"].startswith("IMAGE_DLLCHARACTERISTICS_")

    def test_a_binary_that_is_not_a_pe_is_a_sentence(self, tmp_path):
        path = tmp_path / "static_analyzer.exe"
        path.write_bytes(b"hello")

        report = hardening.compliance(tmp_path, path)

        assert report["available"] is False
        assert "MZ" in report["reason"]

    def test_a_broken_settings_file_still_describes_the_binary(self, tmp_path):
        # The two halves fail independently: a typo in the settings file must
        # not hide what the binary carries. The comparison falls back to the
        # defaults - what a build would use with the file unreadable - and the
        # error rides alongside.
        _write_raw(tmp_path, "nonsense")

        report = hardening.compliance(tmp_path, _binary(tmp_path))

        assert "not valid JSON" in report["settings_error"]
        assert report["available"] is True
        assert report["compliant"] is True


class TestCrossFileContract:
    """The names this module uses must exist where it claims they do.

    hardening.py maps each setting to a CMake option and to a pair of
    build.ps1 switches. If either side is renamed, the settings file would go
    on describing a build nobody is listening to - so the mapping is checked
    against the real files rather than trusted.
    """

    def test_every_cmake_name_is_an_option_in_cmakelists(self):
        text = (REPO / "CMakeLists.txt").read_text(encoding="utf-8",
                                                   errors="replace")

        for option in hardening.OPTIONS:
            assert f"option({option['cmake']}" in text, option["cmake"]

    def test_the_cmake_options_are_actually_applied(self):
        # Declaring an option and honouring it are different claims: the
        # count is at least two per name - once as the declaration, once
        # inside the if() that adds or removes the flag.
        text = (REPO / "CMakeLists.txt").read_text(encoding="utf-8",
                                                   errors="replace")

        for option in hardening.OPTIONS:
            assert text.count(option["cmake"]) >= 2, option["cmake"]

    def test_every_build_switch_is_a_parameter_of_build_ps1(self):
        # build.ps1 declares them as PowerShell parameters ($EnableAslr), and
        # a caller spells them with a dash (-EnableAslr); the parameter is
        # what has to exist for the spelling to work at all.
        text = (REPO / "build.ps1").read_text(encoding="utf-8",
                                              errors="replace")

        for option in hardening.OPTIONS:
            for flag in (option["enable_build_flag"],
                         option["disable_build_flag"]):
                assert "$" + flag.lstrip("-") in text, flag

    def test_build_ps1_reads_the_same_file_this_module_writes(self):
        text = (REPO / "build.ps1").read_text(encoding="utf-8",
                                              errors="replace")

        assert "config\\hardening.json" in text

    def test_the_settings_file_is_tracked_not_gitignored(self):
        # A re-clone that silently reset every protection would produce a
        # binary nobody can tell from a deliberately weakened one.
        text = (REPO / ".gitignore").read_text(encoding="utf-8",
                                               errors="replace")

        assert "!config/hardening.json" in text
