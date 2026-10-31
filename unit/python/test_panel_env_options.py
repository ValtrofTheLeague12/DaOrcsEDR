"""The Analysis Configuration page's contract with the analyzer binary.

The panel's `ENV_OPTIONS` list is the operator-facing half of a claim: each entry
says "this key, this label, and here is the line of code that reads it". The
module's own comment is explicit that `honoured_by` is "the claim the panel is
making on the operator's behalf, and it is rendered next to the control so it
can be checked".

That makes it testable, and these tests are what keep the claim honest:

  * every option is a real key, unique, and of a kind the wizard can render;
  * every `honoured_by` names a file that exists and a line that exists on it;
  * every key is genuinely read somewhere in the C++ - otherwise the control is
    a switch that lies, which is the failure mode the panel comment names as
    worse than having no control at all.

The last one is the valuable check. It is a source scan rather than a runtime
assertion on purpose: running the binary once per option would be slow, would
need a sample, and would prove less. A key that appears nowhere in src/ is not
honoured by anything, no matter what the panel says about it.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "python"))

from panel.analysis.analysis import ENV_BY_KEY, ENV_OPTIONS  # noqa: E402

# Every key in one compiled set, so the scan below reads a large concatenated
# blob once rather than reopening 60-odd files per option.
_CPP_SOURCES = [
    p
    for pattern in ("src/**/*.cpp", "src/**/*.hpp", "include/**/*.hpp")
    for p in REPO.glob(pattern)
    if "build" not in p.parts
]
CPP_BLOB = "\n".join(p.read_text(encoding="utf-8", errors="replace") for p in _CPP_SOURCES)


class TestOptionShape:
    def test_keys_are_unique(self):
        keys = [o["key"] for o in ENV_OPTIONS]
        assert len(keys) == len(set(keys)), "duplicate key in ENV_OPTIONS"

    def test_every_option_has_a_label_and_a_detail(self):
        for opt in ENV_OPTIONS:
            assert opt["label"].strip(), f"{opt['key']} has no label"
            assert len(opt["detail"].strip()) > 20, f"{opt['key']} detail is too thin to be useful"

    def test_kind_is_one_the_wizard_can_render(self):
        # PipelineWizard.tsx branches on exactly these three. A fourth kind would
        # render as nothing and look like a missing control.
        for opt in ENV_OPTIONS:
            assert opt["kind"] in {"flag", "number", "text"}, opt["key"]

    def test_lookup_index_covers_every_option(self):
        assert set(ENV_BY_KEY) == {o["key"] for o in ENV_OPTIONS}


class TestHonouredByIsReal:
    """`honoured_by` is the claim the operator is invited to check."""

    def _ref(self, opt):
        ref = opt["honoured_by"]
        match = re.fullmatch(r"([^:]+):(\d+)", ref)
        assert match, f"{opt['key']}: honoured_by is not file:line - {ref!r}"
        return Path(match.group(1)), int(match.group(2))

    @pytest.mark.parametrize("opt", ENV_OPTIONS, ids=lambda o: o["key"])
    def test_named_file_exists(self, opt):
        path, _ = self._ref(opt)
        assert (REPO / path).exists(), f"{opt['key']}: {path} does not exist"

    @pytest.mark.parametrize("opt", ENV_OPTIONS, ids=lambda o: o["key"])
    def test_named_line_is_in_range(self, opt):
        path, line = self._ref(opt)
        lines = (REPO / path).read_text(encoding="utf-8", errors="replace").splitlines()
        assert 1 <= line <= len(lines), (
            f"{opt['key']}: {path} has {len(lines)} lines, ref points at {line}"
        )

    @pytest.mark.parametrize("opt", ENV_OPTIONS, ids=lambda o: o["key"])
    def test_key_is_actually_read_by_the_code(self, opt):
        # The check that matters. A control for a key the binary never reads is
        # a lie told in the UI, and it survives every other test here.
        assert re.search(rf"\b{re.escape(opt['key'])}\b", CPP_BLOB), (
            f"{opt['key']} appears nowhere in src/ or include/ - "
            f"the panel offers a control the analyzer ignores"
        )


class TestSignalAndDumpOptions:
    """The two fault-related options, pinned individually.

    These are the ones with a real behaviour behind them, so they get their own
    checks rather than riding on the generic loops above.
    """

    def test_core_dump_is_off_by_default(self):
        # A full dump is a large file per crash. Defaulting it on would fill a
        # disk for anyone who crashes twice.
        assert ENV_BY_KEY["IA_ALLOW_CORE_DUMP"]["default"] is False

    def test_continue_on_signal_is_off_by_default(self):
        assert ENV_BY_KEY["IA_CONTINUE_ON_SIGNAL"]["default"] is False

    def test_continue_option_explains_the_rerun_not_a_skip(self):
        # The re-run is the part an operator would otherwise misread. "Continue"
        # reads as "carry on from the next phase"; what it actually does is run
        # the interrupted phase again, and that difference is the whole reason
        # the option exists. If this text is ever trimmed down, this test is why
        # it cannot be.
        detail = ENV_BY_KEY["IA_CONTINUE_ON_SIGNAL"]["detail"]
        assert "re-runs" in detail
        assert "partial output" in detail

    def test_continue_option_says_a_second_interrupt_still_stops(self):
        # Absorbing every interrupt would leave no way to stop a run.
        detail = ENV_BY_KEY["IA_CONTINUE_ON_SIGNAL"]["detail"]
        assert "second" in detail.lower()

    def test_both_are_flags_not_text_fields(self):
        for key in ("IA_ALLOW_CORE_DUMP", "IA_CONTINUE_ON_SIGNAL"):
            assert ENV_BY_KEY[key]["kind"] == "flag"