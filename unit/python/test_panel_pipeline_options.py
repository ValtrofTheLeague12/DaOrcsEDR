"""Per-pipeline options: what the pipelines page offers, and why.

Every pipeline page used to render the same ten environment controls, filtered
only by "is it set globally". A pipeline whose plan is a single phase was
offered six controls for phases it does not run - and pipelines/capa.yaml
carrying inert CTI_SKIP and ML_THRESHOLD lines is the receipt that somebody
used them. These tests pin the fix at both ends:

  read   - a pipeline page receives the four run-wide options only; the CTI and
           ML options are machine-wide (Analysis Configuration owns them), so
           no pipeline page lists one. A stale line still in the file is
           marked `irrelevant`, the way a shadowed line is marked
  write  - setting a phase-scoped key per pipeline is refused wherever it
           would land; clearing one is allowed, because removing a line that
           does not belong is the cleanup the refusal exists to provoke

The catalog is faked rather than absent on purpose: the unavailable-catalog
behaviour (no irrelevant marking, option list unchanged - the run-wide set is
static, not catalog-derived) is its own test.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "python"))
sys.path.insert(0, str(REPO))

from panel.analysis import analysis  # noqa: E402


CATALOG = {"available": True, "source": "test", "error": None, "items": [],
           # The real catalog maps every known phase to its prerequisites, and
           # _verify_pipeline treats a phase missing from this map as unknown -
           # so the fake must list the phases these files declare.
           "requires": {"capa": [], "model": [], "strings": [],
                        "export": [], "summary": []}}

CAPA_YAML = """\
name: capa
description: "capa capability detection"
phases: [capa]

environment:
  CTI_SKIP: 1
  ML_THRESHOLD: "0.7"
"""

MODEL_YAML = """\
name: model
description: "EMBER scoring"
phases: [model]
"""


@pytest.fixture
def pipelines(tmp_path, monkeypatch):
    root = tmp_path / "pipelines"
    root.mkdir()
    (root / "capa.yaml").write_text(CAPA_YAML, encoding="utf-8")
    (root / "model.yaml").write_text(MODEL_YAML, encoding="utf-8")
    monkeypatch.setattr(analysis, "PIPELINE_DIR", root)
    # Hermetic: the real config/analysis.yaml must not decide what these
    # pipelines may set, and the real analyzer must not be consulted.
    monkeypatch.setattr(analysis, "_global_settings", lambda: {})
    monkeypatch.setattr(analysis, "_catalog", lambda: dict(CATALOG))
    return root


def _entry(root: Path, name: str) -> dict:
    # Through analysis._catalog(), not a literal: the unavailable-catalog test
    # monkeypatches it, and the helper must honour that.
    return analysis._resolve_entry(
        analysis._pipeline(root / f"{name}.yaml"), analysis._catalog())


class TestOfferedOptions:
    """The option list a pipeline page receives: the run-wide keys, always.

    The CTI and ML options are machine-wide - Analysis Configuration owns them
    - so a pipeline page neither offers a control for one nor a card. What it
    keeps instead is reportage: a stale line in the file is still visible in
    the environment list, marked `irrelevant` like a shadowed one, and a write
    is refused either way.
    """

    def test_a_pipeline_page_is_offered_the_run_wide_keys_only(self, pipelines):
        # Same list on a one-phase pipeline and on a full one: the run-wide
        # set is static, a property of the keys, not of the plan. Thirteen
        # keys: the original cursing/dump/signal/trace group plus the tracer
        # hard-off, the packed tripwire pair and the MEGA upload overrides -
        # the same set the C++ kKeys list carries minus the machine-wide
        # CTI/ML/TRACE keys this class's parity tests keep in their place.
        expected = ["STATIC_ANALYZER_CURSES", "IA_ALLOW_CORE_DUMP",
                    "IA_CONTINUE_ON_SIGNAL", "TRACE_FILE",
                    "ENABLE_TRACING", "IA_INTERRUPT_IF_PACKED",
                    "IA_INTERRUPT_ENTROPY", "MEGA_UPLOAD", "MEGA_REMOTE_ROOT",
                    "MEGA_SEAL", "MEGA_TIMEOUT"]
        for name in ("capa", "model"):
            options = [o["key"] for o in _entry(pipelines, name)["options"]]
            assert options == expected, name

    def test_no_phase_scoped_key_reaches_the_list(self, pipelines):
        for name in ("capa", "model"):
            options = {o["key"]: o for o in _entry(pipelines, name)["options"]}
            for key in ("CTI_SKIP", "ML_SKIP", "ML_EXPLAIN", "ML_THRESHOLD",
                        "ML_TOP_K", "CTI_CONFIG"):
                assert key not in options, (name, key)

    def test_inert_lines_are_marked_like_shadowed_ones(self, pipelines):
        env = {e["key"]: e for e in _entry(pipelines, "capa")["environment"]}
        # Both of these were written for phases capa does not run - the exact
        # state the page used to invite and could not see.
        assert env["CTI_SKIP"]["irrelevant"] is True
        assert env["ML_THRESHOLD"]["irrelevant"] is True

    def test_a_used_line_is_not_marked(self, pipelines):
        (pipelines / "model.yaml").write_text(
            MODEL_YAML + "\nenvironment:\n  ML_THRESHOLD: \"0.7\"\n",
            encoding="utf-8")
        env = {e["key"]: e for e in _entry(pipelines, "model")["environment"]}
        assert "irrelevant" not in env["ML_THRESHOLD"]

    def test_an_unavailable_catalog_marks_nothing(self, pipelines, monkeypatch):
        # Without the plan there is nothing to judge a line against, so nothing
        # is marked rather than a guessed list - and the option list is the
        # same MEGA/behavior keys either way, because it is not catalog-derived.
        monkeypatch.setattr(analysis, "_catalog",
                            lambda: {"available": False, "source": "none",
                                     "error": "down", "items": [], "requires": {}})
        entry = _entry(pipelines, "capa")
        options = [o["key"] for o in entry["options"]]
        assert options == ["STATIC_ANALYZER_CURSES", "IA_ALLOW_CORE_DUMP",
                           "IA_CONTINUE_ON_SIGNAL", "TRACE_FILE",
                           "ENABLE_TRACING", "IA_INTERRUPT_IF_PACKED",
                           "IA_INTERRUPT_ENTROPY", "MEGA_UPLOAD",
                           "MEGA_REMOTE_ROOT", "MEGA_SEAL", "MEGA_TIMEOUT"]
        assert all("irrelevant" not in e for e in entry["environment"])


class TestWriteScope:
    """Phase-scoped keys are machine-wide; the console no longer writes them.

    This replaces the relevance-based refusal, which let a pipeline running the
    phase write the key. That drew the line in the wrong place: model.yaml
    offered the ML controls right up until someone removed the model phase, and
    the file filled with lines nobody revisits. The line is now the key's kind,
    so the refusal needs no catalog and no plan and cannot drift from the page,
    which stopped offering these controls at the same time.
    """

    def test_a_phase_scoped_key_is_refused_even_where_the_phase_runs(self, pipelines):
        # The policy test: model.yaml runs the model phase, and ML_THRESHOLD is
        # still refused - the setting belongs on Analysis Configuration.
        with pytest.raises(ValueError, match="Analysis Configuration"):
            analysis.write_environment("model", {"ML_THRESHOLD": 0.7})

    def test_a_phase_scoped_key_is_refused_for_an_absent_phase(self, pipelines):
        with pytest.raises(ValueError, match="Analysis Configuration"):
            analysis.write_environment("capa", {"CTI_SKIP": True})

    def test_the_refusal_names_every_key_and_no_other(self, pipelines):
        with pytest.raises(ValueError) as exc:
            analysis.write_environment("capa", {"CTI_SKIP": True})
        assert "CTI_SKIP" in str(exc.value)
        assert "ML_SKIP" not in str(exc.value)

    def test_the_refusal_does_not_need_the_catalog(self, pipelines, monkeypatch):
        # Scope is a property of the key, not of the plan, so a down analyzer
        # cannot make the gate forget it.
        monkeypatch.setattr(analysis, "_catalog",
                            lambda: {"available": False, "source": "none",
                                     "error": "down", "items": [], "requires": {}})
        with pytest.raises(ValueError, match="Analysis Configuration"):
            analysis.write_environment("capa", {"CTI_SKIP": True})

    def test_clearing_an_inert_line_is_allowed(self, pipelines):
        # The refusal exists to stop new lines, not to keep old ones
        # unpurgeable - blocking the cleanup would keep the lie on disk.
        entry = analysis.write_environment("capa", {"CTI_SKIP": False})
        assert "CTI_SKIP" not in [e["key"] for e in entry["environment"]]

    def test_a_number_line_can_be_cleared_with_null(self, pipelines):
        # Only a flag had a removal path before (its false), which left a stale
        # ML_THRESHOLD clearable by nothing but a text editor.
        entry = analysis.write_environment("capa", {"ML_THRESHOLD": None})
        assert "ML_THRESHOLD" not in [e["key"] for e in entry["environment"]]

    def test_a_run_wide_key_stays_writable(self, pipelines):
        # The four settings with no `affects` phase are the whole point of a
        # per-pipeline environment block now.
        entry = analysis.write_environment("capa", {"TRACE_FILE": "logs/t.log"})
        env = {e["key"]: e["value"] for e in entry["environment"]}
        assert env["TRACE_FILE"] == "logs/t.log"

    def test_a_broken_file_is_refused_by_the_existing_gate_not_the_new_one(self, pipelines):
        # A file with an unknown phase cannot be edited through this route at
        # all - _verify_pipeline has refused that all along. What this pins is
        # the layering: the scope refusal must not fire on top of it, so the
        # operator gets one clear error naming the real problem.
        (pipelines / "capa.yaml").write_text(
            CAPA_YAML.replace("phases: [capa]", "phases: [capa, not_a_phase]"),
            encoding="utf-8")
        with pytest.raises(ValueError) as exc:
            analysis.write_environment("capa", {"CTI_SKIP": False})
        assert "no analyzer" not in str(exc.value)
        assert "not in the analyzer's catalog" in str(exc.value)


class TestDocumentScope:
    def test_the_wizard_cannot_bake_in_a_phase_scoped_key(self, pipelines):
        # The document-level twin of the write-route refusal: the wizard writes
        # phases and environment keys in one act, so an ML key is refused at
        # save time, not discovered inert later.
        with pytest.raises(ValueError, match="Analysis Configuration"):
            analysis.save_pipeline(
                "scoped",
                'name: scoped\nphases: [strings]\nenvironment:\n  ML_SKIP: "1"\n',
            )
        assert not (pipelines / "scoped.yaml").exists()

    def test_the_wizard_may_still_write_a_run_wide_key(self, pipelines):
        entry = analysis.save_pipeline(
            "scoped",
            'name: scoped\nphases: [strings]\nenvironment:\n  TRACE_FILE: "t.log"\n',
        )
        assert entry["environment"][0]["key"] == "TRACE_FILE"
