"""config/analysis.yaml - the settings that apply to every run.

The point of this file is the precedence, and precedence is invisible in a unit
test unless it is asserted directly: nothing here can check that the analyzer
applies it *after* the pipeline's environment block, because that ordering lives
in main.cpp. What can be checked, and is what these do:

  * the writer preserves the file's comments, which is the only place the
    precedence is written down for a human;
  * clearing a setting removes the key rather than writing a falsy value, which
    is a genuinely different outcome - absent falls through to the pipeline,
    false overrides it;
  * an unknown key is refused, because the analyzer exits 2 on one and a write
    that could produce that is a write that breaks the next run;
  * the panel's list of settings and the C++ loader's list agree.

The last one is the load-bearing test. `ENV_OPTIONS` is a Python list and
`known_analysis_keys()` is a C++ list; nothing stops them drifting except this.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "python"))

from panel import analysis_settings as S  # noqa: E402
from panel import analysis as A  # noqa: E402
from panel.analysis import ENV_BY_KEY, ENV_OPTIONS  # noqa: E402

HEADER = (
    "# Global analysis settings\n"
    "#\n"
    "CTI_SKIP: \"1\"\n"
    "# a comment that must survive\n"
    "ML_THRESHOLD: \"0.5\"\n"
)


@pytest.fixture
def repo(tmp_path, monkeypatch):
    """A throwaway repository with a config/analysis.yaml already in it."""
    root = tmp_path / "repo"
    (root / "config").mkdir(parents=True)
    (root / "config" / "analysis.yaml").write_text(HEADER, encoding="utf-8")
    return root


def read(root: Path) -> str:
    return (root / "config" / "analysis.yaml").read_text(encoding="utf-8")


class TestCommentPreservation:
    def test_comments_survive_a_write(self, repo):
        S.write_settings(repo, {"ML_SKIP": True})
        body = read(repo)
        assert "# Global analysis settings" in body
        assert "# a comment that must survive" in body

    def test_an_existing_value_is_updated_in_place(self, repo):
        S.write_settings(repo, {"ML_THRESHOLD": 0.6})
        lines = read(repo).splitlines()
        # count() compares whole lines, so match on the prefix instead.
        assert sum(1 for l in lines if l.startswith("ML_THRESHOLD:")) == 1, (
            "the line was duplicated"
        )
        assert any(l.startswith("ML_THRESHOLD:") and "0.6" in l for l in lines)
        # ...and the other key is untouched.
        assert any(l.startswith('CTI_SKIP: "1"') for l in lines)

    def test_a_file_of_only_comments_is_valid_and_writable(self, tmp_path):
        # This is what ships. A null YAML node must mean "no settings", not a
        # parse failure - the first version of the C++ loader rejected it, which
        # meant the stock config could not be read at all.
        root = tmp_path / "repo"
        (root / "config").mkdir(parents=True)
        (root / "config" / "analysis.yaml").write_text("# nothing set\n", encoding="utf-8")
        assert yaml.safe_load(read(root)) is None
        S.write_settings(root, {"ML_SKIP": True})
        assert "ML_SKIP:" in read(root)
        assert "# nothing set" in read(root)


class TestSetAndClear:
    def test_writing_then_reading_round_trips(self, repo):
        S.write_settings(repo, {"ML_THRESHOLD": 0.75, "TRACE_FILE": "x.log"})
        snap = S.snapshot(repo)
        by_key = {s["key"]: s for s in snap["settings"]}
        # Quoted in the file, so YAML reads it back as a string without the
        # quotes - they are YAML syntax, not part of the value.
        assert by_key["ML_THRESHOLD"]["value"] == "0.75"
        assert by_key["TRACE_FILE"]["value"] == "x.log"
        assert by_key["ML_THRESHOLD"]["present"] is True

    def test_clearing_removes_the_key_rather_than_writing_false(self, repo):
        # The distinction the whole file exists for: absent means "fall through
        # to the pipeline", false means "override the pipeline". They look the
        # same on a toggle and are opposites in behaviour.
        S.write_settings(repo, {"ML_SKIP": None})
        snap = S.snapshot(repo)
        ml = {s["key"]: s for s in snap["settings"]}["ML_SKIP"]
        assert ml["present"] is False
        assert "ML_SKIP" not in yaml.safe_load(read(repo))

    def test_clearing_only_touches_its_own_key(self, repo):
        S.write_settings(repo, {"ML_SKIP": None})
        assert 'CTI_SKIP: "1"' in read(repo)

    def test_clearing_a_key_that_is_not_there_is_a_no_op(self, repo):
        before = read(repo)
        S.write_settings(repo, {"IA_CONTINUE_ON_SIGNAL": None})
        assert read(repo) == before


class TestValidation:
    def test_an_unknown_key_is_refused(self, repo):
        with pytest.raises(ValueError, match="not a setting"):
            S.write_settings(repo, {"ML_SKP": True})
        assert "ML_SKP" not in read(repo)

    def test_a_flag_rejects_non_booleans(self, repo):
        with pytest.raises(ValueError, match="true or false"):
            S.write_settings(repo, {"ML_SKIP": "maybe"})

    def test_a_number_is_range_checked(self, repo):
        with pytest.raises(ValueError, match="at most"):
            S.write_settings(repo, {"ML_THRESHOLD": 5.0})
        with pytest.raises(ValueError, match="at least"):
            S.write_settings(repo, {"ML_THRESHOLD": -1.0})

    def test_a_non_object_body_is_refused(self, repo):
        with pytest.raises(ValueError):
            S.write_settings(repo, ["ML_SKIP"])

    def test_a_rejected_write_leaves_the_file_untouched(self, repo):
        before = read(repo)
        with pytest.raises(ValueError):
            S.write_settings(repo, {"ML_SKIP": "maybe", "TRACE_FILE": "a.log"})
        assert read(repo) == before


class TestUnknownKeysSurvive:
    def test_a_key_the_panel_does_not_know_is_reported(self, repo):
        # The analyzer exits 2 on one, so the panel is the only place it can be
        # surfaced before it turns into a broken run.
        (repo / "config" / "analysis.yaml").write_text(
            'LEGACY_SETTING: "1"\n', encoding="utf-8"
        )
        assert S.snapshot(repo)["unknown"] == ["LEGACY_SETTING"]

    def test_saving_does_not_silently_delete_one(self, repo):
        # Two things at once. Rewriting must not drop a key the panel cannot
        # edit, which would destroy whatever reason it was added for. And the
        # write must succeed rather than being refused because the stray key is
        # there - refusing made the panel useless in exactly the situation it
        # exists to explain. The analyzer still refuses to start on it, which is
        # its call, and the panel keeps reporting it.
        (repo / "config" / "analysis.yaml").write_text(
            'LEGACY_SETTING: "1"\n', encoding="utf-8"
        )
        S.write_settings(repo, {"ML_SKIP": True})
        body = yaml.safe_load(read(repo))
        assert body["LEGACY_SETTING"] == "1"
        assert body["ML_SKIP"] is True
        assert S.snapshot(repo)["unknown"] == ["LEGACY_SETTING"]


class TestPipelinesCannotDuplicateAGlobalKey:
    """A key belongs to one layer, or the file that loses is a lie.

    The analyzer applies config/analysis.yaml *after* the selected pipeline, so a
    pipeline line for a key the global file also sets is not a weaker setting -
    it is a setting that does not happen. Left alone that produces the worst
    failure mode available here: a YAML file that says ML_SKIP: "0", a run that
    skips the model, and nothing in either file explaining the gap.

    So the per-pipeline writer refuses it, the pipeline-page verification refuses
    it (which is what covers the wizard and the raw-YAML tab, since every write
    goes through there), and the read side reports which existing lines are
    already inert so an operator can clean them up.
    """

    @pytest.fixture
    def wired(self, repo, monkeypatch):
        """Point the pipeline side at a throwaway repository."""
        monkeypatch.setattr(A.config, "REPO", repo)
        monkeypatch.setattr(A, "PIPELINE_DIR", repo / "pipelines")
        (repo / "pipelines").mkdir()
        return repo

    def test_the_writer_refuses_a_global_key(self, wired):
        with pytest.raises(ValueError, match="config/analysis.yaml"):
            A.write_environment("capa", {"CTI_SKIP": False})

    def test_the_refusal_names_the_key(self, wired):
        with pytest.raises(ValueError) as exc:
            A.write_environment("capa", {"CTI_SKIP": True, "ML_TOP_K": 5})
        assert "CTI_SKIP" in str(exc.value)
        assert "ML_TOP_K" not in str(exc.value)

    def test_a_key_nobody_set_globally_is_still_writable(self, wired):
        # The refusal must not be "refuse everything". TRACE_FILE is not in the
        # fixture's global file, and a run-wide key is exactly what a pipeline
        # may still differ on - the machine-wide ones moved to the other page.
        path = wired / "pipelines" / "triage.yaml"
        path.write_text(
            "name: triage\nphases: [strings]\n", encoding="utf-8"
        )
        entry = A.write_environment("triage", {"TRACE_FILE": "t.log"})
        assert entry["environment"][0]["key"] == "TRACE_FILE"

    def test_a_new_pipeline_cannot_bake_one_in(self, wired):
        # The wizard writes a whole file, so every environment key in it is one
        # the author just introduced. CTI_SKIP is the key the fixture's global
        # file defines.
        with pytest.raises(ValueError, match="config/analysis.yaml"):
            A.save_pipeline(
                "triage",
                'name: triage\nphases: [strings]\nenvironment:\n  CTI_SKIP: "0"\n',
            )
        assert not (wired / "pipelines" / "triage.yaml").exists()

    def test_a_new_pipeline_may_still_use_a_free_key(self, wired):
        entry = A.save_pipeline(
            "triage",
            'name: triage\nphases: [strings]\nenvironment:\n  TRACE_FILE: "t.log"\n',
        )
        assert entry["environment"][0]["key"] == "TRACE_FILE"

    def test_a_new_pipeline_cannot_bake_in_a_key_its_plan_ignores(self, wired):
        # The document-level twin of the write-route refusal: the wizard writes
        # phases and environment keys in one act, so an ML key on a plan with
        # no model phase is refused at save time, not discovered inert later.
        # Phase-scoped keys are refused on scope, so any ML key serves.
        with pytest.raises(ValueError, match="Analysis Configuration"):
            A.save_pipeline(
                "triage",
                'name: triage\nphases: [strings]\nenvironment:\n  ML_TOP_K: "3"\n',
            )
        assert not (wired / "pipelines" / "triage.yaml").exists()

    def test_editing_another_key_is_not_blocked_by_a_stale_line(self, wired):
        # The gate is per-key, not per-file, and it has to be: a pipeline that
        # still carries a stale line is exactly the file an operator needs to
        # edit to clear it, so refusing every edit because of it would make the
        # only way out a text editor.
        path = wired / "pipelines" / "legacy.yaml"
        path.write_text(
            'name: legacy\nphases: [strings]\nenvironment:\n  CTI_SKIP: "0"\n',
            encoding="utf-8",
        )
        entry = A.write_environment("legacy", {"TRACE_FILE": "t.log"})
        assert sorted(e["key"] for e in entry["environment"]) == ["CTI_SKIP", "TRACE_FILE"]
        assert next(e for e in entry["environment"] if e["key"] == "CTI_SKIP")["shadowed"]

    def test_an_existing_inert_line_is_reported_not_hidden(self, wired):
        # The file already says it, and someone reading the YAML has to be able
        # to find out that it does not apply.
        path = wired / "pipelines" / "legacy.yaml"
        path.write_text(
            'name: legacy\nphases: [strings]\nenvironment:\n  CTI_SKIP: "0"\n',
            encoding="utf-8",
        )
        (A.PIPELINE_DIR / "caps.yaml").write_text(
            'name: caps\nphases: [strings]\nenvironment:\n  ML_TOP_K: "3"\n',
            encoding="utf-8",
        )
        by_name = {p["name"]: p for p in A._pipelines(A._catalog())}
        legacy_env = {e["key"]: e for e in by_name["legacy"]["environment"]}
        assert legacy_env["CTI_SKIP"]["shadowed"] is True
        caps_env = {e["key"]: e for e in by_name["caps"]["environment"]}
        assert caps_env["ML_TOP_K"]["shadowed"] is False

    def test_clearing_the_global_key_frees_it_again(self, wired):
        # The rule has to be reversible from the other page, or a setting could
        # only ever be set once and never adjusted. A run-wide key carries the
        # assertion now: a phase-scoped key is refused on scope after handback,
        # which its own test pins.
        S.write_settings(wired, {"TRACE_FILE": None})
        assert "TRACE_FILE" not in A._global_keys()
        path = wired / "pipelines" / "caps.yaml"
        path.write_text(
            'name: caps\nphases: [strings]\n', encoding="utf-8"
        )
        entry = A.write_environment("caps", {"TRACE_FILE": "t.log"})
        assert entry["environment"][0]["key"] == "TRACE_FILE"

    def test_a_phase_scoped_key_stays_refused_after_handback(self, wired):
        # Clearing the global key does NOT reopen per-pipeline writes of a
        # phase-scoped one - scope is a property of the key, not of who owns it
        # this week.
        S.write_settings(wired, {"CTI_SKIP": None})
        assert "CTI_SKIP" not in A._global_keys()
        path = wired / "pipelines" / "caps.yaml"
        path.write_text(
            'name: caps\nphases: [strings, cti]\n', encoding="utf-8"
        )
        with pytest.raises(ValueError, match="Analysis Configuration"):
            A.write_environment("caps", {"CTI_SKIP": True})


class TestSetValues:
    """What the pipelines page is told the global file says."""

    def test_values_are_rendered_as_the_file_writes_them(self, repo):
        # The reader compares this against the YAML they can open in the same
        # console, so Python's repr("1") would be a lie of presentation.
        (repo / "config" / "analysis.yaml").write_text(
            'ML_SKIP: true\nCTI_SKIP: "1"\nML_TOP_K: 10\n', encoding="utf-8"
        )
        assert S.set_values(repo) == {
            "ML_SKIP": "true", "CTI_SKIP": "1", "ML_TOP_K": "10",
        }

    def test_a_nested_value_is_skipped_rather_than_shown(self, repo):
        # The analyzer exits 2 on a non-scalar, so there is no value to display.
        # The unknown-key alert on the global page is where that gets reported.
        (repo / "config" / "analysis.yaml").write_text(
            "ML_SKIP:\n  a: 1\n", encoding="utf-8"
        )
        assert S.set_values(repo) == {}

    def test_an_unreadable_file_yields_nothing_rather_than_raising(self, repo):
        # The analyzer refuses to start on this file anyway, and this collector
        # runs inside the snapshot that explains why. Raising here would replace
        # that explanation with a 500.
        (repo / "config" / "analysis.yaml").write_text(
            "ML_SKIP: [unclosed\n", encoding="utf-8"
        )
        assert S.set_values(repo) == {}
        assert S.set_keys(repo) == set()

    def test_the_file_only_ever_holds_keys_the_analyzer_reads(self):
        # This used to assert the file sets *nothing*, on the grounds that an
        # empty file is why the pipelines page can offer every option. That was
        # asserting local state as if it were a property of the project: the
        # console writes this file from a browser, so an operator setting
        # ML_SKIP globally is doing exactly what it is for, and the test went red
        # for it. Observed, in fact, on the first run after the page shipped.
        #
        # The invariant that is actually the project's is the narrower one: a key
        # in this file is a key the analyzer reads. A drift here means every run
        # exits 2 at startup, which no operator action can be blamed for.
        stray = [k for k in S.set_values(REPO) if k not in ENV_BY_KEY]
        assert not stray, (
            f"config/analysis.yaml has keys the analyzer refuses: {stray}"
        )


class TestShippedConfigIsValid:
    def test_the_config_that_ships_parses_and_uses_only_known_keys(self):
        # The all-comments default is what every checkout starts with. If this
        # ever stops parsing, every run in every checkout fails at startup.
        path = REPO / "config" / "analysis.yaml"
        assert path.exists(), "config/analysis.yaml is missing"
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        assert isinstance(data, dict)
        stray = [k for k in data if k not in ENV_BY_KEY]
        assert not stray, f"config/analysis.yaml has keys the analyzer refuses: {stray}"


class TestPanelAndBinaryAgree:
    """The one list in Python against the one list in C++."""

    def _cpp_keys(self) -> list[str]:
        source = (REPO / "src/main/analysis_config.cpp").read_text(encoding="utf-8")
        block = re.search(
            r"static const std::vector<std::string> kKeys\{(.*?)\};", source, re.S
        )
        assert block, "known_analysis_keys() not found in analysis_config.cpp"
        return re.findall(r'"([A-Z_]+)"', block.group(1))

    def test_the_two_lists_are_identical(self):
        assert set(self._cpp_keys()) == set(ENV_BY_KEY)

    def test_the_order_matches_so_the_ui_does_not_reorder_under_the_operator(self):
        assert self._cpp_keys() == [o["key"] for o in ENV_OPTIONS]

    @pytest.mark.skipif(
        not (REPO / "build-ucrt/static_analyzer.exe").exists(),
        reason="analyzer not built",
    )
    def test_the_built_binary_starts_with_the_shipped_config(self):
        # End to end for the thing these tests are really about: the stock
        # config must not stop the analyzer from starting. The first version of
        # the loader rejected a comment-only file, so this was worth pinning.
        proc = subprocess.run(
            [str(REPO / "build-ucrt/static_analyzer.exe"), "--version"],
            capture_output=True, text=True, cwd=REPO, timeout=60,
        )
        assert proc.returncode == 0, proc.stderr or proc.stdout
        assert "analysis config error" not in (proc.stderr + proc.stdout)