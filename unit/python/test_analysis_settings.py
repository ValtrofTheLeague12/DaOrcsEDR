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