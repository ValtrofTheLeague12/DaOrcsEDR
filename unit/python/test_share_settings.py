"""config/share.json: the expiry applied to public MEGA links.

MEGA's duration grammar is terse and case-sensitive - ``M`` is minutes and
``m`` is months - so the setting is validated rather than passed through. The
tests pin three behaviours the UI depends on:

  * a compound duration such as ``1m12d3h`` is valid, a bare ``7`` is not;
  * an empty value means "permanent" and ``None`` is how the API clears it;
  * a file that cannot be read makes link creation refuse. Falling back to
    permanent there would publish a link that outlives the operator's policy,
    which is the exact failure the setting exists to prevent.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "python"))

from panel.artifacts import share_settings  # noqa: E402


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    return tmp_path


def _write(repo: Path, body) -> Path:
    path = repo / share_settings.CONFIG_RELATIVE
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body if isinstance(body, str) else json.dumps(body),
                    encoding="utf-8")
    return path


class TestDurations:

    @pytest.mark.parametrize("value", [
        "1s", "1M", "12h", "7d", "1m", "2y", "1m12d3h", "0s1d",
    ])
    def test_a_mega_duration_is_accepted(self, value):
        assert share_settings.valid_duration(value)

    @pytest.mark.parametrize("value", [
        "", "  ", "7", "d", "7D", "-7d", "7 days", "0d", "7z", "1.5d", "abc",
    ])
    def test_anything_else_is_refused(self, value):
        assert not share_settings.valid_duration(value)

    def test_describe_spells_the_units_out(self):
        assert share_settings.describe("7d") == "7 days"
        assert share_settings.describe("1m12d3h") == "1 month 12 days 3 hours"
        assert share_settings.describe("1s") == "1 second"
        assert share_settings.describe("nope") == ""


class TestRead:

    def test_a_missing_file_is_permanent_and_not_an_error(self, repo):
        state = share_settings.read(repo)
        assert state["exists"] is False
        assert state["link_expire"] == ""
        assert state["error"] is None

    def test_a_value_is_read_with_its_summary(self, repo):
        _write(repo, {"link_expire": "12h"})
        state = share_settings.read(repo)
        assert state["exists"] is True
        assert state["link_expire"] == "12h"
        assert state["summary"] == "12 hours"
        assert state["error"] is None

    def test_an_empty_value_is_permanent(self, repo):
        _write(repo, {"link_expire": ""})
        assert share_settings.read(repo)["link_expire"] == ""

    def test_none_is_read_as_empty(self, repo):
        _write(repo, {"link_expire": None})
        state = share_settings.read(repo)
        assert state["link_expire"] == ""
        assert state["error"] is None

    def test_an_invalid_duration_is_reported(self, repo):
        _write(repo, {"link_expire": "7 days"})
        state = share_settings.read(repo)
        assert state["link_expire"] == "7 days"
        assert "not a MEGA duration" in state["error"]

    def test_corrupt_json_is_reported_not_raised(self, repo):
        _write(repo, "{")
        state = share_settings.read(repo)
        assert "not valid JSON" in state["error"]
        assert state["link_expire"] == ""

    def test_a_non_object_is_reported(self, repo):
        _write(repo, '["7d"]')
        assert "must be a JSON object" in share_settings.read(repo)["error"]

    def test_a_non_text_value_is_reported(self, repo):
        _write(repo, {"link_expire": 7})
        assert "must be text" in share_settings.read(repo)["error"]


class TestExpire:

    def test_unset_is_none(self, repo):
        assert share_settings.expire(repo) == (None, None)

    def test_a_valid_value_is_returned(self, repo):
        _write(repo, {"link_expire": "7d"})
        assert share_settings.expire(repo) == ("7d", None)

    def test_a_broken_file_is_an_error_not_permanent(self, repo):
        _write(repo, "{")
        value, why = share_settings.expire(repo)
        assert value is None
        assert why and "not valid JSON" in why

    def test_an_invalid_value_is_an_error(self, repo):
        _write(repo, {"link_expire": "7 days"})
        value, why = share_settings.expire(repo)
        assert value is None
        assert why and "not a MEGA duration" in why


class TestWrite:

    def test_it_sets_the_value(self, repo):
        result = share_settings.write(repo, {"link_expire": "7d"})
        assert result["link_expire"] == "7d"
        assert share_settings.read(repo)["link_expire"] == "7d"

    def test_none_clears_it_to_permanent(self, repo):
        _write(repo, {"link_expire": "7d"})
        result = share_settings.write(repo, {"link_expire": None})
        assert result["link_expire"] == ""
        assert share_settings.read(repo)["link_expire"] == ""

    def test_an_empty_string_clears_it(self, repo):
        _write(repo, {"link_expire": "7d"})
        share_settings.write(repo, {"link_expire": ""})
        assert share_settings.read(repo)["link_expire"] == ""

    def test_it_leaves_unrelated_keys_alone(self, repo):
        _write(repo, {"link_expire": "", "something_else": 5})
        share_settings.write(repo, {"link_expire": "1d"})
        data = json.loads((repo / share_settings.CONFIG_RELATIVE).read_text("utf-8"))
        assert data == {"link_expire": "1d", "something_else": 5}

    def test_it_rejects_an_unknown_key(self, repo):
        with pytest.raises(ValueError, match="not a share setting: link_expiry"):
            share_settings.write(repo, {"link_expiry": "7d"})

    def test_it_rejects_an_invalid_duration(self, repo):
        with pytest.raises(ValueError, match="MEGA duration"):
            share_settings.write(repo, {"link_expire": "7 days"})

    def test_it_rejects_a_non_text_value(self, repo):
        with pytest.raises(ValueError, match="must be text"):
            share_settings.write(repo, {"link_expire": 7})

    def test_it_refuses_to_overwrite_corrupt_json(self, repo):
        _write(repo, "{")
        with pytest.raises(ValueError, match="not valid JSON"):
            share_settings.write(repo, {"link_expire": "7d"})
        # The broken file is still there; a repair must not lose unseen keys.
        assert (repo / share_settings.CONFIG_RELATIVE).read_text("utf-8") == "{"

    def test_an_empty_patch_reads_only(self, repo):
        _write(repo, {"link_expire": "2h"})
        assert share_settings.write(repo, {})["link_expire"] == "2h"


class TestSnapshot:

    def test_it_lists_the_units_and_an_example(self, repo):
        _write(repo, {"link_expire": "7d"})
        snap = share_settings.snapshot(repo)
        assert snap["link_expire"] == "7d"
        assert snap["path"] == "config/share.json"
        assert [u["value"] for u in snap["units"]] == ["s", "M", "h", "d", "m", "y"]
        assert "1m12d3h" in snap["example"]
