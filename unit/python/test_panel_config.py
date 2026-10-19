"""Unit tests for the panel's configuration resolver.

`panel.config.setting()` is three lines of string handling, and it is the single
place the project's configuration precedence is decided: process environment,
then the repository `.env`, then a default. Everything else - which port the
analyzer API is on, where logs go, what the bind host is - is downstream of it.

It is worth a unit test precisely because the precedence is load-bearing and was
once wrong. The analyzer's own `server.py` documented "same precedence as
server.py" while implementing none of it, so the panel dialled 60025 (from .env)
while the server listened on 60020 (its own default). Both were healthy; the
result was a dead page and a WinError 10061 that pointed nowhere useful.

These test the resolver directly, with a temporary .env, rather than by starting
services.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "python"))

from panel import config  # noqa: E402


@pytest.fixture
def env_file(tmp_path, monkeypatch):
    """Point config.ENV_FILE at a temporary .env and clear the real environment.

    Both halves matter. The real .env has values in it, so without the temporary
    file these tests would assert against whatever the operator has configured -
    and would pass on one machine and fail on another.
    """
    path = tmp_path / ".env"
    monkeypatch.setattr(config, "ENV_FILE", path)
    for name in ("SA_API_PORT", "SA_API_HOST"):
        monkeypatch.delenv(name, raising=False)
    return path


def write_env(path: Path, body: str) -> None:
    path.write_text(body, encoding="utf-8")


class TestPrecedence:
    def test_default_when_nothing_is_set(self, env_file):
        assert config.setting("SA_API_PORT", "60020") == "60020"

    def test_env_file_beats_the_default(self, env_file):
        write_env(env_file, "SA_API_PORT=60025\n")
        assert config.setting("SA_API_PORT", "60020") == "60025"

    def test_process_env_beats_the_env_file(self, env_file, monkeypatch):
        # The order that matters most. An explicit export has to win, or an
        # operator cannot override a committed .env for one run.
        write_env(env_file, "SA_API_PORT=60025\n")
        monkeypatch.setenv("SA_API_PORT", "60099")
        assert config.setting("SA_API_PORT", "60020") == "60099"

    def test_a_blank_process_value_still_wins(self, env_file, monkeypatch):
        # Present-but-empty is not the same as absent. `if name in os.environ`
        # rather than a truthiness check is deliberate: an empty export is a
        # deliberate way to blank a setting.
        write_env(env_file, "SA_API_PORT=60025\n")
        monkeypatch.setenv("SA_API_PORT", "")
        assert config.setting("SA_API_PORT", "60020") == ""


class TestParsing:
    def test_surrounding_whitespace_is_stripped(self, env_file):
        write_env(env_file, "  SA_API_PORT = 60025  \n")
        assert config.setting("SA_API_PORT", "60020") == "60025"

    def test_quotes_are_stripped(self, env_file):
        write_env(env_file, 'SA_API_PORT="60025"\n')
        assert config.setting("SA_API_PORT", "60020") == "60025"

    def test_single_quotes_are_stripped(self, env_file):
        write_env(env_file, "SA_API_PORT='60025'\n")
        assert config.setting("SA_API_PORT", "60020") == "60025"

    def test_a_prefix_of_another_name_does_not_match(self, env_file):
        # SA_API_PORT must not be satisfied by SA_API_PORT_EXTRA, which is how a
        # naive `line.startswith(name)` goes wrong.
        write_env(env_file, "SA_API_PORT_EXTRA=70000\n")
        assert config.setting("SA_API_PORT", "60020") == "60020"

    def test_comment_lines_are_ignored(self, env_file):
        write_env(env_file, "# SA_API_PORT=11111\nSA_API_PORT=60025\n")
        assert config.setting("SA_API_PORT", "60020") == "60025"

    def test_the_first_occurrence_wins(self, env_file):
        # Two writers appended to the file. Taking the last would make the
        # effective value depend on write order, which is not something a reader
        # can predict.
        write_env(env_file, "SA_API_PORT=11111\nSA_API_PORT=60025\n")
        assert config.setting("SA_API_PORT", "60020") == "11111"

    def test_a_utf8_bom_does_not_hide_the_first_line(self, env_file):
        # Windows editors add one, and it lands on the first key - which is
        # exactly the SA_API_HOST line in this project's .env.
        env_file.write_text("SA_API_HOST=127.0.0.1\n", encoding="utf-8-sig")
        assert config.setting("SA_API_HOST", "0.0.0.0") == "127.0.0.1"

    def test_a_missing_env_file_falls_back_to_the_default(self, tmp_path, monkeypatch):
        monkeypatch.setattr(config, "ENV_FILE", tmp_path / "does-not-exist")
        monkeypatch.delenv("SA_API_PORT", raising=False)
        assert config.setting("SA_API_PORT", "60020") == "60020"


class TestTypedAccessors:
    def test_setting_int_parses(self, env_file):
        write_env(env_file, "SA_API_PORT=60025\n")
        assert config.setting_int("SA_API_PORT", 60020) == 60025

    def test_setting_int_falls_back_on_garbage(self, env_file):
        # A typo in .env must not take the panel down with a ValueError; the
        # default is the safer answer, and a bad port is visible immediately.
        write_env(env_file, "SA_API_PORT=not-a-number\n")
        assert config.setting_int("SA_API_PORT", 60020) == 60020


class TestAppDataRoot:
    def test_the_root_is_keyed_on_the_app_basename(self, monkeypatch, tmp_path):
        # The rule the whole project depends on, expressed three times - here, in
        # C++ (app_paths.cpp) and in the admin terminal. All three must agree on
        # the name, or generated state ends up in three different places.
        monkeypatch.setenv("APPDATA", str(tmp_path))
        monkeypatch.delenv("IA_APPDATA_DIR", raising=False)
        assert config.appdata_root().name == "IAProject"

    def test_the_override_wins_over_appdata(self, monkeypatch, tmp_path):
        monkeypatch.setenv("IA_APPDATA_DIR", str(tmp_path / "elsewhere"))
        monkeypatch.setenv("APPDATA", str(tmp_path / "appdata"))
        assert config.appdata_root() == tmp_path / "elsewhere"