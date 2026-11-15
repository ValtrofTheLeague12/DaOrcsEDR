"""The panel's password generator, and its wiring into the bundle password.

The zip password can be generated in two modes. What matters is that both obey
the same 12..128 contract the endpoint and mega/protect.py enforce, that the
value is stored once and echoed once, and that an unknown mode is refused
rather than silently becoming random.
"""

from __future__ import annotations

import string
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "python"))
sys.path.insert(0, str(REPO / "mega"))

import protect  # noqa: E402

from panel.analysis import analysis  # noqa: E402
from panel.utils import password_generator  # noqa: E402
from panel.utils.password_generator import (  # noqa: E402
    MAX_PASSWORD,
    MIN_PASSWORD,
    PasswordGenerator,
    PasswordModes,
)


@pytest.fixture
def pfile(tmp_path, monkeypatch):
    path = tmp_path / "bundle-keys" / "upload.password"
    monkeypatch.setenv("IA_BUNDLE_PASSWORD_FILE", str(path))
    return path


class TestGenerator:

    @pytest.mark.parametrize("mode", list(PasswordModes))
    def test_both_modes_produce_exactly_the_requested_length(self, mode):
        for length in (MIN_PASSWORD, 24, 40, MAX_PASSWORD):
            value = PasswordGenerator(length, mode).generate()
            assert len(value) == length
            assert value.isascii()

    def test_random_mode_uses_the_printable_charset(self):
        value = PasswordGenerator(64, PasswordModes.RANDOM_MODE).generate()
        assert set(value) <= set(string.printable)
        assert value != PasswordGenerator(64, PasswordModes.RANDOM_MODE).generate()

    def test_stale_mode_carries_the_random_tag(self):
        value = PasswordGenerator(24, PasswordModes.STALE_MODE).generate()
        assert "#" in value
        assert len(value) == 24

    def test_lengths_are_clamped_to_the_contract(self):
        assert PasswordGenerator(2).password_length == MIN_PASSWORD
        assert len(PasswordGenerator(2).generate()) == MIN_PASSWORD
        assert PasswordGenerator(4096).password_length == MAX_PASSWORD
        assert len(PasswordGenerator(4096).generate()) == MAX_PASSWORD

    def test_a_string_mode_is_accepted(self):
        assert PasswordGenerator(24, "stale").password_mode is PasswordModes.STALE_MODE

    def test_an_unknown_mode_is_refused(self):
        with pytest.raises(ValueError, match="unknown password mode"):
            PasswordGenerator(24, "not-a-mode")

    def test_the_module_entry_point_generates(self):
        assert len(password_generator.generate_password(16)) == 16


class TestPanelWiring:

    def test_generate_uses_the_generator_and_stores_the_value(self, pfile):
        res = analysis._bundle_password_generate(24, "stale")
        assert res["ok"] is True and res["shown_once"] is True
        assert len(res["password"]) == 24
        assert "#" in res["password"]
        assert protect.read_password(pfile) == res["password"].encode()

    def test_generate_defaults_still_match_the_old_contract(self, pfile):
        res = analysis._bundle_password_generate()
        assert res["ok"] is True
        assert len(res["password"]) == 24

    def test_an_unknown_mode_is_an_error_not_a_fallback(self, pfile):
        res = analysis._bundle_password_generate(24, "nonsense")
        assert res["ok"] is False
        assert "mode" in res["error"]
        assert not pfile.exists()
