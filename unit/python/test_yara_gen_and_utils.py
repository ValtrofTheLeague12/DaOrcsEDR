"""Unit tests for python/yara_gen.py and the panel's utils module.

Both wrap a subprocess and both have a decision layer worth pinning:

yara_gen decides whether the LLM pass can actually run. That decision is not
"does config.yaml exist" - it is whether the key it points at is set, or for a
local provider whether the endpoint answers. Getting it wrong is not a degraded
run, it is a FAILED one: with `api_key: "${OPENAI_API_KEY}"` unset, yarGen calls
the API, gets "Incorrect API key provided", and exits non-zero without writing a
rule file.

utils classifies YARA compile failures into "needs an absent module", "needs a
sibling rule file" and "genuinely broken". Collapsing those into pass/fail is a
lie in both directions - it reported 134 false failures before the cwd and the
error-line handling were fixed, and would report a clean corpus as broken if the
bucket boundaries moved.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "python"))
sys.path.insert(0, str(REPO))

import yara_gen  # noqa: E402
from panel import utils  # noqa: E402


# ---------------------------------------------------------------------------
# yara_gen: the LLM-usability decision
# ---------------------------------------------------------------------------

OPENAI_CONFIG = """\
llm:
  provider: "openai"
  model: "gpt-4o-mini"
  api_key: "${OPENAI_API_KEY}"
  endpoint: ""
"""

OLLAMA_CONFIG = """\
llm:
  provider: "ollama"
  model: "llama3.1"
  api_key: ""
  endpoint: "http://localhost:11434"
"""


@pytest.fixture
def config_file(tmp_path, monkeypatch):
    monkeypatch.setattr(yara_gen, "CONFIG", tmp_path / "config.yaml")
    return yara_gen.CONFIG


class TestProviderDetection:
    def test_reads_the_provider_and_endpoint(self, config_file):
        config_file.write_text(OLLAMA_CONFIG, encoding="utf-8")
        assert yara_gen._config_provider_and_endpoint() == (
            "ollama", "http://localhost:11434")

    def test_defaults_when_the_file_is_missing(self, config_file):
        assert yara_gen._config_provider_and_endpoint() == ("openai", "")

    def test_a_commented_out_provider_is_not_read(self, config_file):
        # The shipped config documents alternatives in comments. Reading those
        # would pick up whichever example happened to be last.
        config_file.write_text(
            'llm:\n  # provider: "anthropic"\n  provider: "ollama"\n'
            '  endpoint: "http://localhost:11434"\n', encoding="utf-8")
        assert yara_gen._config_provider_and_endpoint()[0] == "ollama"


class TestLlmUsability:
    def test_no_config_means_unusable(self, config_file):
        ok, why = yara_gen._llm_usable()
        assert ok is False
        assert "config.yaml" in why

    def test_a_missing_key_is_unusable_and_names_it(self, config_file, monkeypatch):
        config_file.write_text(OPENAI_CONFIG, encoding="utf-8")
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        ok, why = yara_gen._llm_usable()
        assert ok is False
        # The reason has to name the variable, or the operator is told only that
        # "something is missing".
        assert "OPENAI_API_KEY" in why

    def test_a_present_key_is_usable(self, config_file, monkeypatch):
        config_file.write_text(OPENAI_CONFIG, encoding="utf-8")
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
        assert yara_gen._llm_usable()[0] is True

    def test_a_commented_example_is_not_a_requirement(self, config_file, monkeypatch):
        # This is a bug that shipped in the first version of this check: the
        # config's own documentation writes ${VAR} while explaining the syntax,
        # and a whole-file scan read that as a variable the operator had to set.
        config_file.write_text(
            '# api_key expands ${VAR} for that provider.\n' + OPENAI_CONFIG,
            encoding="utf-8")
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
        ok, why = yara_gen._llm_usable()
        assert ok is True, why

    def test_ollama_needs_no_key(self, config_file, monkeypatch):
        # The bug that matters most: requiring OPENAI_API_KEY for a LOCAL model
        # would refuse a working setup and blame a variable with nothing to do
        # with it.
        config_file.write_text(OLLAMA_CONFIG, encoding="utf-8")
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        ok, why = yara_gen._llm_usable()
        # Nothing is listening in CI, so this reports the endpoint - which is the
        # actionable half and the whole point of the distinction.
        assert ok is False
        assert "ollama" in why and "11434" in why

    def test_ollama_is_usable_when_the_endpoint_answers(self, config_file, monkeypatch):
        config_file.write_text(OLLAMA_CONFIG, encoding="utf-8")
        monkeypatch.setattr(yara_gen, "_port_open", lambda url, timeout=1.0: True)
        assert yara_gen._llm_usable() == (True, "")


# ---------------------------------------------------------------------------
# yara_gen: counting rules in the output
# ---------------------------------------------------------------------------

class TestRuleCounting:
    def test_counts_simple_rules(self):
        text = 'rule alpha {\n  strings:\n    $a = "x"\n  condition:\n    $a\n}\n'
        assert yara_gen._count_rules(text) == (1, 0)

    def test_counts_super_rules_separately(self):
        # A super rule declares its members: `rule Super : a b c {`. Counting it
        # as a simple rule would report a different number than the rule file
        # actually contains, which is the artifact that ships.
        text = (
            'rule alpha {\n  condition:\n    true\n}\n'
            'rule Super : alpha beta {\n  condition:\n    any of them\n}\n'
        )
        assert yara_gen._count_rules(text) == (1, 1)

    def test_a_rule_with_no_members_is_simple(self):
        text = 'rule solo {\n  condition:\n    true\n}\n'
        assert yara_gen._count_rules(text) == (1, 0)

    def test_prose_mentioning_rule_is_not_counted(self):
        text = '// this rule set has no rules at all\n/* rule fake { */\n'
        assert yara_gen._count_rules(text) == (0, 0)

    def test_empty_text_counts_zero(self):
        assert yara_gen._count_rules("") == (0, 0)


# ---------------------------------------------------------------------------
# utils: what the panel can answer without running anything
# ---------------------------------------------------------------------------

class TestSbomState:
    def test_reports_absent_rather_than_raising(self, monkeypatch, tmp_path):
        monkeypatch.setattr(utils, "SBOM_SUMMARY", tmp_path / "absent.json")
        state = utils.sbom()
        assert state["available"] is False
        assert state["stale"] is None
        assert "not been generated" in state["reason"]

    def test_reports_unparseable_rather_than_raising(self, monkeypatch, tmp_path):
        broken = tmp_path / "sbom_summary.json"
        broken.write_text("{ not json", encoding="utf-8")
        monkeypatch.setattr(utils, "SBOM_SUMMARY", broken)
        state = utils.sbom()
        assert state["available"] is False
        assert "could not read" in state["reason"]


class TestYaraInventory:
    def test_a_missing_directory_is_reported_not_fatal(self, monkeypatch, tmp_path):
        monkeypatch.setattr(utils, "YARA_RULES", tmp_path / "absent")
        state = utils.yara()
        assert state["available"] is False
        assert state["total"] == 0

    def test_the_packs_have_no_upstream_and_say_so(self, monkeypatch, tmp_path):
        # yara-rules/ is five unpacked collections, not a checkout. The page must
        # say there is no update rather than omit a button the admin expects.
        root = tmp_path / "yara-rules"
        (root / "pack").mkdir(parents=True)
        (root / "pack" / "a.yar").write_text("rule a { condition: true }", encoding="utf-8")
        monkeypatch.setattr(utils, "YARA_RULES", root)
        state = utils.yara()
        assert state["total"] == 1
        assert state["can_update"] is False
        assert "no recorded upstream" in state["update_reason"]


class TestMalapiState:
    def test_a_missing_checkout_is_reported(self, monkeypatch, tmp_path):
        monkeypatch.setattr(utils, "MALT_DIR", tmp_path / "absent")
        state = utils.malapi()
        assert state["available"] is False
        assert state["can_update"] is False

    def test_a_non_git_directory_cannot_be_updated(self, monkeypatch, tmp_path):
        # Being present is not enough: `git pull` needs a checkout, and the page
        # has to say so rather than offering a button that fails.
        plain = tmp_path / "malt"
        plain.mkdir()
        monkeypatch.setattr(utils, "MALT_DIR", plain)
        state = utils.malapi()
        assert state["available"] is False
        assert "not a git checkout" in state["reason"]


class TestCatalogueSafety:
    def test_every_entry_declares_what_it_touches(self):
        # A utility that reaches the network or rewrites files must say so, and
        # the UI renders these as chips. An entry with an empty effects list is
        # how a 794 MB download ends up behind an unlabelled button.
        for entry in utils.catalogue()["entries"]:
            assert entry["effects"], f"{entry['id']} declares no side effects"

    def test_the_network_reaching_entries_say_so(self):
        by_id = {e["id"]: e for e in utils.catalogue()["entries"]}
        for util in ("malapi-update", "yargen-update"):
            joined = " ".join(by_id[util]["effects"])
            assert "network" in joined.lower(), f"{util} hides that it uses the network"

    def test_the_pull_is_fast_forward_only(self):
        # Checked in the runner's argv rather than trusted: a merge commit
        # created by a browser button is not a thing anyone wants to unpick.
        from pathlib import Path as _Path
        source = _Path(utils.__file__).read_text(encoding="utf-8")
        assert '"--ff-only"' in source
        assert "GIT_TERMINAL_PROMPT" in source