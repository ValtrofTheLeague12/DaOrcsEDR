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
from panel.utils import utils  # noqa: E402


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
        # The endpoint is stubbed shut. It used to rely on nothing happening to
        # be listening on 11434, which is an assumption about the machine rather
        # than about the code - and it failed on any workstation that had Ollama
        # running, which is exactly the machine most likely to run this.
        monkeypatch.setattr(yara_gen, "_port_open", lambda url, timeout=1.0: False)
        ok, why = yara_gen._llm_usable()
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

    def test_unresolved_components_keep_what_they_do(self, monkeypatch, tmp_path):
        # The generator has always written both keys; passing only the names
        # left the card rendering a comma-joined string of identifiers, which is
        # the thing the detail list exists to stop being.
        import json
        detail = {"name": "gnurx",
                  "description": "POSIX regexp compatibility library [Windows system library]"}
        summary = tmp_path / "sbom_summary.json"
        summary.write_text(json.dumps({
            "generated_at": "2026-01-01T00:00:00+00:00",
            "unresolved_versions": ["gnurx"],
            "unresolved_details": [detail],
        }), encoding="utf-8")
        monkeypatch.setattr(utils, "SBOM_SUMMARY", summary)
        monkeypatch.setattr(utils, "SBOM_JSON", tmp_path / "sbom.json")
        monkeypatch.setattr(utils, "_head_commit_date", lambda _cwd: None)
        state = utils.sbom()
        assert state["unresolved"] == ["gnurx"]
        assert state["unresolved_details"] == [detail]

    def test_a_summary_without_details_reports_none(self, monkeypatch, tmp_path):
        # An older summary already on disk must not raise; the card falls back
        # to the bare names rather than showing an empty list as a fact.
        import json
        summary = tmp_path / "sbom_summary.json"
        summary.write_text(json.dumps({"generated_at": "2026-01-01T00:00:00+00:00",
                                       "unresolved_versions": ["curl"]}),
                           encoding="utf-8")
        monkeypatch.setattr(utils, "SBOM_SUMMARY", summary)
        monkeypatch.setattr(utils, "SBOM_JSON", tmp_path / "sbom.json")
        monkeypatch.setattr(utils, "_head_commit_date", lambda _cwd: None)
        assert utils.sbom()["unresolved_details"] == []


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
    """MalAPI rules are a scraped mirror, not a git checkout.

    These replace tests that asserted the old behaviour - that a missing `malt/`
    made the rules unavailable - which described a repository that has nothing to
    do with the rules.
    """

    def test_a_missing_mirror_is_reported(self, monkeypatch, tmp_path):
        monkeypatch.setattr(utils, "MALAPI_SITE", tmp_path / "absent")
        monkeypatch.setattr(utils, "MALAPI_YAML", tmp_path / "absent")
        state = utils.malapi()
        assert state["available"] is False
        assert "never been mirrored" in state["reason"]

    def test_a_missing_generated_api_is_reported(self, monkeypatch, tmp_path):
        monkeypatch.setattr(utils, "MALAPI_SITE", tmp_path)
        monkeypatch.setattr(utils, "MALAPI_YAML", tmp_path)
        monkeypatch.setattr(utils, "MALAPI_SERVER", tmp_path / "absent.py")
        state = utils.malapi()
        assert state["available"] is False
        assert "nothing to query" in state["reason"]

    def test_an_api_older_than_its_mirror_is_flagged(self, monkeypatch, tmp_path):
        # The combination that silently serves old rules: the site was
        # re-mirrored but python/api/server.py was never regenerated from it.
        site = tmp_path / "site"
        yaml = tmp_path / "yaml"
        site.mkdir()
        yaml.mkdir()
        (site / "new.html").write_text("x", encoding="utf-8")
        (yaml / "a.yaml").write_text("x", encoding="utf-8")
        # Mirror is the newer of the two.
        import os, time
        old = time.time() - 86400
        os.utime(yaml / "a.yaml", (old, old))
        monkeypatch.setattr(utils, "MALAPI_SITE", site)
        monkeypatch.setattr(utils, "MALAPI_YAML", yaml)
        monkeypatch.setattr(utils, "MALAPI_SERVER", yaml / "server.py")
        monkeypatch.setattr(utils, "MALAPI_LOCK", tmp_path / "nope.lock")
        state = utils.malapi()
        assert state["generated_stale"] is True
        assert "no longer match the site" in state["reason"]

    def test_a_stale_httrack_lock_is_reported_but_still_runnable(self, monkeypatch, tmp_path):
        # httrack refuses to start while this file exists, but the scrape stage
        # clears a lock older than a day itself before mirroring (see
        # malapi_pipeline.stage_scrape). So a stale lock is worth saying out
        # loud and is NOT a reason to disable the button - disabling it here is
        # what left the card refusing a refresh that would have succeeded.
        site = tmp_path / "site"
        yaml = tmp_path / "yaml"
        site.mkdir()
        yaml.mkdir()
        (site / "a.html").write_text("x", encoding="utf-8")
        (yaml / "a.yaml").write_text("x", encoding="utf-8")
        lock = tmp_path / "hts-in_progress.lock"
        lock.write_text("Mirror in progress", encoding="utf-8")
        import os, time
        stale = time.time() - 3 * 86400
        os.utime(lock, (stale, stale))
        monkeypatch.setattr(utils, "MALAPI_SITE", site)
        monkeypatch.setattr(utils, "MALAPI_YAML", yaml)
        monkeypatch.setattr(utils, "MALAPI_SERVER", yaml / "server.py")
        monkeypatch.setattr(utils, "MALAPI_LOCK", lock)
        monkeypatch.setattr(utils, "_httrack_available", lambda: (True, None))
        state = utils.malapi()
        assert state["lock"]["stale"] is True
        assert state["lock"]["age_days"] == 3
        assert state["blocked"] is False
        assert state["blocked_reason"] is None
        # ...and the action the card offers stays enabled.
        entry = next(e for e in utils.catalogue()["entries"] if e["id"] == "malapi-update")
        assert entry["available"] is True
        assert entry["unavailable_reason"] is None

    def test_a_live_lock_blocks_the_refresh_and_says_why(self, monkeypatch, tmp_path):
        # Under a day could be a real mirror running, and the scrape stage
        # leaves those alone. This is the lock that genuinely prevents a run,
        # and it reports minutes rather than "0 days old".
        site = tmp_path / "site"
        yaml = tmp_path / "yaml"
        site.mkdir()
        yaml.mkdir()
        (site / "a.html").write_text("x", encoding="utf-8")
        (yaml / "a.yaml").write_text("x", encoding="utf-8")
        lock = tmp_path / "hts-in_progress.lock"
        lock.write_text("Mirror in progress", encoding="utf-8")
        import os, time
        fresh = time.time() - 45 * 60
        os.utime(lock, (fresh, fresh))
        monkeypatch.setattr(utils, "MALAPI_SITE", site)
        monkeypatch.setattr(utils, "MALAPI_YAML", yaml)
        monkeypatch.setattr(utils, "MALAPI_SERVER", yaml / "server.py")
        monkeypatch.setattr(utils, "MALAPI_LOCK", lock)
        monkeypatch.setattr(utils, "_httrack_available", lambda: (True, None))
        state = utils.malapi()
        assert state["blocked"] is True
        assert state["lock"]["age_minutes"] == 45
        assert "45 minutes" in state["blocked_reason"]
        entry = next(e for e in utils.catalogue()["entries"] if e["id"] == "malapi-update")
        assert entry["available"] is False
        assert entry["unavailable_reason"] == state["blocked_reason"]

    def test_a_fresh_lock_is_not_treated_as_stale(self, monkeypatch, tmp_path):
        # Under a day could be a real mirror running. Reporting that as stale
        # would have the panel deleting a live mirror's lock.
        site = tmp_path / "site"
        yaml = tmp_path / "yaml"
        site.mkdir()
        yaml.mkdir()
        (site / "a.html").write_text("x", encoding="utf-8")
        (yaml / "a.yaml").write_text("x", encoding="utf-8")
        lock = tmp_path / "hts-in_progress.lock"
        lock.write_text("Mirror in progress", encoding="utf-8")
        monkeypatch.setattr(utils, "MALAPI_SITE", site)
        monkeypatch.setattr(utils, "MALAPI_YAML", yaml)
        monkeypatch.setattr(utils, "MALAPI_SERVER", yaml / "server.py")
        monkeypatch.setattr(utils, "MALAPI_LOCK", lock)
        monkeypatch.setattr(utils, "_httrack_available", lambda: (True, None))
        assert utils.malapi()["lock"]["stale"] is False

    def test_a_missing_httrack_blocks(self, monkeypatch, tmp_path):
        site = tmp_path / "site"
        yaml = tmp_path / "yaml"
        site.mkdir()
        yaml.mkdir()
        (site / "a.html").write_text("x", encoding="utf-8")
        (yaml / "a.yaml").write_text("x", encoding="utf-8")
        monkeypatch.setattr(utils, "MALAPI_SITE", site)
        monkeypatch.setattr(utils, "MALAPI_YAML", yaml)
        monkeypatch.setattr(utils, "MALAPI_SERVER", yaml / "server.py")
        monkeypatch.setattr(utils, "MALAPI_LOCK", tmp_path / "nope.lock")
        monkeypatch.setattr(utils, "_httrack_available",
                            lambda: (False, "httrack is not installed in WSL"))
        state = utils.malapi()
        assert state["blocked"] is True
        assert "httrack" in state["blocked_reason"].lower()

    def test_the_state_does_not_claim_to_be_up_to_date(self, monkeypatch, tmp_path):
        # malapi.io publishes no version to pull against, so "up to date" is not
        # a state this can honestly report. The field the old card rendered is
        # gone rather than repopulated with a guess.
        state = utils.malapi()
        assert "up_to_date" not in state
        assert "behind" not in state
        assert "ahead" not in state

    def test_the_malt_tool_is_reported_as_not_the_rules(self, monkeypatch, tmp_path):
        tool = tmp_path / "malt"
        (tool / ".git").mkdir(parents=True)
        monkeypatch.setattr(utils, "MALT_DIR", tool)
        state = utils.malapi()
        assert state["malt_tool"]["used_by_analyzer"] is False
        assert "not the rules" in state["malt_tool"]["note"]


class TestMalapiUpdateRunsTheRules:
    """The button has to update the rules, not a repository that has none."""

    def test_the_command_mirrors_the_site_and_regenerates(self):
        argv = utils._argv("malapi")
        joined = " ".join(argv)
        assert "malapi_pipeline.py" in joined, joined
        assert "--with-scrape" in joined, joined
        # The thing it used to do instead, which changed nothing about the rules.
        assert "pull" not in joined, joined
        assert "malt" not in joined.lower(), joined

    def test_the_effects_say_what_it_rewrites(self):
        entry = {e["id"]: e for e in utils.catalogue()["entries"]}["malapi-update"]
        joined = " ".join(entry["effects"]).lower()
        assert "network" in joined
        assert "python/yaml/malapi/" in joined
        assert "python/api/server.py" in joined


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

    def test_every_unavailable_entry_says_why(self, monkeypatch, tmp_path):
        # The UI shows `unavailable_reason` in the button's tooltip and falls
        # back to the bare word "unavailable" when it is null. A disabled
        # button with no reason is the state this page had for the MalAPI
        # refresh: reading a `can_update` key that malapi() never returned left
        # it unavailable with nothing to tell the operator.
        monkeypatch.setattr(utils, "_httrack_available", lambda: (False, "httrack is not installed in WSL"))
        for entry in utils.catalogue()["entries"]:
            if not entry["available"]:
                assert entry["unavailable_reason"], f"{entry['id']} is disabled and says nothing"

    def test_an_absent_mirror_does_not_disable_the_refresh(self, monkeypatch, tmp_path):
        # The scrape stage builds the mirror from nothing - that is what it is
        # for - so absent pieces are the strongest reason to press the button,
        # not a reason it is disabled.
        monkeypatch.setattr(utils, "MALAPI_SITE", tmp_path / "absent")
        monkeypatch.setattr(utils, "MALAPI_YAML", tmp_path / "absent")
        monkeypatch.setattr(utils, "MALAPI_SERVER", tmp_path / "absent.py")
        monkeypatch.setattr(utils, "MALAPI_LOCK", tmp_path / "nope.lock")
        monkeypatch.setattr(utils, "_httrack_available", lambda: (True, None))
        entry = {e["id"]: e for e in utils.catalogue()["entries"]}["malapi-update"]
        assert entry["available"] is True
        assert entry["unavailable_reason"] is None

    def test_git_actions_cannot_prompt_or_pull(self):
        # The MalAPI update is no longer a git operation, so what matters is
        # that nothing in this module can create history or hang on a credential
        # prompt if a git path is reintroduced. Checked in the source rather than
        # trusted: _git() is used for the reported tool checkout.
        from pathlib import Path as _Path
        source = _Path(utils.__file__).read_text(encoding="utf-8")
        assert "GIT_TERMINAL_PROMPT" in source
        assert '"pull"' not in source, "a git pull came back; that is not the rules"