"""Tests the YARA check's "ignore compile failures" option without yarac.

The real check compiles ~3,030 rule files one subprocess per file and takes
about a minute - fine as a button, hopeless as a unit test. What these tests
actually exercise is the *decision logic*: which files get classified how, and
what the option changes about the outcome. So the inventory and the rule
directory are faked with a handful of tiny files, one of which contains a
dangling include, which is the exact shape of the real 7 Malekith_Rules
failures.
"""

import json
import textwrap

import pytest

from panel.utils import utils


@pytest.fixture()
def fake_rules(tmp_path, monkeypatch):
    """A one-collection rule set: one compiling file, one with a bad include."""
    coll = tmp_path / "Tiny_Rules"
    coll.mkdir()
    (coll / "ok.yar").write_text(
        'rule ok_rule { condition: true }', encoding="utf-8")
    (coll / "broken.yar").write_text(
        # The real 7 failures are this shape: the index includes a file that
        # the pack does not ship.
        'include "./missing.yar"\n'
        'rule broken_rule { condition: true }', encoding="utf-8")

    monkeypatch.setattr(utils, "YARA_RULES", tmp_path)
    monkeypatch.setattr(utils, "yara", lambda: {
        "available": True,
        "collections": [{"name": coll.name, "rules": 2, "bytes": 1}],
    })
    return coll


def _run_and_collect(fake_rules, ignore):
    """Runs the check synchronously and returns (state, detail, log)."""
    jid = utils.start(["yara-check"],
                      {"ignore_compile_failures": ignore})["job_id"]
    # The thread is a daemon writing to the same in-process job dict; a short
    # bounded wait is enough for two one-file invocations of yarac.
    import time
    for _ in range(240):
        job = next(j for j in utils._jobs.values() if j["id"] == jid)
        if job["state"] != "running":
            return job
        time.sleep(0.05)
    raise AssertionError("yara check did not finish")


def config_path():
    return utils.YARA_CHECK_CONFIG


@pytest.fixture()
def clean_settings(fake_rules, monkeypatch):
    """Points the persisted setting at the temp tree and records the real one."""
    saved = utils.YARA_CHECK_CONFIG
    test_cfg = fake_rules.parent / "yara_check.json"
    monkeypatch.setattr(utils, "YARA_CHECK_CONFIG", test_cfg)
    if test_cfg.exists():
        test_cfg.unlink()
    yield test_cfg
    if saved.name.endswith("yara_check.json"):
        try:
            original = json.loads(saved.read_text(encoding="utf-8"))
        except Exception:
            original = {}
        # Tests must not flip the setting the operator actually has.
        saved.write_text(json.dumps(original, indent=2, sort_keys=True),
                         encoding="utf-8")


class TestIgnoreCompileFailures:

    def test_off_still_fails_and_names_the_file(self, clean_settings,
                                                fake_rules):
        job = _run_and_collect(fake_rules, ignore=False)
        row = next(r for r in job["results"] if r["id"] == "yara-check")
        assert row["state"] == "failed"
        assert "1/2" in row["detail"]
        assert not (clean_settings.parent / "yara_check.json").exists() or \
            json.loads(clean_settings.read_text())["ignore_compile_failures"] \
            is False

    def test_on_passes_but_still_names_the_file(self, clean_settings,
                                                fake_rules):
        job = _run_and_collect(fake_rules, ignore=True)
        row = next(r for r in job["results"] if r["id"] == "yara-check")
        # It passes...
        assert row["state"] == "passed"
        # ...and says in the detail exactly what it swallowed.
        assert "ignoring 1" in row["detail"]
        # The log calls the failure IGNORE rather than FAIL, so the word FAIL
        # still appears next to nothing that passed.
        fails = [ln for ln in job["log"] if "broken.yar" in ln]
        assert fails and all(ln.startswith("    IGNORE") for ln in fails)
        # And it is honest about what was ignored: the missing include itself.
        assert any("missing.yar" in ln for ln in job["log"])

    def test_setting_is_remembered_across_runs(self, clean_settings,
                                               fake_rules):
        _run_and_collect(fake_rules, ignore=True)
        assert json.loads(clean_settings.read_text(
            encoding="utf-8"))["ignore_compile_failures"] is True

    def test_state_reports_the_persisted_switch(self, clean_settings):
        # Deliberately not via utils.yara(): the sample fixture fakes that with
        # an inventory stub, and a test that asserts on a stub is a test of the
        # stub. The settings loader is the thing under test.
        clean_settings.write_text(
            json.dumps({"ignore_compile_failures": True}), encoding="utf-8")
        assert utils._yara_check_settings()["ignore_compile_failures"] is True

    def test_unreadable_config_is_defaults_not_a_crash(self, clean_settings,
                                                       monkeypatch):
        clean_settings.write_text("{not json", encoding="utf-8")
        assert utils._yara_check_settings() == {
            "ignore_compile_failures": False}
