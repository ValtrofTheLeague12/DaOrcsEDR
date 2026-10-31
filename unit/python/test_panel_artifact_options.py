"""The artifact/MEGA settings' single source of truth, per page.

The upload-and-seal settings moved to config/analysis.yaml (MEGA_UPLOAD and
friends), but config/artifacts.yaml keeps accepting its own copies, and the
analyzer takes analysis.yaml's value whenever it is defined - loading the file
copy only to fill the gaps. A page that reported the file copy alone would
therefore be able to say "Upload to MEGA: off" while the next run uploads
anyway; the receipt for exactly that is in the run logs.

What these tests pin:

  read   - every value _artifacts() reports is the EFFECTIVE one, and
           decided_by says which side won; a malformed MEGA_* value lets the
           file's value stand and names itself in mega_warnings, the same
           choice the planner logs
  write  - editing a key analysis.yaml owns is refused with a pointer to the
           Analysis Configuration page, exactly as a pipeline write is refused
           for a key the global file owns; free keys still land

The fixture writes both files under a tmp repo the same way the panel reads
them, so the overlay runs for real rather than being faked.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "python"))

from panel import analysis, config  # noqa: E402

ARTIFACTS_YAML = """\
store_artifact: true
upload_artifacts: false
remote_root: "/"
timeout_seconds: 900
encrypt_artifacts: false
"""


@pytest.fixture
def files(tmp_path, monkeypatch):
    cfgdir = tmp_path / "config"
    cfgdir.mkdir()
    monkeypatch.setattr(config, "REPO", tmp_path)
    monkeypatch.setattr(analysis, "ARTIFACTS_FILE", cfgdir / "artifacts.yaml")
    return cfgdir


def write(files, analysis_yaml: str) -> None:
    """artifacts.yaml is the standing default; analysis.yaml is per test."""
    (files / "artifacts.yaml").write_text(ARTIFACTS_YAML, encoding="utf-8")
    if analysis_yaml is not None:
        (files / "analysis.yaml").write_text(analysis_yaml, encoding="utf-8")


class TestEffectiveValues:

    def test_analysis_yaml_wins_over_the_file_copy(self, files):
        write(files, "MEGA_UPLOAD: true\n")
        state = analysis._artifacts()
        assert state["upload_artifacts"] is True
        assert state["decided_by"]["upload_artifacts"] == \
            "config/analysis.yaml (MEGA_UPLOAD)"

    def test_the_file_still_decides_when_analysis_yaml_stays_silent(self, files):
        # No analysis.yaml at all is the fresh-checkout shape.
        write(files, None)
        state = analysis._artifacts()
        assert state["upload_artifacts"] is False
        assert state["decided_by"]["upload_artifacts"] == "config/artifacts.yaml"

    def test_every_mega_option_is_overlaid_by_its_own_env_name(self, files):
        write(files, """\
MEGA_UPLOAD: true
MEGA_SEAL: on
MEGA_REMOTE_ROOT: "/lab/evidence"
MEGA_TIMEOUT: "5000"
""")
        state = analysis._artifacts()
        assert state["upload_artifacts"] is True
        assert state["encrypt_artifacts"] is True
        assert state["remote_root"] == "/lab/evidence"
        assert state["timeout_seconds"] == 5000
        # store_artifact is deliberately file-only: building a local bundle is
        # not a machine-level question, so nothing owns it.
        assert state["decided_by"].get("store_artifact") is None
        assert "store_artifact" not in analysis.MEGA_OVERRIDES
        # The seal's keypair env names are gone altogether, not just unwired:
        # the password scheme replaced them, and a stale MEGA_RECIPIENT in a
        # checkout must be an unknown analysis setting rather than a decision.
        assert "MEGA_RECIPIENT" not in analysis.ENV_BY_KEY
        assert "MEGA_ADMIN_PUBKEY" not in analysis.ENV_BY_KEY

    def test_a_malformed_mega_value_lets_the_file_stand_and_names_itself(self, files):
        write(files, """\
MEGA_UPLOAD: "maybe"
MEGA_TIMEOUT: "99999"
""")
        state = analysis._artifacts()
        assert state["upload_artifacts"] is False          # the file's value
        assert state["timeout_seconds"] == 900             # stands
        assert state["decided_by"]["upload_artifacts"] == "config/artifacts.yaml"
        joined = " ".join(state["mega_warnings"])
        assert "MEGA_UPLOAD" in joined and "MEGA_TIMEOUT" in joined

    def test_an_unusual_but_in_bounds_timeout_is_honoured(self, files):
        # 99 is legal - anywhere in 1..86400 is - and the analyzer would apply
        # it, so the page must too rather than treating it as malformed.
        write(files, 'MEGA_TIMEOUT: "99"\n')
        assert analysis._artifacts()["timeout_seconds"] == 99
        assert analysis._artifacts()["mega_warnings"] == []

    def test_a_blank_mega_value_is_unset_not_a_decision(self, files):
        write(files, 'MEGA_UPLOAD: ""\n')
        state = analysis._artifacts()
        assert state["upload_artifacts"] is False
        assert state["decided_by"]["upload_artifacts"] == "config/artifacts.yaml"
        assert state["mega_warnings"] == []

    def test_a_broken_artifacts_file_still_shows_the_global_choice(self, files):
        write(files, "MEGA_UPLOAD: true\n")
        (files / "artifacts.yaml").write_text("{ not: [, valid", encoding="utf-8")
        state = analysis._artifacts()
        assert state["errors"], "the broken file is reported"
        # The overlay still lands on the defaults: the uploader gate must keep
        # answering the question the run would actually be answered with.
        assert state["upload_artifacts"] is True
        assert state["decided_by"]["upload_artifacts"] == \
            "config/analysis.yaml (MEGA_UPLOAD)"


class TestGates:

    def test_the_export_gate_agrees_with_what_runs_do(self, files):
        write(files, "MEGA_UPLOAD: true\n")
        assert analysis.artifact_upload_enabled() is True
        assert analysis.artifact_upload_decision() == {
            "enabled": True,
            "decided_by": "config/analysis.yaml (MEGA_UPLOAD)",
        }

    def test_the_seal_gate_takes_mega_seal(self, files):
        write(files, "MEGA_SEAL: true\n")
        assert analysis.artifact_encrypt_enabled() is True

    def test_the_timeout_gate_takes_mega_timeout_within_bounds(self, files):
        write(files, 'MEGA_TIMEOUT: "300"\n')
        assert analysis.artifact_upload_timeout() == 300


class TestWrites:

    def test_a_write_to_an_owned_key_is_refused_with_a_pointer(self, files):
        write(files, "MEGA_UPLOAD: true\n")
        with pytest.raises(ValueError) as excinfo:
            analysis.write_artifact_options({"upload_artifacts": False})
        message = str(excinfo.value)
        assert "config/analysis.yaml" in message
        assert "MEGA_UPLOAD" in message
        assert "Analysis Configuration" in message

    def test_a_write_to_a_free_key_lands(self, files):
        write(files, "MEGA_UPLOAD: true\n")
        result = analysis.write_artifact_options({"store_artifact": False})
        assert result["store_artifact"] is False
        # The refusal list names only the keys that were actually owned, so the
        # write that lands is not shadowed by anything that was refused.
        assert result["upload_artifacts"] is True

    def test_a_write_to_a_key_nobody_owns_lands_in_the_file(self, files):
        write(files, None)
        result = analysis.write_artifact_options({"upload_artifacts": True})
        assert result["upload_artifacts"] is True
        assert result["decided_by"]["upload_artifacts"] == "config/artifacts.yaml"

    def test_the_refusal_reads_the_file_at_write_time_not_at_import(self, files):
        # analysis.yaml is empty when the process started and gains the key
        # before the write: the refusal must see it either way, because the
        # analyzer will see it on the next run.
        write(files, None)
        (files / "analysis.yaml").write_text("MEGA_SEAL: true\n", encoding="utf-8")
        with pytest.raises(ValueError) as excinfo:
            analysis.write_artifact_options({"encrypt_artifacts": True})
        assert "MEGA_SEAL" in str(excinfo.value)
