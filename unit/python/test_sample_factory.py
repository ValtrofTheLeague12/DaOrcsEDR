"""The sample factory's contract, without invoking a real compiler.

Everything here runs against a stubbed `_POPEN` (the module's one indirection,
same discipline as test_panel_pipeline_run) or against pure composition, so a
full suite lands well under a second even though the factory's real job ends
in a compiled binary.

What the tests actually pin:

  * the offer is honest: languages, checkbox names and presets come from the
    module, every template's features are valid for its language, and every
    checkbox is described - a checkbox without a description is a switch
    nobody can audit;
  * noise is what it claims: a TEST-NET-3 IP (RFC 5737 - unroutable by
    design) and one of the known benign domains, present in the composed
    source; without the checkbox, neither appears anywhere in it;
  * composition refusals are sentences: unknown language, unknown template,
    unknown feature;
  * generate() writes the composed source, returns repo-relative paths the
    run card can take as-is, links statically, and surfaces a failed compile
    as a refusal that carries the compiler's log;
  * a generated name is validated outright - path characters are refused,
    not escaped - and the samples directory prunes itself at a cap.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "python"))

from panel import config  # noqa: E402
from panel import sample_factory as sf  # noqa: E402


@pytest.fixture()
def compiler(repo, monkeypatch):
    """A stubbed compile step, plus a fake UCRT64 tree with both exes in it."""
    calls: list[list[str]] = []

    def fake_popen(argv, **kwargs):
        calls.append(list(argv))
        # The "compiler": touch the output path it was told to write.
        Path(argv[argv.index("-o") + 1]).write_bytes(b"MZ\0\0")
        proc = MagicMock()
        proc.returncode = 0
        proc.communicate = lambda timeout=None: ("ok", "")
        return proc

    monkeypatch.setattr(sf, "_POPEN", fake_popen)
    bin_dir = repo / "ucrt64" / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    (bin_dir / "gcc.exe").write_bytes(b"stub")
    (bin_dir / "g++.exe").write_bytes(b"stub")
    monkeypatch.setattr(sf.build, "UCRT64", repo / "ucrt64")
    return calls


@pytest.fixture()
def repo(tmp_path, monkeypatch):
    """A repo-shaped tmp tree; samples/ is created by the factory itself."""
    monkeypatch.setattr(config, "REPO", tmp_path)
    return tmp_path


# --- the offer ----------------------------------------------------------------


class TestOffer:
    def test_both_languages_have_templates(self):
        for lang in sf.LANGUAGES:
            assert sf._template(lang, f"{lang}_minimal") is not None, lang

    def test_template_ids_are_unique(self):
        ids = [t["id"] for t in sf._TEMPLATES]
        assert len(ids) == len(set(ids))

    def test_every_template_is_valid_for_its_language(self):
        for t in sf._TEMPLATES:
            allowed = sf._allowed_features(t["language"])
            stray = [f for f in t["features"] if f not in allowed]
            assert not stray, (t["id"], stray)

    def test_every_checkbox_is_described(self):
        # A checkbox whose effect cannot be named is a switch nobody audits;
        # the notes table must cover every composed fragment in use.
        for lang in sf.LANGUAGES:
            for f in sf._allowed_features(lang):
                assert f in sf._FEATURE_NOTES, (lang, f)


# --- composition and noise ----------------------------------------------------


class TestNoise:
    def test_noise_composes_into_the_source(self):
        p = sf.compose("c", None, ["noise"])
        assert p["ok"], p
        assert p["noise"]["ip"].startswith("203.0.113.")
        assert p["noise"]["domain"] in sf.KNOWN_DOMAINS
        assert p["noise"]["ip"] in p["code"]
        assert p["noise"]["domain"] in p["code"]

    def test_ip_stays_in_test_net_3(self):
        for _ in range(30):
            p = sf.compose("cpp", None, ["wide", "noise"])
            assert p["ok"]
            # 0 is the network address, 255 the broadcast: neither is a host.
            octets = p["noise"]["ip"].split(".")
            assert octets[:3] == ["203", "0", "113"]
            assert 1 <= int(octets[3]) <= 254

    def test_no_noise_means_no_ip_or_domain_in_the_text(self):
        p = sf.compose("c", "c_strings", [])
        assert p["ok"]
        assert "203.0.113" not in p["code"]
        for domain in sf.KNOWN_DOMAINS:
            assert domain not in p["code"]


class TestComposeRefusals:
    def test_unknown_language(self):
        p = sf.compose("rust", None, [])
        assert not p["ok"]
        assert "language" in p["error"]

    def test_unknown_feature_is_named(self):
        p = sf.compose("c", None, ["bogus"])
        assert not p["ok"]
        assert "bogus" in p["error"]

    def test_unknown_template_is_named(self):
        p = sf.compose("c", "c_nope", [])
        assert not p["ok"]
        assert "c_nope" in p["error"]

    def test_custom_is_not_looked_up_as_a_template(self):
        p = sf.compose("c", sf.CUSTOM_ID, ["buffer_overflow"])
        assert p["ok"], p
        assert p["features"] == ["buffer_overflow"]
        assert "strcpy(" in p["code"]

    def test_memory_fault_template_uses_every_archetype(self):
        t = sf._template("c", "c_vulns")
        for feature in ("buffer_overflow", "double_free", "uaf",
                        "stack_crash", "integer_overflow"):
            assert feature in t["features"]

    def test_a_template_and_a_delta_compose_together(self):
        # "String talker" + the noise checkbox = exactly what it says.
        p = sf.compose("c", "c_strings", ["noise"])
        assert p["ok"]
        assert p["features"] == ["strings", "wide", "noise"]
        assert "puts(" in p["code"] and p["noise"]["ip"] in p["code"]

    def test_memory_faults_call_the_codefactory_methods(self, monkeypatch):
        called = []
        names = (
            "create_buffer_overflow_issues",
            "create_double_free_issues",
            "generate_free_after_use_vuln",
            "create_stack_crash",
            "create_integer_overflow_variable",
        )
        for name in names:
            original = getattr(sf.CodeFactory, name)

            def spy(self, *args, __name=name, __original=original, **kwargs):
                called.append(__name)
                return __original(self, *args, **kwargs)

            monkeypatch.setattr(sf.CodeFactory, name, spy)
        p = sf.compose("c", "c_vulns", [])
        assert p["ok"], p
        assert set(called) == set(names)


class TestSourceShape:
    def test_c_keeps_int_main_void(self):
        p = sf.compose("c", "c_minimal", [])
        assert "int main(void) {" in p["code"]
        assert p["code"].rstrip().endswith("}")

    def test_cpp_is_int_main(self):
        p = sf.compose("cpp", "cpp_minimal", [])
        assert "int main() {" in p["code"]

    def test_source_is_rendered_from_the_c2_template(self):
        p = sf.compose("c", "c_vulns", [])
        assert p["ok"], p
        assert "return EXIT_SUCCESS;" in p["code"]
        assert "int main(void) {" in p["code"]
        assert "func_" in p["code"] and "strcpy(" in p["code"]

    def test_imports_are_guarded_for_windows_and_never_call(self):
        p = sf.compose("c", None, ["imports"])
        assert "#ifdef _WIN32" in p["code"]
        assert 'LoadLibraryA("kernel32.dll")' in p["code"]
        # Looked up, never executed: the pointer exists, Sleep does not run.
        code_without_api_name = p["code"].replace('"Sleep"', "")
        assert "Sleep(" not in code_without_api_name

    def test_headers_implore_that_nothing_is_dialled(self):
        for lang in sf.LANGUAGES:
            p = sf.compose(lang, f"{lang}_strings", ["noise"])
            assert "never dialled" in p["code"]
            assert "not a real sample" in p["code"]


# --- generate -----------------------------------------------------------------


class TestGenerate:
    def test_generated_sample_lands_in_samples_and_reaches_the_compiler(
            self, compiler):
        r = sf.generate("c", "c_strings", [], name="factory-good")
        assert r["ok"], r
        assert Path(compiler[0][0]).name == "gcc.exe"
        assert (config.REPO / r["source"]).is_file()
        assert (config.REPO / r["exe"]).is_file()
        assert r["exe"].startswith("samples/")
        assert r["source"].startswith("samples/")
        # -static so the bait runs free of the sysroot's runtime DLLs.
        assert "-static" in " ".join(compiler[0])

    def test_cpp_reaches_the_cxx_compiler(self, compiler):
        r = sf.generate("cpp", "cpp_minimal", [], name="factory-cxx")
        assert r["ok"], r
        assert Path(compiler[0][0]).name == "g++.exe"

    def test_the_written_source_is_the_composed_one(self, compiler):
        r = sf.generate("cpp", "cpp_strings", ["noise"], name="factory-src")
        assert r["ok"], r
        written = (config.REPO / r["source"]).read_text(encoding="utf-8")
        assert written == r["code"]
        assert r["noise"]["ip"] in written

    def test_compile_log_lands_in_the_refusal(self, repo, monkeypatch):
        monkeypatch.setattr(config, "REPO", repo)
        bin_dir = repo / "ucrt64" / "bin"
        bin_dir.mkdir(parents=True, exist_ok=True)
        (bin_dir / "gcc.exe").write_bytes(b"stub")
        monkeypatch.setattr(sf.build, "UCRT64", repo / "ucrt64")

        def failing_popen(argv, **kwargs):
            proc = MagicMock()
            proc.returncode = 1
            # Mirrors the real merge: stderr is piped into stdout at spawn, so
            # whatever the compiler prints arrives as `out`.
            proc.communicate = lambda timeout=None: ("sample.c:6: error: nope", "")
            return proc

        monkeypatch.setattr(sf, "_POPEN", failing_popen)
        r = sf.generate("c", "c_minimal", [], name="factory-broken")
        assert not r["ok"]
        assert "compile failed" in r["error"]
        assert "error: nope" in r["log"]
        # The source is kept so the error can be read against it.
        assert (repo / r["source"]).is_file()

    def test_no_compiler_is_a_sentence_not_a_trace(self, repo, monkeypatch):
        monkeypatch.setattr(config, "REPO", repo)
        monkeypatch.setattr(sf.build, "UCRT64", repo / "nothing-here")
        monkeypatch.setattr(sf.shutil, "which", lambda *a, **k: None)
        r = sf.generate("c", "c_minimal", [], name="factory-x")
        assert not r["ok"]
        assert "was not found" in r["error"]

    def test_bad_names_are_refused_not_escaped(self, compiler):
        for bad in ("..", "a/b", "with space", "x>y"):
            r = sf.generate("c", "c_minimal", [], name=bad)
            assert not r["ok"], bad
            assert "name" in r["error"]

    def test_auto_name_is_timestamped_and_underscores_become_dashes(
            self, compiler):
        r = sf.generate("c", "c_strings", [])
        assert r["ok"], r
        assert "c-strings" in r["source"]
        tail = r["source"].rsplit("-", 1)[-1].split(".")[0]
        assert any(c.isdigit() for c in tail)

    def test_older_pairs_are_pruned_at_the_cap(self, compiler):
        for i in range(sf.SAMPLE_KEEP + 3):
            r = sf.generate("c", "c_minimal", [], name=f"factory-prune-{i:03d}")
            assert r["ok"], (i, r)
        samples = config.REPO / "samples"
        exes = sorted(samples.glob("*.exe"))
        assert len(exes) == sf.SAMPLE_KEEP
        # The oldest three went: prune-000 through prune-002 are gone.
        gone = {"factory-prune-000.exe", "factory-prune-001.exe",
                "factory-prune-002.exe"}
        assert gone.isdisjoint({p.name for p in exes})
        # Their sources left with them: an orphan .c next to nothing is how
        # the directory fills with artefacts that answer to nothing.
        for i in ("000", "001", "002"):
            assert not (samples / f"factory-prune-{i}.c").exists()


# --- the page-facing catalog --------------------------------------------------


class TestCatalog:
    def test_compiler_status_names_what_it_found(self, compiler):
        status = sf.compiler_status()
        assert status["ok"]
        assert "g++.exe" in status["gcc"]

    def test_compiler_status_refuses_by_sentence(self, repo, monkeypatch):
        monkeypatch.setattr(config, "REPO", repo)
        monkeypatch.setattr(sf.build, "UCRT64", repo / "nothing-here")
        monkeypatch.setattr(sf.shutil, "which", lambda *a, **k: None)
        status = sf.compiler_status()
        assert not status["ok"]
        assert "IA_MSYS2_UCRT64" in status["detail"]
