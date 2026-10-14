#!/usr/bin/env python3
"""Black-box tests for the pipeline planner CLI.

Usage:
    python tests/test_pipeline_cli.py [analyzer-executable] [sample-pe]

Every assertion is on observable behaviour only: exit codes, stdout markers,
and the run_summary.json manifest each run writes under exports/. The marker
strings must match what the analyzer actually prints (print_kv_colored /
the "[phase n/total]" headers), so a wording change in the analyzer fails
these tests loudly.

Runs that need the local services are kept to one case (model + ML_THRESHOLD
proves the YAML `environment:` block reaches the child process); everything
else is chosen to stay free of MalAPI/ML launches so the suite stays fast.
"""
from __future__ import annotations

import json
import os
import re
import threading
import subprocess
import sys
import tempfile
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
DEFAULT_ANALYZER = REPO / "build-ucrt" / "static_analyzer.exe"
DEFAULT_SAMPLE = REPO / "tests" / "fixtures" / "suspicious_sample.exe"

failures: list[str] = []


def check(condition: bool, message: str, detail: str = "") -> None:
    if condition:
        print(f"[+] {message}")
        return
    print(f"[-] FAIL: {message}", file=sys.stderr)
    if detail:
        print(detail, file=sys.stderr)
    failures.append(message)


def run_analyzer(
    analyzer: Path,
    args: list[str],
    cwd: Path,
    timeout: int = 120,
    extra_env: dict[str, str] | None = None,
):
    env = os.environ.copy()
    env["STATIC_ANALYZER_CURSES"] = "0"
    env["CTI_SKIP"] = "1"
    env.update(extra_env or {})
    # Unconditional, like build.ps1: ucrt64 must be *first* - a DLL later in
    # the PATH can shadow one of the analyzer's and the exe then dies with
    # 0xC0000135 before printing anything.
    ucrt64 = r"C:\msys64\ucrt64\bin"
    if Path(ucrt64).is_dir() and not env.get("PATH", "").startswith(ucrt64):
        env["PATH"] = ucrt64 + os.pathsep + env["PATH"]
    # The suite sets its own thresholds; a leftover from the developer shell
    # must not silently skip the model phase.
    for name in ("ML_SKIP", "ML_THRESHOLD", "ML_EXPLAIN", "ML_TOP_K"):
        env.pop(name, None)
    return subprocess.run(
        [str(analyzer), *args],
        cwd=str(cwd),
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
    )


def newest_manifest(cwd: Path) -> tuple[dict, Path]:
    cands = list((cwd / "exports").glob("*/run_summary.json"))
    if not cands:
        raise AssertionError(f"no run_summary.json under {cwd / 'exports'}")
    path = max(cands, key=lambda p: p.stat().st_mtime)
    return json.loads(path.read_text(encoding="utf-8")), path


def main() -> int:
    analyzer = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else DEFAULT_ANALYZER
    sample = Path(sys.argv[2]).resolve() if len(sys.argv) > 2 else DEFAULT_SAMPLE
    if not analyzer.is_file():
        print(f"analyzer not found: {analyzer}", file=sys.stderr)
        return 2
    if not sample.is_file():
        print(f"sample not found: {sample}", file=sys.stderr)
        return 2

    # --- CLI surface: help, listing, flag validation (all instant) ---------

    run = run_analyzer(analyzer, ["--help"], REPO)
    check(run.returncode == 0 and "Usage: static_analyzer" in run.stdout,
          "--help exits 0 and prints usage", run.stdout)

    run = run_analyzer(analyzer, ["--bogus"], REPO)
    check(run.returncode == 2 and "unknown option '--bogus'" in run.stdout,
          "unknown option exits 2", run.stdout)

    run = run_analyzer(analyzer, ["--list-phases"], REPO)
    check(run.returncode == 0 and all(n in run.stdout for n in ("strings", "model", "export", "die")),
          "--list-phases exits 0 and names the phases", run.stdout)

    run = run_analyzer(analyzer, ["--list-phases", "--json"], REPO)
    # The analyzer prints its "[trace] loaded ..." line to stdout before the
    # JSON document; the payload starts at the first bare "[" line.
    payload = run.stdout[run.stdout.index("\n[\n") + 1:] if "\n[\n" in run.stdout else ""
    try:
        catalog = json.loads(payload)
        check(
            run.returncode == 0
            and isinstance(catalog, list)
            and len(catalog) == 27
            and {"name", "description", "artifact", "service", "requires"} <= set(catalog[0])
            and any(e["name"] == "strings" for e in catalog)
            and any(e["name"] == "die" for e in catalog),
            "--list-phases --json emits 27 catalog entries with all keys",
            run.stdout,
        )
    except json.JSONDecodeError:
        check(False, "--list-phases --json emits valid JSON", run.stdout)

    run = run_analyzer(analyzer, ["--list-pipelines"], REPO)
    check(
        run.returncode == 0
        and all(n in run.stdout for n in ("default", "extract_strings", "extract_iat",
                                          "extract_eat", "extract_asm", "quick")),
        "--list-pipelines lists the built-in and named pipelines",
        run.stdout,
    )

    run = run_analyzer(analyzer, ["--list-phases", "--list-pipelines"], REPO)
    check(run.returncode == 2 and "mutually exclusive" in run.stdout,
          "--list-phases + --list-pipelines is rejected", run.stdout)

    run = run_analyzer(analyzer, ["--json"], REPO)
    check(run.returncode == 2 and "only valid together" in run.stdout,
          "--json without --list-phases is rejected", run.stdout)

    run = run_analyzer(analyzer, ["-p"], REPO)
    check(run.returncode == 2 and "needs a value" in run.stdout,
          "-p without a value is rejected", run.stdout)

    # --- Config errors: every one must fail fast with exit 2 ----------------

    run = run_analyzer(analyzer, ["-p", '["strngs"]', str(sample)], REPO)
    check(run.returncode == 2 and "did you mean 'strings'" in run.stdout,
          "unknown phase suggests the nearest name", run.stdout)

    run = run_analyzer(analyzer, ["-p", "nope.yaml", str(sample)], REPO)
    check(run.returncode == 2 and "pipeline file not found" in run.stdout,
          "missing pipeline file exits 2", run.stdout)

    run = run_analyzer(analyzer, ["-p", "extract_nothing", str(sample)], REPO)
    check(run.returncode == 2 and "not found (tried" in run.stdout
          and "--list-pipelines" in run.stdout,
          "unknown bare name lists the paths it tried", run.stdout)

    run = run_analyzer(analyzer, [str(sample), str(analyzer)], REPO)
    check(run.returncode == 2 and "multiple input files" in run.stdout,
          "two positional inputs are rejected", run.stdout)

    with tempfile.TemporaryDirectory(prefix="static-analyzer-cli-") as temp:
        tmp = Path(temp)

        bad_yaml = tmp / "bad.yaml"
        bad_yaml.write_text("phases: [strings\n", encoding="utf-8")
        run = run_analyzer(analyzer, ["-p", str(bad_yaml), str(sample)], REPO)
        check(run.returncode == 2 and "pipeline error" in run.stdout,
              "malformed YAML exits 2 with a pipeline error", run.stdout)

        unknown_yaml = tmp / "unknown.yaml"
        unknown_yaml.write_text("phases: [doesnotexist]\n", encoding="utf-8")
        run = run_analyzer(analyzer, ["-p", str(unknown_yaml), str(sample)], REPO)
        check(run.returncode == 2 and "unknown phase" in run.stdout,
              "unknown phase inside a YAML file exits 2", run.stdout)

        # --- Real runs: manifest, phase order, service gating ---------------

        # Bare name: sections + auto-inserted export/summary, no services.
        stamp = time.time()
        run = run_analyzer(analyzer, ["-p", "extract_eat", str(sample)], REPO)
        check(run.returncode == 0 and "extract_eat" in run.stdout
              and "[phase 1/2]" in run.stdout and "[phase 2/2]" in run.stdout
              and "MalAPI lookup" not in run.stdout
              and "EMBER2024 ML score" not in run.stdout,
              "extract_eat runs 2 phases and starts no services", run.stdout)
        try:
            manifest, path = newest_manifest(REPO)
            fresh = path.stat().st_mtime >= stamp - 1
            check(
                fresh
                and manifest["pipeline"]["name"] == "extract_eat"
                and manifest["phases"]["ran"] == ["sections", "export", "summary"]
                and manifest["phases"]["auto_inserted"] == ["export", "summary"]
                and manifest["result"] == "success"
                and manifest["exit_code"] == 0,
                "extract_eat manifest records phases, insertion and success",
                json.dumps(manifest, indent=2),
            )
        except AssertionError as exc:
            check(False, f"extract_eat manifest: {exc}")

        # Inline JSON on the command line (argv, no shell mangling).
        stamp = time.time()
        run = run_analyzer(analyzer, ["-p", '["sections"]', str(sample)], REPO)
        check(run.returncode == 0 and "[phase 1/2]" in run.stdout,
              "inline JSON pipeline runs", run.stdout)
        try:
            manifest, path = newest_manifest(REPO)
            check(
                path.stat().st_mtime >= stamp - 1
                and manifest["pipeline"]["source"] == "inline"
                and "sections" in manifest["phases"]["ran"]
                and "export" in manifest["phases"]["ran"],
                "inline JSON manifest source is 'inline'",
                json.dumps(manifest, indent=2),
            )
        except AssertionError as exc:
            check(False, f"inline manifest: {exc}")

        # File path form.
        run = run_analyzer(analyzer, ["-p", "pipelines/extract_eat.yaml", str(sample)], REPO)
        check(run.returncode == 0 and "extract_eat (pipelines" in run.stdout,
              "file-path pipeline resolves relative to the cwd", run.stdout)

        # Bare name from a foreign working directory: resolved via the copy
        # the build places next to the executable.
        with tempfile.TemporaryDirectory(prefix="static-analyzer-cwd-") as foreign:
            run = run_analyzer(analyzer, ["-p", "extract_eat", str(sample)], Path(foreign))
            check(run.returncode == 0 and "extract_eat" in run.stdout,
                  "bare name resolves from a foreign working directory", run.stdout)

        # Export selection for a partial pipeline: a strings-only run gets only
        # the strings phase's own artifacts (strings + ioc, plus the
        # fileinfo/hash identity files every run writes) - never known_pe,
        # STIX/CTI, MalAPI, extraction, capa or ML artifacts from phases it
        # never asked for. The full default pipeline still exports everything.
        stamp = time.time()
        run = run_analyzer(analyzer, ["-p", "pipelines/extract_strings.yaml", str(sample)], REPO)
        check(run.returncode == 0 and "extract_strings" in run.stdout,
              "extract_strings pipeline runs", run.stdout)
        try:
            manifest, path = newest_manifest(REPO)
            arts = [a.replace("\\", "/") for a in manifest["artifacts"]]

            def wrote(name: str) -> bool:
                return any(f"/{name}/" in a for a in arts)

            leaked = [n for n in ("known_pe", "stix", "cti", "malapi", "extraction",
                                  "capa", "radare2", "iat", "got", "eat", "ml",
                                  "dashboard") if wrote(n)]
            check(
                path.stat().st_mtime >= stamp - 1
                and manifest["pipeline"]["name"] == "extract_strings"
                and wrote("strings") and wrote("ioc")
                and wrote("fileinfo") and wrote("hash")
                and not leaked,
                "extract_strings exports only its own artifacts "
                "(strings/ioc + identity files)",
                json.dumps(manifest, indent=2) + (f"\nleaked: {leaked}" if leaked else ""),
            )
        except AssertionError as exc:
            check(False, f"extract_strings manifest: {exc}")

        # Human-readable hash: hash.json carries the PGP word-list rendering
        # of the first 8 digest bytes, reproducible from the embedded header,
        # and the prologue prints it next to the hex SHA-256.
        try:
            hash_paths = [a for a in arts if "/hash/" in a]
            assert hash_paths, "manifest lists no hash artifact"
            hash_json = json.loads((REPO / hash_paths[0]).read_text(encoding="utf-8"))
            header = (REPO / "include" / "file" / "pgp_wordlist.hpp").read_text(
                encoding="utf-8")
            m_even = re.search(r"kEvenWords = \{(.*?)\};", header, re.S)
            m_odd = re.search(r"kOddWords = \{(.*?)\};", header, re.S)
            assert m_even and m_odd, "wordlist header not parseable"
            even = re.findall(r'"([^"]+)"', m_even.group(1))
            odd = re.findall(r'"([^"]+)"', m_odd.group(1))
            digest = bytes.fromhex(hash_json["sha256"])
            expected = "-".join(
                (even if i % 2 == 0 else odd)[b]
                for i, b in enumerate(digest[:8]))
            check(
                len(even) == 256 and len(odd) == 256
                and hash_json.get("sha256_words") == expected
                and len(expected.split("-")) == 8
                and "Words" in run.stdout,
                "hash.json sha256_words is the PGP word-list rendering of "
                "the first 8 digest bytes (console prints it too)",
                json.dumps({"sha256": hash_json.get("sha256"),
                            "sha256_words": hash_json.get("sha256_words")},
                           indent=2),
            )
        except Exception as exc:
            check(False, f"human-readable hash: {exc}")

        # Dedupe + prerequisite insertion, asserted through the manifest.
        prereq = tmp / "prereq.yaml"
        prereq.write_text(
            "name: prereq\nphases: [sections, sections, hexdump]\n", encoding="utf-8"
        )
        stamp = time.time()
        run = run_analyzer(analyzer, ["-p", str(prereq), str(sample)], REPO)
        check(run.returncode == 0, "dedupe/prereq pipeline runs", run.stdout)
        try:
            manifest, path = newest_manifest(REPO)
            ran = manifest["phases"]["ran"]
            check(
                path.stat().st_mtime >= stamp - 1
                and ran.count("sections") == 1
                and "extraction" in ran
                and ran.index("extraction") < ran.index("hexdump")
                and "extraction" in manifest["phases"]["auto_inserted"],
                "duplicate phases are dropped and 'extraction' is auto-inserted "
                "before 'hexdump'",
                json.dumps(manifest, indent=2),
            )
        except AssertionError as exc:
            check(False, f"dedupe/prereq manifest: {exc}")

        # YAML environment: ML_THRESHOLD must reach the model score line.
        env_yaml = tmp / "env_probe.yaml"
        env_yaml.write_text(
            'name: env_probe\nphases: [model]\nenvironment:\n  ML_THRESHOLD: "0.75"\n',
            encoding="utf-8",
        )
        stamp = time.time()
        run = run_analyzer(analyzer, ["-p", str(env_yaml), str(sample)], REPO, timeout=240)
        check(run.returncode == 0 and "Threshold used:" in run.stdout
              and "0.7500" in run.stdout,
              "YAML environment: ML_THRESHOLD reaches the model phase", run.stdout)
        try:
            manifest, path = newest_manifest(REPO)
            check(
                path.stat().st_mtime >= stamp - 1
                and manifest["pipeline"]["name"] == "env_probe"
                and any("ml" in a for a in manifest["artifacts"]),
                "model run exports ml/<stem>_ml.json",
                json.dumps(manifest, indent=2),
            )
        except AssertionError as exc:
            check(False, f"env probe manifest: {exc}")

        # Artifact automation is a separate opt-in config. It must preserve
        # ordinary exports by default and produce a verified local bundle when
        # storage is enabled, without invoking MEGAcmd.
        with tempfile.TemporaryDirectory(prefix="static-analyzer-artifacts-") as work:
            workdir = Path(work)
            config_dir = workdir / "config"
            config_dir.mkdir()
            artifact_config = config_dir / "artifacts.yaml"
            artifact_config.write_text(
                "store_artifact: false\n"
                "upload_artifacts: false\n"
                "timeout_seconds: 60\n",
                encoding="utf-8",
            )
            run = run_analyzer(
                analyzer, ["-p", '["strings"]', str(sample)], workdir
            )
            check(
                run.returncode == 0
                and not list((workdir / "exports").glob("*_artifact")),
                "artifact config leaves bundle creation disabled by default",
                run.stdout,
            )

            artifact_config.write_text(
                "store_artifact: true\n"
                "upload_artifacts: false\n"
                "timeout_seconds: 60\n",
                encoding="utf-8",
            )
            run = run_analyzer(
                analyzer, ["-p", '["strings"]', str(sample)], workdir
            )
            bundles = list((workdir / "exports").glob("*_artifact"))
            check(
                run.returncode == 0
                and len(bundles) == 1
                and any(bundles[0].glob("*_evidence.tar.gz"))
                and any(bundles[0].glob("*.sha256"))
                and "[+] --no-upload: bundle is local only" in run.stdout,
                "store_artifact creates a local sealed bundle without uploading",
                run.stdout,
            )
            try:
                manifest, _ = newest_manifest(workdir)
                check(
                    manifest["artifact_bundle"]["created"]
                    and not manifest["artifact_bundle"]["uploaded"]
                    and any("_artifact/" in path.replace("\\", "/")
                            for path in manifest["artifacts"]),
                    "run manifest records local artifact bundle output",
                    json.dumps(manifest, indent=2),
                )
            except (AssertionError, KeyError) as exc:
                check(False, f"artifact bundle manifest: {exc}")

        class SlowCtiHandler(BaseHTTPRequestHandler):
            def do_HEAD(self):
                self.send_response(200)
                self.end_headers()

            def do_GET(self):
                time.sleep(5)
                body = b'{"objects":[]}'
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, _format, *_args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), SlowCtiHandler)
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        try:
            cti_config = tmp / "cti-budget.json"
            base_url = f"http://127.0.0.1:{server.server_port}"
            cti_config.write_text(
                json.dumps({
                    "cache_dir": str(tmp / "cti-cache"),
                    "provider_budget_seconds": 1,
                    "endpoints": {
                        "attack_stix": f"{base_url}/attack",
                        "cisa_kev": f"{base_url}/kev",
                    },
                }),
                encoding="utf-8",
            )
            started = time.monotonic()
            run = run_analyzer(
                analyzer,
                ["-p", '["cti"]', str(sample)],
                tmp,
                timeout=30,
                extra_env={"CTI_SKIP": "0", "CTI_CONFIG": str(cti_config)},
            )
            elapsed = time.monotonic() - started
            check(
                run.returncode == 0 and elapsed < 4.5,
                "CTI knowledge downloads respect the shared one-second budget",
                f"elapsed: {elapsed:.2f}s\n{run.stdout}",
            )
        finally:
            server.shutdown()
            server.server_close()
            server_thread.join(timeout=2)

    if failures:
        print(f"\n{len(failures)} test(s) failed:", file=sys.stderr)
        for name in failures:
            print(f"  - {name}", file=sys.stderr)
        return 1
    print("\nall tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
