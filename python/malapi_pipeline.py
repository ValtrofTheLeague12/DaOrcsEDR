#!/usr/bin/env python3
"""Run the whole MalAPI pipeline, then prove the result works.

The pipeline is three existing scripts chained by two directories:

    python/malapi/            scraped malapi.io HTML      (input, not produced here)
    python/lots/              scraped LOTS HTML          (input, not produced here)
        |  _map_to_yaml.py
    python/yaml/malapi/       369 API definitions        .yaml
    python/yaml/lots/         175 domain definitions     .yaml
        |  _create_api.py
    python/api/server.py      Flask app, 547 routes      (what the analyzer queries)
    python/api/manifest.yaml  generation metadata

The analyzer's C++ side (include/net/local_api.hpp) launches server.py itself
and polls /health before querying /malapi/<function_name>/, so a generated
server that does not actually answer is the failure worth catching. That is why
this script does not stop at "files written": it boots the server it just
generated, queries it, and shuts it down again.

Every stage runs with the working directory set to python/, because
_map_to_yaml.py and _create_api.py resolve their inputs and outputs relative to
the current directory rather than to their own location.

    python\\.venv\\Scripts\\python.exe python\\malapi_pipeline.py
    python\\.venv\\Scripts\\python.exe python\\malapi_pipeline.py --quick
    python\\.venv\\Scripts\\python.exe python\\malapi_pipeline.py --serve
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent

# The generator scripts and the tree they read/write, all relative to python/.
MAP_SCRIPT = HERE / "_map_to_yaml.py"
API_SCRIPT = HERE / "_create_api.py"
SERVER_SCRIPT = HERE / "api" / "server.py"
MANIFEST = HERE / "api" / "manifest.yaml"

SCRAPE_SOURCES = {
    "malapi.io": HERE / "malapi",
    "lots-project.com": HERE / "lots",
}
YAML_DIRS = {
    "malapi": HERE / "yaml" / "malapi",
    "lots": HERE / "yaml" / "lots",
}
GENERATED = (SERVER_SCRIPT, MANIFEST, HERE / "api" / "requirements.txt")

# server.py binds MALAPI_PORT, defaulting to the analyzer's 60000. Verification
# uses a different port so it never collides with an analyzer already running.
VERIFY_PORT = 60111
BOOT_TIMEOUT_S = 30.0

REQUIRED_MODULES = ("yaml", "jinja2", "loguru", "selectolax")


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

PASS, WARN, FAIL, SKIP = "PASS", "WARN", "FAIL", "SKIP"


@dataclass
class Check:
    name: str
    status: str
    detail: str = ""


@dataclass
class Report:
    checks: List[Check] = field(default_factory=list)

    def add(self, name: str, status: str, detail: str = "") -> None:
        self.checks.append(Check(name, status, detail))

    def ok(self, name: str, detail: str = "") -> None:
        self.add(name, PASS, detail)

    def warn(self, name: str, detail: str = "") -> None:
        self.add(name, WARN, detail)

    def fail(self, name: str, detail: str = "") -> None:
        self.add(name, FAIL, detail)

    def skip(self, name: str, detail: str = "") -> None:
        self.add(name, SKIP, detail)

    def count(self, status: str) -> int:
        return sum(1 for c in self.checks if c.status == status)

    def render(self) -> str:
        width = max((len(c.name) for c in self.checks), default=10)
        lines = []
        for c in self.checks:
            mark = {PASS: "ok  ", WARN: "warn", FAIL: "FAIL", SKIP: "skip"}[c.status]
            lines.append(f"  [{mark}] {c.name.ljust(width)}  {c.detail}".rstrip())
        return "\n".join(lines)


def section(title: str) -> None:
    print(f"\n== {title} " + "=" * max(0, 62 - len(title)))


def info(message: str) -> None:
    print(f"   {message}")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def count_pages(root: Path) -> int:
    return sum(1 for _ in root.rglob("index.html"))


def route_for_api(name: str) -> str:
    """Route for one MalAPI entry, as the template emits it.

    templates/abuse.py.j2 registers the route from the verbatim ``APIName``
    (``@app.get("/malapi/{{ i.APIName }}/")``), because that is the import name
    the analyzer sends: malapi.cpp builds ``"/malapi/" + function_name + "/"``
    from the IAT entry verbatim. ``functionName`` - the lowercased slug
    _create_api.py computes - is only the Python view function's identifier and
    never appears in the URL, so probing it 404s a perfectly good server.
    """
    return f"/malapi/{name}/"


def run_stage(name: str, script: Path, report: Report, *extra: str) -> bool:
    """Run one generator script with python/ as the working directory."""
    section(name)
    if not script.is_file():
        report.fail(name, f"missing {script.name}")
        return False
    cmd = [sys.executable, str(script), *extra]
    info("$ " + " ".join(cmd))
    started = time.monotonic()
    proc = subprocess.run(cmd, cwd=str(HERE), capture_output=True, text=True)
    elapsed = time.monotonic() - started
    # The generators log through loguru at DEBUG, so their own output is the
    # useful part of the result; keep the tail for the failure message.
    tail = (proc.stdout or "").strip().splitlines()[-4:]
    for line in tail:
        info(line)
    if proc.returncode == 0:
        report.ok(name, f"{elapsed:.1f}s")
        return True
    report.fail(name, f"exit {proc.returncode}")
    for line in (proc.stderr or "").strip().splitlines()[-6:]:
        info("stderr: " + line)
    return False


# ---------------------------------------------------------------------------
# Stages
# ---------------------------------------------------------------------------


def stage_scrape(report: Report) -> bool:
    """Re-mirror malapi.io with httrack.

    The mirror is the only stage that reaches the network, and it is the only
    one that can leave the tree in a state the next run cannot recover from: if
    it is killed partway, HTTrack leaves hts-in_progress.lock behind and
    refuses to start again until that file is removed. So a lock older than a
    day is cleared here, before mirroring, and the removal is reported - a lock
    younger than that is left alone, because that one might be a real run.
    """
    lock = HERE / "malapi" / "hts-in_progress.lock"
    if lock.is_file():
        age_s = time.time() - lock.stat().st_mtime
        if age_s > 86400:
            lock.unlink(missing_ok=True)
            # info() rather than a report row: this is an action taken on
            # the way in, not a finding about the result, and the stage itself
            # is about to report its own outcome.
            info(f"removed a stale httrack lock ({int(age_s // 86400)} days old)")
        else:
            report.fail(
                "scrape malapi.io",
                f"{lock.name} is {int(age_s // 60)} minutes old. HTTrack "
                f"refuses to start while it exists, and it is too young to be "
                f"stale. If no mirror is actually running, delete it and retry.")
            return False

    return run_stage("scrape malapi.io", HERE / "_extract_files.py", report)


def stage_preflight(report: Report) -> bool:
    section("preflight")

    missing = []
    for module in REQUIRED_MODULES:
        try:
            __import__(module)
        except ImportError:
            missing.append(module)
    if missing:
        report.fail("python modules", "missing: " + ", ".join(missing))
        info(f"install with: {sys.executable} -m pip install -r python/requirements.txt")
        return False
    report.ok("python modules", ", ".join(REQUIRED_MODULES))

    info(f"interpreter {sys.version.split()[0]} at {sys.executable}")

    for script in (MAP_SCRIPT, API_SCRIPT):
        if script.is_file():
            report.ok(f"script {script.name}", f"{script.stat().st_size} bytes")
        else:
            report.fail(f"script {script.name}", "missing")

    for label, root in SCRAPE_SOURCES.items():
        pages = count_pages(root) if root.is_dir() else 0
        if pages:
            report.ok(f"scrape {label}", f"{pages} pages under {root.name}/")
        else:
            # Not fatal: the YAML catalog is the real input to the API stage, so
            # a tree without scraped HTML can still regenerate from what is
            # already mapped.
            report.warn(f"scrape {label}", "no index.html found; mapping stage will find nothing")

    return not report.count(FAIL)


def stage_map(report: Report, force: bool) -> bool:
    return run_stage("map html -> yaml", MAP_SCRIPT, report)


def stage_api(report: Report, force: bool) -> bool:
    return run_stage("yaml -> api", API_SCRIPT, report)


def _free_port_in_use(port: int) -> bool:
    import socket

    with socket.socket() as s:
        s.settimeout(0.5)
        return s.connect_ex(("127.0.0.1", port)) == 0


def _http(path: str, port: int, timeout: float = 5.0) -> Tuple[int, str]:
    url = f"http://127.0.0.1:{port}{path}"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return resp.status, resp.read(4096).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(4096).decode("utf-8", "replace")
    except Exception as exc:  # URLError, socket.timeout, ...
        return 0, str(exc)


def _wait_for_health(port: int, proc: subprocess.Popen) -> Optional[str]:
    deadline = time.monotonic() + BOOT_TIMEOUT_S
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            return f"server exited early with code {proc.returncode}"
        status, body = _http("/health", port, timeout=2.0)
        if status == 200:
            return None
        time.sleep(0.25)
    return f"/health did not answer within {BOOT_TIMEOUT_S:.0f}s"


def stage_verify(report: Report, keep_serving: bool) -> bool:
    """Boot the generated server and prove it answers the routes the analyzer uses."""
    section("verify")

    if not SERVER_SCRIPT.is_file():
        report.fail("generated server", "api/server.py missing")
        return False
    report.ok("generated server", f"{SERVER_SCRIPT.stat().st_size} bytes")

    # A syntax error in the generated file is the common failure, and it is
    # cheap to catch without booting anything.
    compile_proc = subprocess.run(
        [sys.executable, "-m", "py_compile", str(SERVER_SCRIPT)],
        capture_output=True, text=True,
    )
    if compile_proc.returncode != 0:
        report.fail("server compiles", "syntax error")
        for line in (compile_proc.stderr or "").strip().splitlines()[-4:]:
            info("stderr: " + line)
        return False
    report.ok("server compiles", "no syntax errors")

    counts: Dict[str, int] = {}
    if MANIFEST.is_file():
        try:
            import yaml

            meta = yaml.safe_load(MANIFEST.read_text(encoding="utf-8")) or {}
            counts = {
                "apis": int(meta.get("api_count") or 0),
                "domains": int(meta.get("domain_count") or 0),
            }
            report.ok("manifest", meta.get("generated_at", "?"))
        except Exception as exc:
            report.warn("manifest", f"unreadable: {exc}")

    port = VERIFY_PORT
    if _free_port_in_use(port):
        report.warn("port", f"{port} busy, verification will likely fail")

    env = dict(os.environ)
    env["MALAPI_HOST"] = "127.0.0.1"
    env["MALAPI_PORT"] = str(port)
    proc = subprocess.Popen(
        [sys.executable, str(SERVER_SCRIPT)],
        cwd=str(HERE), env=env,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )

    try:
        problem = _wait_for_health(port, proc)
        if problem:
            report.fail("server /health", problem)
            return False
        report.ok("server /health", f"answered on 127.0.0.1:{port}")

        if keep_serving:
            report.ok("server left running", f"pid {proc.pid}; stop it when done")
            return True

        # Spot-check one API and one LOTS domain, using the real route so a
        # success proves routing, not just that the process is alive.
        api_files = sorted(YAML_DIRS["malapi"].glob("*.yaml"))
        if api_files:
            import yaml

            try:
                doc = yaml.safe_load(api_files[0].read_text(encoding="utf-8")) or {}
                name = doc.get("name") or api_files[0].stem
                route = route_for_api(name)
                status, body = _http(route, port)
                if status == 200:
                    report.ok("malapi route", f"{route} -> {len(body)} bytes")
                else:
                    report.fail("malapi route", f"{route} -> HTTP {status}")
            except Exception as exc:
                report.warn("malapi route", f"could not build a probe: {exc}")

        lot_files = sorted(YAML_DIRS["lots"].glob("*.yaml"))
        if lot_files:
            import yaml

            try:
                doc = yaml.safe_load(lot_files[0].read_text(encoding="utf-8")) or {}
                host = doc.get("host") or lot_files[0].stem
                route = f"/lolbas/domain/{host}"
                status, body = _http(route, port)
                if status == 200:
                    report.ok("lolbas route", f"{route} -> {len(body)} bytes")
                else:
                    report.fail("lolbas route", f"{route} -> HTTP {status}")
            except Exception as exc:
                report.warn("lolbas route", f"could not build a probe: {exc}")

        if counts:
            info(f"catalog: {counts['apis']} APIs, {counts['domains']} LOTS domains")
    finally:
        if not keep_serving:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                report.warn("server shutdown", "had to kill the process")

    return not report.count(FAIL)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--quick", action="store_true",
                    help="verify the existing output without regenerating it")
    ap.add_argument("--with-scrape", action="store_true",
                    help="re-mirror malapi.io before regenerating. This is the "
                         "long, network-bound stage; without it the pipeline "
                         "only rebuilds from whatever HTML is already on disk, "
                         "which is not the same thing as updating the rules")
    ap.add_argument("--skip-map", action="store_true",
                    help="skip the html -> yaml stage (it is the slow one)")
    ap.add_argument("--skip-verify", action="store_true",
                    help="skip booting the generated server")
    ap.add_argument("--serve", action="store_true",
                    help="leave the verified server running instead of stopping it")
    ap.add_argument("--json", dest="as_json", action="store_true",
                    help="emit the check results as JSON")
    args = ap.parse_args()

    report = Report()

    if not stage_preflight(report):
        print(report.render())
        return 1

    if args.quick:
        report.skip("scrape malapi.io", "--quick")
        report.skip("map html -> yaml", "--quick")
        report.skip("yaml -> api", "--quick")
    else:
        if args.with_scrape:
            if not stage_scrape(report):
                print(report.render())
                print("\nscrape failed; regenerating from a partial mirror "
                      "would replace good rules with fewer")
                return 1
        else:
            report.skip("scrape malapi.io", "pass --with-scrape to re-mirror")
        if args.skip_map:
            report.skip("map html -> yaml", "--skip-map")
        elif not stage_map(report, force=False):
            print(report.render())
            print("\nmap stage failed; the api stage would read a partial catalog")
            return 1

        if not stage_api(report, force=False):
            print(report.render())
            return 1

    if args.skip_verify:
        report.skip("verify", "--skip-verify")
    else:
        stage_verify(report, args.serve)

    section("summary")
    print(report.render())
    print(f"\n  {report.count(PASS)} passed, {report.count(WARN)} warnings, "
          f"{report.count(FAIL)} failed, {report.count(SKIP)} skipped")

    if args.as_json:
        print(json.dumps({
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "checks": [vars(c) for c in report.checks],
            "passed": report.count(PASS), "warnings": report.count(WARN),
            "failed": report.count(FAIL), "skipped": report.count(SKIP),
        }, indent=2))

    if report.count(FAIL):
        print("\nPIPELINE FAILED")
        return 1
    print("\nPIPELINE OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())