"""Activate Services - start whatever is down, wait until it answers.

Each entry: how to start the service (command + cwd) and how long to wait
for its health endpoint.  Logs of every start attempt land in
admin-terminal/logs/.

Prerequisites are checked up front (docker daemon pre-flight, compose
files, venvs) so a service that cannot possibly start is skipped with a
clear reason instead of hanging on a health wait.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import time
import webbrowser
from dataclasses import dataclass

import core


@dataclass
class Starter:
    key: str            # matches Service.key
    name: str
    cmd: list[str]      # argv
    cwd: str            # working directory
    ready: float        # seconds to wait for /health
    needs: str = ""     # executable that must exist, else a clear skip
    hint: str = ""      # shown when the starter cannot run


# ---------------------------------------------------------------------------
# Docker pre-flight (cached - one `docker info` per screen, not per service)
# ---------------------------------------------------------------------------
_DOCKER_CACHE: tuple[float, tuple[str, str]] | None = None


def _docker_state() -> tuple[str, str]:
    """('ok', version) | ('blocked', reason) - never raises."""
    global _DOCKER_CACHE
    if _DOCKER_CACHE and time.monotonic() - _DOCKER_CACHE[0] < 30.0:
        return _DOCKER_CACHE[1]
    result: tuple[str, str]
    if not shutil.which("docker"):
        result = ("blocked", "docker CLI not found (install Docker Desktop)")
    else:
        try:
            out = subprocess.run(
                ["docker", "info", "--format", "{{.ServerVersion}}"],
                capture_output=True, text=True, timeout=6,
                encoding="utf-8", errors="replace")
        except subprocess.TimeoutExpired:
            result = ("blocked",
                      "docker daemon not responding (Desktop still starting?)")
        except OSError as exc:
            result = ("blocked", f"docker CLI cannot run: {exc}")
        else:
            if out.returncode == 0 and out.stdout.strip():
                result = ("ok", out.stdout.strip())
            else:
                result = ("blocked",
                          "Docker daemon not running - start Docker Desktop first")
    _DOCKER_CACHE = (time.monotonic(), result)
    return result


def _docker_compose_file() -> str | None:
    """Root compose file for CyberChef (see CONTAINER-TESTING.md)."""
    for name in ("docker-compose.yml", "docker-compose.yaml",
                 "compose.yml", "compose.yaml"):
        path = os.path.join(core.REPO, name)
        if os.path.isfile(path):
            return path
    return None


def _malapi_cmd() -> tuple[list[str], str, str]:
    """Use the repository venv, which contains MalAPI's Flask dependencies."""
    return [core.PY_VENV, "api/server.py"], core.PY_VENV, \
        "python/.venv is missing - recreate it first"


def _starter_list() -> list[Starter]:
    compose = _docker_compose_file()
    malapi_cmd, malapi_needs, malapi_hint = _malapi_cmd()
    out = [
        Starter("analyzer", "Analyzer API", core.ANALYZER_CMD, core.REPO,
                ready=30.0, needs=core.PY_VENV,
                hint="python/.venv is missing - recreate it first"),
        Starter("malapi", "MalAPI", malapi_cmd,
                os.path.join(core.REPO, "python"), ready=15.0,
                needs=malapi_needs, hint=malapi_hint),
        Starter("ml", "ML scorer",
                [core.ML_VENV, os.path.join("ml", "serve.py"),
                 "--host", core.bind_addr(core.ml_host()),
                 "--port", str(core.ml_port())], core.REPO, ready=20.0,
                needs=core.ML_VENV,
                hint="ml/_t/venv is missing - recreate it first"),
    ]
    if compose:
        out.append(Starter(
            "cyberchef", "CyberChef",
            ["docker", "compose", "-f", compose, "up", "-d",
             "cyberchef-api", "cyberchef-ui"],
            core.REPO, ready=60.0))
    else:
        out.append(Starter(
            "cyberchef", "CyberChef", [], core.REPO, ready=0.0,
            needs="__missing__",
            hint="compose file + Containerfile.cyberchef missing "
                 "(see CONTAINER-TESTING.md)"))
    if compose:
        out.append(Starter(
            "guacamole", "Guacamole",
            ["docker", "compose", "-f", compose, "up", "-d", "guacamole"],
            core.REPO, ready=120.0))
    else:
        out.append(Starter(
            "guacamole", "Guacamole", [], core.REPO, ready=0.0,
            needs="__missing__",
            hint="compose.yaml missing (see CONTAINER-TESTING.md)"))
    out.append(Starter(
        "kafka", "Kafka broker",
        ["docker", "compose", "-f",
         os.path.join(core.REPO, "kafka-agent", "docker-compose.yaml"),
         "up", "-d", "kafka"],
        core.REPO, ready=90.0))
    return out


def _blocker(st: Starter) -> str:
    """Why this service cannot start right now ('' = startable)."""
    if not st.cmd or st.needs == "__missing__":
        return st.hint
    exe = st.cmd[0]
    if os.path.isabs(exe):
        if not os.path.isfile(exe):
            return st.hint or f"{exe} missing"
    elif not shutil.which(exe):
        return st.hint or f"'{exe}' not found"
    if st.needs and not os.path.isfile(st.needs) \
            and not shutil.which(st.needs):
        return st.hint or f"{st.needs} missing"
    if st.key == "analyzer":
        analyzer = os.environ.get("SA_ANALYZER") or os.path.join(
            core.REPO, "build-ucrt", "static_analyzer.exe")
        analyzer_path = (analyzer if os.path.isabs(analyzer) else
                         os.path.join(core.REPO, analyzer))
        if not os.path.isfile(analyzer_path) and not shutil.which(analyzer):
            return "static analyzer is not built (use Compile Static Analyzer)"
        if not os.path.isfile(os.path.join(core.REPO, "server.py")):
            return "server.py is missing"
    if st.key == "malapi" and not os.path.isfile(
            os.path.join(core.REPO, "python", "api", "server.py")):
        return "python/api/server.py is missing"
    if st.key == "ml" and not os.path.isfile(
            os.path.join(core.REPO, "ml", "serve.py")):
        return "ml/serve.py is missing"
    if st.key == "ml" and not os.path.isfile(
            os.path.join(core.REPO, "ml", "model.txt")):
        return "ml/model.txt is missing (train or install the model first)"
    if st.key == "ml" and core.bind_addr(core.ml_host()) != core.ml_host() \
            and not core.ml_token():
        return ("ML_HOST is off-loopback and ML_SERVE_TOKEN is unset - "
                "serve.py refuses that bind (netcfg generates the token)")
    if st.key == "kafka" and not os.path.isfile(
            os.path.join(core.REPO, "kafka-agent", "docker-compose.yaml")):
        return "kafka-agent/docker-compose.yaml is missing"
    if exe == "docker":
        state, detail = _docker_state()
        if state != "ok":
            return detail
    return ""


def screen(only: set[str] | None = None) -> None:
    starters = _starter_list()
    if only:
        starters = [s for s in starters if s.key in only]

    svcs = core.services()
    core.probe_all(svcs)
    upmap = {s.key: s.up for s in svcs}

    down = [s for s in starters if not upmap.get(s.key, False)]
    starter_keys = {s.key for s in starters}
    selected_svcs = [s for s in svcs if s.key in starter_keys]
    print(core.render_services(selected_svcs))
    print()
    if not down:
        print(core.paint("  all services are already up", core.GREEN, core.BOLD))
        core.pause()
        return

    print(core.paint("  services to start:", core.BOLD))
    for st in down:
        why_ = _blocker(st)
        suffix = f" - unavailable: {why_}" if why_ else ""
        print(f"    {st.key:<10} {st.name}{suffix}")
    print(core.paint(
        "  Enter starts all available services; or type service key(s).",
        core.DIM))
    choice = core.ask("  start [Enter=all / analyzer,ml / b=back]", "all").lower()

    if choice in ("b", "q", "back"):
        return
    if choice in ("a", "all", "*"):
        chosen = down
    else:
        requested = {part.strip() for part in choice.split(",") if part.strip()}
        by_key = {st.key: st for st in down}
        unknown = requested - by_key.keys()
        if not requested or unknown:
            print(core.paint(
                f"  ! unknown or unavailable service key(s): "
                f"{', '.join(sorted(unknown or requested))}",
                core.RED))
            core.pause()
            return
        chosen = [by_key[key] for key in by_key if key in requested]

    for st in chosen:
        _start(st)
    core.pause()


def _tail_log(path: str, limit: int = 12) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return "".join(fh.readlines()[-limit:]).strip()
    except OSError:
        return ""


def _start(st: Starter) -> None:
    print()
    print(core.paint(f"  starting {st.name}...", core.CYAN, core.BOLD))
    why_ = _blocker(st)
    if why_:
        print(core.paint(f"  not started: {why_}", core.YELLOW))
        return

    log = os.path.join(core.ensure_admin_logs(),
                       f"start_{st.key}_{core.timestamp()}.log")
    env = dict(os.environ)
    env["PYTHONUNBUFFERED"] = "1"
    # .env is read by the admin, not by a freshly spawned child - hand the
    # configured endpoint (and ML token) over explicitly.
    env.update({k: v for k, v in core.service_env(st.key).items() if v})
    try:
        pid = core.spawn_detached(st.cmd, st.cwd, log, env=env)
    except OSError as exc:
        print(core.paint(f"  could not launch: {exc}", core.RED))
        return

    svc = next((s for s in core.services({st.key})), None)
    if svc is None:
        print(core.paint(f"  launched PID {pid}; no health check is configured.",
                         core.YELLOW))
        return

    print(f"  launched PID {pid}; waiting up to {st.ready:.0f}s for "
          f"{svc.shown}", end="", flush=True)
    deadline = time.monotonic() + st.ready
    next_update = time.monotonic() + 1.0
    while True:
        core.probe(svc)
        if svc.up:
            print()
            print(core.paint(f"  {st.name} is ready ({svc.ms:.0f} ms).",
                             core.GREEN, core.BOLD))
            if st.key == "guacamole" and core.confirm(
                    "  open Guacamole in the browser?", True):
                webbrowser.open(f"http://{svc.shown}")
                print(core.paint("  opened http://127.0.0.1:61000",
                                 core.DIM))
            return
        now = time.monotonic()
        if now >= deadline:
            break
        if now >= next_update:
            print(".", end="", flush=True)
            next_update = now + 1.0
        time.sleep(min(0.5, deadline - now))

    print()
    print(core.paint(f"  {st.name} did not become ready: {svc.note or 'timeout'}",
                     core.RED, core.BOLD))
    print(f"  log: {os.path.relpath(log, core.REPO)}")
    tail = _tail_log(log)
    if tail:
        print("  --- startup log ---")
        print(tail)
        print("  -------------------")
