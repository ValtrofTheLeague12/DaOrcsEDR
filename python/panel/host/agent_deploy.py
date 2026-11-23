"""Build the endpoint-agent installer and share it as a public MEGA link.

The deploy flow has three steps, and each one is a state the operator may sit
in for a while:

1. **Build** - ``agent\\build.ps1`` packages the agent with PyInstaller and
   compiles the Inno Setup wrapper into ``agent/output/DaOrcsAgent-Setup.exe``.
   This runs for minutes, which is why it is a job, not a request.
2. **Stage** - the Setup exe is copied beside the per-agent files: the
   ``agent.json`` template (brokers/topic from .env, heartbeat API bound to
   ``0.0.0.0`` on the requested port, default 8787) and an ``install-agent.ps1``
   that runs the installer silently with this target's switches. One installer
   binary serves every endpoint; what makes the package "for the given agent"
   is this folder.
3. **Share** - the staged folder goes up to MEGA under a fixed root and
   ``megacmd.public_link`` returns (creating if needed) its public link, with
   the same expiry policy ``config/share.json`` applies to evidence links.

The staging tree lives under the AppData root, not the repo: generated state
belongs in the profile, and a repo checkout is not a distribution point.
"""

from __future__ import annotations

import hashlib
import importlib
import json
import re
import shutil
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

from ..artifacts import share_settings
from ..core import config
from . import agents as agent_fleet
from . import endpoints

BUILD_SCRIPT = config.REPO / "agent" / "build.ps1"
OUTPUT_EXE = config.REPO / "agent" / "output" / "DaOrcsAgent-Setup.exe"
SETUP_NAME = "DaOrcsAgent-Setup.exe"

REMOTE_ROOT = "/DaOrcsAgent"
UPLOAD_TIMEOUT = 900

JOB_TTL = 6 * 3600.0
_MAX_LINES = 600
_KEEP_STAGED = 5

_jobs: dict[str, dict] = {}
_jobs_lock = threading.Lock()
_running: str | None = None


class DeployError(Exception):
    """A synchronous refusal with an HTTP status for the route."""

    def __init__(self, message: str, code: str, status: int) -> None:
        super().__init__(message)
        self.code = code
        self.status = status


def _slug(name: str) -> str:
    """A filesystem- and remote-path-safe form of the agent name."""
    text = re.sub(r"[^A-Za-z0-9._-]+", "-", name.strip()).strip("-.")
    return text.lower() or "agent"


def _utc_now() -> float:
    return round(time.time(), 1)


def _load_megacmd():
    """mega/megacmd.py by path - it is a script outside this package."""
    mega_dir = config.REPO / "mega"
    if not mega_dir.is_dir():
        return None, "mega/ not found"
    if str(mega_dir) not in sys.path:
        sys.path.insert(0, str(mega_dir))
    try:
        module = importlib.import_module("megacmd")
        return module, None
    except Exception as exc:  # noqa: BLE001 - a broken client is a state
        return None, f"{type(exc).__name__}: {exc}"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _view(job: dict) -> dict:
    out = {
        k: job.get(k) for k in (
            "id", "kind", "agent", "state", "started_at", "finished_at",
            "exit_code", "error", "artifact", "bytes", "sha256",
            "remote_path", "link", "account", "expire",
            # The per-agent configuration the package seeds, so the fleet
            # card can show the port/brokers/topic without parsing agent.json.
            "api_host", "api_port", "brokers", "topic",
        )
    }
    out["log"] = list(job.get("log") or [])
    dropped = job.get("log_dropped") or 0
    if dropped:
        out["log_truncated"] = dropped
    return out


def job(job_id: str) -> dict | None:
    with _jobs_lock:
        _prune(_utc_now())
        job_ = _jobs.get(job_id)
        return _view(dict(job_)) if job_ else None


def current() -> dict | None:
    """The newest job, so a reload reattaches instead of orphaning it."""
    with _jobs_lock:
        _prune(_utc_now())
        if not _jobs:
            return None
        newest = max(_jobs.values(), key=lambda j: j.get("started_at", 0.0))
        return _view(dict(newest))


def _prune(now: float) -> None:
    for jid in [k for k, v in _jobs.items()
                if v.get("state") != "running"
                and now - v.get("finished_at", now) > JOB_TTL]:
        del _jobs[jid]


def _append(job_id: str, line: str) -> None:
    with _jobs_lock:
        job_ = _jobs.get(job_id)
        if not job_:
            return
        log = job_["log"]
        log.append(str(line).rstrip())
        if len(log) > _MAX_LINES:
            del log[:len(log) - _MAX_LINES]
            job_["log_dropped"] = int(job_.get("log_dropped", 0)) + 1


# ---------------------------------------------------------------------------
# Per-agent package
# ---------------------------------------------------------------------------

def _agent_values() -> tuple[str, str]:
    """(brokers, topic) the template carries, with the example defaults."""
    example = endpoints._agent_example()  # noqa: SLF001 - one module, one truth
    brokers = config.setting(endpoints.AGENT_BROKERS, example["brokers"])
    topic = config.setting(endpoints.AGENT_TOPIC, example["topic"])
    return brokers, topic


def _stage(job: dict, name: str, folder: Path) -> Path:
    """Build the per-agent folder: Setup exe + agent.json + install script."""
    brokers = job["brokers"]
    topic = job["topic"]
    port = job["api_port"]
    template = endpoints.agent_template(brokers, topic, port=port)
    folder.mkdir(parents=True, exist_ok=True)

    setup = folder / SETUP_NAME
    shutil.copy2(OUTPUT_EXE, setup)
    (folder / "agent.json").write_text(
        json.dumps(template, indent=2) + "\n", encoding="utf-8")

    safe_name = name.replace("'", "''")
    safe_brokers = brokers.replace("'", "''")
    safe_topic = topic.replace("'", "''")
    (folder / "install-agent.ps1").write_text(
        "# Generated by the admin panel for agent '%s'.\n"
        "# Runs the bundled installer silently with this target's values.\n"
        "$ErrorActionPreference = 'Stop'\n"
        "$here = Split-Path -Parent $MyInvocation.MyCommand.Path\n"
        "& (Join-Path $here '%s') /VERYSILENT /NORESTART `\n"
        "    /APIHOST=0.0.0.0 /APIPORT=%d /BROKERS='%s' /TOPIC='%s'\n"
        "exit $LASTEXITCODE\n" % (safe_name, SETUP_NAME, port,
                                 safe_brokers, safe_topic),
        encoding="utf-8")

    stat = setup.stat()
    job["artifact"] = str(setup)
    job["bytes"] = stat.st_size
    job["sha256"] = _sha256(setup)
    return folder


# ---------------------------------------------------------------------------
# The job
# ---------------------------------------------------------------------------

def _normalise_port(port: object) -> int:
    """Accept None, int or numeric string; 1-65535 or a DeployError."""
    if port is None or port == "":
        return 8787
    try:
        value = int(port)
    except (TypeError, ValueError):
        raise DeployError(
            f"API port must be an integer, got {port!r}", "invalid-port", 400
        ) from None
    if not 1 <= value <= 65535:
        raise DeployError(
            f"API port must be between 1 and 65535, got {value}",
            "invalid-port", 400)
    return value


def start_deploy(name: object, port: object = None) -> dict:
    """Preflight, then start one deploy job. Refusals are answers, not 500s."""
    global _running

    try:
        clean_name = agent_fleet._normalise_name(name)  # noqa: SLF001
    except agent_fleet.AgentError as exc:
        raise DeployError(str(exc), exc.code, exc.status) from exc
    api_port = _normalise_port(port)

    with _jobs_lock:
        _prune(_utc_now())
        if _running is not None and _jobs.get(_running, {}).get("state") == "running":
            running = _jobs[_running]
            return {"ok": False,
                    "error": "a deploy is already running",
                    "detail": f"job {_running} (agent {running.get('agent')!r}) "
                              "is in progress; wait for it to finish",
                    "job_id": _running}

    if not BUILD_SCRIPT.is_file():
        raise DeployError(f"{BUILD_SCRIPT.name} not found under agent/",
                          "missing-build-script", 400)

    megacmd, why = _load_megacmd()
    if megacmd is None:
        raise DeployError(f"MEGA tooling unavailable: {why}", "mega-missing", 400)
    if not megacmd.available():
        raise DeployError(f"MEGAcmd missing - {megacmd.missing_message()}",
                          "mega-missing", 400)
    account = megacmd.whoami()
    if not account:
        raise DeployError(
            "no MEGAcmd session - run: python mega/login.py --mega",
            "no-session", 400)

    # The expiry policy is read BEFORE minutes of building, not after: a
    # broken share.json failing a finished upload would be the same
    # too-late surprise artifacts.link_for() exists to prevent.
    expire, why = share_settings.expire(config.REPO)
    if why:
        raise DeployError(f"share link expiry: {why}", "share-policy", 400)

    jid = f"d{_utc_now():.0f}{uuid.uuid4().hex[:4]}"
    brokers, topic = _agent_values()
    job_ = {
        "id": jid, "kind": "agent-deploy", "agent": clean_name,
        "state": "running", "started_at": _utc_now(), "finished_at": None,
        "exit_code": None, "error": None, "log": [], "log_dropped": 0,
        "artifact": None, "bytes": None, "sha256": None,
        "remote_path": None, "link": None, "account": account,
        "expire": expire,
        # The per-agent configuration the staged package will seed; surfaced
        # on the job so the fleet card can show it without re-reading files.
        "api_host": "0.0.0.0", "api_port": api_port,
        "brokers": brokers, "topic": topic,
    }
    with _jobs_lock:
        _jobs[jid] = job_
        _running = jid

    threading.Thread(target=_run, args=(jid,), daemon=True,
                     name="agent-deploy").start()
    return {"ok": True, "job_id": jid, "agent": clean_name, "reused": False,
            "api_host": "0.0.0.0", "api_port": api_port,
            "brokers": brokers, "topic": topic}


def _run(job_id: str) -> None:
    global _running
    try:
        _finish_setup(job_id)
    except Exception as exc:  # noqa: BLE001 - a job must report, not vanish
        _append(job_id, f"{type(exc).__name__}: {exc}")
        with _jobs_lock:
            job_ = _jobs.get(job_id)
            if job_:
                job_["state"] = "error"
                job_["error"] = f"{type(exc).__name__}: {exc}"
                job_["finished_at"] = _utc_now()
    finally:
        with _jobs_lock:
            if _running == job_id:
                _running = None


def _finish_setup(job_id: str) -> None:
    job_ = _jobs[job_id]
    name = job_["agent"]

    # 1. Build. An argument list, never a shell string - the paths reach a
    #    filesystem that expands metacharacters.
    powershell = shutil.which("powershell") or shutil.which("pwsh")
    if powershell is None:
        raise RuntimeError("neither powershell nor pwsh is on PATH")
    argv = [powershell, "-NoProfile", "-NonInteractive",
            "-ExecutionPolicy", "Bypass", "-File", str(BUILD_SCRIPT)]
    _append(job_id, f"$ {' '.join(argv)}")
    proc = subprocess.Popen(
        argv, cwd=str(BUILD_SCRIPT.parent),
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, encoding="utf-8", errors="replace", bufsize=1,
    )
    assert proc.stdout is not None
    for line in proc.stdout:
        _append(job_id, line.rstrip("\n"))
    code = proc.wait()
    if code != 0:
        raise RuntimeError(f"agent build.ps1 exited {code} - see the log above")
    if not OUTPUT_EXE.is_file():
        raise RuntimeError(
            f"build.ps1 exited 0 but {SETUP_NAME} is not in agent/output/")

    # 2. Stage the per-agent package under the AppData root. Old staging
    #    folders are pruned to the newest few: each deploy replaces the
    #    contents for its agent, so nothing here is history worth keeping.
    staging = config.appdata_root() / "agent-deploy" / "staging"
    staging.mkdir(parents=True, exist_ok=True)
    stale = sorted(staging.glob("installer-*"),
                   key=lambda p: p.stat().st_mtime, reverse=True)
    for old in stale[_KEEP_STAGED:]:
        shutil.rmtree(old, ignore_errors=True)
    folder = _stage(job_, name, staging / f"installer-{_slug(name)}")
    _append(job_id, f"staged package: {folder}")

    # 3. Upload and share. The destination must exist before `put`, or
    #    MEGAcmd treats it as a container and flattens the folder - the same
    #    behaviour mega/upload.py arbitrates for evidence bundles.
    megacmd, why = _load_megacmd()
    if megacmd is None:
        raise RuntimeError(f"MEGA tooling unavailable: {why}")
    made = megacmd.run("mkdir", "-p", REMOTE_ROOT, check=False,
                       timeout=megacmd.QUICK_TIMEOUT)
    if made.code != 0:
        # Exit 54 ("already exists") is the expected rerun case; anything else
        # surfaces in the put below, which raises on a real failure.
        _append(job_id, f"mkdir {REMOTE_ROOT} exit {made.code}: "
                        f"{(made.err or made.out or '').strip()[:200]}")
    _append(job_id, f"uploading {folder.name} to {REMOTE_ROOT} ...")
    megacmd.run("put", str(folder), REMOTE_ROOT, timeout=UPLOAD_TIMEOUT)
    remote_path = f"{REMOTE_ROOT}/{folder.name}".replace("//", "/")
    job_["remote_path"] = remote_path

    # 4. The link. Only created here, never by a poll.
    link = megacmd.public_link(remote_path, megacmd.QUICK_TIMEOUT,
                               expire=job_["expire"])
    job_["link"] = link
    job_["state"] = "done"
    job_["exit_code"] = 0
    job_["finished_at"] = _utc_now()
    _append(job_id, f"shared: {link}")
