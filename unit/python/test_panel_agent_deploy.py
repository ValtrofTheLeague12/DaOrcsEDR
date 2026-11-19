"""The agent installer deploy's contract, without building anything.

The real flow (PyInstaller, Inno Setup, a MEGA upload) runs for minutes and
needs a MEGAcmd session, so everything here runs against the module's
preflights and its pure helpers only - the same discipline the rest of the
unit tree keeps.

What the tests actually pin:

  * a deploy without a valid agent name is refused with the fleet's own
    wording (the address book is the one source of truth for names);
  * a missing build script, MEGAcmd, a MEGA session, or a broken share-link
    expiry policy each refuse BEFORE any job starts - the expiry policy is
    read pre-build on purpose, so a broken share.json must never surface
    only after minutes of building, and must never fall back to a
    permanent link;
  * a second deploy while one is running is refused with the running job's
    id, as a payload rather than an exception;
  * `_slug` produces remote-path-safe folder names, `_view` hands out a copy
    of the log (a caller appending to their view must not edit the store),
    and `current()`/`job()` agree on what the store holds.
"""

from __future__ import annotations

import json
import sys
import threading
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "python"))

from panel.host import agent_deploy as ad  # noqa: E402


# --- the stubs ---------------------------------------------------------------

class FakeMegacmd:
    """megacmd-shaped enough for the preflights: client, session, timeouts."""

    QUICK_TIMEOUT = 5

    def __init__(self, *, available=True, account="ops@example.com"):
        self._available = available
        self._account = account

    def available(self) -> bool:
        return self._available

    def missing_message(self) -> str:
        return "megacmd is not installed"

    def whoami(self, timeout: int = 5):
        return self._account


@pytest.fixture(autouse=True)
def clean_store():
    with ad._jobs_lock:
        ad._jobs.clear()
        ad._running = None
    yield
    with ad._jobs_lock:
        ad._jobs.clear()
        ad._running = None


@pytest.fixture()
def build_ready(tmp_path, monkeypatch):
    """A repo shape whose build script exists, and a megacmd that answers."""
    script = tmp_path / "build.ps1"
    script.write_text("# stub\n")
    monkeypatch.setattr(ad, "BUILD_SCRIPT", script)
    monkeypatch.setattr(ad, "_load_megacmd", lambda: (FakeMegacmd(), None))
    monkeypatch.setattr(ad.share_settings, "expire",
                        lambda _repo: ("1w", None))
    return tmp_path


# --- refusals ----------------------------------------------------------------

def test_empty_name_is_refunded_with_the_fleet_wording():
    with pytest.raises(ad.DeployError) as excinfo:
        ad.start_deploy("   ")
    assert excinfo.value.code == "invalid-name"
    assert excinfo.value.status == 400


def test_non_string_name_is_refused():
    with pytest.raises(ad.DeployError) as excinfo:
        ad.start_deploy(None)
    assert excinfo.value.code == "invalid-name"


def test_missing_build_script_refuses_before_any_job(build_ready, monkeypatch):
    monkeypatch.setattr(ad, "BUILD_SCRIPT",
                        build_ready / "nope" / "build.ps1")
    with pytest.raises(ad.DeployError) as excinfo:
        ad.start_deploy("win-user")
    assert excinfo.value.code == "missing-build-script"
    assert excinfo.value.status == 400
    with ad._jobs_lock:
        assert ad._jobs == {}


def test_missing_megacmd_refuses(build_ready, monkeypatch):
    monkeypatch.setattr(ad, "_load_megacmd",
                        lambda: (None, "ImportError: broken"))
    with pytest.raises(ad.DeployError) as excinfo:
        ad.start_deploy("win-user")
    assert excinfo.value.code == "mega-missing"
    assert "broken" in str(excinfo.value)


def test_logged_out_mega_refuses(build_ready, monkeypatch):
    monkeypatch.setattr(ad, "_load_megacmd",
                        lambda: (FakeMegacmd(account=None), None))
    with pytest.raises(ad.DeployError) as excinfo:
        ad.start_deploy("win-user")
    assert excinfo.value.code == "no-session"


def test_broken_expiry_policy_refuses_before_the_build(build_ready,
                                                       monkeypatch):
    """A broken share.json is an error, not 'publish permanently'."""
    monkeypatch.setattr(ad.share_settings, "expire",
                        lambda _repo: (None, "link_expire 'x' is not a "
                                           "MEGA duration"))
    with pytest.raises(ad.DeployError) as excinfo:
        ad.start_deploy("win-user")
    assert excinfo.value.code == "share-policy"
    assert "MEGA duration" in str(excinfo.value)
    # Nothing may have started: the whole point of reading the policy first.
    with ad._jobs_lock:
        assert ad._jobs == {}
        assert ad._running is None


def test_second_deploy_is_refused_with_the_running_job(build_ready):
    with ad._jobs_lock:
        ad._jobs["d1234"] = {"id": "d1234", "state": "running",
                             "agent": "win-user"}
        ad._running = "d1234"
    result = ad.start_deploy("other-box")
    assert result["ok"] is False
    assert result["job_id"] == "d1234"
    assert "already running" in result["error"]
    assert "win-user" in result["detail"]


# --- a clean start -----------------------------------------------------------

def test_clean_start_starts_a_job(build_ready, monkeypatch):
    monkeypatch.setattr(ad, "_run", lambda _jid: None)  # no real build here
    result = ad.start_deploy("Win User")
    assert result["ok"] is True
    assert result["agent"] == "Win User"
    jid = result["job_id"]
    with ad._jobs_lock:
        job = ad._jobs[jid]
        assert ad._running == jid
    assert job["state"] == "running"
    assert job["account"] == "ops@example.com"
    assert job["expire"] == "1w"
    assert job["link"] is None
    # The per-agent configuration the staged package will seed.
    assert job["api_host"] == "0.0.0.0"
    assert job["api_port"] == 8787
    assert job["brokers"] and job["topic"]
    view = ad.job(jid)
    assert view["id"] == jid
    assert view["agent"] == "Win User"
    assert view["api_port"] == 8787
    assert view["brokers"] == job["brokers"]
    assert ad.current()["id"] == jid


def test_start_accepts_a_port_and_stores_it(build_ready, monkeypatch):
    monkeypatch.setattr(ad, "_run", lambda _jid: None)
    result = ad.start_deploy("win-user", "9001")
    assert result["api_port"] == 9001
    view = ad.job(result["job_id"])
    assert view["api_port"] == 9001


def test_invalid_port_refuses_before_any_job(build_ready):
    for bad in (0, -1, 70000, "abc", {"x": 1}):
        with pytest.raises(ad.DeployError) as excinfo:
            ad.start_deploy("win-user", bad)
        assert excinfo.value.code == "invalid-port"
        assert excinfo.value.status == 400
    with ad._jobs_lock:
        assert ad._jobs == {}


def test_clean_start_takes_the_build_lock(build_ready, monkeypatch):
    """The running job blocks a second start even after its thread exits the
    store's critical section - the lock is the job, not the request."""
    monkeypatch.setattr(ad, "_run", lambda _jid: None)
    first = ad.start_deploy("win-user")
    second = ad.start_deploy("other-box")
    assert first["ok"] is True
    assert second["ok"] is False
    assert second["job_id"] == first["job_id"]


# --- the pure helpers --------------------------------------------------------

def test_slug_is_remote_path_safe():
    assert ad._slug("Win 10 Lab VM!") == "win-10-lab-vm"
    assert ad._slug("  ..agent..  ") == "agent"
    assert ad._slug("a/b\\c") == "a-b-c"
    assert ad._slug("###") == "agent"


def test_stage_seeds_the_port_and_the_install_switches(tmp_path, monkeypatch):
    """agent.json and install-agent.ps1 carry the job's port/config so a
    deployed agent's heartbeat answers where the fleet card expects it."""
    exe = tmp_path / "DaOrcsAgent-Setup.exe"
    exe.write_bytes(b"MZ")
    monkeypatch.setattr(ad, "OUTPUT_EXE", exe)
    with ad._jobs_lock:
        ad._jobs["j9"] = {"id": "j9", "api_host": "0.0.0.0", "api_port": 9001,
                          "brokers": "broker-host:9092", "topic": "lab-topic"}
    job = ad._jobs["j9"]
    folder = ad._stage(job, "win-user", tmp_path / "stage")

    doc = json.loads((folder / "agent.json").read_text(encoding="utf-8"))
    assert doc["api"] == {"enabled": True, "host": "0.0.0.0", "port": 9001}
    assert doc["kafka"]["bootstrap_servers"] == "broker-host:9092"
    assert doc["kafka"]["topic"] == "lab-topic"

    script = (folder / "install-agent.ps1").read_text(encoding="utf-8")
    assert "/APIHOST=0.0.0.0 /APIPORT=9001" in script
    assert "/BROKERS='broker-host:9092'" in script
    assert "/TOPIC='lab-topic'" in script

    assert job["artifact"] == str(folder / ad.SETUP_NAME)
    assert job["bytes"] == exe.stat().st_size


def test_view_hands_out_a_copy_of_the_log():
    stored = {"id": "j1", "state": "done", "log": ["a", "b"],
              "log_dropped": 2, "link": "https://mega.nz/file/x"}
    view = ad._view(stored)
    view["log"].append("caller mutation")
    assert stored["log"] == ["a", "b"]
    assert view["log_truncated"] == 2
    assert view["link"].startswith("https://mega.nz/")


def test_job_unknown_id_is_none():
    assert ad.job("nope") is None
    assert ad.current() is None


def test_append_truncates_to_the_tail():
    jid = "j2"
    with ad._jobs_lock:
        ad._jobs[jid] = {"id": jid, "log": [], "log_dropped": 0}
    for i in range(ad._MAX_LINES + 25):
        ad._append(jid, f"line {i}")
    view = ad.job(jid)
    assert len(view["log"]) == ad._MAX_LINES
    assert view["log"][0] == "line 25"
    assert view["log"][-1] == f"line {ad._MAX_LINES + 24}"
    assert view["log_truncated"] == 25


def test_thread_target_signature(build_ready, monkeypatch):
    """_run must swallow a worker exception into the job's state, not let the
    thread die silently - a vanished job is the failure mode job stores exist
    to prevent."""
    seen = {}

    def boom(job_id):
        seen["called"] = job_id
        raise RuntimeError("build exploded")

    monkeypatch.setattr(ad, "_finish_setup", boom)
    result = ad.start_deploy("win-user")
    jid = result["job_id"]
    # The worker runs on a daemon thread; give it a moment to fail.
    for _ in range(100):
        if ad.job(jid)["state"] != "running":
            break
        threading.Event().wait(0.01)
    view = ad.job(jid)
    assert seen["called"] == jid
    assert view["state"] == "error"
    assert "build exploded" in view["error"]
    assert ad._running is None
