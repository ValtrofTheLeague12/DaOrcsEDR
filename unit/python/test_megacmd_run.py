"""megacmd.run's process handling, without needing MEGAcmd installed.

The uploader must not be able to wedge the analyzer after a run has finished.
Two ways it did:

  * `subprocess.run(..., timeout=...)` kills only the direct child, then
    communicates with its pipes again - and a grandchild that inherited those
    handles keeps them open forever. The timeout fires and the caller still
    never returns.
  * a CLI that asks a question on stdin waits for an answer no script has.

These tests pin the replacements: output goes to files, stdin is closed, and a
timed-out command is killed as a tree and reported as a timeout.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "mega"))

import megacmd  # noqa: E402


def _argv_for(script: str):
    def build(_command, _args):
        return [sys.executable, "-c", script]
    return build


def test_stdout_and_stderr_are_captured(monkeypatch):
    monkeypatch.setattr(
        megacmd, "build_argv",
        _argv_for("import sys; print('out'); print('err', file=sys.stderr)"))
    res = megacmd.run("whoami")
    assert res.code == 0
    assert res.out == "out"
    assert res.err == "err"


def test_a_nonzero_exit_raises_with_the_detail(monkeypatch):
    monkeypatch.setattr(
        megacmd, "build_argv",
        _argv_for("import sys; print('nope', file=sys.stderr); sys.exit(54)"))
    with pytest.raises(megacmd.MegaError, match=r"failed \(exit 54\): nope"):
        megacmd.run("mkdir", "-p", "evidence")


def test_check_false_returns_the_failed_result(monkeypatch):
    monkeypatch.setattr(
        megacmd, "build_argv",
        _argv_for("import sys; print('already there'); sys.exit(54)"))
    res = megacmd.run("mkdir", "-p", "evidence", check=False)
    assert (res.code, res.out) == (54, "already there")


def test_a_timeout_does_not_hang_on_an_inherited_pipe(monkeypatch):
    # The direct child stays alive AND leaves a grandchild holding its
    # stdout/stderr. That is the shape of MEGAclient starting its daemon (or a
    # .bat shim) behind a pipe: killing the child alone is not enough.
    script = (
        "import subprocess, sys, time\n"
        "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])\n"
        "print('parent alive', flush=True)\n"
        "time.sleep(30)\n")
    monkeypatch.setattr(megacmd, "build_argv", _argv_for(script))

    started = time.monotonic()
    with pytest.raises(megacmd.MegaError, match="did not finish within 1s"):
        megacmd.run("whoami", timeout=1)
    # Well under the 30s either process would have slept for; the old
    # subprocess.run path never returned at all.
    assert time.monotonic() - started < 15


def test_a_question_on_stdin_is_not_waited_for(monkeypatch):
    monkeypatch.setattr(
        megacmd, "build_argv",
        _argv_for("import sys; print(repr(sys.stdin.read()))"))
    started = time.monotonic()
    res = megacmd.run("whoami", timeout=10)
    assert res.out == "''"
    assert time.monotonic() - started < 5
