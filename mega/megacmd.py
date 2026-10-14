#!/usr/bin/env python3
"""Thin, honest wrapper over the MEGAcmd command line.

    megacmd.run("whoami")               -> Result(out=..., err=..., code=...)

Why this file exists
--------------------
`shutil.which("megacmd")` is the POSIX answer and returns None on Windows.
There is no megacmd.exe. The Windows install (default
%LOCALAPPDATA%\\MEGAcmd) ships:

    MEGAclient.exe      the real CLI - takes the subcommand as argv[1]
    MEGAcmdServer.exe   the daemon holding the session
    MEGAcmdShell.exe    an INTERACTIVE terminal - must never be spawned here
    mega-<cmd>.bat      shims that call MegaClient.exe <cmd> %*

MEGAcmdShell.exe is called out because it accepts no argv command and no stdin
command and never exits; a naive `shutil.which("megacmd")`-style probe that
picks it up hangs the caller forever. It is excluded on purpose.

Every call gets a timeout for the same reason: MegaClient.exe talks to the
daemon, which may be starting, resuming a session, or waiting on an MFA
prompt. A call that blocks forever is worse than one that fails.

Verified command shapes (Windows build, against a live account):

    whoami                                   Account e-mail: <email>
    mkdir [-p] remotepath                    silent on success
    put [-c] local [local2 ...] [dst]        see PUT below
    get [remotepath] [localpath]             see GET below
    ls [-l] [--time-format=FMT] remotepath   -l gives "FLAGS VERS SIZE DATE NAME"
    rm [-r] [-f] remotepath                  -r needed to delete a folder
    login [--auth-code=XXXX] email password  password only via argv

Three behaviours here cost real debugging time, so they are written down
rather than left to be rediscovered. All were measured, not inferred:

PUT  If the destination folder does not yet exist and -c is allowed to create
     it, MEGAcmd writes the source folder's CONTENTS flat into the destination
     - "Upload finished: /<dest>", no wrapper folder. If the destination
     already exists, `put` nests normally as <dest>/<name>. The only difference
     between the two outcomes is whether mkdir ran first, so upload.py always
     does `mkdir -p` and then `put`, and then re-lists to confirm. Nothing
     about the checksum can catch this: the bytes are identical either way,
     they are just in the wrong shape on the far end.

GET  Two rules, both learned the hard way:
       1. The local destination directory must ALREADY EXIST. MEGAcmd will
          not create it; it fails with exit 55 and
          "\\\\?\\<path> is not a valid Download Folder".
       2. -m must NOT be passed. With -m the remote folder's contents are
          merged flat into the destination and the wrapper folder never
          appears. Without -m, `get` nests as <dest>/<remote_folder_name>/.

LS   --time-format=ISO6081 is documented but this build ignores it and emits
     the two-token SHORT form ("13Oct2026 15:53:11"), so consumers must
     tolerate either one-token or two-token dates. In the FLAGS column the
     node TYPE is the LEFTMOST character (d/-/r/i/b/x) and the remaining three
     are sharing/export status - reading the last character makes every
     folder look like a file.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

DEFAULT_TIMEOUT = 300
QUICK_TIMEOUT = 60

# Interactive front-end. Never a valid target for a scripted call.
INTERACTIVE = {"megacmdshell.exe"}


class MegaError(RuntimeError):
    """A MEGAcmd call failed. Never carries secret material."""


@dataclass
class Result:
    cmd: str
    argv: list[str]
    code: int
    out: str
    err: str

    @property
    def text(self) -> str:
        return "\n".join(p for p in (self.out, self.err) if p)


# ---------------------------------------------------------------------------
# Locating the CLI
# ---------------------------------------------------------------------------

def _roots() -> list[Path]:
    found: list[Path] = []
    seen: set[str] = set()

    def add(p: Path | None) -> None:
        if p is None:
            return
        try:
            if not p.is_dir():
                return
        except OSError:
            return
        key = str(p).lower()
        if key not in seen:
            seen.add(key)
            found.append(p)

    for var in ("MEGACMD_HOME", "MEGAcmd_HOME"):
        val = os.environ.get(var)
        if val:
            add(Path(val))

    # The install dir is on PATH on this machine; a shim is the cheapest anchor.
    for probe in ("mega-whoami.bat", "mega-whoami.cmd", "megacmd"):
        hit = shutil.which(probe)
        if hit:
            add(Path(hit).parent)

    local = os.environ.get("LOCALAPPDATA")
    if local:
        add(Path(local) / "MEGAcmd")
    add(Path.home() / "AppData" / "Local" / "MEGAcmd")
    return found


def _find(names: list[str]) -> Path | None:
    for root in _roots():
        for name in names:
            cand = root / name
            try:
                if cand.is_file() and cand.name.lower() not in INTERACTIVE:
                    return cand
            except OSError:
                continue
    return None


def client() -> Path | None:
    """The CLI proper. The subcommand is passed as the first argument."""
    win = _find(["MEGAclient.exe", "MegaClient.exe", "megaClient.exe"])
    if win:
        return win
    posix = shutil.which("megacmd")
    if posix and Path(posix).name.lower() not in INTERACTIVE:
        return Path(posix)
    return None


def wrapper(command: str) -> Path | None:
    """The mega-<command>.bat shim, used only if no direct client was found."""
    return _find([f"mega-{command}.bat", f"mega-{command}.cmd", f"mega-{command}.exe"])


def available() -> bool:
    return client() is not None or wrapper("whoami") is not None


def missing_message() -> str:
    return (
        "the MEGAcmd CLI was not found.\n"
        "        Windows installs to %LOCALAPPDATA%\\MEGAcmd (MEGAclient.exe);\n"
        "        Linux installs /usr/bin/megacmd. Either put it on PATH or set\n"
        "        MEGACMD_HOME to the install directory."
    )


def build_argv(command: str, args: tuple | list) -> list[str]:
    extra = [str(a) for a in args]

    direct = client()
    if direct is not None:
        return [str(direct), command, *extra]

    shim = wrapper(command)
    if shim is None:
        raise MegaError(missing_message())
    if shim.suffix.lower() in (".bat", ".cmd"):
        comspec = os.environ.get("COMSPEC") or os.environ.get("ComSpec") or "cmd.exe"
        return [comspec, "/c", str(shim), *extra]
    return [str(shim), *extra]


# ---------------------------------------------------------------------------
# Output hygiene
# ---------------------------------------------------------------------------

# Progress redraws, and the boxed transfer lines that go with them.
_NOISE = re.compile(r"\b(TRANSFERRING|UPLOADING|DOWNLOADING|SCANNING|CHECKING)\b"
                    r"|\(\s*\d+\s*/\s*\d+\s*KB"
                    r"|\|[#.\s]*\|\s*\(\s*\d+\s*/", re.I)


def clean(text: str) -> str:
    """Drop progress redraws so only real lines survive."""
    if not text:
        return ""
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    keep = []
    for line in text.split("\n"):
        line = line.strip().strip("\x00").strip()
        if line and not _NOISE.search(line):
            keep.append(line)
    return "\n".join(keep)


# ---------------------------------------------------------------------------
# Running
# ---------------------------------------------------------------------------

def run(command: str, *args, timeout: int = DEFAULT_TIMEOUT,
        check: bool = True) -> Result:
    """Invoke a MEGAcmd subcommand. Raises MegaError unless check=False."""
    argv = build_argv(command, args)
    try:
        proc = subprocess.run(
            argv, capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=timeout)
    except subprocess.TimeoutExpired:
        raise MegaError(
            f"megacmd {command} did not finish within {timeout}s. "
            "MEGAcmd may be starting its server, resuming a session, or "
            "waiting on an MFA prompt.") from None
    except OSError as exc:
        raise MegaError(f"could not run {argv[0]}: {exc}") from None

    res = Result(command, argv, proc.returncode,
                 clean(proc.stdout or ""), clean(proc.stderr or ""))
    if check and res.code != 0:
        detail = res.err or res.out or "(no output)"
        raise MegaError(f"megacmd {command} failed (exit {res.code}): {detail}")
    return res


# ---------------------------------------------------------------------------
# Session
# ---------------------------------------------------------------------------

_EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")


def whoami(timeout: int = QUICK_TIMEOUT) -> str | None:
    """The logged-in account's email, or None if there is no usable session."""
    try:
        res = run("whoami", timeout=timeout, check=False)
    except MegaError:
        return None
    if res.code != 0:
        return None
    for line in res.text.splitlines():
        found = _EMAIL.search(line)
        if found:
            return found.group(0)
    return None


def logged_in(email: str | None = None, timeout: int = QUICK_TIMEOUT) -> bool:
    who = whoami(timeout)
    if not who:
        return False
    return who.lower() == email.lower() if email else True