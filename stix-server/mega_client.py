#!/usr/bin/env python3
"""MegaClient - a small SDK facade over the repository's ``mega/`` scripts.

The ``mega/`` directory is a set of importable modules and CLI entry points,
not a package. This facade gives a STIX bundler server one object to talk to:

    from mega_client import MegaClient

    client = MegaClient()
    client.status()
    client.list_bundles()
    client.export("quick_test", encrypt=True, link=True, expire="7d")
    client.retrieve("quick_test")

Design notes
------------
* Read-only/quick calls (session, listing, links) run in-process through the
  modules loaded from ``../mega``.
* Build/upload and download/extract run as subprocess **jobs**, because they
  print narration, can take minutes, and their exit code is the contract. Use
  ``export()`` / ``retrieve()`` to block, or ``start_export()`` /
  ``start_retrieve()`` for a ``Job`` you can poll.
* Nothing here changes the existing ``mega/`` scripts. The facade loads them by
  path and registers modules in ``sys.modules`` before executing, which is
  required for ``megacmd.py``'s module-level ``@dataclass`` on Python 3.13+.

The directory name ``stix-server`` contains a hyphen, so this file is not part
of an importable package. Run your server with ``stix-server`` on ``sys.path``,
or start scripts from inside that directory.
"""

from __future__ import annotations

import collections
import importlib.util
import json
import os
import re
import subprocess
import sys
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from loguru import logger

_log = logger.bind(sdk="mega")

__all__ = [
    "Bundle",
    "CommandResult",
    "Job",
    "MegaArgumentError",
    "MegaClient",
    "MegaCommandError",
    "MegaJobTimeout",
    "MegaNotAvailable",
    "MegaNotLoggedIn",
    "MegaProtectionError",
    "MegaRemoteError",
    "MegaSDKError",
]

ARTIFACT_SUFFIX = "_artifact"
ARCHIVE_SUFFIX = "_evidence.tar.gz"
ZIP_SUFFIX = "_evidence.zip"

# A plain artifact name: one path component, no separators, no leading dot.
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")

# Modules the others import by their top-level names. They are registered under
# those names so a script's ``import megacmd`` / ``import protect`` reuses the
# same module object (and therefore the same exception classes).
_REAL_NAMES = {"megacmd", "credential", "protect"}

# Load dependencies before the dependent module so its ``import`` statements
# find the real-name modules already in sys.modules.
_DEPENDENCIES = {
    "share": ("megacmd",),
    "list": ("megacmd",),
    "recover": ("megacmd",),
    "upload": ("megacmd", "protect"),
    "login": ("megacmd", "credential"),
    "protect": ("credential",),
}


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class MegaSDKError(RuntimeError):
    """Base class for every facade failure."""


class MegaArgumentError(MegaSDKError, ValueError):
    """A name, remote root, path or duration the wrapper would reject."""


class MegaNotAvailable(MegaSDKError):
    """The MEGAcmd CLI is not installed / cannot be found."""


class MegaNotLoggedIn(MegaSDKError):
    """A MEGAcmd session is required but there is none."""


class MegaRemoteError(MegaSDKError):
    """A MEGAcmd call failed for a reason other than missing CLI/session."""


class MegaProtectionError(MegaSDKError):
    """Password protection or unsealing failed."""


class MegaCommandError(MegaSDKError):
    """A subprocess script returned a non-zero exit code."""

    def __init__(self, message: str, result: "CommandResult"):
        super().__init__(message)
        self.result = result


class MegaJobTimeout(MegaSDKError):
    """A started job was cancelled because it exceeded its deadline."""

    def __init__(self, label: str, timeout: float, lines: list[str]):
        detail = "\n".join(lines[-20:])
        super().__init__(
            f"{label} exceeded {timeout:g}s and was cancelled."
            + (f"\nLast output:\n{detail}" if detail else "")
        )
        self.lines = lines


# ---------------------------------------------------------------------------
# Values
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Bundle:
    """One remote ``<name>_artifact`` folder."""

    name: str
    remote_path: str
    kind: str
    size: int
    date: str
    is_dir: bool = True

    @property
    def artifact(self) -> str:
        """The plain artifact name, without the ``_artifact`` folder suffix."""
        if self.name.endswith(ARTIFACT_SUFFIX):
            return self.name[: -len(ARTIFACT_SUFFIX)]
        return self.name

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "artifact": self.artifact,
            "remote_path": self.remote_path,
            "kind": self.kind,
            "size": self.size,
            "date": self.date,
            "is_dir": self.is_dir,
        }


@dataclass
class CommandResult:
    """The outcome of one CLI script run."""

    command: list[str]
    returncode: int
    stdout: str = ""
    stderr: str = ""
    data: dict[str, Any] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.returncode == 0

    @property
    def text(self) -> str:
        return "\n".join(p for p in (self.stdout, self.stderr) if p)

    def require_ok(self) -> "CommandResult":
        if not self.ok:
            message = (
                f"{Path(self.command[1] if len(self.command) > 1 else self.command[0]).name} "
                f"failed (exit {self.returncode}): "
                + (self.stderr.strip() or self.stdout.strip() or "(no output)")
            )
            _log.error(message)
            raise MegaCommandError(message, self)
        return self

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "returncode": self.returncode,
            "command": list(self.command),
            "stdout": self.stdout,
            "stderr": self.stderr,
            "data": dict(self.data),
        }


# ---------------------------------------------------------------------------
# Module loader
# ---------------------------------------------------------------------------

class _ModuleLoader:
    """Load ``mega/*.py`` by path, with sys.modules registration."""

    def __init__(self, mega_dir: Path):
        self.mega_dir = mega_dir
        self._cache: dict[str, Any] = {}
        self._lock = threading.RLock()

    def get(self, name: str):
        with self._lock:
            if name in self._cache:
                _log.trace("Using cached mega module {!r}", name)
                return self._cache[name]

            for dep in _DEPENDENCIES.get(name, ()):
                self.get(dep)

            path = self.mega_dir / f"{name}.py"
            if not path.is_file():
                message = f"{path} does not exist"
                _log.error("Cannot load mega module {!r}: {}", name, message)
                raise MegaSDKError(message)

            module_name = name if name in _REAL_NAMES else f"ia_mega_{name}"
            existing = sys.modules.get(module_name)
            if (existing is not None
                    and Path(getattr(existing, "__file__", "")).resolve() == path.resolve()):
                _log.trace("Reusing already imported mega module {!r}", module_name)
                self._cache[name] = existing
                return existing

            _log.debug("Loading mega module {!r} from {}", name, path)
            spec = importlib.util.spec_from_file_location(module_name, path)
            if spec is None or spec.loader is None:
                message = f"{path} could not be loaded"
                _log.error("Cannot load mega module {!r}: {}", name, message)
                raise MegaSDKError(message)
            module = importlib.util.module_from_spec(spec)
            # Register BEFORE exec: megacmd.py's @dataclass needs its defining
            # module to be present in sys.modules on Python 3.13+.
            sys.modules[module_name] = module
            try:
                spec.loader.exec_module(module)
            except Exception as exc:
                sys.modules.pop(module_name, None)
                _log.opt(exception=exc).error(
                    "Failed to import mega module {!r} from {}", name, path)
                raise

            self._cache[name] = module
            _log.debug("Loaded mega module {!r}", name)
            return module


# ---------------------------------------------------------------------------
# Job
# ---------------------------------------------------------------------------

class Job:
    """A running subprocess with captured, streamed output.

    ``start_export()`` / ``start_retrieve()`` return one of these. Poll with
    ``poll()``, inspect ``lines()``, and call ``wait()`` for the final
    ``CommandResult``. ``cancel()`` kills the process.
    """

    def __init__(self, popen: subprocess.Popen, command: list[str], *,
                 label: str = "", max_lines: int = 4000,
                 data: dict[str, Any] | None = None):
        self._popen = popen
        self.command = command
        self.label = label or Path(command[0]).name
        self.data = dict(data or {})
        self._lines: collections.deque[str] = collections.deque(maxlen=max_lines)
        self._seen = 0
        self._lock = threading.Lock()
        self._thread = threading.Thread(target=self._read, name=f"job-{popen.pid}",
                                        daemon=True)
        self._thread.start()

    def _read(self) -> None:
        stream = self._popen.stdout
        if stream is None:
            _log.warning("Job {!r} has no stdout stream to read", self.label)
            return
        try:
            for raw in stream:
                line = raw.rstrip("\r\n")
                with self._lock:
                    self._lines.append(line)
                    self._seen += 1
        except OSError as exc:
            _log.opt(exception=exc).warning(
                "Lost the output stream for job {!r}", self.label)
        finally:
            try:
                stream.close()
            except OSError:
                pass

    @property
    def pid(self) -> int:
        return self._popen.pid

    def poll(self) -> int | None:
        return self._popen.poll()

    def running(self) -> bool:
        return self.poll() is None

    def lines(self) -> list[str]:
        with self._lock:
            return list(self._lines)

    def dropped(self) -> int:
        with self._lock:
            return self._seen - len(self._lines)

    def cancel(self) -> None:
        if self.poll() is None:
            _log.warning("Cancelling job {!r} (pid {})", self.label, self.pid)
            try:
                self._popen.kill()
            except OSError as exc:
                _log.opt(exception=exc).error(
                    "Could not kill job {!r} (pid {})", self.label, self.pid)

    def wait(self, timeout: float | None = None) -> CommandResult:
        try:
            code = self._popen.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            _log.error(
                "Job {!r} exceeded its {!s}s deadline; cancelling", self.label, timeout)
            self.cancel()
            raise MegaJobTimeout(self.label, timeout, self.lines()) from None
        self._thread.join(timeout=5)
        result = CommandResult(
            command=self.command,
            returncode=code,
            stdout="\n".join(self.lines()),
            stderr="",
            data=dict(self.data),
        )
        if not result.ok:
            _log.error(
                "Job {!r} failed (exit {}):\n{}",
                self.label, code, _tail(result.text))
        else:
            _log.debug("Job {!r} finished successfully (exit 0)", self.label)
        return result

    def to_dict(self) -> dict[str, Any]:
        return {
            "pid": self.pid,
            "label": self.label,
            "running": self.running(),
            "returncode": self.poll(),
            "lines": self.lines(),
            "dropped": self.dropped(),
            "data": dict(self.data),
        }


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------

class MegaClient:
    """One-object facade over ``mega/`` for a bundler server.

    Parameters
    ----------
    repo_root:
        The checkout that contains ``mega/``. Defaults to ``IA_REPO_ROOT`` or
        the parent of this file's directory.
    remote_root:
        Default MEGA parent folder. Normalised to an absolute MEGA path.
    timeout:
        Seconds allowed for one MEGA operation (upload/recover). Default 300.
    quick_timeout:
        Seconds allowed for session/listing/link calls. Default 60.
    retrieve_timeout:
        Default subprocess deadline for a restore. Default 1800.
    grace:
        Extra seconds on top of a MEGA timeout before the subprocess is killed.
    python_executable:
        Interpreter used for the ``mega/`` scripts. Defaults to this one, so a
        server started from the project venv keeps its dependencies.
    max_job_lines:
        Ring-buffer size for a Job's captured output. Default 4000.
    """

    def __init__(
        self,
        repo_root: str | Path | None = None,
        *,
        remote_root: str = "/",
        timeout: int = 300,
        quick_timeout: int = 60,
        retrieve_timeout: int = 1800,
        grace: int = 180,
        python_executable: str | Path | None = None,
        max_job_lines: int = 4000,
    ):
        if repo_root is None:
            repo_root = os.environ.get("IA_REPO_ROOT")
        if repo_root is None:
            repo_root = Path(__file__).resolve().parent.parent
            if not (Path(repo_root) / "mega").is_dir():
                # Fall back to the current directory for an unusual layout.
                repo_root = Path.cwd()
        self.repo_root = Path(repo_root).resolve()
        self.mega_dir = self.repo_root / "mega"
        if not self.mega_dir.is_dir():
            message = f"no mega/ directory under {self.repo_root}"
            _log.error(message)
            raise MegaSDKError(message)

        self.remote_root = self._normalise_root(remote_root)
        self.timeout = int(timeout)
        self.quick_timeout = int(quick_timeout)
        self.retrieve_timeout = int(retrieve_timeout)
        self.grace = int(grace)
        self.python_executable = str(python_executable or sys.executable)
        self.max_job_lines = int(max_job_lines)
        self._modules = _ModuleLoader(self.mega_dir)
        _log.debug(
            "MegaClient ready: repo_root={} mega_dir={} remote_root={} "
            "timeout={}s quick_timeout={}s retrieve_timeout={}s",
            self.repo_root, self.mega_dir, self.remote_root,
            self.timeout, self.quick_timeout, self.retrieve_timeout,
        )

    # -- escape hatch -------------------------------------------------------

    def module(self, name: str):
        """Load and return a raw ``mega/`` module (``megacmd``, ``list``, ...)."""
        return self._modules.get(name)

    @property
    def megacmd(self):
        return self._modules.get("megacmd")

    # -- validation ---------------------------------------------------------

    @staticmethod
    def _plain_name(name: str) -> str:
        if not isinstance(name, str):
            message = "artifact name must be a string"
            _log.warning("Rejected artifact name: {}", message)
            raise MegaArgumentError(message)
        value = name.strip()
        if not value:
            message = "artifact name is empty"
            _log.warning("Rejected artifact name: {}", message)
            raise MegaArgumentError(message)
        if value.endswith(ARTIFACT_SUFFIX):
            message = (
                f"{value!r} is the bundle folder name; pass the artifact name "
                f"without {ARTIFACT_SUFFIX!r} (e.g. {value[:-len(ARTIFACT_SUFFIX)]!r})")
            _log.warning("Rejected artifact name: {}", message)
            raise MegaArgumentError(message)
        if not _NAME_RE.match(value):
            message = (
                f"invalid artifact name {value!r}: use letters, digits, '.', '_' "
                "or '-', starting with a letter or digit")
            _log.warning("Rejected artifact name: {}", message)
            raise MegaArgumentError(message)
        return value

    @staticmethod
    def _normalise_root(root: str | Path | None) -> str:
        if root is None:
            return "/"
        value = str(root).strip()
        if not value:
            return "/"
        if "\x00" in value:
            message = "remote root contains a NUL byte"
            _log.warning("Rejected remote root: {}", message)
            raise MegaArgumentError(message)
        value = value.replace("\\", "/")
        if any(part == ".." for part in value.split("/")):
            message = f"remote root may not contain '..': {root!r}"
            _log.warning("Rejected remote root: {}", message)
            raise MegaArgumentError(message)
        parts = [p for p in value.split("/") if p not in ("", ".")]
        return "/" + "/".join(parts) if parts else "/"

    def _root(self, remote_root: str | Path | None = None) -> str:
        return self._normalise_root(self.remote_root if remote_root is None else remote_root)

    def bundle_path(self, name: str, remote_root: str | Path | None = None) -> str:
        """``<root>/<name>_artifact``, with a plain-name check."""
        plain = self._plain_name(name)
        root = self._root(remote_root)
        return f"{root}/{plain}{ARTIFACT_SUFFIX}".replace("//", "/")

    def _bundle_location(self, bundle_path: str | Path) -> tuple[str, str]:
        """Return the artifact name and remote parent for a full bundle path."""
        value = self._normalise_root(bundle_path)
        name = value.rsplit("/", 1)[-1]
        if not name.endswith(ARTIFACT_SUFFIX):
            message = (
                f"remote bundle path must end in {ARTIFACT_SUFFIX!r}: {bundle_path!r}")
            _log.warning("Rejected bundle path: {}", message)
            raise MegaArgumentError(message)
        artifact = self._plain_name(name[:-len(ARTIFACT_SUFFIX)])
        root = value.rsplit("/", 1)[0] or "/"
        return artifact, root

    def _target(self, name_or_path: str, remote_root: str | Path | None = None) -> str:
        """Resolve an artifact name or an absolute remote path for link calls."""
        value = str(name_or_path or "").strip()
        if not value:
            message = "remote path or artifact name is empty"
            _log.warning("Rejected link target: {}", message)
            raise MegaArgumentError(message)
        if value.startswith("/") or "/" in value or "\\" in value:
            return self._normalise_root(value)
        return self.bundle_path(value, remote_root)

    def _resolve(self, path: str | Path | None) -> Path | None:
        """Absolute, canonical path (also expands Windows 8.3 short names).

        Canonicalising matters for ``restore.py``: it compares paths from
        ``os.walk`` against the destination it was handed, and a short 8.3
        temp path (``C:\\Users\\THE4TH~1\\...``) does not compare equal to the
        long form ``os.walk`` reports.
        """
        if path is None:
            return None
        p = Path(path)
        return (p if p.is_absolute() else (self.repo_root / p)).resolve()

    # -- status -------------------------------------------------------------

    def status(self) -> dict[str, Any]:
        """Best-effort health snapshot. Never raises.

        Keys: ``available``, ``cli``, ``account``, ``expected_account``,
        ``account_matches``, ``session_ok``, ``remote_root``, ``password_file``,
        ``password_present``, ``secrets_dir``, ``repo_root``, ``error``.
        """
        out: dict[str, Any] = {
            "available": False,
            "cli": None,
            "account": None,
            "expected_account": None,
            "account_matches": None,
            "session_ok": False,
            "remote_root": self.remote_root,
            "password_file": None,
            "password_present": False,
            "secrets_dir": None,
            "repo_root": str(self.repo_root),
            "error": None,
        }
        try:
            mc = self.megacmd
            out["available"] = bool(mc.available())
            out["cli"] = str(mc.client()) if mc.client() else None
            if out["available"]:
                out["account"] = mc.whoami(self.quick_timeout)
                out["session_ok"] = out["account"] is not None
            else:
                _log.warning("MEGAcmd is not available: {}", mc.missing_message())
            if out["available"] and not out["session_ok"]:
                _log.warning("MEGAcmd is installed but no session is logged in")
        except Exception as exc:  # noqa: BLE001 - status is a report, not a crash
            out["error"] = f"{type(exc).__name__}: {exc}"
            _log.opt(exception=exc).warning("MEGA status check failed")
            return out

        try:
            protect = self._modules.get("protect")
            out["password_file"] = str(protect.password_file())
            out["password_present"] = bool(protect.password_present())
            if not out["password_present"]:
                _log.warning("No bundle password is present at {}", out["password_file"])
        except Exception as exc:  # noqa: BLE001
            out["error"] = f"password: {type(exc).__name__}: {exc}"
            _log.opt(exception=exc).warning("MEGA password check failed")

        try:
            credential = self._modules.get("credential")
            out["secrets_dir"] = str(credential.secrets_dir())
            out["expected_account"] = self._sealed_email(credential)
            if out["expected_account"] and out["account"]:
                out["account_matches"] = (
                    out["expected_account"].lower() == out["account"].lower())
                if not out["account_matches"]:
                    _log.warning(
                        "MEGA session account {!r} does not match the sealed "
                        "expected account {!r}",
                        out["account"], out["expected_account"])
        except Exception as exc:  # noqa: BLE001
            out["error"] = f"credential: {type(exc).__name__}: {exc}"
            _log.opt(exception=exc).warning("MEGA credential check failed")

        return out

    def account(self) -> str | None:
        """The logged-in address, or ``None``."""
        return self.megacmd.whoami(self.quick_timeout)

    def require_session(self) -> str:
        """Return the account, or raise ``MegaNotAvailable``/``MegaNotLoggedIn``."""
        mc = self.megacmd
        if not mc.available():
            message = mc.missing_message()
            _log.error("MEGA session required but MEGAcmd is unavailable: {}", message)
            raise MegaNotAvailable(message)
        account = mc.whoami(self.quick_timeout)
        if not account:
            message = (
                "no MEGAcmd session. Run: python mega/login.py --emit check --mega")
            _log.error("MEGA session required but none is logged in")
            raise MegaNotLoggedIn(message)
        _log.debug("MEGA session is logged in as {!r}", account)
        return account

    @staticmethod
    def _sealed_email(credential) -> str | None:
        """The expected account from the keyfile seal, or None. Never the password."""
        try:
            enc, key = credential.DEFAULT_ENC, credential.DEFAULT_KEY
            if not (enc.is_file() and key.is_file()):
                return None
            data = credential.open_sealed(enc, key=credential.read_key_file(key))
            value = data.get("email")
            return value if isinstance(value, str) else None
        except Exception:  # noqa: BLE001 - a missing seal only disables the guard
            return None

    # -- listing ------------------------------------------------------------

    def ls(self, remote_path: str | Path = "/", timeout: int | None = None) -> list[dict]:
        """Raw ``ls -l`` rows for one remote path."""
        mc = self.megacmd
        listing = self._modules.get("list")
        path = self._normalise_root(remote_path)
        _log.debug("Listing MEGA path {!r}", path)
        try:
            rows = listing.ls(path, timeout or self.timeout)
        except mc.MegaError as exc:
            _log.opt(exception=exc).error("Could not list MEGA path {!r}", path)
            raise MegaRemoteError(str(exc)) from exc
        _log.debug("MEGA path {!r} returned {} row(s)", path, len(rows))
        return rows

    def list_bundles(self, remote_root: str | Path | None = None, *,
                     all: bool = False, timeout: int | None = None) -> list[Bundle]:
        """Bundle folders under ``remote_root`` (``*_artifact`` unless ``all``)."""
        root = self._root(remote_root)
        rows = self.ls(root, timeout=timeout)
        bundles: list[Bundle] = []
        for row in rows:
            if not row.get("is_dir"):
                continue
            name = row["name"]
            if not all and not name.endswith(ARTIFACT_SUFFIX):
                continue
            bundles.append(Bundle(
                name=name,
                remote_path=f"{root}/{name}".replace("//", "/"),
                kind=row.get("kind", "d"),
                size=int(row.get("size") or 0),
                date=row.get("date", ""),
                is_dir=True,
            ))
        _log.debug("Found {} bundle(s) under {!r}", len(bundles), root)
        return bundles

    def exists(self, name: str, remote_root: str | Path | None = None) -> bool:
        """Whether ``<root>/<name>_artifact`` is present. Best-effort."""
        target = self.bundle_path(name, remote_root)
        try:
            res = self.megacmd.run("ls", target, timeout=self.quick_timeout, check=False)
        except self.megacmd.MegaError as exc:
            _log.opt(exception=exc).debug("Existence check failed for {!r}", target)
            return False
        _log.debug("Existence check for {!r}: {}", target, res.code == 0)
        return res.code == 0

    def bundle_files(
        self,
        name: str,
        remote_root: str | Path | None = None,
        timeout: int | None = None,
    ) -> list[dict]:
        """The files inside one bundle, with per-file SHA-256 hashes.

        Downloads the bundle's ``manifest.json`` (written by ``mega/upload.py``)
        and returns one entry per file::

            {"path": "notes.txt", "size": 16, "hash": "f0852a..."}

        Bundles built before per-file hashes were added will have entries
        without a ``hash`` value. Returns an empty list when the bundle
        does not exist or its manifest cannot be read.
        """
        plain = self._plain_name(name)
        root = self._root(remote_root)
        bundle_path = f"{root}/{plain}{ARTIFACT_SUFFIX}".replace("//", "/")

        rows = self.ls(bundle_path, timeout or self.quick_timeout)
        files = [r for r in rows if not r["is_dir"]]

        hashes = self._manifest_hashes(bundle_path)

        out: list[dict] = []
        for r in files:
            out.append({
                "path": r["name"],
                "size": r["size"],
                "hash": hashes.get(r["name"], ""),
            })
        return out

    def _manifest_hashes(self, bundle_path: str) -> dict[str, str]:
        """Download ``manifest.json`` from a bundle and return {filename: sha256}."""
        import tempfile
        import shutil
        from pathlib import Path

        manifest_name = "manifest.json"
        remote_manifest = f"{bundle_path}/{manifest_name}".replace("//", "/")
        tmpdir = Path(tempfile.mkdtemp(prefix="ia-bundle-files-"))
        hashes: dict[str, str] = {}
        try:
            res = self.megacmd.run("get", remote_manifest, str(tmpdir),
                                   timeout=self.quick_timeout)
            if res.code != 0:
                return hashes
            candidates = list(tmpdir.rglob(manifest_name))
            if not candidates:
                return hashes
            manifest = json.loads(candidates[0].read_text(encoding="utf-8"))
            for entry in manifest.get("files", []):
                if isinstance(entry, dict) and "path" in entry and "hash" in entry:
                    hashes[entry["path"]] = entry["hash"]
        except Exception:
            pass
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)
        return hashes

    def _manifest_document(self, bundle_path: str) -> dict[str, Any]:
        """Download and parse a bundle's ``manifest.json``, or return ``{}``."""
        import tempfile
        import shutil

        manifest_name = "manifest.json"
        remote_manifest = f"{bundle_path}/{manifest_name}".replace("//", "/")
        tmpdir = Path(tempfile.mkdtemp(prefix="ia-bundle-manifest-"))
        try:
            res = self.megacmd.run("get", remote_manifest, str(tmpdir),
                                   timeout=self.quick_timeout)
            if res.code != 0:
                return {}
            candidates = list(tmpdir.rglob(manifest_name))
            if not candidates:
                return {}
            manifest = json.loads(candidates[0].read_text(encoding="utf-8"))
            return manifest if isinstance(manifest, dict) else {}
        except Exception as exc:
            _log.debug("Could not read manifest for bundle {!r}: {}", bundle_path, exc)
            return {}
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def find_bundles_by_hash(
        self,
        sha256_hash: str,
        remote_root: str | Path | None = None,
        *,
        timeout: int | None = None,
    ) -> list[str]:
        """Artifact names whose bundle manifest contains ``sha256_hash``.

        Every bundle under ``remote_root`` is checked by reading its
        ``manifest.json``. A bundle matches when either its ``archive_sha256``
        or one of its ``files[].hash`` values equals the digest. Matching is
        case-insensitive and ignores surrounding whitespace.

        Returns plain artifact names (no ``_artifact`` suffix), ready to pass
        to :meth:`retrieve`. Bundles without a readable manifest are skipped.
        """
        if not isinstance(sha256_hash, str):
            message = "sha256_hash must be a string"
            _log.warning("Rejected SHA-256 lookup: {}", message)
            raise MegaArgumentError(message)
        digest = sha256_hash.strip().lower()
        if not digest:
            message = "sha256_hash is empty"
            _log.warning("Rejected SHA-256 lookup: {}", message)
            raise MegaArgumentError(message)

        _log.debug("Searching bundles under {!r} for sha256_hash={}",
                   remote_root, digest)
        matches: list[str] = []
        for bundle in self.list_bundles(remote_root, timeout=timeout):
            manifest = self._manifest_document(bundle.remote_path)
            if not manifest:
                _log.debug("Skipping bundle {!r}: no readable manifest",
                           bundle.artifact)
                continue

            archive_hash = str(manifest.get("archive_sha256") or "").strip().lower()
            found = archive_hash == digest
            if not found:
                for entry in manifest.get("files") or []:
                    if not isinstance(entry, dict):
                        continue
                    file_hash = str(entry.get("hash") or "").strip().lower()
                    if file_hash == digest:
                        found = True
                        break
            if found:
                _log.debug("Bundle {!r} matches sha256_hash={}",
                           bundle.artifact, digest)
                matches.append(bundle.artifact)

        _log.info("SHA-256 lookup {} matched {} bundle(s): {}",
                  digest, len(matches), matches)
        return matches

    # -- links --------------------------------------------------------------

    def list_links(self, remote_root: str | Path | None = None) -> list[dict]:
        """Every current export, optionally filtered to one remote subtree."""
        share = self._modules.get("share")
        root = self._root(remote_root)
        _log.debug("Listing MEGA exports under {!r}", root)
        try:
            exports = share.list_exports(self.quick_timeout)
        except self.megacmd.MegaError as exc:
            _log.opt(exception=exc).error("Could not list MEGA exports")
            raise MegaRemoteError(str(exc)) from exc
        if root == "/":
            _log.debug("Found {} export(s)", len(exports))
            return exports
        filtered = [e for e in exports
                    if e["path"] == root or e["path"].startswith(root + "/")]
        _log.debug("Found {} export(s) under {!r}", len(filtered), root)
        return filtered

    def exported_link(self, name_or_path: str,
                      remote_root: str | Path | None = None) -> str | None:
        """Read an existing public link. Never creates one."""
        target = self._target(name_or_path, remote_root)
        share = self._modules.get("share")
        _log.debug("Reading existing public link for {!r}", target)
        try:
            link = share.show(target, self.quick_timeout)
        except self.megacmd.MegaError as exc:
            _log.opt(exception=exc).error(
                "Could not read public link for {!r}", target)
            raise MegaRemoteError(str(exc)) from exc
        _log.debug("Public link for {!r}: {}", target, "present" if link else "absent")
        return link

    def link(self, name_or_path: str, remote_root: str | Path | None = None, *,
             create: bool = False, expire: str | None = None,
             permanent: bool = False) -> dict[str, Any]:
        """Read a public link, or create one when ``create=True``.

        ``expire`` uses MEGA's grammar (``12h``, ``7d``, ``1m12d3h``). When
        neither ``expire`` nor ``permanent`` is given, ``config/share.json`` is
        used, exactly like ``share.py --create``. An existing link is reused.
        """
        target = self._target(name_or_path, remote_root)
        share = self._modules.get("share")
        mc = self.megacmd

        if not create:
            link = self.exported_link(target)
            return {"ok": True, "path": target, "link": link,
                    "exported": link is not None, "created": False,
                    "expire": None}

        if permanent:
            chosen = None
        elif expire is not None:
            chosen = str(expire).strip()
            if not mc.valid_duration(chosen):
                message = (
                    f"invalid MEGA expiry {expire!r}: use e.g. 12h, 7d or 1m12d3h "
                    "(M = minutes, m = months)")
                _log.warning("Rejected MEGA expiry: {}", message)
                raise MegaArgumentError(message)
        else:
            try:
                chosen = share.configured_expire()
            except ValueError as exc:
                message = f"{exc}. Pass permanent=True to override."
                _log.opt(exception=exc).warning("Invalid configured MEGA expiry")
                raise MegaArgumentError(message) from exc

        _log.info("Creating public link for {!r} (expire={!r})", target, chosen)
        try:
            created, link = share.create(target, self.quick_timeout, expire=chosen)
        except mc.MegaError as exc:
            _log.opt(exception=exc).error(
                "Could not create public link for {!r}", target)
            raise MegaRemoteError(str(exc)) from exc
        _log.debug("Public link for {!r} created={} expire={!r}",
                   target, created, chosen)
        return {"ok": True, "path": target, "link": link, "exported": True,
                "created": created, "expire": chosen}

    def revoke_link(self, name_or_path: str,
                    remote_root: str | Path | None = None) -> dict[str, Any]:
        """Revoke a public link. ``deleted=False`` means it was not exported."""
        target = self._target(name_or_path, remote_root)
        share = self._modules.get("share")
        _log.info("Revoking public link for {!r}", target)
        try:
            removed = share.revoke(target, self.quick_timeout)
        except self.megacmd.MegaError as exc:
            _log.opt(exception=exc).error(
                "Could not revoke public link for {!r}", target)
            raise MegaRemoteError(str(exc)) from exc
        if not removed:
            _log.warning("No public link existed for {!r}", target)
        return {"ok": True, "path": target, "deleted": bool(removed)}

    # -- protection ---------------------------------------------------------

    def password_file(self) -> Path:
        """The operator bundle password file in use (it may not exist)."""
        return Path(self._modules.get("protect").password_file())

    def password_present(self, password_file: str | Path | None = None) -> bool:
        protect = self._modules.get("protect")
        path = Path(password_file) if password_file else None
        present = bool(protect.password_present(path))
        _log.debug("Bundle password present={} (file={!s})", present,
                   path or self.password_file())
        return present

    def set_password(self, value: str | bytes,
                     password_file: str | Path | None = None) -> Path:
        """Write the operator password byte-exact. Minimum 8 bytes."""
        protect = self._modules.get("protect")
        try:
            path = Path(protect.set_password(
                value, Path(password_file) if password_file else None))
        except protect.PasswordError as exc:
            _log.opt(exception=exc).error("Could not store the MEGA bundle password")
            raise MegaProtectionError(str(exc)) from exc
        _log.info("Stored the MEGA bundle password in {}", path)
        return path

    def generate_password(self, length: int = 24,
                          password_file: str | Path | None = None) -> tuple[str, Path]:
        """Generate and store a password; returns it once. Never logged."""
        protect = self._modules.get("protect")
        try:
            value, path = protect.generate_password(
                length, Path(password_file) if password_file else None)
            path = Path(path)
        except protect.PasswordError as exc:
            _log.opt(exception=exc).error(
                "Could not generate the MEGA bundle password")
            raise MegaProtectionError(str(exc)) from exc
        _log.info("Generated a {} character MEGA bundle password in {}",
                  length, path)
        return value, path

    def encrypt_archive(self, archive: str | Path,
                        out_zip: str | Path | None = None,
                        password_file: str | Path | None = None) -> dict[str, Any]:
        """Wrap ``archive`` in a WinZip AES-256 zip. Returns the manifest fragment."""
        protect = self._modules.get("protect")
        source = Path(archive)
        target = Path(out_zip) if out_zip else source.with_suffix(".zip")
        _log.debug("Encrypting archive {!s} -> {!s}", source, target)
        try:
            password = protect.read_password(
                Path(password_file) if password_file else None)
            return protect.zip_bundle(source, target, password)
        except protect.PasswordError as exc:
            _log.opt(exception=exc).error(
                "Could not encrypt archive {!s}", source)
            raise MegaProtectionError(str(exc)) from exc

    def decrypt_archive(self, zip_path: str | Path, out_dir: str | Path,
                        password_file: str | Path | None = None) -> Path:
        """Recover the archive from a protected zip."""
        protect = self._modules.get("protect")
        _log.debug("Decrypting archive {!s} -> {!s}", zip_path, out_dir)
        try:
            password = protect.read_password(
                Path(password_file) if password_file else None)
            return Path(protect.unzip_bundle(Path(zip_path), Path(out_dir), password))
        except protect.PasswordError as exc:
            _log.opt(exception=exc).error(
                "Could not decrypt archive {!s}", zip_path)
            raise MegaProtectionError(str(exc)) from exc

    # -- export -------------------------------------------------------------

    def export(self, name: str, *, source: str | Path | None = None,
               remote_root: str | Path | None = None,
               out_root: str | Path | None = None,
               encrypt: bool = True, timeout: int | None = None,
               password_file: str | Path | None = None,
               expect_account: str | None = None,
               dry_run: bool = False, no_upload: bool = False,
               link: bool = False, expire: str | None = None,
               permanent: bool = False,
               color: str = "never") -> CommandResult:
        """Build a bundle and upload it. Blocks; use ``start_export`` for a job.

        Exit codes are the ``upload.py`` contract: ``0`` ok, ``1`` failed,
        ``2`` bad arguments, ``3`` built but MEGA unavailable, ``4`` protection
        failed (nothing uploaded). The result's ``data`` carries ``artifact``,
        ``bundle_dir``, ``remote_path``, ``encrypted`` and ``link``.
        """
        command, data, deadline = self._export_command(
            name, source=source, remote_root=remote_root, out_root=out_root,
            encrypt=encrypt, timeout=timeout, password_file=password_file,
            expect_account=expect_account, dry_run=dry_run,
            no_upload=no_upload, link=link, expire=expire,
            permanent=permanent, color=color)
        _log.info(
            "Exporting bundle {!r} (encrypt={} dry_run={} no_upload={} link={})",
            name, encrypt, dry_run, no_upload, link)
        result = self._run(command, timeout=deadline)
        result.data.update(data)
        if result.ok:
            _log.info("Bundle {!r} exported successfully", name)
        if result.ok and not no_upload and link:
            try:
                info = self.link(name, remote_root=remote_root, create=True,
                                 expire=expire, permanent=permanent)
                result.data["link"] = info["link"]
                result.data["link_created"] = info["created"]
                result.data["link_expire"] = info["expire"]
            except Exception as exc:  # noqa: BLE001 - bytes are safe; link is extra
                _log.opt(exception=exc).warning(
                    "Bundle {!r} was exported but its public link failed", name)
                result.data["link"] = None
                result.data["link_error"] = f"{type(exc).__name__}: {exc}"
        return result

    def start_export(self, name: str, **kwargs: Any) -> Job:
        """Start ``export`` as a job. Same keyword arguments; returns ``Job``."""
        command, data, _deadline = self._export_command(name, **kwargs)
        popen = self._popen(command)
        _log.info("Started export job for {!r} (pid {})", name, popen.pid)
        return Job(popen, command, label=f"export {name}",
                   max_lines=self.max_job_lines, data=data)

    def _export_command(self, name: str, *, source=None, remote_root=None,
                        out_root=None, encrypt=True, timeout=None,
                        password_file=None, expect_account=None,
                        dry_run=False, no_upload=False,
                        link=False, expire=None, permanent=False,
                        color="never") -> tuple[list[str], dict[str, Any], float]:
        plain = self._plain_name(name)
        root = self._root(remote_root)
        op_timeout = int(timeout or self.timeout)
        source_path = self._resolve(source)
        out_root_path = self._resolve(out_root) or (self.repo_root / "exports")
        password_path = self._resolve(password_file)

        command = [
            self.python_executable, str(self.mega_dir / "upload.py"),
            "--artifact", plain,
            "--remote-root", root,
            "--timeout", str(op_timeout),
            "--encrypt" if encrypt else "--no-encrypt",
            "--color", color,
        ]
        if source_path is not None:
            command += ["--source", str(source_path)]
        if out_root is not None:
            command += ["--out-root", str(out_root_path)]
        if password_path is not None:
            command += ["--password-file", str(password_path)]
        if expect_account:
            command += ["--expect-account", expect_account]
        if dry_run:
            command += ["--dry-run"]
        if no_upload:
            command += ["--no-upload"]

        data = {
            "artifact": plain,
            "bundle_dir": str(out_root_path / f"{plain}{ARTIFACT_SUFFIX}"),
            "remote_root": root,
            "encrypted": bool(encrypt),
            "uploaded": False,
            # Only export() acts on these; start_export() leaves the link to the
            # caller once the job reports success.
            "link_requested": bool(link),
            "link_expire": expire,
        }
        if not no_upload:
            data["remote_path"] = f"{root}/{plain}{ARTIFACT_SUFFIX}".replace("//", "/")
        return command, data, op_timeout + self.grace

    # -- retrieve -----------------------------------------------------------

    def retrieve(self, name: str, *, remote_root: str | Path | None = None,
                 dest: str | Path | None = None,
                 out_root: str | Path | None = None,
                 mode: str = "restore", timeout: int | None = None,
                 force: bool = False, verify_only: bool = False,
                 bundle: str | Path | None = None) -> CommandResult:
        """Download a bundle and verify it. Blocks; use ``start_retrieve`` for a job.

        ``mode="restore"`` runs ``restore.py``: digest verification *before*
        extraction, safe tar handling, then a per-file manifest check.
        ``dest`` is the final tree, default ``exports/<name>_recovered``.
        ``mode="recover"`` runs ``recover.py``: download + archive digest only;
        ``out_root`` is the parent and ``force`` overwrites a local copy.

        ``name`` may be an artifact name or a full remote bundle path such as
        ``/evidence/quick_test_artifact``.
        ``verify_only=True`` (restore) checks a local ``bundle`` without the
        network; ``bundle`` is the ``<name>_artifact`` directory.
        """
        command, data, deadline = self._retrieve_command(
            name, remote_root=remote_root, dest=dest, out_root=out_root,
            mode=mode, timeout=timeout, force=force,
            verify_only=verify_only, bundle=bundle)
        _log.info("Retrieving bundle {!r} (mode={})", name, data.get("mode", mode))
        result = self._run(command, timeout=deadline)
        result.data.update(data)
        if result.ok:
            _log.info("Bundle {!r} retrieved successfully", name)
        return result

    def retrieve_bundle(self, bundle_path: str | Path, **kwargs: Any) -> CommandResult:
        """Retrieve a bundle by its full remote path, e.g. ``/evidence/foo_artifact``."""
        if "remote_root" in kwargs:
            message = "remote_root cannot be combined with a full bundle path"
            _log.warning("Rejected retrieve_bundle call: {}", message)
            raise MegaArgumentError(message)
        artifact, root = self._bundle_location(bundle_path)
        return self.retrieve(artifact, remote_root=root, **kwargs)

    def start_retrieve(self, name: str, **kwargs: Any) -> Job:
        """Start ``retrieve`` as a job. Same keyword arguments; returns ``Job``."""
        command, data, _deadline = self._retrieve_command(name, **kwargs)
        popen = self._popen(command)
        _log.info("Started retrieve job for {!r} (pid {})", name, popen.pid)
        return Job(popen, command, label=f"retrieve {name}",
                   max_lines=self.max_job_lines, data=data)

    def _retrieve_command(self, name: str, *, remote_root=None, dest=None,
                          out_root=None, mode="restore", timeout=None,
                          force=False, verify_only=False,
                          bundle=None) -> tuple[list[str], dict[str, Any], float]:
        if isinstance(name, (str, Path)) and ("/" in str(name) or "\\" in str(name)):
            plain, root = self._bundle_location(name)
            if remote_root is not None:
                message = "remote_root cannot be combined with a full bundle path"
                _log.warning("Rejected retrieve call: {}", message)
                raise MegaArgumentError(message)
        else:
            plain = self._plain_name(name)
            root = self._root(remote_root)
        chosen_mode = str(mode or "restore").lower()
        op_timeout = int(timeout or self.timeout)

        if chosen_mode not in ("restore", "recover"):
            message = "mode must be 'restore' or 'recover'"
            _log.warning("Rejected retrieve call: {}", message)
            raise MegaArgumentError(message)

        dest_path = self._resolve(dest)
        out_root_path = self._resolve(out_root)

        if chosen_mode == "restore":
            command = [self.python_executable, str(self.mega_dir / "restore.py")]
            if verify_only:
                if bundle is None:
                    message = "verify_only needs bundle=<local *_artifact dir>"
                    _log.warning("Rejected restore verification: {}", message)
                    raise MegaArgumentError(message)
                bundle_path = self._resolve(bundle)
                if bundle_path is None or not bundle_path.is_dir():
                    message = f"bundle directory not found: {bundle}"
                    _log.warning("Rejected restore verification: {}", message)
                    raise MegaArgumentError(message)
                command += ["--verify-only", "--bundle", str(bundle_path),
                            "--artifact", plain]
                if dest_path is not None:
                    command += ["--dest", str(dest_path)]
                deadline = self.retrieve_timeout
                data = {"artifact": plain, "mode": "restore",
                        "bundle": str(bundle_path), "network": False,
                        "dest": str(dest_path or (self.repo_root / "exports"
                                                 / f"{plain}_recovered"))}
            else:
                command += ["--artifact", plain, "--remote-root", root]
                if dest_path is not None:
                    command += ["--dest", str(dest_path)]
                deadline = int(timeout or self.retrieve_timeout)
                data = {"artifact": plain, "mode": "restore",
                        "remote_path": f"{root}/{plain}{ARTIFACT_SUFFIX}".replace("//", "/"),
                        "dest": str(dest_path or (self.repo_root / "exports"
                                                 / f"{plain}_recovered")),
                        "network": True}
            return command, data, deadline

        # recover.py: download + digest verification only
        command = [
            self.python_executable, str(self.mega_dir / "recover.py"),
            "--artifact", plain,
            "--remote-root", root,
            "--timeout", str(op_timeout),
        ]
        if out_root_path is not None:
            command += ["--out-root", str(out_root_path)]
        if force:
            command += ["--force"]
        actual_root = out_root_path or (self.repo_root / "exports")
        data = {
            "artifact": plain,
            "mode": "recover",
            "remote_path": f"{root}/{plain}{ARTIFACT_SUFFIX}".replace("//", "/"),
            "out_root": str(actual_root),
            "local_path": str(actual_root / f"{plain}{ARTIFACT_SUFFIX}"),
            "network": True,
        }
        return command, data, op_timeout + self.grace

    # -- process helpers ----------------------------------------------------

    def _popen(self, command: list[str]) -> subprocess.Popen:
        _log.debug("Starting MEGA subprocess: {}", _command_text(command))
        try:
            return subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
                cwd=str(self.repo_root),
            )
        except OSError as exc:
            _log.opt(exception=exc).error(
                "Could not start MEGA subprocess: {}", _command_text(command))
            raise

    def _run(self, command: list[str], timeout: float | None) -> CommandResult:
        _log.debug("Running MEGA subprocess: {}", _command_text(command))
        try:
            proc = subprocess.run(
                command,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                cwd=str(self.repo_root),
            )
            result = CommandResult(command, proc.returncode,
                                   proc.stdout or "", proc.stderr or "")
        except subprocess.TimeoutExpired as exc:
            _log.error(
                "MEGA subprocess timed out after {}s: {}",
                timeout, _command_text(command))
            return CommandResult(
                command, -1,
                _as_text(exc.stdout),
                _as_text(exc.stderr) or f"timed out after {timeout}s",
            )
        except OSError as exc:
            _log.opt(exception=exc).error(
                "Could not start MEGA subprocess: {}", _command_text(command))
            return CommandResult(command, -1, "", f"could not start: {exc}")

        if not result.ok:
            _log.error(
                "MEGA subprocess failed (exit {}): {}\n{}",
                result.returncode, _command_text(command), _tail(result.text))
        return result


def _command_text(command: list[str]) -> str:
    return " ".join(str(part) for part in command)


def _tail(text: str, limit: int = 2000) -> str:
    value = (text or "").strip()
    return value if len(value) <= limit else "..." + value[-limit:]


def _as_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value)


def _main(argv: list[str] | None = None) -> int:
    """``python mega_client.py [status|bundles|links]`` — a quick inspection."""
    import argparse

    ap = argparse.ArgumentParser(description="inspect MEGA through MegaClient")
    ap.add_argument("action", nargs="?", choices=("status", "bundles", "links"),
                    default="status")
    ap.add_argument("--remote-root", default="/")
    ap.add_argument("--all", action="store_true",
                    help="list every folder, not just *_artifact")
    args = ap.parse_args(argv)

    client = MegaClient(remote_root=args.remote_root)
    if args.action == "status":
        print(json.dumps(client.status(), indent=2))
        return 0
    if args.action == "bundles":
        payload = [b.to_dict() for b in client.list_bundles(all=args.all)]
    else:
        payload = client.list_links()
    print(json.dumps(payload, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
