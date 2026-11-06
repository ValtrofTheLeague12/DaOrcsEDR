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
            raise MegaCommandError(
                f"{Path(self.command[1] if len(self.command) > 1 else self.command[0]).name} "
                f"failed (exit {self.returncode}): "
                + (self.stderr.strip() or self.stdout.strip() or "(no output)"),
                self,
            )
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
                return self._cache[name]

            for dep in _DEPENDENCIES.get(name, ()):
                self.get(dep)

            path = self.mega_dir / f"{name}.py"
            if not path.is_file():
                raise MegaSDKError(f"{path} does not exist")

            module_name = name if name in _REAL_NAMES else f"ia_mega_{name}"
            existing = sys.modules.get(module_name)
            if (existing is not None
                    and Path(getattr(existing, "__file__", "")).resolve() == path.resolve()):
                self._cache[name] = existing
                return existing

            spec = importlib.util.spec_from_file_location(module_name, path)
            if spec is None or spec.loader is None:
                raise MegaSDKError(f"{path} could not be loaded")
            module = importlib.util.module_from_spec(spec)
            # Register BEFORE exec: megacmd.py's @dataclass needs its defining
            # module to be present in sys.modules on Python 3.13+.
            sys.modules[module_name] = module
            try:
                spec.loader.exec_module(module)
            except Exception:
                sys.modules.pop(module_name, None)
                raise

            self._cache[name] = module
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
            return
        try:
            for raw in stream:
                line = raw.rstrip("\r\n")
                with self._lock:
                    self._lines.append(line)
                    self._seen += 1
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
            try:
                self._popen.kill()
            except OSError:
                pass

    def wait(self, timeout: float | None = None) -> CommandResult:
        try:
            code = self._popen.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.cancel()
            raise MegaJobTimeout(self.label, timeout, self.lines()) from None
        self._thread.join(timeout=5)
        return CommandResult(
            command=self.command,
            returncode=code,
            stdout="\n".join(self.lines()),
            stderr="",
            data=dict(self.data),
        )

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
            raise MegaSDKError(f"no mega/ directory under {self.repo_root}")

        self.remote_root = self._normalise_root(remote_root)
        self.timeout = int(timeout)
        self.quick_timeout = int(quick_timeout)
        self.retrieve_timeout = int(retrieve_timeout)
        self.grace = int(grace)
        self.python_executable = str(python_executable or sys.executable)
        self.max_job_lines = int(max_job_lines)
        self._modules = _ModuleLoader(self.mega_dir)

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
            raise MegaArgumentError("artifact name must be a string")
        value = name.strip()
        if not value:
            raise MegaArgumentError("artifact name is empty")
        if value.endswith(ARTIFACT_SUFFIX):
            raise MegaArgumentError(
                f"{value!r} is the bundle folder name; pass the artifact name "
                f"without {ARTIFACT_SUFFIX!r} (e.g. {value[:-len(ARTIFACT_SUFFIX)]!r})")
        if not _NAME_RE.match(value):
            raise MegaArgumentError(
                f"invalid artifact name {value!r}: use letters, digits, '.', '_' "
                "or '-', starting with a letter or digit")
        return value

    @staticmethod
    def _normalise_root(root: str | Path | None) -> str:
        if root is None:
            return "/"
        value = str(root).strip()
        if not value:
            return "/"
        if "\x00" in value:
            raise MegaArgumentError("remote root contains a NUL byte")
        value = value.replace("\\", "/")
        if any(part == ".." for part in value.split("/")):
            raise MegaArgumentError(f"remote root may not contain '..': {root!r}")
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
            raise MegaArgumentError(
                f"remote bundle path must end in {ARTIFACT_SUFFIX!r}: {bundle_path!r}")
        artifact = self._plain_name(name[:-len(ARTIFACT_SUFFIX)])
        root = value.rsplit("/", 1)[0] or "/"
        return artifact, root

    def _target(self, name_or_path: str, remote_root: str | Path | None = None) -> str:
        """Resolve an artifact name or an absolute remote path for link calls."""
        value = str(name_or_path or "").strip()
        if not value:
            raise MegaArgumentError("remote path or artifact name is empty")
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
        except Exception as exc:  # noqa: BLE001 - status is a report, not a crash
            out["error"] = f"{type(exc).__name__}: {exc}"
            return out

        try:
            protect = self._modules.get("protect")
            out["password_file"] = str(protect.password_file())
            out["password_present"] = bool(protect.password_present())
        except Exception as exc:  # noqa: BLE001
            out["error"] = f"password: {type(exc).__name__}: {exc}"

        try:
            credential = self._modules.get("credential")
            out["secrets_dir"] = str(credential.secrets_dir())
            out["expected_account"] = self._sealed_email(credential)
            if out["expected_account"] and out["account"]:
                out["account_matches"] = (
                    out["expected_account"].lower() == out["account"].lower())
        except Exception as exc:  # noqa: BLE001
            out["error"] = f"credential: {type(exc).__name__}: {exc}"

        return out

    def account(self) -> str | None:
        """The logged-in address, or ``None``."""
        return self.megacmd.whoami(self.quick_timeout)

    def require_session(self) -> str:
        """Return the account, or raise ``MegaNotAvailable``/``MegaNotLoggedIn``."""
        mc = self.megacmd
        if not mc.available():
            raise MegaNotAvailable(mc.missing_message())
        account = mc.whoami(self.quick_timeout)
        if not account:
            raise MegaNotLoggedIn(
                "no MEGAcmd session. Run: python mega/login.py --emit check --mega")
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
        try:
            return listing.ls(path, timeout or self.timeout)
        except mc.MegaError as exc:
            raise MegaRemoteError(str(exc)) from exc

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
        return bundles

    def exists(self, name: str, remote_root: str | Path | None = None) -> bool:
        """Whether ``<root>/<name>_artifact`` is present. Best-effort."""
        target = self.bundle_path(name, remote_root)
        try:
            res = self.megacmd.run("ls", target, timeout=self.quick_timeout, check=False)
        except self.megacmd.MegaError:
            return False
        return res.code == 0

    # -- links --------------------------------------------------------------

    def list_links(self, remote_root: str | Path | None = None) -> list[dict]:
        """Every current export, optionally filtered to one remote subtree."""
        share = self._modules.get("share")
        root = self._root(remote_root)
        try:
            exports = share.list_exports(self.quick_timeout)
        except self.megacmd.MegaError as exc:
            raise MegaRemoteError(str(exc)) from exc
        if root == "/":
            return exports
        return [e for e in exports
                if e["path"] == root or e["path"].startswith(root + "/")]

    def exported_link(self, name_or_path: str,
                      remote_root: str | Path | None = None) -> str | None:
        """Read an existing public link. Never creates one."""
        target = self._target(name_or_path, remote_root)
        share = self._modules.get("share")
        try:
            return share.show(target, self.quick_timeout)
        except self.megacmd.MegaError as exc:
            raise MegaRemoteError(str(exc)) from exc

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
                raise MegaArgumentError(
                    f"invalid MEGA expiry {expire!r}: use e.g. 12h, 7d or 1m12d3h "
                    "(M = minutes, m = months)")
        else:
            try:
                chosen = share.configured_expire()
            except ValueError as exc:
                raise MegaArgumentError(f"{exc}. Pass permanent=True to override.") from exc

        try:
            created, link = share.create(target, self.quick_timeout, expire=chosen)
        except mc.MegaError as exc:
            raise MegaRemoteError(str(exc)) from exc
        return {"ok": True, "path": target, "link": link, "exported": True,
                "created": created, "expire": chosen}

    def revoke_link(self, name_or_path: str,
                    remote_root: str | Path | None = None) -> dict[str, Any]:
        """Revoke a public link. ``deleted=False`` means it was not exported."""
        target = self._target(name_or_path, remote_root)
        share = self._modules.get("share")
        try:
            removed = share.revoke(target, self.quick_timeout)
        except self.megacmd.MegaError as exc:
            raise MegaRemoteError(str(exc)) from exc
        return {"ok": True, "path": target, "deleted": bool(removed)}

    # -- protection ---------------------------------------------------------

    def password_file(self) -> Path:
        """The operator bundle password file in use (it may not exist)."""
        return Path(self._modules.get("protect").password_file())

    def password_present(self, password_file: str | Path | None = None) -> bool:
        protect = self._modules.get("protect")
        path = Path(password_file) if password_file else None
        return bool(protect.password_present(path))

    def set_password(self, value: str | bytes,
                     password_file: str | Path | None = None) -> Path:
        """Write the operator password byte-exact. Minimum 8 bytes."""
        protect = self._modules.get("protect")
        try:
            return Path(protect.set_password(
                value, Path(password_file) if password_file else None))
        except protect.PasswordError as exc:
            raise MegaProtectionError(str(exc)) from exc

    def generate_password(self, length: int = 24,
                          password_file: str | Path | None = None) -> tuple[str, Path]:
        """Generate and store a password; returns it once. Never logged."""
        protect = self._modules.get("protect")
        try:
            value, path = protect.generate_password(
                length, Path(password_file) if password_file else None)
            return value, Path(path)
        except protect.PasswordError as exc:
            raise MegaProtectionError(str(exc)) from exc

    def encrypt_archive(self, archive: str | Path,
                        out_zip: str | Path | None = None,
                        password_file: str | Path | None = None) -> dict[str, Any]:
        """Wrap ``archive`` in a WinZip AES-256 zip. Returns the manifest fragment."""
        protect = self._modules.get("protect")
        source = Path(archive)
        target = Path(out_zip) if out_zip else source.with_suffix(".zip")
        try:
            password = protect.read_password(
                Path(password_file) if password_file else None)
            return protect.zip_bundle(source, target, password)
        except protect.PasswordError as exc:
            raise MegaProtectionError(str(exc)) from exc

    def decrypt_archive(self, zip_path: str | Path, out_dir: str | Path,
                        password_file: str | Path | None = None) -> Path:
        """Recover the archive from a protected zip."""
        protect = self._modules.get("protect")
        try:
            password = protect.read_password(
                Path(password_file) if password_file else None)
            return Path(protect.unzip_bundle(Path(zip_path), Path(out_dir), password))
        except protect.PasswordError as exc:
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
        result = self._run(command, timeout=deadline)
        result.data.update(data)
        if result.ok and not no_upload and link:
            try:
                info = self.link(name, remote_root=remote_root, create=True,
                                 expire=expire, permanent=permanent)
                result.data["link"] = info["link"]
                result.data["link_created"] = info["created"]
                result.data["link_expire"] = info["expire"]
            except Exception as exc:  # noqa: BLE001 - bytes are safe; link is extra
                result.data["link"] = None
                result.data["link_error"] = f"{type(exc).__name__}: {exc}"
        return result

    def start_export(self, name: str, **kwargs: Any) -> Job:
        """Start ``export`` as a job. Same keyword arguments; returns ``Job``."""
        command, data, _deadline = self._export_command(name, **kwargs)
        popen = self._popen(command)
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
        result = self._run(command, timeout=deadline)
        result.data.update(data)
        return result

    def retrieve_bundle(self, bundle_path: str | Path, **kwargs: Any) -> CommandResult:
        """Retrieve a bundle by its full remote path, e.g. ``/evidence/foo_artifact``."""
        if "remote_root" in kwargs:
            raise MegaArgumentError(
                "remote_root cannot be combined with a full bundle path")
        artifact, root = self._bundle_location(bundle_path)
        return self.retrieve(artifact, remote_root=root, **kwargs)

    def start_retrieve(self, name: str, **kwargs: Any) -> Job:
        """Start ``retrieve`` as a job. Same keyword arguments; returns ``Job``."""
        command, data, _deadline = self._retrieve_command(name, **kwargs)
        popen = self._popen(command)
        return Job(popen, command, label=f"retrieve {name}",
                   max_lines=self.max_job_lines, data=data)

    def _retrieve_command(self, name: str, *, remote_root=None, dest=None,
                          out_root=None, mode="restore", timeout=None,
                          force=False, verify_only=False,
                          bundle=None) -> tuple[list[str], dict[str, Any], float]:
        if isinstance(name, (str, Path)) and ("/" in str(name) or "\\" in str(name)):
            plain, root = self._bundle_location(name)
            if remote_root is not None:
                raise MegaArgumentError(
                    "remote_root cannot be combined with a full bundle path")
        else:
            plain = self._plain_name(name)
            root = self._root(remote_root)
        chosen_mode = str(mode or "restore").lower()
        op_timeout = int(timeout or self.timeout)

        if chosen_mode not in ("restore", "recover"):
            raise MegaArgumentError("mode must be 'restore' or 'recover'")

        dest_path = self._resolve(dest)
        out_root_path = self._resolve(out_root)

        if chosen_mode == "restore":
            command = [self.python_executable, str(self.mega_dir / "restore.py")]
            if verify_only:
                if bundle is None:
                    raise MegaArgumentError("verify_only needs bundle=<local *_artifact dir>")
                bundle_path = self._resolve(bundle)
                if bundle_path is None or not bundle_path.is_dir():
                    raise MegaArgumentError(f"bundle directory not found: {bundle}")
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

    def _run(self, command: list[str], timeout: float | None) -> CommandResult:
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
            return CommandResult(command, proc.returncode,
                                 proc.stdout or "", proc.stderr or "")
        except subprocess.TimeoutExpired as exc:
            return CommandResult(
                command, -1,
                _as_text(exc.stdout),
                _as_text(exc.stderr) or f"timed out after {timeout}s",
            )
        except OSError as exc:
            return CommandResult(command, -1, "", f"could not start: {exc}")


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
