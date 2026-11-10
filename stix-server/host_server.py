#!/usr/bin/env python3
"""STIX-server orchestrator.

Responsibilities
----------------
1. Pull every ``*_artifact`` bundle from MEGA's ``evidence/`` folder.
2. Verify each bundle's SHA-256 against the local manifest sidecar.
3. Gate display on the Supabase ``arts_whishlist`` table **and** on the
   ``banned_artifacts`` list in ``config/cti_config.json``.
4. Render a static ``index.html`` catalog page from the Jinja template.
5. Render ``server.py`` from ``templates/server.py.j2`` so the catalog
   can be served by Flask without regenerating.

Usage
-----
    python host_server.py                  # pull, verify, generate
    python host_server.py --serve          # also start Flask after generation
    python host_server.py --serve --port 8772
    python host_server.py --skip-pull      # use existing exported_evidence/
    python host_server.py --generate-only  # only regenerate HTML + server.py
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import importlib.util
import ipaddress
import json
import os
import pathlib
import secrets
import string
import sys
from urllib.parse import quote

import numpy as np
from jinja2 import Environment, FileSystemLoader, select_autoescape
from loguru import logger

import mega_client

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

HERE = pathlib.Path(__file__).resolve().parent
EXPORT_PATH = HERE / "exported_evidence"
CONFIG_PATH = HERE / "config" / "cti_config.json"
CATALOG_PATH = HERE / "artifact_catalog.json"
TEMPLATE_DIR = HERE / "templates"
STATIC_DIR = HERE / "static"
LOGO_PATH = STATIC_DIR / "daorcs.logo"

BUNDLE_REMOTE_ROOT = "evidence"

# The catalogue ships the ZIP password to signed-in CTI users, because the
# archives are WinZip AES-256 and useless without it. The value is read from
# the operator password file at generation time and copied into config/
# (git-ignored) so a deployed server does not need the operator profile.
PASSWORD_SIDECAR = HERE / "config" / "bundle-password"

# Per-bundle passwords: one generated value per exported artifact (the
# MEGA_PER_BUNDLE_PASSWORD option), stored by mega/protect.py in the
# operator profile and mirrored here at generation time as a JSON mapping
# {sample_name: password}. Same rules as the sidecar above: git-ignored,
# shown only behind the login gate, never in the tracked catalog JSON.
BUNDLE_PASSWORDS_SIDECAR = HERE / "config" / "bundle-passwords.json"

log = logger.bind(component="stix-server")

# ---------------------------------------------------------------------------
# Supabase import (optional – if unavailable, whitelist check is skipped)
# ---------------------------------------------------------------------------

_supabase_path = HERE.parent / "supabase"
if str(_supabase_path) not in sys.path:
    sys.path.append(str(_supabase_path))

try:
    import User as _User
    _SUPABASE_AVAILABLE = True
    log.debug("Supabase SDK imported from {}", _supabase_path)
except ImportError as _exc:
    _SUPABASE_AVAILABLE = False
    log.warning("Supabase SDK not available ({}); whitelist checks disabled", _exc)


# ---------------------------------------------------------------------------
# Config helpers
# ---------------------------------------------------------------------------

def _load_config() -> dict:
    """Parse config/cti_config.json.  Returns {} on any error."""
    if not CONFIG_PATH.exists():
        log.warning("Config not found at {}", CONFIG_PATH)
        return {}
    try:
        # utf-8-sig: Windows editors and PowerShell's UTF8 writer can prepend a
        # BOM, which plain json.loads rejects.
        return json.loads(CONFIG_PATH.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        log.error("Failed to parse config {}: {}", CONFIG_PATH, exc)
        return {}


def _banned_set(config: dict) -> set[str]:
    """Return a normalised set of banned names/hashes from config.

    Accepts both the new flat-string format and the legacy
    ``{"name": "...", "hash": "..."}`` object format.
    """
    raw = config.get("banned_artifacts", [])
    out: set[str] = set()
    for entry in raw:
        if isinstance(entry, str):
            v = entry.strip()
            if v:
                out.add(v.lower())
        elif isinstance(entry, dict):
            # Legacy object format.
            for key in ("name", "hash"):
                v = entry.get(key, "")
                if isinstance(v, str) and v.strip():
                    out.add(v.strip().lower())
    return out


# ---------------------------------------------------------------------------
# Bundle (ZIP) password
# ---------------------------------------------------------------------------

def _read_bundle_password() -> str | None:
    """The operator's bundle password, or None when it is not configured.

    This is the ZIP password, NOT a login credential. It lives outside the
    repo (``mega/protect.py`` resolves the file) and is only published to
    authenticated catalog users. Importing the repo helper keeps one
    definition of "where the password is"; a standalone copy of stix-server
    without ``mega/`` simply shows no password.
    """
    mega_dir = HERE.parent / "mega"
    if str(mega_dir) not in sys.path:
        sys.path.insert(0, str(mega_dir))
    try:
        import protect  # noqa: PLC0415 - operator helper, optional on a copy
        raw = protect.read_password()
    except Exception as exc:  # noqa: BLE001 - a missing password is a valid state
        log.info("Bundle password not available for the catalog: {}", exc)
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        log.warning(
            "Bundle password is not valid UTF-8; it will not be shown in the catalog")
        return None


def _write_bundle_password_sidecar(password: str | None) -> None:
    """Copy the ZIP password beside the generated server, or drop a stale one.

    ``config/`` is git-ignored, so the password never enters the tracked
    catalog JSON or the templates. The generated server reads this file at
    request time and shows it only behind its login gate. A missing password
    removes the sidecar so an old value cannot outlive a cleared password.
    """
    try:
        if password is None:
            PASSWORD_SIDECAR.unlink(missing_ok=True)
            return
        PASSWORD_SIDECAR.parent.mkdir(parents=True, exist_ok=True)
        PASSWORD_SIDECAR.write_text(password, encoding="utf-8")
        try:
            os.chmod(PASSWORD_SIDECAR, 0o600)
        except OSError:
            pass  # Windows ACLs do not map to POSIX modes; the file is ignored anyway
    except OSError as exc:
        log.warning("Could not write the bundle-password sidecar: {}", exc)


def _read_bundle_passwords() -> dict[str, str]:
    """Every per-bundle password as {sample_name: password}, or {}.

    Same reuse rule as ``_read_bundle_password()``: the scheme (where the
    files live, how the bytes decode) is mega/protect.py's, imported by
    path, so a standalone copy of stix-server without ``mega/`` simply has
    no per-bundle passwords to show. Values that are not valid UTF-8 are
    skipped rather than failed: one unreadable bundle must not hide the
    passwords of every other bundle.
    """
    mega_dir = HERE.parent / "mega"
    if str(mega_dir) not in sys.path:
        sys.path.insert(0, str(mega_dir))
    try:
        import protect  # noqa: PLC0415 - operator helper, optional on a copy
        raw = protect.list_bundle_passwords()
    except Exception as exc:  # noqa: BLE001 - no per-bundle passwords is a valid state
        log.info("Per-bundle passwords not available for the catalog: {}", exc)
        return {}
    out: dict[str, str] = {}
    for artifact, password in raw.items():
        try:
            out[artifact] = password.decode("utf-8")
        except UnicodeDecodeError:
            log.warning(
                "Bundle password for {} is not valid UTF-8; it will not be "
                "shown in the catalog", artifact)
    return out


def _write_bundle_passwords_sidecar(mapping: dict[str, str]) -> None:
    """Mirror the per-bundle passwords beside the generated server.

    The generated server reads this file at request time and shows each
    artifact's value on that artifact's page, behind the login gate. An empty
    mapping removes the file so no stale password can outlive the profile it
    came from. Like the single-password sidecar, a failure here must not
    fail the generation - the catalog is still correct without it.
    """
    try:
        if not mapping:
            BUNDLE_PASSWORDS_SIDECAR.unlink(missing_ok=True)
            return
        BUNDLE_PASSWORDS_SIDECAR.parent.mkdir(parents=True, exist_ok=True)
        BUNDLE_PASSWORDS_SIDECAR.write_text(
            json.dumps(mapping, indent=2, sort_keys=True) + "\n",
            encoding="utf-8")
        try:
            os.chmod(BUNDLE_PASSWORDS_SIDECAR, 0o600)
        except OSError:
            pass
    except OSError as exc:
        log.warning("Could not write the bundle-passwords sidecar: {}", exc)


# ---------------------------------------------------------------------------
# Extracted-analysis details
# ---------------------------------------------------------------------------

# The analyzer writes its full report tree to exports/<name>_analysis/; the
# upload bundle only carries the sealed archive. When that tree is present on
# the same host, read the three files the catalog page wants and degrade to an
# empty detail block when it is not, so a standalone stix-server still works.
ANALYSIS_ASM_LINES = 140
MAX_SECTIONS = 48


def _read_json_object(path: pathlib.Path) -> dict:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _human_bytes(value: object) -> str:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        return ""
    size = float(value)
    units = ("B", "KiB", "MiB", "GiB", "TiB")
    index = 0
    while size >= 1024 and index < len(units) - 1:
        size /= 1024
        index += 1
    return f"{int(size)} B" if index == 0 else f"{size:.1f} {units[index]}"


def _analysis_dir(artifact_name: str) -> pathlib.Path | None:
    for base in (HERE.parent / "exports", EXPORT_PATH):
        candidate = base / f"{artifact_name}_analysis"
        if candidate.is_dir():
            return candidate
    return None


def _analysis_details(artifact_name: str) -> dict:
    """Sample size, PE section table and an asm snippet, when available."""
    details: dict = {
        "sample_name": artifact_name,
        "sample_size": None,
        "sample_size_human": "",
        "sections": [],
        "asm": "",
        "asm_truncated": False,
    }
    analysis = _analysis_dir(artifact_name)
    if analysis is None:
        return details

    fileinfo = _read_json_object(
        analysis / "fileinfo" / f"{artifact_name}_fileinfo.json")
    if fileinfo:
        details["sample_name"] = str(
            fileinfo.get("filename") or artifact_name)
        size = fileinfo.get("size")
        if isinstance(size, int) and not isinstance(size, bool):
            details["sample_size"] = size
        human = fileinfo.get("size_human")
        if isinstance(human, str):
            details["sample_size_human"] = human

    extraction = _read_json_object(
        analysis / "extraction" / f"{artifact_name}_extraction.json")
    raw_sections = (extraction.get("sections") or {}).get("details") or []
    sections: list[dict] = []
    for item in raw_sections[:MAX_SECTIONS]:
        if not isinstance(item, dict):
            continue
        sections.append({
            "name": str(item.get("name") or "?"),
            "size": item.get("size"),
            "entropy": item.get("entropy"),
            "virtual_address": item.get("virtual_address"),
        })
    details["sections"] = sections

    asm_path = analysis / "radare2" / f"{artifact_name}_functions.asm"
    if not asm_path.is_file():
        asm_path = next(analysis.glob("radare2/*.asm"), None)
    if asm_path is not None and asm_path.is_file():
        try:
            lines = asm_path.read_text(
                encoding="utf-8", errors="replace").splitlines()
        except OSError:
            lines = []
        details["asm"] = "\n".join(lines[:ANALYSIS_ASM_LINES])
        details["asm_truncated"] = len(lines) > ANALYSIS_ASM_LINES
    return details


# ---------------------------------------------------------------------------
# SHA-256 verification
# ---------------------------------------------------------------------------

def _sha256_of_file(path: pathlib.Path) -> str:
    """Return lower-hex SHA-256 of *path*."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def _verify_bundle_hashes(bundle_dir: pathlib.Path) -> tuple[bool, str]:
    """Verify every file in the bundle against its manifest.

    Returns ``(ok, archive_sha256)``.  ``ok`` is ``True`` only when every
    listed file that exists on disk passes.

    An encrypted bundle ships one sealed ZIP instead of the plaintext
    ``.tar.gz``, so the ZIP is what gets hashed against
    ``encryption.sealed_sha256``.  Bundles without a manifest are skipped
    (not failed): they predate the manifest, and rejecting them would hide
    evidence that is intact.
    """
    manifest_path = bundle_dir / "manifest.json"
    if not manifest_path.is_file():
        log.warning("No manifest in bundle {}; accepting without verification",
                    bundle_dir.name)
        return True, ""

    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        log.error("Cannot read manifest for bundle {}: {}", bundle_dir.name, exc)
        return False, ""

    archive_sha256: str = str(manifest.get("archive_sha256", "")).strip().lower()

    encrypted = bool(manifest.get("encrypted", False))
    encryption = manifest.get("encryption")
    if not isinstance(encryption, dict):
        encryption = {}

    if encrypted:
        sealed_name = str(encryption.get("sealed_file", "")).strip()
        sealed_sha256 = str(encryption.get("sealed_sha256", "")).strip().lower()
        if not sealed_name:
            log.error(
                "Encrypted bundle {} has no encryption.sealed_file; "
                "cannot verify the upload", bundle_dir.name,
            )
            return False, archive_sha256
        sealed_path = bundle_dir / sealed_name
        if not sealed_path.is_file():
            log.error(
                "Encrypted bundle {} is missing its sealed archive {}",
                bundle_dir.name, sealed_name,
            )
            return False, archive_sha256
        actual = _sha256_of_file(sealed_path)
        if not sealed_sha256:
            log.warning(
                "Encrypted bundle {} has no encryption.sealed_sha256; "
                "sealed archive was hashed but cannot be compared",
                bundle_dir.name,
            )
        elif actual != sealed_sha256:
            log.error(
                "Sealed archive hash MISMATCH for bundle {}: expected {} got {}",
                bundle_dir.name, sealed_sha256, actual,
            )
            return False, archive_sha256
        else:
            log.debug("Sealed archive hash OK for bundle {}", bundle_dir.name)
    else:
        # Verify the archive tarball if it's present (non-encrypted bundles).
        archive_name: str = manifest.get("archive", "")
        if archive_name:
            archive_path = bundle_dir / archive_name
            if archive_path.is_file():
                actual = _sha256_of_file(archive_path)
                if archive_sha256 and actual != archive_sha256:
                    log.error(
                        "Archive hash MISMATCH for bundle {}: expected {} got {}",
                        bundle_dir.name, archive_sha256, actual,
                    )
                    return False, archive_sha256
                log.debug("Archive hash OK for bundle {}", bundle_dir.name)
            else:
                log.debug(
                    "Archive {} not present in {} (encrypted or not yet extracted)",
                    archive_name, bundle_dir.name,
                )

    # Verify individual loose files listed in the manifest.
    all_ok = True
    for entry in manifest.get("files", []):
        if not isinstance(entry, dict):
            continue
        rel = entry.get("path", "")
        expected_hash = str(entry.get("hash", "")).strip().lower()
        if not rel or not expected_hash:
            continue
        file_path = bundle_dir / rel
        if not file_path.is_file():
            # Files may be inside a compressed archive; skip gracefully.
            continue
        actual = _sha256_of_file(file_path)
        if actual != expected_hash:
            log.error(
                "File hash MISMATCH in bundle {}: {} expected {} got {}",
                bundle_dir.name, rel, expected_hash, actual,
            )
            all_ok = False

    if all_ok:
        log.info("Hash verification PASSED for bundle {}", bundle_dir.name)
    return all_ok, archive_sha256


# ---------------------------------------------------------------------------
# Main orchestrator
# ---------------------------------------------------------------------------

class StixServer:
    """Pull MEGA bundles, verify them, and generate the CTI catalog."""

    def __init__(self) -> None:
        self._config = _load_config()
        self._banned = _banned_set(self._config)
        log.debug("Loaded {} banned entries from config", len(self._banned))

        self._mega: mega_client.MegaClient | None = None
        self._supabase = None

        try:
            log.info("Connecting to MEGA …")
            self._mega = mega_client.MegaClient()
            status = self._mega.status()
            if not status.get("available"):
                log.warning("MEGAcmd is not available; MEGA operations will be skipped")
                self._mega = None
            elif not status.get("session_ok"):
                log.warning("No MEGA session; MEGA operations will be skipped")
                self._mega = None
            else:
                log.success("MEGA connected as {}", status.get("account"))
        except Exception as exc:
            log.error("MEGA init failed: {}", exc)
            self._mega = None

        if _SUPABASE_AVAILABLE:
            try:
                log.info("Connecting to Supabase …")
                self._supabase = _User.SupabaseClient()
                log.success("Supabase connected")
            except Exception as exc:
                log.warning(
                    "Supabase init failed ({}); whitelist checks disabled", exc)
                self._supabase = None

    # ------------------------------------------------------------------
    # MEGA retrieval
    # ------------------------------------------------------------------

    def pull_all_bundles(self) -> list[str]:
        """Download every ``*_artifact`` bundle from MEGA ``evidence/``.

        Returns a list of artifact names that were successfully downloaded.
        """
        if self._mega is None:
            log.warning("Skipping MEGA pull — no session")
            return []

        EXPORT_PATH.mkdir(parents=True, exist_ok=True)

        try:
            bundles = self._mega.list_bundles(remote_root=BUNDLE_REMOTE_ROOT)
        except Exception as exc:
            log.error("Failed to list MEGA bundles: {}", exc)
            return []

        if not bundles:
            log.warning("No *_artifact bundles found under MEGA:{}/",
                        BUNDLE_REMOTE_ROOT)
            return []

        log.info("Found {} bundle(s) on MEGA", len(bundles))
        retrieved: list[str] = []

        for bundle in bundles:
            artifact = bundle.artifact
            log.info("Retrieving bundle {} …", artifact)
            try:
                result = self._mega.retrieve(
                    artifact,
                    remote_root=BUNDLE_REMOTE_ROOT,
                    out_root=EXPORT_PATH,
                    mode="recover",
                    force=True,
                )
                if result.ok:
                    log.success("Retrieved bundle {}", artifact)
                    retrieved.append(artifact)
                else:
                    detail = (result.stderr or result.stdout or "").strip()[:200]
                    log.error(
                        "Failed to retrieve bundle {} (exit {}): {}",
                        artifact, result.returncode, detail,
                    )
            except Exception as exc:
                log.exception("Exception while retrieving bundle {}: {}", artifact, exc)

        return retrieved

    # ------------------------------------------------------------------
    # Whitelist / ban logic
    # ------------------------------------------------------------------

    def _is_whitelisted_supabase(self, archive_sha256: str) -> bool:
        """Return True when Supabase says the hash is ``allow`` (or is unknown)."""
        if not self._supabase or not archive_sha256:
            # No Supabase connection: optimistic — do not block.
            return True
        try:
            entry = self._supabase.get_artifact_by_hash(archive_sha256)
        except Exception as exc:
            log.warning(
                "Supabase lookup failed for hash {} ({}); allowing by default",
                archive_sha256[:16], exc,
            )
            return True

        if entry is None:
            # Hash not registered — allow display (not registered ≠ blocked).
            log.debug(
                "Hash {} not in Supabase table; displaying by default",
                archive_sha256[:16],
            )
            return True

        allowed = entry.decision == "allow"
        if not allowed:
            log.warning(
                "Supabase decision={!r} for hash {}; hiding bundle",
                entry.decision, archive_sha256[:16],
            )
        return allowed

    def _is_config_banned(self, artifact_name: str, archive_sha256: str) -> bool:
        """Return True when the artifact is in config's banned_artifacts list."""
        if not self._banned:
            return False
        checks = {artifact_name.lower(), archive_sha256.lower()}
        return bool(checks & self._banned)

    # ------------------------------------------------------------------
    # Catalog building
    # ------------------------------------------------------------------

    def build_catalog(self) -> list[dict]:
        """Scan ``exported_evidence/``, verify hashes, apply bans, return rows."""
        rows: list[dict] = []

        if not EXPORT_PATH.is_dir():
            log.warning(
                "Export path {} does not exist; nothing to catalog", EXPORT_PATH)
            return rows

        # Collect any existing MEGA public links for each artifact.
        mega_links: dict[str, str] = {}
        if self._mega is not None:
            try:
                for link_info in self._mega.list_links(
                        remote_root=BUNDLE_REMOTE_ROOT):
                    path = link_info.get("path", "")
                    link = link_info.get("link", "")
                    if path and link:
                        # "/evidence/foo_artifact" → artifact name "foo"
                        name = path.rstrip("/").rsplit("/", 1)[-1]
                        if name.endswith("_artifact"):
                            mega_links[name[: -len("_artifact")]] = link
            except Exception as exc:
                log.warning("Could not read MEGA public links: {}", exc)

        for entry in sorted(EXPORT_PATH.iterdir()):
            if not entry.is_dir():
                continue
            bundle_name = entry.name  # e.g. custom-523822_protected_artifact
            if not bundle_name.endswith("_artifact"):
                continue
            artifact_name = bundle_name[: -len("_artifact")]

            log.info("Processing bundle {}", bundle_name)

            # --- hash verification ---
            hash_ok, archive_sha256 = _verify_bundle_hashes(entry)
            if not hash_ok:
                log.warning(
                    "Bundle {} failed hash verification; excluding from catalog",
                    bundle_name,
                )
                continue

            # --- ban checks (config + Supabase) ---
            if self._is_config_banned(artifact_name, archive_sha256):
                log.info("Bundle {} is config-banned; excluding", bundle_name)
                continue
            if not self._is_whitelisted_supabase(archive_sha256):
                log.info("Bundle {} is Supabase-blocked; excluding", bundle_name)
                continue

            # --- extract metadata from manifest ---
            manifest: dict = {}
            manifest_path = entry / "manifest.json"
            if manifest_path.is_file():
                try:
                    manifest = json.loads(
                        manifest_path.read_text(encoding="utf-8"))
                except Exception:
                    pass

            submitted_at: str = manifest.get("generated_at", "")
            file_count: int = int(manifest.get("file_count", 0))
            encrypted: bool = bool(manifest.get("encrypted", False))
            archive_bytes = manifest.get("archive_bytes", 0)
            if isinstance(archive_bytes, bool) or not isinstance(archive_bytes, int):
                archive_bytes = 0
            source_bytes = 0
            for entry_file in manifest.get("files", []) or []:
                if isinstance(entry_file, dict):
                    size = entry_file.get("size", 0)
                    if isinstance(size, int) and not isinstance(size, bool):
                        source_bytes += size

            details = _analysis_details(artifact_name)

            rows.append({
                "sample_name": artifact_name,
                "bundle_name": bundle_name,
                "sha256": archive_sha256,
                "submitted_at": submitted_at,
                "file_count": file_count,
                "encrypted": encrypted,
                "mega_link": mega_links.get(artifact_name, ""),
                "hash_verified": True,
                "archive_bytes": archive_bytes,
                "archive_size_human": _human_bytes(archive_bytes),
                "source_bytes": source_bytes,
                "sample_size": details["sample_size"],
                "sample_size_human": details["sample_size_human"],
                "sections": details["sections"],
                "asm": details["asm"],
                "asm_truncated": details["asm_truncated"],
                "artifacts_url": f"/artifact/{quote(artifact_name)}",
                "download_url": f"/download/{quote(artifact_name)}",
            })
            log.info("Catalog entry added: {}", artifact_name)

        log.info("Built catalog with {} visible artifact(s)", len(rows))
        return rows

    # ------------------------------------------------------------------
    # Static HTML + server.py generation
    # ------------------------------------------------------------------

    def generate_html(self, catalog: list[dict]) -> pathlib.Path:
        """Render ``templates/index.html.j2`` → ``index.html``.

        The static preview deliberately omits the ZIP password: that file has
        no login gate, so a copied or web-served index.html would publish the
        secret. The live Flask server injects it per request instead. The
        per-bundle passwords are omitted for the same reason: an empty
        mapping, never the values.
        """
        env = Environment(
            loader=FileSystemLoader(str(TEMPLATE_DIR)),
            autoescape=select_autoescape(["html", "htm", "html.j2"]),
        )
        template = env.get_template("index.html.j2")

        logo = ""
        if LOGO_PATH.is_file():
            try:
                logo = LOGO_PATH.read_text(encoding="utf-8")
            except OSError as exc:
                log.warning("Cannot read logo file: {}", exc)

        generated_at = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
        html = template.render(
            artifacts=catalog,
            logo=logo,
            generated_at=generated_at,
            bundle_password=None,
            bundle_passwords={},
        )

        out_path = HERE / "index.html"
        out_path.write_text(html, encoding="utf-8")
        log.success("Generated static catalog → {}", out_path)
        return out_path

    def generate_server(self) -> pathlib.Path:
        """Render ``templates/server.py.j2`` → ``server.py``."""
        env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)))
        template = env.get_template("server.py.j2")
        code = template.render()
        out_path = HERE / "server.py"
        out_path.write_text(code, encoding="utf-8")
        log.success("Generated server.py → {}", out_path)
        return out_path

    def save_catalog(self, catalog: list[dict]) -> pathlib.Path:
        """Persist the catalog JSON for Flask's live route."""
        CATALOG_PATH.write_text(
            json.dumps(catalog, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        log.debug("Saved catalog ({} entries) → {}", len(catalog), CATALOG_PATH)
        return CATALOG_PATH

    # ------------------------------------------------------------------
    # Password utilities (kept for user-creation flows)
    # ------------------------------------------------------------------

    @staticmethod
    def _generate_password(length: int = 12) -> str:
        alphabet = string.ascii_letters + string.digits + string.punctuation
        while True:
            password = "".join(secrets.choice(alphabet) for _ in range(length))
            if (
                any(c.islower() for c in password)
                and any(c.isupper() for c in password)
                and sum(c.isdigit() for c in password) >= 3
            ):
                return password

    @staticmethod
    def _calculate_entropy(password: str) -> float:
        if not isinstance(password, str) or not password:
            return 0.0
        pool = (
            26 * any(c in string.ascii_lowercase for c in password)
            + 26 * any(c in string.ascii_uppercase for c in password)
            + 10 * any(c in string.digits for c in password)
            + len(string.punctuation) * any(c in string.punctuation for c in password)
        )
        return round(float(len(password) * np.log2(pool)) if pool else 0.0, 2)

    def hash_password(self, password: str) -> dict:
        """Hash *password* with bcrypt + pepper.  Returns a metadata dict.

        The digest is ``bcrypt(password + unique_peper)``, the scheme
        ``cti_auth.verify_password`` reproduces.  Earlier builds shuffled the
        peppered string before hashing and never stored the permutation, so
        their digests could not be verified by anyone - including the server.
        """
        if not isinstance(password, str) or not password:
            raise ValueError("password must be a non-empty string")
        if str(HERE) not in sys.path:
            sys.path.insert(0, str(HERE))
        import cti_auth

        record = cti_auth.hash_password(password)
        return {
            "time_of_generation": str(datetime.datetime.now()),
            "password_length": len(record["password"]),
            "generated_password": record["password"],
            "generated_pepper": record["unique_peper"],
        }

    @staticmethod
    def _validate_ip(ip: str) -> bool:
        if not isinstance(ip, str) or not ip:
            return False
        try:
            parsed = ipaddress.ip_address(ip)
            return isinstance(parsed, ipaddress.IPv4Address)
        except ValueError:
            return False


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def _build_argparser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description="STIX-server: pull MEGA bundles, verify hashes, build CTI catalog",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument(
        "--serve", action="store_true",
        help="start the Flask server after generation",
    )
    ap.add_argument(
        "--port", type=int, default=None,
        help="override the port from cti_config.json",
    )
    ap.add_argument(
        "--skip-pull", action="store_true",
        help="skip MEGA download; use whatever is already in exported_evidence/",
    )
    ap.add_argument(
        "--generate-only", action="store_true",
        help="only regenerate server.py and index.html from existing catalog JSON",
    )
    return ap


def main(argv: list[str] | None = None) -> int:
    logger.remove()
    logger.add(
        sys.stderr, level="DEBUG",
        format=(
            "<green>{time:HH:mm:ss}</green> | <level>{level:<8}</level> | "
            "<cyan>{name}</cyan>:<cyan>{function}</cyan> — {message}"
        ),
        colorize=True,
    )

    args = _build_argparser().parse_args(argv)
    server = StixServer()

    if args.generate_only:
        log.info("--generate-only: loading existing catalog from {}", CATALOG_PATH)
        try:
            catalog = json.loads(CATALOG_PATH.read_text(encoding="utf-8"))
            if not isinstance(catalog, list):
                catalog = []
        except (OSError, json.JSONDecodeError):
            catalog = []
    else:
        if not args.skip_pull:
            server.pull_all_bundles()

        catalog = server.build_catalog()
        server.save_catalog(catalog)

    bundle_password = _read_bundle_password()
    _write_bundle_password_sidecar(bundle_password)
    _write_bundle_passwords_sidecar(_read_bundle_passwords())
    server.generate_html(catalog)
    server.generate_server()

    log.info("Generation complete — {} artifact(s) in catalog.", len(catalog))

    if args.serve:
        config = server._config
        srv = config.get("server", {})
        host = srv.get("ip", "0.0.0.0")
        port = args.port or srv.get("port", 8772)
        log.info("Starting Flask server on {}:{} …", host, port)

        spec = importlib.util.spec_from_file_location(
            "_cti_server", HERE / "server.py")
        if spec and spec.loader:
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)   # type: ignore[union-attr]
            mod.create_app().run(
                host=host, port=port, debug=False, use_reloader=False)
        else:
            log.error("Could not load generated server.py")
            return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
