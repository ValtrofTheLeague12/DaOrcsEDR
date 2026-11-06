"""Panel-managed API credentials for the static analyzer's CTI phase."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import threading
import uuid
from pathlib import Path

from ..core import config

_lock = threading.RLock()
_providers = {
    "abuseipdb": {
        "name": "AbuseIPDB",
        "env": "ABUSEIPDB_API_KEY",
        "optional": False,
        "description": "IP reputation and abuse-confidence lookups.",
    },
    "otx": {
        "name": "AlienVault OTX",
        "env": "OTX_API_KEY",
        "optional": False,
        "description": "Open threat-intelligence pulse and indicator lookups.",
    },
    "virustotal": {
        "name": "VirusTotal",
        "env": "VT_API_KEY",
        "optional": False,
        "description": "File, domain, URL, and IP reputation lookups.",
    },
    "abusech": {
        "name": "abuse.ch",
        "env": "ABUSECH_AUTH_KEY",
        "optional": False,
        "description": "One shared key for ThreatFox, URLhaus, and MalwareBazaar.",
    },
    "greynoise": {
        "name": "GreyNoise Community",
        "env": "GREYNOISE_API_KEY",
        "optional": True,
        "description": "Community IP context; works without a key, with a higher quota when configured.",
    },
    "nvd": {
        "name": "NVD",
        "env": "NVD_API_KEY",
        "optional": True,
        "description": "CVE lookups; works without a key, with a higher rate limit when configured.",
    },
}


class CTISettingsError(ValueError):
    """A settings file or update cannot safely be used."""


def settings_path() -> Path:
    """The panel's API-key file, outside the source tree."""
    return config.appdata_root() / "cti-secrets" / "cti-config.json"


def _harden(path: Path, *, directory: bool = False) -> None:
    if os.name == "nt":
        user = os.environ.get("USERNAME", "")
        if not user:
            raise OSError("cannot restrict CTI settings: Windows user is unknown")
        grant = f"{user}:(OI)(CI)F" if directory else f"{user}:F"
        subprocess.run(
            ["icacls", str(path), "/inheritance:r", "/grant:r", grant],
            capture_output=True, check=True, timeout=15,
        )
    else:
        os.chmod(path, 0o700 if directory else 0o600)


def _read_file(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CTISettingsError(f"cannot read CTI configuration: {exc}") from None
    if not isinstance(value, dict):
        raise CTISettingsError("CTI configuration must be a JSON object")
    keys = value.get("keys", {})
    if not isinstance(keys, dict):
        raise CTISettingsError("CTI configuration 'keys' must be an object")
    for key, secret in keys.items():
        if key not in _providers or not isinstance(secret, str):
            raise CTISettingsError("CTI configuration contains an invalid API key entry")
    return value


def _read_managed_keys() -> dict[str, str]:
    path = settings_path()
    if not path.is_file():
        return {}
    with _lock:
        return dict(_read_file(path).get("keys", {}))


def _atomic_write(path: Path, value: dict) -> None:
    directory = path.parent
    directory.mkdir(parents=True, exist_ok=True)
    _harden(directory, directory=True)
    temp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=directory,
            prefix=".cti-", suffix=".tmp", delete=False,
        ) as temp:
            temp_path = Path(temp.name)
        _harden(temp_path)
        temp_path.write_text(
            json.dumps(value, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        os.replace(temp_path, path)
        temp_path = None
        _harden(path)
    finally:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)


def status() -> dict:
    """Return provider metadata and saved state, never credential values."""
    with _lock:
        keys = _read_managed_keys()
    return {
        "providers": [
            {
                "id": provider_id,
                **provider,
                "configured": provider_id in keys,
            }
            for provider_id, provider in _providers.items()
        ],
        "source": "Panel-saved keys are stored in the user's application data folder.",
    }


def update(keys: object) -> dict:
    """Apply a partial update; null explicitly removes a saved provider key."""
    if not isinstance(keys, dict) or not keys:
        raise CTISettingsError("'keys' must be a non-empty object")

    updated: dict[str, str | None] = {}
    for provider_id, value in keys.items():
        if provider_id not in _providers:
            raise CTISettingsError(f"unknown CTI provider: {provider_id}")
        if value is None:
            updated[provider_id] = None
            continue
        if not isinstance(value, str):
            raise CTISettingsError(f"{provider_id} API key must be text or null")
        secret = value.strip()
        if not secret or len(secret) > 4096 or any(char in secret for char in "\r\n\x00"):
            raise CTISettingsError(f"{provider_id} API key is empty or invalid")
        updated[provider_id] = secret

    with _lock:
        current = _read_managed_keys()
        for provider_id, secret in updated.items():
            if secret is None:
                current.pop(provider_id, None)
            else:
                current[provider_id] = secret

        path = settings_path()
        if current:
            _atomic_write(path, {"keys": current})
        else:
            path.unlink(missing_ok=True)
    return status()


def analyzer_config_path() -> Path | None:
    """Build a secure effective config, preserving any existing CTI_CONFIG.

    The panel's saved keys take precedence over same-provider keys in the
    existing file, while unrelated endpoint and CTI options remain intact.
    """
    managed_path = settings_path()
    if not managed_path.is_file():
        return None

    with _lock:
        managed = _read_file(managed_path)
        env_path = os.environ.get("CTI_CONFIG")
        if not env_path:
            return managed_path

        base_path = Path(env_path)
        if not base_path.is_absolute():
            base_path = config.REPO / base_path
        if base_path.resolve() == managed_path.resolve():
            return managed_path

        base = _read_file(base_path)
        merged = dict(base)
        merged_keys = dict(base.get("keys", {}))
        merged_keys.update(managed.get("keys", {}))
        merged["keys"] = merged_keys
        effective = managed_path.with_name(
            f"cti-config-effective-{uuid.uuid4().hex}.json"
        )
        _atomic_write(effective, merged)
        return effective


def cleanup_analyzer_config(path: Path | None) -> None:
    """Remove a per-run merged config after the analyzer exits."""
    if path is None:
        return
    directory = settings_path().parent.resolve()
    resolved = path.resolve()
    if resolved.parent != directory or not resolved.name.startswith(
            "cti-config-effective-"):
        return
    resolved.unlink(missing_ok=True)
