"""Dynamic-analysis policy - config/dynamic_analysis.json.

One choice, in one file, and it is deliberately a choice rather than a pair of
switches: the sample under dynamic analysis is allowed to communicate ONE way.

    tcp    the guest may open TCP/IP sockets directly (the Qiling harness
           exposes its virtual NIC to the sample)
    sftp   the guest is driven over an SFTP session instead; artefacts and
           samples move over SSH and the sample itself gets no raw socket

WHY A RADIO AND NOT TWO CHECKBOXES. The two are not additive. A guest allowed
to open TCP sockets AND driven over SFTP is the current behaviour, and it is
also the state nobody can reason about: "is the network on?" has two answers
depending on which path the sample took. Recording one transport makes the
answer single and makes an accidental change visible in review.

The file is JSON beside the other panel-owned config (hardening.json,
yara_check.json, sample_resources.json) rather than in analysis.yaml: that
file's keys are read by src/main/analysis_config.cpp and an unknown key is a
hard error there. This setting belongs to the dynamic side (Qiling / ClamAV),
not to the static analyzer.

The path is a FUNCTION, not a constant, so tests can point config.REPO at a
tmp tree without writing to the real config/.
"""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path

CONFIG_RELATIVE = Path("config") / "dynamic_analysis.json"

DEFAULT_COMMUNICATION = "tcp"

# The options, in the order the radio group shows them. The id is the value
# persisted; the label is what the operator reads. Every sentence here is
# written down once so the API and the page cannot drift.
OPTIONS: list[dict] = [
    {
        "id": "tcp",
        "label": "Allow TCP/IP Communication",
        "summary": "Let the sample talk over the guest's TCP/IP stack.",
        "detail": (
            "The emulated guest keeps a routable virtual NIC, so a sample that "
            "opens a socket reaches its destination. Use this when the run is "
            "about network behaviour - C2 callbacks, DNS, HTTP."
        ),
    },
    {
        "id": "sftp",
        "label": "Usage of SFTP Session",
        "summary": "Move samples and artefacts over an SFTP session.",
        "detail": (
            "The panel drives the guest over SSH/SFTP and the sample itself is "
            "not given a raw TCP path out. Use this when the run is about what "
            "the sample does on disk, and containment matters more than "
            "observing its traffic."
        ),
    },
]

OPTION_IDS = [option["id"] for option in OPTIONS]
_BY_ID = {option["id"]: option for option in OPTIONS}

_write_lock = threading.RLock()


def config_path(repo: Path) -> Path:
    """Resolved per call, so tests can point config.REPO at a tmp tree."""
    return repo / CONFIG_RELATIVE


def defaults() -> dict[str, str]:
    return {"communication": DEFAULT_COMMUNICATION}


def _coerce(value: object) -> str:
    if not isinstance(value, str) or value not in _BY_ID:
        raise ValueError(
            "'communication' must be one of: " + ", ".join(OPTION_IDS))
    return value


def load(repo: Path) -> dict[str, str]:
    """The policy as it stands, with the default filled in for an absent file.

    A missing file is not an error: the default is the policy. A file that is
    present but malformed is raised rather than ignored - a typo must not
    silently put the sample on the transport nobody chose.
    """
    path = config_path(repo)
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return defaults()
    except OSError as exc:
        raise OSError(f"could not read {path}: {exc}") from exc

    if not raw.strip():
        return defaults()

    try:
        loaded = json.loads(raw)
    except ValueError as exc:
        raise ValueError(
            f"{CONFIG_RELATIVE.as_posix()} is not valid JSON: {exc}") from exc
    if not isinstance(loaded, dict):
        raise ValueError(f"{CONFIG_RELATIVE.as_posix()} must be a JSON object")

    settings = defaults()
    for key, value in loaded.items():
        if key != "communication":
            raise ValueError(
                f"not a dynamic-analysis setting: {key} "
                f"(known: communication)")
        settings[key] = _coerce(value)
    return settings


def write(repo: Path, patch: dict) -> dict[str, str]:
    """Set the policy. The file is rewritten whole, like the other JSON config."""
    if not isinstance(patch, dict):
        raise ValueError("body must be a JSON object")
    unknown = [key for key in patch if key != "communication"]
    if unknown:
        raise ValueError(
            "not a dynamic-analysis setting: " + ", ".join(sorted(unknown)))

    with _write_lock:
        current = load(repo)
        if "communication" in patch:
            current["communication"] = _coerce(patch["communication"])

        path = config_path(repo)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_text(json.dumps(current, indent=2) + "\n", encoding="utf-8")
        os.replace(tmp, path)
    return current


def snapshot(repo: Path) -> dict:
    """The policy, the options, and where the file is."""
    try:
        settings = load(repo)
        error = None
    except (ValueError, OSError) as exc:
        settings = defaults()
        error = str(exc)

    selected = settings.get("communication", DEFAULT_COMMUNICATION)
    path = config_path(repo)
    try:
        modified = path.stat().st_mtime if path.is_file() else None
    except OSError:
        modified = None
    return {
        "path": CONFIG_RELATIVE.as_posix(),
        "exists": path.is_file(),
        "modified": modified,
        "options": [
            {
                "id": option["id"],
                "label": option["label"],
                "summary": option["summary"],
                "detail": option["detail"],
                "selected": option["id"] == selected,
            }
            for option in OPTIONS
        ],
        "settings": settings,
        "default": DEFAULT_COMMUNICATION,
        "error": error,
    }
