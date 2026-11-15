"""Public MEGA link settings - config/share.json.

Only the panel creates share links: the Artifacts page's *Get MEGA link* and the
end of an *Export to MEGA* job. The analyzer never publishes anything, so this is
a panel-owned file beside hardening.json and dynamic_analysis.json rather than a
key the analyzer would have to accept and carry into every run.

    {"link_expire": "7d"}     links expire seven days after creation
    {"link_expire": ""}       permanent links (the default)

MEGA's duration grammar is compact and case-sensitive:

    s  seconds
    M  minutes        (capital M - this is the one that surprises people)
    h  hours
    d  days
    m  months         (lowercase m)
    y  years

and components may be combined, e.g. ``12h``, ``7d`` or ``1m12d3h``. The
setting is used only when a link is CREATED. An existing export keeps whatever
expiry it already has: MEGA cannot modify an export in place, so changing this
does not rewrite links that are already out. Revoke and recreate one to change
it.

A note on the account: MEGA only allows an expiry on PRO accounts. On a free
account the export command fails with "Only PRO users can set an expiry time
for links", and that refusal is surfaced rather than silently downgraded to a
permanent link - a link that outlives the policy the operator set is worse than
no link at all.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

CONFIG_RELATIVE = Path("config") / "share.json"

# MEGA's units, in its own case: M = minutes, m = months.
_DURATION = re.compile(r"^(?:\d+[smhdMy])+$")
_UNITS = [
    ("s", "second", "seconds"),
    ("M", "minute", "minutes"),
    ("h", "hour", "hours"),
    ("d", "day", "days"),
    ("m", "month", "months"),
    ("y", "year", "years"),
]
_UNIT_NAMES = {unit: (one, many) for unit, one, many in _UNITS}

EXAMPLE = "12h, 7d or 1m12d3h (M = minutes, m = months)"


def valid_duration(text: str) -> bool:
    """True for a MEGA time delay with at least one non-zero component."""
    text = str(text or "").strip()
    if not _DURATION.match(text):
        return False
    return any(int(part) > 0 for part in re.findall(r"\d+", text))


def describe(text: str) -> str:
    """A short human rendering of a duration, for the API/UI."""
    text = str(text or "").strip()
    if not valid_duration(text):
        return ""
    parts = []
    for count, unit in re.findall(r"(\d+)([smhdMy])", text):
        one, many = _UNIT_NAMES[unit]
        parts.append(f"{count} {one if int(count) == 1 else many}")
    return " ".join(parts)


def read(repo: Path) -> dict:
    """The file's state, never raising.

    A broken file is reported in `error` with `link_expire` left empty, because
    the caller has to decide whether an unreadable policy means "permanent" or
    "refuse to publish". It means refuse - see ``expire()``.
    """
    path = repo / CONFIG_RELATIVE
    out = {"path": CONFIG_RELATIVE.as_posix(), "exists": False,
           "link_expire": "", "summary": "", "error": None}
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return out
    except OSError as exc:
        out["error"] = f"could not read {CONFIG_RELATIVE.as_posix()}: {exc}"
        return out

    out["exists"] = True
    try:
        data = json.loads(raw or "{}")
    except json.JSONDecodeError as exc:
        out["error"] = f"{CONFIG_RELATIVE.as_posix()} is not valid JSON: {exc}"
        return out
    if not isinstance(data, dict):
        out["error"] = f"{CONFIG_RELATIVE.as_posix()} must be a JSON object"
        return out

    value = data.get("link_expire", "")
    if value is None:
        value = ""
    if not isinstance(value, str):
        out["error"] = "link_expire must be text"
        return out
    value = value.strip()
    out["link_expire"] = value
    if value and not valid_duration(value):
        out["error"] = (
            f"link_expire {value!r} is not a MEGA duration; use {EXAMPLE}")
        return out
    out["summary"] = describe(value)
    return out


def expire(repo: Path) -> tuple[str | None, str | None]:
    """(duration or None, error or None) for link creation.

    None means permanent. A file that cannot be read is an error rather than
    None: treating a broken policy as "publish permanently" is exactly the
    silent failure this setting exists to prevent.
    """
    state = read(repo)
    if state["error"]:
        return None, state["error"]
    return (state["link_expire"] or None), None


def write(repo: Path, patch: dict) -> dict:
    """Set or clear link_expire, leaving any other key in the file alone."""
    if not isinstance(patch, dict):
        raise ValueError("body must be a JSON object")
    unknown = sorted(k for k in patch if k != "link_expire")
    if unknown:
        raise ValueError("not a share setting: " + ", ".join(unknown))
    if "link_expire" not in patch:
        return read(repo)

    value = patch["link_expire"]
    if value is None:
        value = ""
    if not isinstance(value, str):
        raise ValueError("link_expire must be text")
    value = value.strip()
    if value and not valid_duration(value):
        raise ValueError(
            f"link_expire must be a MEGA duration, e.g. {EXAMPLE}")

    path = repo / CONFIG_RELATIVE
    data: dict = {}
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise ValueError(f"could not read {CONFIG_RELATIVE.as_posix()}: {exc}") from exc
    else:
        try:
            loaded = json.loads(raw or "{}")
        except json.JSONDecodeError as exc:
            # Do not overwrite a file whose other keys we cannot see: that is
            # how an unrelated setting disappears during a repair.
            raise ValueError(
                f"{CONFIG_RELATIVE.as_posix()} is not valid JSON: {exc}") from exc
        if not isinstance(loaded, dict):
            raise ValueError(
                f"{CONFIG_RELATIVE.as_posix()} must be a JSON object")
        data = loaded

    data["link_expire"] = value

    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, path)
    return read(repo)


def snapshot(repo: Path) -> dict:
    """What the Analysis Configuration page reads and writes."""
    state = read(repo)
    return {
        **state,
        "units": [
            {"value": "s", "label": "seconds"},
            {"value": "M", "label": "minutes"},
            {"value": "h", "label": "hours"},
            {"value": "d", "label": "days"},
            {"value": "m", "label": "months"},
            {"value": "y", "label": "years"},
        ],
        "example": EXAMPLE,
    }
