"""Global analysis settings - config/analysis.yaml.

The counterpart to `pipeline_options()` in analysis.py. That one reads and
writes the `environment:` block inside a pipeline; this reads and writes the
file that applies to every run regardless of which pipeline was selected.

Why both exist, and why this one wins
-------------------------------------
The settings were per-pipeline first, and that turned out to be the wrong shape.
"Is CTI running?" became a question you could only answer by remembering the
contents of thirteen YAML files, and `pipelines/default.yaml` pinned
`ML_SKIP: 1` and `CTI_SKIP: 1` - so the default analysis silently never ran the
model or enrichment, decided by nobody, in a place designed for per-run
differences and unreachable from the environment.

So the precedence is inverted, and deliberately:

    .env / shell   <   pipeline `environment:`   <   config/analysis.yaml

A pipeline can still set a key this file does not mention - the analyzer reads
its `environment:` block regardless of what this console offers - but the
console no longer writes phase-scoped keys into pipelines at all: they are set
here, machine-wide, because per-pipeline CTI and ML toggles are how pipelines
ended up full of inert lines for phases they do not run. The run-wide options
remain per-pipeline writable; that is what they are for.

`ENV_OPTIONS` is shared with the per-pipeline writer deliberately: it is one
list of the settings the analyzer reads, described once. The allowlist lives in
the C++ loader (`known_analysis_keys()` in src/main/analysis_config.cpp) and
`unit/python/test_panel_env_options.py` fails if the two drift apart.

Comment preservation
--------------------
Rewrites are line-oriented and touch only the lines naming a key, exactly as
`write_artifact_options()` does. This file's comments explain the precedence
rules; a PyYAML round trip would strip them on the first save and the next
person to edit it would have no idea which way the layering goes.
"""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Any

import yaml

from .analysis import ENV_OPTIONS, ENV_BY_KEY, _quote

# Mirrors the C++ loader's search order closely enough for the panel, which
# runs from the repository root. The analyzer does the real search at startup
# and applies whatever it finds; this is only for reading and editing.
CONFIG_RELATIVE = Path("config") / "analysis.yaml"

_write_lock = threading.RLock()


def config_path(repo: Path) -> Path:
    return repo / CONFIG_RELATIVE


def _read_raw(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return ""
    except OSError as exc:
        raise OSError(f"could not read {path}: {exc}") from exc


def _scalar_text(value: Any) -> str:
    """A scalar as the file writes it, so the reader can match it to the YAML."""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def set_values(repo: Path) -> dict[str, str]:
    """What this file actually defines right now, as {key: value}.

    Read on its own, without the ENV_OPTIONS decoration, because its callers are
    the per-pipeline side asking "may I still set this key?" and the pipelines
    page asking "what is it set to?". Both are answered by what is on disk, not
    by what is available: a key nobody has set globally is free for a pipeline
    to claim.

    A file that cannot be parsed yields an empty map rather than raising. The
    analyzer will refuse to start on it, and analysis.py's own snapshot already
    reports the unreadable file - a collector that raised here would turn "show
    me the config" into a 500 and hide the real error behind it.
    """
    raw = _read_raw(config_path(repo))
    if not raw.strip():
        return {}
    try:
        loaded = yaml.safe_load(raw)
    except yaml.YAMLError:
        return {}
    if not isinstance(loaded, dict):
        return {}
    out: dict[str, str] = {}
    for key, value in loaded.items():
        if not isinstance(key, str):
            continue
        if isinstance(value, (dict, list)):
            # The analyzer refuses to start on a non-scalar, so there is nothing
            # worth showing. The unknown-key alert on the global page is where
            # that gets to complain about it.
            continue
        out[key] = _scalar_text(value)
    return out


def set_keys(repo: Path) -> set[str]:
    """The keys this file defines. Membership only - see set_values()."""
    return set(set_values(repo))


def flag_enabled(repo: Path, key: str) -> dict:
    """{key, present, value, enabled} for one flag, read with the ANALYZER's
    own semantics rather than the panel's looser truthiness.

    The C++ readers (env_flag in src/main/phase_extract.cpp:241, trace_enable
    in src/core/trace.cpp:44) accept only 1/true/yes/on, and an absent key
    means the binary's own default applies - which is OFF for
    IA_INTERRUPT_IF_PACKED and ON for ENABLE_TRACING. `enabled` here mirrors
    that, defaulting to the ENV_OPTIONS default, so a caller reporting "will
    the analyzer do X" cannot disagree with the analyzer about its own file.
    """
    raw = set_values(repo).get(key)
    if raw is None:
        option = ENV_BY_KEY.get(key, {})
        return {"key": key, "present": False, "value": None,
                "enabled": bool(option.get("default", False))}
    return {"key": key, "present": True, "value": raw,
            "enabled": raw.strip().lower() in ("1", "true", "yes", "on")}


def snapshot(repo: Path) -> dict[str, Any]:
    """What is on disk now, plus what each setting would mean if untouched.

    `value: None` means the key is absent, which is different from a value of
    "0" or "false": absent falls back to the binary's own default AND to the
    pipeline's `environment:` block, while present overrides both. The UI shows
    which of those it is, because "off" and "not set" are the same button and
    different outcomes.
    """
    raw = _read_raw(config_path(repo))
    data: dict[str, Any] = {}
    if raw.strip():
        try:
            loaded = yaml.safe_load(raw)
        except yaml.YAMLError as exc:
            raise ValueError(f"{CONFIG_RELATIVE} is not valid YAML: {exc}") from exc
        if loaded is None:
            loaded = {}
        if not isinstance(loaded, dict):
            raise ValueError(f"{CONFIG_RELATIVE} must be a YAML map")
        data = loaded

    settings = []
    for option in ENV_OPTIONS:
        key = option["key"]
        present = key in data
        settings.append({
            "key": key,
            "label": option["label"],
            "kind": option["kind"],
            "detail": option["detail"],
            "honoured_by": option["honoured_by"],
            "default": option.get("default", False if option["kind"] == "flag" else ""),
            "min": option.get("min"),
            "max": option.get("max"),
            "present": present,
            "value": str(data[key]) if present else None,
        })
    return {
        "path": CONFIG_RELATIVE.as_posix(),
        "exists": config_path(repo).exists(),
        "settings": settings,
        # Anything in the file the list above does not know about. The analyzer
        # refuses to start on an unknown key, so surfacing one here is the only
        # warning it gets before it turns into an exit code 2.
        "unknown": sorted(k for k in data if k not in ENV_BY_KEY),
    }


def _coerce(option: dict, value: Any) -> str:
    """Validate one value against the option's kind, the way the C++ reads it."""
    kind = option["kind"]
    key = option["key"]
    if kind == "flag":
        if isinstance(value, bool):
            return "true" if value else "false"
        if isinstance(value, str):
            low = value.strip().lower()
            if low in ("1", "true", "yes", "on"):
                return "true"
            if low in ("0", "false", "no", "off"):
                return "false"
        raise ValueError(f"'{key}' must be true or false")
    if kind == "number":
        try:
            number = float(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"'{key}' must be a number") from exc
        low, high = option.get("min"), option.get("max")
        if low is not None and number < low:
            raise ValueError(f"'{key}' must be at least {low}")
        if high is not None and number > high:
            raise ValueError(f"'{key}' must be at most {high}")
        return _quote(f"{number:g}")
    if not isinstance(value, str):
        raise ValueError(f"'{key}' must be text")
    return _quote(value.strip())


def write_settings(repo: Path, patch: dict) -> dict[str, Any]:
    """Set or clear individual settings, leaving the file's comments intact.

    Only keys the client actually sent are touched, so two people editing
    different settings cannot clobber each other by submitting a stale copy of
    the whole form. A value of `null` removes the key, which is how a setting
    goes back to the binary default and to the pipeline's value.
    """
    if not isinstance(patch, dict):
        raise ValueError("body must be a JSON object")
    unknown = [k for k in patch if k not in ENV_BY_KEY]
    if unknown:
        raise ValueError(
            "not a setting the analyzer reads: " + ", ".join(sorted(unknown))
        )

    path = config_path(repo)
    with _write_lock:
        raw = _read_raw(path)
        lines = raw.splitlines()

        for key, value in patch.items():
            option = ENV_BY_KEY[key]
            rendered = None if value is None else _coerce(option, value)
            lines = _replace_key(lines, key, rendered)

        body = "\n".join(lines).rstrip("\n") + "\n"

        # Re-parse before landing it. The analyzer refuses to start on a config
        # it cannot read, so a save that produced one would break the next run.
        try:
            parsed = yaml.safe_load(body) or {}
        except yaml.YAMLError as exc:
            raise ValueError(f"the edited file would not parse: {exc}") from exc
        if not isinstance(parsed, dict):
            raise ValueError("the edited file would not be a YAML map")
        # Note what is NOT here: a check that refuses the write because the
        # file already contains a key the analyzer does not read. It was, and it
        # made the panel useless in exactly the situation it exists to explain -
        # the operator could see the stray key in the alert and could do nothing
        # about it from here. Unknown keys are reported in `unknown` on every
        # read and preserved on every write; the analyzer still refuses to start
        # on one, which is its call to make and is the reason the alert is a
        # danger rather than a warning.

        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".yaml.tmp")
        tmp.write_text(body, encoding="utf-8")
        tmp.replace(path)

    return snapshot(repo)


def _replace_key(lines: list[str], key: str, rendered: str | None) -> list[str]:
    """Set, update or remove one `KEY: value` line, keeping comments and order.

    A comment-only or empty file has no line to update, so the key is appended
    under a short marker rather than at the very top - the file's own comment
    block explains the precedence, and appending after it reads better than
    inserting a bare line above the explanation.
    """
    prefix = key + ":"
    for index, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith(prefix):
            if rendered is None:
                del lines[index]
            else:
                lines[index] = f"{prefix} {rendered}"
            return lines

    if rendered is None:
        return lines  # absent and asked to stay absent

    if not any(line.strip() and not line.strip().startswith("#") for line in lines):
        lines.append("")
        lines.append("# --- set from the admin console ---")
    lines.append(f"{prefix} {rendered}")
    return lines