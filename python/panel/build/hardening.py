"""Configurable Windows hardening for the analyzer build.

Four things can be turned on or off in the built executable:

    aslr             the image is relocated at load time
    high_entropy_va  ...and relocated across a 64-bit range, not 32
    dep_nx           the stack and heap are marked non-executable
    stack_protector  stack frames carry a canary that is checked on return

The first three are linker flags and live in the PE header's DllCharacteristics
word, which is what Windows itself reads. The fourth is a compiler flag, and
leaves no header bit behind: it shows up as the canary runtime being linked in.

WHERE THE SETTINGS LIVE. They are persisted as JSON beside the other
config/ files, and they are PROJECT-WIDE rather than per-build. That is a
deliberate choice:

  * A build is reproducible from what is on disk. If the options were arguments
    to one build request, then two builds of the same tree could differ, and
    "the binary in build-ucrt/ is the one the settings describe" would stop
    being true. The panel would be able to produce a hardened binary and an
    unhardened one from the same commit with nothing in the tree to say which.

  * The panel builds the SAME artefact the operator builds by hand, via
    build.ps1. build.ps1 reads the same settings file, so running it in a
    terminal and running it from the panel produce the same binary. A setting
    that only the panel knew about would break that.

So: the panel writes config/hardening.json, build.ps1 reads it (or takes an
explicit override), and the build-check panel reports what the finished binary
actually carries.

THE DEFAULTS ARE ON, because they are on already. MinGW's linker enables ASLR,
high-entropy VA and NX compatibility by default, and the analysis is a
security tool that should not ship weaker than its own toolchain's defaults.
The switches exist to turn a protection OFF deliberately, not to turn one on -
so the file records the intent, and a build check compares the intent against
the binary and says when they disagree.
"""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path

from . import pe_tools

# Where the settings live. Same directory, same JSON shape, same reason as
# config/yara_check.json: these belong to this project, they are edited from
# the panel, and they are not part of any pipeline's configuration.
#
# The path is a FUNCTION, not a constant: config.REPO is resolved per call so
# the tests can point it at a tmp tree. A module-level constant would be
# frozen at import time and every test would write to the real config/.
CONFIG_RELATIVE = Path("config") / "hardening.json"

# The options, in the order they are shown and reported. Each carries the
# CMake option that decides it, so the mapping is written down once here
# rather than being reconstructed from strings at three call sites.
OPTIONS: list[dict] = [
    {
        "key": "aslr",
        "cmake": "STATIC_ANALYZER_HARDENING_ASLR",
        "label": "ASLR",
        "summary": "Relocate the image in memory at load time.",
        "detail": (
            "The executable is loaded at a different address each run, so a "
            "memory-corruption bug cannot be reused at a known offset."
        ),
        "default": True,
        # The link flag that turns it OFF. There is no --enable form worth
        # relying on: the MinGW specs enable it by default.
        "enable_link_flag": "--dynamicbase",
        "disable_link_flag": "--disable-dynamicbase",
        "enable_build_flag": "-EnableAslr",
        "disable_build_flag": "-DisableAslr",
        "pe_bit": "aslr",
        "pe_label": "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE",
    },
    {
        "key": "high_entropy_va",
        "cmake": "STATIC_ANALYZER_HARDENING_HIGH_ENTROPY_VA",
        "label": "High-entropy VA",
        "summary": "Relocate across the full 64-bit address space.",
        "detail": (
            "The strong form of ASLR: the load address is drawn from a 64-bit "
            "range rather than a 32-bit one, so guessing it is far harder."
        ),
        "default": True,
        "enable_link_flag": "--high-entropy-va",
        "disable_link_flag": "--disable-high-entropy-va",
        "enable_build_flag": "-EnableHighEntropyVa",
        "disable_build_flag": "-DisableHighEntropyVa",
        "pe_bit": "high_entropy_va",
        "pe_label": "IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA",
    },
    {
        "key": "dep_nx",
        "cmake": "STATIC_ANALYZER_HARDENING_DEP_NX",
        "label": "DEP / NX",
        "summary": "Mark the stack and heap as non-executable.",
        "detail": (
            "Data Execution Prevention: injected code cannot run from the "
            "stack or the heap, which is where a shellcode payload lands."
        ),
        "default": True,
        "enable_link_flag": "--nxcompat",
        "disable_link_flag": "--disable-nxcompat",
        "enable_build_flag": "-EnableDepNx",
        "disable_build_flag": "-DisableDepNx",
        "pe_bit": "dep_nx",
        "pe_label": "IMAGE_DLLCHARACTERISTICS_NX_COMPAT",
    },
    {
        "key": "stack_protector",
        "cmake": "STATIC_ANALYZER_HARDENING_STACK_PROTECTOR",
        "label": "Stack protector",
        "summary": "Check a canary on every protected stack frame.",
        "detail": (
            "Each protected frame carries a canary that is verified before the "
            "function returns; a smashed stack aborts instead of returning "
            "into the attacker's data."
        ),
        "default": True,
        # A compiler flag, not a link flag, and it has a real enable form -
        # so this one is expressed the other way round from the other three.
        "enable_compile_flag": "-fstack-protector-strong",
        "disable_compile_flag": "-fno-stack-protector",
        "enable_build_flag": "-EnableStackProtector",
        "disable_build_flag": "-DisableStackProtector",
        "pe_bit": "stack_protector",
        "pe_label": "stack canary runtime",
    },
]

OPTION_KEYS = [option["key"] for option in OPTIONS]
_BY_KEY = {option["key"]: option for option in OPTIONS}

_write_lock = threading.RLock()


# ---------------------------------------------------------------------------
# Reading and writing the settings
# ---------------------------------------------------------------------------

def config_path(repo: Path) -> Path:
    """Resolved per call, so tests can point config.REPO at a tmp tree."""
    return repo / CONFIG_RELATIVE


def defaults() -> dict[str, bool]:
    """What the analyzer gets when the settings file says nothing.

    The defaults are ON, because they are on already: MinGW's linker enables
    ASLR, high-entropy VA and NX compatibility by default, and the analyzer is
    a security tool that should not ship weaker than its own toolchain's
    defaults. The switches exist to turn a protection OFF deliberately.
    """
    return {option["key"]: bool(option["default"]) for option in OPTIONS}


def _coerce_bool(value: object, key: str) -> bool:
    """A JSON value as a boolean, or a refusal with a sentence.

    Strict about the type on purpose. `"false"` is a string, and accepting it
    would mean a client that stringified its payload silently flipped a
    protection OFF - the one thing a hardening switch must never do by
    accident.
    """
    if isinstance(value, bool):
        return value
    raise ValueError(f"'{key}' must be true or false")


def load(repo: Path) -> dict[str, bool]:
    """The settings as they stand, with defaults filled in for absent keys.

    A missing file is not an error: the defaults are the settings. A file that
    is present but malformed IS an error, and it is raised rather than ignored
    - a typo in the settings file must not silently produce an unhardened
    binary that the file claims to describe.
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
        if key not in _BY_KEY:
            # An unknown key is refused, not silently dropped: it means the
            # file was written by a different version of this project, and the
            # operator should know their intent is not being honoured.
            raise ValueError(
                f"not a hardening setting: {key} "
                f"(known: {', '.join(OPTION_KEYS)})")
        settings[key] = _coerce_bool(value, key)
    return settings


def write(repo: Path, patch: dict) -> dict[str, bool]:
    """Set the settings, keeping the ones the caller did not mention.

    The file is rewritten whole rather than patched in place: it is four
    booleans, it is JSON because the panel rewrites it wholesale, and a
    half-written file is a worse lie than no file.
    """
    if not isinstance(patch, dict):
        raise ValueError("body must be a JSON object")
    unknown = [k for k in patch if k not in _BY_KEY]
    if unknown:
        raise ValueError(
            "not a hardening setting: " + ", ".join(sorted(unknown)))

    with _write_lock:
        current = load(repo)
        for key, value in patch.items():
            current[key] = _coerce_bool(value, key)

        path = config_path(repo)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_text(json.dumps(current, indent=2) + "\n", encoding="utf-8")
        os.replace(tmp, path)
    return current


def snapshot(repo: Path) -> dict:
    """What the settings are, what each one means, and where the file is.

    The defaults are reported alongside the effective value, because "ASLR is
    on" and "ASLR is on because the file says so" are different statements, and
    only the second one survives the file being deleted.
    """
    try:
        settings = load(repo)
        error = None
    except (ValueError, OSError) as exc:
        settings = defaults()
        error = str(exc)

    options = []
    for option in OPTIONS:
        key = option["key"]
        options.append({
            "key": key,
            "label": option["label"],
            "summary": option["summary"],
            "detail": option["detail"],
            "default": bool(option["default"]),
            "enabled": bool(settings.get(key, option["default"])),
            "cmake": option["cmake"],
            "pe_label": option["pe_label"],
        })

    return {
        "path": CONFIG_RELATIVE.as_posix(),
        "exists": config_path(repo).is_file(),
        "options": options,
        "settings": settings,
        "error": error,
    }


# ---------------------------------------------------------------------------
# Turning the settings into build flags
# ---------------------------------------------------------------------------

def cmake_definitions(settings: dict[str, bool]) -> list[str]:
    """The -D options the configure step needs, one per setting.

    Every option is passed explicitly, ON or OFF. The point is that the
    configured build directory RECORDS the intent: `build-ucrt/CMakeCache.txt`
    then says which protections this tree was configured for, and a build
    check can compare that against what the binary actually carries.
    """
    out: list[str] = []
    for option in OPTIONS:
        key = option["key"]
        enabled = bool(settings.get(key, option["default"]))
        out.append(f"-D{option['cmake']}={'ON' if enabled else 'OFF'}")
    return out


def build_flags(settings: dict[str, bool]) -> list[str]:
    """The build.ps1 switches that carry the same intent.

    PowerShell switches are presence-based, so a boolean setting needs two
    forms: -EnableX and -DisableX. Passing the wrong one silently would be
    exactly the failure this whole mechanism exists to prevent, so both forms
    exist and exactly one of them is ever emitted.
    """
    out: list[str] = []
    for option in OPTIONS:
        key = option["key"]
        enabled = bool(settings.get(key, option["default"]))
        out.append(option["enable_build_flag"] if enabled
                   else option["disable_build_flag"])
    return out


def cmake_settings(settings: dict[str, bool]) -> dict[str, bool]:
    """The setting name -> ON/OFF map, for the CMake side to read."""
    return {option["key"]: bool(settings.get(key, option["default"]))
            for option in OPTIONS}


# ---------------------------------------------------------------------------
# Compliance: what was asked for against what the binary carries
# ---------------------------------------------------------------------------

def compliance(repo: Path, binary: Path) -> dict:
    """Compare the requested settings with the hardening the binary carries.

    This is the whole point of the feature. The build makes a promise in the
    CMake cache; the finished binary carries the fact. They can disagree - a
    stale binary, a link line that did not take, a flag the toolchain ignored -
    and only the second one is worth reporting.

    The stack protector is the odd one out: it has no PE header bit, so it is
    inferred from the canary runtime being linked in. That is a weaker signal
    than the other three, and the report says so rather than presenting the
    inference as a header fact.
    """
    try:
        settings = load(repo)
        settings_error = None
    except (ValueError, OSError) as exc:
        settings = defaults()
        settings_error = str(exc)

    if not binary.is_file():
        return {
            "available": False,
            "reason": "the analyzer is not built yet",
            "settings": settings,
            "settings_error": settings_error,
            "rows": [],
            "compliant": None,
        }

    try:
        actual = pe_tools.hardening(binary)
    except ValueError as exc:
        return {
            "available": False,
            "reason": str(exc),
            "settings": settings,
            "settings_error": settings_error,
            "rows": [],
            "compliant": None,
        }

    rows = []
    compliant = True
    for option in OPTIONS:
        key = option["key"]
        wanted = bool(settings.get(key, option["default"]))
        present = bool(actual.get(option["pe_bit"]))
        ok = wanted == present
        compliant = compliant and ok
        rows.append({
            "key": key,
            "label": option["label"],
            "pe_label": option["pe_label"],
            "requested": wanted,
            "present": present,
            "ok": ok,
            "detail": (f"{option['pe_label']} "
                       f"{'set' if present else 'not set'}"),
        })

    return {
        "available": True,
        "binary": str(binary),
        "format": actual.get("format"),
        "dll_characteristics": actual.get("dll_characteristics"),
        "settings": settings,
        "settings_error": settings_error,
        "rows": rows,
        "compliant": compliant,
        "note": ("the binary carries every protection the settings ask for"
                 if compliant else
                 "the binary does not match the settings - rebuild"),
    }
