"""What the analyzer will actually run, read from the files that decide it.

Two files, both in the repo and both edited by hand:

  pipelines/*.yaml      which phases run, in which order, and what environment
                        they are given. `static_analyzer --pipeline <name>`.
  config/artifacts.yaml whether the evidence bundle is built, and whether it is
                        uploaded to MEGA, and where.

Neither is fetched from a service, because neither is served by one: they are
configuration, and a console that reports configuration by re-deriving it
somewhere else is a console that can disagree with the analyzer. The one fact
that IS a service question - the list of phase names a pipeline may use - comes
from the analyzer's own `GET /phases`, cached in `server.py` from
`static_analyzer --list-phases --json`. When the analyzer is down the catalog is
absent, the phase check is skipped, and the payload says so rather than
validating against a stale copy of the names.

Validation here mirrors `pipeline::planner` rather than inventing rules of its
own, because the only definition of a valid pipeline is the one the binary
enforces: a phase name that is not in the catalog is rejected with exit 2, a
prerequisite the config forgot is inserted silently, and `export`/`summary` are
appended if absent. Showing the resolved order next to the declared one is what
makes a hand-written config reviewable without running it.

Read-only, like the rest of this panel: nothing here writes, starts or queues
anything. A pipeline is authored by editing its YAML, which the analyzer already
reads - there is no second store for it to drift out of sync with.

Environment values that look like credentials are masked with the same
name rules `redact::is_secret_name()` applies, so a pipeline that exports a CTI
key can be reviewed in the console without the console becoming the place the
key is written down.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import threading
import time
import urllib.request

import yaml

from ..core import config, yamlview

PIPELINE_DIR = config.REPO / "pipelines"
ARTIFACTS_FILE = config.REPO / "config" / "artifacts.yaml"
UPLOADER_SCRIPT = config.REPO / "mega" / "upload.py"

# Keys planner::load_artifact_options() accepts. It rejects everything else, so a
# stray key is a hard error at startup and is reported here as one rather than
# quietly ignored the way a permissive parser would.
ARTIFACT_KEYS = ("store_artifact", "upload_artifacts", "remote_root", "timeout_seconds",
                 "encrypt_artifacts")

# The MEGA upload-and-protection settings moved to config/analysis.yaml, applied
# at analyzer startup and arriving at the planner as env names. Where one of
# these is defined there it WINS over config/artifacts.yaml - that precedence is
# in load_artifact_options() - so every value this module reports and every gate
# it answers goes through the same overlay. store_artifact stays file-only:
# building a local bundle is not a machine-level question.
#
# The seal's keypair pair is gone: protection is the operator password zip, and
# the password file lives outside the repo (see mega/protect.py), managed on the
# page as a status chip - never as a value, so no secret-looking string can
# enter a repo config through any form.
MEGA_OVERRIDES = {
    "upload_artifacts": "MEGA_UPLOAD",
    "encrypt_artifacts": "MEGA_SEAL",
    "remote_root": "MEGA_REMOTE_ROOT",
    "timeout_seconds": "MEGA_TIMEOUT",
}

# Phases the planner appends to any config that omits them, so a two-phase
# pipeline still writes its artifacts and prints a report.
EPILOGUE = ("export", "summary")

# Always-run phases. Not selectable and not part of any config - listed so the
# phases page does not look like it is missing half the analyzer.
ALWAYS_ON = ("preamble", "hashes")

_CATALOG_TTL = 30.0
_catalog_cache: tuple[float, dict] | None = None

# One writer at a time. Every write below is read-modify-write on a text file
# that the analyzer may also be reading, so two concurrent panel requests would
# otherwise be able to interleave and lose one of the edits.
_write_lock = threading.RLock()


def _flag(key: str, label: str, detail: str, honoured_by: str,
          affects: tuple[str, ...] = (), default: bool = False) -> dict:
    return {"key": key, "label": label, "kind": "flag", "detail": detail,
            "honoured_by": honoured_by, "affects": list(affects), "default": default}


def _number(key: str, label: str, detail: str, honoured_by: str, default: float,
            low: float, high: float, affects: tuple[str, ...] = ()) -> dict:
    return {"key": key, "label": label, "kind": "number", "detail": detail,
            "honoured_by": honoured_by, "affects": list(affects),
            "default": default, "min": low, "max": high}


def _text(key: str, label: str, detail: str, honoured_by: str,
          affects: tuple[str, ...] = ()) -> dict:
    return {"key": key, "label": label, "kind": "text", "detail": detail,
            "honoured_by": honoured_by, "affects": list(affects), "default": ""}


# ---------------------------------------------------------------------------
# Pipeline `environment:` options the analyzer really honours.
#
# Every entry names the code that reads it, and there is a test for each one that
# is listed. That is the whole bar for something appearing here: an option the
# binary ignores is not a feature, it is a switch that lies, and a config page
# full of those is worse than no config page. `honoured_by` is therefore not
# decoration - it is the claim the panel is making on the operator's behalf, and
# it is rendered next to the control so it can be checked.
#
# The defaults mirror the binary, not this file: ML_EXPLAIN defaults to ON in
# phase_ml.cpp, so a pipeline that never mentions it still asks for SHAP. The UI
# shows the inherited value and writes an explicit one only when asked.
# ---------------------------------------------------------------------------
ENV_OPTIONS = [
    _flag("CTI_SKIP", "Skip CTI lookups",
          "Stops the CTI phase touching the internet. Providers, DNS, crt.sh and "
          "the Bitwarden reconciliation pass are all off; everything else still runs.",
          "src/main/phase_cti.cpp:36", ("cti",)),
    _flag("ML_SKIP", "Skip ML scoring",
          "The model phase still appears in the plan and reports itself skipped, "
          "rather than the phase being quietly absent.",
          "src/main.cpp:291", ("model",)),
    _flag("ML_EXPLAIN", "Explain the ML score",
          "Requests SHAP contributions for the score. Slower and a much bigger "
          "report section - the one ML option worth turning off for bulk runs.",
          "src/main/phase_ml.cpp:97", ("model",), default=True),
    _number("ML_THRESHOLD", "ML decision threshold",
            "The single biggest lever on this model's output; the value actually "
            "applied is echoed into the report.",
            "src/main/phase_ml.cpp:96", 0.5, 0.0, 1.0, ("model",)),
    _number("ML_TOP_K", "ML features explained",
            "How many SHAP rows the explanation carries.",
            "src/main/phase_ml.cpp:98", 8.0, 1.0, 50.0, ("model",)),
    _text("CTI_CONFIG", "CTI overlay file",
           "Path to the JSON overlay for provider URLs, cache dir, offline mode "
           "and disabled providers. Relative paths resolve from the repo root.",
           "src/main/phase_cti.cpp:176", ("cti",)),
    _flag("STATIC_ANALYZER_CURSES", "PDCurses progress screen",
          "The curses UI only works on a real terminal; turn it off when output "
          "is redirected, piped or captured.",
          "src/main.cpp:219"),
    _flag("IA_ALLOW_CORE_DUMP", "Keep a crash dump",
          "On POSIX raises RLIMIT_CORE so a core file is written when the run "
          "dies - distributions usually ship a soft limit of 0, which is why "
          "there is no core file today. On Windows there is no core dump, so "
          "this widens the minidump in logs/crash/ to carry the whole address "
          "space. Off by default: a full dump is a large file per crash, and "
          "most crashes are explained by the text report next to it.",
          "src/main.cpp:343"),
    _flag("IA_CONTINUE_ON_SIGNAL", "Continue when interrupted",
          "Ctrl+C no longer stops the run. The first one is consumed by the run "
          "loop, which re-runs the phase it landed on and carries on with the "
          "plan; only a second Ctrl+C stops it, at the usual phase boundary. "
          "Re-running rather than skipping past matters: an interrupted phase "
          "can leave partial output behind, and the next phase reading that is "
          "how a report ends up quietly wrong. For unattended runs, where a "
          "stray interrupt should not throw away an hour of analysis.",
          "src/core/resume.cpp:246"),
    _text("TRACE_FILE", "Trace diagnostics file",
           "Writes symbol/offset diagnostics here. Empty means the trace layer "
           "writes nothing.",
           "src/core/trace.cpp:21"),

    # --- the nine keys the planner's own kKeys list carries, in that order ---
    # Backed by the parity tests in unit/python/test_analysis_settings.py: this
    # list must name exactly the keys analysis_config.cpp reads, in the same
    # order, or the console drifts from what the binary honours. ENABLE_TRACING
    # is default-true because its C++ says unset MEANS tracing on; the defaults
    # on the MEGA group are artifacts.yaml's own values, which is what a run
    # without these keys configured would use.
    _flag("ENABLE_TRACING", "Trace layer hard-off",
          "false, 0, no or off silences the trace file entirely - even where "
          "TRACE_FILE is set, without touching it. The cost to know about: the "
          "last-calls tail in a crash report goes quiet with it. Unset or true "
          "leaves tracing exactly as it was.",
          "src/core/trace.cpp:44", default=True),
    _flag("IA_INTERRUPT_IF_PACKED", "Stop when the sample looks packed",
          "The byte histogram's whole-file entropy becomes a tripwire: at or "
          "above the threshold the run stops right there - before the phases "
          "that would spend hours on a packed artifact nothing will be "
          "believed about - and the report names both numbers. --resume "
          "pushes past the stop without editing anything.",
          "src/main/phase_extract.cpp:251"),
    _number("IA_INTERRUPT_ENTROPY", "Packed threshold, bits/byte",
            "The threshold the stop above compares against. The analyzer "
            "accepts anything above 0 up to 8 bits/byte (0 rejects the run "
            "back left at default); the console floors the form at 0.1, and "
            "out-of-range values are warned about with the default standing.",
            "src/main/phase_extract.cpp:253", 7.5, 0.1, 8.0),
    _flag("MEGA_UPLOAD", "Upload the evidence bundle",
          "Per-run override of artifacts.yaml's upload_artifacts: on ends the "
          "run with a MEGA push, off suppresses it everywhere this applies. "
          "IA_ARTIFACT_UPLOAD=0 (the panel's own runner sets it for every job "
          "it starts) still wins over everything, in both directions.",
          "src/main/pipeline_planner.cpp:745"),
    _text("MEGA_REMOTE_ROOT", "MEGA destination parent",
          "The bundle lands under <remote_root>/<sample>_artifact. Overrides "
          "the file's remote_root for this run only; empty keeps it.",
          "src/main/pipeline_planner.cpp:747"),
    _flag("MEGA_SEAL", "Password-protect the bundle before upload",
          "Per-run override of artifacts.yaml's encrypt_artifacts: the archive "
          "is wrapped in a password-protected zip (WinZip AES-256) and only "
          "the zip is uploaded - the plaintext stays local. Off leaves it "
          "plain. The password comes from the operator password file outside "
          "the repo, managed just below; nothing here ever holds the value.",
          "src/main/pipeline_planner.cpp:746"),
    _number("MEGA_TIMEOUT", "Upload timeout, seconds",
            "How long the MEGA push may take before it is abandoned: 1 to "
            "86400. Out-of-range or non-numeric values are reported with the "
            "file's value standing. 900 is artifacts.yaml's default.",
            "src/main/pipeline_planner.cpp:751", 900.0, 1.0, 86400.0),
]

ENV_BY_KEY = {o["key"]: o for o in ENV_OPTIONS}



# The opt-in rule-generation phase, and the phases it must land BEFORE.
#
# Order is the whole reason this is not a plain append: the phase writes a .yar
# into the artifact set, so anything that assembles or ships that set runs first
# means the rules are generated and then lost. `sanity` is in the list because it
# is a self-test that should still see the finished output, not because it ships
# anything.
YARA_GEN_PHASE = "yara_gen"
_BEFORE_YARA_GEN_STOP = ("export", "dashboard", "sanity", "summary")

# Mirrors redact::is_secret_name() in src/core/redact.cpp, needles and all.
_SECRET_SUBSTRINGS = ("api_key", "auth_key", "token", "password", "passwd",
                      "secret", "session", "private", "credential", "apikey",
                      "passphrase")
_SECRET_SUFFIXES = ("_key", "_pwd", "_pw")


def _is_secret(name: str) -> bool:
    low = name.lower()
    if any(n in low for n in _SECRET_SUBSTRINGS):
        return True
    return any(low.endswith(s) and len(low) > len(s) for s in _SECRET_SUFFIXES)


def _rel(path) -> str:
    try:
        return str(path.relative_to(config.REPO)).replace("\\", "/")
    except (ValueError, TypeError):
        return str(path)


def _scalar(value) -> str:
    """Environment and option values as the string they will actually become."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


# ---------------------------------------------------------------------------
# Phase catalog - the one thing here that comes from a service
# ---------------------------------------------------------------------------


_ANALYZER_EXE = config.REPO / "build-ucrt" / "static_analyzer.exe"


def _catalog_from_binary() -> list[dict]:
    """Ask the built analyzer directly: `--list-phases --json`.

    This is not a substitute for the API and not a cached copy of it. It is the
    same answer the API gives, because the API is a thin wrapper that runs
    exactly this command (server.py: `proc = self.run_analyzer(["--list-phases",
    "--json"])`). Going through HTTP adds a dependency and no information.

    That matters because the API only runs when somebody starts server.py, and
    until then the New-pipeline tab is dead - no catalog, no steps, nothing to
    build from - for a tool that is sitting right there on disk able to answer.
    Authoring a pipeline does not need a running service; it needs the binary.

    Deliberately NOT a fallback to a bundled copy of the names. A stale list
    would let somebody compose a config the analyzer rejects with exit 2, which
    is the exact failure this catalog exists to prevent - and the list changes
    whenever the binary is rebuilt, which is precisely when a cached copy goes
    wrong.
    """
    if not _ANALYZER_EXE.is_file():
        raise FileNotFoundError(
            f"{_ANALYZER_EXE.name} is not built, so the phase catalog is "
            f"unavailable")
    proc = subprocess.run(
        [str(_ANALYZER_EXE), "--list-phases", "--json"],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        # Generous next to PANEL_TIMEOUT: this spawns the analyzer, which
        # constructs its tracer and loads symbols before main() runs.
        timeout=30.0, check=False, cwd=str(config.REPO),
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"--list-phases exited {proc.returncode}: "
            f"{(proc.stderr or '').strip()[:200]}")
    return json.loads(proc.stdout or "[]")


def _fetch_catalog() -> dict:
    source = "analyzer"
    try:
        url = f"http://{config.analyzer_base()}/phases"
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=config.PANEL_TIMEOUT) as resp:
            payload = json.loads(resp.read(262144).decode("utf-8", "replace"))
    except Exception:  # noqa: BLE001 - the API being down is the normal case
        # Fall through to the binary. The reason the API failed is kept, not
        # swallowed: "the REST service was unreachable" and "the binary would
        # not answer" are different problems and the page should say which.
        api_error = f"the analyzer REST service was unreachable"
        payload = _catalog_from_binary()
        source = "binary"
    if not isinstance(payload, list):
        raise ValueError("phase catalog is not a list")
    items = []
    for entry in payload:
        if not isinstance(entry, dict):
            continue
        items.append({
            "name": str(entry.get("name") or ""),
            "description": str(entry.get("description") or ""),
            "artifact": str(entry.get("artifact") or ""),
            "service": str(entry.get("service") or ""),
            "requires": [str(r) for r in (entry.get("requires") or [])],
        })
    items = [i for i in items if i["name"]]
    if not items:
        raise ValueError("phase catalog is empty")
    return {"available": True, "source": source,
            # Left as a note rather than an error: the catalog IS usable, and a
            # banner reading like a failure next to a working list teaches the
            # reader to ignore banners.
            "error": "" if source == "analyzer" else
                      f"read from {config.REPO.name}/build-ucrt/"
                      f"{_ANALYZER_EXE.name} - the REST service was unreachable",
            "items": items, "requires": {i["name"]: i["requires"] for i in items}}


def _catalog() -> dict:
    """The analyzer's phase catalog, cached briefly because it is immutable for
    the lifetime of the process that published it and the panel polls often.

    Failure is cached too, but only for a fraction of the TTL: a panel that was
    opened while the analyzer was still booting should pick the catalog up as
    soon as it is there rather than waiting out a full window.
    """
    global _catalog_cache
    now = time.monotonic()
    if _catalog_cache is not None:
        when, payload = _catalog_cache
        ttl = _CATALOG_TTL if payload["available"] else _CATALOG_TTL / 6
        if now - when < ttl:
            return payload
    try:
        payload = _fetch_catalog()
    except Exception as exc:  # noqa: BLE001 - an offline analyzer is normal here
        payload = {"available": False, "source": "none",
                   "error": f"{type(exc).__name__}: {exc}", "items": [],
                   "requires": {}}
    _catalog_cache = (now, payload)
    return payload


# ---------------------------------------------------------------------------
# Phase resolution - the planner's closure, driven by the catalog
# ---------------------------------------------------------------------------


def _resolve(declared: list[str], requires: dict[str, list[str]]) -> tuple[list[str], list[str]]:
    """(phases the analyzer will run, phases it added that the config omitted).

    Inserted prerequisites land immediately before the phase that needs them,
    which is what planner::close() does; without that placement a pipeline that
    lists `hexdump` before `extraction` would read as running the dump first.
    The order is otherwise the declared order, deduplicated.
    """
    ordered: list[str] = []
    for phase in declared:
        for req in requires.get(phase, []):
            if req not in ordered:
                ordered.append(req)
        if phase not in ordered:
            ordered.append(phase)
    inserted = [p for p in ordered if p not in declared]
    for phase in EPILOGUE:
        if phase not in ordered:
            ordered.append(phase)
            if phase not in inserted:
                inserted.append(phase)
    return ordered, inserted


# ---------------------------------------------------------------------------
# Pipelines
# ---------------------------------------------------------------------------


def _phase_list(value) -> list[str]:
    """A `phases:` entry as names. A bare string is accepted because the planner
    accepts it; anything else is reported by the caller as a shape error."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [_scalar(v).strip() for v in value if _scalar(v).strip()]
    return []


def _global_settings() -> dict[str, str]:
    """What config/analysis.yaml defines, as {key: value}.

    Imported here rather than at module scope because analysis_settings imports
    this module for ENV_OPTIONS: a top-level import would be a cycle. A
    function-local import is the same escape hatch this file already uses for
    tempfile and pathlib, for the same reason.

    Read per call rather than cached: this file is the operator's standing
    choice and is edited from the console on the page sitting next to this one,
    so a cached copy would be wrong within one poll of the edit that mattered.
    """
    from . import analysis_settings

    try:
        return analysis_settings.set_values(config.REPO)
    except OSError:
        # The file exists but cannot be read. Refusing every pipeline edit would
        # be a worse failure than allowing one: the operator cannot fix an
        # unreadable config from here anyway, and the analyzer will not start on
        # it either, so nothing is silently mis-applied.
        return {}


def _global_keys() -> set[str]:
    """Keys config/analysis.yaml defines, which no pipeline may also set."""
    return set(_global_settings())


def _refuse_shadowed(updates: dict) -> None:
    """Refuse a per-pipeline write for any key set globally.

    The analyzer applies config/analysis.yaml *after* the pipeline's
    `environment:` block, so such a line is not a weaker setting - it is a
    setting that does not happen. Writing one from a browser is how you get a
    file that says ML_SKIP: "0" and a run that skips the model anyway, with
    nothing in either file explaining it.

    So this is refused rather than accepted-and-ignored, and the message names
    where the key actually lives so the fix is one click on the other page.
    """
    _refuse_shadowed_document_names(
        sorted(k for k in updates if k in _global_keys()))


def _refuse_shadowed_document_names(shadowed: list[str]) -> None:
    """The shared message, so the two callers cannot drift apart in wording."""
    if shadowed:
        raise ValueError(
            "set globally in config/analysis.yaml, where it wins over any "
            "pipeline: " + ", ".join(shadowed)
            + ". Clear it there first."
        )


def _refuse_shadowed_document(text: str) -> None:
    """Refuse a whole new pipeline file that duplicates a global key.

    Used by save_pipeline, where every `environment:` key in the text is one the
    caller has just introduced - so unlike an edit to an existing file, there is
    no "pre-existing line" that is not the caller's to own.

    Deliberately NOT in _verify_pipeline. That is the shared gate for the yarGen
    toggle as well, which does not write an environment key; putting
    the rule there would refuse every edit to a pipeline that still carries a
    stale shadowed line - which is precisely the file the operator needs to be
    able to edit in order to clean it up.
    """
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError:
        return  # _verify_pipeline reports the parse failure with a better message
    if not isinstance(doc, dict):
        return
    env = doc.get("environment")
    if not isinstance(env, dict):
        return
    global_keys = _global_keys()
    _refuse_shadowed_document_names(
        sorted(str(k) for k in env if str(k) in global_keys))


def _refuse_global_only(updates: dict) -> None:
    """Refuse a per-pipeline write of a phase-scoped setting.

    Phase-scoped keys - everything with an `affects` phase - are machine-wide:
    they are set on Analysis Configuration and apply to every run. The
    per-pipeline controls for them are what filled these files with inert
    ML_SKIP and CTI_SKIP lines on pipelines that never run the affected phase,
    so the console no longer offers a control for one on any pipeline page, on
    either write route.

    Unlike the shadowing rule this needs no catalog and no plan - it is a
    property of the key, so it refuses the same way with the analyzer down.

    Refusal is scoped to keys being SET. Clearing one is allowed, because
    removing a line that does not belong is the cleanup this rule exists to
    provoke. A hand-edited pipeline file still works - the analyzer reads its
    environment block regardless of what this console offers - but the console
    no longer helps write one.
    """
    scoped = sorted(k for k in updates if ENV_BY_KEY[k]["affects"])
    if scoped:
        raise ValueError(
            "managed on Analysis Configuration, not per pipeline: "
            + ", ".join(scoped)
            + ". A phase-scoped setting applies to every run; this page sets "
              "only the run-wide options."
        )


def _pipeline(path, global_keys: set[str] | None = None) -> dict:
    # `global_keys` is passed in by callers that render a whole listing, which
    # would otherwise re-read config/analysis.yaml once per pipeline file.
    global_keys = _global_keys() if global_keys is None else global_keys
    entry = {
        "name": path.stem,
        "description": "",
        "file": _rel(path),
        "source": "repo",
        "ok": True,
        "error": "",
        "stages": [],
        "phases": [],
        "environment": [],
        "resolved": [],
        "inserted": [],
        "unknown_phases": [],
        "phase_check": "unavailable",        # When the file itself last changed. Not the same as when this page read
        # it: the panel polls on a timer, so "read Ns ago" only ever describes
        # the poll, while "edited Nm ago" is the fact an operator wants when they
        # are deciding whether what they are looking at is current.
        "mtime": 0.0,
        "content": "",
        "spans": [],
    }
    try:
        entry["mtime"] = round(path.stat().st_mtime, 1)
    except OSError:
        pass
    try:
        content = path.read_text(encoding="utf-8-sig")
    except OSError as exc:
        entry.update(ok=False, error=f"unreadable: {exc}")
        return entry
    entry["content"] = content
    entry["spans"] = yamlview.spans(content)
    try:
        # JSON is valid YAML, so a .json pipeline in this directory parses with
        # the same loader the planner uses for both.
        doc = yaml.safe_load(content)
    except yaml.YAMLError as exc:
        entry.update(ok=False, error=f"invalid YAML: {exc}")
        return entry
    if doc is None:
        doc = {}
    if not isinstance(doc, dict):
        entry.update(ok=False, error="pipeline config must be a mapping")
        return entry

    name = doc.get("name")
    if isinstance(name, str) and name.strip():
        entry["name"] = name.strip()
    description = doc.get("description")
    entry["description"] = description.strip() if isinstance(description, str) else ""

    declared: list[str] = []
    stages = doc.get("stages")
    if stages is not None:
        if not isinstance(stages, list):
            entry.update(ok=False, error="'stages' must be a list")
            return entry
        for stage in stages:
            if not isinstance(stage, dict):
                entry["stages"].append({"name": "", "phases": []})
                continue
            stage_name = stage.get("name")
            phases = _phase_list(stage.get("phases"))
            entry["stages"].append({
                "name": stage_name.strip() if isinstance(stage_name, str) else "",
                "phases": phases,
            })
            declared.extend(phases)
    else:
        phases = _phase_list(doc.get("phases"))
        entry["stages"].append({"name": "", "phases": phases})
        declared.extend(phases)

    if not declared:
        entry.update(ok=False,
                     error=entry["error"] or "config contains no 'stages' or 'phases'")
        return entry

    # Flattened, deduplicated, order preserved: what the operator picked, with
    # the stage grouping kept alongside for readability.
    flat: list[str] = []
    for phase in declared:
        if phase not in flat:
            flat.append(phase)
    entry["phases"] = flat

    env = doc.get("environment")
    if env is not None:
        if not isinstance(env, dict):
            entry.update(ok=False, error="'environment' must be a map")
        else:
            for key, value in sorted(env.items(), key=lambda kv: str(kv[0]).lower()):
                key = str(key)
                if isinstance(value, (dict, list)):
                    entry.update(ok=False,
                                 error=f"environment value for '{key}' must be a scalar")
                    continue
                secret = _is_secret(key)
                entry["environment"].append({
                    "key": key,
                    # Masked for the same reason the analyzer logs it masked:
                    # this page is a review surface, not a place to read secrets.
                    "value": "••••••" if secret else _scalar(value),
                    "secret": secret,
                    # True when config/analysis.yaml sets this key too, so this
                    # line does not happen. Reported rather than hidden: it is
                    # already in the file, and an operator reading the YAML has
                    # to be able to find out that it is inert.
                    "shadowed": key in global_keys,
                })
    return entry


def _options_for() -> list[dict]:
    """The options a pipeline page offers.

    The run-wide ones only. The phase-scoped settings - CTI_SKIP and the ML
    knobs - are machine-wide, changed on Analysis Configuration, so a pipeline
    page neither offers a control for one nor a card: a setting neither this
    page nor this file can change has no business taking up a slot here, and
    listing it read-only is how the "Settings for this pipeline" heading came
    to hold six controls that could not affect the run. The file's own stale
    lines for those keys are still reported in the environment list below,
    marked like any other line that does not mean what it says.

    Copies, never the ENV_OPTIONS dicts themselves: ENV_BY_KEY shares them,
    and decorating one pipeline's copy would leak into every other pipeline.
    """
    return [dict(o) for o in ENV_OPTIONS if not o["affects"]]


def _resolve_entry(entry: dict, catalog: dict) -> dict:
    """Fill in the fields that depend on the catalog, in place.

    Shared with the write routes so a save and a read return the same shape. A
    POST that answered with a thinner object than the GET would leave a client
    reading `pipeline.resolved` as undefined - which is the
    kind of difference that only shows up as a blank panel later.
    """
    requires = catalog["requires"]
    available = bool(catalog["available"])
    if available:
        unknown = [p for p in entry["phases"] if p not in requires]
        entry["unknown_phases"] = unknown
        entry["phase_check"] = "ok" if not unknown else "unknown"
        if unknown and entry["ok"]:
            entry["ok"] = False
            entry["error"] = "phase not in the analyzer's catalog: " + ", ".join(unknown)
    resolved, inserted = _resolve(entry["phases"], requires)
    entry["resolved"] = resolved
    entry["inserted"] = inserted
    entry["options"] = _options_for()
    # An environment line for a phase this plan does not run is the same kind
    # of inert line `shadowed` marks - read, then never used - so it gets the
    # same treatment: reported beside the value rather than silently rendered
    # as if it did something.
    if available:
        for line in entry["environment"]:
            spec = ENV_BY_KEY.get(line["key"])
            if spec and spec["affects"] and not any(p in resolved for p in spec["affects"]):
                line["irrelevant"] = True
    return entry


def _pipelines(catalog: dict, global_keys: set[str] | None = None) -> list[dict]:
    entries: list[dict] = []
    try:
        files = sorted(
            p for p in PIPELINE_DIR.iterdir()
            if p.is_file() and p.suffix.lower() in (".yaml", ".yml", ".json")
        )
    except OSError:
        files = []

    seen: set[str] = set()
    # Once per listing, not once per file: this is a disk read of a file the
    # console can edit, and thirteen reads for one page render is thirteen
    # chances to render two different snapshots of it.
    keys = _global_keys() if global_keys is None else global_keys
    for path in files:
        entry = _pipeline(path, keys)
        # Bare `--pipeline default` is the built-in plan, so a default.yaml in
        # here is a copy of it rather than a pipeline that shadows it. The
        # analyzer's own listing hides it for the same reason; this page shows it
        # because reading it is the point.
        if entry["name"] in seen:
            entry["source"] = "shadowed"
        seen.add(entry["name"])
        _resolve_entry(entry, catalog)
        entries.append(entry)
    return entries


# ---------------------------------------------------------------------------
# Artifact / MEGA upload options
# ---------------------------------------------------------------------------


def _artifact_file() -> dict:
    """config/artifacts.yaml parsed, with no overlay applied yet."""
    out = {
        "present": False,
        "file": _rel(ARTIFACTS_FILE),
        "store_artifact": False,
        "upload_artifacts": False,
        "remote_root": "",
        "timeout_seconds": 900,
        "encrypt_artifacts": False,
        "errors": [],
        "uploader_script": "",
        "mtime": 0.0,
        "content": "",
        "spans": [],
    }
    try:
        content = ARTIFACTS_FILE.read_text(encoding="utf-8-sig")
    except OSError:
        return out
    out["present"] = True
    try:
        out["mtime"] = round(ARTIFACTS_FILE.stat().st_mtime, 1)
    except OSError:
        pass
    out["content"] = content
    out["spans"] = yamlview.spans(content)

    try:
        doc = yaml.safe_load(content)
    except yaml.YAMLError as exc:
        out["errors"].append(f"invalid YAML: {exc}")
        return out
    if doc is None:
        doc = {}
    if not isinstance(doc, dict):
        out["errors"].append("artifact config must be a YAML map")
        return out

    for key, value in doc.items():
        key = str(key)
        if key not in ARTIFACT_KEYS:
            out["errors"].append(f"unknown artifact option '{key}'")
            continue
        if key in ("store_artifact", "upload_artifacts", "encrypt_artifacts"):
            # Assign the value, not the fact that the key was present: a config
            # that says `store_artifact: false` means the bundle is NOT built,
            # and reading key-presence here would invert the one option on this
            # page that decides whether evidence leaves the host. Same reasoning
            # for encrypt_artifacts, which decides whether it leaves readable.
            if not isinstance(value, bool):
                out["errors"].append(f"'{key}' must be true or false")
                continue
            out[key] = value
            continue
        if key == "remote_root":
            if not isinstance(value, str) or not value.strip():
                out["errors"].append("'remote_root' must not be empty")
                continue
            out["remote_root"] = value.strip()
        if key == "timeout_seconds":
            try:
                seconds = int(value)
            except (TypeError, ValueError):
                out["errors"].append("'timeout_seconds' must be a whole number of seconds")
                continue
            # Same bounds the planner enforces, so a value the analyzer would
            # refuse is refused here too.
            if not 1 <= seconds <= 86400:
                out["errors"].append("'timeout_seconds' must be between 1 and 86400")
                continue
            out["timeout_seconds"] = seconds
            continue

    # encrypt_artifacts without a password file is not an error here - the
    # uploader refuses to ship anything until one exists, which is the
    # fail-closed behaviour wanted - but the page owes the operator that state,
    # so the artifact dict below carries bundle_password (see password helpers).

    out["uploader_script"] = _rel(UPLOADER_SCRIPT) if UPLOADER_SCRIPT.is_file() else ""
    return out


def _artifacts() -> dict:
    """The artifact options as the analyzer will see them.

    config/artifacts.yaml parsed, then config/analysis.yaml's MEGA_* values
    overlaid exactly where load_artifact_options() overlays the env vars. Every
    exit path - a missing file, a broken one, a healthy one - lands here, so the
    pages always display what the next run will actually do.
    """
    return _apply_mega_overrides(_artifact_file())


def _mega_value(option: str, raw):
    """A MEGA_* analysis setting as the artifact option's type, or None.

    None means "unusable" and matches the analyzer's own behaviour: the planner
    warns and lets config/artifacts.yaml's value stand, so this file cannot
    claim the decision - it never decided anything.
    """
    if option in ("upload_artifacts", "encrypt_artifacts"):
        text = str(raw).strip().lower()
        if text in ("1", "true", "yes", "on"):
            return True
        if text in ("0", "false", "no", "off"):
            return False
        return None
    if option == "timeout_seconds":
        try:
            seconds = int(str(raw).strip())
        except (TypeError, ValueError):
            return None
        return seconds if 1 <= seconds <= 86400 else None
    # remote_root is a plain string: the same value the env var will carry. A
    # blank line in analysis.yaml is treated as unset, exactly as the planner
    # treats an empty env var.
    text = str(raw).strip()
    return text or None


def _apply_mega_overrides(out: dict) -> dict:
    """Overlay config/analysis.yaml's MEGA_* onto the file-parsed values.

    Read per call rather than cached: this is the operator's standing choice and
    the Analysis Configuration page edits it from the console a few pixels away,
    so a cached copy would be wrong within one poll of the edit that mattered.
    """
    from . import analysis_settings  # noqa: PLC0415 - analysis_settings imports this module

    mega = analysis_settings.set_values(config.REPO)
    out["decided_by"] = {k: "config/artifacts.yaml"
                         for k in MEGA_OVERRIDES if k in out}
    out["mega_warnings"] = []
    for option, env_key in MEGA_OVERRIDES.items():
        if option not in out:
            continue
        raw = mega.get(env_key)
        if raw is None:
            continue
        parsed = _mega_value(option, raw)
        if parsed is None:
            if str(raw).strip():
                out["mega_warnings"].append(
                    f"{env_key}={raw} does not fit '{option}'; "
                    "config/artifacts.yaml's value stands (the analyzer logs "
                    "the same choice at startup)")
            continue
        out[option] = parsed
        out["decided_by"][option] = f"config/analysis.yaml ({env_key})"
    return out



# ---------------------------------------------------------------------------
# Public snapshot
# ---------------------------------------------------------------------------


def snapshot() -> dict:
    catalog = _catalog()
    global_settings = _global_settings()
    pipelines = _pipelines(catalog, set(global_settings))
    artifacts = _artifacts()

    # Newest mtime across everything this page reads, so one label can answer
    # "how old is this configuration?" without the operator hunting for it.
    newest = max([artifacts["mtime"]] + [p["mtime"] for p in pipelines])

    return {
        "pipelines_dir": _rel(PIPELINE_DIR),
        "pipelines_present": PIPELINE_DIR.is_dir(),
        "pipelines": pipelines,
        "pipeline_count": len(pipelines),
        "broken": [p["name"] for p in pipelines if not p["ok"]],
        "newest_edit": newest,
        "phases": {
            "available": catalog["available"],
            "source": catalog["source"],
            "error": catalog["error"],
            "items": catalog["items"],
            "count": len(catalog["items"]),
            "always_on": list(ALWAYS_ON),
            "epilogue": list(EPILOGUE),
        },
        "artifacts": artifacts,
        # MEGA upload is the one option with a side effect outside the host, so
        # it gets its own top-level flag rather than being buried in a tab.
        "mega_upload": bool(artifacts["upload_artifacts"]),
        "mega_encrypt": bool(artifacts["encrypt_artifacts"]),
        # The password state, not the password: whether the operator password
        # file exists and where it lives, so the page can show a status chip
        # without any secret ever returning through this payload.
        "bundle_password": _password_payload(),
        "options": _options_for(),
        # What config/analysis.yaml already owns, with the value it owns it at.
        # The pipeline controls for these keys are rendered read-only rather than
        # hidden: the key is on the other page, it applies to every run including
        # this one, and an operator looking for "where do I turn this off" should
        # be pointed somewhere, not left with an absence.
        "global_settings": global_settings,        "checked_at": round(time.time(), 1),
    }


def artifact_upload_enabled() -> bool:
    """Whether a MEGA upload is on right now, whatever page was last edited.

    Answered through the same precedence the planner applies - analysis.yaml's
    MEGA_UPLOAD over config/artifacts.yaml's upload_artifacts - so the Artifacts
    page's Export gate and the analyzer never disagree about who decided.
    """
    return bool(_artifacts()["upload_artifacts"])


def artifact_upload_decision() -> dict:
    """The upload toggle's value AND where it was decided, for gate messages.

    Saying "artifacts.yaml says off" when analysis.yaml's MEGA_UPLOAD turned it
    on would send the operator to fix the wrong file; the decider is part of the
    answer, not a detail someone can guess.
    """
    state = _artifacts()
    return {"enabled": bool(state["upload_artifacts"]),
            "decided_by": state.get("decided_by", {}).get("upload_artifacts", "")}


def artifact_upload_timeout() -> int:
    """The uploader's own timeout budget, so a manual export obeys the same
    ceiling an analyzer run would (MEGA_TIMEOUT wins over the file, as usual)."""
    return int(_artifacts()["timeout_seconds"])


def artifact_encrypt_enabled() -> bool:
    """Whether a bundle must be password-protected before it is uploaded.

    Read through the same MEGA_SEAL-over-file precedence as the analyzer, so the
    button and the run can never disagree about whether evidence leaves the host
    in the clear.
    """
    return bool(_artifacts().get("encrypt_artifacts"))


# --- bundle password -------------------------------------------------------
#
# The password file resource itself (mega/protect.py is the scheme that reads
# it). The panel manages the FILE - create, replace, clear - and reports only
# its existence and location. The value is never echoed back except in the one
# response to a successful generate, and never written into any repo config:
# a repo-read YAML holding evidence protection would put it one `cat` away
# from anything that can read the checkout.

_PASSWORD_TOO_SHORT_HINT = "the password must be at least 8 bytes to be a protection"


def _load_protect():
    """Load mega/protect.py by path, the way artifacts.py loads mega/list.py.

    mega/ holds scripts, not a package - no __init__.py, and protect.py rewrites
    sys.path to reach credential.py - so the import is by file location with a
    stable module name, and the failure is a value the routes can show rather
    than a crash mid-request.
    """
    import importlib.util
    path = config.REPO / "mega" / "protect.py"
    if not path.is_file():
        return None, f"{_rel(path)} not found"
    if str(path.parent) not in sys.path:
        sys.path.insert(0, str(path.parent))
    try:
        spec = importlib.util.spec_from_file_location("mega_protect", path)
        if spec is None or spec.loader is None:
            return None, f"could not load {_rel(path)}"
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module, None
    except Exception as exc:  # noqa: BLE001 - the error text is the UI's message
        return None, f"mega/protect.py failed to load: {exc}"


def _password_file():
    """The operator password file, or None when the protect module is absent."""
    protect, _ = _load_protect()
    return protect.password_file() if protect else None


def _password_payload() -> dict:
    """The response shape for the password state; never the value."""
    protect, error = _load_protect()
    if protect is None:
        return {"present": False, "path": "", "error": error}
    try:
        path = protect.password_file()
        present = protect.password_present(path)
    except Exception as exc:  # noqa: BLE001 - report, do not 500 over a chip
        return {"present": False, "path": "", "error": str(exc)}
    return {"present": present, "path": _rel(path), "error": None}


def _bundle_password_status() -> dict:
    return _password_payload()


def _bundle_password_clear() -> dict:
    """Remove the password file; a missing one is already the wanted state."""
    protect, error = _load_protect()
    if protect is None:
        return {"ok": False, "error": error}
    protect.clear_password()
    return {"ok": True, "status": _password_payload()}


def _bundle_password_set(value: str) -> dict:
    """Store the operator's own password, byte-exact, under the resolved file."""
    if not isinstance(value, str) or not value.strip():
        return {"ok": False, "error": "the password cannot be empty"}
    # The repo refuses secret-looking values from browser forms - the vault and
    # the .env are where credentials belong - and the password is no exception:
    # it never lands in a repo config, only in the profile password file.
    if len(value.encode("utf-8")) < 8:
        return {"ok": False, "error": _PASSWORD_TOO_SHORT_HINT}
    protect, error = _load_protect()
    if protect is None:
        return {"ok": False, "error": error}
    try:
        protect.set_password(value)
    except protect.PasswordError as exc:
        return {"ok": False, "error": str(exc)}
    # The value is deliberately NOT returned here: only a generate shows the
    # password once, because an operator-typed one is already in someone's
    # head / password manager.
    return {"ok": True, "status": _password_payload()}


def _bundle_password_generate(length: int = 24) -> dict:
    """Generate, store, and RETURN the password exactly once."""
    protect, error = _load_protect()
    if protect is None:
        return {"ok": False, "error": error}
    try:
        if not 12 <= int(length) <= 128:
            return {"ok": False, "error": "length must be between 12 and 128"}
        value, _ = protect.generate_password(int(length))
    except (protect.PasswordError, TypeError, ValueError) as exc:
        return {"ok": False, "error": str(exc)}
    return {"ok": True, "status": _password_payload(),
            "password": value, "shown_once": True}


# ---------------------------------------------------------------------------
# Writing
#
# These edit the text, not the parse tree. PyYAML's round trip would rewrite
# config/artifacts.yaml into a stripped, comment-free version of itself, and
# those comments are the file's documentation - they say what each option is for
# and why it defaults the way it does. Losing them to save a button click would
# be a bad trade, so a key is replaced in place and everything around it is left
# byte-identical.
#
# Every write is validated before it lands: the new text is re-parsed with the
# same loader the analyzer uses and compared against what was intended. A write
# that does not round-trip is refused, not saved. That is what makes a
# line-oriented edit safe here.
# ---------------------------------------------------------------------------


def _split_comment(line: str) -> tuple[str, str]:
    """(body, comment) split at the first real comment marker.

    A `#` only starts a comment at the start of the content or after whitespace
    (that is YAML's rule), and never inside a quoted scalar - so the walk tracks
    quote state rather than using `find('#')`, which would truncate
    `description: "a # b"` and write a value the file never had.
    """
    quote = ""
    for i, ch in enumerate(line):
        if quote:
            if ch == quote:
                quote = ""
            continue
        if ch in "\"'":
            quote = ch
        elif ch == "#" and (i == 0 or line[i - 1] in " \t"):
            return line[:i].rstrip(), line[i:].rstrip()
    return line.rstrip(), ""


def _find_key(lines: list[str], key: str, indent: str) -> int | None:
    pattern = re.compile(r"^" + re.escape(indent) + re.escape(key) + r"\s*:")
    for i, line in enumerate(lines):
        if pattern.match(line) and not line.lstrip().startswith("#"):
            return i
    return None


def _set_key(lines: list[str], key: str, value: str, indent: str,
             append_at: int | None = None) -> None:
    """Set `key: value` in place, or insert a new line at `append_at`.

    `append_at` matters inside a block: appending to the end of the FILE would
    put the key outside the `environment:` block whenever anything followed it,
    which parses as a mapping key in the wrong parent rather than as an error.
    """
    index = _find_key(lines, key, indent)
    if index is None:
        line = f"{indent}{key}: {value}"
        if append_at is None:
            lines.append(line)
        else:
            lines.insert(append_at, line)
        return
    _, comment = _split_comment(lines[index])
    lines[index] = f"{indent}{key}: {value}" + (f"  {comment}" if comment else "")


def _drop_key(lines: list[str], key: str, indent: str) -> bool:
    index = _find_key(lines, key, indent)
    if index is None:
        return False
    del lines[index]
    return True


def _read_text(path) -> tuple[str, str, bool]:
    """(text, newline, had_bom) with the file's own line endings intact.

    `newline=""` disables universal-newline translation, which matters because a
    CRLF file that came back as LF gets written back as LF and then shows as a
    whole-file change in every diff - including the case where the edit was a
    no-op. Preserving what is there means a save touches the keys it changed and
    nothing else, byte for byte.
    """
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        text = handle.read()
    bom = path.read_bytes().startswith(b"\xef\xbb\xbf")
    return text, ("\r\n" if "\r\n" in text else "\n"), bom


def _atomic_write(path, text: str, newline: str = "\n", bom: bool = False) -> None:
    """Replace a file in one step.

    The analyzer may be reading these files right now, and a half-written YAML
    is a config the planner would reject on the next run. Temp + rename means a
    reader sees either the old file or the new one, never a prefix of either.
    """
    tmp = path.with_name(path.name + ".panel-tmp")
    try:
        # newline="" on WRITE, not the file's own newline: Python translates every
        # "\n" in the string to whatever is named there, so writing CRLF text with
        # newline="\r\n" turns each existing "\r\n" into "\r\r\n". The text already
        # carries the line endings it was read with, so nothing may be translated.
        with tmp.open("w", encoding="utf-8-sig" if bom else "utf-8", newline="") as handle:
            handle.write(text)
        os.replace(tmp, path)
    except OSError as exc:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise OSError(f"could not write {path.name}: {exc}") from exc


def _environment_span(lines: list[str]) -> tuple[int, int] | None:
    """(start, end) line range of the `environment:` block, or None."""
    start = _find_key(lines, "environment", "")
    if start is None:
        return None
    end = start + 1
    for i in range(start + 1, len(lines)):
        line = lines[i]
        if not line.strip():
            continue
        if not line[0].isspace():
            break
        end = i + 1
    return start, end


def _quote(value: str) -> str:
    """A double-quoted YAML scalar for a value typed into a browser box.

    One pass over both characters, so a value holding `\"` is escaped once
    rather than twice - the mistake a sequential replace makes and one that
    produces a file PyYAML refuses.
    """
    return '"' + re.sub(r'["\\]', r"\\\g<0>", value) + '"'


def write_artifact_options(patch: dict) -> dict:
    """Apply a validated subset of the four artifact options to the YAML.

    Only keys the client actually sent are touched, so two people editing
    different options cannot clobber each other by submitting a stale copy of
    the whole form.
    """
    if not isinstance(patch, dict):
        raise ValueError("body must be an object")
    unknown = [k for k in patch if k not in ARTIFACT_KEYS]
    if unknown:
        raise ValueError("unknown artifact option: " + ", ".join(sorted(unknown)))

    # Where config/analysis.yaml defines a MEGA_* setting, that wins over
    # config/artifacts.yaml - the planner overlays the env vars onto the file.
    # Accepting the write here would put a value in the file that does not
    # decide what it says, so it is refused with a pointer to the page that
    # actually decides, exactly as a pipeline write is refused for a key the
    # global file owns.
    shadowed = sorted(
        f"'{k}' ({MEGA_OVERRIDES[k]})" for k in patch
        if k in MEGA_OVERRIDES and _global_settings().get(MEGA_OVERRIDES[k]) is not None)
    if shadowed:
        raise ValueError(
            "decided by config/analysis.yaml, which wins over config/"
            "artifacts.yaml where both are set (MEGA_*): " + ", ".join(shadowed)
            + ". Clear it there first - Analysis Configuration page, MEGA upload group.")

    prepared: dict[str, str] = {}
    for key, value in patch.items():
        if key in ("store_artifact", "upload_artifacts", "encrypt_artifacts"):
            if not isinstance(value, bool):
                raise ValueError(f"'{key}' must be true or false")
            prepared[key] = "true" if value else "false"
        elif key == "remote_root":
            if not isinstance(value, str) or not value.strip():
                raise ValueError("'remote_root' must not be empty")
            # This is a MEGA path, not a local one, but a leading backslash or a
            # `..` segment is still a path-traversal attempt against whatever
            # consumes it downstream.
            root = value.strip()
            if not root.startswith("/") or "\\" in root or any(
                part == ".." for part in root.split("/")
            ):
                raise ValueError("'remote_root' must be an absolute MEGA path")
            prepared[key] = _quote(root)
        else:
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError("'timeout_seconds' must be a whole number of seconds")
            seconds = int(value)
            if not 1 <= seconds <= 86400:
                raise ValueError("'timeout_seconds' must be between 1 and 86400")
            prepared[key] = str(seconds)

    with _write_lock:
        try:
            original, newline, bom = _read_text(ARTIFACTS_FILE)
        except OSError as exc:
            raise OSError(f"cannot read {ARTIFACTS_FILE.name}: {exc}") from exc

        lines = original.splitlines()
        for key, raw in prepared.items():
            _set_key(lines, key, raw, "")
        text = newline.join(lines).rstrip() + newline

        # Round-trip before landing: the analyzer's loader rejects this file
        # outright on a bad value, so a write that does not parse is a write
        # that would break the next run.
        try:
            parsed = yaml.safe_load(text) or {}
        except yaml.YAMLError as exc:
            raise ValueError(f"the edit would produce invalid YAML: {exc}") from exc
        if not isinstance(parsed, dict) or set(prepared) - set(parsed):
            raise ValueError("the edit would produce an unusable artifact config")
        _atomic_write(ARTIFACTS_FILE, text, newline, bom)

    return _artifacts()


def write_environment(pipeline: str, updates: dict) -> dict:
    """Set or clear `environment:` entries in one pipeline file.

    A flag set false is REMOVED rather than written as "0": the analyzer tests
    these with `== "1" || == "true"`, so "0" happens to mean off, but a reader
    (or a future consumer that only checks for presence) would not know that. An
    absent key is off in one unambiguous way.
    """
    if not isinstance(updates, dict) or not updates:
        raise ValueError("no options supplied")
    unknown = [k for k in updates if k not in ENV_BY_KEY]
    if unknown:
        raise ValueError("option not honoured by the analyzer: " + ", ".join(sorted(unknown)))
    # After the allowlist and before any coercion: a key the analyzer reads but
    # one this file already owns is refused for the same reason an unknown key is
    # - writing it would put a line in the file that does not mean what it says.
    _refuse_shadowed(updates)
    # Belt and braces on top of the allowlist: a value that reads like a secret
    # has no business being written into a repo file from a browser form, even
    # if a future option slipped past the allowlist.
    for key in updates:
        if _is_secret(key):
            raise ValueError(f"'{key}' looks like a credential; set it in .env or the vault")

    prepared: dict[str, str | None] = {}
    for key, value in updates.items():
        spec = ENV_BY_KEY[key]
        if value is None:
            # An explicit null clears the key, whatever its kind. Only a flag
            # had a removal path before (its false), which left a stale
            # number-or-path line clearable by nothing but a text editor - and
            # cleanup is the one write this page must never refuse.
            prepared[key] = None
        elif spec["kind"] == "flag":
            if not isinstance(value, bool):
                raise ValueError(f"'{key}' must be true or false")
            prepared[key] = "1" if value else None
        elif spec["kind"] == "number":
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError(f"'{key}' must be a number")
            number = float(value)
            if not spec["min"] <= number <= spec["max"]:
                raise ValueError(f"'{key}' must be between {spec['min']:g} and {spec['max']:g}")
            # Written the way the binary parses it, and trimmed of a pointless
            # trailing ".0" so the file reads like the existing ones.
            text = f"{number:g}"
            prepared[key] = _quote(text)
        else:
            if not isinstance(value, str):
                raise ValueError(f"'{key}' must be a string")
            text = value.strip()
            if not text:
                raise ValueError(f"'{key}' must not be empty")
            prepared[key] = _quote(text)

    with _write_lock:
        # After coercion, and handed only the keys being set: clearing a line
        # that does not belong is the cleanup this check exists to provoke, so
        # it must pass.
        _refuse_global_only({k: v for k, v in prepared.items() if v is not None})
        path = _pipeline_path(pipeline)
        original, newline, bom = _read_text(path)
        lines = original.splitlines()

        span = _environment_span(lines)
        if span is None:
            # Appended, with a blank line first, so the block is a block and not
            # glued onto the last stage.
            while lines and not lines[-1].strip():
                lines.pop()
            lines.extend(["", "environment:"])

        for key, raw in prepared.items():
            if raw is None:
                _drop_key(lines, key, "  ")
            else:
                # Re-read the extent every time: each insert grows the block, so a
                # span captured before the loop goes stale after the first key.
                current = _environment_span(lines)
                _set_key(lines, key, raw, "  ", append_at=current[1] if current else None)

        # Re-derived after the edits, never cached from before them: an
        # `environment:` left with nothing under it is valid YAML that reads as a
        # mistake, and a stale extent is how the header gets deleted while its
        # keys stay behind as orphans.
        current = _environment_span(lines)
        if current is not None:
            start, end = current
            body = [l for l in lines[start + 1:end] if l.strip() and not l.lstrip().startswith("#")]
            if not body:
                del lines[start:end]

        text = newline.join(lines).rstrip() + newline
        _verify_pipeline(path.name, text)
        _atomic_write(path, text, newline, bom)

    return _resolve_entry(_pipeline(path), _catalog())


def set_yara_gen(pipeline: str, enabled: bool) -> dict:
    """Add or remove the `yara_gen` phase in a pipeline's phase lists.

    This is the writable form of the yarGen decision, and it edits the same
    inline `phases: [...]` lists - which means the wizard
    preview, the planner and this toggle cannot disagree about what the file
    says. It is deliberately a phase and not an `environment:` flag: the
    analyzer has no `YARA_GEN_SKIP`, because the phase not being in the list is
    already the whole mechanism.

    Where it goes, and why it is not simply appended: the phase is inserted
    immediately BEFORE `export` in the final stage. A rule file written after
    the artifact set is assembled is a rule file nobody receives, and the one
    thing worse than generating no rules is generating them and losing them in
    transit. When the last stage has no `export` - an unusual but legal shape -
    it is appended instead.

    Removal needs no undo marker: this deletes one known literal, so
    re-adding it is an exact reversal by construction.

    Block-style pipelines are refused with an explanation rather than rewritten
    blind. Guessing at the file's shape and saving the guess is how a config
    gets quietly damaged.
    """
    with _write_lock:
        path = _pipeline_path(pipeline)
        original, newline, bom = _read_text(path)
        lines = original.splitlines()
        out: list[str] = []
        targets = [i for i, line in enumerate(lines) if _PHASES_LINE.match(line)]

        if not targets:
            raise ValueError(
                "this pipeline has no inline 'phases: [...]' list to edit; add "
                "yara_gen to it by hand"
            )

        if enabled:
            if any(YARA_GEN_PHASE in lines[i] for i in targets):
                raise ValueError(
                    f"{pipeline} already selects {YARA_GEN_PHASE}")
            last = targets[-1]
            indent, inner, comment = _PHASES_LINE.match(lines[last]).groups()
            names = [n.strip() for n in inner.split(",") if n.strip()]
            # Before the first phase that finalises the run, so the .yar is part
            # of what gets written.
            at = next((i for i, n in enumerate(names)
                       if n in _BEFORE_YARA_GEN_STOP), len(names))
            names.insert(at, YARA_GEN_PHASE)
            suffix = f"  {comment}" if comment else ""
            out = list(lines)
            out[last] = f"{indent}phases: [{', '.join(names)}]{suffix}"
        else:
            edited: set[int] = set()
            for i in targets:
                indent, inner, comment = _PHASES_LINE.match(lines[i]).groups()
                if YARA_GEN_PHASE in [n.strip() for n in inner.split(",")]:
                    edited.add(i)
            if not edited:
                raise ValueError(
                    f"{pipeline} does not select {YARA_GEN_PHASE}, so there is "
                    f"nothing to remove"
                )
            out = []
            for i, line in enumerate(lines):
                if i in edited:
                    indent, inner, comment = _PHASES_LINE.match(line).groups()
                    names = [n.strip() for n in inner.split(",")
                             if n.strip() and n.strip() != YARA_GEN_PHASE]
                    suffix = f"  {comment}" if comment else ""
                    out.append(f"{indent}phases: [{', '.join(names)}]{suffix}")
                else:
                    out.append(line)

        text = newline.join(out).rstrip() + newline
        verified = _verify_pipeline(path.name, text)

        # Verified rather than assumed: a write that silently dropped the phase,
        # or left it after the export, would show the operator a toggle that
        # says "on" while the file says something else.
        present = YARA_GEN_PHASE in verified["phases"]
        if present != enabled:
            raise ValueError(
                f"the edit did not take effect ({YARA_GEN_PHASE} "
                f"{'missing from' if enabled else 'still in'} the pipeline); "
                f"nothing was written"
            )
        if enabled:
            order = verified["phases"]
            at = order.index(YARA_GEN_PHASE)
            if "export" in order and at > order.index("export"):
                raise ValueError(
                    f"{YARA_GEN_PHASE} would run after export, so its rule file "
                    f"would not be in the artifact set; nothing was written")

        _atomic_write(path, text, newline, bom)
        return _resolve_entry(_pipeline(path), _catalog())


def save_pipeline(name: str, content: str) -> dict:
    """Write a new pipeline file from the builder.

    Refuses to overwrite: an existing pipeline is someone's work, and a "save"
    that silently replaces it is how a tuned config disappears. Editing an
    existing file's options goes through write_environment(), which touches only
    the keys it was asked to touch.
    """
    if not isinstance(content, str) or not content.strip():
        raise ValueError("no content supplied")
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", name or ""):
        raise ValueError("name must be lowercase letters, digits, '-' or '_'")

    with _write_lock:
        path = PIPELINE_DIR / f"{name}.yaml"
        if path.exists():
            raise FileExistsError(f"pipelines/{name}.yaml already exists")
        if any(p.stem == name for p in PIPELINE_DIR.glob("*.json")):
            raise FileExistsError(f"a {name}.json pipeline already exists")
        _refuse_shadowed_document(content)
        _refuse_global_only_document(content)
        _verify_pipeline(path.name, content)
        _atomic_write(path, content if content.endswith("\n") else content + "\n")

    return _resolve_entry(_pipeline(path), _catalog())


def _refuse_global_only_document(text: str) -> None:
    """Refuse a new pipeline file that carries a phase-scoped setting.

    The document-level twin of _refuse_global_only, for the same reason
    _refuse_shadowed_document exists beside _refuse_shadowed: the wizard writes
    a whole file, so every environment key in it is one the author just
    introduced, and without this gate the edit route's refusal would be an
    invitation to bake the same line in through the builder instead.
    """
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError:
        return  # _verify_pipeline reports the parse failure with a better message
    if not isinstance(doc, dict):
        return
    env = doc.get("environment")
    if not isinstance(env, dict):
        return
    _refuse_global_only(sorted(str(k) for k in env if str(k) in ENV_BY_KEY))


def _pipeline_path(name: str):
    """Resolve a pipeline name to a file inside pipelines/, or refuse.

    The name comes from a request, so it is matched against the directory rather
    than joined onto it: a `../` would otherwise let a write land anywhere the
    panel can write.
    """
    if not isinstance(name, str) or not name:
        raise ValueError("no pipeline named")
    stem = name[:-5] if name.endswith(".yaml") else name
    for suffix in (".yaml", ".yml", ".json"):
        candidate = PIPELINE_DIR / f"{stem}{suffix}"
        if candidate.is_file() and candidate.parent == PIPELINE_DIR:
            return candidate
    raise ValueError(f"no pipeline named '{name}' in {PIPELINE_DIR.name}/")


def _verify_pipeline(label: str, text: str, expect_phases: list[str] | None = None) -> dict:
    """Parse the edited text and confirm it is a pipeline the analyzer accepts.

    The check is the analyzer's own rules, run on the text about to be written:
    a phase name that is not in the catalog, a document that will not parse, or a
    config with no phases at all is refused here rather than written and
    discovered on the next run.
    """
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ValueError(f"the edit would produce invalid YAML: {exc}") from exc
    if doc is None:
        raise ValueError("the edit would produce an empty pipeline")
    if not isinstance(doc, dict):
        raise ValueError("a pipeline config must be a mapping")

    declared: list[str] = []
    stages = doc.get("stages")
    if isinstance(stages, list):
        for stage in stages:
            if isinstance(stage, dict):
                declared.extend(_phase_list(stage.get("phases")))
    else:
        declared.extend(_phase_list(doc.get("phases")))
    if not declared:
        raise ValueError("a pipeline needs at least one phase")

    catalog = _catalog()
    if catalog["available"]:
        unknown = [p for p in declared if p not in catalog["requires"]]
        if unknown:
            raise ValueError("phase not in the analyzer's catalog: " + ", ".join(unknown))
    if expect_phases is not None and declared != expect_phases:
        raise ValueError("the edit did not produce the phases intended")

    return {"name": str(doc.get("name") or ""), "phases": declared}