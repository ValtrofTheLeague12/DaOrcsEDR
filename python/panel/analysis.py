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
import threading
import time
import urllib.request

import yaml

from . import config, yamlview

PIPELINE_DIR = config.REPO / "pipelines"
ARTIFACTS_FILE = config.REPO / "config" / "artifacts.yaml"
UPLOADER_SCRIPT = config.REPO / "mega" / "upload.py"

# Keys planner::load_artifact_options() accepts. It rejects everything else, so a
# stray key is a hard error at startup and is reported here as one rather than
# quietly ignored the way a permissive parser would.
ARTIFACT_KEYS = ("store_artifact", "upload_artifacts", "remote_root", "timeout_seconds",
                 "encrypt_artifacts", "encryption_recipient", "admin_public_key")

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
]

ENV_BY_KEY = {o["key"]: o for o in ENV_OPTIONS}

# ---------------------------------------------------------------------------
# Phase rush.
#
# "Rush" is triage: run the cheap local phases, drop the ones that dominate wall
# clock on a shared research box. The list is a judgement call, so each entry
# says why - an unexplained list would become folklore.
#
#   radare2, graphs, xref   disassembly, call graphs and cross-references; the
#                           single biggest cost of a run, and useless for a
#                           first look at a file
#   capa                    rule matching over every section; minutes on a large
#                           PE, and a triage answer rarely needs it
#   cminer                  function-name inference by ML; wants `extraction`
#   recovery                carve-and-recover pass, same input as cminer
#   hexdump                 dumps blobs; only useful once something was carved
#   cti                     internet lookups: slow, rate-limited, and the thing
#                           most likely to be unwanted on an isolated network
#   model                   EMBER2024 scoring, which starts a local service
#
# `extraction` is deliberately KEPT even though it only feeds the dropped phases:
# it is fast, it is what produces the carved blob inventory, and dropping it
# would silently change the report for every run that did not ask for rush.
# ---------------------------------------------------------------------------
SLOW_PHASES = ("radare2", "graphs", "xref", "capa", "cminer", "recovery",
               "hexdump", "cti", "model")

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


def _pipeline(path) -> dict:
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
        "phase_check": "unavailable",
        # True when a previous phase-rush trimmed this pipeline. Read from the
        # marker in the file rather than inferred from the phase set, because
        # "no slow phases" and "rushed" are not the same claim: a pipeline
        # authored as triage was never trimmed.
        "rushed": False,
        # When the file itself last changed. Not the same as when this page read
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
    entry["rushed"] = bool(_rush_markers(content))

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
                })
    return entry


def _resolve_entry(entry: dict, catalog: dict) -> dict:
    """Fill in the fields that depend on the catalog, in place.

    Shared with the write routes so a save and a read return the same shape. A
    POST that answered with a thinner object than the GET would leave a client
    reading `pipeline.rushed` or `pipeline.resolved` as undefined - which is the
    kind of difference that only shows up as a blank panel later.
    """
    requires = catalog["requires"]
    if catalog["available"]:
        unknown = [p for p in entry["phases"] if p not in requires]
        entry["unknown_phases"] = unknown
        entry["phase_check"] = "ok" if not unknown else "unknown"
        if unknown and entry["ok"]:
            entry["ok"] = False
            entry["error"] = "phase not in the analyzer's catalog: " + ", ".join(unknown)
    resolved, inserted = _resolve(entry["phases"], requires)
    entry["resolved"] = resolved
    entry["inserted"] = inserted
    return entry


def _pipelines(catalog: dict) -> list[dict]:
    entries: list[dict] = []
    try:
        files = sorted(
            p for p in PIPELINE_DIR.iterdir()
            if p.is_file() and p.suffix.lower() in (".yaml", ".yml", ".json")
        )
    except OSError:
        files = []

    seen: set[str] = set()
    for path in files:
        entry = _pipeline(path)
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


def _artifacts() -> dict:
    out = {
        "present": False,
        "file": _rel(ARTIFACTS_FILE),
        "store_artifact": False,
        "upload_artifacts": False,
        "remote_root": "",
        "timeout_seconds": 900,
        "encrypt_artifacts": False,
        "encryption_recipient": "user",
        "admin_public_key": "",
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
        if key == "encryption_recipient":
            # Refused here for the same reason the planner refuses it: a value
            # that only fails once an upload is halfway through is worse than
            # one that never saves.
            if value not in ("user", "admin"):
                out["errors"].append("'encryption_recipient' must be 'user' or 'admin'")
                continue
            out["encryption_recipient"] = value
            continue
        if key == "admin_public_key":
            # Empty is legal and means "use the default location", so this is
            # the one string option that is allowed to be blank.
            if not isinstance(value, str):
                out["errors"].append("'admin_public_key' must be a path")
                continue
            out["admin_public_key"] = value.strip()

    if out["admin_public_key"] and not out["encrypt_artifacts"]:
        # Not an error - the two options are independent - but the combination
        # looks configured while doing nothing, so it is surfaced.
        out["errors"].append(
            "'admin_public_key' is set but 'encrypt_artifacts' is false, "
            "so bundles will NOT be sealed")

    out["uploader_script"] = _rel(UPLOADER_SCRIPT) if UPLOADER_SCRIPT.is_file() else ""
    return out


# ---------------------------------------------------------------------------
# Public snapshot
# ---------------------------------------------------------------------------


def snapshot() -> dict:
    catalog = _catalog()
    pipelines = _pipelines(catalog)
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
       "encryption_recipient": artifacts["encryption_recipient"],
       "admin_public_key": artifacts["admin_public_key"],
        "options": ENV_OPTIONS,
        "rush": {
            "phases": list(SLOW_PHASES),
            # Which pipelines carry a rush marker, so the toggle shows the real
            # state of the file rather than guessing it from the phase list.
            "active": [p["name"] for p in pipelines if p["rushed"]],
        },
        "checked_at": round(time.time(), 1),
    }


def _is_rush(phases: list[str]) -> bool:
    """Whether a pipeline already drops every slow phase.

    Needs at least one phase: a pipeline with an empty list is broken, and
    calling that "rushing" would report a broken config as a configured one.
    """
    return bool(phases) and not [p for p in SLOW_PHASES if p in phases]


def artifact_upload_enabled() -> bool:
    """Whether config/artifacts.yaml currently asks for a MEGA upload.

    Read through the same parser the page uses, so the Export button's gate and
    the toggle the operator just flipped cannot disagree.
    """
    return bool(_artifacts()["upload_artifacts"])


def artifact_upload_timeout() -> int:
    """The uploader's own timeout budget, so a manual export obeys the same
    ceiling an analyzer run would."""
    return int(_artifacts()["timeout_seconds"])


def artifact_encrypt_enabled() -> bool:
    """Whether a bundle must be sealed to a public key before it is uploaded.

    Read through the same parser as the upload toggle, so the button and the
    analyzer can never disagree about whether evidence leaves the host in the
    clear.
    """
    return bool(_artifacts().get("encrypt_artifacts"))


def artifact_encryption_recipient() -> str:
    """'user' (this machine's operator key) or 'admin' (the lab's public key)."""
    return str(_artifacts().get("encryption_recipient") or "user")


def artifact_admin_public_key() -> str:
    """Configured admin public key path, or '' to use the default location."""
    return str(_artifacts().get("admin_public_key") or "")


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

    prepared: dict[str, str] = {}
    for key, value in patch.items():
        if key in ("store_artifact", "upload_artifacts", "encrypt_artifacts"):
            if not isinstance(value, bool):
                raise ValueError(f"'{key}' must be true or false")
            prepared[key] = "true" if value else "false"
        elif key == "encryption_recipient":
            if value not in ("user", "admin"):
                raise ValueError("'encryption_recipient' must be 'user' or 'admin'")
            prepared[key] = _quote(value)
        elif key == "admin_public_key":
            # Empty is legal: it means "use the default location". Anything
            # else is a local path, so the same traversal guard the remote root
            # gets applies here.
            if not isinstance(value, str):
                raise ValueError("'admin_public_key' must be a path")
            path_text = value.strip()
            if path_text and ("\\" in path_text
                              or any(part == ".." for part in path_text.replace("\\", "/").split("/"))):
                raise ValueError("'admin_public_key' must not contain '..'")
            prepared[key] = _quote(path_text)
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
    # Belt and braces on top of the allowlist: a value that reads like a secret
    # has no business being written into a repo file from a browser form, even
    # if a future option slipped past the allowlist.
    for key in updates:
        if _is_secret(key):
            raise ValueError(f"'{key}' looks like a credential; set it in .env or the vault")

    prepared: dict[str, str | None] = {}
    for key, value in updates.items():
        spec = ENV_BY_KEY[key]
        if spec["kind"] == "flag":
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


_RUSH_MARKER = re.compile(r"^(\s*)#\s*phase-rush:\s*\[(.*?)\]\s*$")
_PHASES_LINE = re.compile(r"^(\s*)phases:\s*\[(.*?)\]\s*(#.*)?$")


def _rush_markers(text: str) -> list[list[str]]:
    """The phase lists a previous rush trimmed, as recorded in the file."""
    return [[n.strip() for n in m.group(2).split(",") if n.strip()]
            for m in (_RUSH_MARKER.match(l) for l in text.splitlines()) if m]


def set_rush(pipeline: str, enabled: bool) -> dict:
    """Add or remove the triage profile in a pipeline's phase lists.

    Reversible, and reversibility is why this leaves a marker behind:

        stages:
          - name: threat-intel
            # phase-rush: [cti]
            phases: []

    The original list is recorded as a comment directly above the trimmed one,
    so turning rush back off restores exactly what was there - no guessing at
    which stage a phase belonged to, and no needing the panel to remember
    something the file should know. The marker is also what makes the edit
    legible to a human reading the YAML later: an empty stage with a comment
    naming what it dropped explains itself, a mysteriously empty stage does not.

    Only inline `phases: [...]` lists are touched. A pipeline written with
    block-style lists is refused with an explanation rather than rewritten blind,
    because guessing at its shape and saving the guess is how a config gets
    quietly damaged.
    """
    with _write_lock:
        path = _pipeline_path(pipeline)
        original, newline, bom = _read_text(path)
        lines = original.splitlines()
        out: list[str] = []
        restored: list[list[str]] = []
        trimmed: list[list[str]] = []

        i = 0
        while i < len(lines):
            marker = _RUSH_MARKER.match(lines[i])
            phases = _PHASES_LINE.match(lines[i])
            next_is_phases = i + 1 < len(lines) and _PHASES_LINE.match(lines[i + 1])

            if marker and next_is_phases:
                # A marker with no list under it is a half-edited file. Leaving
                # it alone is right: it says a rush was applied, and the operator
                # should see it, not have the panel tidy it away silently.
                out.append(lines[i])
                i += 1
                continue

            if enabled and phases:
                indent, inner, comment = phases.groups()
                names = [n.strip() for n in inner.split(",") if n.strip()]
                kept = [n for n in names if n not in SLOW_PHASES]
                if len(kept) != len(names):
                    if out and _RUSH_MARKER.match(out[-1]):
                        # Already trimmed on a previous apply; the marker holds
                        # the fuller original, so leave it exactly as it is.
                        out.append(lines[i])
                        i += 1
                        continue
                    suffix = f"  {comment}" if comment else ""
                    out.append(f"{indent}# phase-rush: [{', '.join(names)}]")
                    out.append(f"{indent}phases: [{', '.join(kept)}]{suffix}")
                    trimmed.append(names)
                    i += 1
                    continue

            if not enabled and phases and i > 0 and _RUSH_MARKER.match(lines[i - 1]):
                indent, _, comment = phases.groups()
                recorded = [n.strip() for n in _RUSH_MARKER.match(lines[i - 1]).group(2).split(",") if n.strip()]
                suffix = f"  {comment}" if comment else ""
                # The marker line is replaced by the list it described, which is
                # what makes the restore a true undo rather than an append.
                out[-1] = f"{indent}phases: [{', '.join(recorded)}]{suffix}"
                restored.append(recorded)
                i += 1
                continue

            out.append(lines[i])
            i += 1

        if enabled and not trimmed:
            if any(_RUSH_MARKER.match(l) for l in lines):
                raise ValueError("phase rush is already applied to this pipeline")
            raise ValueError(
                "this pipeline selects none of the slow phases, so phase rush "
                "has nothing to remove"
            )
        if not enabled and not restored:
            raise ValueError("this pipeline has no phase-rush marker to restore")

        text = newline.join(out).rstrip() + newline
        verified = _verify_pipeline(path.name, text)

        if enabled:
            if not _is_rush(verified["phases"]):
                raise ValueError("rush left slow phases in the pipeline; nothing was written")
        else:
            # A restore that came back with something other than what the marker
            # recorded is a bug, not a success: the operator would believe the
            # original pipeline is back and it would not be.
            recorded = [p for group in restored for p in group]
            missing = [p for p in recorded if p not in verified["phases"]]
            if missing:
                raise ValueError(
                    "restore did not bring back " + ", ".join(missing) + "; nothing was written")

        _atomic_write(path, text, newline, bom)
        return _resolve_entry(_pipeline(path), _catalog())


def set_yara_gen(pipeline: str, enabled: bool) -> dict:
    """Add or remove the `yara_gen` phase in a pipeline's phase lists.

    This is the writable form of the yarGen decision, and it edits the same
    inline `phases: [...]` lists as set_rush() does - which means the wizard
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

    Removal needs no undo marker, unlike phase rush. Rush trims an unknown set
    of phases and records what it took; this deletes one known literal, so
    re-adding it is an exact reversal by construction.

    Block-style pipelines are refused with an explanation rather than rewritten
    blind, for the same reason rush refuses them: guessing at the file's shape
    and saving the guess is how a config gets quietly damaged.
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
        _verify_pipeline(path.name, content)
        _atomic_write(path, content if content.endswith("\n") else content + "\n")

    return _resolve_entry(_pipeline(path), _catalog())


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