"""Sample paths: validation and metadata, in one place.

The Build page's sample picker offers listed files, but these rules still stand
between a browser and `static_analyzer.exe <whatever was chosen>`: an uploaded
name, a factory-generated path and a stale listing all reach the same gate. Two
rules carry the weight:

  * the name must be an allowed executable extension (config.ALLOWED_SAMPLE_EXT);
  * the RESOLVED path must stay inside the repo's sample roots
    (config.SAMPLE_ROOTS). resolve() runs first, so "..", symlinks and drive
    tricks collapse to a real path before the containment check instead of
    being string-matched after it - the same defense admin_server._serve_spa
    uses to keep a crafted URL inside admin-web/dist.

Everything else is Win32 hygiene: no control characters, no NTFS alternate
data streams, no trailing dots or spaces (Win32 silently strips them before
opening, so "evil.exe." would open the un-validated "evil.exe"), no reserved
device names.

The run gate (pipeline_run.start) and the picker's inspect endpoint both call
`resolve`/`meta` here, so the two can never refuse different things - a path
the page shows as valid is a path the gate will accept.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from pathlib import Path

from ..analysis import analysis_settings
from ..build import pe_tools
from ..clamd import clamd
from ..core import config

log = logging.getLogger("panel.samples")

# The analyzer's own mid-run packed tripwire. Reported, never written: the
# panel gate stops a packed run BEFORE the spawn, this key stops it INSIDE the
# analyzer at the histogram phase, and an operator overriding the panel gate
# has the right to know the analyzer will overrule them mid-run.
PACKED_STOP_KEY = "IA_INTERRUPT_IF_PACKED"

# Win32 maps these to devices whatever the extension is, so "samples/CON.exe"
# is not a file an operator can meaningfully analyse - it cannot even be opened
# for writing, which is a confusing way for a generate-then-run to fail.
_WINDOWS_RESERVED = frozenset(
    {"CON", "PRN", "AUX", "NUL",
     *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))})


def _relative(path: str | Path) -> str:
    """A repo-relative path with '/' separators.

    The API is consumed by the browser, where forward slashes are the stable
    spelling on every host and a select's value compares literally. The run
    gate re-resolves whatever it is given, so this is presentation only.
    """
    return os.path.relpath(path, config.REPO).replace(os.sep, "/")


def _check_name(name: str) -> str | None:
    """The name-only rules, shared by resolve() and the upload path.

    Order matters: the dot/space rule comes before the extension rule because
    pathlib reads "new.exe." as suffix ".", so the extension check would fire
    first with a sentence about dots that misdiagnoses the real problem.
    """
    if name != name.rstrip(". "):
        return "the file name may not end in a dot or a space"
    if Path(name).suffix.lower() not in config.ALLOWED_SAMPLE_EXT:
        allowed = ", ".join(sorted(config.ALLOWED_SAMPLE_EXT))
        return (f"'{Path(name).suffix or name}' is not an allowed executable "
                f"extension ({allowed})")
    if Path(name).stem.upper() in _WINDOWS_RESERVED:
        return f"'{Path(name).stem}' is a reserved Windows device name"
    return None


def resolve(sample: str) -> tuple[str | None, str | None]:
    """(absolute path, None) when the sample may be analysed; (None, reason).

    Returns the RESOLVED path rather than the typed one: what the analyzer is
    handed should be the file that was actually validated, not the string that
    named it.
    """
    if not sample or not sample.strip():
        return None, "no sample given - a pipeline run analyzes a file on disk"
    if sample.strip().startswith("--"):
        return None, f"'{sample}' looks like an option, not a sample path"
    if any(ord(c) < 32 for c in sample):
        return None, "control characters are not allowed in a sample path"
    if ":" in sample[2:]:
        # "x.exe:stream" is an NTFS alternate data stream and "C:foo" is
        # drive-relative; neither can be what an operator meant to type, and
        # the stream would be opened by anything that took the string as-is.
        return None, ("alternate data streams and drive-relative paths "
                      "are not allowed")
    if ".." in Path(sample).parts:
        return None, "a sample path may not contain '..' segments"

    p = Path(os.path.expanduser(sample))
    if why := _check_name(p.name):
        return None, why

    resolved = ((config.REPO / p).resolve() if not p.is_absolute()
                else p.resolve())
    roots = [(config.REPO / r).resolve() for r in config.SAMPLE_ROOTS]
    if not any(resolved.is_relative_to(r) for r in roots):
        return None, ("the sample must resolve inside the repo's sample roots "
                      f"({', '.join(config.SAMPLE_ROOTS)})")
    if not resolved.is_file():
        return None, f"sample not found: {resolved}"
    return str(resolved), None


def analyzer_packed_stop() -> dict:
    """What the ANALYZER will do to a packed run, per config/analysis.yaml.

    IA_INTERRUPT_IF_PACKED is the analyzer's own tripwire: on, it aborts the
    run at the histogram phase and prints the entropy facts (with the run
    resumable via --resume); off - the shipped default - a packed run goes
    through to the end. The panel reports this state so that overriding the
    PANEL gate is an informed decision: with the analyzer flag on, an
    overridden run still dies mid-flight. "Not set" is reported honestly: the
    pipeline's `environment:` block and then the binary default (off) decide.
    """
    return analysis_settings.flag_enabled(config.REPO, PACKED_STOP_KEY)


def meta(sample: str) -> dict:
    """Validate a typed path and describe the file it names.

    `ok: False` carries the refusal sentence. `ok: True` carries what the
    picker and the run card need: the resolved path, size, mtime, the packed
    verdict the run gate enforces (pe_tools.pack_verdict), and the state of
    the analyzer's own packed stop so the page can say what an override would
    run into.
    """
    path, why = resolve(sample)
    if why is not None:
        return {"ok": False, "error": why}
    st = os.stat(path)
    return {"ok": True,
            "path": path,
            "relative": _relative(path),
            "bytes": st.st_size,
            "modified": round(st.st_mtime, 1),
            "packed": pe_tools.pack_verdict(Path(path)),
            "analyzer_packed_stop": analyzer_packed_stop()}


def list_samples(limit: int = 200) -> dict:
    """The analysable files directly under the sample roots, newest first.

    Direct children only: recursing would pull in exported extraction trees,
    upload staging and quarantine, none of which are samples an operator means
    to run from the picker.

    Metadata ONLY - no packed verdicts: pack_verdict reads each file whole,
    and the combo box inspects the one file the operator picks (meta(), which
    the page already calls, debounced). The listing is a convenience and
    never the authority: a file deleted after it was listed is caught by
    inspect and again by the run gate, both of which re-check the disk.
    """
    entries = []
    for root in config.SAMPLE_ROOTS:
        directory = config.REPO / root
        if not directory.is_dir():
            continue
        try:
            children = list(directory.iterdir())
        except OSError:
            continue
        for f in children:
            if (not f.is_file()
                    or f.suffix.lower() not in config.ALLOWED_SAMPLE_EXT):
                continue
            try:
                st = f.stat()
            except OSError:
                continue
            entries.append({"name": f.name,
                            "relative": _relative(f),
                            "bytes": st.st_size,
                            "modified": round(st.st_mtime, 1)})
    entries.sort(key=lambda e: e["modified"], reverse=True)
    return {"ok": True, "files": entries[:limit],
            "upload_max_bytes": config.SAMPLE_UPLOAD_MAX_BYTES}


# ---------------------------------------------------------------------------
# The upload manifest.
#
# sample_factory._prune keeps samples/ at SAMPLE_KEEP factory outputs; an
# upload is not factory output but an operator's own file, chosen and dropped
# here - deleting it because someone generated a thirteenth bait would be the
# prune eating evidence it was never meant to touch. The manifest is the
# record of which files are which. It is a cache of intent, not a security
# boundary: every path in it is re-validated by resolve() like any other.
# ---------------------------------------------------------------------------
def _manifest_path() -> Path:
    return config.REPO / "samples" / ".manifest.json"


def _manifest() -> dict:
    try:
        data = json.loads(_manifest_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def protected_paths() -> set[str]:
    """Absolute paths of uploaded samples, for sample_factory._prune.

    A missing or unreadable manifest means nothing is protected - reported as
    an empty set rather than guessed at, because the prune's job is to bound
    FACTORY output and it can only spare what it can name.
    """
    return {str((config.REPO / rel).resolve())
            for rel in _manifest().get("uploads", {})}


def _manifest_add(relative: str, sha256: str, size: int) -> None:
    manifest = _manifest()
    uploads = manifest.get("uploads") if isinstance(manifest.get("uploads"),
                                                    dict) else {}
    # Stale entries are pruned on write: a manifest that only ever grows
    # becomes a list of files that stopped existing.
    uploads = {rel: info for rel, info in uploads.items()
               if (config.REPO / rel).is_file()}
    uploads[relative] = {"sha256": sha256, "bytes": size,
                         "at": round(time.time(), 1)}
    manifest["uploads"] = uploads
    path = _manifest_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")


def save_upload(filename: str, stream, allow_unscanned: bool = False) -> dict:
    """Stage, scan and admit an operator-uploaded executable.

    The pipeline, in order, each step able to refuse with a machine-readable
    code the page switches on: the client's file name is only ever a NAME
    (separators refused outright, then the shared name rules); the body is
    streamed to staging under SAMPLE_UPLOAD_DIR with the size cap enforced
    mid-write and the sha256 computed as it goes - never get_data() whole;
    clamdscan decides clean / infected / unavailable; infected moves to
    samples/_quarantine/ as evidence and is refused; an unreachable scanner
    refuses by default, and allow_unscanned is the explicit, logged way past
    it; the name existing already refuses rather than overwrites. Only a file
    that survives every step lands in samples/, where the picker offers it.
    """
    raw = (filename or "").strip()
    if not raw:
        return {"ok": False, "code": "bad-name", "error": "no file name"}
    if any(c in raw for c in "/\\:") or ".." in raw:
        return {"ok": False, "code": "bad-name",
                "error": "the upload's file name may not contain a path"}
    if why := _check_name(raw):
        code = "bad-extension" if "extension" in why else "bad-name"
        return {"ok": False, "code": code, "error": why}

    final = config.REPO / "samples" / raw
    if final.exists():
        return {"ok": False, "code": "exists",
                "error": f"samples/{raw} already exists",
                "detail": "rename the file and upload again - the panel "
                          "never overwrites a sample that is already there"}

    staging = config.REPO / config.SAMPLE_UPLOAD_DIR
    try:
        staging.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        return {"ok": False, "code": "staging-failed",
                "error": f"could not create the staging dir: {exc}"}

    tmp = staging / f"{int(time.time())}-{os.getpid()}{Path(raw).suffix.lower()}"
    digest = hashlib.sha256()
    total = 0
    moved = False
    try:
        with open(tmp, "wb") as out:
            while True:
                chunk = stream.read(1 << 16)
                if not chunk:
                    break
                total += len(chunk)
                if total > config.SAMPLE_UPLOAD_MAX_BYTES:
                    mib = config.SAMPLE_UPLOAD_MAX_BYTES / (1024 * 1024)
                    return {"ok": False, "code": "too-large",
                            "error": f"{raw} exceeds the {mib:g} MB upload limit"}
                digest.update(chunk)
                out.write(chunk)
            out.flush()
            os.fsync(out.fileno())

        sha = digest.hexdigest()
        scan = clamd.scan_file(tmp)

        if scan["verdict"] == "infected":
            quarantine = config.REPO / "samples" / "_quarantine"
            quarantine.mkdir(parents=True, exist_ok=True)
            keep = quarantine / f"{int(time.time())}-{raw}"
            os.replace(tmp, keep)
            moved = True
            log.warning("refused infected upload %s (%s) - kept as evidence "
                        "in %s", raw, scan.get("signature"),
                        os.path.relpath(keep, config.REPO))
            return {"ok": False, "code": "scan-infected",
                    "error": f"{raw} is infected: "
                             f"{scan.get('signature') or 'signature withheld'}",
                    "detail": f"kept as evidence in "
                              f"{os.path.relpath(keep, config.REPO)}",
                    "scan": scan}

        if scan["verdict"] == "unavailable" and not allow_unscanned:
            log.warning("refused unscanned upload %s: %s", raw,
                        scan.get("error") or "scanner unreachable")
            return {"ok": False, "code": "scan-unavailable",
                    "error": "the scanner is not reachable",
                    "detail": "upload rejected by policy - retry when clamd "
                              "is up, or admit it explicitly without a scan",
                    "scan": scan}

        final.parent.mkdir(parents=True, exist_ok=True)
        os.replace(tmp, final)
        moved = True
        if allow_unscanned and scan["verdict"] == "unavailable":
            # The one path a file enters without a scan, and it is a person's
            # decision - said loudly enough to grep for after the fact.
            log.warning("UPLOAD ADMITTED WITHOUT SCAN: %s (%s bytes)",
                        final, total)
        try:
            _manifest_add(
                os.path.relpath(final, config.REPO).replace(os.sep, "/"),
                sha, total)
        except OSError as exc:
            # The file IS admitted at this point; a manifest that cannot be
            # written costs prune-protection, not the upload itself.
            log.warning("could not record %s in the manifest: %s", raw, exc)
        st = os.stat(final)
        return {"ok": True,
                "file": {"name": raw,
                         "relative": _relative(final),
                         "bytes": st.st_size,
                         "modified": round(st.st_mtime, 1)},
                "sha256": sha, "scan": scan}
    except OSError as exc:
        log.warning("upload of %s failed: %s", raw, exc)
        return {"ok": False, "code": "staging-failed",
                "error": f"could not stage the upload: {exc}"}
    finally:
        if not moved:
            tmp.unlink(missing_ok=True)
