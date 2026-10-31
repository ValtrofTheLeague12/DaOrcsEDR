# Pipeline-Run Hardening Plan — Build page & Analysis Configuration page

Scope: the four issues named for the admin console —
**(1)** packed-sample execution gate, **(2)** trace.txt lifecycle, **(3)** manual executable
name validation, **(4)** executable picker + upload in "Run a pipeline".
Pages affected: **Build** (`admin-web/src/panels/Build.tsx`) and **Analysis Configuration**
(`admin-web/src/panels/AnalysisConfig.tsx`). Backend: `python/panel/`.

---

## 1. Current state (verified)

| Fact | Where |
|---|---|
| Run a pipeline takes a free-text sample path; the only server validation is "not empty" and "does not start with `--`" | `pipeline_run.py:151-165` (`_validate_sample`, `_resolve_sample`) |
| The run executes `static_analyzer.exe --no-curses --pipeline <name> <sample>` with no packed check | `pipeline_run.py:273` |
| Sample factory can UPX-pack a generated sample and reports `packed: {before, after, ratio}` | `sample_factory.py:737-753`, `generate()` return `:767-785` |
| `onGenerated` only lands the packed exe path into the run card's text box — nothing warns or blocks | `Build.tsx:1449`, `SampleFactory.tsx:295` |
| The analyzer's own packed tripwire is entropy-based, opt-in and **off** in the shipped config | `phase_extract.cpp:250-282`, `config/analysis.yaml:51` (`IA_INTERRUPT_IF_PACKED: false`) |
| No packer detection exists in the panel; `pe_tools.py` parses PE sections already (`_pe_layout`) | `pe_tools.py:51-101` |
| No sample-listing endpoint; `samples/` is only pruned (12 newest) | `sample_factory.py:864-876` (`SAMPLE_KEEP`) |
| `trace.txt` written by the C++ trace layer, hard-gated by `ENABLE_TRACING` (unset ⇒ on) | `src/core/trace.cpp:22-61, 443-449` |
| `ENABLE_TRACING` (default true) and `TRACE_FILE` already exist as explicit config keys + panel toggles | `analysis.py:155-172`, `config/analysis.yaml:49`, AnalysisConfig "Behaviour" card |
| trace.txt is unbounded (~80 MB on disk, 512 MB mmap pre-size), never rotated; a stale file survives after tracing is disabled | `trace.cpp:151-157`, `python/panel/host/trace.py:22` |
| No upload endpoint in the panel; `UPLOAD_DIR`/`UPLOAD_MAX_BYTES` are dead constants | `config.py:106-109` |
| ClamAV scanning only ever happens inside the VM; the panel reads result JSONs, there is no `scan_file` helper | `python/panel/clamd/clamd.py`, `python/clamd/clamd-python.py` |
| Auth: one shared token + HMAC cookie, `before_request` gate over all `/api/*`, no roles | `auth.py`, `app.py:119-147` |

---

## 2. Priorities and effort

| # | Task | Priority | Effort |
|---|---|---|---|
| T2 | Sample path/name validation (backend + inline UI messages) | P0 | 1.0 d |
| T1 | Packed gate: detect, refuse, UI state, override interlock | P0 | 2.0 d |
| T3 | Executable picker (combo box) populated from `samples/` | P1 | 1.5 d |
| T4 | Executable upload: limits, clamd scan, checksum, quarantine | P1 | 3.0 d |
| T5 | trace.txt lifecycle: status, archive, observability | P2 | 1.5 d |
| T6 | Selection persistence (sample + pipeline) | P2 | 0.5 d |
| — | Contingency (clamd availability on Windows host, QA) | — | 1.0 d |
| | **Total** | | **≈ 10.5 dev-days** |

Recommended implementation order: **T2 → T1 → T3 → T4 → T5 → T6** — validation first,
because the picker, the upload and the packed gate all lean on it.

---

## 3. T2 — Manual executable name validation (P0, 1 d)

### Backend

New module-private rules in `python/panel/pipeline/pipeline_run.py` (or a small shared
`python/panel/samples/samples.py` that T3/T4 also import). Constants in `config.py`:

```python
# config.py
SAMPLE_ROOTS = ("samples", "tests/fixtures", "exports")  # relative to REPO
ALLOWED_SAMPLE_EXT = {".exe", ".dll", ".bin", ".sys"}
```

```python
# pipeline_run.py — replaces the body of _validate_sample; returns (meta, None) or (None, reason)
import ntpath
from pathlib import Path

def _validate_sample(sample: str) -> tuple[Path | None, str | None]:
    if not sample or not sample.strip():
        return None, "no sample given - a pipeline run analyzes a file on disk"
    if sample.strip().startswith("--"):
        return None, f"'{sample}' looks like an option, not a sample path"
    if any(ord(c) < 32 for c in sample):
        return None, "control characters are not allowed in a path"
    if ":" in sample[2:]:                      # NTFS ADS: "x.exe:stream"; also "C:x" drive-relative
        return None, "alternate data streams and drive-relative paths are not allowed"
    if ".." in Path(sample).parts:
        return None, "a sample path may not contain '..' segments"

    p = Path(os.path.expanduser(sample))
    if p.suffix.lower() not in config.ALLOWED_SAMPLE_EXT:
        allowed = ", ".join(sorted(config.ALLOWED_SAMPLE_EXT))
        return None, f"'{p.suffix or p.name}' is not an allowed executable extension ({allowed})"

    # Win32 silently strips trailing dots/spaces: "evil.exe." opens "evil.exe".
    if p.name != p.name.rstrip(". "):
        return None, "the file name may not end in a dot or space"
    if p.stem.upper() in {"CON","PRN","AUX","NUL",*(f"COM{i}" for i in range(1,10)),*(f"LPT{i}" for i in range(1,10))}:
        return None, "that is a reserved Windows device name"

    resolved = (config.REPO / p).resolve() if not p.is_absolute() else p.resolve()
    roots = [(config.REPO / r).resolve() for r in config.SAMPLE_ROOTS]
    if not any(resolved.is_relative_to(r) for r in roots):
        roots_fmt = ", ".join(config.SAMPLE_ROOTS)
        return None, f"the sample must resolve inside the repo's sample roots ({roots_fmt})"
    if not resolved.is_file():
        return None, f"sample not found: {resolved}"
    return resolved, None
```

Notes:
- `Path.resolve()` collapses `..` and resolves symlinks **before** the
  `is_relative_to` check — this is the same defense `_serve_spa` already uses for
  `admin-web/dist` (`admin_server.py:46`).
- Absolute paths remain allowed, but only when they land inside the roots —
  a documented behaviour narrowing (see §7).
- The existing `isfile` check in `start()` (`pipeline_run.py:266-270`) folds in here.

### Front end (`Build.tsx`, PipelineRunCard)

Mirror the rules client-side for instant feedback; the server remains the authority.
The Run button disables on `!sampleMeta.ok` and the reason becomes the button title.

Validation message copy (identical rules, human phrasing):

| Rule | Message under the field |
|---|---|
| empty | (no message — Run stays disabled, title "Give the sample a path") |
| `..` | "A sample path may not contain `..` segments." |
| extension | "Allowed executable extensions: .exe, .dll, .bin, .sys." |
| outside roots | "Must resolve inside samples/, tests/fixtures/ or exports/." |
| ADS / trailing dot / reserved | "That file name is not valid on Windows." |
| not found | "No such file — upload one, or generate it in Sample generation." |

### Acceptance criteria
- G1: `POST /api/pipeline-run` with `sample: "../../x.exe"` → 400, message names `..`.
- G2: `sample: "C:\\Windows\\System32\\notepad.exe"` → 400 (outside roots).
- G3: `sample: "samples/x.txt"` → 400 naming allowed extensions.
- G4: `sample: "samples\\\\evil.exe:stream"` → 400.
- G5: `sample: "samples/new.exe."` → 400.
- G6: valid `samples/x.exe` (absolute or repo-relative) still runs — no regression.
- G7: inline message appears on the field without submitting; Run is disabled meanwhile.

### Tests (`unit/python/test_panel_pipeline_run.py`, new class `TestSamplePathValidation`)
Follow the module's existing conventions: `repo(tmp_path, monkeypatch)` fixture,
`FakeProc`, `monkeypatch.setattr(pr, "_POPEN", ...)`. One test per G-case plus one
symlink-escape test (skipif no Windows privilege: create `samples/link -> C:\outside`).

### Logging
One line per refusal: `logging.getLogger("panel.pipeline_run").warning("refused sample %r: %s", ...)`.

---

## 4. T1 — Packed gate (P0, 2 d)

Three layers, cheapest first: a static signal at selection, an authoritative check at
run start, and the analyzer's existing entropy tripwire as the last line of defense.

### 4.1 Detection — `pe_tools.pack_verdict(path)`

```python
UPX_MARKERS = (b"UPX0", b"UPX1", b"UPX2", b"UPX!")          # section names + packer magic
ENTROPY_PACKED = 7.5                                         # same threshold as phase_extract.cpp:239

def pack_verdict(path: Path) -> dict:
    """Offline packed-ness verdict. Never executes or fully unpacks the file."""
    head = path.read_bytes()                                 # size-capped by upload/typing rules;
                                                             # guard: refuse > _MAX_PROBE_BYTES (64 MB)
    marks = [m.decode() for m in UPX_MARKERS if m in head]
    if marks:
        return {"packed": True, "method": "upx", "evidence": f"UPX markers {marks} in the file"}
    e = _shannon_sampled(head)                               # 1 MB strided sample, cheap
    if e >= ENTROPY_PACKED:
        return {"packed": True, "method": "entropy",
                "evidence": f"whole-file entropy {e:.2f} bits/byte >= {ENTROPY_PACKED}"}
    return {"packed": False, "method": None, "evidence": ""}
```

SHA-256 is computed in the same pass and cached by `(path, size, mtime)` in
`samples/.manifest.json` (lazily created; see T3).

### 4.2 Server validation — `pipeline_run.start()`

`start(pipeline, sample, duration=None, allow_packed=False)`; the route passes
`bool(body.get("allow_packed"))`. Insert after the resolved-path existence check:

```python
    verdict = pe_tools.pack_verdict(full_sample)
    if verdict["packed"] and not allow_packed:
        return {"ok": False, "code": "sample-packed",
                "error": f"{Path(full_sample).name} is packed ({verdict['method']})",
                "detail": verdict["evidence"]
                          + " - execution from the panel is prevented; unpack it, "
                            "or repeat with allow_packed=true after confirming on the page",
                "sample": _sample_meta(full_sample)}
```

- The verdict is stored on the job and exposed in `_job_view` (`pipeline_run.py:110-119`)
  as `"packed": verdict` so the running-run header can label a live run.
- Refusal is `400`; add `"code"` to every refusal payload (additive, see §7).
- Overrides are logged loudly: `[pipeline-run] OVERRIDING packed gate for %s by operator`.
- `IA_INTERRUPT_IF_PACKED` stays the analyzer-side backstop; the panel does **not**
  silently flip it — an operator override that the analyzer then halts would be a
  contradiction (documented in the refusal `detail`).

### 4.3 UI state (`Build.tsx` PipelineRunCard)

- Once sample metadata is known (T3's endpoint, or a cheap `POST /api/build/samples/inspect`
  for a typed path), render under the sample field:
  - `Chip color="danger">packed (UPX)</Chip>` or `(high entropy)`.
  - Danger `Alert`: **"This sample is packed. Running it from the panel is prevented —
    packed executables spend the run in unpacking loops and the phases after histogram
    cannot be trusted. Unpack it, or analyse the packed original from the CLI."**
- `runDisabled` gains `|| (sampleMeta?.packed && !allowPacked)`.
- After a refusal carrying `code: "sample-packed"`, reveal a single-use interlock:
  checkbox **"Run anyway (packed override)"** + the Run button requires a fresh click.
  Persist nothing; the checkbox resets on selection change.
- **Immediate stop path**: if a live job's `sample` equals the newly selected packed
  sample, the card switches to a red state — "A run of this packed sample is live" —
  and the existing Stop button becomes the primary action with a confirm step
  (`POST /api/pipeline-run/<id>/stop`). Selecting a packed sample while a *different*
  run is live only prevents, never stops (nothing to stop).
- Sample generation tab: after Generate with `upx: true`, the summary chip already
  shows before/after bytes; add "packed — execution from Run a pipeline will be
  prevented" to the generated summary (`SampleFactory.tsx:275-295`).

### Acceptance criteria
- G1: selecting a packed sample disables Run immediately and shows the danger alert.
- G2: `POST /api/pipeline-run` on a packed sample without `allow_packed` → 400,
  `code: "sample-packed"`, evidence in `detail`; nothing is spawned (`_POPEN` not called).
- G3: with `allow_packed: true` the run starts and the job carries `packed`.
- G4: clicking a packed sample while it is the subject of a live run surfaces Stop
  with confirm; Stop still goes through the two-stage terminate/kill.
- G5: a clean sample is unaffected (no verdict cost beyond one hash, cached).
- G6: the analyzer tripwire still fires independently when `IA_INTERRUPT_IF_PACKED` is on.

### Tests
- `TestPackedGate` in `test_panel_pipeline_run.py`: UPX-marker file refused;
  `allow_packed=True` starts; `_POPEN` not called on refusal; job records verdict.
- `test_panel_pe_tools.py`: `pack_verdict` on a marker file, on `os.urandom(1<<17)`
  (entropy path), on plain text (clean), on > probe-cap file (refused).
- Flask-level test asserting 400 + payload `code`.

---

## 5. T3 — Executable picker (P1, 1.5 d)

### Backend — new endpoints in `create_app()` (`app.py`, next to the pipeline-run
block at `:1862-1983`, same docstring/OpenAPI pattern; auth gate covers them automatically):

```
GET /api/build/samples
200 {
  "ok": true,
  "dir": "samples",
  "files": [
    { "name": "gen-3.exe", "relative": "samples/gen-3.exe",
      "bytes": 81920, "modified": 1761050000.0,
      "sha256": "…", "source": "factory" | "upload" | "typed",
      "packed": {"packed": true, "method": "upx", "evidence": "…"} | null,
      "protected": false }
  ],
  "scanner": {"available": true, "mode": "clamdscan"}          // from T4
}
```

- Lists `config.SAMPLE_ROOTS` (deduped), newest first, capped at 200 entries.
- Manifest-cached hashes/verdicts keyed `(path, size, mtime)`; stale entries pruned.
- `POST /api/build/samples/inspect` — body `{path}` — same meta object for a typed
  path (validates with the T2 rules first). This is what makes the free-text box
  able to show "packed" without a full listing.

### Front end (`Build.tsx`)

The repo has no combobox dependency; a native `<input list>` + `<datalist>` gives
type-ahead suggestions while keeping typed paths (CLI parity) — zero new deps:

```tsx
const [samples, setSamples] = useState<SampleEntry[]>([])
useEffect(() => { void api.buildSamples().then((r) => setSamples(r.files)).catch(() => undefined) }, [])

<input list="run-sample-list" className="field …" value={sample} … />
<datalist id="run-sample-list">
  {samples.map((f) => (
    <option key={f.relative} value={f.relative}>
      {`${bytes(f.bytes)} · ${ago(f.modified)}${f.packed ? ' · PACKED' : ''}`}
    </option>
  ))}
  <option value="upload…" />   {/* opens the T4 uploader */}
</datalist>
```

- On blur/commit, call `inspect` and enter one of the states: `clean` / `packed`
  (T1 interlock) / `invalid` (T2 messages) / `unknown` (metadata pending — Run
  stays disabled until the server has seen the path).
- In `api.ts`: `buildSamples()`, `inspectSample(path)`; in `types.ts`:
  `SampleEntry`, `SampleMeta` (mirroring the JSON above).

### Acceptance criteria
- G1: the dropdown lists `samples/*.exe` newest-first with size, age and PACKED tag.
- G2: typing a path not in the list still works after `inspect` succeeds.
- G3: an entry deleted by `sample_factory._prune` while shown → selecting it yields
  "No such file" (inspect re-checks disk; listing is a cache, never the authority).
- G4: `GET /api/build/samples` is covered by the auth gate (401 without token when set).

### Tests
- `test_panel_samples_endpoint.py` (Flask-client pattern from
  `test_panel_hardening_endpoints.py:53-67`): list ordering, cap, manifest cache hit
  (mtime change re-hashes), inspect refusals delegate to the T2 rules.

### Migration note
`samples/` files made by Generate are pruned at 12 (`SAMPLE_KEEP`); `_prune` must
learn `protected` from the manifest (uploads are protected, factory outputs are not)
or the combo will offer files that no longer exist.

---

## 6. T4 — Executable upload (P1, 3 d)

### Backend

```
POST /api/build/samples/upload          # multipart/form-data, field "file"
201 { "ok": true, "file": <SampleEntry>,
     "scan": {"verdict": "clean"|"infected"|"unavailable",
              "signature": null | "Win.Trojan.X", "sha256": "…", "seconds": 1.2} }
400 { "ok": false, "code": "scan-infected"|"bad-extension"|"bad-name", "error", "detail" }
409 { "ok": false, "code": "scan-unavailable", "error": "the scanner is not reachable",
      "detail": "upload rejected by policy; retry when clamd is up" }
413 { "ok": false, "code": "too-large", "error": "… exceeds 64 MB" }
```

Pipeline inside the route → new `python/panel/samples/samples.py`:

1. **Name & size**: reject over `config.SAMPLE_UPLOAD_MAX_BYTES = 64 * 1024 * 1024`
   (raise from the dead `UPLOAD_MAX_BYTES` intent, `config.py:106-109`; stream
   `file.stream.read(chunk)` into the staging dir — never `get_data()` whole-body).
   Extension allowlist = T2's `ALLOWED_SAMPLE_EXT`; the client filename is **not**
   trusted: the staged name is `{utc}-{sha256[:12]}{ext}`, original kept in the manifest.
2. **Staging**: write to `config.UPLOAD_DIR` (`exports/_panel_uploads/`), fsync,
   hash while writing.
3. **Scan**: new `clamd.scan_file(path) -> dict`, never raises:
   - `clamdscan --no-summary <path>` when on `PATH` (mode `clamdscan`) — this is what
     `clamd.status()` already probes (`clamd.py:143-219`);
   - else python-clamd `INSTREAM` over the socket/TCP in `python/clamd/vm_info.json`
     (`mode/socket/port/timeout`) — same client construction as
     `python/clamd/clamd-python.py:55-61`;
   - else `{"verdict": "unavailable", "error": …}`. Timeout 60 s, subprocess killed
     on expiry.
4. **Verdict handling**: `infected` → move to `samples/_quarantine/` (never delete;
     evidence), 400 with the signature. `clean` → `os.replace` into `samples/`,
     manifest entry with `source: "upload", protected: true`. `unavailable` →
   **policy**: refused with 409 by default. An explicit
   `allow_unscanned=true` field plus a red confirm in the UI admits the file and is
   logged as `[samples] UPLOAD ADMITTED WITHOUT SCAN: %s`.
5. **One upload at a time** (module lock), matching the one-run-at-a-time rule.

### Front end (Build.tsx, inside the picker dropdown → inline panel)

- Drop zone + file input `accept=".exe,.dll,.bin,.sys"`, states:
  `hashing → scanning → done | infected | refused | scanner-down`.
- Scanner-down shows the policy confirm: "The scanner is not reachable. Admit
  without scanning?" — checkbox + button, both explicit; result banner persists.
- On success the entry is selected in the combo and inspected like any other.

### Acceptance criteria
- G1: > 64 MB → 413, nothing staged left behind.
- G2: `.txt` → 400 naming allowed extensions; `x.exe:stream` filename → 400.
- G3: EICAR-in-a-PE test file with a stubbed `scan_file → infected` → 400, file in
  `_quarantine/`, nothing in `samples/`.
- G4: scanner down + no override → 409; with override → 201 and manifest says so.
- G5: uploaded file survives `sample_factory._prune` (protected).
- G6: sha256 in the manifest matches `certutil -hashfile` ground truth.
- G7: every upload/admission produces one log line.

### Tests
`test_panel_samples_upload.py` (Flask client + monkeypatched `clamd.scan_file`):
cap, extension, filename, infected, unavailable±override, happy path, lock contention.

---

## 7. T5 — trace.txt lifecycle (P2, 1.5 d)

`ENABLE_TRACING` and `TRACE_FILE` already exist end-to-end (registry
`analysis.py:155-172`, shipped `config/analysis.yaml:49`, analyzer gate
`trace.cpp:44-49`, panel toggle on the Analysis Configuration "Behaviour" card). **Do
not add a second flag.** What is missing is observability and lifecycle.

### Backend — `python/panel/host/trace.py` additions

```python
def status() -> dict:
    """{enabled, path, exists, bytes, modified, archives: [{name, bytes, modified}], live}"""
    enabled = analysis_settings.snapshot(config.REPO)   # read ENABLE_TRACING present/value
    ...
def archive() -> dict:
    """gzip logs/trace.txt -> trace.<utc>.txt.gz, atomically; keep newest 5."""
    if pipeline_run.status()["running"]:
        raise RuntimeError("a run is live; the trace file is memory-mapped - archive after it ends")
    # gzip to <tmp>, os.replace, prune to TRACE_ARCHIVE_KEEP = 5
```

Routes in `app.py`: `GET /api/trace/status`, `POST /api/trace/archive` (same
docstring pattern; both under the auth gate).

### Front end (`AnalysisConfig.tsx`)

New "Tracing" strip card **below** the Behaviour card (it must not duplicate the
`ENABLE_TRACING` toggle — the page's own rule: one key, one control):

- Status line: `ENABLE_TRACING: on · trace.txt 78.4 MB · last written 3 min ago`
  or, when off: `tracing disabled — trace.txt is no longer written; the file below is stale`.
- Buttons: **Archive now** (calls the endpoint; disabled while a run is live, with
  that reason as the title) and **Open trace viewer** (existing `/api/trace/<key>`).
- When tracing was just disabled, an info banner: "The existing trace.txt is kept —
  archive it to stop the Trace viewer showing a stale 78 MB file."

### Run-card observability (`Build.tsx` / `pipeline_run.py`)
`start()` records `(size, mtime)` of the trace file before spawn; the job view
carries `trace_bytes_written`. The run header shows `trace: 12.4 MB` or
`trace: off` — turning "is tracing actually on for this run" from a guess into a fact.

### Acceptance criteria
- G1: with `ENABLE_TRACING: false`, a full run writes no trace bytes (delta 0).
- G2: with it true, the run reports a positive delta and the file exists.
- G3: archive while a run is live → 409-style refusal with the mmap reason.
- G4: archive keeps ≤ 5 archives; the viewer no longer offers the old file id.
- G5: crash leftover (zero-filled tail) is not reported as used size — reuse
  `trace_used_bytes()` semantics already noted in `trace.cpp:569` when presenting size.

### Tests
`test_panel_trace_lifecycle.py`: status reads the seeded yaml; archive creates
`.gz` + removes the original; refuses while `pipeline_run.status()` says running;
prunes to 5. Follow `test_analysis_settings.py`'s `repo(tmp_path, monkeypatch)` style.

---

## 8. T6 — Selection persistence (P2, 0.5 d)

- Key `build-run-selection` in `localStorage` (same pattern as `RUN_CURSOR_KEY` /
  `RUN_DURATION_KEY`, `Build.tsx:231-236`): `{pipeline, sample}` written on change,
  restored on mount **only if** `inspect` still validates the sample; otherwise fall
  back to the Tests-catalogue fixture (`Build.tsx:788-790`).
- Never persist the packed override.

---

## 9. Cross-cutting requirements

**Error handling / logging**
- Every refusal: `{ok:false, code, error, detail}`; HTTP 400, 409 for state
  conflicts, 413 size — matching the existing "refusal is a payload" rule
  (`pipeline_run.py:19-21`).
- `code` becomes part of every refusal payload (additive field) so the UI switches
  on machine-readable reasons instead of string matching (today `Build.tsx:419`
  joins free text; `"already"`-substring status mapping at `app.py` route stays).

**Security controls**
- Server is the only packed/validity authority; client state is display only.
- TOCTOU: verdict + hash cached by `(path, size, mtime)`; `start()` re-checks mtime
  and recomputes on mismatch — the file analysed is the file vetted.
- Uploads: staged, streamed, size-capped, scanned pre-admission, quarantined not
  deleted, server-named, one at a time; `IA_ARTIFACT_UPLOAD=0` forcing unchanged
  (`pipeline_run.py:392`).
- RBAC: all new endpoints inherit the `/api/*` token gate. Single-operator model is
  unchanged; when roles land (`auth.py:27-31` says replace, not extend), mark
  `upload`, `allow_packed` and `allow_unscanned` as the privileged actions.

**Backward compatibility / migration**
- `POST /api/pipeline-run` keeps `sample: string`; `allow_packed` optional. The only
  behaviour change for old clients: packed samples are refused — intended, and the
  payload says why. Typed absolute paths keep working inside the roots.
- New fields everywhere are additive; no `config/analysis.yaml` keys are added, so
  the parity tests (`test_analysis_settings.py:369-399`) are untouched. If a future
  key is needed, the four-place rule applies (`analysis.py` `ENV_OPTIONS`,
  `analysis_config.cpp` `kKeys`, yaml comment block, docs).
- Migration is lazy: `samples/.manifest.json` appears on first use; absent manifest
  ⇒ compute on the fly. `_prune` gains `protected` awareness before uploads ship.
- Docs: update `docs/admin-console/build.md` and `analysis-config.md` with the new
  picker, upload policy and trace lifecycle in the same change that ships them.
