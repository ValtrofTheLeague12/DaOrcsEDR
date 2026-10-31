# EMBER2024 -> LightGBM training pipeline

Self-contained folder to copy onto a training VM. Downloads the EMBER2024 feature
dataset, flattens it, trains a LightGBM malware classifier, and scores samples.

Nothing here executes a malware sample. EMBER2024 ships **precomputed feature
vectors plus labels**, not binaries, so this is safe on an isolated host.

## Why Python and not C++/CMake

This was asked for as a C++ project with a `CMakeLists.txt`. That is not possible,
for three independent reasons:

1. **The dataset is pickled Python dicts.** `Win64_train.zip` unpacks to
   `*.pickle` files. C++ has no reader for that format.
2. **LightGBM has no C++ training API.** It ships a C API for *inference* only.
   Training is Python by design.
3. **There is no `liblightgbm` in MSYS2/UCRT64** (checked
   `C:\msys64\ucrt64\lib`), so a C++ build would first have to compile LightGBM
   from source.

So the trainer is Python. The C++ side of the project is unaffected: it already
emits the two EMBER byte-statistics vectors, and `predict.py --check` is the gate
that proves they match upstream.

## Setup

```bash
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
python -m pip install -r requirements.txt

# thrember is the EMBER v3 feature extractor. Needed to re-vectorize and to score.
git clone https://github.com/FutureComputing4AI/EMBER2024.git
python -m pip install -e ./EMBER2024
```

## Run

```bash
# 1. Download (~7 GB for Win64). Add --include-challenge for the 6,315 evasive set.
python download_dataset.py --subset Win64 --include-challenge --extract

# 2. Flatten pickles -> float32 matrices
python vectorize.py --data data --out data/vectors

# 3. Train
python train.py --vectors data/vectors --model model.txt \
                --challenge data/vectors/X_challenge.npy

# 4. Run the static analyzer, then score its matching report with the binary
static_analyzer.exe sample.exe
python predict.py --model model.txt --file sample.exe \
                  --analysis ../exports/sample_analysis/extraction/sample_extraction.json
```

`download_dataset.py --list` shows every subset. Sizes are published counts, and
the downloader refuses to continue on a truncated zip rather than training on
half a corpus.

### The corpus lives on D:, not in the repo

`data/` in the repo root is a Windows junction to `D:\IAProject\data`, so every
command above reads and writes through `data/...` with no changed arguments
while the actual bytes - the zips, the extracted pickles, the vectors, and the
`known_pe_hashes.jsonl` roster the analyzer looks up at run time - sit on the
larger disk. The only ML file that stays in the tree is `ml/model.txt`, which
`serve.py` loads from its own directory at scoring time. Recreating the junction
after a fresh clone is one command:

```powershell
New-Item -ItemType Directory -Path "D:\IAProject\data" -Force
New-Item -ItemType Junction -Path data -Target "D:\IAProject\data"
```

Scoring always needs the executable: `thrember` extracts the complete 2,568
features from its bytes. `--analysis` additionally loads the analyzer's
`ember_histogram` and `ember_byteentropy`, verifies the report size and available
SHA-256 against the executable, checks both vectors against `thrember`, and
scores using those analyzer-produced values. A report alone is not enough for
this model because the analyzer does not yet export all 2,568 EMBER features.

## Logging

Every script writes a real file log through `mllog.py`:

```text
logs/ml_<script>_<UTC timestamp>.log      e.g. logs/ml_train_20261003-170912.log
```

`ML_LOG_DIR` overrides the directory, for when `ml/` is copied onto a training
VM that keeps its logs somewhere else. The file receives everything at DEBUG
and above, including full tracebacks from the `__main__` crash handler, so a
failed overnight run can be diagnosed after the terminal is gone.

Console behaviour is deliberately unchanged: `[*]` / `[+]` INFO lines still go
to stdout and warnings/errors still go to stderr, so existing pipes and
eyeballing keep working. `predict.py --json` drops the console handlers
entirely, which keeps stdout machine-readable while the run is still captured
in the file. `setup(script, console=False)` is the file-only mode for anything
that must not write to a terminal.

Adding it to a new script is three lines:

```python
import mllog
log = mllog.setup("scriptname")            # file + console
log.error("[!] %s", message)               # raises nothing, just logs
```

`logs/` is git-ignored.

## Local scoring API (`serve.py`)

Wraps the trained model in a loopback HTTP service so the analyzer (or anything
else) can score without re-loading LightGBM each time. It runs in its own
virtualenv so thrember's dependency tree and the `signify==0.7.1` pin stay out of
the main interpreter.

```bash
python -m venv ml/_t/venv
ml/_t/venv/Scripts/pip install -r ml/requirements.txt   # Windows
python -m ml/_t/venv/Scripts/python ml/serve.py --port 60010
```

| Endpoint | Body | Purpose |
|---|---|---|
| `GET /health` | – | liveness + which model is loaded |
| `GET /model` | – | metadata + EMBER group offsets (`histogram`@7, `byteentropy`@263, …) |
| `POST /score` | `{"path": "<binary>"}` | thrember vectorises the file, then scores |
| `POST /score/vector` | `{"vector": [2568 floats]}` | score a vector you already have |
| `POST /score/batch` | `{"vectors": [[...], ...]}` | up to 10,000 at once |

Every response carries `malicious_probability`, `verdict`, `threshold`,
`model_sha256` and `feature_source`. `threshold` is a request parameter, not a
constant — it is the single biggest lever on the results (see the evasion column
above). Errors come back as `{"error", "detail"}` with a specific code: a
1,000-element vector is `400 expected 2568 values, got 100`, a NaN is
`400 non-finite value at index 5`.

### `verdict` can be `not_applicable`

The model was trained only on Win64 PE images. Every scoring response also
carries `is_pe`, read from the vector itself rather than trusted from the
request. When `is_pe` is false the response is:

```json
{"malicious_probability": 0.916071, "verdict": "not_applicable",
 "is_pe": false,
 "verdict_note": "not a PE image; the model was trained only on Win64 PE
                  binaries, so this score is an extrapolation and not a
                  detection"}
```

The raw probability is still returned so the model output stays auditable, but
it is deliberately **not** labelled `malicious`. This matters more than it
looks: a 32-byte text file scores 0.916, and an all-zeros vector scores 0.996.
Both are artefacts of a malformed input, not detections, and a caller that
switches on `verdict` would otherwise treat them as malware. Handle the third
value explicitly.

### Verdicts are banded, not thresholded

`verdict` is one of `benign` / `inconclusive` / `malicious` / `not_applicable`,
from fixed bands (below 0.3, 0.3-0.8, above 0.8). **This is a breaking change**
for any client that expects `malicious` / `benign`.

The reason is that the score is **not calibrated**. On deduplicated test files
the model is strongly bimodal, so a score of 0.55 sits in a sparse region where
the observed malware rate is nothing like 55%. Calling that "malicious"
overstates the evidence. `verdict_at_threshold` retains the old hard-threshold
result during any transition.

See the report's "What these numbers mean in practice" section for the
reliability diagram and precision at realistic prevalence.

### The analyzer's `threat_level` is a display band, not a model output

The analyzer adds one derived field on top of the service response —
`threat_level` (`low` / `moderate` / `high` / `critical`, or `n/a` for
`not_applicable`), written into `<stem>_ml.json` next to `threshold_margin`
(`p - threshold`, signed) and printed in the ML section of the console report
and the dashboard.

It is computed **client-side** (`ml_api::level_for()` in `src/ml_api/ml_api.cpp`)
because it bands `p` against the threshold that was actually applied, while the
service bands `p` alone. The margin is normalised by the room left on its own
side of the threshold, so a `ML_THRESHOLD=0.9` run reads on the same scale as a
`0.5` one: with the default threshold the four labels land at `p < 0.25`,
`0.25-0.75`, `0.75-0.90` and `>= 0.90`.

It never replaces `verdict`, and it is not a confidence: it is a reading aid
over the same uncalibrated ranking signal, which is why the margin is always
printed beside it.

### Limits

`/health` and `/model` report `max_file_bytes` and `sandbox_root`. The 256 MB
request-body cap does **not** bound `/score`: that endpoint reads a file named
in the request, so an oversized file would be read regardless of body size. It
is rejected with `413 file too large` before any parsing. Real Win64 PEs are
orders of magnitude smaller.

```bash
curl -s localhost:60010/health
curl -s -X POST localhost:60010/score -H 'content-type: application/json' \
     -d '{"path": "a.exe"}'
```

### Why did it score that way? (`explain`)

Add `"explain": true` to `/score` or `/score/vector` (optional `"top_k": N`,
default 8) and the response gains an `explanation` block. It is LightGBM's own
TreeSHAP attribution (`pred_contrib=True`, no extra dependency), expressed in
log-odds:

```json
"explanation": {
  "base_log_odds": 0.737,
  "prediction_log_odds": 0.199,
  "sum_shap": -0.539,
  "consistency_error": 0.0,
  "top_features": [
    {"feature_index": 2405, "group": "datadirectories",
     "label": "IMAGE_DIRECTORY_ENTRY_EXPORT size", "value": 0,
     "shap_log_odds": 2.885, "direction": "towards malicious"},
    {"feature_index": 2237, "group": "imports", "named": ["kernel32.dll:Sleep"],
     "bucket_occupancy": 1, "shap_log_odds": 0.101,
     "direction": "towards malicious"}
  ],
  "group_rollup": [{"group": "header", "shap_log_odds": 3.773,
                    "analyzer_implemented": false}]
}
```

`base_log_odds` is the model's average prediction and `consistency_error`
asserts that base + sum(SHAP) reproduces the reported log-odds — it is `0.0`, so
the attribution is exact for this sample, not an approximation.

Two details make this readable rather than a column dump:

* **Names, not column numbers.** Most of the 2,568 columns are `FeatureHasher`
  buckets, so bare SHAP would only say "column 2237". `serve.py` reproduces
  thrember's own hasher configuration (256 library + 1,024 function buckets for
  imports, 128 for exports) and hashes each name from the file individually to
  find its exact column. Verified by round-trip against pefile: all 70 of
  a.exe's imports resolve to the column whose vector value is non-zero.
* **Collisions are reported, not hidden.** kernel32.dll has 1,697 exports in 128
  buckets, so one bucket can hold 15 names and its SHAP is their *sum*. Rows
  carry `bucket_occupancy`/`shared_bucket` so a shared number is never read as
  one import's fault. Non-hashed groups are named only where the layout was
  verified against the installed thrember (`datadirectories`, `general`,
  `imports`, `exports`); other groups report the column index rather than a
  guess.

`analyzer_implemented` marks whether the C++ exporter can produce that group at
all, which makes the attribution usable for prioritising exporter work: a.exe's
two strongest drivers are `header` and `datadirectories`, and the exporter
currently sends neither.

The same attribution is available offline, with no server:

```bash
python ml/predict.py --model ml/model.txt --file sample.exe --explain
python ml/predict.py --model ml/model.txt --file sample.exe --json --explain
```

It binds `127.0.0.1` on purpose: `/score` parses any file the process can read,
so it is an arbitrary-file parser for anyone who can reach the port.

### Running it as a server

**Not safe to expose as-is.** `/score` accepts any filesystem path and parses it
with thrember/pefile. Unauthenticated, that is a remote arbitrary-file-parser
and a file-existence oracle (404 vs 422). Three hardening options are built in:

| Flag | Purpose |
|---|---|
| `--token` (or `$ML_SERVE_TOKEN`) | Require `Authorization: Bearer <token>`, compared in constant time |
| `--root DIR` | Confine `/score` to files under `DIR`; `../` traversal is resolved first and refused with 403 |
| — | `MAX_CONTENT_LENGTH` = 256 MB, so oversized bodies are refused before parsing |

Two guards make the unsafe combinations fail closed: binding a non-loopback
address **without** a token refuses to start (exit 2), and `--debug` on a
non-loopback bind refuses to start, because the Werkzeug debugger permits remote
code execution.

```bash
# confined, authenticated, TLS terminated by a proxy in front
export ML_SERVE_TOKEN="$(python -c 'import secrets;print(secrets.token_urlsafe(32))')"
ml/_t/venv/Scripts/python ml/serve.py --host 0.0.0.0 --root C:\samples
```

**Still required before any real deployment.** Flask's development server is
not a production WSGI server: no TLS, and it will fall over under concurrency.
Put it behind nginx/Caddy or gunicorn, add rate limiting, run it as an
unprivileged user in a container, and give `--root` a directory containing only
samples. Parsing untrusted binaries is inherently risky (pefile and thrember
run on attacker-controlled input), so treat this service as a parser sandbox.

**The analyzer cannot call `/score/vector` yet.** The C++ exporter emits only
`histogram` + `byteentropy` — 512 of the 2,568 dimensions — so it has to use
`/score` with the file path and let the service run thrember for the other
80%. Making the analyzer self-sufficient would mean training a second,
512-dimension model on the columns it can already produce bit-exactly; that is
the natural follow-up if the Python service becomes a deployment dependency.

### Called by the analyzer (no setup needed)

The analyzer launches this service itself and scores every sample, over the
same loopback HTTP client it already uses for the MalAPI server
(`include/net/local_api.hpp`, `include/ml_api/ml_api.hpp`). Nothing to start by
hand:

```bash
static-analyzer.exe sample.exe       # [phase n/total] EMBER2024 ML score
```

It runs from the venv interpreter (`ml/_t/venv/Scripts/python.exe`), so
thrember and its `signify==0.7.1` pin stay out of the interpreter running
`python/api/server.py`. If the venv or `model.txt` is missing the phase is
**skipped**, never failed — a missing model does not turn a good static
analysis into a red one.

| Env var | Default | Effect |
|---|---|---|
| `ML_SKIP` | unset | `1`/`true` skips the phase and does not launch the service |
| `ML_THRESHOLD` | `0.5` | decision threshold sent with the request; the applied value is echoed back |
| `ML_EXPLAIN` | `1` | request the TreeSHAP `why` block (named evidence, not column numbers) |
| `ML_TOP_K` | `8` | how many SHAP rows (1–50, clamped) |

Results land in the terminal report, the summary block, and
`exports/<stem>_analysis/ml/<stem>_ml.json`.

The banded `verdict` is passed through verbatim, which matters: an ELF scores
`0.985799` from this model and still reports `not_applicable`, because only
Win64 PE images were in the training set. The JSON keeps
`malicious_probability`, `is_pe` and `probability_is_calibrated: false`
separate so no consumer can collapse that into a false detection.

## PDF evaluation report (`report_pdf.py` + `templates/report.html.j2`)

Renders everything above into a single paginated PDF — 16 figures for a
per-sample report, 14 for the corpus-wide one — plus the provenance tables and a
scannable integrity block:

```bash
python ml/report_pdf.py                                  # -> ml/report/default/report.pdf
python ml/report_pdf.py --sample a.exe                   # -> ml/report/a/report.pdf
python ml/report_pdf.py --verify-only -o ml/report/a/report.pdf
python ml/report_pdf.py --save-manifest ml/report/m.json
```

Each report is written into its own directory (`default/`, or one named after
the sample) containing the PDF, its `.sha256` sidecar, `manifest.json`, the
HTML and the vector CSV, so a report can be moved or deleted as a unit. Reports
verify independently — rebuilding one does not invalidate another.

`--sample` makes the report about one executable: its name becomes the title,
the cover carries its path, size, SHA-256, verdict and the SHAP reasons behind
that verdict, its digest joins the integrity manifest, and the PDF is named
after it. Use `--sample-threshold` to score at a threshold other than 0.5.

### What the report shows about the input

A per-sample report is meant to be auditable, so it states what went **into**
the model, not only what came out:

- **Section 3, "What was actually passed into the model"** &mdash; the full
  2,568-dimension `float32` vector: how many columns are non-zero, the
  offset/width/min/max/mean of each of the 12 EMBER groups, and every hashed
  column flagged in that file, resolved back to its import, library or export
  names with bucket-occupancy shown when several names collide in one bucket.
- **`<stem>.vector.csv`** &mdash; beside the PDF, one row per column
  (`column_index, group, label, named_items, value, shap_log_odds,
  bucket_occupancy, in_top_k`), all 2,568 rows, for offline auditing. It is
  covered by the report's manifest and is excluded from the shared `*.csv`
  wildcard so one report's derived input cannot invalidate another's.
- **`<stem>.fields.csv`** &mdash; the fields that actually mattered, one row per
  impactful column, with its **resolved name**, **data type**, value, SHAP,
  direction, model-wide gain share and tree-split count. Every column name is
  derived from `thrember`'s own extractor layout, so column 739 reads as
  `IMAGE_FILE_CHARACTERISTICS: DLL` rather than an index; hashed columns that
  cannot be resolved to a concrete value are named by kind (`hashed
  imported-function bucket`) instead of being left blank. **Zero of the 2,395
  rows are unnamed.**
- **Non-zero is not a finding.** The report says so explicitly: most of a normal
  PE is non-zero by construction, and only the sign of a column's SHAP
  contribution says which way it pushed the score.
- **Non-PE inputs are marked out of scope.** The model is trained only on Win64
  PE files. If the sample is not a PE image the cover shows an amber
  `NOT A PE FILE - score only` badge instead of a verdict, with a callout
  explaining that the number is an extrapolation and must not be read as a
  detection. The raw score is still printed so the model output stays auditable.

Charts are regenerated per build rather than reused from disk: metric comparison
at both operating points (recomputed from `predictions_test.csv`, so the
FPR-constrained point is exact rather than read off the nearest grid row),
error rate per weekly chunk as bars, a two-panel threshold sweep, and per-sample
coverage and top-contribution charts.

Each report owns a directory, so a report and everything derived from it can be
moved, archived or deleted as one unit:

```
ml/report/                     # shared inputs only (evaluate_report.py output)
  01_roc_curve.png  *.csv ...
ml/report/default/              # the corpus-wide report
  report.pdf  report.pdf.sha256  manifest.json  report.html
ml/report/a/                    # --sample a.exe
  report.pdf  report.pdf.sha256  manifest.json  report.html
  report.vector.csv  report.fields.csv
```

The directory is named after the subject (`default` when there is no sample) and
sample names are sanitised, so a name with spaces or `..` cannot escape
`ml/report/`. To re-check a named report, pass the same flags:

```bash
python ml/report_pdf.py --verify-only --sample a.exe -o ml/report/a/report.pdf
```

Reports are fully independent: rebuilding one does not invalidate another, and
each manifest covers only its own directory's outputs.

It needs a Chromium-family browser for headless printing (Edge or Chrome); it
locates one automatically, or `--engine edge|chrome`. Charts are base64-inlined,
so the HTML has no external references and the PDF is self-contained.

**Integrity: what the QR actually proves.** A file cannot contain its own
SHA-256 &mdash; writing the digest into the document changes the bytes, so it
would no longer match. The QR therefore encodes `sha256(manifest.json)`, where
the manifest is a canonical JSON listing all 22 input artifacts (model, both
metric JSONs, every chart, every CSV) with their own digests. That digest is
stable, reproducible across machines, and covers all the evidence; the scan
payload states plainly that it verifies the evidence and not the PDF bytes.
The PDF's own digest is written to `report.pdf.sha256` in `sha256sum -c` format.
Manifest entry paths are relative to `ml/`.

`--verify-only` recomputes the manifest from the files on disk, compares it with
the digest printed in the report, and checks the sidecar against the PDF.

<!-- @@PDF@@ -->

Printing needs a Chromium-family browser. Discovery covers Edge and Chrome in
system and per-user locations, the Beta/Dev/Canary channels, and the Chromium
that `playwright install chromium` provides; `REPORT_PDF_BROWSER` or
`--browser <path>` overrides discovery, and `--html-only` produces the HTML with
no browser at all. The intermediate HTML is rendered to a temp directory and
deleted; `--keep-html` retains it.

| Flag | Effect |
|---|---|
| `--self-test` | Decodes the QR back out of the HTML and asserts the PDF paginated, embedded 8 figures and kept every section |
| `--html-only` | Render HTML, skip printing |
| `--keep-html` | Keep `report.html` beside the PDF |
| `--browser <path>` | Use an explicit browser executable |
| `--verify-only` | Check recorded digests, the PDF sidecar, and staleness |

`--verify-only` reports three independent failures: a **manifest mismatch** (an
input artifact changed, naming the file), a **PDF mismatch** (the bytes differ
from the sidecar), and **staleness** (an artifact is newer than the PDF, i.e.
`evaluate_report.py` was re-run and the report should be rebuilt). Each exits 1.

Verified on this checkout: clean verify passes; appending one row to
`roc_points.csv` is detected and names the file; flipping one byte of the PDF is
detected; a future-dated chart triggers the staleness check.

## Verify the analyzer's vectors (no dataset, no model needed)

This is the check that matters most. It diffs the C++ analyzer's
`ember_histogram` / `ember_byteentropy` against real `thrember` output for the
same file:

```bash
static_analyzer.exe sample.exe
python ml/predict.py --file sample.exe \
                     --check exports/sample_analysis/extraction/sample_extraction.json
```

Exit code 0 means the vectors are EMBER-compatible. Run this after any change to
the byte-histogram stage, and before trusting analyzer output as model input.

Current status: **verified** on `suspicious_sample.exe` (265,396 B, multi-window
path) and `suspicious_sample.macho` (1,830 B, sub-window path), max abs diff
~7e-09 (float32 vs float64 rounding) on both.

## Coverage: what exists and what does not

The model needs all 2,568 EMBER dimensions. The analyzer currently implements
**2 of 12 groups (512 dims)**:

| Group | Dims | Analyzer |
|---|---|---|
| general | 7 | no |
| histogram | 256 | **yes** |
| byteentropy | 256 | **yes** |
| strings | 177 | partial (hits only, not the fixed-width vector) |
| header | 74 | partial (LIEF vs pefile field order) |
| section | 224 | no (needs EMBER's per-section hashers) |
| imports | 1282 | no (needs the 256/1024 hashers; highest signal) |
| exports | 129 | no |
| datadirectories | 34 | no |
| richheader | 33 | no |
| authenticode | 8 | no |
| pefilewarnings | 88 | no |

The analyzer report can supply its 512 byte-statistics dimensions to
`predict.py --analysis`; `thrember` still supplies the other 2,056 dimensions.
The executable must be provided alongside its report, and scoring is refused if
the report's byte statistics differ from `thrember`.

## Metrics and methods used in the report

Vocabulary for the numbers in the next section: what each one measures, why this
project uses it, and where it misleads.

### TreeSHAP — "which field moved *this* score"

**What it is.** A Shapley-value decomposition of a tree ensemble's prediction
into one signed contribution per input feature. It is the standard way to open up
a gradient-boosted model, which is otherwise a black box: you get a number per
feature saying how much it added to or subtracted from the output.

**Why TreeSHAP specifically.** SHAP has two implementations: an exact algorithm
over the tree structure (TreeSHAP, what LightGBM exposes via `pred_contrib`),
and a slower sampled approximation. We use the exact one, so the contributions
sum *perfectly* to the prediction rather than approximately.

**The property we rely on** — exact additivity:

```
base_value + sum(SHAP contributions) = the model's log-odds
```

For `a.exe` this is checked on every run and is exact to floating point:

```
base_value  +0.737490
sum(SHAP)   -0.538700
            -----------
log-odds    +0.198790   <- what the model actually output
sigmoid()   = 0.549535   <- the p(malicious) you see
```

`consistency_error` in the report and API is that gap; it is `0.00e+00`.

**Why contributions are in log-odds, not probability.** The ensemble emits a raw
score which is then passed through a sigmoid. TreeSHAP decomposes the
*pre-sigmoid* value, because that is where the model is additive. "+3.25 to
log-odds" means "this feature pushed the raw score up by 3.25"; it is not "+325%
probability". The sigmoid is monotonic, so ranking is unaffected.

**Why it matters here.** The input is 2,568 anonymous floats. SHAP is the only
thing connecting a score back to "this file had 19 sections" or "this export
directory is 2.9 MB". Without it the model would just be a number.

**Caveat.** When features are correlated, SHAP splits credit between them
somewhat arbitrarily. That is why the report shows *bucket occupancy* for hashed
import buckets: if 3 names collide in one hash slot, the SHAP value belongs to
all three, not to whichever name happens to be listed first.

### Gain vs SHAP — two different questions

| | Gain (LightGBM) | SHAP |
|---|---|---|
| Scope | model-wide, whole training set | one file |
| Answers | "what does the model *rely on*?" | "what moved *this* score?" |
| In report | section 11 | sections 1 and 6 |

They can disagree, and the disagreement is informative: `datadirectories` holds
36% of total gain (globally important) but contributes nothing to many individual
files. `report.fields.csv` shows both columns rather than collapsing them into
one "importance" number, because collapsing hides exactly those cases.

### Discrimination metrics

**ROC-AUC** — the probability that a random malicious file scores above a random
benign one. *Why:* threshold-free, so it measures whether the model can *rank* at
all, independent of where you put the cut. *Ours:* 0.997121 on deduplicated test
files. *Why not to quote alone:* AUC is blind to the operating point and to class
balance — a model can have excellent AUC and still be unusable.

**Average precision (AP)** — area under the precision-recall curve. *Why:* unlike
ROC its baseline is the class prevalence rather than 0.5, so it stays meaningful
under imbalance. The baseline here is 0.5; ours is 0.996942. *Caveat:* still
prevalence-dependent — see below.

**Precision, recall, FPR, F1, accuracy** — the standard confusion-matrix rates,
reported at explicit thresholds rather than as one headline number. *Why both at
once:* precision and recall trade off against each other, and neither is
meaningful without the threshold it was measured at.

**The confusion matrix** (section 9) is included because rates hide costs. At 0.5
the model makes 1,060 false alarms; at the FPR-constrained point only 300, but
false negatives rise from 1,718 to 4,502 — 2,784 more missed. Counts make that
trade explicit.

### Precision at realistic prevalence — the most important caveat

The test split is 50% malicious **by construction**. A deployed scanner is not.
Precision at a base rate *pi* is:

```
precision(pi) = (pi x TPR) / (pi x TPR + (1 - pi) x FPR)
```

Precision is not a property of the model alone — it depends on how much malware
the scanner actually meets:

| Base rate | Precision @0.5 | Precision @FPR-constrained |
| --- | --- | --- |
| 50% (the test set) | 0.9821 | 0.9946 |
| 10% | 0.8593 | 0.9536 |
| **1%** | **0.3570** | **0.6514** |
| **0.1%** | **0.0522** | **0.1562** |

*Why include it:* quoting the 50% figure alone would misrepresent the system by
an order of magnitude. *Caveat:* these are recomputed from the observed
TPR/FPR, so they assume the base rate shifts but the score distribution does not.

### Calibration and reliability

A score is **calibrated** if, among files scoring ~0.6, about 60% are malicious.
*Why it matters:* calibration is what licenses statements like "this is a 55%
chance". Without it, the score is only a ranking signal.

Our reliability diagram shows a strongly **bimodal** model — few files land in
the middle. Measured consequence:

| Band | Files | Share | Malware rate in band |
| --- | --- | --- | --- |
| benign (<0.3) | 30,181 | 50.3% | 2.60% |
| **inconclusive (0.3-0.8)** | **400** | **0.67%** | **56.75%** |
| malicious (>0.8) | 29,414 | 49.1% | 98.56% |

That middle band is the entire argument for **three-band verdicts**: a score of
0.55 sits where the observed rate is ~57%, so calling it "malicious" overstates
the evidence. Fixing it needs isotonic or Platt calibration fitted on a held-out
time slice — not done yet.

### Confidence intervals

**Bootstrap** — resample the evaluation files with replacement, recompute the
statistic, report the 2.5th/97.5th percentiles. *Why:* a point estimate with no
uncertainty is not a result; two models at 0.9971 may not be distinguishable.
*Ours:* AUC 0.997121, 95% CI [0.996810, 0.997413] over 400 resamples.

The resampling unit is the **file**, not the row. The corpus repeats each file
about twice, so resampling rows would treat 2,568 rows as independent evidence
when there are only 59,995 files.

### Operating point and threshold

An **operating point** is the (threshold, FPR, recall) triple you actually ship.
*Why it is the central decision:* the threshold is the single biggest lever on
the results. The report shows both 0.5 (the default in `predict.py`) and an
FPR-constrained 0.999343.

*Caveat:* that constrained threshold is chosen from the test predictions
themselves, so its recall/precision carry a selection bias. The default 0.5 does
not. (The three-band verdict avoids the issue by not using a tuned threshold.)

### Evasion catch rate

Fraction of the 6,315 challenge samples scoring above threshold. **Every
challenge row is malicious, so this is recall, not accuracy** — a number often
misread as precision. *Why include it:* it is the honest test of whether the
model handles modern evasive malware. Ours is 50.23% at 0.5 and 15.98% at the
strict threshold — the weakest result in the project.

### Data-integrity metrics

**SHA-256 disjointness** and **deduplicated counts** (section 3) are reported
because a corpus that repeats files will silently leak them across a train/test
split, inflating every metric. Here the official splits are SHA-256 disjoint, and
metrics are additionally recomputed on deduplicated files. Dedup leaves AUC
unchanged (0.997121) because duplicate rows carry identical labels and identical
scores — it removes inflated file counts, not inflated accuracy.

**Label conflicts** — files appearing with both a benign and a malicious label.
Reported per split; all are currently 0, which is worth stating because non-zero
would undermine every label-based metric.

### Why these and not others

- **No accuracy as a headline.** Accuracy is 0.9768 here but would be equally
  impressive for a model that predicted the majority class on imbalanced data.
- **No learning curve.** We cannot show whether more of the ~1.04M available
  Win64 rows would help, because this checkout has no vectors to retrain on.
- **No per-family AUC.** Only per-family error counts; a family-aware analysis is
  listed as future work.

## Results

Measured on the **official EMBER2024 Win64 test split** (120,000 rows /
59,995 distinct files), which is sha256-disjoint from training. Every figure
below is reproduced in the PDF report, so none of it is hand-maintained:

```bash
python ml/evaluate_report.py        # refreshes ml/report/*.csv and *.png
python ml/report_pdf.py             # rebuilds the PDF from those artifacts
```

The evaluation also profiles the held-out feature matrix with pandas and writes
`dataset_profile.csv` (dtype, missing values, descriptive statistics and
feature-to-label correlations) plus `dataset_summary.csv` (full row counts and
sample details). The PDF includes a feature-correlation chart based on a
deterministic 20,000-row sample; adjust that sample with
`python ml/evaluate_report.py --profile-sample-size 50000`.
The 2,568-dimensional matrix is already numeric, so pandas sees its columns as
`float32` features plus an `int8` label rather than recovering a mixed raw-data
schema.

The prevalence, verdict-band and bootstrap figures are recomputed by
`report_pdf.py` from `ml/report/predictions_test.csv` at render time.

### Discrimination (deduplicated files)

| Metric | Value |
| --- | --- |
| ROC-AUC | **0.997121**, 95% CI [0.996810, 0.997413] (400 bootstrap resamples) |
| Average precision | 0.996942 |
| Files scored | 59,995 |

Deduplication does not change ROC-AUC (0.997121 either way, because duplicate
rows carry identical labels and identical scores), but it does move average
precision slightly: 0.996942 on distinct files against 0.997622 across all
120,000 rows. The row-level figure is the one `test_metrics.json` stores.

### Operating points

| Threshold | Recall | FPR | Prec @50% | @10% | @1% | @0.1% |
| --- | --- | --- | --- | --- | --- | --- |
| 0.5 | 0.9714 | 0.01767 | 0.9821 | 0.8593 | **0.3570** | **0.0522** |
| 0.999343 (0.5% FPR) | 0.9250 | 0.00500 | 0.9946 | 0.9536 | **0.6514** | **0.1562** |

Precision is a function of prevalence, not a property of the model. The test
split is 50/50 by construction; at a realistic 1% base rate precision is 0.357,
and at 0.1% only 0.052. **Quote the base rate with the number or not at all.**

### Verdict bands and what the score actually means

| Band | Files | Share | Malware rate in band |
| --- | --- | --- | --- |
| benign (<0.3) | 30,181 | 50.3% | 2.60% |
| **inconclusive (0.3–0.8)** | **400** | **0.67%** | **56.75%** |
| malicious (>0.8) | 29,414 | 49.1% | 98.56% |

This is the clearest evidence that the score is **not calibrated**. The
inconclusive band holds 0.67% of files and is close to a coin flip — 56.75%
malware. A score of 0.55 genuinely does not mean 55%.

### Evasion (the weakest result)

6,315 obfuscated samples that ~70 AV engines initially missed, spanning 64
weekly chunks from 2023-09-24 to 2024-12-08. **Never trained on.**

| Threshold | Challenge caught |
| --- | --- |
| 0.5 | **50.23%** |
| 0.999343 | **15.98%** |

This is the number that matters most and the one this model is worst at. Half
of modern evasive malware is missed outright at the default threshold, and
raising the threshold for a cleaner benign false-positive rate makes it
drastically worse. It is a training-data problem, not a thresholding problem.

### What the model relies on (share of total LightGBM gain)

| Group | Gain | Attacker-cheap? |
| --- | --- | --- |
| datadirectories | 36.3% | yes — trivially editable |
| strings | 14.7% | partly |
| authenticode | 13.3% | yes — just strip or add a signature |
| exports | 11.3% | yes |
| histogram | 5.1% | no (content-derived) |
| header | 5.0% | partly |
| imports | 4.6% | partly |
| section | 3.7% | partly |
| byteentropy | 3.5% | no (content-derived) |
| pefilewarnings | 1.6% | yes |
| richheader | 0.7% | toolchain-dependent |
| general | 0.1% | no |

The three groups marked "yes" — the ones an attacker changes most cheaply —
carry **60.9%** of the model's total gain between them. How much accuracy
survives adversarial modification is **unmeasured**: no ablation or perturbation
experiment has been run.

### Errors

At t=0.5: 1,718 false negatives, 1,060 false positives (2.05%–2.61% error,
flat across all six weekly chunks, so the model is not merely tracking a
shifting corpus).

Missed-malware families cluster: `wacatac` 168, `sleepobf` 48, `fakecert` 44,
`neshta` 28, `cobaltstrike` 28, plus 530 unlabelled. Every one of the 1,060
false positives is an unlabelled benign file.

### Trained on

300,000 rows = **150,000 distinct files** (the corpus lists each ~twice), 12
groups / 2,568 dimensions, 500 trees, `num_leaves=1024`, train AUC 1.0. See
"Known limitations" for what that implies.

## Interpreting the metrics

`train.py` reports ROC-AUC, but **AUC is not the number to decide on**:

- **TPR at max_fpr=5e-3** is the operating point that matters. A model can post
  0.99 AUC while missing most malware at a usable false-positive rate.
- **`--challenge` evasion rate** is the honest test: 6,315 files that ~70 AV
  engines initially missed. Expect a large drop from the test-set AUC. A model
  that scores well on test and poorly on challenge has learned the corpus, not
  malware.
- The challenge rows are **all malicious**, so the catch rate there is TPR, not
  accuracy. Do not read it as a precision figure.

## Known limitations of the current model

These are real and measured, not hypothetical. They are also stated in the
generated report's "Limitations and honest caveats" section.

1. **Training duplication.** The corpus lists each file roughly twice
   (300,000 training rows = 150,000 distinct sha256). This does **not** inflate
   the headline test metrics, because duplicate rows carry identical labels and
   identical scores — deduplicating leaves ROC-AUC unchanged at 0.9971. It would
   however leak badly across a *random* train/test split, which is why headline
   numbers use the official sha256-disjoint test split and never the random 10%
   holdout. The `0.99993` figure in `model.txt.metrics.json` **is** that leaked
   holdout; do not quote it.

2. **Precision is prevalence-dependent.** On the 50/50 test split precision is
   0.982 at t=0.5. At a realistic 1% base rate it is **0.357**, and at 0.1%
   **0.052**. Never quote the 50% number on its own.

3. **Scores are not calibrated.** The model is strongly bimodal; few files score
   in the middle, so 0.55 does not mean 55%. This is why verdicts are banded.
   Isotonic or Platt calibration on a held-out time slice is still to do.

4. **Toolchain bias.** Benign corpus files skew MSVC. MinGW/GCC, Rust and Go
   binaries (no Rich header, unsigned, different section layout) will be
   over-scored. There is no held-out clean-MinGW set, so this is not yet
   measurable. `a.exe` (MinGW-built) is a live example: it scores 0.55, which
   is now correctly reported as INCONCLUSIVE rather than MALICIOUS.

5. **Shortcut-heavy features.** The largest gain shares are `datadirectories`
   (36%), `strings` (15%), `authenticode` (13%) and `exports` (11%), and those are
   the cheapest fields for an attacker to change — see the full table above. No
   ablation or perturbation experiment has been run, so the share of accuracy
   surviving adversarial modification is unknown.

6. **Memorisation risk.** `num_leaves=1024` with train AUC exactly 1.0. A
   regularised model would very likely generalise better.

### Work not yet done

Retraining is **not possible in this checkout**: `ml/data/vectors/` is absent, so
all of the following need `vectorize.py` re-run against the corpus first.

- Deduplicate before training, then use more of the ~1.04M available Win64 rows.
- Time-based split by weekly chunk instead of a random split.
- Train on part of the challenge set, split by week.
- Group ablations; monotonic constraints or perturbation robustness.
- Regularised parameters with early stopping on a time-based validation slice.
- Per-family analysis for the error clusters (wacatac, sleepobf, fakecert).
- Benign MinGW/Rust/Go binaries in training, or a held-out clean-MinGW set.
- C++/thrember parity tests over a few thousand files.

The evasion weakness (50.2% caught at t=0.5) is the most important open item. It
is a property of the training data, not of the reporting, and cannot be fixed
without retraining on challenge weeks.

## VM sizing for Win64

`X_train` is 520,000 x 2,568 float32 ~= 5 GB, and LightGBM's binned Dataset adds
its own copy.

| RAM | Notes |
|---|---|
| 16 GB | works, vectorize and train as separate steps |
| 32 GB | comfortable |
| 8 GB | use `--limit` for a smoke run, or pick ELF/PDF (small) |

CPU-only is fine; `device_type` stays `cpu` and `num_threads: 0` uses all cores.
No GPU is required or used.

## License

EMBER2024 and `thrember` are Apache-2.0. Training on them and redistributing the
resulting model is permitted. Attribute the dataset and include a NOTICE file if
you ship the model.

## Files

| File | Purpose |
|---|---|
| `download_dataset.py` | HuggingFace download, size/CRC verification, optional extract |
| `vectorize.py` | pickles -> `X_*.npy` / `y_*.npy` / `meta_*.jsonl` |
| `vectorize_jsonl.py` | same, streaming the weekly JSONL chunks without unpickling |
| `train.py` | LightGBM training, evaluation, model + metrics output |
| `predict.py` | score a file; `--check` verifies the analyzer's vectors |
| `serve.py` | local scoring API (`/score`, `/score/vector`, `/score/batch`) |
| `evaluate_report.py` | charts + CSV: metrics, error analysis, corpus composition and pandas dataset profile |
| `report_pdf.py` | renders the PDF report, one directory per report |
| `templates/report.html.j2` | the report template |
| `mllog.py` | shared logging: UTC-stamped file under `logs/`, stdout/stderr console split |
| `requirements.txt` | dependencies |
| `model.txt` | trained booster (500 trees, 2,568 features) |
| `report/` | `evaluate_report.py` output (shared inputs) + one directory per report |
