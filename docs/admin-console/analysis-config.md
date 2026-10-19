# Analysis configuration

<!-- Source: README.md, split by topic. -->

#### Analysis configuration

`GET /api/analysis/config` reads the two files that decide what an analysis run
does, and shows them as the analyzer itself understands them:

- **`pipelines/*.yaml`** — every named pipeline: description, stages, declared
  phases, `environment:` exports, and the raw file with PyYAML-coloured YAML.
- **`config/artifacts.yaml`** — `store_artifact`, `upload_artifacts` (the MEGA
  upload), `remote_root`, `timeout_seconds`, and the `mega/upload.py` uploader
  the analyzer resolves alongside them.

**Declared phases and run order are shown separately, because they differ.** The
planner inserts a prerequisite immediately before the phase that needs it, and
appends `export` and `summary` when a config omits them, so `quick.yaml` — three
phases on disk — runs five. Inserted phases are drawn dashed with a `+`, which
is the difference between reviewing a config and running it.

**The phase catalog is the analyzer's, not a copy.** Which names a pipeline may
use comes from the analyzer's own `GET /phases`, cached in `server.py` from
`static_analyzer --list-phases --json`. That is what turns the page into a check:
a phase name the binary does not know is an exit code 2, and a pipeline naming
one is listed as *rejected* with the reason attached rather than silently
omitted. The same rules are applied to `config/artifacts.yaml`, whose loader
accepts exactly four keys and rejects the rest. With the analyzer down the
catalog is absent, the phase check is skipped, and the page says *analyzer
offline — names unvalidated* rather than validating against a list that may be
out of date.

`environment:` values whose name looks like a credential are masked before they
leave the process, using the same rules `redact::is_secret_name()` applies
(`src/core/redact.cpp`). A pipeline that exports a CTI key can be reviewed here
without the console becoming the place the key is written down.

#### Options the console can write

Four routes write, and they are the only routes in the panel that change a file
the analyzer reads:

| route | writes | notes |
| --- | --- | --- |
| `POST /api/analysis/artifact-options` | the four keys in `config/artifacts.yaml` | only the keys in the body |
| `POST /api/analysis/pipeline/environment` | `environment:` in one pipeline | a flag set false *removes* the key |
| `POST /api/analysis/pipeline/rush` | the phase lists in one pipeline | reversible; see below |
| `POST /api/analysis/pipeline` | a new `pipelines/<name>.yaml` | never overwrites |

Three properties hold for all of them, and they are what make a toggle on a
config file safe to offer at all:

- **The text is edited, not the parse tree.** A key is replaced in place, so the
  comments in `config/artifacts.yaml` — which are the file's documentation —
  survive byte for byte. PyYAML's round trip would strip them.
- **The result is validated before it lands.** The edited text is re-parsed with
  the same loader the analyzer uses and checked against the analyzer's own rules.
  An edit that would not parse, or that names a phase the binary does not know,
  is refused and the file is left alone.
- **Nothing arbitrary crosses the wire.** Only allowlisted keys with typed
  values; which file, which key and what counts as valid are never taken from the
  request.

Line endings and a BOM are preserved per file, because a save that rewrote CRLF
as LF would show as a whole-file change in every diff — including the case where
the edit was a no-op.

#### Only options the analyzer actually reads

The `environment:` controls are the ten variables the binary reads, each shown
with the source line that reads it: `CTI_SKIP` (`phase_cti.cpp:36`), `ML_SKIP`
(`main.cpp:291`), `ML_EXPLAIN` and `ML_THRESHOLD` and `ML_TOP_K`
(`phase_ml.cpp:96-98`), `CTI_CONFIG` (`phase_cti.cpp:176`),
`STATIC_ANALYZER_CURSES` (`main.cpp:219`), `IA_ALLOW_CORE_DUMP`
(`resume.cpp:246`), `IA_CONTINUE_ON_SIGNAL` (`resume.cpp:246`) and `TRACE_FILE`
(`trace.cpp:21`).
That reference is rendered under each control on purpose: the panel is making a
claim on the operator's behalf, so the claim should be checkable rather than
trusted. An option nothing reads is not offered — a switch that does nothing is
worse than no switch. Inherited defaults are displayed but not written: a
pipeline that never mentions `ML_EXPLAIN` still gets SHAP, because that is the
binary's default, and the file is left saying nothing about it until somebody
changes it.

That claim is enforced, not just asserted.
`unit/python/test_panel_env_options.py` walks `ENV_OPTIONS` and fails if a key
appears nowhere under `src/` or `include/`, if a `honoured_by` reference points
at a line that does not exist, or if a control is offered for a key the binary
ignores. Adding a checkbox therefore cannot outrun the code that reads it.

The last two are read once in `main.cpp`, in the narrow window after
`apply_environment()` has put the pipeline's `environment:` block into the
process and before the handlers are installed. Both are off by default.

`IA_ALLOW_CORE_DUMP` goes to `crash::install()` and widens the dump written when
the process dies. `IA_CONTINUE_ON_SIGNAL` goes to `resume::install()`'s module
instead, because it is about the pipeline rather than about a fault: with it set,
the first Ctrl+C is absorbed and the run carries on to the next phase, and only
a second one stops it. [Failure handling](../failure-and-recovery.md#carrying-on-when-the-run-is-interrupted)
explains both, and why the second interrupt is still honoured.

A name that looks like a credential is refused outright, even before the
allowlist: the vault and `.env` are where those belong, and a browser form is
not.

#### Phase rush

`phase_rush` is triage — run the cheap local phases and drop the ones that
dominate wall clock on a shared box: `radare2`, `graphs`, `xref`, `capa`,
`cminer`, `recovery`, `hexdump`, `cti` and `model`. `extraction` is deliberately
kept: it is fast, it produces the carved blob inventory, and dropping it would
silently change the report for every run that did not ask for rush.

Applying it records each original list as a comment directly above the list it
trimmed:

```yaml
  - name: threat-intel
    # phase-rush: [cti]
    phases: []
```

That marker is what makes undoing it exact rather than a guess — no needing the
panel to remember which stage a phase belonged to — and what explains an empty
stage to whoever reads the YAML next, where a mysteriously empty stage would not.
The round trip is byte-identical on a file this panel did not otherwise change.
Two cases are refused rather than half-applied: a pipeline with none of the slow
phases (nothing to remove), and a one-phase pipeline that consists *only* of slow
phases (nothing would be left to run).

Only inline `phases: [...]` lists are edited. A pipeline written with block-style
lists is refused with an explanation rather than rewritten blind.

#### Authoring

The **New pipeline** tab builds one from the analyzer's own phase catalog, so the
admin picks from exactly the set the binary will accept — a name that is not in
that catalog is an exit code 2, and this is where that is worth catching. The
steps are not a hardcoded list; they arrive from `GET /phases`, which the
analyzer serves from `--list-phases --json`.

Order *is* the pipeline, so the selection is a numbered list with move up/down
rather than a set, and "Recommended order" restores the catalog's own order —
the classic 27-phase order, which is the one ordering known to work end to end.
**Triage preset** fills the selection with everything phase-rush does not drop,
because "run it fast" is a question with a known answer on this page.

The wizard shows the **resolved** run order while you build, not just the
selection: picking `hexdump` shows `extraction` being inserted before it and
`export`/`summary` appended, so a list of three steps that runs six is visible
rather than a surprise. The same closure the planner performs is shown on the
client for the preview and recomputed server-side for the file — the preview is
a convenience, the saved file is authoritative.

Options the admin sets are written into `environment:`; options left alone are
omitted entirely, because a block full of defaults is noise that has to be
re-read every time the file is opened. Descriptions are emitted as
double-quoted scalars and comments are stripped of `#`, because free text typed
into a browser box otherwise produces YAML that does not parse. An existing name
is refused rather than overwritten, because an existing pipeline is someone's
work. Running a pipeline stays a CLI action for the same reason as everywhere
else on this console.

#### Generating YARA rules (`yara_gen`)

`yara` and `yara_gen` answer opposite questions, and the names are easy to
conflate:

* **`yara`** — does this sample match a rule that already exists?
* **`yara_gen`** — what rule *would have* caught it?

The packs in `yara-rules/` are last year's malware. `yara_gen` is how the next
one gets written, using [yarGen-Go](https://github.com/Neo23x0/yarGen-Go).

It is a **phase, opt-in per pipeline**, so the choice is the checkbox in the
**New pipeline** wizard. It is deliberately never auto-inserted and never in a
default pipeline: it takes 100s+ on a small sample, it needs a tool nothing else
depends on, and its output is a rule set an analyst still has to review. What it
generates is written to `yara_gen/<stem>_generated.yar` beside the other
artifacts, and `run_summary.json` records the count, the author, whether the
LLM pass ran, and `"reviewed": false`.

It works with **no API key**. yarGen refuses to start without
`yarGen-Go/config/config.yaml`, which is only an LLM key holder, so the wrapper
passes `-no-llm` when there is no config and says so in the output. Rules are
still generated from strings and opcodes; only the LLM enrichment is lost, and
`llm_used: false` in the manifest records that they are weaker than the tool can
produce.

Two things the wrapper handles that are not obvious:

**yarGen resolves `./dbs` relative to the working directory**, not to its own
location. Run it from anywhere else and it reports
`failed to read database directory ./dbs`, which reads like a missing download
rather than the wrong directory. `python/yara_gen.py` pins the cwd.

**Author and identifier are passed explicitly.** Left to its defaults yarGen
writes `yarGen` as the author on every rule, and a rule set attributed to nobody
is one nobody will maintain.

Environment overrides: `YARGEN_PYTHON`, `YARGEN_TIMEOUT` (default 600s),
`YARGEN_AUTHOR`, `YARGEN_IDENTIFIER`.

