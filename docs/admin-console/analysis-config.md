# Analysis configuration

<!-- Source: README.md, split by topic. -->

#### Analysis configuration

The machine-wide layer: `config/analysis.yaml`, the file that decides what an
analysis does on *this* machine regardless of which pipeline is selected. The
per-pipeline layer is a different page —
[Pipelines Configuration](pipelines-configuration.md) — and the two never offer
the same key.

`GET /api/analysis/settings` reads the file; `PUT /api/analysis/settings` writes
it. Both are the panel's own pair of routes for this one file, alongside the
pipeline page's four.

## Why the two layers are not equal

```
binary default  <  .env / shell  <  pipeline `environment:`  <  config/analysis.yaml
```

The analyzer applies this file **after** the selected pipeline
(`apply_environment()` then `apply_analysis_settings()` in `main.cpp`), so a key
set here is not outvoted by a pipeline that pins the same one.

That inversion is the reason the file exists at all. The settings were
per-pipeline first, and that turned out to be the wrong shape: `pipelines/
default.yaml` shipped `ML_SKIP: 1` and `CTI_SKIP: 1`, so the default analysis
silently never ran the model or the enrichment — decided by nobody, in a place
designed for per-run differences, and unreachable from the environment.

The consequence for this page is that a key set here is **final** for that key.
A pipeline can still set anything this file does not mention, which is how a
one-off run turns CTI on for an investigation and off again afterwards, but a key
it *does* mention cannot be overridden from there. See
[a key belongs to one layer](pipelines-configuration.md#a-key-belongs-to-one-layer).

## "Not set" is a third state

A toggle reads as on/off, and that is the trap. Absent is not off:

| state | what a run does |
| --- | --- |
| set here | this value, for every run, overriding the pipeline |
| not set here | the pipeline's value, else `.env` / shell, else the binary default |
| set here to `false` | **not** the pipeline's value — an explicit global off |

So every control states which of the three it is, and clearing is a real action
with its own button — *Follow the pipeline* on a flag, *Clear* on a value.
Writing `false` is not the same as clearing, and the difference is the whole
reason the third state is shown rather than inferred.

## The file

```yaml
# Precedence, lowest to highest:
#     .env / shell   <   pipeline `environment:`   <   this file
ML_SKIP: "1"
CTI_SKIP: "1"
ML_THRESHOLD: "0.7"
```

An **unknown key is a startup error, not a warning** — exit code 2, before any
work happens. Silently ignoring one would leave an operator who mistyped `ML_SKP`
believing they had skipped the model. The console reports such a key in a red
alert on this page, and refuses to delete it on a save: the analyzer's refusal is
its call to make, and the panel's job is to say why the next run will not start.

Only the keys the analyzer actually reads are accepted, and the console only
offers those nineteen — the same list, described once and checked by
`unit/python/test_panel_env_options.py`, which fails if the panel and the C++
loader ever drift apart.

The nineteen arrive on this page grouped to match what they decide: the
phase-scoped CTI/ML keys, the process behaviour flags and values (curses, core
dumps, interrupt handling, the trace file and its `ENABLE_TRACING` hard-off,
the `IA_INTERRUPT_IF_PACKED` tripwire with its entropy threshold), and a
**MEGA upload and sealing** section of its own - the six keys that used to live
only in `config/artifacts.yaml`. That file keeps working, but where one of the
six is set here it wins, and the analyzer's log names which file decided. A
third card, **Evidence bundle**, holds the one artifact option that never
migrated: `store_artifact` - deliberately file-only, because building a local
bundle is not a per-machine transfer decision - edited through the artifact
writer the other page keeps.

Where a setting is decided is one question, so the whole upload decision lives
on this page and nowhere else: the Pipelines Configuration page removed its
upload tab rather than keep a second set of controls that could quietly
disagree with this one.

A name that looks like a credential is refused outright, even before the
allowlist: the vault and `.env` are where those belong, and a browser form is
not.

## Editing it

The same three properties the pipeline writer holds to, because they are what
make a toggle on a config file safe to offer at all:

- **The text is edited, not the parse tree.** This file's comments explain the
  precedence — stripping them on the first save would leave the next person to
  edit it with no idea which way the layering goes.
- **The result is validated before it lands**, with the same rules the analyzer
  applies. A save that would produce a config the analyzer refuses is refused,
  and the file is left alone.
- **Only the keys sent are touched**, so two people editing different settings
  cannot clobber each other by submitting a stale copy of the whole form.

Line endings and a BOM are preserved per file, because a save that rewrote CRLF
as LF would show as a whole-file change in every diff — including when the edit
was a no-op.

## The hardening and bundle cards do not edit this file

The page also carries two cards that are *not* `config/analysis.yaml`:

- **Evidence bundle** edits `store_artifact` in `config/artifacts.yaml` — a
  run-time file read by `load_artifact_options()`, and the one artifact key
  with no MEGA twin.
- **Hardening** edits `config/hardening.json` — the four compiler protection
  switches — and its values reach a build, not a run.

Both are here because they answer the same standing question the rest of the
page does (*how is this machine's analysis configured?*). See
[build.md § Binary hardening](build.md#binary-hardening) for the hardening
settings themselves and the requested-vs-present comparison.

Two consequences worth stating, because the files are easy to conflate:

- A hardening change takes effect at the **next build**. Nothing on this page
  changes a run already in progress, and nothing on the hardening card changes
  a run at all.
- Clearing a key here hands it back to **Pipelines Configuration**. That rule
  covers `analysis.yaml` and `artifacts.yaml` keys only; the hardening switches
  have no second location to fall back to, and are simply on or off.

## Where it is read

Once at startup, by `src/main/analysis_config.cpp`, searching `config/` beside
the working directory, then beside the executable, then one level above it — the
same search shape `config/artifacts.yaml` uses, so a packaged build finds the
config it shipped with.

Changes apply to the **next** run. A run already in progress has read them.

### One gap worth knowing about

`config/analysis.yaml` is not copied by the build. The POST_BUILD step in
`CMakeLists.txt` copies `pipelines/`, `config/artifacts.yaml` and the `mega/`
modules beside the executable, and `install()` does the same, but this file is in
neither. Since a missing file is a silent no-op by design, a binary run from
outside the source tree gets its pipelines and its artifact options and
**no global settings at all** — and nothing says so, because "absent" is
supposed to be quiet.