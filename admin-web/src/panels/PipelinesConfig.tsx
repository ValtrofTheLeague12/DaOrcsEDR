import { useEffect, useMemo, useState } from 'react'
import { Alert } from '@heroui/react/alert'
import { Button } from '@heroui/react/button'
import { Card } from '@heroui/react/card'
import { Chip } from '@heroui/react/chip'
import { api, usePoll } from '../api'
import Icon from '../components/Icon'
import CopyButton, { useCopy } from '../components/CopyButton'
import Loading from '../components/Loading'
import PipelineWizard from '../components/PipelineWizard'
import SubNav from '../components/SubNav'
import { StatTile } from '../components/Stat'
import Switch, { OptionField } from '../components/Switch'
import YamlView from '../components/YamlView'
import { ago } from '../lib/format'
import { useMinuteTick } from '../lib/tick'
import type {
  AnalysisConfig,
  EnvOption,
  PhaseInfo,
  PipelineConfig,
  YargenState,
} from '../types'

// ---------------------------------------------------------------------------
// Pipelines Configuration - what the analyzer will run, before it runs it.
//
// This page replaces the "Analyze" placeholder that used to sit in the Analysis
// group. It was never going to be a run button: starting an analysis is a
// subprocess that writes exports/ and can upload to MEGA, which is the same
// line the rest of the panel draws (see the comments on api.artifactArchiveUrl
// and api.vmAction). What is worth showing is the configuration those runs read,
// because it lives in two YAML files and nothing else on the console explains
// either of them.
//
// Everything here is read-only and comes from the same files the analyzer reads:
//
//   pipelines/*.yaml      which phases run, in which order
//   config/artifacts.yaml bundle the evidence, upload it to MEGA, where to
//
// One thing on this page is NOT a file read: the list of phase names a pipeline
// may use. That comes from the analyzer's own GET /phases, cached in server.py
// from `static_analyzer --list-phases --json`, and it is what turns this page
// from a file browser into a check - a phase name the binary does not know is
// an exit code 2, and the page can say so before anyone runs it.
//
// Authoring a new pipeline is therefore an editor, not a form. The builder in
// the Pipelines tab renders YAML in the browser for you to copy into
// pipelines/<name>.yaml, because the file is the interface: the analyzer reads
// that same file with the same loader, so there is no second format to keep in
// sync and no state here that can disagree with what will run.
//
// One thing this page deliberately does NOT offer. `config/analysis.yaml` is the
// machine-wide layer and it wins over anything set here:
//
//     .env / shell   <   pipeline `environment:`   <   config/analysis.yaml
//
// So an option the global file defines has no editable control here - it is shown
// read-only, pointing at Analysis Configuration. It is not hidden, because "why
// can I not turn ML off on this pipeline" is answered by pointing, not by an
// absence. The backend refuses the same writes, so the rule holds for the YAML
// tab and the wizard as well as for these controls.
// ---------------------------------------------------------------------------

// Configuration, not telemetry: a poll this fast would only re-read the same
// bytes. 60s keeps the catalog (which needs the analyzer to be up) roughly
// current without being a spin loop, and the manual Refresh is there for the
// moment someone has just edited a YAML.
const INTERVAL = 60_000

type Tab = 'pipelines' | 'create' | 'phases'

// --- small pieces ---------------------------------------------------------

function StatusChip({ pipeline }: { pipeline: PipelineConfig }) {
  if (!pipeline.ok) {
    return (
      <Chip size="sm" variant="soft" color="danger" title={pipeline.error}>
        rejected
      </Chip>
    )
  }
  if (pipeline.phase_check === 'unavailable') {
    return (
      <Chip size="sm" variant="soft" color="warning" title="analyzer offline: phase names not checked">
        unchecked
      </Chip>
    )
  }
  return <Chip size="sm" variant="soft" color="success">valid</Chip>
}

/** The command an operator runs to use this pipeline. Copyable, because the
 *  whole point of the name is that it is typed on a command line. */
function CommandLine({ value }: { value: string }) {
  const { copied, copy } = useCopy()
  return (
    <button
      type="button"
      onClick={() => void copy(value)}
      className="flex w-full items-center gap-2 rounded-lg border border-default-200 bg-default-50/60 px-3 py-2 text-left transition-colors hover:border-accent/40"
      title="Copy"
    >
      <Icon name="terminal" size={13} className="shrink-0 text-default-400" />
      <code className="metric flex-1 truncate font-mono text-[11px] text-foreground">{value}</code>
      <Icon name={copied ? 'check' : 'copy'} size={12} className={copied ? 'text-success' : 'text-default-400'} />
    </button>
  )
}

/** One phase chip. `inserted` marks a phase the planner adds by itself, which
 *  is the distinction this page exists to make visible. */
function PhaseChip({
  name,
  inserted,
  title,
  onClick,
}: {
  name: string
  inserted?: boolean
  title?: string
  onClick?: () => void
}) {
  const body = (
    <span
      className={`metric inline-flex items-center gap-1 rounded-md border px-1.5 py-0.5 font-mono text-[10px] ${
        inserted
          ? 'border-dashed border-accent/50 bg-accent/8 text-accent'
          : 'border-default-200 bg-default-50 text-default-600'
      }`}
    >
      {inserted && <Icon name="plus" size={9} className="opacity-70" />}
      {name}
    </span>
  )
  return onClick ? (
    <button type="button" onClick={onClick} title={title}>
      {body}
    </button>
  ) : (
    <span title={title}>{body}</span>
  )
}

// --- pipelines ------------------------------------------------------------

function PipelineList({
  pipelines,
  selected,
  onSelect,
}: {
  pipelines: PipelineConfig[]
  selected: string | null
  onSelect: (name: string) => void
}) {
  if (pipelines.length === 0) {
    return (
      <Card className="w-full">
        <Card.Content className="py-8 text-center text-[11px] text-default-500">
          No pipeline files in <code className="font-mono">pipelines/</code>.
        </Card.Content>
      </Card>
    )
  }
  return (
    <Card className="w-full">
      <Card.Header className="flex items-center justify-between gap-3">
        <Card.Title className="text-sm font-semibold">Pipelines</Card.Title>
        <Chip size="sm" variant="soft">{pipelines.length}</Chip>
      </Card.Header>
      <Card.Content className="flex flex-col gap-1 p-2">
        {pipelines.map((p) => {
          const on = p.name === selected
          return (
            <button
              key={`${p.file}:${p.name}`}
              type="button"
              onClick={() => onSelect(p.name)}
              className={`flex items-start gap-2.5 rounded-lg px-2.5 py-2 text-left transition-colors ${
                on ? 'bg-accent/10 ring-1 ring-accent/30' : 'hover:bg-default-100'
              }`}
            >
              <span
                className={`mt-1 h-2 w-2 shrink-0 rounded-full ${
                  p.ok ? 'bg-success' : 'bg-danger'
                }`}
                title={p.ok ? 'valid' : p.error}
              />
              <span className="min-w-0 flex-1">
                <span className="flex items-baseline gap-2">
                  <span className="truncate font-mono text-[12px] font-semibold text-foreground">{p.name}</span>
                  <span className="shrink-0 font-mono text-[9px] text-default-400">{p.phases.length} phases</span>
                </span>
                <span className="mt-0.5 block truncate text-[11px] text-default-500">
                  {p.description || p.file}
                </span>
              </span>
            </button>
          )
        })}
      </Card.Content>
    </Card>
  )
}

function PipelineDetail({ pipeline, catalog }: { pipeline: PipelineConfig; catalog: PhaseInfo[] }) {
  const byName = useMemo(() => new Map(catalog.map((p) => [p.name, p])), [catalog])
  const lineCount = pipeline.content.split('\n').length

  return (
    <div className="flex min-w-0 flex-col gap-3">
      <Card className="w-full">
        <Card.Header className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0">
            <Card.Title className="font-mono text-sm">{pipeline.name}</Card.Title>
            <p className="mt-1 text-[11px] text-default-500">
              {pipeline.description || 'No description in the file.'}
            </p>
            <p className="mt-1 font-mono text-[10px] text-default-400">
              {pipeline.file} · edited {ago(pipeline.mtime)}
            </p>
          </div>
          <StatusChip pipeline={pipeline} />
        </Card.Header>

        <Card.Content className="flex flex-col gap-3">
          {!pipeline.ok && pipeline.error && (
            <Alert status="danger">
              <Alert.Title>The analyzer will refuse this file</Alert.Title>
              <Alert.Description>
                <code className="font-mono text-[11px]">{pipeline.error}</code>
              </Alert.Description>
            </Alert>
          )}

          <CommandLine value={`static_analyzer --pipeline ${pipeline.name} sample.exe`} />

          {pipeline.stages.length > 0 && (
            <div>
              <p className="section-label mb-1.5">Declared</p>
              <div className="flex flex-col gap-1.5">
                {pipeline.stages.map((stage, i) => (
                  <div className="flex items-start gap-2" key={`${stage.name}:${i}`}>
                    <span className="metric w-28 shrink-0 truncate pt-0.5 font-mono text-[10px] text-default-400">
                      {stage.name || '—'}
                    </span>
                    <div className="flex flex-wrap gap-1">
                      {stage.phases.length === 0 ? (
                        <span className="text-[11px] text-default-400">no phases</span>
                      ) : (
                        stage.phases.map((phase) => (
                          <PhaseChip
                            key={phase}
                            name={phase}
                            inserted={false}
                            title={byName.get(phase)?.description}
                          />
                        ))
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          <div>
            <p className="section-label mb-1.5">
              Run order
              <span className="ml-1.5 font-normal normal-case tracking-normal text-default-400">
                {pipeline.inserted.length > 0
                  ? 'inserted by the planner, dashed'
                  : 'as declared'}
              </span>
            </p>
            <div className="flex flex-wrap gap-1">
              {pipeline.resolved.map((phase, i) => (
                <PhaseChip
                  key={`${phase}:${i}`}
                  name={phase}
                  inserted={pipeline.inserted.includes(phase)}
                  title={byName.get(phase)?.description}
                />
              ))}
            </div>
            {pipeline.inserted.length > 0 && (
              <p className="mt-1.5 text-[10px] text-default-400">
                <code className="font-mono">{pipeline.inserted.join(', ')}</code>{' '}
                {pipeline.inserted.length === 1 ? 'was' : 'were'} added automatically: missing
                prerequisites are inserted before what needs them, and export/summary close
                the run.
              </p>
            )}
          </div>

          {pipeline.environment.length > 0 && (
            <div>
              <p className="section-label mb-1.5">Environment</p>
              <dl className="compose-kv">
                {pipeline.environment.map((env) => (
                  <div className="compose-kv-row" key={env.key}>
                    <dt title={env.key}>{env.key}</dt>
                    <dd className="font-mono text-[11px]">
                      {env.secret ? (
                        <span className="text-default-400" title="masked: the analyzer treats this name as a credential">
                          {env.value}
                        </span>
                      ) : (
                        env.value
                      )}
                      {/* Not a different value - a different truth. config/
                          analysis.yaml is applied after this pipeline, so this
                          line is read and discarded, and a file that says one
                          thing while the run does another is worth naming. */}
                      {env.shadowed && (
                        <span
                          className="ml-1.5 rounded border border-default-200 px-1 text-[9px] text-default-400"
                          title="config/analysis.yaml sets this key too, and the analyzer applies that file after this pipeline - so this value does not apply. Remove the line to keep the file honest."
                        >
                          overridden globally
                        </span>
                      )}
                      {/* The other way a line can be inert: nothing is
                          overriding it, but the phase it belongs to is not in
                          this pipeline's plan, so the value is read and used
                          by nothing. Same treatment as shadowed, because it is
                          the same kind of truth. */}
                      {env.irrelevant && !env.shadowed && (
                        <span
                          className="ml-1.5 rounded border border-default-200 px-1 text-[9px] text-default-400"
                          title="This key affects a phase this pipeline does not run, so the value is read and used by nothing. Remove the line to keep the file honest."
                        >
                          unused here
                        </span>
                      )}
                    </dd>
                  </div>
                ))}
              </dl>
              <p className="mt-1.5 text-[10px] text-default-400">
                Exported into the process before any phase runs, so child services inherit it.
                Values whose name looks like a credential are masked here.
              </p>
            </div>
          )}
        </Card.Content>
      </Card>

      <Card className="w-full overflow-hidden">
        <Card.Header className="flex items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <Icon name="file-code" size={15} className="text-default-400" />
            <Card.Title className="text-sm font-semibold">{pipeline.file}</Card.Title>
          </div>
          <div className="flex items-center gap-2">
            <Chip size="sm" variant="soft">{lineCount} lines</Chip>
            <CopyButton text={pipeline.content} />
          </div>
        </Card.Header>
        {/* flex-col + max-h, not overflow-hidden: .compose-viewer-pane is the
            scroll container (flex:1, min-height:0), so the pane scrolls inside a
            capped box instead of the content being clipped at the cut. */}
        <div className="flex max-h-[26rem] flex-col border-t border-default-200">
          <YamlView content={pipeline.content} spans={pipeline.spans} />
        </div>
      </Card>
    </div>
  )
}

function PipelinesTab({
  data,
  onSaved,
  selected,
  onSelect,
  yargen,
}: {
  data: AnalysisConfig
  onSaved: () => void
  /** Lifted to the page so a pipeline created in the wizard can be selected. */
  selected: string | null
  onSelect: (name: string) => void
  /** yarGen-Go's readiness, fetched separately from /api/utils. */
  yargen: YargenState | null
}) {
  // Selection is by name, not index: a poll that adds or removes a file must not
  // silently re-point the detail pane at a different pipeline.
  const current = useMemo(
    () => data.pipelines.find((p) => p.name === selected) ?? data.pipelines[0] ?? null,
    [data.pipelines, selected],
  )

  useEffect(() => {
    if (selected && !data.pipelines.some((p) => p.name === selected)) onSelect('')
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [data.pipelines, selected])

  return (
    <div className="grid grid-cols-1 gap-3 xl:grid-cols-[300px_1fr]">
      <PipelineList pipelines={data.pipelines} selected={current?.name ?? null} onSelect={onSelect} />

      <div className="flex min-w-0 flex-col gap-3">
        {current ? (
          <>
            <PipelineDetail pipeline={current} catalog={data.phases.items} />
            <PipelineOptions
              pipeline={current}
              /* Per pipeline, from the backend: relevance is decided against
                 the plan the analyzer will run, which the panel cannot recompute
                 without the catalog it may not have. */
              options={current.options ?? data.options}
              globalSettings={data.global_settings}
              yargen={yargen}
              onSaved={onSaved}
            />
          </>
        ) : (
          <Card className="w-full">
            <Card.Content className="py-8 text-center text-[11px] text-default-500">
              Nothing to show - there are no pipeline files in{' '}
              <code className="font-mono">{data.pipelines_dir}</code>.
            </Card.Content>
          </Card>
        )}
      </div>
    </div>
  )
}

/**
 * A setting config/analysis.yaml owns, drawn instead of offered.
 *
 * The analyzer applies the global file after this pipeline, so a pipeline page
 * has no control for such a key: a value set here would be a value that does
 * not happen. The pipeline's own line for the key, if it has one, is shown
 * struck through beside the global value that actually applies - with a remove
 * button, because cleanup should not require a text editor.
 */
function GlobalOptionCard({
  opt,
  globalValue,
  pipelineValue,
  onRemove,
  pending,
}: {
  opt: EnvOption
  /** What config/analysis.yaml sets; the caller only renders the card when set. */
  globalValue: string
  pipelineValue: string | undefined
  onRemove?: () => void
  pending?: boolean
}) {
  return (
    <div className="rounded-md border border-dashed border-default-300 px-3 py-2">
      <div className="flex items-baseline justify-between gap-2">
        <span className="text-[12px] text-default-500">{opt.label}</span>
        <Chip size="sm" variant="soft" color="accent">
          set globally
        </Chip>
      </div>
      <p className="mt-1 font-mono text-[11px] text-accent-400">
        {opt.key} = {globalValue}
      </p>
      {pipelineValue !== undefined && (
        <p className="mt-1 flex flex-wrap items-center gap-x-2 font-mono text-[11px]">
          <span
            className="font-mono text-[11px] text-default-400 line-through"
            title={`This pipeline says ${pipelineValue}. The analyzer applies the global file afterwards, so this line has no effect - remove it to keep the file honest.`}
          >
            {opt.key} = {pipelineValue} — inert here
          </span>
          {onRemove && (
            <button
              type="button"
              className="build-link"
              disabled={pending}
              onClick={onRemove}
            >
              {pending ? 'Removing…' : 'Remove this line'}
            </button>
          )}
        </p>
      )}
      <p className="mt-1 text-[11px] text-default-500">
        Applies to this pipeline and every other one. Change it on Analysis
        Configuration; this page cannot, because the global value wins.
      </p>
    </div>
  )
}

/**
 * The writable half of a pipeline: the environment options.
 *
 * It writes into the file the analyzer reads rather than into panel state, so
 * what the console shows is what the next run will do. Every control here sends
 * a key the server allowlists and the analyzer actually reads - the reason each
 * one carries its source line - and the server re-parses the result before it
 * replaces anything.
 *
 * The one exception is `globalSettings`: a key config/analysis.yaml owns has no
 * control here at all. See GlobalOwnedOption.
 */
function PipelineOptions({
  pipeline,
  options,
  globalSettings,
  yargen,
  onSaved,
}: {
  pipeline: PipelineConfig
  options: EnvOption[]
  globalSettings: Record<string, string>
  yargen: YargenState | null
  onSaved: () => void
}) {
  const [pending, setPending] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [note, setNote] = useState<string | null>(null)

  const declared = useMemo(() => new Map(pipeline.environment.map((e) => [e.key, e.value])), [pipeline.environment])

  // Effective value = what the file says, else what the binary defaults to. The
  // inherited value is shown but not stored, so a pipeline that never mentions
  // ML_EXPLAIN is not rewritten to say what it was already doing.
  const effective = (opt: EnvOption): boolean | number | string => {
    const raw = declared.get(opt.key)
    if (raw === undefined) return opt.default ?? (opt.kind === 'number' ? 0 : '')
    if (opt.kind === 'flag') return raw === '1' || raw === 'true'
    if (opt.kind === 'number') return Number(raw)
    return raw
  }

  const [draft, setDraft] = useState<Record<string, boolean | number | string>>({})
  useEffect(() => {
    setDraft(Object.fromEntries(options.map((o) => [o.key, effective(o)])))
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [pipeline.name, pipeline.mtime, options])

  const send = async (
    key: string,
    body: () => Promise<unknown>,
    successNote: string,
  ) => {
    setPending(key)
    setError(null)
    setNote(null)
    try {
      await body()
      setNote(successNote)
      onSaved()
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
      // Re-seed from the file: the write was refused, so what is on disk is
      // still the truth and the control must go back to showing it.
      setDraft(Object.fromEntries(options.map((o) => [o.key, effective(o)])))
    } finally {
      setPending(null)
    }
  }

  const writeEnv = (opt: EnvOption, value: boolean | number | string) =>
    send(
      opt.key,
      () => api.setPipelineEnvironment(pipeline.name, { [opt.key]: value }),
      `${opt.label} saved to ${pipeline.file}.`,
    )

  // Only run-wide options reach this component, which is the list's whole
  // point: the CTI and ML options are machine-wide - Analysis Configuration
  // owns them - so no pipeline page carries a control or a card for one. What
  // this page keeps instead of those controls is reportage: a stale line for
  // one of those keys in this file still shows in the environment block, badge
  // attached, and a write is refused whichever way it is phrased.
  const removeLine = (opt: EnvOption) =>
    send(
      opt.key,
      () => api.setPipelineEnvironment(pipeline.name, { [opt.key]: null }),
      `${opt.key} removed from ${pipeline.file}.`,
    )

  const renderOption = (opt: EnvOption) => {
    const globalValue = globalSettings[opt.key]
    if (globalValue !== undefined) {
      return (
        <GlobalOptionCard
          key={opt.key}
          opt={opt}
          globalValue={globalValue}
          pipelineValue={declared.get(opt.key)}
          onRemove={declared.has(opt.key) ? () => removeLine(opt) : undefined}
          pending={pending === opt.key}
        />
      )
    }

    const value = draft[opt.key] ?? effective(opt)
    const inherited = !declared.has(opt.key)
    const dirty =
      opt.kind === 'text' || opt.kind === 'number'
        ? String(value) !== String(effective(opt))
        : value !== effective(opt)

    const control =
      opt.kind === 'flag' ? (
        <Switch
          label={opt.label}
          checked={Boolean(value)}
          pending={pending === opt.key}
          onChange={(v) => {
            setDraft({ ...draft, [opt.key]: v })
            void writeEnv(opt, v)
          }}
          detail={opt.detail}
          footnote={`${opt.honoured_by}${inherited ? ` · default ${opt.default ? 'on' : 'off'}` : ''}${opt.affects.length ? ` · affects ${opt.affects.join(', ')}` : ''}`}
        />
      ) : (
        <OptionField
          label={opt.label}
          detail={opt.detail}
          footnote={`${opt.honoured_by}${inherited ? ' · default ' + opt.default : ''}`}
        >
          <div className="flex items-center gap-2">
            <input
              className="field font-mono"
              type={opt.kind === 'number' ? 'number' : 'text'}
              min={opt.min}
              max={opt.max}
              step={opt.kind === 'number' ? 'any' : undefined}
              value={String(value ?? '')}
              spellCheck={false}
              onChange={(e) =>
                setDraft({
                  ...draft,
                  [opt.key]: opt.kind === 'number' ? Number(e.target.value) : e.target.value,
                })
              }
              aria-label={opt.label}
            />
            <Button
              size="sm"
              variant="outline"
              isDisabled={!dirty || pending === opt.key}
              onPress={() =>
                void writeEnv(
                  opt,
                  opt.kind === 'number' ? Number(value) : String(value),
                )
              }
            >
              {pending === opt.key ? 'Saving…' : 'Save'}
            </Button>
          </div>
        </OptionField>
      )

    return <div key={opt.key}>{control}</div>
  }

  return (
    <Card className="w-full">
      <Card.Header className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <Card.Title className="text-sm font-semibold">Options for {pipeline.name}</Card.Title>
          <p className="mt-1 text-[11px] text-default-500">
            Written into <code className="font-mono">{pipeline.file}</code>. Each one is a variable
            the analyzer reads - the source is named under the control.
          </p>
        </div>
      </Card.Header>

      <Card.Content className="flex flex-col gap-3">
        {/* --- phase list -----------------------------------------------------
            yarGen edits the phase list rather than setting an option, so it
            gets its own section instead of the environment block. */}
        <p className="section-label">Phase plan</p>

        {/* --- yarGen rule generation -----------------------------------------
            Opt-in per pipeline, because it is slow, it needs a tool nothing
            else depends on, and what it produces needs review before anyone
            deploys it. It edits the phase list rather than setting an
            environment flag, so the wizard preview and the planner cannot
            disagree with what this control says. */}
        <div className="rounded-lg border border-default-200 p-3">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div className="min-w-0 flex-1">
              <p className="text-[12px] font-semibold text-foreground">
                YARA rule generation
              </p>
              <p className="mt-1 text-[11px] leading-relaxed text-default-500">
                Adds a <code className="font-mono">yara_gen</code> phase that runs
                yarGen-Go on the sample and writes new rules to{' '}
                <code className="font-mono">yara_gen/&lt;sample&gt;_generated.yar</code>.
                Different from the existing <code className="font-mono">yara</code>{' '}
                phase, which asks whether the sample matches rules you already
                have. It is inserted before <code className="font-mono">export</code>{' '}
                so the rule file is part of the artifact set.
              </p>
              <p className="mt-1.5 text-[11px] text-default-400">
                Adds roughly two minutes to a run on a small sample, and the
                output is unreviewed — validate before deploying it.
              </p>
              {yargen && !yargen.available && (
                <p className="mt-1.5 text-[11px] text-danger">{yargen.reason}</p>
              )}
              {yargen?.available && (
                <div className="mt-2 flex flex-wrap gap-1.5">
                  {yargen.checks.map((c) => (
                    <Chip
                      key={c.id}
                      size="sm"
                      variant="soft"
                      color={c.ok ? 'success' : 'warning'}
                    >
                      {c.label}
                    </Chip>
                  ))}
                </div>
              )}
              {/* Said here rather than left to the operator to discover: the
                  missing config does not stop the phase, it only costs the LLM
                  pass, so the rules are weaker than the tool can produce. */}
              {yargen?.faults?.includes('config/config.yaml') && (
                <p className="mt-1.5 text-[11px] text-warning">
                  No <code className="font-mono">config.yaml</code>: rules are
                  still generated, but without the LLM pass. Fix it in the Utils
                  page.
                </p>
              )}
            </div>
            <div className="flex shrink-0 flex-col items-end gap-2">
              <Switch
                label="Generate YARA rules"
                checked={pipeline.phases.includes('yara_gen')}
                pending={pending === '__yaragen'}
                disabled={yargen != null && !yargen.checks.some((c) => c.id === 'binary' && c.ok)}
                onChange={(v) =>
                  void send(
                    '__yaragen',
                    () => api.setYaraGen(pipeline.name, v),
                    v
                      ? `${pipeline.name} will generate YARA rules from each analyzed sample.`
                      : `${pipeline.name} no longer generates YARA rules.`,
                  )
                }
                detail=""
              />
              <span className="max-w-[16rem] text-right text-[10px] text-default-400">
                {yargen == null
                  ? 'Checking yarGen-Go…'
                  : !yargen.checks.some((c) => c.id === 'binary' && c.ok)
                    ? 'Refused: yargen.exe is not built.'
                    : pipeline.phases.includes('yara_gen')
                      ? 'Rules are written beside the other artifacts.'
                      : 'Off. The phase is not in this pipeline.'}
              </span>
            </div>
          </div>
        </div>

        {/* --- environment options ------------------------------------------ */}
        {/* Only run-wide options arrive; the CTI and ML settings are machine-
            wide and live on Analysis Configuration, so this page lists none. */}
        <p className="section-label mb-1.5">Options this pipeline can set</p>
        <div className="grid grid-cols-1 gap-3 xl:grid-cols-2">
          {options.map(renderOption)}
        </div>

        {note && <p className="text-[11px] text-success">{note}</p>}
        {error && (
          <Alert status="danger">
            <Alert.Title>Not written</Alert.Title>
            <Alert.Description>{error}</Alert.Description>
          </Alert>
        )}
      </Card.Content>
    </Card>
  )
}

// --- phases ---------------------------------------------------------------

function PhasesTab({ data }: { data: AnalysisConfig }) {
  const [query, setQuery] = useState('')

  // Which pipelines select each phase. Answered from the files on disk, so it
  // moves the moment a YAML is edited - no analyzer run in between.
  const usage = useMemo(() => {
    const map = new Map<string, string[]>()
    for (const pipeline of data.pipelines) {
      for (const phase of pipeline.phases) {
        map.set(phase, [...(map.get(phase) ?? []), pipeline.name])
      }
    }
    return map
  }, [data.pipelines])

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase()
    if (!q) return data.phases.items
    return data.phases.items.filter(
      (p) =>
        p.name.toLowerCase().includes(q) ||
        p.description.toLowerCase().includes(q) ||
        p.artifact.toLowerCase().includes(q) ||
        p.service.toLowerCase().includes(q),
    )
  }, [data.phases.items, query])

  return (
    <div className="flex flex-col gap-3">
      <Card className="w-full">
        <Card.Header className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <Card.Title className="text-sm font-semibold">Phase catalog</Card.Title>
            <Chip size="sm" variant="soft" color={data.phases.available ? 'success' : 'warning'}>
              {data.phases.available ? 'from the analyzer' : 'analyzer offline'}
            </Chip>
          </div>
          <div className="flex items-center gap-2">
            <Chip size="sm" variant="soft">{filtered.length} of {data.phases.count}</Chip>
            <div className="compose-viewer-search">
              <Icon name="filter" size={13} className="text-default-400" />
              <input
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Filter phases…"
                aria-label="Filter phases"
              />
              {query && (
                <button type="button" onClick={() => setQuery('')} aria-label="Clear filter">
                  <Icon name="x" size={12} />
                </button>
              )}
            </div>
          </div>
        </Card.Header>

        <Card.Content className="flex flex-col gap-3">
          {!data.phases.available && (
            <Alert status="warning">
              <Alert.Title>Phase names could not be validated</Alert.Title>
              <Alert.Description>
                The catalog is the analyzer's own <code className="font-mono">GET /phases</code>,
                cached from <code className="font-mono">--list-phases --json</code>. With the
                analyzer down the panel does not keep a copy of the names, so pipelines are listed
                unvalidated rather than checked against a list that may be out of date.
                {data.phases.error && (
                  <span className="mt-1 block font-mono text-[10px] opacity-70">{data.phases.error}</span>
                )}
              </Alert.Description>
            </Alert>
          )}

          <p className="text-[11px] text-default-500">
            These are the names a <code className="font-mono">phases:</code> list may use. Anything
            else makes the analyzer exit 2 before it starts. Prerequisite phases are inserted
            automatically, and{' '}
            <code className="font-mono">{data.phases.epilogue.join(', ')}</code>{' '}
            {data.phases.epilogue.length === 1 ? 'is' : 'are'} appended when a config omits{' '}
            {data.phases.epilogue.length === 1 ? 'it' : 'them'}.{' '}
            <code className="font-mono">{data.phases.always_on.join(', ')}</code> always run and
            cannot be selected.
          </p>

          {filtered.length === 0 ? (
            <p className="py-6 text-center text-[11px] text-default-400">
              No phase matches “{query}”.
            </p>
          ) : (
            <div className="flex flex-col divide-y divide-default-200/70">
              {filtered.map((phase) => (
                <div key={phase.name} className="flex flex-col gap-1.5 py-2.5 md:flex-row md:items-start md:gap-3">
                  <span className="metric w-32 shrink-0 font-mono text-[12px] font-semibold text-foreground">
                    {phase.name}
                  </span>
                  <div className="min-w-0 flex-1">
                    <p className="text-[11px] text-default-600">{phase.description}</p>
                    <div className="mt-1 flex flex-wrap items-center gap-1.5">
                      {phase.artifact && (
                        <span className="metric rounded border border-default-200 px-1 font-mono text-[9px] text-default-400">
                          {phase.artifact}
                        </span>
                      )}
                      {phase.service && (
                        <span className="metric rounded border border-accent/30 bg-accent/8 px-1 font-mono text-[9px] text-accent">
                          service: {phase.service}
                        </span>
                      )}
                      {phase.requires.map((req) => (
                        <PhaseChip key={req} name={req} inserted title="inserted before this phase" />
                      ))}
                    </div>
                  </div>
                  <div className="flex shrink-0 flex-wrap gap-1 md:max-w-[220px] md:justify-end">
                    {(usage.get(phase.name) ?? []).length === 0 ? (
                      <span className="text-[10px] text-default-400">unused</span>
                    ) : (
                      (usage.get(phase.name) ?? []).map((name) => (
                        <span
                          key={name}
                          className="metric rounded bg-default-100 px-1 font-mono text-[9px] text-default-500"
                        >
                          {name}
                        </span>
                      ))
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </Card.Content>
      </Card>
    </div>
  )
}

// --- page -----------------------------------------------------------------

export default function AnalysisConfig() {
  const { data, error, refresh } = usePoll(api.analysisConfig, INTERVAL)
  const [tab, setTab] = useState<Tab>('pipelines')
  const [selectedPipeline, setSelectedPipeline] = useState<string>('')
  // yarGen-Go's readiness, for the rule-generation toggle. Fetched from
  // /api/utils rather than folded into /api/analysis/config, so the analysis
  // config does not have to know whether a rule generator happens to be
  // vendored in this checkout. Slow poll: it changes when somebody runs the
  // yarGen update, not on a phase poll.
  const [yargen, setYargen] = useState<YargenState | null>(null)
  useEffect(() => {
    let cancelled = false
    const load = () =>
      api.utilsOverview()
        .then((u) => { if (!cancelled) setYargen(u.yargen) })
        .catch(() => undefined)
    void load()
    const id = window.setInterval(load, 120000)
    return () => { cancelled = true; window.clearInterval(id) }
  }, [])
  // The two "ago" labels below describe a fixed timestamp, so they tick on their
  // own clock rather than waiting for the next payload. Called for the re-render
  // it schedules - the value itself is arithmetic, not state.
  useMinuteTick()

  const broken = data?.broken ?? []

  // A pipeline the wizard just wrote: land the operator on it rather than
  // leaving them on a blank form wondering whether it saved.
  const onCreated = (name: string) => {
    setSelectedPipeline(name)
    refresh()
    setTab('pipelines')
  }

  return (
    <>
      <div className="mb-6 flex flex-wrap items-baseline justify-between gap-4">
        <div>
          <h2 className="page-title">Pipelines Configuration</h2>
          <p className="mt-1 text-[11px] text-default-500">
            The pipelines and upload options the analyzer reads. Options are written into the same
            YAML the analyzer loads, and every edit is validated against the analyzer's own rules
            before it replaces anything. Settings that apply to <em>every</em> run live on Analysis
            Configuration and win over anything set here.
          </p>
        </div>
        <div className="flex items-center gap-3">
          {data && (
            <span className="font-mono text-[10px] text-default-400">
              files edited {ago(data.newest_edit)}
            </span>
          )}
          <Button size="sm" variant="outline" onPress={refresh}>
            <Icon name="refresh" size={13} />
            Refresh
          </Button>
        </div>
      </div>

      {error && (
        <Alert status="danger" className="mb-4">
          <Alert.Title>Cannot read the pipelines configuration</Alert.Title>
          <Alert.Description>{error}</Alert.Description>
        </Alert>
      )}

      {!data && !error && (
        <Loading label="Reading pipelines…" hint="pipelines/*.yaml and config/artifacts.yaml" />
      )}

      {data && (
        <>
          <div className="mb-5 grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-4">
            <StatTile
              label="Pipelines"
              value={data.pipeline_count}
              sub={broken.length > 0 ? `${broken.length} the analyzer would reject` : 'all valid'}
              icon={<Icon name="git-merge" size={15} />}
              trendTone={broken.length > 0 ? 'danger' : 'success'}
              onClick={() => setTab('pipelines')}
            />
            <StatTile
              label="Phases available"
              value={data.phases.count > 0 ? data.phases.count : '—'}
              sub={
                data.phases.available
                  ? 'catalog from the running analyzer'
                  : 'analyzer offline - names unvalidated'
              }
              icon={<Icon name="model" size={15} />}
              trendTone={data.phases.available ? 'success' : 'warning'}
              onClick={() => setTab('phases')}
            />
            <StatTile
              label="MEGA upload"
              value={data.mega_upload ? 'on' : 'off'}
              sub={data.mega_upload ? `bundles go to ${data.artifacts.remote_root}` : 'no evidence leaves this host'}
              icon={<Icon name="rocket" size={15} />}
              trendTone={data.mega_upload ? 'warning' : 'accent'}
              /* Read-only here by design: the upload decisions live on the
                 Analysis Configuration page, so this tile reports the
                 effective state instead of hosting a second control for it. */
            />
            <StatTile
              label="Last edited"
              value={ago(data.newest_edit)}
              sub="newest change across the pipeline and artifact configs"
              icon={<Icon name="activity" size={15} />}
            />
          </div>

          <SubNav
            tabs={[
              { id: 'pipelines', label: 'Pipelines', icon: 'git-merge', tone: broken.length > 0 ? 'bad' : 'ok' },
              { id: 'create', label: 'New pipeline', icon: 'plus', tone: data.phases.available ? 'ok' : 'warn' },
              { id: 'phases', label: 'Phases', icon: 'model', tone: data.phases.available ? 'ok' : 'warn' },
            ]}
            active={tab}
            onChange={(id) => setTab(id as Tab)}
          />

          {tab === 'pipelines' && (
            <PipelinesTab
              data={data}
              onSaved={refresh}
              selected={selectedPipeline}
              onSelect={setSelectedPipeline}
              yargen={yargen}
            />
          )}
          {tab === 'create' && (
            <PipelineWizard
              catalog={data.phases.items}
              // Filtered rather than passed whole: the wizard writes a real
              // `environment:` block, and a key config/analysis.yaml owns would
              // land in the new file as a line that does not happen. The server
              // refuses it too - this is so the author never sees the control.
              options={data.options.filter((o) => data.global_settings[o.key] === undefined)}
              onCreated={onCreated}
            />
          )}
          {tab === 'phases' && <PhasesTab data={data} />}
        </>
      )}
    </>
  )
}