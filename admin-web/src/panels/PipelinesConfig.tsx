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
// Analysis configuration - what the analyzer will run, before it runs it.
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
// ---------------------------------------------------------------------------

// Configuration, not telemetry: a poll this fast would only re-read the same
// bytes. 60s keeps the catalog (which needs the analyzer to be up) roughly
// current without being a spin loop, and the manual Refresh is there for the
// moment someone has just edited a YAML.
const INTERVAL = 60_000

type Tab = 'pipelines' | 'create' | 'phases' | 'artifacts'

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
              options={data.options}
              rushPhases={data.rush.phases}
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
 * The writable half of a pipeline: phase rush, and the environment options.
 *
 * Both write into the file the analyzer reads rather than into panel state, so
 * what the console shows is what the next run will do. Every control here sends
 * a key the server allowlists and the analyzer actually reads - the reason each
 * one carries its source line - and the server re-parses the result before it
 * replaces anything.
 */
function PipelineOptions({
  pipeline,
  options,
  rushPhases,
  yargen,
  onSaved,
}: {
  pipeline: PipelineConfig
  options: EnvOption[]
  rushPhases: string[]
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

  const slowPresent = rushPhases.filter((p) => pipeline.phases.includes(p))
  const rushable = slowPresent.length > 0
  const rushableOff = pipeline.phases.length > slowPresent.length

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
        <Chip size="sm" variant="soft" color={pipeline.rushed ? 'accent' : 'default'}>
          {pipeline.rushed ? 'phase rush applied' : 'full profile'}
        </Chip>
      </Card.Header>

      <Card.Content className="flex flex-col gap-3">
        {/* --- phase rush ---------------------------------------------------- */}
        <div className="rounded-xl border border-default-200 p-3.5">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div className="min-w-0">
              <p className="text-[12px] font-medium text-foreground">Phase rush (triage)</p>
              <p className="mt-1 text-[11px] leading-relaxed text-default-500">
                Drops the phases that dominate wall clock and answers nothing a first look needs:{' '}
                <code className="font-mono">{rushPhases.join(', ')}</code>. The original list is
                recorded as a <code className="font-mono"># phase-rush</code> comment above each
                trimmed list, so this is reversible and explains itself to whoever reads the YAML
                next.
              </p>
              {!pipeline.rushed && (
                <p className="mt-1.5 font-mono text-[10px] text-default-400">
                  {rushable
                    ? `would remove: ${slowPresent.join(', ')}`
                    : 'this pipeline selects none of the slow phases'}
                  {!rushableOff && rushable && ' · nothing would be left, so it is refused'}
                </p>
              )}
            </div>
            <div className="flex shrink-0 flex-col items-end gap-2">
              <Switch
                label="Phase rush"
                checked={pipeline.rushed}
                pending={pending === '__rush'}
                disabled={!pipeline.rushed && (!rushable || !rushableOff)}
                onChange={(v) =>
                  void send(
                    '__rush',
                    () => api.setPipelineRush(pipeline.name, v),
                    v
                      ? `Phase rush applied to ${pipeline.name}.`
                      : `Original phases restored in ${pipeline.name}.`,
                  )
                }
                detail=""
              />
              <span className="max-w-[16rem] text-right text-[10px] text-default-400">
                {pipeline.rushed
                  ? 'Undo puts every recorded phase back where it was.'
                  : rushable && rushableOff
                    ? 'Removes the slow phases from every phase list in this file.'
                    : rushable
                      ? 'Refused: nothing would be left to run.'
                      : 'Nothing to drop here.'}
              </span>
            </div>
          </div>
        </div>

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
        <div className="grid grid-cols-1 gap-3 xl:grid-cols-2">
          {options.map((opt) => {
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
          })}
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

// --- artifacts / upload ---------------------------------------------------

/** What the form holds, and what it was seeded from. Kept apart from the polled
 *  payload so a background refresh cannot discard half-typed edits: `saved` is
 *  the file as of the last successful write, and dirty is the comparison. */
interface ArtifactForm {
  store_artifact: boolean
  upload_artifacts: boolean
  remote_root: string
  timeout_seconds: number
  encrypt_artifacts: boolean
  encryption_recipient: 'user' | 'admin'
  admin_public_key: string
}

const isDirty = (form: ArtifactForm, base: ArtifactForm): boolean =>
  form.store_artifact !== base.store_artifact ||
  form.upload_artifacts !== base.upload_artifacts ||
  form.remote_root.trim() !== base.remote_root ||
  form.timeout_seconds !== base.timeout_seconds ||
  form.encrypt_artifacts !== base.encrypt_artifacts ||
  form.encryption_recipient !== base.encryption_recipient ||
  form.admin_public_key.trim() !== base.admin_public_key

function ArtifactsTab({ data, onSaved }: { data: AnalysisConfig; onSaved: () => void }) {
  const a = data.artifacts
  const [form, setForm] = useState<ArtifactForm>({
    store_artifact: a.store_artifact,
    upload_artifacts: a.upload_artifacts,
    remote_root: a.remote_root,
    timeout_seconds: a.timeout_seconds,
    encrypt_artifacts: a.encrypt_artifacts,
    encryption_recipient: a.encryption_recipient,
    admin_public_key: a.admin_public_key,
  })
  const [saved, setSaved] = useState<ArtifactForm>({ ...form })
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [ok, setOk] = useState(false)

  const dirty = isDirty(form, saved)

  // Re-seed only when the file itself changes underneath us - another editor,
  // or this panel's own write. Keyed on the mtime rather than on every poll, so
  // a 60s refresh never overwrites what someone is typing.
  useEffect(() => {
    const next = {
      store_artifact: a.store_artifact,
      upload_artifacts: a.upload_artifacts,
      remote_root: a.remote_root,
      timeout_seconds: a.timeout_seconds,
      encrypt_artifacts: a.encrypt_artifacts,
      encryption_recipient: a.encryption_recipient,
      admin_public_key: a.admin_public_key,
    }
    setSaved(next)
    setForm((current) => (isDirty(current, next) ? current : next))
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [a.mtime])

  // Mirrors the bounds load_artifact_options() enforces, so the button is
  // disabled for a value the server would refuse rather than after a round trip.
  const rootOk = form.remote_root.trim().startsWith('/') &&
    !form.remote_root.includes('\\') &&
    !form.remote_root.split('/').includes('..')
  const timeoutOk = Number.isInteger(form.timeout_seconds) &&
    form.timeout_seconds >= 1 && form.timeout_seconds <= 86400
  const valid = rootOk && timeoutOk

  const save = async () => {
    setSaving(true)
    setError(null)
    setOk(false)
    try {
      // Only what changed. Sending the whole form would let a stale copy of an
      // unrelated option overwrite a value somebody else just changed.
      const patch: Record<string, boolean | string | number> = {}
      if (form.store_artifact !== saved.store_artifact) patch.store_artifact = form.store_artifact
      if (form.upload_artifacts !== saved.upload_artifacts) patch.upload_artifacts = form.upload_artifacts
      if (form.remote_root.trim() !== saved.remote_root) patch.remote_root = form.remote_root.trim()
      if (form.timeout_seconds !== saved.timeout_seconds) patch.timeout_seconds = form.timeout_seconds
      if (form.encrypt_artifacts !== saved.encrypt_artifacts) patch.encrypt_artifacts = form.encrypt_artifacts
      if (form.encryption_recipient !== saved.encryption_recipient) patch.encryption_recipient = form.encryption_recipient
      if (form.admin_public_key.trim() !== saved.admin_public_key) patch.admin_public_key = form.admin_public_key.trim()

      const res = await api.setArtifactOptions(patch)
      const next = {
        store_artifact: res.artifacts.store_artifact,
        upload_artifacts: res.artifacts.upload_artifacts,
        remote_root: res.artifacts.remote_root,
        timeout_seconds: res.artifacts.timeout_seconds,
        encrypt_artifacts: res.artifacts.encrypt_artifacts,
        encryption_recipient: res.artifacts.encryption_recipient,
        admin_public_key: res.artifacts.admin_public_key,
      }
      setForm(next)
      setSaved(next)
      setOk(true)
      window.setTimeout(() => setOk(false), 2500)
      onSaved()
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="flex flex-col gap-3">
      <div className="grid grid-cols-1 gap-3 xl:grid-cols-2">
        <Switch
          label="Bundle locally"
          checked={form.store_artifact}
          pending={saving}
          onChange={(v) => setForm({ ...form, store_artifact: v })}
          detail="Builds exports/<sample>_artifact/ as a deterministic tar.gz with a SHA-256, a manifest and a README. The JSON reports under exports/<sample>_analysis/ are written either way."
          footnote="planner::load_artifact_options()"
        />
        <Switch
          label="Upload to MEGA"
          checked={form.upload_artifacts}
          pending={saving}
          onChange={(v) => setForm({ ...form, upload_artifacts: v })}
          detail="Uploads the sealed bundle with MEGAcmd after each run. Implies building it locally first, and is the option that sends evidence off this host - the Artifacts page's Export button obeys it too."
          footnote="planner::load_artifact_options()"
        />
        <Switch
          label="Encrypt the bundle before upload"
          checked={form.encrypt_artifacts}
          pending={saving}
          onChange={(v) => setForm({ ...form, encrypt_artifacts: v })}
          detail="Seals the archive to a public key with X25519 + HKDF-SHA256 + AES-256-GCM before anything is uploaded. The plaintext archive stays on local disk; only the sealed file is sent, and if sealing fails the upload is ABORTED rather than falling back to plaintext."
          footnote="mega/seal.py"
        />
        <OptionField
          label="MEGA remote root"
          detail="The bundle lands in <root>/<sample>_artifact. An absolute MEGA path; .. and backslashes are refused."
          footnote="config/artifacts.yaml"
        >
          <input
            className="field font-mono"
            value={form.remote_root}
            onChange={(e) => setForm({ ...form, remote_root: e.target.value })}
            placeholder="/"
            spellCheck={false}
            aria-invalid={!rootOk}
          />
          {!rootOk && (
            <span className="text-[10px] text-danger">
              Must start with / and contain no '..' or backslash.
            </span>
          )}
        </OptionField>
        <OptionField
          label="Seal to which key"
          detail="user = the operator keypair on this machine. admin = the lab's public key, so evidence is sealed to whoever owns it; only the public half is needed here, and the admin private key never has to exist on this machine."
          footnote="config/artifacts.yaml"
        >
          <select
            className="field"
            value={form.encryption_recipient}
            disabled={!form.encrypt_artifacts || saving}
            onChange={(e) => setForm({ ...form, encryption_recipient: e.target.value as 'user' | 'admin' })}
          >
            <option value="user">user - this machine's operator key</option>
            <option value="admin">admin - the lab's public key</option>
          </select>
        </OptionField>
        {form.encryption_recipient === 'admin' && (
          <OptionField
            label="Admin public key"
            detail="Path to the lab's X25519 public key, base64 or PEM. Leave empty to use %APPDATA%\IAProject\bundle-keys\admin.pub or IA_BUNDLE_ADMIN_PUBKEY."
            footnote="config/artifacts.yaml"
          >
            <input
              className="field font-mono"
              value={form.admin_public_key}
              onChange={(e) => setForm({ ...form, admin_public_key: e.target.value })}
              placeholder="(default location)"
              spellCheck={false}
            />
          </OptionField>
        )}
        <OptionField
          label="Upload timeout"
          detail="Hard ceiling on the uploader, in seconds (1 - 86400). The Artifacts page's Export action uses the same budget."
          footnote="config/artifacts.yaml"
        >
          <input
            className="field font-mono"
            type="number"
            min={1}
            max={86400}
            value={form.timeout_seconds}
            onChange={(e) => setForm({ ...form, timeout_seconds: Number(e.target.value) })}
            aria-invalid={!timeoutOk}
          />
          {!timeoutOk && (
            <span className="text-[10px] text-danger">Between 1 and 86400 seconds.</span>
          )}
        </OptionField>
      </div>

      <div className="flex flex-wrap items-center gap-3">
        <Button
          size="sm"
          variant="primary"
          onPress={() => void save()}
          isDisabled={!dirty || !valid || saving}
        >
          <Icon name="check" size={13} />
          {saving ? 'Saving…' : 'Save to config/artifacts.yaml'}
        </Button>
        <button
          type="button"
          className="btn-ghost"
          onClick={() => { setForm({ ...saved }); setError(null) }}
          disabled={!dirty || saving}
        >
          Discard changes
        </button>
        {ok && !dirty && (
          <span className="text-[11px] text-success">Written. Applies to the analyzer on its next run.</span>
        )}
        {!dirty && !ok && (
          <span className="text-[11px] text-default-400">
            In sync with the file. The analyzer reads this once at startup, so a change takes effect
            on its next run - the Artifacts page picks it up immediately.
          </span>
        )}
      </div>

      {error && (
        <Alert status="danger">
          <Alert.Title>Not written</Alert.Title>
          <Alert.Description>{error}</Alert.Description>
        </Alert>
      )}

      {a.errors.length > 0 && (
        <Alert status="danger">
          <Alert.Title>The analyzer will refuse this file</Alert.Title>
          <Alert.Description>
            <ul className="list-disc pl-4">
              {a.errors.map((e) => (
                <li key={e} className="font-mono text-[11px]">{e}</li>
              ))}
            </ul>
          </Alert.Description>
        </Alert>
      )}

      <Card className="w-full">
        <Card.Header className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0">
            <Card.Title className="font-mono text-sm">{a.file}</Card.Title>
            <p className="mt-1 text-[11px] text-default-500">
              Only these four keys are accepted; anything else is a hard error at startup, which is
              why this page reports unknown keys instead of ignoring them. Saving edits the keys in
              place - the comments in the file are its documentation and are left exactly as they
              are.
            </p>
            {a.uploader_script && (
              <p className="mt-1 font-mono text-[10px] text-default-400">
                uploader: {a.uploader_script}
              </p>
            )}
            {a.mtime > 0 && (
              <p className="mt-1 font-mono text-[10px] text-default-400">
                last edited {ago(a.mtime)}
              </p>
            )}
          </div>
          <div className="flex shrink-0 items-center gap-2">
            <Chip size="sm" variant="soft" color={a.present ? 'success' : 'warning'}>
              {a.present ? 'present' : 'missing'}
            </Chip>
            {a.content && <CopyButton text={a.content} />}
          </div>
        </Card.Header>
        {a.content ? (
          <div className="flex max-h-[26rem] flex-col border-t border-default-200">
            <YamlView content={a.content} spans={a.spans} />
          </div>
        ) : (
          <Card.Content className="py-6 text-[11px] text-default-500">
            No file at this path. The analyzer falls back to safe defaults: no archive, no cloud
            upload - which is the same state the switches above show. Standard JSON reports under{' '}
            <code className="font-mono">exports/</code> are unaffected either way.
          </Card.Content>
        )}
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
          <h2 className="page-title">Analysis Configuration</h2>
          <p className="mt-1 text-[11px] text-default-500">
            The pipelines and upload options the analyzer reads. Options are written into the same
            YAML the analyzer loads, and every edit is validated against the analyzer's own rules
            before it replaces anything.
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
          <Alert.Title>Cannot read the analysis configuration</Alert.Title>
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
              onClick={() => setTab('artifacts')}
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
              { id: 'artifacts', label: 'Upload & artifacts', icon: 'rocket' },
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
              options={data.options}
              slowPhases={data.rush.phases}
              onCreated={onCreated}
            />
          )}
          {tab === 'phases' && <PhasesTab data={data} />}
          {tab === 'artifacts' && <ArtifactsTab data={data} onSaved={refresh} />}
        </>
      )}
    </>
  )
}