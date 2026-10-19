import { useEffect, useMemo, useState } from 'react'
import { Alert, Card, Chip } from '@heroui/react'
import Icon from '../components/Icon'
import type {
  BuildCheck,
  BuildConfiguration,
  BuildFreshness,
  BuildProvenance,
  BuildTestCatalogue,
  BuildTestEntry,
  BuildTestResult,
  BuildValidation,
} from '../types'

// ---------------------------------------------------------------------------
// The parts of the Build page that answer "can I trust this binary?".
//
// These are separate from Build.tsx on purpose. They read nothing from the
// build-overview poll and hold no state of their own beyond a selection, so
// they can be reasoned about - and broken - without touching the build job
// machinery that streams thousands of log lines.
//
// The ordering is the argument: identity, then currency, then whether it works.
// A binary built from the wrong commit passes every functional check there is,
// so identity has to come first or the rest is reassurance about the wrong
// thing.
// ---------------------------------------------------------------------------

/**
 * The four colours this theme defines. `undefined` means "no colour" rather than
 * a neutral grey: a grey chip reads as disabled, and most of the things marked
 * neutral here (pytest unavailable, an option compiled out) are informative,
 * not broken.
 */
type ChipColor = 'accent' | 'danger' | 'success' | 'warning' | undefined

function CheckRow({ check }: { check: BuildCheck }) {
  const mark = check.ok === true ? 'pass' : check.ok === false ? 'fail' : 'unknown'
  return (
    <div className="flex items-center justify-between gap-3 py-1">
      <span className="flex min-w-0 items-center gap-2">
        <span
          aria-hidden
          className={
            'inline-block h-1.5 w-1.5 shrink-0 rounded-full ' +
            (mark === 'pass' ? 'bg-success' : mark === 'fail' ? 'bg-danger' : 'bg-default-300')
          }
        />
        <span className="truncate text-foreground text-[11px]">{check.label}</span>
      </span>
      <span className="shrink-0 truncate font-mono text-[10px] text-default-500" title={check.detail}>
        {check.detail}
      </span>
    </div>
  )
}

export function ProvenanceCard({
  provenance,
  freshness,
  validation,
}: {
  provenance: BuildProvenance
  freshness: BuildFreshness
  validation: BuildValidation
}) {
  const { git, baked, agrees } = provenance

  // The one sentence that matters. Everything else on this card is supporting
  // detail for it.
  const verdict = useMemo<{ text: string; tone: ChipColor }>(() => {
    if (validation.verdict === 'fail') {
      return { text: 'A check failed', tone: 'danger' }
    }
    if (agrees === false) {
      return { text: 'Built from a different commit', tone: 'danger' }
    }
    if (freshness.stale) {
      return { text: 'Rebuild recommended', tone: 'warning' }
    }
    if (validation.verdict === 'pass' && agrees) {
      return { text: 'Current and working', tone: 'success' }
    }
    return { text: 'Unverified', tone: undefined }
  }, [validation.verdict, agrees, freshness.stale])

  return (
    <Card className="build-card">
      <Card.Header className="flex flex-wrap items-center justify-between gap-2">
        <div className="min-w-0">
          <Card.Title>Build identity</Card.Title>
          {/* The commit line, not a paragraph. Which commit this is answers in
              four words what four facts and a paragraph would answer in a
              paragraph. */}
          <p className="mt-0.5 truncate font-mono text-[10px] text-default-500" title={baked.version ?? ''}>
            {git.short ?? '—'}
            <span className="text-default-400"> · </span>
            {git.branch ?? '—'}
            {git.dirty ? <span className="text-warning"> · dirty</span> : null}
          </p>
        </div>
        <Chip size="sm" variant="soft" color={verdict.tone}>{verdict.text}</Chip>
      </Card.Header>
      <Card.Content className="build-card-body gap-2">
        {agrees === false && (
          <Alert status="danger">
            <Alert.Title>The binary is not the working tree</Alert.Title>
            <Alert.Description>
              <code className="font-mono">HEAD</code> is{' '}
              <code className="font-mono">{git.short}</code> but{' '}
              <code className="font-mono">{baked.version}</code> was built into the
              executable. Anything you run is from the other commit until you rebuild.
            </Alert.Description>
          </Alert>
        )}

        {/* Freshness as one line rather than a boxed sub-block. It is one fact -
            is the exe older than the sources - and a box made it look like a
            fifth thing to evaluate instead of part of the verdict above. */}
        {freshness.available && (
          <div className="flex flex-col gap-1">
            <p className="flex flex-wrap items-baseline gap-x-1.5 text-[11px]">
              <span className="eyebrow">Freshness</span>
              <span className={freshness.stale ? 'text-warning' : 'text-success'}>
                {freshness.stale
                  ? `${freshness.lag_seconds}s behind ${freshness.newest_source}`
                  : 'newer than every source'}
              </span>
            </p>
            {/* Only when stale. "Stale" with nothing behind it is a verdict the
                operator cannot act on; this is the list that makes it one. */}
            {freshness.stale && (freshness.newer_sources?.length ?? 0) > 0 && (
              <ul className="ml-1 space-y-0.5">
                {freshness.newer_sources!.map((s) => (
                  <li key={s.path} className="truncate font-mono text-[10px] text-warning">
                    {s.path}
                  </li>
                ))}
              </ul>
            )}
          </div>
        )}

        <div>
          <p className="eyebrow mb-0.5">Validation</p>
          <div className="divide-y divide-default-100">
            {validation.checks.map((c) => <CheckRow key={c.id} check={c} />)}
          </div>
        </div>
      </Card.Content>
    </Card>
  )
}

export function ConfigurationCard({ config }: { config: BuildConfiguration }) {
  if (!config.available) {
    return (
      <Card className="build-card">
        <Card.Header><Card.Title>Build configuration</Card.Title></Card.Header>
        <Card.Content>
          <p className="text-[12px] text-default-500">
            {config.reason ?? 'not configured'}
          </p>
        </Card.Content>
      </Card>
    )
  }
  const entries = Object.entries(config.options).sort(([a], [b]) => a.localeCompare(b))
  return (
    <Card className="build-card">
      <Card.Header className="flex items-center justify-between gap-3">
        <Card.Title>Build configuration</Card.Title>
        <span className="font-mono text-[11px] text-default-500">{config.build_type ?? '—'}</span>
      </Card.Header>
      <Card.Content className="flex flex-col gap-2">
        <p className="text-[11px] text-default-500">
          These are the CMake options this binary was compiled with — not merely
          what is installed. A library that is present but whose option is{' '}
          <code className="font-mono">OFF</code> is code that is not in the executable.
        </p>
        <div className="grid grid-cols-1 gap-x-6 gap-y-1 sm:grid-cols-2">
          {entries.map(([k, v]) => (
            <div key={k} className="flex items-center justify-between gap-2 py-0.5">
              <span className="truncate font-mono text-[11px] text-default-500" title={k}>
                {k.replace('STATIC_ANALYZER_', '').toLowerCase()}
              </span>
              <Chip size="sm" variant="soft" color={v === 'ON' ? 'success' : undefined}>
                {v === 'ON' ? 'on' : v === 'OFF' ? 'off' : v}
              </Chip>
            </div>
          ))}
        </div>
        {config.compiler && (
          <p className="truncate font-mono text-[10px] text-default-400" title={config.compiler}>
            {config.compiler}
          </p>
        )}
      </Card.Content>
    </Card>
  )
}

// ---------------------------------------------------------------------------
// Test picker
// ---------------------------------------------------------------------------

const KIND_TONE: Record<BuildTestEntry['kind'], ChipColor> = {
  smoke: 'accent',
  // Integration runs the analyzer: it writes exports/ and takes minutes, which
  // is worth a different colour from a smoke test before anyone clicks it.
  integration: 'warning',
  pytest: undefined,
}

function effectTone(effect: string): ChipColor {
  // Anything that writes or reaches out gets a warning colour. "Writes
  // exports/" is not the same risk as "faults on purpose", and the reader
  // decides which they care about.
  return /write|fault|upload|network|mutat/i.test(effect) ? 'warning' : undefined
}

function TestRow({
  entry,
  selected,
  onToggle,
}: {
  entry: BuildTestEntry
  selected: boolean
  onToggle: () => void
}) {
  return (
    <label
      className={
        'flex cursor-pointer items-start gap-3 rounded-lg border p-3 transition-colors ' +
        (entry.available ? 'hover:bg-default-50' : 'opacity-55') +
        (selected ? 'border-accent bg-accent/5' : 'border-default-200')
      }
    >
      <input
        type="checkbox"
        className="mt-0.5 h-4 w-4 shrink-0 accent-[var(--accent)]"
        checked={selected}
        disabled={!entry.available}
        onChange={onToggle}
      />
      <span className="min-w-0 flex-1">
        <span className="flex flex-wrap items-center gap-2">
          <span className="text-[13px] font-semibold text-foreground">{entry.label}</span>
          <Chip size="sm" variant="soft" color={KIND_TONE[entry.kind]}>{entry.kind}</Chip>
          {entry.effects.map((e) => (
            <Chip key={e} size="sm" variant="soft" color={effectTone(e)}>{e}</Chip>
          ))}
        </span>
        <span className="mt-1 block text-[11px] text-default-500">{entry.description}</span>
        {!entry.available && entry.unavailable_reason && (
          <span className="mt-1 block text-[11px] text-danger">{entry.unavailable_reason}</span>
        )}
      </span>
    </label>
  )
}

function ResultRow({ result }: { result: BuildTestResult }) {
  // `clock` and `close` are not icons this theme has. A passing test gets a
  // tick, a failure a cross, and everything in flight a refresh glyph - which
  // also reads correctly as "this is still moving" rather than "unknown".
  const icon = result.state === 'passed' ? 'check'
    : result.state === 'failed' ? 'x'
      : 'refresh'
  const colour = result.state === 'passed' ? 'text-success'
    : result.state === 'failed' ? 'text-danger'
      : 'text-default-400'
  return (
    <div className="flex items-center justify-between gap-3 py-1.5">
      <span className="flex min-w-0 items-center gap-2">
        <Icon name={icon} size={13} className={colour} />
        <span className="truncate text-[12px] text-foreground">{result.label}</span>
        {result.state === 'skipped' && (
          <Chip size="sm" variant="soft" color="warning">skipped</Chip>
        )}
      </span>
      <span className="shrink-0 font-mono text-[11px] text-default-500">
        {result.detail ?? result.state}
        {result.duration != null && ` · ${result.duration}s`}
      </span>
    </div>
  )
}

export function TestPicker({
  catalogue,
  results,
  running,
  onRun,
  busy,
}: {
  catalogue: BuildTestCatalogue
  results: BuildTestResult[]
  running: boolean
  onRun: (ids: string[]) => void
  busy: boolean
}) {
  const [selected, setSelected] = useState<string[]>(catalogue.quick)

  // Re-seed when the catalogue arrives, but never clobber a deliberate choice:
  // the first render has an empty catalogue, and seeding from that would leave
  // nothing ticked.
  useEffect(() => {
    setSelected((cur) => (cur.length ? cur : catalogue.quick))
  }, [catalogue.quick])

  const toggle = (id: string) =>
    setSelected((cur) => (cur.includes(id) ? cur.filter((x) => x !== id) : [...cur, id]))

  const runnable = catalogue.entries.filter((e) => e.available)
  const chosen = selected.filter((id) =>
    catalogue.entries.some((e) => e.id === id && e.available))

  const allSelected = chosen.length > 0 && chosen.length === runnable.length

  return (
    <Card className="w-full">
      <Card.Header className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <Card.Title>Tests</Card.Title>
          <p className="mt-1 text-[11px] text-default-500">
            Pick what to run. Every entry declares what it touches, and analyzer-backed
            runs execute with <code className="font-mono">IA_ARTIFACT_UPLOAD=0</code> —
            nothing is uploaded to MEGA from here.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Chip size="sm" variant="soft">{chosen.length} selected</Chip>
          <button
            type="button"
            className="artifact-action"
            onClick={() => setSelected(allSelected ? [] : catalogue.quick)}
            disabled={running}
          >
            {allSelected ? 'Clear quick' : 'Select quick'}
          </button>
          <button
            type="button"
            className="artifact-action"
            onClick={() =>
              setSelected(allSelected ? [] : runnable.map((e) => e.id))
            }
            disabled={running}
          >
            {allSelected ? 'Clear all' : 'Select all'}
          </button>
          <button
            type="button"
            className="artifact-refresh"
            onClick={() => onRun(chosen)}
            disabled={running || busy || chosen.length === 0}
          >
            {running ? 'Running…' : `Run ${chosen.length || ''}`.trim()}
            <Icon name="refresh" size={13} />
          </button>
        </div>
      </Card.Header>

      <Card.Content className="flex flex-col gap-2">
        {!catalogue.pytest_available && (
          <Alert status="warning">
            <Alert.Description>
              <code className="font-mono">pytest</code> is not installed in{' '}
              <code className="font-mono">python/.venv</code>, so the pytest suites
              are listed but cannot run. Install it with{' '}
              <code className="font-mono">python/.venv\Scripts\python.exe -m pip install pytest</code>.
            </Alert.Description>
          </Alert>
        )}

        {(['smoke', 'integration', 'pytest'] as const).map((kind) => {
          const group = catalogue.entries.filter((e) => e.kind === kind)
          if (group.length === 0) return null
          return (
            <div key={kind} className="mt-1">
              <p className="eyebrow mb-1.5">
                {kind === 'smoke' ? 'Smoke — fast, read-only'
                  : kind === 'integration' ? 'Integration — runs the analyzer'
                    : 'pytest suites'}
              </p>
              <div className="flex flex-col gap-2">
                {group.map((entry) => (
                  <TestRow
                    key={entry.id}
                    entry={entry}
                    selected={selected.includes(entry.id)}
                    onToggle={() => toggle(entry.id)}
                  />
                ))}
              </div>
            </div>
          )
        })}

        {results.length > 0 && (
          <div className="mt-2 rounded-lg bg-default-50 p-3">
            <p className="eyebrow mb-1">Results</p>
            <div className="divide-y divide-default-100">
              {results.map((r) => <ResultRow key={r.id} result={r} />)}
            </div>
          </div>
        )}
      </Card.Content>
    </Card>
  )
}