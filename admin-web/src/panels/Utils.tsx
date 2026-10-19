import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Alert, Card, Chip } from '@heroui/react'
import { api } from '../api'
import Icon from '../components/Icon'
import Loading from '../components/Loading'
import { ago, bytes } from '../lib/format'
import type {
  AnalyzerBuildJob,
  MalapiState,
  SbomState,
  UtilEntry,
  UtilsOverview,
  YaraState,
  YargenState,
} from '../types'

// ---------------------------------------------------------------------------
// Utils.
//
// Four things that can only be maintained by reading the source: the CycloneDX
// SBOM, the MalAPI rule checkout, the unpacked YARA rule packs, and yarGen-Go's
// databases.
//
// One card per utility, each with its own button, rather than one picker with
// four rows. The reason is that these are not variants of one operation - one
// rewrites two JSON files, one runs `git pull`, one compiles three thousand
// rules, one downloads 794 MB - so the button belongs next to the state it acts
// on, where the cost is legible before it is paid.
//
// Every action declares what it touches, and the chips are shown before the
// button is pressed, not in a log afterwards.
// ---------------------------------------------------------------------------

type ChipColor = 'accent' | 'danger' | 'success' | 'warning' | undefined

function Fact({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="min-w-0">
      <span className="eyebrow block">{label}</span>
      <span
        className={'block truncate text-[12px] text-foreground ' + (mono ? 'font-mono' : '')}
        title={value}
      >
        {value}
      </span>
    </div>
  )
}

/** The action row: what it does, what it touches, and the button. */
function Action({
  entry,
  busy,
  onRun,
}: {
  entry: UtilEntry | undefined
  busy: boolean
  onRun: (ids: string[]) => void
}) {
  if (!entry) return null
  const enabled = entry.available && !busy
  return (
    <div className="mt-3 flex flex-wrap items-center justify-between gap-3 border-t border-default-100 pt-3">
      <div className="flex min-w-0 flex-wrap items-center gap-1.5">
        {entry.effects.map((e) => (
          <Chip key={e} size="sm" variant="soft" color={/network|reach/i.test(e) ? 'warning' : undefined}>
            {e}
          </Chip>
        ))}
      </div>
      <button
        type="button"
        className="artifact-refresh"
        disabled={!enabled}
        onClick={() => onRun([entry.id])}
        title={
          entry.available
            ? entry.description
            : (entry.unavailable_reason ?? 'unavailable')
        }
      >
        {busy ? 'Running…' : entry.label}
        <Icon name="refresh" size={13} />
      </button>
    </div>
  )
}

function Shell({
  title,
  verdict,
  note,
  children,
  entry,
  busy,
  onRun,
}: {
  title: string
  verdict: { text: string; tone: ChipColor }
  note?: string
  children: React.ReactNode
  entry?: UtilEntry
  busy: boolean
  onRun: (ids: string[]) => void
}) {
  return (
    <Card className="w-full">
      <Card.Header className="flex flex-wrap items-center justify-between gap-3">
        <Card.Title>{title}</Card.Title>
        <Chip size="sm" variant="soft" color={verdict.tone}>{verdict.text}</Chip>
      </Card.Header>
      <Card.Content className="flex flex-col gap-3">
        {children}
        {note && <p className="text-[11px] text-default-500">{note}</p>}
        <Action entry={entry} busy={busy} onRun={onRun} />
      </Card.Content>
    </Card>
  )
}

function SbomCard({ s, entry, busy, onRun }: {
  s: SbomState; entry?: UtilEntry; busy: boolean; onRun: (ids: string[]) => void
}) {
  const verdict = !s.available
    ? { text: 'not generated', tone: 'warning' as ChipColor }
    : s.stale
      ? { text: 'stale', tone: 'warning' as ChipColor }
      : { text: 'current', tone: 'success' as ChipColor }

  return (
    <Shell title="SBOM" verdict={verdict} note={s.note} entry={entry} busy={busy} onRun={onRun}>
      {!s.available ? (
        <p className="text-[12px] text-default-500">{s.reason}</p>
      ) : (
        <>
          <div className="grid grid-cols-2 gap-x-6 gap-y-2 md:grid-cols-4">
            <Fact label="components" value={(s.total_components ?? 0).toLocaleString()} />
            <Fact label="format" value={`${s.format ?? '—'} ${s.spec_version ?? ''}`} />
            <Fact label="generated" value={s.generated_at ? ago(Date.parse(s.generated_at) / 1000) : '—'} />
            <Fact label="cyclonedx" value={s.cyclonedx_present ? bytes(s.cyclonedx_bytes ?? 0) : 'missing'} />
          </div>
          {Object.keys(s.by_origin ?? {}).length > 0 && (
            <div className="flex flex-wrap gap-1.5">
              {Object.entries(s.by_origin ?? {}).map(([k, v]) => (
                <Chip key={k} size="sm" variant="soft">{k} {v}</Chip>
              ))}
            </div>
          )}
          {(s.unresolved?.length ?? 0) > 0 && (
            <p className="text-[11px] text-default-500">
              {s.unresolved!.length} component(s) with no resolvable version:{' '}
              <span className="font-mono">{s.unresolved!.slice(0, 8).join(', ')}</span>
              {(s.unresolved!.length > 8) && ` +${s.unresolved!.length - 8} more`}
            </p>
          )}
          {s.behind_last_commit && (
            <Alert status="warning">
              <Alert.Description>
                Regenerated after the last commit, so it may not describe the current tree.
              </Alert.Description>
            </Alert>
          )}
        </>
      )}
    </Shell>
  )
}

function MalapiCard({ m, entry, busy, onRun }: {
  m: MalapiState; entry?: UtilEntry; busy: boolean; onRun: (ids: string[]) => void
}) {
  const verdict = !m.available
    ? { text: 'absent', tone: 'warning' as ChipColor }
    : m.dirty
      ? { text: 'local changes', tone: 'danger' as ChipColor }
      : m.behind
        ? { text: `${m.behind} behind`, tone: 'warning' as ChipColor }
        : { text: 'up to date', tone: 'success' as ChipColor }

  return (
    <Shell title="MalAPI rules" verdict={verdict} note={m.note} entry={entry} busy={busy} onRun={onRun}>
      {!m.available ? (
        <p className="text-[12px] text-default-500">{m.reason}</p>
      ) : (
        <>
          <div className="grid grid-cols-2 gap-x-6 gap-y-2 md:grid-cols-4">
            <Fact label="checkout" value={m.path ?? '—'} mono />
            <Fact label="commit" value={`${m.short ?? '—'}${m.dirty ? ' (dirty)' : ''}`} mono />
            <Fact label="branch" value={m.branch ?? '—'} mono />
            <Fact label="remote" value={(m.remote ?? '—').replace('https://github.com/', '')} mono />
          </div>
          {m.dirty && (
            <Alert status="danger">
              <Alert.Title>Update refused</Alert.Title>
              <Alert.Description>
                {m.dirty_count} file(s) have local changes. A pull could not be
                applied cleanly, so the button stays disabled — commit or stash
                first rather than losing work to a browser click.
              </Alert.Description>
            </Alert>
          )}
        </>
      )}
    </Shell>
  )
}

function YaraCard({ y, entry, busy, onRun }: {
  y: YaraState; entry?: UtilEntry; busy: boolean; onRun: (ids: string[]) => void
}) {
  return (
    <Shell
      title="YARA rules"
      verdict={y.available
        ? { text: `${y.total.toLocaleString()} rules`, tone: 'success' as ChipColor }
        : { text: 'absent', tone: 'warning' as ChipColor }}
      note={y.note}
      entry={entry}
      busy={busy}
      onRun={onRun}
    >
      {!y.available ? (
        <p className="text-[12px] text-default-500">{y.reason}</p>
      ) : (
        <>
          <div className="grid grid-cols-2 gap-x-6 gap-y-2 md:grid-cols-3">
            <Fact label="compiler" value={y.yara_version ?? 'yarac not found'} mono />
            <Fact label="on disk" value={bytes(y.bytes)} />
            <Fact label="collections" value={String(y.collections.length)} />
          </div>
          <div className="flex flex-col gap-1">
            {y.collections.map((c) => {
              const share = y.total ? (c.rules / y.total) * 100 : 0
              return (
                <div key={c.name} className="flex items-center gap-2">
                  <span className="w-44 shrink-0 truncate font-mono text-[11px] text-default-500" title={c.name}>
                    {c.name}
                  </span>
                  <span className="h-1.5 min-w-0 flex-1 overflow-hidden rounded-full bg-default-100">
                    <span className="block h-full rounded-full bg-accent/60" style={{ width: `${share}%` }} />
                  </span>
                  <span className="w-12 shrink-0 text-right font-mono text-[11px] text-default-500">
                    {c.rules.toLocaleString()}
                  </span>
                </div>
              )
            })}
          </div>
          {/* Said here rather than omitted: there is no upstream for these, so a
              missing "update" is a fact about the project, not a gap in the UI. */}
          {y.update_reason && (
            <Alert status="warning">
              <Alert.Description>{y.update_reason}.</Alert.Description>
            </Alert>
          )}
        </>
      )}
    </Shell>
  )
}

function YargenCard({ g, entry, busy, onRun }: {
  g: YargenState; entry?: UtilEntry; busy: boolean; onRun: (ids: string[]) => void
}) {
  const verdict = !g.available
    ? { text: 'absent', tone: 'warning' as ChipColor }
    : g.ok
      ? { text: 'ready', tone: 'success' as ChipColor }
      : { text: `${g.faults?.length ?? 0} gap(s)`, tone: 'warning' as ChipColor }

  return (
    <Shell title="yarGen-Go" verdict={verdict} note={g.note} entry={entry} busy={busy} onRun={onRun}>
      {!g.available ? (
        <p className="text-[12px] text-default-500">{g.reason}</p>
      ) : (
        <>
          <div className="divide-y divide-default-100">
            {g.checks.map((c) => (
              <div key={c.id} className="flex items-center justify-between gap-3 py-1.5">
                <span className="flex min-w-0 items-center gap-2">
                  <span
                    aria-hidden
                    className={'inline-block h-2 w-2 shrink-0 rounded-full ' +
                      (c.ok ? 'bg-success' : 'bg-warning')}
                  />
                  <span className="truncate text-[12px]">{c.label}</span>
                </span>
                <span
                  className={'shrink-0 truncate font-mono text-[11px] ' +
                    (c.ok ? 'text-default-500' : 'text-warning')}
                  title={c.fix ? `${c.detail} — ${c.fix}` : c.detail}
                >
                  {c.detail}
                </span>
              </div>
            ))}
          </div>
          {/* A missing config.yaml does not stop yarGen, so nothing else would
              ever tell you it is missing. It only costs the LLM pass. */}
          {(g.faults ?? []).includes('config/config.yaml') && (
            <Alert status="warning">
              <Alert.Description>
                Without <code className="font-mono">config.yaml</code> yarGen
                still runs, but skips the LLM pass — so generated rules are
                weaker than the tool can produce and nothing else will say so.
                Rule generation works without it.
              </Alert.Description>
            </Alert>
          )}
        </>
      )}
    </Shell>
  )
}

export default function Utils() {
  const [data, setData] = useState<UtilsOverview | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [job, setJob] = useState<AnalyzerBuildJob | null>(null)
  const [notice, setNotice] = useState<{ tone: 'ok' | 'bad'; text: string } | null>(null)
  const [starting, setStarting] = useState(false)
  const logRef = useRef<HTMLDivElement>(null)
  const [follow, setFollow] = useState(true)

  const load = useCallback(async () => {
    try {
      setData(await api.utilsOverview())
      setError(null)
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void load()
    const id = window.setInterval(() => void load(), 30000)
    return () => window.clearInterval(id)
  }, [load])

  const running = job?.state === 'running'

  useEffect(() => {
    if (!running || !job) return
    const id = window.setInterval(async () => {
      try {
        const next = await api.buildJob(job.id)
        setJob(next)
        // The whole page is state, and every utility just changed some of it.
        if (next.state !== 'running') void load()
      } catch {
        // A dropped poll is not a failure; the next tick tries again.
      }
    }, 1500)
    return () => window.clearInterval(id)
  }, [running, job?.id, load])

  useEffect(() => {
    if (follow && logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight
  }, [job?.log?.length, follow])

  const run = useCallback(async (ids: string[]) => {
    setStarting(true)
    setNotice(null)
    try {
      const res = await api.runUtils(ids)
      if (!res.ok || !res.job_id) {
        setNotice({ tone: 'bad', text: res.error ?? 'the run was refused' })
        return
      }
      setJob(await api.buildJob(res.job_id))
      setFollow(true)
    } catch (e) {
      setNotice({ tone: 'bad', text: e instanceof Error ? e.message : String(e) })
    } finally {
      setStarting(false)
    }
  }, [])

  const entryOf = useMemo(() => {
    const map = new Map<string, UtilEntry>()
    for (const e of data?.entries ?? []) map.set(e.id, e)
    return (id: string) => map.get(id)
  }, [data?.entries])

  const results = job?.results ?? []

  if (loading && !data) return <Loading label="utils" />

  return (
    <div className="flex flex-col gap-4">
      {error && (
        <Alert status="danger">
          <Alert.Title>Cannot read the utility state</Alert.Title>
          <Alert.Description>{error}</Alert.Description>
        </Alert>
      )}

      {notice && (
        <Alert status={notice.tone === 'ok' ? 'success' : 'danger'}>
          <Alert.Description>{notice.text}</Alert.Description>
        </Alert>
      )}

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        {data && (
          <>
            <SbomCard s={data.sbom} entry={entryOf('sbom')} busy={starting || running} onRun={run} />
            <MalapiCard m={data.malapi} entry={entryOf('malapi-update')} busy={starting || running} onRun={run} />
            <YaraCard y={data.yara} entry={entryOf('yara-check')} busy={starting || running} onRun={run} />
            <YargenCard g={data.yargen} entry={entryOf('yargen-update')} busy={starting || running} onRun={run} />
          </>
        )}
      </div>

      {results.length > 0 && (
        <Card className="w-full">
          <Card.Header className="flex flex-wrap items-center justify-between gap-2">
            <Card.Title>Results</Card.Title>
            {job?.summary && (
              <Chip
                size="sm"
                variant="soft"
                color={job.state === 'passed' ? 'success' : job.state === 'failed' ? 'danger' : 'accent'}
              >
                {job.summary}
              </Chip>
            )}
          </Card.Header>
          <Card.Content>
            <div className="divide-y divide-default-100">
              {results.map((r) => (
                <div key={r.id} className="flex items-center justify-between gap-3 py-1.5">
                  <span className="flex min-w-0 items-center gap-2">
                    <Icon
                      name={r.state === 'passed' ? 'check' : r.state === 'failed' ? 'x' : 'refresh'}
                      size={13}
                      className={r.state === 'passed' ? 'text-success'
                        : r.state === 'failed' ? 'text-danger' : 'text-default-400'}
                    />
                    <span className="truncate text-[12px]">{r.label}</span>
                  </span>
                  <span className="shrink-0 font-mono text-[11px] text-default-500">
                    {r.detail ?? r.state}{r.duration != null && ` · ${r.duration}s`}
                  </span>
                </div>
              ))}
            </div>
          </Card.Content>
        </Card>
      )}

      <Card className="w-full">
        <Card.Header className="flex flex-wrap items-center justify-between gap-2">
          <Card.Title>Output</Card.Title>
          {!follow && (
            <button type="button" className="build-link" onClick={() => setFollow(true)}>
              Jump to tail
            </button>
          )}
        </Card.Header>
        <Card.Content>
          {!job ? (
            <p className="build-empty">
              Nothing has run this session. Pick an action above and its output
              streams here.
            </p>
          ) : (
            <div
              className="build-log"
              role="log"
              aria-label="Utility output"
              aria-live="polite"
              ref={logRef}
              onScroll={(e) => {
                const el = e.currentTarget
                setFollow(el.scrollHeight - el.scrollTop - el.clientHeight < 40)
              }}
            >
              {(job.log ?? []).map((line, i) => (
                <div key={i} className="build-log-line">
                  <span className="text-default-400">{String(i + 1).padStart(5)}</span>
                  <span className="whitespace-pre-wrap break-all">{line}</span>
                </div>
              ))}
            </div>
          )}
        </Card.Content>
      </Card>
    </div>
  )
}