import { useEffect, useMemo, useState } from 'react'
import { Card } from '@heroui/react/card'
import { Chip } from '@heroui/react/chip'
import { Alert } from '@heroui/react/alert'
import { api } from '../api'
import { bytes as fmtBytes } from '../lib/format'
import type { LogFile, TraceMetrics } from '../types'

// ---------------------------------------------------------------------------
// Trace output gets its own panel, and a different parser, because it is not a
// log.
//
// trace.txt is an ~80 MB append-only spdlog call-graph dump from the native
// extractor with no rotation. Putting it in the generic log viewer produced a
// page of identical-looking `[trace] 85325.749 ms | depth=01 | ...` lines with
// nothing to sort, filter or click. Nobody opens an 80 MB trace to read it;
// they open it to answer a question, so that is what the top of this panel
// answers:
//
//   how many events   how deep did it nest   how long did it take
//   which symbols dominate   what did it cost in memory
//
// and the raw records sit underneath for the moment you need the actual call.
//
// The parser is deliberately strict about what it renders as a "row": a line
// that is not a trace record is shown verbatim in a dimmed style rather than
// being coerced into one, because the binary the extractor interleaves with
// these records must not masquerade as a call.
// ---------------------------------------------------------------------------

const RECORD = /^\[(?<channel>[a-z][\w]*)\]\s+(?<ms>[\d.]+)\s*ms\s*\|\s*depth=(?<depth>\d+)\s*\|\s*(?<kind>ENTER|LEAVE)\s*\|\s*(?<sig>.+?)\s*\|\s*(?<tail>.*)$/

interface TraceRow {
  channel: string
  ms: number
  depth: number
  kind: 'ENTER' | 'LEAVE'
  signature: string
  detail: string
  durationMs: number | null
  /** Collapse the template noise so the symbol column is actually readable. */
  short: string
  raw: string
}

function shortSignature(sig: string): string {
  return sig.replace(/^\s*(?:void|int|bool|char|auto|const)\s+/, '')
}

function parseTraceLine(line: string): TraceRow | null {
  const hit = RECORD.exec(line)
  if (!hit) return null
  const g = hit.groups as Record<string, string>
  const duration = /duration=([\d.]+)\s*(ns|us|ms|s)/.exec(g.tail)
  const scale: Record<string, number> = { ns: 1e-6, us: 1e-3, ms: 1, s: 1000 }
  return {
    channel: g.channel,
    ms: Number(g.ms),
    depth: Number(g.depth),
    kind: g.kind as 'ENTER' | 'LEAVE',
    signature: g.sig,
    short: shortSignature(g.sig),
    detail: g.tail,
    durationMs: duration ? Number(duration[1]) * scale[duration[2]] : null,
    raw: line,
  }
}

function humanMs(ms: number | null): string {
  if (ms === null) return '—'
  if (ms >= 1000) return `${(ms / 1000).toFixed(2)} s`
  if (ms >= 1) return `${ms.toFixed(2)} ms`
  return `${(ms * 1000).toFixed(0)} µs`
}

function Metric({ label, value, hint }: { label: string; value: string; hint?: string }) {
  return (
    <div className="trace-metric" title={hint}>
      <span className="trace-metric-label">{label}</span>
      <span className="trace-metric-value">{value}</span>
      {hint && <span className="trace-metric-hint">{hint}</span>}
    </div>
  )
}

function memoryField(
  fields: Record<string, { bytes?: number; count?: number; percent?: number; raw: string }>,
  label: string,
): string {
  const field = fields[label]
  if (!field) return '—'
  if (field.bytes !== undefined) return fmtBytes(field.bytes)
  if (field.count !== undefined) return field.count.toLocaleString()
  if (field.percent !== undefined) return `${field.percent}%`
  return field.raw
}

function TraceMetricsPanel({
  data,
  loading,
  error,
}: {
  data: TraceMetrics | null
  loading: boolean
  error: string | null
}) {
  if (error) {
    return <Alert status="danger"><Alert.Description>{error}</Alert.Description></Alert>
  }
  if (loading && !data) {
    return <p className="py-6 text-center text-[12px] text-muted">Reading the trace tail…</p>
  }
  if (!data) return null

  if (!data.available) {
    return (
      <Alert status="warning">
        <Alert.Title>Nothing to analyse</Alert.Title>
        <Alert.Description>
          {data.error ?? 'The read window contained no trace records.'}
        </Alert.Description>
      </Alert>
    )
  }

  const enter = data.kinds.ENTER ?? 0
  const leave = data.kinds.LEAVE ?? 0
  // A mismatch is the interesting case: an unbalanced call graph means the
  // trace was cut mid-stack, which is exactly what a truncated read window
  // looks like and should be visible rather than silently normalised.
  const unbalanced = Math.abs(enter - leave)
  const fields = (data.memory as { fields?: Record<string, { bytes?: number; count?: number; percent?: number; raw: string }> })?.fields ?? {}

  return (
    <div className="trace-metrics">
      <div className="trace-metrics-grid">
        <Metric label="Events" value={data.events.toLocaleString()}
                hint="Trace records parsed from the read window" />
        <Metric label="Max depth" value={String(data.depth.max)}
                hint={`Currently at depth ${data.depth.current}`} />
        <Metric label="Wall clock" value={humanMs(data.span.duration_ms)}
                hint={`${Math.round(data.span.first_ms ?? 0)} ms → ${Math.round(data.span.last_ms ?? 0)} ms`} />
        <Metric label="Enter / Leave" value={`${enter.toLocaleString()} / ${leave.toLocaleString()}`}
                hint={unbalanced ? `${unbalanced} unpaired — the read window may have cut the stack` : 'balanced call graph'} />
        <Metric label="Total in calls" value={humanMs(data.duration_ms.total)}
                hint="Sum of every LEAVE duration in the window" />
        <Metric label="p50 / p95" value={`${humanMs(data.duration_ms.p50)} / ${humanMs(data.duration_ms.p95)}`}
                hint="Median and 95th percentile call duration" />
      </div>

      {data.clipped && (
        <p className="trace-note">
          Aggregated over the last 8 MB only — the file is {fmtBytes(data.bytes)} and
          grows without rotation. These are the most recent events, not the whole run.
        </p>
      )}

      <div className="trace-columns">
        <Card className="w-full">
          <Card.Header>
            <Card.Title className="text-xs font-semibold">Slowest calls</Card.Title>
            <p className="mt-0.5 text-[11px] text-muted">Where the time actually goes</p>
          </Card.Header>
          <Card.Content className="flex flex-col gap-1">
            {data.slowest.length === 0 && (
              <p className="py-3 text-center text-[11px] text-muted">No durations found.</p>
            )}
            {data.slowest.map((s, i) => (
              <div className="trace-row" key={`${s.signature}-${i}`}>
                <span className="trace-row-depth">{s.depth}</span>
                <span className="trace-row-sym" title={s.signature}>{s.signature}</span>
                <span className="trace-row-ms">{humanMs(s.duration_ms)}</span>
              </div>
            ))}
          </Card.Content>
        </Card>

        <Card className="w-full">
          <Card.Header>
            <Card.Title className="text-xs font-semibold">Hottest symbols</Card.Title>
            <p className="mt-0.5 text-[11px] text-muted">Most-entered frames</p>
          </Card.Header>
          <Card.Content className="flex flex-col gap-1">
            {data.symbols.map((s) => {
              const top = data.symbols[0]?.count || 1
              return (
                <div className="trace-row" key={s.name} title={s.name}>
                  <span
                    className="trace-row-bar"
                    style={{ width: `${Math.max(4, (s.count / top) * 100)}%` }}
                  />
                  <span className="trace-row-sym">{s.name}</span>
                  <span className="trace-row-ms">{s.count.toLocaleString()}</span>
                </div>
              )
            })}
          </Card.Content>
        </Card>

        <Card className="w-full">
          <Card.Header>
            <Card.Title className="text-xs font-semibold">Shutdown memory</Card.Title>
            <p className="mt-0.5 text-[11px] text-muted">
              {((data.memory as { process_id?: string | null })?.process_id)
                ? `PID ${(data.memory as { process_id?: string | null }).process_id}`
                : 'Process counters'}
            </p>
          </Card.Header>
          <Card.Content className="flex flex-col gap-1.5">
            {Object.keys(fields).length === 0 && (
              <p className="py-3 text-center text-[11px] text-muted">
                No memory block in this window.
              </p>
            )}
            {[
              ['Working Set Size', 'working set'],
              ['Peak Working Set Size', 'peak working set'],
              ['Private Usage', 'private usage'],
              ['Pagefile Usage', 'pagefile'],
              ['Pagefile Usage %', 'pagefile %'],
              ['Page Fault Count', 'page faults'],
            ].map(([key, label]) =>
              Object.keys(fields).includes(key) && (
                <div className="trace-row" key={key}>
                  <span className="trace-row-sym">{label}</span>
                  <span className="trace-row-ms">{memoryField(fields, key)}</span>
                </div>
              ),
            )}
          </Card.Content>
        </Card>
      </div>
    </div>
  )
}

function TraceViewer({ text, query }: { text: string; query: string }) {
  const needle = query.trim().toLowerCase()

  const rows = useMemo(() => {
    const out: { row: TraceRow | null; raw: string }[] = []
    for (const raw of text.split('\n')) {
      const row = parseTraceLine(raw)
      if (row && needle) {
        const hay = `${row.signature} ${row.detail} ${row.kind}`.toLowerCase()
        if (!hay.includes(needle)) continue
      }
      out.push({ row, raw })
    }
    return out
  }, [text, needle])

  if (rows.length === 0) {
    return (
      <p className="py-8 text-center text-[12px] text-muted">
        {needle ? 'No trace record matches that filter.' : 'Nothing to show.'}
      </p>
    )
  }

  return (
    <div className="trace-viewer" role="log" aria-label="Trace records">
      {rows.map(({ row, raw }, i) =>
        row ? (
          <div
            className={`trace-record is-${row.kind.toLowerCase()}`}
            key={i}
            style={{ paddingLeft: `${8 + row.depth * 10}px` }}
            title={raw}
          >
            <span className="trace-record-ms">{row.ms.toFixed(3)}</span>
            <span className="trace-record-depth">d{row.depth}</span>
            <span className="trace-record-kind">{row.kind === 'ENTER' ? '→' : '←'}</span>
            <span className="trace-record-sym">{row.short}</span>
            {row.durationMs !== null && (
              <span className="trace-record-dur">{humanMs(row.durationMs)}</span>
            )}
          </div>
        ) : (
          <div className="trace-record is-raw" key={i} title={raw}>
            {raw.slice(0, 400)}
          </div>
        ),
      )}
    </div>
  )
}

export default function TracePanel({ files }: { files: LogFile[] }) {
  const [selected, setSelected] = useState<LogFile | null>(files[0] ?? null)
  const [metrics, setMetrics] = useState<TraceMetrics | null>(null)
  const [metricsErr, setMetricsErr] = useState<string | null>(null)
  const [loadingMetrics, setLoadingMetrics] = useState(false)
  const [tail, setTail] = useState<string[] | null>(null)
  const [tailErr, setTailErr] = useState<string | null>(null)
  const [query, setQuery] = useState('')
  const [lines, setLines] = useState(600)

  // Default to the first file when the list arrives or changes underneath us.
  useEffect(() => {
    if (!selected && files.length > 0) setSelected(files[0])
  }, [files, selected])

  const load = (file: LogFile, depth: number, filter: string) => {
    setMetrics(null)
    setMetricsErr(null)
    setLoadingMetrics(true)
    setTail(null)
    setTailErr(null)
    api
      .traceMetrics(file.id)
      .then(setMetrics)
      .catch((e) => setMetricsErr(e instanceof Error ? e.message : String(e)))
      .finally(() => setLoadingMetrics(false))
    api
      .tail(file.id, depth)
      .then((t) => {
        if (t.error) setTailErr(t.error)
        else setTail(t.lines ?? [])
      })
      .catch((e) => setTailErr(e instanceof Error ? e.message : String(e)))
    void filter
  }

  useEffect(() => {
    if (selected) load(selected, lines, query)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selected, lines])

  if (files.length === 0) {
    return (
      <Alert status="accent">
        <Alert.Title>No trace files</Alert.Title>
        <Alert.Description>
          Nothing in the log tree is classified as trace output. A trace appears here
          once the analyzer writes one to <code>logs/*.txt</code>.
        </Alert.Description>
      </Alert>
    )
  }

  return (
    <div className="grid grid-cols-1 gap-3 xl:grid-cols-[minmax(260px,320px)_1fr]">
      <Card className="w-full">
        <Card.Header>
          <Card.Title className="text-xs font-semibold">Trace files</Card.Title>
          <p className="mt-0.5 text-[11px] text-muted">
            Native call-graph dumps, kept out of the log list
          </p>
        </Card.Header>
        <Card.Content className="flex flex-col gap-1">
          {files.map((file) => (
            <button
              key={file.id}
              onClick={() => setSelected(file)}
              className={`log-file-row ${selected?.id === file.id ? 'is-active' : ''}`}
            >
              <span className="truncate font-mono text-xs">{file.name}</span>
              <span className="shrink-0 font-mono text-[10px] text-muted">
                {fmtBytes(file.bytes)}
              </span>
            </button>
          ))}
        </Card.Content>
      </Card>

      <div className="flex flex-col gap-3">
        <TraceMetricsPanel data={metrics} loading={loadingMetrics} error={metricsErr} />

        <Card className="w-full">
          <Card.Header className="flex flex-wrap items-center justify-between gap-2">
            <Card.Title className="truncate font-mono text-sm">
              {selected?.name ?? 'Select a trace'}
            </Card.Title>
            {selected && (
              <div className="flex flex-wrap items-center gap-2">
                <Chip size="sm" variant="soft">{fmtBytes(selected.bytes)}</Chip>
                {metrics && metrics.clipped && (
                  <Chip size="sm" variant="soft" color="warning">windowed</Chip>
                )}
              </div>
            )}
          </Card.Header>
          <Card.Content>
            <div className="log-controls">
              <input
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Filter records by symbol…"
                aria-label="Filter trace records"
                className="log-search"
              />
              <select
                value={lines}
                onChange={(e) => setLines(Number(e.target.value))}
                aria-label="Records to load"
              >
                {[200, 600, 1500, 2000].map((n) => (
                  <option key={n} value={n}>{n} records</option>
                ))}
              </select>
            </div>

            {tailErr && (
              <Alert status="danger">
                <Alert.Description>{tailErr}</Alert.Description>
              </Alert>
            )}
            {tail === null && !tailErr && (
              <p className="py-8 text-center text-[12px] text-muted">Loading…</p>
            )}
            {tail && <TraceViewer text={tail.join('\n')} query={query} />}
          </Card.Content>
        </Card>
      </div>
    </div>
  )
}