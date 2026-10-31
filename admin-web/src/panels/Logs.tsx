import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Card } from '@heroui/react/card'
import { Chip } from '@heroui/react/chip'
import { Alert } from '@heroui/react/alert'
import { api } from '../api'
import SubNav from '../components/SubNav'
import Pager, { usePaged } from '../components/Pager'
import TracePanel from '../components/TracePanel'
import Icon from '../components/Icon'
import { LogRow, parseLines, rowText, statsOf, type ParsedLine, type Severity } from '../lib/logColor'
import type { LogFile } from '../types'

// Two tabs, one panel.
//
// Trace output was the reason this split. It is ~80 MB of native call-graph
// records in a directory of 140-odd small text logs, and mixing them meant the
// log list carried an entry nobody could meaningfully open and the trace viewer
// had to cope with lines that share no structure with anything else. They are
// different data with different questions, so they get different screens - but
// they stay under one nav entry because they are one concern.
//
// The viewer below is structured rather than a <textarea> full of monospace:
// time, level, source and message each get their own column so the one error in
// two thousand lines is findable without reading two thousand lines.
//
// Everything it shows comes from ONE parse of the tail:
//
//   tail lines ──▶ parseLines() ──▶ rows ──┬──▶ rendered rows
//                                          ├──▶ severity counts (filter chips)
//                                          ├──▶ source list
//                                          └──▶ volume strip
//
// That is the change this page needed. The header used to ask the server for a
// summary computed by a *second* regex parser while the rows were parsed in the
// browser, so the two could disagree - a chip saying "12 errors" above a filter
// that found three, and a filter that matched the word "error" inside a message
// rather than the level of the line. One parse means the numbers and the rows
// cannot drift apart.

const FILES_PER_PAGE = 24

// How often a followed log is re-read. The panel writes to its own logs, so
// this is the difference between watching a build and refreshing by hand; it is
// also why the request is skipped while the tab is hidden.
const FOLLOW_MS = 2500

type SeverityFilter = 'all' | Severity

const SEVERITY_LABEL: Record<SeverityFilter, string> = {
  all: 'all',
  error: 'errors',
  warning: 'warnings',
  info: 'info',
  debug: 'debug',
}

function humanBytes(n: number): string {
  if (n < 1024) return `${n} B`
  if (n < 1024 ** 2) return `${(n / 1024).toFixed(0)} KB`
  if (n < 1024 ** 3) return `${(n / 1024 ** 2).toFixed(1)} MB`
  return `${(n / 1024 ** 3).toFixed(1)} GB`
}

function humanAge(sec: number): string {
  if (sec < 90) return `${Math.round(sec)}s ago`
  if (sec < 5400) return `${Math.round(sec / 60)}m ago`
  if (sec < 172800) return `${Math.round(sec / 3600)}h ago`
  return `${Math.round(sec / 86400)}d ago`
}

function FileRow({
  file,
  onOpen,
  active,
}: {
  file: LogFile
  onOpen: () => void
  active: boolean
}) {
  return (
    <button onClick={onOpen} className={`log-file-row ${active ? 'is-active' : ''}`}>
      <span className="truncate font-mono text-xs" title={file.name}>{file.name}</span>
      <span className="flex shrink-0 items-center gap-3 text-[11px] text-muted">
        <span className="font-mono">{humanBytes(file.bytes)}</span>
        <span className="w-14 text-right">{humanAge(file.age_seconds)}</span>
      </span>
    </button>
  )
}

/**
 * Line volume per minute across the window.
 *
 * Not a chart: a strip. It answers "was this file quiet until the moment it
 * broke" at a glance, and it is derived from the same parse as the rows, so a
 * burst on the strip lines up with the rows that caused it. Hidden when the
 * window has fewer than two buckets - one bar is not a shape.
 */
function VolumeStrip({ buckets }: { buckets: { key: string; count: number }[] }) {
  const max = Math.max(...buckets.map((b) => b.count), 1)
  return (
    <div className="logs-volume" aria-hidden="true">
      {buckets.map((b) => (
        <span
          key={b.key}
          className="logs-volume-bar"
          style={{ height: `${Math.max(8, (b.count / max) * 100)}%` }}
          title={`${b.key} · ${b.count} line${b.count === 1 ? '' : 's'}`}
        />
      ))}
    </div>
  )
}

export default function Logs() {
  const [tab, setTab] = useState<'logs' | 'trace'>('logs')

  const [data, setData] = useState<Awaited<ReturnType<typeof api.logs>> | null>(null)
  const [err, setErr] = useState<string | null>(null)
  const [filter, setFilter] = useState('')
  const [selected, setSelected] = useState<LogFile | null>(null)
  const [tail, setTail] = useState<Awaited<ReturnType<typeof api.tail>> | null>(null)
  const [tailErr, setTailErr] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)

  const [wrap, setWrap] = useState(true)
  const [lines, setLines] = useState(300)
  const [severity, setSeverity] = useState<SeverityFilter>('all')
  const [source, setSource] = useState<string | null>(null)
  const [needle, setNeedle] = useState('')
  const [matchPos, setMatchPos] = useState(0)
  const [follow, setFollow] = useState(false)
  const [copied, setCopied] = useState(false)

  const scroller = useRef<HTMLDivElement>(null)
  const reqId = useRef(0)
  const copyTimer = useRef<number | null>(null)

  const load = () => {
    setLoading(true)
    api
      .logs()
      .then((d) => {
        setData(d)
        setErr(null)
      })
      .catch((e) => setErr(e instanceof Error ? e.message : String(e)))
      .finally(() => setLoading(false))
  }

  useEffect(load, [])

  // A newer request wins. Without this, clicking file A then file B leaves the
  // viewer showing A if A's tail happens to come back second - which on a 79 MB
  // trace is not hypothetical.
  const open = useCallback(
    (f: LogFile, opts: { quiet?: boolean; depth?: number; fresh?: boolean } = {}) => {
      const { quiet = false, depth = lines, fresh = false } = opts
      if (fresh) {
        setSelected(f)
        setTail(null)
        setTailErr(null)
        setNeedle('')
        setSeverity('all')
        setSource(null)
        setMatchPos(0)
      }
      const token = ++reqId.current
      api
        .tail(f.id, depth)
        .then((t) => {
          if (token !== reqId.current) return
          if (t.error) {
            setTailErr(t.error)
            return
          }
          setTailErr(null)
          setTail((prev) => {
            // A follow poll that read the same bytes must not replace the array:
            // a new array identity re-parses the window and re-renders every
            // row, twice a second, to show exactly what was already on screen.
            if (
              quiet && prev &&
              prev.bytes === t.bytes &&
              prev.returned === t.returned &&
              prev.lines?.[prev.lines.length - 1] === t.lines?.[(t.lines?.length ?? 0) - 1]
            ) return prev
            return t
          })
        })
        .catch((e) => {
          if (token === reqId.current) setTailErr(e instanceof Error ? e.message : String(e))
        })
    },
    [lines],
  )

  // --- derived -------------------------------------------------------------

  const groups = useMemo(() => {
    if (!data) return []
    const query = filter.trim().toLowerCase()
    return data.groups
      .filter((g) => g.present && g.files.length > 0)
      // Traces are the other tab. Filtering here (not only when counting) is
      // what keeps trace.txt out of this rail: it was listed as an openable
      // "log" and made the pager say 56 while the header said 55.
      .map((g) => {
        const logs = g.files.filter((f) => f.kind !== 'trace')
        return {
          ...g,
          files: query
            ? logs.filter((f) => f.name.toLowerCase().includes(query))
            : logs,
        }
      })
      .filter((g) => g.files.length > 0)
  }, [data, filter])

  const { traceFiles, logFileCount } = useMemo(() => {
    if (!data) return { traceFiles: [], logFileCount: 0 }
    const traces: LogFile[] = []
    let count = 0
    for (const g of data.groups) {
      for (const f of g.files) {
        if (f.kind === 'trace') traces.push(f)
        else count += 1
      }
    }
    traces.sort((a, b) => b.modified - a.modified)
    return { traceFiles: traces, logFileCount: count }
  }, [data])

  // Flat list for paging: the groups are for the reader's benefit, not the
  // pager's, and a pager that counts groups rather than files is a pager that
  // lies about the total.
  const flatFiles = useMemo(
    () => groups.flatMap((g) => g.files.map((f) => ({ file: f, group: g.label }))),
    [groups],
  )
  const pagedFiles = usePaged(flatFiles, FILES_PER_PAGE)

  const tailLines = useMemo(() => tail?.lines ?? [], [tail?.lines])

  // The single parse. Everything below reads these records; nothing re-tests
  // the raw line with its own regex.
  const parsed = useMemo(() => parseLines(tailLines), [tailLines])
  const stats = useMemo(() => statsOf(parsed), [parsed])

  const rows = useMemo(
    () => tailLines.map((line, index) => ({ line, index, parsed: parsed[index] })),
    [tailLines, parsed],
  )

  const visible = useMemo(
    () => rows.filter((r) => {
      if (severity !== 'all' && r.parsed.severity !== severity) return false
      if (source && r.parsed.source !== source) return false
      return true
    }),
    [rows, severity, source],
  )

  // Matches are counted over what is ON SCREEN - the message plus the source
  // cell, which is where the highlight can land. Counting the raw line instead
  // meant "3 matches" above a viewport with none in it, because the hit was in
  // a timestamp the row does not render separately.
  const matches = useMemo(() => {
    const query = needle.trim().toLowerCase()
    if (!query) return []
    return visible
      .filter((r) => `${r.parsed.source ?? ''} ${rowText(r.parsed)}`.toLowerCase().includes(query))
      .map((r) => r.index)
  }, [visible, needle])

  const pos = matches.length ? Math.min(matchPos, matches.length - 1) : 0

  const selectedGroup = useMemo(() => {
    if (!selected || !data) return ''
    for (const g of data.groups) {
      if (g.files.some((f) => f.id === selected.id)) return g.label
    }
    return ''
  }, [selected, data])

  // --- effects -------------------------------------------------------------

  const scrollToLine = useCallback((index: number) => {
    const el = scroller.current?.querySelector<HTMLElement>(`[data-line="${index + 1}"]`)
    el?.scrollIntoView({ block: 'center' })
  }, [])

  // A new search starts at its first hit, not at whatever position the previous
  // search happened to be sitting on.
  useEffect(() => { setMatchPos(0) }, [needle, severity, source])

  useEffect(() => {
    if (!needle.trim() || matches.length === 0) return
    scrollToLine(matches[pos])
  }, [needle, matches, pos, scrollToLine])

  // Following means two things: poll, and stay pinned to the bottom. Turning it
  // on jumps there immediately rather than waiting for the next append.
  useEffect(() => {
    if (!follow || !selected) return
    const id = window.setInterval(() => {
      if (document.visibilityState !== 'visible') return
      open(selected, { quiet: true })
    }, FOLLOW_MS)
    return () => window.clearInterval(id)
  }, [follow, selected, open])

  useEffect(() => {
    if (follow && scroller.current) {
      scroller.current.scrollTop = scroller.current.scrollHeight
    }
  }, [follow, tail?.bytes])

  useEffect(() => () => {
    if (copyTimer.current) window.clearTimeout(copyTimer.current)
  }, [])

  const changeDepth = (n: number) => {
    setLines(n)
    // Keep the filters: changing how much history to read is not a request to
    // forget what you were looking for.
    if (selected) open(selected, { depth: n })
  }

  const copyVisible = async () => {
    try {
      await navigator.clipboard.writeText(visible.map((r) => r.line).join('\n'))
      setCopied(true)
      if (copyTimer.current) window.clearTimeout(copyTimer.current)
      copyTimer.current = window.setTimeout(() => setCopied(false), 1400)
    } catch {
      setTailErr('The browser refused clipboard access.')
    }
  }

  const step = (delta: number) => {
    if (matches.length === 0) return
    setMatchPos((p) => (p + delta + matches.length) % matches.length)
  }

  const maxBucket = stats.buckets.length >= 2

  // --- render --------------------------------------------------------------

  return (
    <>
      <div className="mb-4 flex items-baseline justify-between gap-4">
        <h2 className="page-title">Logs</h2>
        <div className="flex items-center gap-3">
          {data && (
            <Chip size="sm" variant="soft">
              {logFileCount} logs · {humanBytes(data.total_bytes)}
            </Chip>
          )}
          <button
            onClick={load}
            className="rounded-md border border-default-300 px-3 py-1.5 text-xs hover:border-accent hover:text-accent"
          >
            Refresh
          </button>
        </div>
      </div>

      <SubNav
        tabs={[
          { id: 'logs', label: `Logs${logFileCount ? ` (${logFileCount})` : ''}`, icon: 'logs' },
          {
            id: 'trace',
            label: `Trace${traceFiles.length ? ` (${traceFiles.length})` : ''}`,
            icon: 'activity',
            // A trace that has not been written in a day is not stale in any way
            // that matters; the dot is for "there is nothing here yet".
            tone: traceFiles.length === 0 ? 'warn' : undefined,
          },
        ]}
        active={tab}
        onChange={(id) => setTab(id as 'logs' | 'trace')}
      />

      {err && (
        <Alert status="danger" className="mb-4">
          <Alert.Title>Cannot list logs</Alert.Title>
          <Alert.Description>{err}</Alert.Description>
        </Alert>
      )}

      {loading && !data && <div className="py-10 text-sm text-muted">Listing…</div>}

      {tab === 'trace' && data && <TracePanel files={traceFiles} />}

      {tab === 'logs' && data && (
        <div className="logs-split">
          {/* --- the files ------------------------------------------------- */}
          <Card className="logs-rail">
            <Card.Header className="logs-rail-head">
              <input
                value={filter}
                onChange={(e) => setFilter(e.target.value)}
                placeholder="Filter by name…"
                aria-label="Filter log files by name"
                className="log-search"
              />
            </Card.Header>
            <Card.Content className="logs-rail-list">
              {flatFiles.length === 0 && (
                <p className="py-6 text-center text-xs text-muted">
                  {filter ? 'Nothing matches that filter.' : 'No logs found.'}
                </p>
              )}
              {groups.map((g) => {
                const onThisPage = pagedFiles.slice
                  .filter((entry) => entry.group === g.label)
                  .map((entry) => entry.file)
                if (onThisPage.length === 0) return null
                return (
                  <div key={g.key} className="mb-4 last:mb-0">
                    <div className="log-group-head">
                      <span>{g.label}</span>
                      <span className="font-mono text-[10px]">{g.files.length}</span>
                    </div>
                    <div className="flex flex-col">
                      {onThisPage.map((f) => (
                        <FileRow
                          key={f.id}
                          file={f}
                          active={selected?.id === f.id}
                          onOpen={() => open(f, { fresh: true })}
                        />
                      ))}
                    </div>
                  </div>
                )
              })}
            </Card.Content>
            {flatFiles.length > FILES_PER_PAGE && (
              <Card.Footer className="logs-rail-foot">
                <Pager
                  page={pagedFiles.page}
                  pages={pagedFiles.pages}
                  first={pagedFiles.first}
                  last={pagedFiles.last}
                  total={flatFiles.length}
                  onPrev={pagedFiles.prev}
                  onNext={pagedFiles.next}
                />
              </Card.Footer>
            )}
          </Card>

          {/* --- the viewer ------------------------------------------------ */}
          <Card className="logs-viewer">
            <Card.Header className="logs-head">
              <div className="min-w-0">
                <Card.Title className="truncate font-mono text-sm">
                  {selected ? selected.name : 'Select a log'}
                </Card.Title>
                <p className="logs-head-sub">
                  {selected ? (
                    <>
                      {selectedGroup && <>{selectedGroup} · </>}
                      {humanBytes(selected.bytes)} · {humanAge(selected.age_seconds)}
                      {tail?.returned ? <> · {tail.returned} lines in view</> : null}
                    </>
                  ) : (
                    'Pick a file on the left to read its tail.'
                  )}
                </p>
              </div>

              {selected && (
                <div className="logs-head-actions">
                  {stats.counts.error > 0 && (
                    <button
                      type="button"
                      onClick={() => setSeverity(severity === 'error' ? 'all' : 'error')}
                      aria-pressed={severity === 'error'}
                      className={`logs-pill is-danger ${severity === 'error' ? 'is-on' : ''}`}
                    >
                      {stats.counts.error} error{stats.counts.error === 1 ? '' : 's'}
                    </button>
                  )}
                  {stats.counts.warning > 0 && (
                    <button
                      type="button"
                      onClick={() => setSeverity(severity === 'warning' ? 'all' : 'warning')}
                      aria-pressed={severity === 'warning'}
                      className={`logs-pill is-warning ${severity === 'warning' ? 'is-on' : ''}`}
                    >
                      {stats.counts.warning} warning{stats.counts.warning === 1 ? '' : 's'}
                    </button>
                  )}
                  <button
                    type="button"
                    onClick={() => setFollow((f) => !f)}
                    aria-pressed={follow}
                    className={`log-toggle ${follow ? 'is-on' : ''}`}
                    title={`Re-read the file every ${FOLLOW_MS / 1000}s and stay at the bottom`}
                  >
                    <Icon name="activity" size={11} className={follow ? 'text-success' : ''} />
                    {follow ? 'Live' : 'Follow'}
                  </button>
                  <button
                    type="button"
                    onClick={() => selected && open(selected, { quiet: true })}
                    className="log-toggle"
                    title="Read the tail again"
                  >
                    <Icon name="refresh" size={11} />
                    Reload
                  </button>
                </div>
              )}
            </Card.Header>

            {selected && (
              <div className="logs-toolbar">
                <div className="logs-search-wrap">
                  <Icon name="search" size={12} className="text-muted" />
                  <input
                    value={needle}
                    onChange={(e) => setNeedle(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key !== 'Enter') return
                      e.preventDefault()
                      step(e.shiftKey ? -1 : 1)
                    }}
                    placeholder="Find in this log…"
                    aria-label="Find in the selected log"
                    className="logs-search-input"
                  />
                  {needle.trim() !== '' && (
                    <span className={`logs-match-count ${matches.length ? '' : 'is-empty'}`}>
                      {matches.length ? `${pos + 1}/${matches.length}` : '0'}
                    </span>
                  )}
                  <button
                    type="button"
                    onClick={() => step(-1)}
                    disabled={matches.length === 0}
                    aria-label="Previous match"
                    className="logs-step"
                  >
                    <Icon name="chevron-up" size={12} />
                  </button>
                  <button
                    type="button"
                    onClick={() => step(1)}
                    disabled={matches.length === 0}
                    aria-label="Next match"
                    className="logs-step"
                  >
                    <Icon name="chevron-down" size={12} />
                  </button>
                </div>

                <div className="log-severity" role="group" aria-label="Filter by severity">
                  {(['all', 'error', 'warning', 'info', 'debug'] as SeverityFilter[]).map((value) => {
                    const count = value === 'all' ? stats.total : stats.counts[value]
                    return (
                      <button
                        key={value}
                        onClick={() => setSeverity(value)}
                        aria-pressed={severity === value}
                        className={severity === value ? 'is-on' : ''}
                        disabled={value !== 'all' && count === 0}
                      >
                        {SEVERITY_LABEL[value]}
                        <span className="logs-sev-count">{count}</span>
                      </button>
                    )
                  })}
                </div>

                {stats.sources.length > 0 && (
                  <select
                    value={source ?? ''}
                    onChange={(e) => setSource(e.target.value || null)}
                    aria-label="Filter by source"
                    className="logs-select"
                  >
                    <option value="">All sources</option>
                    {stats.sources.map((s) => (
                      <option key={s.name} value={s.name}>{s.name} ({s.count})</option>
                    ))}
                  </select>
                )}

                <select
                  value={lines}
                  onChange={(e) => changeDepth(Number(e.target.value))}
                  aria-label="How many lines to read"
                  className="logs-select"
                >
                  {[80, 120, 300, 800, 2000].map((n) => (
                    <option key={n} value={n}>{n} lines</option>
                  ))}
                </select>

                <button onClick={() => setWrap((w) => !w)} className="log-toggle">
                  {wrap ? 'No wrap' : 'Wrap'}
                </button>
              </div>
            )}

            {maxBucket && selected && <VolumeStrip buckets={stats.buckets} />}

            <Card.Content className="logs-body">
              {!selected && (
                <div className="logs-placeholder">
                  <Icon name="logs" size={26} className="text-muted" />
                  <p>Pick a file on the left to read its tail.</p>
                  <p className="logs-placeholder-sub">
                    Levels, timestamps and sources are parsed into columns; a
                    search jumps between hits instead of hiding the context
                    around them.
                  </p>
                </div>
              )}

              {selected && tailErr && (
                <Alert status="danger" className="m-2">
                  <Alert.Description>{tailErr}</Alert.Description>
                </Alert>
              )}

              {selected && !tailErr && !tail && (
                <p className="py-10 text-center text-xs text-muted">Reading the tail…</p>
              )}

              {selected && tail?.empty && (
                <p className="py-10 text-center text-xs text-muted">This file is empty.</p>
              )}

              {selected && tailLines.length > 0 && (
                <div
                  className="log-viewer logs-scroll"
                  role="log"
                  aria-label={selected.name}
                  aria-live="off"
                  ref={scroller}
                >
                  {tail?.truncated && (
                    <p className="log-viewer-note">
                      showing the last {tail.returned} lines — the file is larger
                      than the read window
                    </p>
                  )}
                  <div className="log-view-head">
                    <span className="log-view-gutter">#</span>
                    <span className="log-view-time">time</span>
                    <span className="log-view-level">level</span>
                    <span className="log-view-source">source</span>
                    <span className="log-view-body">message</span>
                  </div>

                  {visible.length === 0 ? (
                    <p className="py-8 text-center text-xs text-muted">
                      No line is {severity === 'all' ? 'visible' : SEVERITY_LABEL[severity]}
                      {source ? ` from ${source}` : ''} in this window.
                    </p>
                  ) : (
                    visible.map((row) => (
                      <LogRow
                        key={row.index}
                        line={row.line}
                        number={row.index + 1}
                        parsed={row.parsed}
                        wrap={wrap}
                        query={needle}
                        active={needle.trim() !== '' && matches[pos] === row.index}
                      />
                    ))
                  )}
                </div>
              )}
            </Card.Content>

            {selected && tailLines.length > 0 && (
              <Card.Footer className="logs-foot">
                <span className="logs-foot-count">
                  {visible.length === stats.total
                    ? `${stats.total} line${stats.total === 1 ? '' : 's'}`
                    : `${visible.length} of ${stats.total} lines`}
                  {severity !== 'all' && <> · {SEVERITY_LABEL[severity]} only</>}
                  {source && <> · {source}</>}
                </span>
                <span className="logs-foot-actions">
                  {stats.firstError !== null && (
                    <button
                      type="button"
                      className="log-toggle"
                      onClick={() => scrollToLine(stats.firstError!)}
                    >
                      <Icon name="alert-circle" size={11} />
                      First error
                    </button>
                  )}
                  <button type="button" className="log-toggle" onClick={copyVisible}>
                    <Icon name={copied ? 'check' : 'copy'} size={11} />
                    {copied ? 'Copied' : 'Copy visible'}
                  </button>
                </span>
              </Card.Footer>
            )}
          </Card>
        </div>
      )}
    </>
  )
}

/** Exported for the parser's own tests; not part of the panel's API. */
export type { ParsedLine }
