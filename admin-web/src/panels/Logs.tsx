import { useEffect, useMemo, useState } from 'react'
import { Card } from '@heroui/react/card'
import { Chip } from '@heroui/react/chip'
import { Alert } from '@heroui/react/alert'
import { api } from '../api'
import SubNav from '../components/SubNav'
import Pager, { usePaged } from '../components/Pager'
import TracePanel from '../components/TracePanel'
import { LogRow } from '../lib/logColor'
import type { LogFile, LogSummary } from '../types'

// Two tabs, one panel.
//
// Trace output was the reason this split. It is ~80 MB of native call-graph
// records in a directory of 140-odd small text logs, and mixing them meant the
// log list carried an entry nobody could meaningfully open and the trace viewer
// had to cope with lines that share no structure with anything else. They are
// different data with different questions, so they get different screens - but
// they stay under one nav entry because they are one concern.
//
// The log viewer below is structured rather than a <textarea> full of monospace:
// time, level, logger and message each get their own column so the one error in
// two thousand lines is findable without reading two thousand lines.

const FILES_PER_PAGE = 24

type Severity = 'all' | 'error' | 'warning' | 'info'

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

export default function Logs() {
  const [tab, setTab] = useState<'logs' | 'trace'>('logs')

  const [data, setData] = useState<Awaited<ReturnType<typeof api.logs>> | null>(null)
  const [err, setErr] = useState<string | null>(null)
  const [filter, setFilter] = useState('')
  const [selected, setSelected] = useState<LogFile | null>(null)
  const [tail, setTail] = useState<Awaited<ReturnType<typeof api.tail>> | null>(null)
  const [summary, setSummary] = useState<LogSummary | null>(null)
  const [tailErr, setTailErr] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [wrap, setWrap] = useState(true)
  const [lines, setLines] = useState(300)
  const [severity, setSeverity] = useState<Severity>('all')
  const [needle, setNeedle] = useState('')

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

  const open = (f: LogFile) => {
    setSelected(f)
    setTail(null)
    setTailErr(null)
    setSummary(null)
    api
      .tail(f.id, lines)
      .then((t) => {
        if (t.error) setTailErr(t.error)
        else setTail(t)
      })
      .catch((e) => setTailErr(e instanceof Error ? e.message : String(e)))
    api
      .logSummary(f.id, Math.max(lines, 2000))
      .then(setSummary)
      .catch(() => setSummary(null))
  }

  // Changing the depth reloads so the count and the pane agree.
  useEffect(() => {
    if (selected) open(selected)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [lines])

  const groups = useMemo(() => {
    if (!data) return []
    const query = filter.trim().toLowerCase()
    return data.groups
      .filter((g) => g.present && g.files.length > 0)
      // Traces are the other tab. They are still counted in the header so the
      // total matches what is actually on disk.
      .map((g) => ({
        ...g,
        files: query
          ? g.files.filter((f) => f.name.toLowerCase().includes(query))
          : g.files,
      }))
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

  const counts = summary?.levels ?? {}
  const errorCount = counts.error ?? counts.err ?? counts.fatal ?? counts.critical ?? 0
  const warnCount = counts.warn ?? counts.warning ?? counts.notice ?? 0
  const infoCount = counts.info ?? counts.information ?? 0

  // `lines` is optional on the wire type, so it is narrowed once here rather
  // than with a guard at each of the five places the viewer reads it.
  const tailLines = useMemo(() => tail?.lines ?? [], [tail?.lines])

  const visibleLines = useMemo(() => {
    const query = needle.trim().toLowerCase()
    return tailLines.filter((line) => {
      if (severity === 'error' && !/\b(error|err|fatal|critical|crit|panic)\b/i.test(line)) return false
      if (severity === 'warning' && !/\b(warn|warning|notice)\b/i.test(line)) return false
      if (severity === 'info' && !/\b(info|information|debug|trace|verbose)\b/i.test(line)) return false
      if (query && !line.toLowerCase().includes(query)) return false
      return true
    })
  }, [tailLines, severity, needle])

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
        <>
          {data && (
            <Alert status="accent" className="mb-4">
              <Alert.Title>No cap applied</Alert.Title>
              <Alert.Description>
                The admin terminal's log browser caps its admin group at 5 files and has
                no way to reach the rest. This lists everything on disk.
              </Alert.Description>
            </Alert>
          )}

          <div className="grid grid-cols-1 gap-3 xl:grid-cols-[minmax(300px,380px)_1fr]">
            <Card className="w-full">
              <Card.Header>
                <input
                  value={filter}
                  onChange={(e) => setFilter(e.target.value)}
                  placeholder="Filter by name…"
                  aria-label="Filter log files by name"
                  className="log-search"
                />
              </Card.Header>
              <Card.Content className="max-h-[70vh] overflow-y-auto">
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
                            onOpen={() => open(f)}
                          />
                        ))}
                      </div>
                    </div>
                  )
                })}
              </Card.Content>
              {flatFiles.length > FILES_PER_PAGE && (
                <Card.Footer>
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

            <Card className="w-full">
              <Card.Header className="flex flex-wrap items-center justify-between gap-2">
                <Card.Title className="truncate font-mono text-sm">
                  {selected ? selected.name : 'Select a log'}
                </Card.Title>

                {selected && (
                  <div className="flex flex-wrap items-center gap-2">
                    {tail?.jsonl && (
                      <Chip size="sm" variant="soft" color="accent">json</Chip>
                    )}
                    {!!tail?.ansi_stripped && (
                      <Chip size="sm" variant="soft">
                        {tail.ansi_stripped} ansi stripped
                      </Chip>
                    )}
                    {errorCount > 0 && (
                      <Chip size="sm" variant="soft" color="danger">{errorCount} error</Chip>
                    )}
                    {warnCount > 0 && (
                      <Chip size="sm" variant="soft" color="warning">{warnCount} warn</Chip>
                    )}
                    {infoCount > 0 && (
                      <Chip size="sm" variant="soft" color="accent">{infoCount} info</Chip>
                    )}
                    <span className="font-mono text-[11px] text-muted">
                      {humanBytes(selected.bytes)} · {humanAge(selected.age_seconds)}
                    </span>
                  </div>
                )}
              </Card.Header>

              <Card.Content>
                {selected && (
                  <div className="log-controls">
                    <input
                      value={needle}
                      onChange={(e) => setNeedle(e.target.value)}
                      placeholder="Search inside this log…"
                      aria-label="Search inside the selected log"
                      className="log-search"
                    />
                    <select
                      value={lines}
                      onChange={(e) => setLines(Number(e.target.value))}
                      aria-label="How many lines to read"
                    >
                      {[80, 120, 300, 800, 2000].map((n) => (
                        <option key={n} value={n}>{n} lines</option>
                      ))}
                    </select>
                    <div className="log-severity" role="group" aria-label="Filter by severity">
                      {(['all', 'error', 'warning', 'info'] as Severity[]).map((value) => (
                        <button
                          key={value}
                          onClick={() => setSeverity(value)}
                          aria-pressed={severity === value}
                          className={severity === value ? 'is-on' : ''}
                        >
                          {value}
                        </button>
                      ))}
                    </div>
                    <button
                      onClick={() => setWrap((w) => !w)}
                      className="log-toggle"
                    >
                      {wrap ? 'No wrap' : 'Wrap'}
                    </button>
                    <button
                      onClick={() => selected && open(selected)}
                      className="log-toggle"
                    >
                      Reload
                    </button>
                  </div>
                )}

                {!selected && (
                  <p className="py-10 text-center text-xs text-muted">
                    Pick a file on the left to tail it.
                  </p>
                )}
                {selected && tailErr && (
                  <Alert status="danger">
                    <Alert.Description>{tailErr}</Alert.Description>
                  </Alert>
                )}
                {selected && !tailErr && !tail && (
                  <p className="py-6 text-center text-xs text-muted">Loading…</p>
                )}
                {selected && tail?.empty && (
                  <p className="py-6 text-center text-xs text-muted">This file is empty.</p>
                )}

                {tailLines.length > 0 && (
                  <div className="log-viewer" role="log" aria-label={selected?.name ?? 'log'}>
                    {tail?.truncated && (
                      <p className="log-viewer-note">
                        showing the last {tail.returned} lines — the file is larger than
                        the read window
                      </p>
                    )}
                    {visibleLines.length === 0 && (
                      <p className="py-6 text-center text-xs text-muted">
                        No line matches the current filter.
                      </p>
                    )}
                    {visibleLines.map((line, i) => (
                      <LogRow
                        key={i}
                        line={line}
                        number={tailLines.length - visibleLines.length + i + 1}
                        wrap={wrap}
                        query={needle}
                      />
                    ))}
                    {(severity !== 'all' || needle.trim() !== '') && (
                      <p className="log-viewer-note">
                        {visibleLines.length} of {tailLines.length} lines shown
                      </p>
                    )}
                  </div>
                )}
              </Card.Content>
            </Card>
          </div>
        </>
      )}
    </>
  )
}