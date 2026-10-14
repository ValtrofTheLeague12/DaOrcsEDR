import { useEffect, useMemo, useState } from 'react'
import { Card, Chip, Alert } from '@heroui/react'
import { api } from '../api'
import type { LogFile } from '../types'
import { LogLine, summarize } from '../lib/logColor'

// No auto-refresh here on purpose: the file list only changes when a service
// starts, which the operator already knows. Polling 120 files every 5s would
// be noise. Press Refresh, or switch panels and come back.

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
    <button
      onClick={onOpen}
      className={`flex w-full items-center justify-between gap-3 rounded-md px-3 py-2 text-left transition-colors ${
        active ? 'bg-default-100' : 'hover:bg-default-50'
      }`}
    >
      <span className="truncate font-mono text-xs">{file.name}</span>
      <span className="flex shrink-0 items-center gap-3 text-[11px] text-default-400">
        <span className="font-mono">{humanBytes(file.bytes)}</span>
        <span className="w-16 text-right">{humanAge(file.age_seconds)}</span>
      </span>
    </button>
  )
}

export default function Logs() {
  const [data, setData] = useState<Awaited<ReturnType<typeof api.logs>> | null>(null)
  const [err, setErr] = useState<string | null>(null)
  const [filter, setFilter] = useState('')
  const [selected, setSelected] = useState<LogFile | null>(null)
  const [tail, setTail] = useState<Awaited<ReturnType<typeof api.tail>> | null>(null)
  const [tailErr, setTailErr] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [wrap, setWrap] = useState(true)
  const [lines, setLines] = useState(120)

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
    api
      .tail(f.id, lines)
      .then((t) => {
        if (t.error) setTailErr(t.error)
        else setTail(t)
      })
      .catch((e) => setTailErr(e instanceof Error ? e.message : String(e)))
  }

  // Changing the depth reloads so the count and the pane agree.
  useEffect(() => {
    if (selected) open(selected)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [lines])

  const groups = useMemo(() => {
    if (!data) return []
    const needle = filter.trim().toLowerCase()
    return data.groups
      .filter((g) => g.present && g.files.length > 0)
      .map((g) => ({
        ...g,
        files: needle ? g.files.filter((f) => f.name.toLowerCase().includes(needle)) : g.files,
      }))
      .filter((g) => g.files.length > 0)
  }, [data, filter])

  const counts = useMemo(() => (tail?.lines ? summarize(tail.lines) : null), [tail])

  return (
    <>
      <div className="mb-6 flex items-baseline justify-between gap-4">
        <h2 className="page-title">Logs</h2>
        <div className="flex items-center gap-3">
          {data && (
            <Chip size="sm" variant="soft">
              {data.file_count} files · {humanBytes(data.total_bytes)}
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

      {err && (
        <Alert status="danger" className="mb-4">
          <Alert.Title>Cannot list logs</Alert.Title>
          <Alert.Description>{err}</Alert.Description>
        </Alert>
      )}

      {data && (
        <Alert status="accent" className="mb-4">
          <Alert.Title>No cap applied</Alert.Title>
          <Alert.Description>
            The admin terminal's log browser caps its admin group at 5 files and has
            no way to reach the rest. This lists everything on disk.
          </Alert.Description>
        </Alert>
      )}

      {loading && !data && <div className="py-10 text-sm text-default-500">Listing…</div>}

      {data && (
        <div className="grid grid-cols-1 gap-3 xl:grid-cols-[minmax(300px,380px)_1fr]">
          <Card className="w-full">
            <Card.Header>
              <input
                value={filter}
                onChange={(e) => setFilter(e.target.value)}
                placeholder="Filter by name…"
                className="w-full rounded-md border border-default-300 bg-transparent px-3 py-1.5 text-sm outline-none placeholder:text-default-400 focus:border-accent"
              />
            </Card.Header>
            <Card.Content className="max-h-[70vh] overflow-y-auto">
              {groups.length === 0 && (
                <p className="py-6 text-center text-xs text-default-400">
                  {filter ? 'Nothing matches that filter.' : 'No logs found.'}
                </p>
              )}
              {groups.map((g) => (
                <div key={g.key} className="mb-4 last:mb-0">
                  <div className="mb-1 flex items-center justify-between px-3">
                    <span className="text-[10px] font-semibold uppercase tracking-widest text-default-400">
                      {g.label}
                    </span>
                    <span className="font-mono text-[10px] text-default-400">
                      {g.files.length}
                    </span>
                  </div>
                  <div className="flex flex-col">
                    {g.files.map((f) => (
                      <FileRow
                        key={f.id}
                        file={f}
                        active={selected?.id === f.id}
                        onOpen={() => open(f)}
                      />
                    ))}
                  </div>
                </div>
              ))}
            </Card.Content>
          </Card>

          <Card className="w-full">
            <Card.Header className="flex flex-wrap items-center justify-between gap-2">
              <Card.Title className="truncate font-mono text-sm">
                {selected ? selected.name : 'Select a log'}
              </Card.Title>

              {selected && (
                <div className="flex items-center gap-2">
                  {tail?.jsonl && (
                    <Chip size="sm" variant="soft" color="accent">
                      json
                    </Chip>
                  )}
                  {!!tail?.ansi_stripped && (
                    <Chip size="sm" variant="soft">
                      {tail.ansi_stripped} ansi stripped
                    </Chip>
                  )}
                  {counts && (counts.danger > 0 || counts.warning > 0) && (
                    <span className="flex items-center gap-1.5">
                      {counts.danger > 0 && (
                        <Chip size="sm" variant="soft" color="danger">
                          {counts.danger} error
                        </Chip>
                      )}
                      {counts.warning > 0 && (
                        <Chip size="sm" variant="soft" color="warning">
                          {counts.warning} warn
                        </Chip>
                      )}
                    </span>
                  )}
                  <span className="font-mono text-[11px] text-default-400">
                    {humanBytes(selected.bytes)} · {humanAge(selected.age_seconds)}
                  </span>
                </div>
              )}
            </Card.Header>

            <Card.Content>
              {selected && (
                <div className="mb-3 flex items-center gap-2">
                  <select
                    value={lines}
                    onChange={(e) => setLines(Number(e.target.value))}
                    className="rounded-md border border-default-300 bg-transparent px-2 py-1 text-xs outline-none focus:border-accent"
                  >
                    {[80, 120, 300, 800, 2000].map((n) => (
                      <option key={n} value={n}>
                        {n} lines
                      </option>
                    ))}
                  </select>
                  <button
                    onClick={() => setWrap((w) => !w)}
                    className="rounded-md border border-default-300 px-2.5 py-1 text-xs hover:border-accent hover:text-accent"
                  >
                    {wrap ? 'No wrap' : 'Wrap'}
                  </button>
                  <button
                    onClick={() => selected && open(selected)}
                    className="rounded-md border border-default-300 px-2.5 py-1 text-xs hover:border-accent hover:text-accent"
                  >
                    Reload
                  </button>
                </div>
              )}

              {!selected && (
                <p className="py-10 text-center text-xs text-default-400">
                  Pick a file on the left to tail it.
                </p>
              )}
              {selected && tailErr && (
                <Alert status="danger">
                  <Alert.Description>{tailErr}</Alert.Description>
                </Alert>
              )}
              {selected && !tailErr && !tail && (
                <p className="py-6 text-center text-xs text-default-400">Loading…</p>
              )}
              {selected && tail?.empty && (
                <p className="py-6 text-center text-xs text-default-400">
                  This file is empty.
                </p>
              )}
              {tail?.lines && tail.lines.length > 0 && (
                <div className="max-h-[62vh] overflow-auto font-mono text-[11px] leading-relaxed">
                  {tail.truncated && (
                    <p className="mb-2 font-sans text-[11px] text-default-400">
                      showing the last {tail.returned} lines — the file is larger
                      than the read window
                    </p>
                  )}
                  {tail.lines.map((line, i) => (
                    <div
                      key={i}
                      className={wrap ? 'whitespace-pre-wrap break-all' : 'whitespace-pre'}
                    >
                      <LogLine line={line} number={i + 1} />
                    </div>
                  ))}
                </div>
              )}
            </Card.Content>
          </Card>
        </div>
      )}
    </>
  )
}