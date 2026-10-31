import { useEffect, useMemo, useRef, useState } from 'react'
import { Alert } from '@heroui/react/alert'
import { Button } from '@heroui/react/button'
import { usePoll, api } from '../api'
import { ServiceCard } from '../components/ServiceCard'
import Loading from '../components/Loading'
import Icon from '../components/Icon'
import type { Probe } from '../types'

// 5s matches the admin terminal's own status cadence (--interval default 5).
// Faster is indistinguishable; slower starts to feel broken.
const INTERVAL = 5000

// Group labels for the role keys services.py assigns. Ordered pipeline-first:
// these are the services an analysis depends on, so they read top to bottom in
// the order a sample would flow through them.
const ROLE_ORDER = ['analysis', 'pipeline', 'access', 'core'] as const

const ROLE_LABEL: Record<string, string> = {
  analysis: 'Analysis',
  pipeline: 'Pipeline',
  access: 'Access',
  core: 'Core',
}

const ROLE_HINT: Record<string, string> = {
  analysis: 'Processes a sample and scores it',
  pipeline: 'Feeds the streaming pipeline',
  access: 'Reaches the sandbox VMs',
  core: 'Everything else',
}

type Filter = 'all' | 'down' | 'up'
type Sort = 'role' | 'health' | 'latency'

// Five per page. Ten services fit on two pages, which is the point: the panel
// stops being one long scroll of cards and starts being a list you can move
// through. Chosen to leave a partial page visible rather than exactly filling
// two - a full second page with nothing after it hides that anything follows.
const PAGE_SIZE = 5

// Matches on everything an operator might plausibly type. Port is included
// separately so "60025" finds the analyzer without the user having to know it
// is in the endpoint string.
function matches(p: Probe, q: string): boolean {
  if (!q) return true
  const hay = `${p.name} ${p.key} ${p.host} ${p.port} ${p.role} ${p.description} ${p.endpoint}`.toLowerCase()
  return hay.includes(q)
}

// Down services sort last for latency purposes, not first: a 0 ms refused
// connection is not "fast", and letting it top the slowest list would be a lie.
// Infinity puts them below every real measurement, and the Down filter catches
// them anyway.
function latencyOf(p: Probe): number {
  return p.up ? p.ms : Number.POSITIVE_INFINITY
}

export default function Overview() {
  const { data, error, loading, refresh } = usePoll(api.overview, INTERVAL)
  const [filter, setFilter] = useState<Filter>('all')
  const [sort, setSort] = useState<Sort>('role')
  const [q, setQ] = useState('')
  const [page, setPage] = useState(0)
  const searchRef = useRef<HTMLInputElement>(null)

  // "/" focuses search, the way every other tool on earth does it. Ignored while
  // the user is already typing somewhere, and cleared by Escape.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const el = document.activeElement
      const typing =
        el instanceof HTMLInputElement ||
        el instanceof HTMLTextAreaElement ||
        (el instanceof HTMLElement && el.isContentEditable)
      if (e.key === '/' && !typing) {
        e.preventDefault()
        searchRef.current?.focus()
      } else if (e.key === 'Escape' && document.activeElement === searchRef.current) {
        setQ('')
        searchRef.current?.blur()
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  const services = data?.services ?? []

  const downCount = services.filter((s) => !s.up).length
  const upCount = services.length - downCount

  const visible = useMemo(() => {
    let out = services.filter((s) => matches(s, q.trim().toLowerCase()))
    if (filter === 'down') out = out.filter((s) => !s.up)
    if (filter === 'up') out = out.filter((s) => s.up)
    return out
  }, [services, q, filter])

  const groups = useMemo(() => {
    const known = new Set(ROLE_ORDER as readonly string[])
    const buckets = new Map<string, Probe[]>()
    for (const s of visible) {
      const key = known.has(s.role) ? s.role : 'other'
      const list = buckets.get(key)
      if (list) list.push(s)
      else buckets.set(key, [s])
    }

    const entries = [...buckets.entries()].map(([role, items]) => {
      const worst = items.reduce((m, p) => Math.max(m, p.up ? p.ms : 0), 0)
      const down = items.filter((p) => !p.up).length
      return { role, items, worst, down }
    })

    const byMembers = (a: Probe, b: Probe) => {
      if (sort === 'latency') return latencyOf(b) - latencyOf(a)
      if (sort === 'health') {
        if (a.up !== b.up) return a.up ? 1 : -1
        return latencyOf(b) - latencyOf(a)
      }
      return a.name.localeCompare(b.name)
    }
    entries.forEach((e) => e.items.sort(byMembers))

    if (sort === 'role') {
      entries.sort((a, b) => {
        const ai = ROLE_ORDER.indexOf(a.role as (typeof ROLE_ORDER)[number])
        const bi = ROLE_ORDER.indexOf(b.role as (typeof ROLE_ORDER)[number])
        return (ai === -1 ? 99 : ai) - (bi === -1 ? 99 : bi)
      })
    } else if (sort === 'health') {
      // Worst group first, so the reason a filter matched is at the top.
      entries.sort((a, b) => b.down - a.down || b.worst - a.worst)
    } else {
      entries.sort((a, b) => latencyOf(a.items[0]) - latencyOf(b.items[0]))
    }

    // Flatten to a single ordered list for paging, then regroup within the page.
    // Grouping is kept because it is the only thing that explains what a
    // service is FOR; the page boundary is what keeps the scroll bounded.
    const flat = entries.flatMap((e) => e.items)
    return flat
  }, [visible, sort])

  const pageCount = Math.max(1, Math.ceil(groups.length / PAGE_SIZE))
  // Clamp rather than trust the state: a filter that narrows the list can leave
  // the page index pointing past the end, which renders an empty page.
  const pageIdx = Math.min(page, pageCount - 1)
  const paged = groups.slice(pageIdx * PAGE_SIZE, pageIdx * PAGE_SIZE + PAGE_SIZE)

  // Regroup whatever landed on this page, preserving the sorted order.
  const pageGroups = useMemo(() => {
    const known = new Set(ROLE_ORDER as readonly string[])
    const buckets = new Map<string, Probe[]>()
    for (const s of paged) {
      const key = known.has(s.role) ? s.role : 'other'
      const list = buckets.get(key)
      if (list) list.push(s)
      else buckets.set(key, [s])
    }
    return [...buckets.entries()].map(([role, items]) => ({ role, items }))
  }, [paged])

  // Any change to what is listed or ordered invalidates the page: keeping page
  // 3 while a filter drops the list to one page would show nothing at all.
  const resetKey = `${filter}|${sort}|${q}|${visible.length}`
  const [lastResetKey, setLastResetKey] = useState(resetKey)
  if (lastResetKey !== resetKey) {
    setLastResetKey(resetKey)
    setPage(0)
  }

  const filtered = visible.length !== services.length

  return (
    <>
      <div className="mb-4 flex items-baseline justify-between gap-4">
        <h2 className="page-title">Services</h2>
        <div className="flex items-center gap-3">
          <span className="meta-pill">live probe of every endpoint</span>
          <Button size="sm" variant="outline" onPress={refresh}>
            Refresh
          </Button>
        </div>
      </div>

      {error && (
        <Alert status="danger" className="mb-4">
          <Alert.Title>Panel API unreachable</Alert.Title>
          <Alert.Description>{error}</Alert.Description>
        </Alert>
      )}

      {loading && !data && <Loading label="Loading services…" hint="probing every endpoint" />}

      {data && !data.ml_auth && (
        <Alert status="warning" className="mb-4">
          <Alert.Title>ML_SERVE_TOKEN is not set</Alert.Title>
          <Alert.Description>
            Per <code>ml/serve.py</code>, an unset token means{' '}
            <code>/score</code> accepts any caller and will parse any readable file.
            Safe only because it is loopback-bound.
          </Alert.Description>
        </Alert>
      )}

      {data && upCount === 0 && (
        <Alert status="accent" className="mb-4">
          <Alert.Title>Nothing is up</Alert.Title>
          <Alert.Description>
            Every endpoint refused. Check the host/port on each card against what
            the service is actually bound to, or start them from the Containers
            panel.
          </Alert.Description>
        </Alert>
      )}

      {data && (
        <>
          {/* headline + triage toolbar */}
          <div className="mb-4 flex flex-wrap items-center justify-between gap-4">
            <div className="flex items-baseline gap-2">
              <span
                className={`font-mono text-3xl font-semibold leading-none tracking-tight ${
                  upCount === services.length ? 'text-success' : upCount === 0 ? 'text-danger' : 'text-warning'
                }`}
              >
                {upCount}
              </span>
              <span className="text-xs text-default-500">/ {services.length} up</span>
              {downCount > 0 && (
                <span className="ml-2 text-xs text-danger">{downCount} down</span>
              )}
              {data.ml_auth && (
                <span
                  title="ML_SERVE_TOKEN is set, so /score rejects unauthenticated callers"
                  className="ml-2 inline-flex items-center gap-1 rounded-full bg-success/12 px-2 py-0.5 text-[11px] font-medium text-success"
                >
                  <Icon name="overview" size={12} />
                  ML auth on
                </span>
              )}
            </div>

            <div className="flex flex-wrap items-center gap-2">
              {/* search */}
              <div className="relative">
                <Icon
                  name="search"
                  size={13}
                  className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-default-400"
                />
                <input
                  ref={searchRef}
                  value={q}
                  onChange={(e) => setQ(e.target.value)}
                  placeholder="Filter…  /"
                  aria-label="Filter services"
                  className="w-44 rounded-lg border border-default-200 bg-surface/60 py-1.5 pl-8 pr-7 text-xs outline-none transition-colors placeholder:text-default-400 focus:border-accent"
                />
                {q && (
                  <button
                    onClick={() => setQ('')}
                    aria-label="Clear filter"
                    className="absolute right-2 top-1/2 -translate-y-1/2 text-default-400 hover:text-foreground"
                  >
                    <Icon name="refresh" size={11} />
                  </button>
                )}
              </div>

              {/* health filter */}
              <div className="flex overflow-hidden rounded-lg border border-default-200">
                {(
                  [
                    ['all', `All ${services.length}`],
                    ['down', `Down ${downCount}`],
                    ['up', `Live ${upCount}`],
                  ] as [Filter, string][]
                ).map(([id, label]) => (
                  <button
                    key={id}
                    onClick={() => setFilter(id)}
                    className={`px-2.5 py-1.5 text-[11px] font-medium transition-colors ${
                      filter === id
                        ? 'bg-accent/12 text-foreground'
                        : 'text-default-500 hover:bg-default-100 hover:text-foreground'
                    }`}
                  >
                    {label}
                  </button>
                ))}
              </div>

              {/* sort */}
              <select
                value={sort}
                onChange={(e) => setSort(e.target.value as Sort)}
                aria-label="Sort services"
                className="cursor-pointer rounded-lg border border-default-200 bg-surface/60 px-2 py-1.5 text-[11px] text-default-600 outline-none focus:border-accent"
              >
                <option value="role">By role</option>
                <option value="health">Worst first</option>
                <option value="latency">Slowest first</option>
              </select>
            </div>
          </div>

          {/* result count, only once a filter is actually narrowing things */}
          {filtered && (
            <p className="mb-3 font-mono text-[11px] text-default-400">
              showing {visible.length} of {services.length}
              {downCount > 0 && filter !== 'down' && (
                <button
                  onClick={() => setFilter('down')}
                  className="ml-2 underline decoration-dotted underline-offset-2 hover:text-danger"
                >
                  show only the {downCount} down service{downCount === 1 ? '' : 's'}
                </button>
              )}
            </p>
          )}

          {/* cards */}
          {groups.length === 0 ? (
            <div className="rounded-xl border border-default-200/70 py-12 text-center">
              <p className="text-sm text-default-500">
                {filter === 'down' && downCount === 0
                  ? 'Nothing is down — every endpoint answered.'
                  : 'No service matches that filter.'}
              </p>
              {(q || filter !== 'all') && (
                <button
                  onClick={() => {
                    setQ('')
                    setFilter('all')
                  }}
                  className="mt-2 text-xs text-accent underline underline-offset-2"
                >
                  clear filters
                </button>
              )}
            </div>
          ) : (
            <>
              <div className="flex flex-col gap-6">
                {pageGroups.map((g) => (
                  <div key={g.role}>
                    <div className="mb-2.5 flex items-baseline gap-3">
                      <h3 className="section-label">{ROLE_LABEL[g.role] ?? g.role}</h3>
                      <span className="text-[11px] text-default-400">{ROLE_HINT[g.role] ?? ''}</span>
                      <span className="font-mono text-[11px] text-default-400">
                        {g.items.filter((s) => s.up).length}/{g.items.length}
                      </span>
                    </div>
                    <div className="grid grid-cols-1 gap-3 lg:grid-cols-2 2xl:grid-cols-3">
                      {g.items.map((s) => (
                        <ServiceCard key={s.key} probe={s} />
                      ))}
                    </div>
                  </div>
                ))}
              </div>

              {/* Controls only appear when there is more than one page, so a
                  short list does not get a decorative pager under it. */}
              {pageCount > 1 && (
                <nav
                  aria-label="Service pages"
                  className="mt-6 flex items-center justify-center gap-2"
                >
                  <button
                    onClick={() => setPage((p) => Math.max(0, p - 1))}
                    disabled={pageIdx === 0}
                    className="rounded-md border border-default-300 px-2.5 py-1 text-xs hover:border-accent hover:text-accent disabled:opacity-35 disabled:hover:border-default-300 disabled:hover:text-inherit"
                  >
                    Prev
                  </button>
                  {Array.from({ length: pageCount }, (_, i) => (
                    <button
                      key={i}
                      onClick={() => setPage(i)}
                      aria-current={i === pageIdx ? 'page' : undefined}
                      className={`min-w-[1.75rem] rounded-md px-2 py-1 font-mono text-xs transition-colors ${
                        i === pageIdx
                          ? 'bg-accent/15 text-foreground ring-1 ring-accent/30'
                          : 'text-default-500 hover:bg-default-100 hover:text-foreground'
                      }`}
                    >
                      {i + 1}
                    </button>
                  ))}
                  <button
                    onClick={() => setPage((p) => Math.min(pageCount - 1, p + 1))}
                    disabled={pageIdx >= pageCount - 1}
                    className="rounded-md border border-default-300 px-2.5 py-1 text-xs hover:border-accent hover:text-accent disabled:opacity-35 disabled:hover:border-default-300 disabled:hover:text-inherit"
                  >
                    Next
                  </button>
                  <span className="ml-2 font-mono text-[11px] text-default-400">
                    {page * PAGE_SIZE + 1}–{Math.min((page + 1) * PAGE_SIZE, groups.length)} of{' '}
                    {groups.length}
                  </span>
                </nav>
              )}
            </>
          )}
        </>
      )}
    </>
  )
}