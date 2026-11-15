import { useEffect, useMemo, useState } from 'react'
import { Alert } from '@heroui/react/alert'
import { api } from '../api'
import { bytes } from '../lib/format'
import type { MemoryMapCategory, MemoryMapLayout, MemoryMapRegion, MemoryProfilingJob } from '../types'

// ---------------------------------------------------------------------------
// Colour: one fixed hue per VMMap region type, so "Heap" is the same colour in
// the donut, the breakdown bars, the region ranking and the tree. Unknown types
// fall back to a stable hash. Free address space is drawn as a neutral grey.
// ---------------------------------------------------------------------------

const TYPE_COLOR: Record<string, string> = {
  image: '#5b8def',
  heap: '#2fbf9b',
  'private data': '#8b7cf6',
  stack: '#f2a33a',
  'mapped file': '#ec6a9a',
  shareable: '#38bdf8',
  'page table': '#8c9bb0',
  'managed heap': '#4ade80',
  unusable: '#ef6b6b',
  free: '#64748b',
}

function typeColor(value: string) {
  const known = TYPE_COLOR[value.trim().toLowerCase()]
  if (known) return known
  let hash = 0
  for (const char of value) hash = (hash * 31 + char.charCodeAt(0)) >>> 0
  return `hsl(${hash % 360} 55% 58%)`
}

const isFree = (type: string) => type.trim().toLowerCase() === 'free'

type Metric = 'ws' | 'committed' | 'size'

const METRICS: { id: Metric; label: string; hint: string }[] = [
  { id: 'ws', label: 'Working set', hint: 'Physical memory in use right now' },
  { id: 'committed', label: 'Committed', hint: 'Memory the process has backing for' },
  { id: 'size', label: 'Reserved', hint: 'Virtual address space set aside' },
]

function metricValue(category: MemoryMapCategory, metric: Metric) {
  if (metric === 'ws') return category.total_ws_bytes ?? 0
  if (metric === 'committed') return category.committed_bytes ?? 0
  return category.size_bytes ?? 0
}

const share = (part: number | null, whole: number | null) =>
  part && whole ? `${Math.round((part / whole) * 100)}%` : '—'

// ---------------------------------------------------------------------------
// Pieces
// ---------------------------------------------------------------------------

function Kpi({ label, value, note }: { label: string; value: number | null; note: string }) {
  return (
    <div className="mem-kpi">
      <p className="mem-kpi-label">{label}</p>
      <p className="mem-kpi-value">{bytes(value)}</p>
      <p className="mem-kpi-note">{note}</p>
    </div>
  )
}

function Donut({
  slices,
  total,
  label,
  hot,
  setHot,
}: {
  slices: { type: string; value: number }[]
  total: number
  label: string
  hot: string | null
  setHot: (type: string | null) => void
}) {
  const radius = 44
  const circumference = 2 * Math.PI * radius
  const gap = slices.length > 1 ? 1.4 : 0
  let offset = 0

  return (
    <div className="mem-donut">
      <svg viewBox="0 0 120 120" role="img" aria-label={`${label} by region type`}>
        <circle cx="60" cy="60" r={radius} className="mem-donut-track" />
        {slices.map((slice) => {
          const length = total ? (slice.value / total) * circumference : 0
          const dash = Math.max(0, length - gap)
          const node = (
            <circle
              key={slice.type}
              cx="60"
              cy="60"
              r={radius}
              className="mem-donut-slice"
              style={{
                stroke: typeColor(slice.type),
                strokeDasharray: `${dash} ${circumference - dash}`,
                strokeDashoffset: -offset,
                opacity: hot && hot !== slice.type ? 0.28 : 1,
              }}
              onMouseEnter={() => setHot(slice.type)}
              onMouseLeave={() => setHot(null)}
            >
              <title>{`${slice.type}: ${bytes(slice.value)}`}</title>
            </circle>
          )
          offset += length
          return node
        })}
      </svg>
      <div className="mem-donut-center">
        <strong>{bytes(hot ? slices.find((s) => s.type === hot)?.value ?? 0 : total)}</strong>
        <span>{hot ?? label}</span>
      </div>
    </div>
  )
}

function flatten(regions: MemoryMapRegion[], trail: string[] = []): (MemoryMapRegion & { trail: string })[] {
  const rows: (MemoryMapRegion & { trail: string })[] = []
  for (const region of regions) {
    rows.push({ ...region, trail: trail.join(' › ') })
    if (region.children?.length) {
      rows.push(...flatten(region.children, [...trail, region.details || region.type]))
    }
  }
  return rows
}

function matches(region: MemoryMapRegion, needle: string): boolean {
  if (!needle) return true
  const own = `${region.address} ${region.type} ${region.details} ${region.protection}`.toLowerCase()
  return own.includes(needle) || (region.children ?? []).some((child) => matches(child, needle))
}

function RegionNode({
  region,
  defaultOpen,
  needle,
}: {
  region: MemoryMapRegion
  defaultOpen: boolean
  needle: string
}) {
  const children = (region.children ?? []).filter((child) => matches(child, needle))
  const [open, setOpen] = useState(defaultOpen)
  const hasChildren = children.length > 0
  const expanded = open || (Boolean(needle) && hasChildren)

  return (
    <li className="list-none">
      <div className="mem-row" title={`${region.protection}${region.details ? ` · ${region.details}` : ''}`}>
        {hasChildren ? (
          <button
            type="button"
            onClick={() => setOpen((value) => !value)}
            aria-expanded={expanded}
            aria-label={`${expanded ? 'Collapse' : 'Expand'} ${region.address}, ${children.length} subregions`}
            className="mem-twisty"
          >
            <span aria-hidden="true">{expanded ? '▾' : '▸'}</span>
          </button>
        ) : (
          <span aria-hidden="true" className="mem-twisty" />
        )}
        <code className="mem-addr">{region.address}</code>
        <span className="mem-type">
          <i style={{ backgroundColor: typeColor(region.type) }} />
          <span className="truncate">{region.type}</span>
        </span>
        <span className="mem-detail truncate">{region.details || region.protection}</span>
        <span className="mem-size">{bytes(region.size_bytes)}</span>
      </div>
      {expanded && hasChildren && (
        <ul className="mem-children">
          {children.map((child, index) => (
            <RegionNode key={`${child.address}-${index}`} region={child} defaultOpen={defaultOpen} needle={needle} />
          ))}
        </ul>
      )}
    </li>
  )
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export type MemoryView = 'overview' | 'tree' | 'output'

export default function MemoryLayout({ job, view = 'overview' }: { job: MemoryProfilingJob; view?: MemoryView }) {
  const [layout, setLayout] = useState<MemoryMapLayout | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [metric, setMetric] = useState<Metric>('ws')
  const [hot, setHot] = useState<string | null>(null)
  const [treeOpen, setTreeOpen] = useState(false)
  const [treeGeneration, setTreeGeneration] = useState(0)
  const [query, setQuery] = useState('')

  useEffect(() => {
    let cancelled = false
    setLayout(null)
    setError(null)
    if (job.state === 'running' || !job.csv_path) return

    void api.memoryProfilingLayout(job.id)
      .then((response) => {
        if (!cancelled) setLayout(response.layout)
      })
      .catch((exc) => {
        if (!cancelled) setError(exc instanceof Error ? exc.message : String(exc))
      })
    return () => { cancelled = true }
  }, [job.id, job.state, job.csv_path])

  const view_ = useMemo(() => {
    if (!layout) return null
    const real = layout.categories.filter((category) => !isFree(category.type))
    const free = layout.categories.find((category) => isFree(category.type))
    const ranked = real
      .map((category) => ({ category, value: metricValue(category, metric) }))
      .filter((row) => row.value > 0)
      .sort((a, b) => b.value - a.value)
    const total = ranked.reduce((sum, row) => sum + row.value, 0)
    const regions = flatten(layout.regions)
      .filter((region) => !isFree(region.type) && (region.size_bytes ?? 0) > 0)
      .sort((a, b) => (b.size_bytes ?? 0) - (a.size_bytes ?? 0))
      .slice(0, 8)
    return { ranked, total, free, regions }
  }, [layout, metric])

  if (job.state === 'running' || !job.csv_path) return null
  if (view === 'output') return null

  if (error) {
    return (
      <Alert status="danger">
        <Alert.Title>Could not display the VMMap export</Alert.Title>
        <Alert.Description>{error}</Alert.Description>
      </Alert>
    )
  }
  if (!layout || !view_) {
    return <p className="mem-loading">Reading VMMap memory map…</p>
  }

  const { ranked, total, free, regions } = view_
  const totals = layout.totals
  const topValue = ranked[0]?.value || 1
  const largest = regions[0]?.size_bytes || 1
  const metricInfo = METRICS.find((entry) => entry.id === metric)!
  const privateWs = totals.private_ws_bytes ?? 0
  const sharedWs = totals.shareable_ws_bytes ?? 0
  const compWs = privateWs + sharedWs
  const needle = query.trim().toLowerCase()
  const visibleRoots = layout.regions.filter((region) => matches(region, needle))

  if (view === 'tree') {
    return (
      <div className="mem-tree">
        <div className="mem-tree-bar">
          <input
            className="field mem-search"
            type="search"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Filter by address, type, module or protection…"
            aria-label="Filter memory regions"
          />
          <span className="mem-count">
            {needle
              ? `${visibleRoots.length.toLocaleString()} matching roots`
              : `${(layout.root_count ?? layout.regions.length).toLocaleString()} roots · ${layout.region_count.toLocaleString()} nodes`}
          </span>
          <div className="mem-tree-actions">
            <button type="button" onClick={() => { setTreeOpen(true); setTreeGeneration((v) => v + 1) }}>Expand all</button>
            <button type="button" onClick={() => { setTreeOpen(false); setTreeGeneration((v) => v + 1) }}>Collapse all</button>
          </div>
        </div>
        {layout.regions_truncated && (
          <p className="mem-warn">
            Showing {layout.region_count.toLocaleString()} of{' '}
            {(layout.region_total ?? layout.region_count).toLocaleString()} nodes.
          </p>
        )}
        {visibleRoots.length === 0 ? (
          <p className="mem-empty">
            {layout.regions.length === 0
              ? 'No address regions were present in this export.'
              : 'No regions match this filter.'}
          </p>
        ) : (
          <div className="mem-tree-scroll">
            <div className="mem-row mem-head">
              <span />
              <span>Address</span>
              <span>Type</span>
              <span>Details</span>
              <span className="text-right">Size</span>
            </div>
            <ul key={`${treeGeneration}-${needle}`}>
              {visibleRoots.map((region, index) => (
                <RegionNode key={`${region.address}-${index}`} region={region} defaultOpen={treeOpen} needle={needle} />
              ))}
            </ul>
          </div>
        )}
      </div>
    )
  }

  return (
    <div className="mem-overview">
      <div className="mem-kpis">
        <Kpi label="Virtual space" value={totals.size_bytes} note={free ? `${bytes(free.size_bytes)} of it is free` : 'address space reserved'} />
        <Kpi label="Committed" value={totals.committed_bytes} note={`${share(totals.committed_bytes, totals.size_bytes)} of virtual`} />
        <Kpi label="Working set" value={totals.total_ws_bytes} note={`${share(totals.total_ws_bytes, totals.committed_bytes)} of committed`} />
        <Kpi label="Private" value={totals.private_bytes} note={`${share(totals.private_bytes, totals.committed_bytes)} of committed`} />
      </div>

      <section className="mem-panel">
        <div className="mem-panel-head">
          <div>
            <h4>Memory by region type</h4>
            <p>{metricInfo.hint}.{free ? ' Free address space is left out.' : ''}</p>
          </div>
          <div className="mem-seg" role="tablist" aria-label="Chart metric">
            {METRICS.map((entry) => (
              <button
                key={entry.id}
                type="button"
                role="tab"
                aria-selected={metric === entry.id}
                className={metric === entry.id ? 'is-on' : ''}
                onClick={() => setMetric(entry.id)}
              >
                {entry.label}
              </button>
            ))}
          </div>
        </div>

        {ranked.length === 0 ? (
          <p className="mem-empty">Nothing is counted under this metric.</p>
        ) : (
          <div className="mem-chart">
            <Donut slices={ranked.map((row) => ({ type: row.category.type, value: row.value }))} total={total} label={metricInfo.label} hot={hot} setHot={setHot} />
            <div className="mem-legend" role="table" aria-label="Breakdown by type">
              <div className="mem-legend-row mem-legend-head" role="row">
                <span role="columnheader">Type</span>
                <span role="columnheader" />
                <span role="columnheader" className="text-right">Share</span>
                <span role="columnheader" className="text-right">{metricInfo.label}</span>
              </div>
              {ranked.map(({ category, value }) => (
                <div
                  key={category.type}
                  role="row"
                  title={`${category.type} · reserved ${bytes(category.size_bytes)} · committed ${bytes(category.committed_bytes)} · working set ${bytes(category.total_ws_bytes)}`}
                  className={`mem-legend-row ${hot === category.type ? 'is-hot' : ''}`}
                  onMouseEnter={() => setHot(category.type)}
                  onMouseLeave={() => setHot(null)}
                >
                  <span className="mem-type" role="cell"><i style={{ backgroundColor: typeColor(category.type) }} /><span className="truncate">{category.type}</span></span>
                  <span className="mem-bar" role="cell"><b style={{ width: `${Math.max(2, (value / topValue) * 100)}%`, backgroundColor: typeColor(category.type) }} /></span>
                  <span className="mem-num" role="cell">{Math.round((value / total) * 100)}%</span>
                  <span className="mem-num strong" role="cell">{bytes(value)}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </section>

      <div className="mem-split">
        {compWs > 0 && (
          <section className="mem-panel">
            <div className="mem-panel-head">
              <div>
                <h4>Working set ownership</h4>
                <p>How much resident memory belongs to this process alone.</p>
              </div>
            </div>
            <div className="mem-stack" role="img" aria-label={`Private ${bytes(privateWs)}, shareable ${bytes(sharedWs)}`}>
              <b className="is-private" style={{ width: `${(privateWs / compWs) * 100}%` }} />
              <b className="is-shared" style={{ width: `${(sharedWs / compWs) * 100}%` }} />
            </div>
            <dl className="mem-stack-key">
              <div><dt><i className="is-private" />Private</dt><dd>{bytes(privateWs)}<small>{share(privateWs, compWs)}</small></dd></div>
              <div><dt><i className="is-shared" />Shareable</dt><dd>{bytes(sharedWs)}<small>{share(sharedWs, compWs)}</small></dd></div>
            </dl>
          </section>
        )}

        {regions.length > 0 && (
          <section className="mem-panel">
            <div className="mem-panel-head">
              <div>
                <h4>Largest regions</h4>
                <p>Biggest single address ranges by reserved size.</p>
              </div>
            </div>
            <ol className="mem-top">
              {regions.map((region, index) => (
                <li key={`${region.address}-${index}`}>
                  <div className="mem-top-line">
                    <span className="mem-type"><i style={{ backgroundColor: typeColor(region.type) }} /><span className="truncate">{region.details || region.type}</span></span>
                    <span className="mem-num strong">{bytes(region.size_bytes)}</span>
                  </div>
                  <div className="mem-bar"><b style={{ width: `${Math.max(2, ((region.size_bytes ?? 0) / largest) * 100)}%`, backgroundColor: typeColor(region.type) }} /></div>
                  <code className="mem-top-addr">{region.address}<span>{region.protection}</span></code>
                </li>
              ))}
            </ol>
          </section>
        )}
      </div>

      <p className="mem-foot">
        VMMap shows process layout and working set, not function-level allocations or individual leaks.
      </p>
    </div>
  )
}
