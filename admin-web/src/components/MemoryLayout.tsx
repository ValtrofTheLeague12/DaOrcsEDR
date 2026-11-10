import { useEffect, useState } from 'react'
import { Alert } from '@heroui/react/alert'
import { api } from '../api'
import { bytes } from '../lib/format'
import type { MemoryMapLayout, MemoryProfilingJob } from '../types'

function typeColor(value: string) {
  let hash = 0
  for (const char of value) hash = (hash * 31 + char.charCodeAt(0)) >>> 0
  return `hsl(${hash % 360} 58% 48%)`
}

function Stat({ label, value }: { label: string; value: number | null }) {
  return (
    <div className="min-w-[8rem] flex-1 rounded-medium bg-default-100 p-3">
      <p className="text-[10px] uppercase tracking-wide text-default-500">{label}</p>
      <p className="mt-1 text-sm font-semibold text-default-800">{bytes(value)}</p>
    </div>
  )
}

function RegionNode({
  region,
  defaultOpen,
}: {
  region: MemoryMapLayout['regions'][number]
  defaultOpen: boolean
}) {
  const children = region.children ?? []
  const [open, setOpen] = useState(defaultOpen)
  const hasChildren = children.length > 0

  return (
    <li className="relative list-none">
      <div
        className="grid grid-cols-[1.25rem_minmax(0,1.4fr)_minmax(4rem,1fr)_auto] items-center gap-2 rounded px-2 py-1.5 text-[10px] hover:bg-default-100/70"
        title={`${region.protection}${region.details ? ` · ${region.details}` : ''}`}
      >
        {hasChildren ? (
          <button
            type="button"
            onClick={() => setOpen((value) => !value)}
            aria-expanded={open}
            aria-label={`${open ? 'Collapse' : 'Expand'} ${region.address}, ${children.length} subregions`}
            className="flex h-5 w-5 items-center justify-center rounded text-default-500 hover:bg-default-200 hover:text-default-800"
          >
            <span aria-hidden="true" className="text-[11px] leading-none">{open ? '▾' : '▸'}</span>
          </button>
        ) : (
          <span aria-hidden="true" className="h-5 w-5" />
        )}
        <code className="truncate font-mono text-default-700">{region.address}</code>
        <span className="flex min-w-0 items-center gap-1.5">
          <span
            className="h-1.5 w-1.5 shrink-0 rounded-full"
            style={{ backgroundColor: typeColor(region.type) }}
          />
          <span className="truncate text-default-600" title={region.details || region.type}>
            {region.type}
          </span>
        </span>

        <span className="whitespace-nowrap text-right font-mono tabular-nums text-default-500">
          {bytes(region.size_bytes)}
        </span>
      </div>

      {open && hasChildren && (
        <ul className="ml-3 border-l border-default-200 pl-3">
          {children.map((child, index) => (
            <RegionNode
              key={`${child.address}-${index}`}
              region={child}
              defaultOpen={defaultOpen}
            />
          ))}
        </ul>
      )}
    </li>
  )
}

export default function MemoryLayout({ job }: { job: MemoryProfilingJob }) {
  const [layout, setLayout] = useState<MemoryMapLayout | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [treeOpen, setTreeOpen] = useState(false)
  const [treeGeneration, setTreeGeneration] = useState(0)

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
        if (!cancelled) {
          setError(exc instanceof Error ? exc.message : String(exc))
        }
      })
    return () => { cancelled = true }
  }, [job.id, job.state, job.csv_path])

  if (job.state === 'running') return null
  if (!job.csv_path) return null

  if (error) {
    return (
      <Alert status="danger" className="mt-3">
        <Alert.Title>Could not display the VMMap export</Alert.Title>
        <Alert.Description>{error}</Alert.Description>
      </Alert>
    )
  }
  if (!layout) {
    return <p className="mt-3 text-xs text-default-500">Reading VMMap memory map…</p>
  }

  const largestCategory = Math.max(1, ...layout.categories.map((category) => category.size_bytes ?? 0))
  const rootCount = layout.root_count ?? layout.regions.length

  return (
    <div className="mt-4 overflow-hidden rounded-xl border border-default-200 bg-background">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-default-200 px-4 py-3">
        <div>
          <h4 className="text-sm font-semibold text-default-800">Captured memory layout</h4>
          <p className="mt-0.5 text-[11px] text-default-500">
            {layout.process_name || 'Process'}{layout.process_id ? ` · PID ${layout.process_id}` : ''}
          </p>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-2 p-3 sm:grid-cols-4">
        <Stat label="Virtual space" value={layout.totals.size_bytes} />
        <Stat label="Committed" value={layout.totals.committed_bytes} />
        <Stat label="Working set" value={layout.totals.total_ws_bytes} />
        <Stat label="Private" value={layout.totals.private_bytes} />
      </div>

      <section className="px-4 pb-4">
        <div className="mb-3">
          <h4 className="text-xs font-semibold text-default-700">Memory by type</h4>
          <p className="text-[10px] text-default-500">Bars compare reserved size. Values also show working set.</p>
        </div>
        <div className="flex flex-col gap-2.5">
          {layout.categories.map((category) => {
            const size = category.size_bytes ?? 0
            const width = Math.max(1, (size / largestCategory) * 100)
            return (
              <div key={category.type} className="grid grid-cols-[6.5rem_minmax(3rem,1fr)_auto] items-center gap-3 text-[11px]">
                <span className="truncate text-default-600" title={category.type}>{category.type}</span>
                <div className="h-2 overflow-hidden rounded-full bg-default-200">
                  <div className="h-full rounded-full" style={{ width: `${width}%`, backgroundColor: typeColor(category.type) }} />
                </div>
                <span className="text-right font-mono text-default-600">{bytes(size)}</span>
                <span className="col-start-2 col-span-2 -mt-2 text-right text-[10px] text-default-400">
                  {bytes(category.total_ws_bytes)} working set
                </span>
              </div>
            )
          })}
        </div>
      </section>

      <section className="border-t border-default-200">
        <div className="flex flex-wrap items-center gap-2 px-4 py-3">
          <h4 className="text-xs font-medium text-default-600">Memory tree</h4>
          <span className="rounded-full bg-default-200/70 px-2 py-0.5 font-mono text-[10px] text-default-500">
            {rootCount.toLocaleString()} roots · {layout.region_count.toLocaleString()} nodes
          </span>
          <div className="ml-auto flex items-center gap-3 text-[10px]">
            <button
              type="button"
              className="text-accent underline underline-offset-2"
              onClick={(event) => {
                event.preventDefault()
                setTreeOpen(true)
                setTreeGeneration((value) => value + 1)
              }}
            >
              Expand all
            </button>
            <button
              type="button"
              className="text-accent underline underline-offset-2"
              onClick={(event) => {
                event.preventDefault()
                setTreeOpen(false)
                setTreeGeneration((value) => value + 1)
              }}
            >
              Collapse all
            </button>
          </div>
        </div>
        <div className="px-3 pb-3">
          <p className="mb-2 text-[10px] text-default-500">
            Expand a branch to inspect its subregions. Hover a row for protection and region details.
          </p>
          {layout.regions_truncated && (
            <p className="mb-2 text-[10px] text-warning">
              Showing {layout.region_count.toLocaleString()} of{' '}
              {(layout.region_total ?? layout.region_count).toLocaleString()} nodes.
            </p>
          )}
          {layout.regions.length === 0 ? (
            <p className="text-[11px] text-default-500">No address regions were present in this export.</p>
          ) : (
            <div className="max-h-[32rem] overflow-auto rounded-lg border border-default-200 bg-background p-2">
              <div className="grid grid-cols-[1.25rem_minmax(0,1.4fr)_minmax(4rem,1fr)_auto] gap-2 border-b border-default-200 px-2 pb-2 text-[9px] font-medium uppercase tracking-wide text-default-400">
                <span />
                <span>Address</span>
                <span>Type</span>
                <span className="text-right">Size</span>
              </div>
              <ul key={treeGeneration} className="pt-1">
                {layout.regions.map((region, index) => (
                  <RegionNode
                    key={`${region.address}-${index}`}
                    region={region}
                    defaultOpen={treeOpen}
                  />
                ))}
              </ul>
            </div>
          )}
        </div>
      </section>
      <p className="border-t border-default-200 px-4 py-2 text-[10px] text-default-500">
        VMMap shows process layout and working set, not function-level allocations or individual leaks.
      </p>
    </div>
  )
}
