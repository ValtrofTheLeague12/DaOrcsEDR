import { useMemo } from 'react'
import type { NetLink, NetMap, NetNode } from '../types'

// ---------------------------------------------------------------------------
// Network map - a hand-rolled SVG topology.
//
// A graph library for one rooted tree is not worth the bundle, and this keeps
// the styling tied to CSS tokens so it restyles with the theme. The backend
// returns a node/link graph rooted at the host, so the layout is a BFS by
// depth: depth 0 is the host at the centre, each deeper depth rings out around
// it. Same-depth nodes spread on an arc so they do not overlap.
//
// Colour encodes kind; opacity encodes status - a powered-off VM is visibly
// dimmer than a running container, which is the whole point of a map.
// ---------------------------------------------------------------------------

export const KIND_STROKE: Record<NetNode['kind'], string> = {
  host: 'var(--accent)',
  adapter: '#a78bfa', // violet - a NIC is distinct from the machine itself
  network: 'var(--success)',
  vm: 'var(--warning)',
  container: '#38bdf8', // sky - containers cluster under their bridge
}

// Same palette, used to fill the node disc faintly so kind reads even when the
// circle overlaps a link.
const KIND_FILL_OPACITY = 0.14

const STATUS_OPACITY: Record<NetNode['status'], number> = {
  up: 1,
  running: 0.75,
  down: 0.35,
}

const KIND_LABEL: Record<NetNode['kind'], string> = {
  host: 'Host',
  adapter: 'Interface',
  network: 'Network',
  vm: 'VM',
  container: 'Container',
}

export function statusTone(status: NetNode['status']): string {
  return status === 'up' ? 'text-success' : status === 'running' ? 'text-warning' : 'text-danger'
}

const W = 760
const H = 420
const CX = W / 2
const CY = H / 2

interface Placed extends NetNode {
  x: number
  y: number
  depth: number
}

function layout(nodes: NetNode[], links: NetLink[]): { placed: Placed[]; edges: [Placed, Placed][] } {
  const childrenOf = new Map<string, string[]>()
  const hasParent = new Set<string>()
  for (const l of links) {
    if (!childrenOf.has(l.source)) childrenOf.set(l.source, [])
    childrenOf.get(l.source)!.push(l.target)
    hasParent.add(l.target)
  }
  const roots = nodes.filter((n) => !hasParent.has(n.id)).map((n) => n.id)
  const rootId = roots.find((id) => nodes.find((n) => n.id === id)?.kind === 'host') ?? roots[0]

  const depth: Record<string, number> = {}
  if (rootId) {
    const queue = [rootId]
    depth[rootId] = 0
    while (queue.length) {
      const cur = queue.shift()!
      for (const child of childrenOf.get(cur) ?? []) {
        if (depth[child] === undefined) {
          depth[child] = depth[cur] + 1
          queue.push(child)
        }
      }
    }
  }
  nodes.forEach((n) => {
    if (depth[n.id] === undefined) depth[n.id] = 1
  })

  const rings: Record<number, string[]> = {}
  nodes.forEach((n) => {
    ;(rings[depth[n.id]] ??= []).push(n.id)
  })
  const maxDepth = Math.max(1, ...Object.keys(rings).map(Number))
  const pos: Record<string, [number, number]> = {}
  Object.entries(rings).forEach(([dStr, ids]) => {
    const d = Number(dStr)
    if (d === 0) {
      pos[ids[0]] = [CX, CY]
      return
    }
    const radius = (Math.min(CX, CY) - 60) * (d / maxDepth)
    const n = ids.length
    ids.forEach((id, i) => {
      const angle = (i / n) * Math.PI * 2 - Math.PI / 2
      pos[id] = [CX + radius * Math.cos(angle), CY + radius * Math.sin(angle)]
    })
  })

  const placed: Placed[] = nodes.map((n) => {
    const [x, y] = pos[n.id] ?? [CX, CY]
    return { ...n, x, y, depth: depth[n.id] }
  })
  const placedById = new Map(placed.map((p) => [p.id, p]))
  const edges: [Placed, Placed][] = []
  for (const l of links) {
    const a = placedById.get(l.source)
    const b = placedById.get(l.target)
    if (a && b) edges.push([a, b])
  }
  return { placed, edges }
}


export default function NetworkMap({ data }: { data: NetMap }) {
  const { placed, edges } = useMemo(() => layout(data.nodes, data.links), [data.nodes, data.links])

  if (!data.nodes.length) {
    return <p className="py-6 text-center text-[11px] text-default-400">No topology discovered.</p>
  }

  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="w-full" style={{ maxHeight: 460 }} role="img" aria-label="network map">
      <defs>
        <marker id="nm-arrow" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
          <path d="M0,0 L6,3 L0,6 z" fill="var(--default-300)" />
        </marker>
      </defs>

      {edges.map(([a, b], i) => (
        <line
          key={i}
          x1={a.x}
          y1={a.y}
          x2={b.x}
          y2={b.y}
          stroke="var(--default-300)"
          strokeWidth={1.2}
          markerEnd="url(#nm-arrow)"
        />
      ))}

      {placed.map((n) => {
        const stroke = KIND_STROKE[n.kind]
        const opacity = STATUS_OPACITY[n.status]
        const r = n.kind === 'host' ? 22 : n.kind === 'network' ? 17 : n.kind === 'adapter' ? 12 : 14
        const tag = n.kind === 'host' ? 'HOST' : n.kind === 'network' ? 'NET' : n.kind === 'vm' ? 'VM' : n.kind === 'adapter' ? 'IP' : 'CTR'
        const where = n.subnet || n.ip || ''
        // adapters and containers show their IP as the label; longer names
        // (networks, VMs) show the name.
        const showIp = n.kind === 'adapter' || n.kind === 'container'
        const label = showIp && n.ip ? n.ip : n.label
        return (
          <g key={n.id} opacity={opacity} transform={`translate(${n.x} ${n.y})`}>
            <circle r={r} fill={stroke} fillOpacity={KIND_FILL_OPACITY} stroke={stroke} strokeWidth={2} />
            <text textAnchor="middle" y={4} fontSize={n.kind === 'host' ? 11 : 9} fill={stroke} fontWeight={700}>
              {tag}
            </text>
            <title>{`${n.label}${where ? ` (${where})` : ''} — ${n.status}${n.detail ? ' · ' + n.detail : ''}`}</title>
            <text textAnchor="middle" y={r + 14} fontSize={10} fill="var(--default-600)" fontWeight={500}>
              {label.length > 20 ? label.slice(0, 19) + '…' : label}
            </text>
          </g>
        )
      })}
    </svg>
  )
}

// Legend beside the map so the kind + status encoding is explicit.
export function NetworkLegend() {
  return (
    <div className="flex flex-wrap items-center gap-x-4 gap-y-1.5 text-[11px] text-default-500">
      {(['host', 'adapter', 'network', 'vm', 'container'] as NetNode['kind'][]).map((k) => (
        <span key={k} className="flex items-center gap-1.5">
          <span className="inline-block h-2.5 w-2.5 rounded-full border-2" style={{ borderColor: KIND_STROKE[k], backgroundColor: KIND_STROKE[k], opacity: 0.85 }} />
          {KIND_LABEL[k]}
        </span>
      ))}
      <span className="flex items-center gap-1.5">
        <span className="inline-block h-2.5 w-2.5 rounded-full border-2" style={{ borderColor: 'var(--default-400)', opacity: 0.35 }} />
        dimmed = off / unreachable
      </span>
    </div>
  )
}
