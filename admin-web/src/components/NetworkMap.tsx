import { useState } from 'react'
import type { NetLink, NetMap, NetNode } from '../types'

type InterfaceGroup = {
  name: string
  addresses: string[]
  adapterIds: string[]
}

const KIND_LABEL: Record<NetNode['kind'], string> = {
  host: 'Host',
  adapter: 'Interface',
  network: 'Network',
  vm: 'Virtual machine',
  container: 'Container',
}

function groupedInterfaces(data: NetMap): InterfaceGroup[] {
  const groups = new Map<string, InterfaceGroup>()
  for (const adapter of data.host_adapters) {
    const name = adapter.alias || 'Unidentified interface'
    let group = groups.get(name)
    if (!group) {
      group = { name, addresses: [], adapterIds: [] }
      groups.set(name, group)
    }
    group.addresses.push(adapter.ip)
    const node = data.nodes.find((item) => item.kind === 'adapter' && item.ip === adapter.ip)
    if (node) group.adapterIds.push(node.id)
  }
  return [...groups.values()]
}

function childrenOf(links: NetLink[]): Map<string, string[]> {
  const children = new Map<string, string[]>()
  for (const link of links) {
    const next = children.get(link.source) ?? []
    next.push(link.target)
    children.set(link.source, next)
  }
  return children
}

function descendants(
  id: string,
  children: Map<string, string[]>,
  byId: Map<string, NetNode>,
  seen = new Set<string>(),
): NetNode[] {
  const result: NetNode[] = []
  for (const childId of children.get(id) ?? []) {
    if (seen.has(childId)) continue
    seen.add(childId)
    const child = byId.get(childId)
    if (!child) continue
    result.push(child)
    result.push(...descendants(childId, children, byId, seen))
  }
  return result
}

type DiagramNode = NetNode & { x: number; y: number; depth: number }

const NODE_TONE: Record<NetNode['kind'], string> = {
  host: 'var(--accent)',
  adapter: '#a78bfa',
  network: 'var(--success)',
  vm: 'var(--warning)',
  container: '#38bdf8',
}

type DiagramLink = {
  source: DiagramNode
  target: DiagramNode
  kind: NetLink['kind']
  // Position of this edge within its source's outgoing / target's incoming
  // fan. The renderer needs these to spread the edges apart instead of letting
  // them all share one anchor point.
  outIndex: number
  outTotal: number
  inIndex: number
  inTotal: number
}

function diagramLayout(data: NetMap): {
  nodes: DiagramNode[]
  links: DiagramLink[]
  width: number
  height: number
} {
  const children = childrenOf(data.links)
  const parent = new Set(data.links.map((link) => link.target))
  const root = data.nodes.find((node) => node.kind === 'host' && !parent.has(node.id))
    ?? data.nodes.find((node) => !parent.has(node.id))
  const depth = new Map<string, number>()

  if (root) {
    depth.set(root.id, 0)
    const queue = [root.id]
    for (let index = 0; index < queue.length; index += 1) {
      const current = queue[index]
      for (const id of children.get(current) ?? []) {
        if (depth.has(id)) continue
        depth.set(id, (depth.get(current) ?? 0) + 1)
        queue.push(id)
      }
    }
  }
  for (const node of data.nodes) {
    if (!depth.has(node.id)) depth.set(node.id, 1)
  }

  const levels = new Map<number, NetNode[]>()
  for (const node of data.nodes) {
    const level = depth.get(node.id) ?? 1
    const nodes = levels.get(level) ?? []
    nodes.push(node)
    levels.set(level, nodes)
  }
  for (const nodes of levels.values()) {
    nodes.sort((a, b) => a.kind.localeCompare(b.kind) || a.label.localeCompare(b.label))
  }

  const maxDepth = Math.max(1, ...levels.keys())
  const maxLevelCount = Math.max(1, ...[...levels.values()].map((nodes) => nodes.length))
  const width = 220 + maxDepth * 240
  const height = Math.max(360, maxLevelCount * 94 + 64)
  const placed: DiagramNode[] = []
  for (const [level, nodes] of levels) {
    nodes.forEach((node, index) => {
      placed.push({
        ...node,
        depth: level,
        x: 24 + level * 240,
        y: Math.round(((index + 1) * height) / (nodes.length + 1)),
      })
    })
  }
  const byId = new Map(placed.map((node) => [node.id, node]))
  const mapped = data.links.flatMap((link) => {
    const source = byId.get(link.source)
    const target = byId.get(link.target)
    return source && target ? [{ source, target, kind: link.kind }] : []
  })

  // Fan-out bookkeeping.
  //
  // Every edge used to start and end at the single centre point of the node's
  // left/right border, so all five edges leaving the host departed from exactly
  // the same coordinate. Their first few pixels were indistinguishable - five
  // curves painted over each other, and five arrowheads stacked on one pixel.
  // No amount of arrow styling fixes that, because the problem is upstream of
  // the arrow: the edges are not individually traceable at their anchors.
  //
  // So each edge is numbered among its source's outgoing set and its target's
  // incoming set, and the renderer spreads those anchors down the node's edge.
  // Totals are counted before indexing so the spread is symmetric - five edges
  // always divide the same span five ways, whichever one is being drawn.
  const outTotal = new Map<string, number>()
  const inTotal = new Map<string, number>()
  for (const link of mapped) {
    outTotal.set(link.source.id, (outTotal.get(link.source.id) ?? 0) + 1)
    inTotal.set(link.target.id, (inTotal.get(link.target.id) ?? 0) + 1)
  }
  const seenOut = new Map<string, number>()
  const seenIn = new Map<string, number>()
  const links: DiagramLink[] = mapped.map((link) => {
    const outIndex = seenOut.get(link.source.id) ?? 0
    const inIndex = seenIn.get(link.target.id) ?? 0
    seenOut.set(link.source.id, outIndex + 1)
    seenIn.set(link.target.id, inIndex + 1)
    return {
      ...link,
      outIndex,
      outTotal: outTotal.get(link.source.id) ?? 1,
      inIndex,
      inTotal: inTotal.get(link.target.id) ?? 1,
    }
  })
  return { nodes: placed, links, width, height }
}

// Card geometry. Declared ahead of the arrow and text helpers because both
// measure against it, and a helper that reads a constant declared below it is a
// use-before-declaration waiting to happen the next time someone reorders this
// file.
const NODE_W = 184
const NODE_H = 58

// ---------------------------------------------------------------------------
// Fitting text to the node card.
//
// A card is 184px wide and carries two strings on one line: the name at the
// left, the detail at the right. Truncation used to be a character COUNT, and a
// count is not a width. Twenty characters at 10px is 120px and sixteen at 8px
// is 77px - 197px of text in a 155px gap. They overlapped, and overlapped
// silently: SVG text has no layout pass and no clipping, so the overflow just
// painted on top of whatever sat beside it. "VirtualBox Host-Only" came out
// printed straight through "192.168.56.0/24".
//
// So both strings are measured in the font they will actually be drawn with and
// the pair is fitted as a pair - one side is offered the room and gives back
// whatever the other needs. The fonts are monospace, which makes a per-character
// guess nearly right, but this measures rather than guesses so that swapping the
// font stack in the CSS cannot quietly reintroduce the collision.
// ---------------------------------------------------------------------------

const LABEL_FONT =
  '600 10px "Cascadia Mono", "Cascadia Code", ui-monospace, Consolas, monospace'
const META_FONT =
  '8px "Cascadia Mono", "Cascadia Code", ui-monospace, Consolas, monospace'

// Horizontal room between the two anchors, i.e. NODE_W less the 14px left
// inset and the 15px right one.
const LABEL_GAP = NODE_W - 14 - 15

// Width left over between the name and the detail.
const LABEL_NOTCH = 10

// Module-scoped because measuring means handing a string to a canvas, and
// allocating one per label on every render of a nine-node diagram would be
// absurd. `undefined` means "not tried yet", which is distinct from "no canvas".
let measureCtx: CanvasRenderingContext2D | null | undefined

function textWidth(text: string, font: string): number {
  if (measureCtx === undefined) {
    measureCtx = document.createElement('canvas').getContext('2d')
  }
  if (!measureCtx) {
    // No 2D context available. Monospace, so size x count is close - and
    // deliberately over rather than under, so the fallback cannot overflow.
    const size = Number.parseFloat(font.match(/(\d+(?:\.\d+)?)px/)?.[1] ?? '10')
    return text.length * size * 0.62
  }
  measureCtx.font = font
  return measureCtx.measureText(text).width
}

function ellipsize(text: string, font: string, maxWidth: number): string {
  if (!text || maxWidth <= 0) return ''
  if (textWidth(text, font) <= maxWidth) return text
  // Binary search on the character count. Linear would be fine at this length,
  // but this is the one place in the diagram where an off-by-one shows up as
  // visibly overlapping text rather than as a wrong pixel.
  const chars = [...text]
  let low = 0
  let high = chars.length - 1
  while (low < high) {
    const mid = Math.ceil((low + high) / 2)
    if (textWidth(`${chars.slice(0, mid).join('')}…`, font) <= maxWidth) low = mid
    else high = mid - 1
  }
  return low === 0 ? '' : `${chars.slice(0, low).join('')}…`
}

// Fit the name and the detail into one shared gap.
//
// The name wins the argument. It is the thing the node IS, while the detail is
// supporting detail, so when the pair cannot both fit the detail is the side
// that gets squeezed - but only to a floor, below which it is dropped entirely
// rather than drawn as a stub that is all ellipsis.
function fitPair(name: string, detail: string, gap = LABEL_GAP): [string, string] {
  if (!detail) return [ellipsize(name, LABEL_FONT, gap), '']
  const nameWidth = textWidth(name, LABEL_FONT)
  const detailWidth = textWidth(detail, META_FONT)
  if (nameWidth + detailWidth + LABEL_NOTCH <= gap) return [name, detail]
  if (detailWidth + LABEL_NOTCH >= gap) {
    // The detail alone overruns the gap, so proportions cannot save it. Give
    // the name the majority and cap the detail at a readable minimum.
    const detailShare = Math.min(detailWidth, gap * 0.34)
    return [
      ellipsize(name, LABEL_FONT, gap - detailShare - LABEL_NOTCH),
      ellipsize(detail, META_FONT, detailShare),
    ]
  }
  return [ellipsize(name, LABEL_FONT, gap - detailWidth - LABEL_NOTCH), detail]
}

// ---------------------------------------------------------------------------
// Relationship arrows.
//
// This is the part that was missing, and the reason was not a layout bug. The
// marker was declared and referenced correctly, but it was filled with
// `var(--default-400)` - a token HeroUI 3 does not define - and the edge stroke
// used the same name inside a color-mix. Both resolved to nothing, so the
// connectors were painted with no colour at all: invisible lines with invisible
// heads, on a diagram whose entire job is to show what is connected to what.
//
// An arrow is only useful if it is a real mark: a filled head in the edge's own
// colour, sized so it does not shrink on a thin edge, and landing ON the node it
// points at rather than floating short of it.
//
// Three fixes over the previous version:
//
//   * `userSpaceOnUse` instead of `strokeWidth`. Under strokeWidth the head is
//     a multiple of the stroke, so nudging `.topology-diagram-edge`'s
//     stroke-width from 1.6 to 2 silently resized every arrowhead on the page.
//     The head is now a fixed size in diagram units and cannot be resized from
//     CSS by accident.
//   * `refX` sits on the TIP, not one unit behind it. With the tip on the
//     endpoint, ending a curve at the node's border puts the point of the arrow
//     exactly on that border. The old head stopped ~5px short and the comment
//     above claimed otherwise.
//   * The back edge is notched rather than flat. A plain triangle reads as a
//     blunt blob at 10px; the notch reads as a direction at the same size.
// ---------------------------------------------------------------------------

const LINK_TONE: Record<NetLink['kind'], string> = {
  adapter: 'var(--accent)',
  bridge: '#38bdf8',
  member: '#38bdf8',
  'host-only': 'var(--warning)',
}

const LINK_LABEL: Record<NetLink['kind'], string> = {
  adapter: 'interface',
  bridge: 'bridge',
  member: 'member of',
  'host-only': 'host-only',
}

// How much of a node's height the anchors may use.
//
// Inset from the ends on purpose: the corners are rounded (rx=10) and the left
// one carries the 3px tone stripe, so an anchor placed hard against a corner
// reads as touching the decoration rather than the card.
const ANCHOR_INSET = 15

function arrowMarkerId(kind: NetLink['kind'], suffix: string): string {
  // The kind is in the id so four markers coexist in one <defs> without
  // colliding on a shared name.
  return `topology-arrow-${kind}${suffix}`
}

// Anchor positions for one edge's two ends, spread across the node borders.
//
// A single edge is centred, which is the common case and the one that should
// look deliberate. A fan of N is divided into N equal slots. The divider is
// inset so the first and last anchors never land on the rounded corner.
function anchorY(centre: number, index: number, total: number): number {
  if (total <= 1) return centre
  const span = NODE_H - ANCHOR_INSET * 2
  return centre - span / 2 + ((index + 0.5) * span) / total
}

// Hover state carries the endpoints of an edge, not just its key.
//
// The previous version stored the bare key and recovered the endpoints by
// testing `endsWith('|id')` on it, which quietly broke the case that matters
// most: hovering a connector dimmed the very two nodes it joins, because a key
// like "host->adapter-1" never ends with "|host". The nodes at either end of a
// hovered edge are exactly what should light up - that is the reason to hover a
// connector rather than merely to look at it.
type Hover = { edge: string; from: string; to: string } | { node: string } | null

// The detail is dropped whenever it says nothing the card is not already saying.
//
// Two ways that happens on live data: a VM and a container both report
// label === ip, so the slot reprinted the name verbatim in a second size; and a
// node with no address at all falls back to its own kind label, which is
// printed at the top of the very same card. Neither is information - both are a
// second copy of something the reader can already see.
function usefulDetail(
  node: NetNode,
  main: string,
  detail: string | null,
): string | null {
  const value = detail?.trim()
  if (!value) return null
  if (value.toLowerCase() === main.trim().toLowerCase()) return null
  if (value.toLowerCase() === KIND_LABEL[node.kind].toLowerCase()) return null
  return detail
}

function TopologyDiagram({ data }: { data: NetMap }) {
  const layout = diagramLayout(data)
  const [hover, setHover] = useState<Hover>(null)
  if (layout.nodes.length === 0) return null

  const kinds = [...new Set(data.links.map((l) => l.kind))]

  return (
    <section className="topology-diagram-section" aria-label="Visual network topology map">
      <div className="topology-section-heading">
        <div>
          <h3>Topology map</h3>
          <p className="topology-diagram-caption">
            Follow each arrow from the host through interfaces and networks to its nodes.
          </p>
        </div>
        <span>{layout.nodes.length} node{layout.nodes.length === 1 ? '' : 's'} · {layout.links.length} connection{layout.links.length === 1 ? '' : 's'}</span>
      </div>

      <ul className="topology-edge-legend" aria-label="Relationship types">
        {kinds.map((kind) => (
          <li key={kind}>
            <svg width="26" height="8" aria-hidden="true">
              <line
                x1="1" y1="4" x2="16" y2="4"
                stroke={LINK_TONE[kind]} strokeWidth="1.5"
                markerEnd={`url(#${arrowMarkerId(kind, '-legend')})`}
              />
            </svg>
            {LINK_LABEL[kind]}
          </li>
        ))}
      </ul>

      <div className="topology-diagram-scroll">
        <svg
          viewBox={`0 0 ${layout.width} ${layout.height}`}
          role="img"
          aria-label="Diagram of host interfaces, networks, virtual machines and containers"
          className="topology-diagram"
        >
          <defs>
            {kinds.map((kind) => (
              <marker
                key={kind}
                id={arrowMarkerId(kind, '-legend')}
                markerWidth="8"
                markerHeight="8"
                refX="7"
                refY="3.5"
                orient="auto"
                markerUnits="userSpaceOnUse"
              >
                <path d="M0,0.3 L7,3.5 L0,6.7 L1.7,3.5 z" fill={LINK_TONE[kind]} />
              </marker>
            ))}
            {kinds.map((kind) => (
              <marker
                key={`${kind}-main`}
                id={arrowMarkerId(kind, '-main')}
                // 11x11 viewport holding a 10x10 head: the spare unit is margin,
                // so a renderer that antialiases the tip against the viewport
                // edge cannot shave it off.
                markerWidth="11"
                markerHeight="11"
                refX="10"
                refY="5"
                orient="auto"
                markerUnits="userSpaceOnUse"
              >
                <path d="M0,0.6 L10,5 L0,9.4 L2.4,5 z" fill={LINK_TONE[kind]} />
              </marker>
            ))}
          </defs>

          {/* Edges first so nodes always paint over the endpoints. */}
          {layout.links.map(({ source, target, kind, outIndex, outTotal, inIndex, inTotal }) => {
            const key = `${source.id}->${target.id}`
            const tone = LINK_TONE[kind]
            // Anchors spread down the facing borders, so N edges into one node
            // land in N distinct places instead of stacking on one pixel.
            const startY = anchorY(source.y, outIndex, outTotal)
            const endY = anchorY(target.y, inIndex, inTotal)
            // End exactly on the target's border. The marker is anchored with
            // its tip on this point, so the arrow touches the card it points at
            // and the node's own fill covers any antialiasing overshoot.
            const startX = source.x + NODE_W
            const endX = target.x
            const curve = Math.max(26, (endX - startX) * 0.45)
            const d = `M ${startX} ${startY} C ${startX + curve} ${startY}, ${endX - curve} ${endY}, ${endX} ${endY}`
            const lit = hover === null
              ? true
              : 'edge' in hover
                ? hover.edge === key
                : source.id === hover.node || target.id === hover.node
            return (
              <g key={key}>
                <path
                  d={d}
                  className="topology-diagram-edge"
                  stroke={tone}
                  markerEnd={`url(#${arrowMarkerId(kind, '-main')})`}
                  opacity={lit ? 1 : 0.22}
                />
                {/* Invisible fat line: a 1.6px stroke is a terrible hover target
                    and these are the only interactive part of the diagram.
                    Carrying the source and target ids keeps the hover test a
                    field read instead of a string match on the key. */}
                <path
                  d={d}
                  className="topology-diagram-hit"
                  onMouseEnter={() => setHover({ edge: key, from: source.id, to: target.id })}
                  onMouseLeave={() => setHover(null)}
                >
                  <title>{`${source.label} → ${target.label} · ${LINK_LABEL[kind]}`}</title>
                </path>
              </g>
            )
          })}

          {layout.nodes.map((node) => {
            const tone = NODE_TONE[node.kind]
            const main = node.kind === 'adapter' ? node.ip ?? node.label : node.label
            const secondary = usefulDetail(
              node,
              main,
              node.kind === 'adapter'
                ? node.detail
                : node.ip ?? node.subnet ?? KIND_LABEL[node.kind],
            )
            const [name, detail] = fitPair(main, secondary ?? '')
            const lit = hover === null
              ? true
              : 'edge' in hover
                ? node.id === hover.from || node.id === hover.to
                : node.id === hover.node
            return (
              <g
                key={node.id}
                transform={`translate(${node.x} ${node.y - NODE_H / 2})`}
                onMouseEnter={() => setHover({ node: node.id })}
                onMouseLeave={() => setHover(null)}
              >
                <title>
                  {`${KIND_LABEL[node.kind]}: ${node.label}${node.ip ? ` · ${node.ip}` : ''}${node.subnet ? ` · ${node.subnet}` : ''} · ${node.status}${node.detail ? ` · ${node.detail}` : ''}`}
                </title>
                <rect
                  width={NODE_W}
                  height={NODE_H}
                  rx="10"
                  className="topology-diagram-node"
                  stroke={tone}
                  opacity={lit ? 1 : 0.45}
                />
                <rect width="3" height={NODE_H} rx="1.5" fill={tone} />
                <text x="14" y="22" className="topology-diagram-kind" fill={tone}>
                  {KIND_LABEL[node.kind].toUpperCase()}
                </text>
                <circle
                  cx={NODE_W - 15}
                  cy="16"
                  r="3.5"
                  fill={node.status === 'up'
                    ? 'var(--success)'
                    : node.status === 'running' ? 'var(--warning)' : 'var(--danger)'}
                />
                <text x="14" y="43" className="topology-diagram-label">
                  {name}
                </text>
                {detail && (
                  <text
                    x={NODE_W - 15}
                    y="43"
                    textAnchor="end"
                    className="topology-diagram-meta"
                  >
                    {detail}
                  </text>
                )}
              </g>
            )
          })}
        </svg>
      </div>
    </section>
  )
}

function NodeStatus({ node }: { node: NetNode }) {
  const status = node.status === 'up' ? 'up' : node.status === 'running' ? 'running' : 'down'
  return <span className={`topology-status is-${status}`}>{status}</span>
}

function ConnectedNetwork({ network, nodes }: { network: NetNode; nodes: NetNode[] }) {
  return (
    <div className="topology-network">
      <div className="topology-network-heading">
        <span className="topology-node-icon is-network" aria-hidden="true">N</span>
        <div className="min-w-0 flex-1">
          <p className="truncate topology-node-name" title={network.label}>{network.label}</p>
          <p className="topology-node-meta">{network.subnet ?? network.detail}</p>
        </div>
        <NodeStatus node={network} />
      </div>
      {nodes.length > 0 && (
        <div className="topology-members">
          {nodes.filter((node) => node.kind !== 'network').map((node) => (
            <div className="topology-member" key={node.id}>
              <span
                className={`topology-node-icon is-${node.kind}`}
                aria-hidden="true"
              >
                {node.kind === 'vm' ? 'VM' : node.kind === 'container' ? 'C' : 'N'}
              </span>
              <div className="min-w-0 flex-1">
                <p className="truncate topology-node-name" title={node.label}>{node.label}</p>
                <p className="topology-node-meta">
                  {node.ip ? <code>{node.ip}</code> : KIND_LABEL[node.kind]}
                  {node.detail && node.detail !== node.ip && ` · ${node.detail}`}
                </p>
              </div>
              <NodeStatus node={node} />
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

function InterfaceCard({
  group,
  data,
  children,
  byId,
}: {
  group: InterfaceGroup
  data: NetMap
  children: Map<string, string[]>
  byId: Map<string, NetNode>
}) {
  const connected = group.adapterIds.flatMap((id) =>
    (children.get(id) ?? [])
      .map((networkId) => byId.get(networkId))
      .filter((node): node is NetNode => Boolean(node && node.kind === 'network'))
      .map((network) => ({
        network,
        nodes: descendants(network.id, children, byId),
      })),
  )

  return (
    <article className="topology-interface-card">
      <header className="topology-interface-header">
        <span className="topology-node-icon is-adapter" aria-hidden="true">IF</span>
        <div className="min-w-0 flex-1">
          <p className="topology-interface-name" title={group.name}>{group.name}</p>
          <p className="topology-node-meta">
            {group.addresses.length} address{group.addresses.length === 1 ? '' : 'es'}
          </p>
        </div>
        <span className="topology-status is-up">up</span>
      </header>

      <div className="topology-addresses" aria-label={`IP addresses on ${group.name}`}>
        {group.addresses.map((ip) => {
          const facts = data.host_adapters.find((adapter) => adapter.ip === ip)
          return (
            <span className="topology-address" key={ip}>
              <code>{ip}</code>
              {facts?.loopback && <span className="topology-address-kind">loopback</span>}
            </span>
          )
        })}
      </div>

      <div className="topology-connectors">
        {connected.length === 0 ? (
          <p className="topology-empty-connection">No attached virtual network was identified.</p>
        ) : (
          connected.map(({ network, nodes }) => (
            <ConnectedNetwork key={network.id} network={network} nodes={nodes} />
          ))
        )}
      </div>
    </article>
  )
}

export default function NetworkMap({ data }: { data: NetMap }) {
  const groups = groupedInterfaces(data)
  const children = childrenOf(data.links)
  const byId = new Map(data.nodes.map((node) => [node.id, node]))
  const hostNetworks = (children.get('host') ?? [])
    .map((id) => byId.get(id))
    .filter((node): node is NetNode => Boolean(node && node.kind === 'network'))
  const mappedNetworks = new Set(
    groups.flatMap((group) =>
      group.adapterIds.flatMap((id) => children.get(id) ?? []),
    ),
  )
  const unattachedNetworks = hostNetworks.filter((network) => !mappedNetworks.has(network.id))

  if (groups.length === 0 && unattachedNetworks.length === 0) {
    return <p className="py-6 text-center text-[12px] text-default-400">No interfaces or connected networks discovered.</p>
  }

  return (
    <div className="topology-overview">
      <div className="topology-map-intro">
        <span className="topology-host-badge">
          <span className="topology-node-icon is-host" aria-hidden="true">H</span>
          This host
        </span>
        <span className="topology-intro-line" aria-hidden="true" />
        <span className="topology-map-caption">Interfaces, IP addresses, and connected nodes</span>
      </div>

      <TopologyDiagram data={data} />

      {groups.length > 0 && (
        <section aria-label="Host interfaces and attached networks">
          <div className="topology-section-heading">
            <h3>Host interfaces</h3>
            <span>{groups.length} interface{groups.length === 1 ? '' : 's'}</span>
          </div>
          <div className="topology-interface-grid">
            {groups.map((group) => (
              <InterfaceCard
                key={group.name}
                group={group}
                data={data}
                children={children}
                byId={byId}
              />
            ))}
          </div>
        </section>
      )}

      {unattachedNetworks.length > 0 && (
        <section aria-label="Host-attached virtual networks">
          <div className="topology-section-heading">
            <h3>Host-attached networks</h3>
            <span>Bridges and virtual networks</span>
          </div>
          <div className="topology-network-grid">
            {unattachedNetworks.map((network) => (
              <ConnectedNetwork
                key={network.id}
                network={network}
                nodes={descendants(network.id, children, byId)}
              />
            ))}
          </div>
        </section>
      )}
    </div>
  )
}

export function NetworkLegend() {
  return (
    <div className="topology-legend" aria-label="Network status legend">
      <span><i className="is-up" />Up / reachable</span>
      <span><i className="is-running" />Running</span>
      <span><i className="is-down" />Down / unreachable</span>
    </div>
  )
}
