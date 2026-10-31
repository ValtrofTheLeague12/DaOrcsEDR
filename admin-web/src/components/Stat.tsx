import type { ReactNode } from 'react'

// ---------------------------------------------------------------------------
// Sparkline - hand-rolled SVG.
//
// A chart library for one polyline is not worth the bundle, and this keeps the
// colour tied to HeroUI tokens so it restyles with the theme. Gaps (null
// samples) break the line rather than being interpolated to zero, which would
// read as "CPU was 0%" when the truth is "we did not measure it".
// ---------------------------------------------------------------------------

export type SparkTone = 'accent' | 'success' | 'warning' | 'danger'

const STROKE: Record<SparkTone, string> = {
  accent: 'var(--accent)',
  success: 'var(--success)',
  warning: 'var(--warning)',
  danger: 'var(--danger)',
}

export function Sparkline({
  data,
  tone = 'accent',
  height = 40,
  max,
  min = 0,
}: {
  data: (number | null)[]
  tone?: SparkTone
  height?: number
  max?: number | null
  min?: number | null
}) {
  const points = data.filter((d): d is number => d !== null && d !== undefined)
  if (points.length < 2) {
    return (
      <div className="flex items-center text-[10px] text-default-400">
        collecting…
      </div>
    )
  }

  const hi = max ?? Math.max(...points)
  const lo = min ?? Math.min(...points)
  const span = hi - lo
  const W = 100
  const H = height
  const pad = 2
  const usable = H - pad * 2

  // Normalise against the widest window so the shape is comparable over time.
  const step = data.length > 1 ? W / (data.length - 1) : W
  // A perfectly flat series has no range to map onto. Drawing it at the floor
  // reads as a UI underline rather than as a trend; centring it says "measured,
  // unchanged", which is what the data actually means.
  const y = (v: number) =>
    span === 0 ? pad + usable / 2 : pad + usable - ((v - lo) / span) * usable

  // Split into contiguous runs of non-null samples.
  const runs: { d: string; area: string }[] = []
  let cur: string[] = []
  data.forEach((v, i) => {
    const x = i * step
    if (v === null || v === undefined) {
      if (cur.length > 1) runs.push(buildPath(cur, H))
      cur = []
      return
    }
    cur.push(`${x.toFixed(2)},${y(v).toFixed(2)}`)
  })
  if (cur.length > 1) runs.push(buildPath(cur, H))

  if (!runs.length) {
    return <div className="flex items-center text-[10px] text-default-400">no data</div>
  }

  const id = `spark-${tone}-${Math.round(lo)}-${Math.round(hi)}`

  return (
    <svg
      viewBox={`0 0 ${W} ${H}`}
      preserveAspectRatio="none"
      className="w-full"
      style={{ height: H }}
      role="img"
      aria-label={`trend, ${points.length} samples`}
    >
      <defs>
        <linearGradient id={id} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={STROKE[tone]} stopOpacity="0.28" />
          <stop offset="100%" stopColor={STROKE[tone]} stopOpacity="0" />
        </linearGradient>
      </defs>

      {runs.map((r, i) => (
        <g key={i}>
          <path d={r.area} fill={`url(#${id})`} />
          <path
            d={r.d}
            fill="none"
            stroke={STROKE[tone]}
            strokeWidth={1.5}
            strokeLinecap="round"
            strokeLinejoin="round"
            vectorEffect="non-scaling-stroke"
          />
        </g>
      ))}

      {/* last point marker */}
      {(() => {
        const lastIdx = data.length - 1
        const lastVal = data[lastIdx]
        if (lastVal === null || lastVal === undefined) return null
        const cx = lastIdx * step
        const cy = y(lastVal)
        return (
          <circle cx={cx} cy={cy} r={1.8} fill={STROKE[tone]} vectorEffect="non-scaling-stroke" />
        )
      })()}
    </svg>
  )
}

function buildPath(pts: string[], baseline: number): { d: string; area: string } {
  const d = `M ${pts.join(' L ')}`
  const first = pts[0].split(',')
  const last = pts[pts.length - 1].split(',')
  return {
    d,
    area: `${d} L ${last[0]},${baseline} L ${first[0]},${baseline} Z`,
  }
}

// ---------------------------------------------------------------------------
// Stat tile
// ---------------------------------------------------------------------------

export function StatTile({
  label,
  value,
  sub,
  icon,
  trend,
  trendMax,
  trendTone = 'accent',
  onClick,
}: {
  label: string
  value: ReactNode
  sub?: ReactNode
  icon?: ReactNode
  trend?: (number | null)[]
  trendMax?: number | null
  trendTone?: SparkTone
  onClick?: () => void
}) {
  const Tag = onClick ? 'button' : 'div'
  return (
    <Tag
      onClick={onClick}
      className={`stat-tile tone-${trendTone} group ${onClick ? 'cursor-pointer' : ''}`}
    >
      <div className="flex items-start justify-between gap-3">
        <span className="text-[11px] font-medium uppercase tracking-wider text-default-400">
          {label}
        </span>
        {icon && <span className="stat-tile-icon">{icon}</span>}
      </div>

      <div className="mt-3 font-mono text-2xl font-semibold leading-none tracking-tight text-foreground tabular-nums">
        {value}
      </div>

      {sub && <div className="mt-1.5 text-[11px] text-default-500">{sub}</div>}

      {trend && trend.length > 0 && (
        <div className="mt-3 -mb-1 opacity-90">
          <Sparkline data={trend} tone={trendTone} max={trendMax} />
        </div>
      )}
    </Tag>
  )
}

export function Skeleton({ rows = 3 }: { rows?: number }) {
  return (
    <div className="flex flex-col gap-3">
      {Array.from({ length: rows }).map((_, i) => (
        <div
          key={i}
          className="stat-tile animate-pulse"
          style={{ animationDelay: `${i * 90}ms` }}
        >
          <div className="h-3 w-24 rounded bg-default-200" />
          <div className="mt-3 h-7 w-20 rounded bg-default-200" />
          <div className="mt-3 h-8 w-full rounded bg-default-100" />
        </div>
      ))}
    </div>
  )
}