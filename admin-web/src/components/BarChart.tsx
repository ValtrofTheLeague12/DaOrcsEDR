import { useState } from 'react'

// ---------------------------------------------------------------------------
// BarChart - hand-rolled SVG, same reasoning as Sparkline in Stat.tsx: a chart
// library for a dozen rectangles is not worth the bundle, and this keeps the
// colour on HeroUI tokens so it restyles with the theme.
//
// This exists because Sparkline cannot do this job. The values here are
// discrete and labelled - one bar per artifact, each a different bundle with a
// name - and a polyline between them would imply a continuous series and draw
// a slope that means nothing. Bars do not imply continuity, so bars it is.
//
// Every bar is interactive rather than sitting under a title: with a dozen
// categories the label alone is too small to read, and the hover card is where
// the exact numbers and the caveat live.
// ---------------------------------------------------------------------------

export type BarTone = 'accent' | 'success' | 'warning' | 'danger'

const FILL: Record<BarTone, string> = {
  accent: 'var(--accent)',
  success: 'var(--success)',
  warning: 'var(--warning)',
  danger: 'var(--danger)',
}

export interface BarDatum {
  label: string
  value: number
  /** Shown in the hover card. Defaults to the value. */
  detail?: string
  /** Tints the bar individually - used to mark a negative delta. */
  tone?: BarTone
}

export default function BarChart({
  data,
  tone = 'accent',
  height = 120,
  format = (n) => String(n),
  emptyLabel = 'no data yet',
}: {
  data: BarDatum[]
  tone?: BarTone
  height?: number
  format?: (n: number) => string
  emptyLabel?: string
}) {
  const [hover, setHover] = useState<number | null>(null)

  // A null value is a gap, not a zero. Rendered as a hairline placeholder so
  // the bar's absence is visible rather than being silently drawn as "nothing
  // happened", which would read as a rate of zero.
  const live = data.filter((d) => Number.isFinite(d.value))
  if (!live.length) {
    return (
      <div className="flex items-center justify-center py-6 text-[11px] text-default-400">
        {emptyLabel}
      </div>
    )
  }

  const W = 100
  const H = height
  const padTop = 4
  const padBottom = 16
  const usable = H - padTop - padBottom

  // Symmetric around zero so a chart mixing positive and negative deltas does
  // not render the negative half as a fraction of the positive one.
  const hi = Math.max(0, ...live.map((d) => d.value))
  const lo = Math.min(0, ...live.map((d) => d.value))
  const span = (hi - lo) || 1

  const zero = padTop + (hi / span) * usable
  const slot = W / Math.max(1, data.length)
  // Leave a gutter so adjacent bars read as separate values.
  const barW = Math.min(slot * 0.62, 8)

  const y = (v: number) => zero - (v / span) * usable
  const barH = (v: number) => Math.max(Math.abs(y(v) - zero), 0.6)

  return (
    <div className="relative">
      <div className="chart-frame">
        <svg
          viewBox={`0 0 ${W} ${H}`}
          preserveAspectRatio="none"
          className="w-full"
          style={{ height: H }}
          role="img"
          aria-label={`${data.length} bars, max ${format(hi)}, min ${format(lo)}`}
        >
        {lo < 0 && (
          <line
            x1="0" y1={zero} x2={W} y2={zero}
            stroke="var(--border)" strokeWidth="0.5" vectorEffect="non-scaling-stroke"
          />
        )}

        {data.map((d, i) => {
          const cx = i * slot + slot / 2
          const has = Number.isFinite(d.value)
          const top = has ? Math.min(y(d.value), zero) : zero - 1
          const active = hover === i
          return (
            <g key={`${d.label}-${i}`}>
              <rect
                x={cx - slot / 2} y={padTop}
                width={slot} height={usable}
                fill={active ? 'var(--default-100)' : 'transparent'}
              />
              <rect
                x={cx - barW / 2}
                y={top}
                width={barW}
                height={has ? barH(d.value) : 1}
                rx={0.8}
                fill={has ? FILL[d.tone ?? tone] : 'var(--default-200)'}
                opacity={hover === null || active ? 0.95 : 0.4}
                onMouseEnter={() => setHover(i)}
                onMouseLeave={() => setHover(null)}
                style={{ transition: 'opacity 120ms' }}
              />
            </g>
          )
        })}
        </svg>
      </div>

      {/* Category labels. SVG text would scale with the viewBox and come out
          unreadable at 100 units wide, so this is HTML positioned underneath. */}
      <div className="mt-1 flex">
        {data.map((d, i) => (
          <div
            key={`${d.label}-lbl-${i}`}
            className="min-w-0 flex-1 truncate text-center font-mono text-[9px] text-default-400"
            title={d.label}
          >
            {d.label}
          </div>
        ))}
      </div>

      {hover !== null && data[hover] && (
        <div className="pointer-events-none absolute -top-1 right-0 rounded-md border border-default-200 bg-surface px-2 py-1 text-[11px] shadow-lg">
          <span className="font-mono text-default-500">{data[hover].label}</span>
          <span className="ml-2 font-mono tabular-nums">
            {data[hover].detail ?? format(data[hover].value)}
          </span>
        </div>
      )}
    </div>
  )
}
