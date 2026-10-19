import { bytes as fmtBytes, duration, pct } from '../lib/format'
import type { VmMetrics, VmMetricSample } from '../types'

// ---------------------------------------------------------------------------
// The trend diagram.
//
// A gauge answers "what is it now". That is not the question anybody has during
// an incident, when the machine is at 100% CPU: the question is whether it has
// BEEN at 100% for ten minutes or spiked once in the last thirty seconds, and
// those need completely different responses. So the three gauges are followed by
// a chart of the same three series on one shared time axis.
//
// The window is a fixed half hour at the collector's 15s cadence, oldest on the
// left. Nulls are carried through rather than dropped - the line breaks at them -
// so a guest that stopped answering shows as a gap at the moment it stopped,
// which is the honest reading. Filtering those points out would draw a confident
// straight line through the outage.
// ---------------------------------------------------------------------------

/** How far back the chart reaches, phrased for a human. */
function windowLabel(history: VmMetricSample[]): string | null {
  const first = history[0]?.at
  const last = history.at(-1)?.at
  if (first === undefined || last === undefined || last <= first) return null
  const mins = Math.round((last - first) / 60)
  if (mins < 1) return 'last minute'
  return `last ${mins} min`
}

// ---------------------------------------------------------------------------
// Live guest metrics.
//
// Drawn from the cache the backend refreshes in the background over SSH + SFTP,
// so nothing here blocks and a powered-off guest reports why rather than
// rendering as a machine idling at zero.
//
// The three states are visually distinct on purpose:
//   pending  the first collection has not landed yet
//   down     the guest refused, timed out, or has no credentials on file
//   up       the numbers mean something
//
// Collapsing "no answer" into a set of zeroed gauges is the one thing this
// component must not do. A powered-off VM drawing a 0% CPU ring looks exactly
// like a healthy idle VM, and the operator acts on it.
// ---------------------------------------------------------------------------

/**
 * Three percentage series on one 0-100 axis.
 *
 * Sparkline cannot do this job: it draws one series, auto-scales to that
 * series' own min and max, and fills under the line. Here the three have to
 * share an axis so they can be compared, the scale must be fixed at 0-100 or a
 * 4% CPU spike would fill the frame, and three overlapping fills would be mud.
 * So this is its own renderer: lines only, no fill, fixed scale.
 */
function TrendPlot({ history }: { history: VmMetricSample[] }) {
  if (history.length < 2) {
    return <div className="vm-metrics-plot-empty">collecting a trend…</div>
  }

  const W = 100
  const H = 60
  const pad = 2
  const usable = H - pad * 2
  const step = W / (history.length - 1)

  const y = (v: number) => pad + usable - (Math.max(0, Math.min(100, v)) / 100) * usable

  // Split into contiguous runs so a gap breaks the line instead of being
  // interpolated across. Same rule as Sparkline, applied to three series at
  // once: a failed collection yields a null, and the line stops and restarts.
  const build = (key: 'cpu' | 'mem' | 'disk') => {
    const runs: string[] = []
    let cur: string[] = []
    history.forEach((s, i) => {
      const v = s[key]
      if (v === null || v === undefined) {
        if (cur.length > 1) runs.push(cur.join(' '))
        cur = []
        return
      }
      cur.push(`${(i * step).toFixed(2)},${y(v).toFixed(2)}`)
    })
    if (cur.length > 1) runs.push(cur.join(' '))
    return runs
  }

  const lanes = (['cpu', 'mem', 'disk'] as const).map((key) => ({
    key,
    runs: build(key),
  }))
  const drawn = lanes.reduce((n, l) => n + l.runs.length, 0)

  if (!drawn) {
    // Every sample in the window is null. That is a real state - the guest has
    // not answered once - and it is not the same as having no history.
    return (
      <div className="vm-metrics-plot-empty">
        no samples in this window — the guest did not answer
      </div>
    )
  }

  return (
    <svg
      viewBox={`0 0 ${W} ${H}`}
      preserveAspectRatio="none"
      className="vm-metrics-svg"
      style={{ height: H }}
      role="img"
      aria-label={`CPU, memory and disk over the last ${history.length} samples`}
    >
      {lanes.map((lane) =>
        lane.runs.map((d, i) => (
          <polyline
            key={`${lane.key}-${i}`}
            points={d}
            fill="none"
            stroke={`var(--${lane.key === 'disk' ? 'warning' : lane.key === 'mem' ? 'success' : 'accent'})`}
            strokeWidth={1.4}
            strokeLinecap="round"
            strokeLinejoin="round"
            vectorEffect="non-scaling-stroke"
          />
        )),
      )}
    </svg>
  )
}

function Gauge({
  label,
  value,
  percent,
  tone,
  hint,
}: {
  label: string
  value: string
  percent: number | null
  tone: 'accent' | 'success' | 'warning' | 'danger'
  hint?: string
}) {
  // Clamped for the bar only: a percent over 100 from a rounding artefact
  // should not overflow its track.
  const fill = percent === null ? 0 : Math.max(0, Math.min(100, percent))
  return (
    <div className="vm-metric">
      <div className="vm-metric-head">
        <span className="vm-metric-label">{label}</span>
        <span className="vm-metric-value">{value}</span>
      </div>
      <div
        className={`vm-metric-track is-${tone}`}
        role="meter"
        aria-valuenow={percent ?? undefined}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-label={label}
      >
        <span className="vm-metric-fill" style={{ width: `${fill}%` }} />
      </div>
      {hint && <span className="vm-metric-hint">{hint}</span>}
    </div>
  )
}

function Stat({ label, value, title }: { label: string; value: string; title?: string }) {
  return (
    <div className="vm-metric-stat" title={title}>
      <span className="vm-metric-label">{label}</span>
      <span className="vm-metric-stat-value">{value}</span>
    </div>
  )
}

/** cpu/load saturation against core count - the number worth judging by. */
function cpuTone(cpu: number | null): 'accent' | 'success' | 'warning' | 'danger' {
  if (cpu === null) return 'accent'
  if (cpu >= 90) return 'danger'
  if (cpu >= 70) return 'warning'
  return 'success'
}

function memTone(used: number | null): 'accent' | 'success' | 'warning' | 'danger' {
  if (used === null) return 'accent'
  if (used >= 90) return 'danger'
  if (used >= 75) return 'warning'
  return 'success'
}

function diskTone(used: number | null): 'accent' | 'success' | 'warning' | 'danger' {
  if (used === null) return 'accent'
  if (used >= 92) return 'danger'
  if (used >= 80) return 'warning'
  return 'success'
}

export default function VmMetricsPanel({ metrics }: { metrics: VmMetrics | null | undefined }) {
  if (!metrics) {
    return (
      <div className="vm-metrics is-empty">
        <p className="vm-metrics-note">
          No SSH credentials on file for this machine. Add it to
          <code> qiling_dlls/vm_info.json</code> to collect live metrics.
        </p>
      </div>
    )
  }

  if (metrics.state === 'pending') {
    return (
      <div className="vm-metrics is-empty">
        <p className="vm-metrics-note">
          Collecting… the first SSH sample has not come back yet.
        </p>
      </div>
    )
  }

  if (metrics.state === 'down') {
    return (
      <div className="vm-metrics is-down">
        <p className="vm-metrics-note">
          Guest unreachable{metrics.error ? ` — ${metrics.error}` : '.'}
        </p>
      </div>
    )
  }

  const cores = metrics.cores ?? 0
  const load1 = metrics.load['1']
  const loadPerCore = load1 !== null && cores > 0 ? load1 / cores : null
  const history = metrics.history ?? []

  return (
    <div className="vm-metrics">
      <div className="vm-metrics-head">
        <span className="eyebrow">Live metrics · SSH + SFTP</span>
        <span className="vm-metrics-stamp" title={`guest ${metrics.hostname ?? ''}`}>
          {metrics.hostname ?? metrics.ip}
          {metrics.age_seconds !== null && ` · ${Math.round(metrics.age_seconds)}s ago`}
        </span>
      </div>

      <div className="vm-metrics-grid">
        <Gauge
          label="CPU"
          value={pct(metrics.cpu_percent)}
          percent={metrics.cpu_percent}
          tone={cpuTone(metrics.cpu_percent)}
          hint={
            loadPerCore !== null
              ? `load ${load1?.toFixed(2)} over ${cores} core${cores === 1 ? '' : 's'}`
              : `${metrics.cores ?? '?'} cores`
          }
        />
        <Gauge
          label="Memory"
          value={
            metrics.memory.percent !== null
              ? `${fmtBytes(metrics.memory.used_bytes)} / ${fmtBytes(metrics.memory.total_bytes)}`
              : '—'
          }
          percent={metrics.memory.percent}
          tone={memTone(metrics.memory.percent)}
          hint={
            metrics.memory.swap_total_bytes
              ? `swap ${fmtBytes(metrics.memory.swap_used_bytes)} of ${fmtBytes(metrics.memory.swap_total_bytes)}`
              : 'no swap'
          }
        />
        <Gauge
          label="Disk /"
          value={pct(metrics.disk.percent)}
          percent={metrics.disk.percent}
          tone={diskTone(metrics.disk.percent)}
          hint={
            metrics.disk.total_bytes
              ? `${fmtBytes(metrics.disk.free_bytes)} free of ${fmtBytes(metrics.disk.total_bytes)}`
              : undefined
          }
        />
      </div>

      {/* The three series on one shared time axis.
          CPU and memory move together when something is genuinely loading the
          machine; memory climbing on its own is a leak; CPU flat at zero while
          memory climbs is a wedged process. Overlaying them is what makes that
          readable, and three separate sparklines stacked vertically would not
          line up well enough to compare by eye. */}
      {history.length > 1 && (
        <div className="vm-metrics-diagram">
          <div className="vm-metrics-diagram-head">
            <span className="eyebrow">Last {windowLabel(history) ?? '—'}</span>
            <div className="vm-metrics-legend">
              <span className="is-cpu">CPU</span>
              <span className="is-mem">Mem</span>
              <span className="is-disk">Disk</span>
            </div>
          </div>

          <div className="vm-metrics-plot">
            {/* 0-100 fixed, not auto-scaled: a CPU line that fills the chart
                because it peaked at 4% would be the single most misleading
                thing on this card. The y axis is always the full range, so
                "looks flat" means flat. */}
            <TrendPlot history={history} />
            <div className="vm-metrics-axis" aria-hidden="true">
              <span>100%</span>
              <span>50%</span>
              <span>0</span>
            </div>
          </div>
        </div>
      )}

      <div className="vm-metrics-stats">
        <Stat label="Uptime" value={duration(metrics.uptime_seconds)} />
        <Stat
          label="Processes"
          value={metrics.processes.count !== null ? String(metrics.processes.count) : '—'}
        />
        <Stat
          label="Net"
          value={
            metrics.network.rx_bytes !== null
              ? `↓${fmtBytes(metrics.network.rx_bytes)} ↑${fmtBytes(metrics.network.tx_bytes ?? 0)}`
              : '—'
          }
          title="Bytes received / transmitted across every interface since boot"
        />
        <Stat label="Cores" value={metrics.cores !== null ? String(metrics.cores) : '—'} />
      </div>

      {metrics.network.addresses.length > 0 && (
        <div className="vm-metrics-addrs">
          {metrics.network.addresses.map((ip) => (
            <code key={ip}>{ip}</code>
          ))}
        </div>
      )}

      {metrics.processes.top.length > 0 && (
        <div className="vm-metrics-procs">
          <span className="eyebrow">Top processes by memory</span>
          <div className="vm-metrics-proc-rows">
            {metrics.processes.top.map((p) => (
              <div className="vm-metrics-proc" key={`${p.pid}-${p.name}`}>
                <span className="vm-metrics-proc-pid">{p.pid ?? '—'}</span>
                <span className="vm-metrics-proc-name" title={p.name}>{p.name}</span>
                <span className="vm-metrics-proc-mem">{fmtBytes(p.mem_bytes)}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      <p className="vm-metrics-footnote">
        {metrics.kernel ? `${metrics.kernel} · ` : ''}
        collected by a shell collector uploaded over SFTP and executed on the guest
      </p>
    </div>
  )
}