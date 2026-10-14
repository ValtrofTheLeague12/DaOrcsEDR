import { api, usePoll } from '../api'
import { StatTile, Sparkline } from '../components/Stat'
import Loading from '../components/Loading'
import Icon from '../components/Icon'
import { bytes, compact, duration, ms, pct, shortDuration } from '../lib/format'
import type { Stats } from '../types'

const INTERVAL = 5000

const VERDICT_TONE: Record<string, 'success' | 'warning' | 'danger' | 'default'> = {
  success: 'success',
  clean: 'success',
  suspicious: 'warning',
  malicious: 'danger',
  failed: 'danger',
  unknown: 'default',
}

function Ring({
  value,
  total,
  label,
  tone,
}: {
  value: number | null
  total: number | null
  label: string
  tone: 'success' | 'warning' | 'danger' | 'default'
}) {
  const v = value ?? 0
  const t = total ?? 0
  const pctDone = t ? Math.round((v / t) * 100) : 0
  const stroke = `var(--${tone === 'default' ? 'default-400' : tone})`
  const r = 30
  const c = 2 * Math.PI * r

  return (
    <div className="flex items-center gap-4">
      <div className="relative h-[76px] w-[76px] shrink-0">
        <svg viewBox="0 0 76 76" className="h-full w-full -rotate-90">
          <circle cx="38" cy="38" r={r} fill="none" strokeWidth="7"
            stroke="var(--default-200)" />
          <circle cx="38" cy="38" r={r} fill="none" strokeWidth="7"
            stroke={stroke} strokeLinecap="round"
            strokeDasharray={c} strokeDashoffset={c - (c * pctDone) / 100}
            style={{ transition: 'stroke-dashoffset 600ms cubic-bezier(0.22,1,0.36,1)' }} />
        </svg>
        <div className="absolute inset-0 flex items-center justify-center">
          <span className="metric font-mono text-lg font-semibold">
            {value === null ? '—' : `${v}/${t}`}
          </span>
        </div>
      </div>
      <div className="min-w-0">
        <p className="text-[11px] font-medium uppercase tracking-wider text-default-400">
          {label}
        </p>
        <p className="mt-1 text-xs text-default-500">
          {t === 0 ? 'nothing to report' : `${pctDone}% of registered endpoints`}
        </p>
      </div>
    </div>
  )
}

export default function Stats() {
  const { data, error } = usePoll<Stats>(api.stats, INTERVAL)

  if (error) {
    return <p className="py-10 text-sm text-danger">Stats unavailable: {error}</p>
  }
  if (!data) return <Loading label="Loading statistics…" hint="aggregating every panel" />

  const { services: svc, machine: mach, logs, runs, containers: ctr, history } = data
  const historyLabel =
    history.samples > 1 ? `last ${shortDuration(history.window_seconds)}` : 'collecting…'
  const containersNote = ctr.available
    ? ctr.running
      ? `daemon ${ctr.version ?? ''}`.trim()
      : 'daemon not responding'
    : (ctr.reason ?? 'unavailable')

  return (
    <>
      <div className="mb-6 flex items-baseline justify-between gap-4">
        <h1 className="page-title">Statistics</h1>
        <span className="text-[11px] text-default-400">
          aggregates every concern · history {historyLabel}
        </span>
      </div>

      {/* --- headline tiles --- */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <StatTile
          label="Services up"
          value={`${svc.up}/${svc.total}`}
          sub={`median ${ms(svc.median_ms)} probe`}
          icon={<Icon name="overview" size={15} />}
          trend={history.up}
          trendMax={history.total ?? undefined}
          trendTone={svc.up === svc.total ? 'success' : svc.up === 0 ? 'danger' : 'warning'}
        />
        <StatTile
          label="CPU"
          value={pct(mach.cpu)}
          sub={`${mach.cores ?? '—'} logical cores`}
          icon={<Icon name="machine" size={15} />}
          trend={history.cpu}
          trendMax={100}
          trendTone={(mach.cpu ?? 0) > 85 ? 'danger' : (mach.cpu ?? 0) > 65 ? 'warning' : 'accent'}
        />
        <StatTile
          label="Memory"
          value={pct(mach.memory)}
          sub={`${bytes(mach.disk_free_bytes, 0)} free on disk`}
          icon={<Icon name="stats" size={15} />}
          trend={history.memory}
          trendMax={100}
          trendTone={(mach.memory ?? 0) > 90 ? 'danger' : (mach.memory ?? 0) > 75 ? 'warning' : 'accent'}
        />
        <StatTile
          label="Uptime"
          value={duration(mach.uptime_seconds)}
          sub={`${mach.host ?? '—'}`}
          icon={<Icon name="refresh" size={15} />}
        />
      </div>

      {/* --- breakdown --- */}
      <div className="mt-4 grid grid-cols-1 gap-3 lg:grid-cols-3">
        {/* Services */}
        <div className="stat-tile">
          <div className="mb-4 flex items-center gap-2">
            <Icon name="overview" size={14} className="text-default-400" />
            <span className="eyebrow">Services</span>
          </div>
          <Ring
            value={svc.up}
            total={svc.total}
            label="healthy"
            tone={svc.up === svc.total ? 'success' : svc.up === 0 ? 'danger' : 'warning'}
          />
          <ul className="mt-4 flex flex-col gap-1.5">
            {svc.items.map((s) => (
              <li key={s.key} className="flex items-center justify-between gap-2 text-[11px]">
                <span className="flex items-center gap-2">
                  <span
                    className={`h-1.5 w-1.5 rounded-full ${
                      s.up ? 'bg-success' : 'bg-danger'
                    }`}
                  />
                  <span className="text-default-500">{s.name}</span>
                </span>
                <span className="metric font-mono text-default-400">{ms(s.ms)}</span>
              </li>
            ))}
          </ul>
        </div>

        {/* Logs */}
        <div className="stat-tile">
          <div className="mb-4 flex items-center gap-2">
            <Icon name="logs" size={14} className="text-default-400" />
            <span className="eyebrow">Logs</span>
          </div>
          <div className="metric font-mono text-2xl font-semibold leading-none">
            {compact(logs.files)}
            <span className="ml-1.5 text-sm font-normal text-default-400">files</span>
          </div>
          <p className="mt-1.5 text-[11px] text-default-500">
            {bytes(logs.bytes)} across {logs.sources} sources
          </p>
          {logs.largest && (
            <p className="mt-2 truncate font-mono text-[10px] text-default-400">
              largest: {logs.largest.name} · {bytes(logs.largest.bytes)}
            </p>
          )}
          <ul className="mt-4 flex flex-col gap-1.5">
            {logs.by_source.slice(0, 6).map((s) => (
              <li key={s.label} className="flex items-center justify-between gap-2 text-[11px]">
                <span className="truncate text-default-500">{s.label}</span>
                <span className="metric font-mono text-default-400">
                  {s.files} · {bytes(s.bytes, 0)}
                </span>
              </li>
            ))}
          </ul>
        </div>

        {/* Runs */}
        <div className="stat-tile">
          <div className="mb-4 flex items-center gap-2">
            <Icon name="artifacts" size={14} className="text-default-400" />
            <span className="eyebrow">Analysis runs</span>
          </div>
          <div className="metric font-mono text-2xl font-semibold leading-none">
            {runs.count}
            <span className="ml-1.5 text-sm font-normal text-default-400">runs</span>
          </div>
          <p className="mt-1.5 text-[11px] text-default-500">
            {compact(runs.artifacts)} artifacts · {bytes(runs.bytes)}
          </p>

          {Object.keys(runs.results).length > 0 && (
            <div className="mt-4 flex flex-wrap gap-1.5">
              {Object.entries(runs.results).map(([k, v]) => (
                <span
                  key={k}
                  className={`rounded-full px-2 py-0.5 text-[10px] font-medium ${
                    VERDICT_TONE[k] === 'success'
                      ? 'bg-success/12 text-success'
                      : VERDICT_TONE[k] === 'warning'
                        ? 'bg-warning/12 text-warning'
                        : VERDICT_TONE[k] === 'danger'
                          ? 'bg-danger/12 text-danger'
                          : 'bg-default-200 text-default-500'
                  }`}
                >
                  {k} {v}
                </span>
              ))}
            </div>
          )}

          <div className="mt-4 border-t border-default-200 pt-3 text-[11px] text-default-500">
            {runs.last_run_at ? `last run ${shortDuration(Date.now() / 1000 - runs.last_run_at)} ago` : 'no runs recorded'}
          </div>
        </div>
      </div>

      {/* --- containers + disk --- */}
      <div className="mt-4 grid grid-cols-1 gap-3 lg:grid-cols-2">
        <div className="stat-tile">
          <div className="mb-4 flex items-center justify-between gap-2">
            <span className="flex items-center gap-2">
              <Icon name="containers" size={14} className="text-default-400" />
              <span className="eyebrow">Containers</span>
            </span>
            <span
              className={`h-2 w-2 rounded-full ${
                ctr.available && ctr.running ? 'bg-success' : 'bg-danger'
              }`}
            />
          </div>
          {ctr.available && ctr.running ? (
            <>
              <div className="metric font-mono text-2xl font-semibold leading-none">
                {ctr.running_count}
                <span className="text-default-400">/{ctr.total}</span>
                <span className="ml-1.5 text-sm font-normal text-default-400">running</span>
              </div>
              <div className="mt-4 h-1.5 overflow-hidden rounded-full bg-default-200">
                <div
                  className="h-full rounded-full bg-success transition-[width] duration-700"
                  style={{
                    width: `${ctr.total ? ((ctr.running_count ?? 0) / ctr.total) * 100 : 0}%`,
                  }}
                />
              </div>
              <p className="mt-2 text-[11px] text-default-500">
                {containersNote} · {ctr.stopped} stopped
              </p>
            </>
          ) : (
            <p className="py-3 text-[11px] leading-relaxed text-default-400">
              {containersNote}
            </p>
          )}
        </div>

        <div className="stat-tile">
          <div className="mb-4 flex items-center gap-2">
            <Icon name="machine" size={14} className="text-default-400" />
            <span className="eyebrow">Storage</span>
          </div>
          <div className="metric font-mono text-2xl font-semibold leading-none">
            {pct(mach.disk_used_percent)}
            <span className="ml-1.5 text-sm font-normal text-default-400">used</span>
          </div>
          <div className="mt-4 h-1.5 overflow-hidden rounded-full bg-default-200">
            <div
              className={`h-full rounded-full transition-[width] duration-700 ${
                (mach.disk_used_percent ?? 0) > 90
                  ? 'bg-danger'
                  : (mach.disk_used_percent ?? 0) > 75
                    ? 'bg-warning'
                    : 'bg-accent'
              }`}
              style={{ width: `${mach.disk_used_percent ?? 0}%` }}
            />
          </div>
          <p className="mt-2 text-[11px] text-default-500">
            {bytes(mach.disk_free_bytes)} free of {bytes(mach.disk_total_bytes, 0)}
          </p>
          {history.samples > 1 && (
            <div className="mt-3 opacity-80">
              <Sparkline data={history.cpu} tone="accent" max={100} height={28} />
            </div>
          )}
        </div>
      </div>
    </>
  )
}