import { useState } from 'react'
import { Alert, Button, Card, Chip } from '@heroui/react'
import Loading from '../components/Loading'
import { api, usePoll } from '../api'
import type { Container, ContainerList, ContainerState, EngineStats, StorageSection } from '../types'
import { ago, bytes, pct, shortDuration } from '../lib/format'
import { Sparkline, type SparkTone } from '../components/Stat'

// ---------------------------------------------------------------------------
// Live Docker state, read from the Docker CLI by the panel backend.
//
// Two compose projects are in this repo, and they are NOT one stack:
//   compose.yaml                      -> cyberchef-api, cyberchef-ui, guacamole
//   kafka-agent/docker-compose.yaml   -> kafka, kafka-agent, kafka-ui
// so the panel is grouped by project and keys are <project>/<service>. A
// "standalone" group holds containers the allowlist cannot map to a compose
// service (one-off runs like iaproject-clamav): visible with live metrics,
// but not start/stop controllable.
//
// Per-container metrics come from `docker stats --no-stream` (one snapshot per
// poll, cached 4s server-side); the engine row from `docker info` plus the
// summed stats; storage from `docker system df`. A stopped container has no
// stats row, so its metrics are null and render as "—", never as zero.
// ---------------------------------------------------------------------------

// 8s: the backend caches the snapshot for 4s and each docker stats pass takes
// ~1s, so polling faster just re-reads the cache; slower starts to feel dead.
const INTERVAL = 8000

const STATE_TONE: Record<ContainerState, 'success' | 'danger' | 'warning' | 'default' | 'accent'> = {
  running: 'success',
  exited: 'danger',
  created: 'default',
  paused: 'warning',
  restarting: 'warning',
  missing: 'danger',
}

// One horizontal resource bar: label + live value on the first line, a thin
// meter below. `used/limit` is the `docker stats` MEM USAGE pair; cpu has no
// limit, so it renders against one core (100%) with the container count noted
// in the engine card instead.
function Meter({
  label,
  display,
  frac,
  tone,
}: {
  label: string
  display: string
  frac: number | null
  tone?: 'accent' | 'success' | 'warning' | 'danger'
}) {
  const bar =
    tone === 'success' ? 'bg-success'
    : tone === 'warning' ? 'bg-warning'
    : tone === 'danger' ? 'bg-danger'
    : 'bg-accent'
  return (
    <div>
      <div className="flex items-baseline justify-between gap-2">
        <span className="text-[11px] text-default-500">{label}</span>
        <span className="font-mono text-[11px] tabular-nums">{display}</span>
      </div>
      <div className="mt-1 h-1 overflow-hidden rounded-full bg-default-200">
        <div
          className={`h-full rounded-full transition-[width] duration-700 ${frac === null ? '' : bar}`}
          style={{ width: `${frac === null ? 0 : Math.max(0, Math.min(100, frac * 100))}%` }}
        />
      </div>
    </div>
  )
}

// Docker Desktop overall, from `docker info` + summed `docker stats`. The
// trend strip underneath sums the per-container series poll-by-poll, so the
// engine line and the container lines always agree with each other.
function EngineCard({
  engine,
  partial,
  history,
}: {
  engine: EngineStats
  partial: boolean
  history: ContainerList['history']
}) {
  const cpuTone =
    engine.cpu_percent === null ? 'accent'
    : engine.cpu_percent > 80 ? 'danger'
    : engine.cpu_percent > 50 ? 'warning'
    : 'success'
  const tracks = history ? Object.values(history.series) : []
  const len = Math.max(0, ...tracks.map((t) => t.cpu.length))
  const engineCpu: (number | null)[] =
    history && len > 0
      ? Array.from({ length: len }, (_, i) => {
          let sum = 0
          let any = false
          for (const t of tracks) {
            const v = t.cpu[i]
            if (v !== null && v !== undefined) {
              sum += v
              any = true
            }
          }
          return any ? Math.round(sum * 100) / 100 : null
        })
      : []
  const engineMem: (number | null)[] =
    history && len > 0
      ? Array.from({ length: len }, (_, i) => {
          let sum = 0
          let any = false
          for (const t of tracks) {
            const v = t.mem[i]
            if (v !== null && v !== undefined) {
              sum += v
              any = true
            }
          }
          return any ? Math.round(sum * 100) / 100 : null
        })
      : []
  const showTrends = (history?.samples ?? 0) > 1
  return (
    <Card className="mb-4 w-full">
      <Card.Header className="flex items-center justify-between gap-3">
        <Card.Title className="text-sm font-semibold">
          Docker Desktop
          <span className="ml-2 font-mono text-xs font-normal text-default-400">
            {engine.os ?? '—'} · {engine.version ? `v${engine.version}` : '—'}
            {engine.arch ? ` · ${engine.arch}` : ''}
          </span>
        </Card.Title>
        <div className="flex items-center gap-2">
          {partial && (
            <Chip size="sm" variant="soft" color="warning" title="Some running containers had no stats row this poll">
              partial stats
            </Chip>
          )}
          <Chip size="sm" variant="soft" color="success">
            {engine.containers_running ?? '—'}/{engine.containers_total ?? '—'} running
          </Chip>
        </div>
      </Card.Header>
      <Card.Content>
        <div className="grid grid-cols-2 gap-x-8 gap-y-3 md:grid-cols-4">
          <Meter
            label={`CPU · ${engine.cpus ?? '—'} cores`}
            display={engine.cpu_percent === null ? '—' : `${engine.cpu_percent.toFixed(1)}%`}
            frac={engine.cpu_percent === null || !engine.cpus ? null : engine.cpu_percent / (engine.cpus * 100)}
            tone={cpuTone}
          />
          <Meter
            label={`Memory · ${bytes(engine.memory_used_bytes)} of ${bytes(engine.memory_total_bytes, 0)}`}
            display={engine.memory_percent === null ? '—' : pct(engine.memory_percent)}
            frac={engine.memory_percent === null ? null : engine.memory_percent / 100}
            tone={
              engine.memory_percent === null ? 'accent'
              : engine.memory_percent > 90 ? 'danger'
              : engine.memory_percent > 75 ? 'warning'
              : 'accent'
            }
          />
          <Meter
            label={`Net I/O · ↓ ${bytes(engine.net_rx_bytes)} / ↑ ${bytes(engine.net_tx_bytes)}`}
            display={`${bytes(engine.net_rx_bytes)} / ${bytes(engine.net_tx_bytes)}`}
            frac={null}
          />
          <Meter
            label={`Block I/O · R ${bytes(engine.block_read_bytes)} / W ${bytes(engine.block_write_bytes)}`}
            display={`${bytes(engine.block_read_bytes)} / ${bytes(engine.block_write_bytes)}`}
            frac={null}
          />
        </div>
        <p className="mt-3 font-mono text-[10px] text-default-400">
          {engine.kernel ?? '—'} · {engine.pids ?? '—'} pids across {engine.stats_containers} reporting containers
          {engine.images !== null && ` · ${engine.images} images`}
          {history && history.samples > 1 && ` · trends last ${shortDuration(history.window_seconds)}`}
        </p>
        {showTrends && (
          <div className="mt-3 grid grid-cols-1 gap-x-8 gap-y-3 border-t border-default-100 pt-3 md:grid-cols-2">
            <Trend label="CPU trend · all containers" unit="%" data={engineCpu} tone="accent" />
            <Trend label="Memory trend · all containers" unit="%" data={engineMem} tone="success" />
          </div>
        )}
      </Card.Content>
    </Card>
  )
}

// CPU + memory trend for one container: two Sparklines in the same style as
// the host-info tiles on the Statistics panel. Gaps (null samples, container
// stopped) break the line rather than reading as zero - that is Sparkline's
// own behaviour, kept deliberately. Needs 2+ samples before it draws.
function Trend({
  label,
  unit,
  data,
  tone,
  max,
}: {
  label: string
  unit: string
  data: (number | null)[]
  tone: SparkTone
  max?: number | null
}) {
  const live = [...data].reverse().find((v) => v !== null && v !== undefined)
  return (
    <div className="min-w-0">
      <div className="flex items-baseline justify-between gap-2">
        <span className="text-[11px] text-default-500">{label}</span>
        <span className="font-mono text-[11px] tabular-nums">
          {live === null || live === undefined ? '—' : `${live.toFixed(1)}${unit}`}
        </span>
      </div>
      <div className="mt-1">
        <Sparkline data={data} tone={tone} max={max} height={36} />
      </div>
    </div>
  )
}

function StorageCard({ storage }: { storage: NonNullable<ContainerList['storage']> }) {
  const rows: { label: string; s: StorageSection | null }[] = [
    { label: 'Images', s: storage.images },
    { label: 'Containers', s: storage.containers },
    { label: 'Volumes', s: storage.local_volumes },
    { label: 'Build cache', s: storage.build_cache },
  ]
  return (
    <Card className="mb-4 w-full">
      <Card.Header>
        <Card.Title className="text-sm font-semibold">Storage</Card.Title>
      </Card.Header>
      <Card.Content className="grid grid-cols-2 gap-x-8 gap-y-2 md:grid-cols-4">
        {rows.map(({ label, s }) => (
          <div key={label} className="flex items-baseline justify-between gap-2 border-b border-default-100 py-1.5">
            <span className="text-[11px] text-default-500">{label}</span>
            <span className="truncate font-mono text-[11px] tabular-nums" title={s?.reclaimable ?? ''}>
              {s?.size ?? '—'}
            </span>
          </div>
        ))}
      </Card.Content>
    </Card>
  )
}

export default function Containers() {
  const [busy, setBusy] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const { data, error, loading, refresh } = usePoll<ContainerList>(api.containers, INTERVAL)

  const act = async (c: Container, action: 'start' | 'stop') => {
    const key = `${c.project}/${c.name}:${action}`
    setBusy(key)
    setNotice(null)
    try {
      const res = await api.containerAction(c.project, c.name, action)
      setNotice(res.detail)
      refresh()
    } catch (e) {
      setNotice(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(null)
    }
  }

  return (
    <>
      <div className="mb-6 flex items-baseline justify-between gap-4">
        <h2 className="page-title">Containers</h2>
        <div className="flex items-center gap-3">
          <span className="font-mono text-xs text-default-500">
            {data?.updated_at ? `updated ${ago(data.updated_at)}` : 'live from the Docker CLI'}
          </span>
          <Button size="sm" variant="outline" onPress={refresh}>
            Refresh
          </Button>
        </div>
      </div>

      {loading && !data && (
        <Loading label="Loading container state…" hint="reading the Docker CLI" />
      )}

      {error && !data && (
        <Alert status="danger" className="mb-4">
          <Alert.Title>Panel API unreachable</Alert.Title>
          <Alert.Description>{error}</Alert.Description>
        </Alert>
      )}

      {notice && (
        <Alert status="accent" className="mb-4">
          <Alert.Description>{notice}</Alert.Description>
        </Alert>
      )}

      {data && !data.daemon.running && (
        <Alert status="danger" className="mb-4">
          <Alert.Title>Docker daemon is not running</Alert.Title>
          <Alert.Description>
            {data.daemon.error ?? 'Start Docker Desktop, then reload.'}
          </Alert.Description>
        </Alert>
      )}

      {data?.engine && <EngineCard engine={data.engine} partial={data.engine.stats_partial} history={data.history} />}
      {data?.storage && <StorageCard storage={data.storage} />}

      {data && !data.stats_available && data.daemon.running && (
        <Alert status="warning" className="mb-4">
          <Alert.Title>No live metrics this poll</Alert.Title>
          <Alert.Description>
            <code>docker stats</code> returned nothing — states and ports below are still live,
            usage meters show "—" until the next successful poll.
          </Alert.Description>
        </Alert>
      )}

      <Alert status="warning" className="mb-4">
        <Alert.Title>Start and stop only</Alert.Title>
        <Alert.Description>
          No <code>down</code> or <code>recreate</code>: <code>recreate</code> on
          guacamole touches its Postgres volume, and a misclick there is not
          cheap to undo. Logs and shell are also absent — the kafka-agent has no
          HTTP surface at all, so its logs are currently its only visibility.
        </Alert.Description>
      </Alert>

      {data?.daemon.running && (
        <div className="mb-4 flex items-center gap-2 text-xs text-default-500">
          <Chip size="sm" variant="soft" color="success">
            daemon {data.daemon.version}
          </Chip>
          <span>
            {data.projects.reduce((n, p) => n + p.containers.length, 0)} containers across{' '}
            {data.projects.length} groups
          </span>
        </div>
      )}

      <div className="flex flex-col gap-4">
        {data?.projects.map((p) => (
          <div key={p.label}>
            <div className="mb-2 flex items-baseline justify-between">
              <h3 className="text-sm font-semibold">
                {p.label}
                {p.label === 'standalone' && (
                  <span className="ml-2 text-[11px] font-normal text-default-400">
                    not in any compose file — metrics only
                  </span>
                )}
              </h3>
              <span className="font-mono text-[11px] text-default-400">{p.compose_file}</span>
            </div>
            <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-3">
              {p.containers.map((c) => {
                const up = c.state === 'running'
                const key = `${c.project}/${c.name}`
                const track = data?.history?.series[key]
                const showTrack = (data?.history?.samples ?? 0) > 1 && track !== undefined
                return (
                  <Card key={key} className="w-full">
                    <Card.Header className="flex items-center justify-between gap-2">
                      <Card.Title className="truncate font-mono text-sm" title={c.container_name ?? c.name}>
                        {c.name}
                      </Card.Title>
                      <Chip size="sm" variant="soft" color={STATE_TONE[c.state]}>
                        {c.state}
                      </Chip>
                    </Card.Header>

                    <Card.Content className="flex flex-col gap-2">
                      <p className="truncate font-mono text-[11px] text-default-400" title={c.image ?? ''}>
                        {c.image ?? '—'}
                      </p>
                      <p className="text-xs text-default-500">{c.status}</p>

                      {c.health !== 'none' && (
                        <div>
                          <Chip
                            size="sm"
                            variant="soft"
                            color={
                              c.health === 'healthy'
                                ? 'success'
                                : c.health === 'starting'
                                  ? 'warning'
                                  : 'danger'
                            }
                          >
                            health: {c.health}
                          </Chip>
                        </div>
                      )}

                      {/* Live usage from `docker stats`. Null when the container is
                          not running (stats has no row for it): render "—" with
                          an empty meter, never a zero that reads as "idle". */}
                      {up && (
                        <div className="flex flex-col gap-2 border-t border-default-100 pt-2">
                          <Meter
                            label="CPU"
                            display={c.cpu_percent === null ? '—' : `${c.cpu_percent.toFixed(1)}%`}
                            frac={c.cpu_percent === null ? null : c.cpu_percent / 100}
                            tone={
                              c.cpu_percent === null ? 'accent'
                              : c.cpu_percent > 80 ? 'danger'
                              : c.cpu_percent > 50 ? 'warning'
                              : 'success'
                            }
                          />
                          <Meter
                            label={`MEM · ${bytes(c.mem_used_bytes)}${c.mem_limit_bytes ? ` / ${bytes(c.mem_limit_bytes, 0)}` : ''}`}
                            display={c.mem_percent === null ? '—' : pct(c.mem_percent)}
                            frac={c.mem_percent === null ? null : c.mem_percent / 100}
                          />
                          <div className="flex items-baseline justify-between gap-2">
                            <span className="text-[11px] text-default-500">Net / Block</span>
                            <span className="font-mono text-[10px] tabular-nums text-default-500" title={`${c.pids ?? '—'} pids`}>
                              ↓{bytes(c.net_rx_bytes, 0)} ↑{bytes(c.net_tx_bytes, 0)} · R{bytes(c.block_read_bytes, 0)} W{bytes(c.block_write_bytes, 0)} · {c.pids ?? '—'} pids
                            </span>
                          </div>
                        </div>
                      )}

                      {/* CPU + memory history, same Sparkline style as the host-info
                          tiles. A stopped container keeps its old samples with
                          nulls appended, so the line visibly breaks instead of
                          freezing or dropping to zero. */}
                      {showTrack && track && (
                        <div className="grid grid-cols-2 gap-3 border-t border-default-100 pt-2">
                          <Trend label="CPU" unit="%" data={track.cpu} tone="accent" />
                          <Trend label="MEM" unit="%" data={track.mem} tone="success" max={100} />
                        </div>
                      )}

                      {c.ports.length > 0 && (
                        <div className="flex flex-wrap gap-1">
                          {c.ports.map((pt) => (
                            <span
                              key={pt}
                              className="rounded border border-default-200 px-1.5 py-0.5 font-mono text-[10px] text-default-500"
                            >
                              {pt}
                            </span>
                          ))}
                        </div>
                      )}
                    </Card.Content>

                    <Card.Footer className="flex justify-end gap-2">
                      <button
                        disabled={busy !== null || up || !c.controllable || !data?.daemon.running}
                        onClick={() => act(c, 'start')}
                        title={c.controllable ? '' : 'Not a compose service — cannot be started from here'}
                        className="rounded-md border border-default-300 px-3 py-1.5 text-xs hover:border-accent hover:text-accent disabled:opacity-40"
                      >
                        {busy === `${key}:start` ? 'Starting…' : 'Start'}
                      </button>
                      <button
                        disabled={busy !== null || !up || !c.controllable || !data?.daemon.running}
                        onClick={() => act(c, 'stop')}
                        title={c.controllable ? '' : 'Not a compose service — cannot be stopped from here'}
                        className="rounded-md border border-default-300 px-3 py-1.5 text-xs hover:border-danger hover:text-danger disabled:opacity-40"
                      >
                        {busy === `${key}:stop` ? 'Stopping…' : 'Stop'}
                      </button>
                    </Card.Footer>
                  </Card>
                )
              })}
            </div>
          </div>
        ))}
      </div>
    </>
  )
}
