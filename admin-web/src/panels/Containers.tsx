import { useState } from 'react'
import { Alert } from '@heroui/react/alert'
import { Button } from '@heroui/react/button'
import { Card } from '@heroui/react/card'
import { Chip } from '@heroui/react/chip'
import Loading from '../components/Loading'
import Icon from '../components/Icon'
import { api, usePoll } from '../api'
import type { Container, ContainerList, ContainerState, EngineStats, StorageSection, ComposeFile } from '../types'
import { ago, bytes, pct, shortDuration } from '../lib/format'
import { Sparkline, type SparkTone } from '../components/Stat'
import Pager, { usePaged } from '../components/Pager'
import ComposeFileViewer from '../components/ComposeFileViewer'
import BuildLog from '../components/BuildLog'

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
  const [building, setBuilding] = useState<string | null>(null)
  const [notice, setNotice] = useState<{ message: string; status: 'success' | 'danger' } | null>(null)
  const { data, error, loading, refresh } = usePoll<ContainerList>(api.containers, INTERVAL)
  const composeFiles = data?.compose_files ?? [
    ...new Map(
      (data?.projects ?? [])
        .filter((project) => project.compose_file)
        .map((project) => [project.label, { label: project.label, file: project.compose_file }]),
    ).values(),
  ]
  const allContainers = data?.projects.flatMap((project) =>
    project.containers.map((container) => ({ project, container })),
  ) ?? []
  const paged = usePaged(allContainers, 4)

  const act = async (c: Container, action: 'start' | 'stop') => {
    const key = `${c.project}/${c.name}:${action}`
    setBusy(key)
    setNotice(null)
    try {
      const res = await api.containerAction(c.project, c.name, action)
      setNotice({ message: res.detail, status: 'success' })
      refresh()
    } catch (e) {
      setNotice({ message: e instanceof Error ? e.message : String(e), status: 'danger' })
    } finally {
      setBusy(null)
    }
  }

  // A build is asynchronous now: the endpoint returns a job handle and the log
  // streams in the popup. The panel being up for the whole build is the point,
  // so it is not torn down on close - only the "building" lock is released,
  // and a click while it is still running reattaches to the same job.
  const [buildJob, setBuildJob] = useState<{ jobId: string; project: string } | null>(null)

  const buildCompose = async (project: string) => {
    setBuilding(project)
    setNotice(null)
    try {
      const res = await api.containerBuild(project)
      setBuildJob({ jobId: res.job_id, project })
      if (res.reused) {
        setNotice({ message: `${project}: a build was already running; showing its output.`, status: 'success' })
      }
    } catch (e) {
      setBuilding(null)
      setNotice({
        message: e instanceof Error ? e.message : String(e),
        status: 'danger',
      })
    }
  }

  const finishBuild = () => {
    setBuilding(null)
    setNotice(null)
    refresh()
  }

  const [composeViewerOpen, setComposeViewerOpen] = useState(false)
  const [selectedCompose, setSelectedCompose] = useState<{ label: string; file: string } | null>(null)

  // Runtime state comes from the poll this page already runs, so the badge costs
  // no extra request and the compose endpoint stays a plain file read.
  const runningServices = new Set(
    (data?.projects ?? []).flatMap((p) =>
      p.containers.filter((c) => c.state === 'running').map((c) => c.name),
    ),
  )

  const fetchComposeContent = async (): Promise<ComposeFile | null> => {
    if (!selectedCompose) return null
    return api.containerCompose(selectedCompose.label)
  }

  const openComposeViewer = (label: string, file: string) => {
    setSelectedCompose({ label, file })
    setComposeViewerOpen(true)
  }

  const closeComposeViewer = () => {
    setComposeViewerOpen(false)
    setSelectedCompose(null)
  }

  return (
    <div className="containers-page">
      <header className="containers-page-header">
        <div>
          <p className="eyebrow">Infrastructure</p>
          <h2 className="page-title mt-1">Containers</h2>
          <p className="containers-page-description">
            Live service status, resource usage, and safe start/stop controls.
          </p>
        </div>
        <div className="containers-page-actions">
          <span className="font-mono text-xs text-default-500">
            {data?.updated_at ? `updated ${ago(data.updated_at)}` : 'live from the Docker CLI'}
          </span>
          <Button size="sm" variant="outline" onPress={refresh}>
            Refresh
          </Button>
        </div>
      </header>

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
        <Alert status={notice.status === 'danger' ? 'danger' : 'accent'} className="mb-4">
          <Alert.Description>{notice.message}</Alert.Description>
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

      {data?.engine && (
        <EngineCard
          engine={data.engine}
          partial={data.engine.stats_partial}
          history={data.history}
        />
      )}
      {data?.storage && <StorageCard storage={data.storage} />}

      {data?.daemon.running && (
        <div className="containers-runtime-strip">
          <span className="containers-runtime-indicator" />
          <span className="containers-runtime-label">Docker engine</span>
          <span className="containers-runtime-version">{data.daemon.version}</span>
          <span className="containers-runtime-divider" />
          <span>
            {data.projects.reduce((n, p) => n + p.containers.length, 0)} containers
          </span>
          <span>
            {data.projects.length} project{data.projects.length === 1 ? '' : 's'}
          </span>
        </div>
      )}

      <section className="compose-files-section" aria-labelledby="compose-files-title">
        <header className="compose-files-heading">
          <div>
            <p className="eyebrow">Build configuration</p>
            <h3 id="compose-files-title">Available Compose files</h3>
            <p>Build project images, then refresh the service status below.</p>
          </div>
          <span className="compose-files-count">{composeFiles.length} configured</span>
        </header>
        {composeFiles.length === 0 ? (
          <p className="compose-files-empty">No Docker Compose files are configured.</p>
        ) : (
          <div className="compose-files-grid">
            {composeFiles.map((file) => {
              const project = data?.projects.find((item) => item.label === file.label)
              const running = project?.containers.filter((container) => container.state === 'running').length ?? 0
              const services = project?.containers.length ?? 0
              const isBuilding = building === file.label
              return (
                <article className="compose-file-card" key={file.label}>
                  <div className="compose-file-info">
                    <span className="compose-file-icon" aria-hidden="true">
                      <Icon name="build" size={16} />
                    </span>
                    <div className="min-w-0">
                      <h4>{file.label}</h4>
                      <p className="compose-file-path" title={file.file}>{file.file}</p>
                    </div>
                  </div>
                  <div className="compose-file-status">
                    <span className={`compose-status-dot ${data?.daemon.running ? (running > 0 ? 'is-running' : 'is-idle') : 'is-unavailable'}`} />
                    <span>
                      {!data?.daemon.running
                        ? 'Docker engine unavailable'
                        : services > 0
                          ? `${running} of ${services} services running`
                          : 'No service status reported'}
                    </span>
                  </div>
                  <div className="compose-file-actions flex items-center gap-2">
                    <button
                      type="button"
                      className="compose-view-button"
                      onClick={() => openComposeViewer(file.label, file.file)}
                      disabled={!data?.daemon.running}
                      title={`View ${file.file} content`}
                    >
                      <Icon name="file-text" size={13} />
                      View content
                    </button>
                    <button
                      type="button"
                      className="compose-build-button"
                      onClick={() => void buildCompose(file.label)}
                      disabled={!data?.daemon.running || building !== null || busy !== null}
                      title={!data?.daemon.running ? 'Start Docker Desktop to build images' : `Build images from ${file.file}`}
                    >
                      <Icon name="build" size={13} />
                      {isBuilding ? 'Building images…' : 'Build images'}
                    </button>
                  </div>
                </article>
              )
            })}
          </div>
        )}
      </section>

      <div className="containers-project-list">
        {data?.projects.map((p) => {
          const projectContainers = paged.slice.filter((item) => item.project.label === p.label)
          if (projectContainers.length === 0) return null
          return (
          <section key={p.label} className="containers-project">
            <header className="containers-project-header">
              <div className="min-w-0">
                <h3>{p.label}</h3>
                <p>
                  {p.label === 'standalone'
                    ? 'Standalone containers · metrics only'
                    : `${p.containers.length} service${p.containers.length === 1 ? '' : 's'}`}
                </p>
              </div>
              <span className="containers-compose-path" title={p.compose_file}>
                {p.compose_file}
              </span>
            </header>
            <div className="containers-card-grid">
              {projectContainers.map(({ container: c }) => {
                const up = c.state === 'running'
                const key = `${c.project}/${c.name}`
                const track = data?.history?.series[key]
                const showTrack = (data?.history?.samples ?? 0) > 1 && track !== undefined
                return (
                  <Card key={key} className="container-service-card w-full">
                    <Card.Header className="container-service-header flex items-center justify-between gap-2">
                      <Card.Title className="truncate font-mono text-sm" title={c.container_name ?? c.name}>
                        {c.name}
                      </Card.Title>
                      <Chip size="sm" variant="soft" color={STATE_TONE[c.state]}>
                        {c.state}
                      </Chip>
                    </Card.Header>

                    <Card.Content className="container-service-content flex flex-col gap-2">
                      <div className="container-image-line">
                        <span>Image</span>
                        <code className="truncate" title={c.image ?? ''}>{c.image ?? '—'}</code>
                      </div>
                      <p className="container-service-status">{c.status}</p>

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
                        <div className="container-metrics">
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
                        <div className="container-trends">
                          <Trend label="CPU" unit="%" data={track.cpu} tone="accent" />
                          <Trend label="MEM" unit="%" data={track.mem} tone="success" max={100} />
                        </div>
                      )}

                      {c.ports.length > 0 && (
                        <div className="container-ports">
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

                    <Card.Footer className="container-service-actions flex justify-end gap-2">
                      <button
                        disabled={busy !== null || up || !c.controllable || !data?.daemon.running}
                        onClick={() => act(c, 'start')}
                        title={c.controllable ? '' : 'Not a compose service — cannot be started from here'}
                        className="container-action start"
                      >
                        {busy === `${key}:start` ? 'Starting…' : 'Start'}
                      </button>
                      <button
                        disabled={busy !== null || !up || !c.controllable || !data?.daemon.running}
                        onClick={() => act(c, 'stop')}
                        title={c.controllable ? '' : 'Not a compose service — cannot be stopped from here'}
                        className="container-action stop"
                      >
                        {busy === `${key}:stop` ? 'Stopping…' : 'Stop'}
                      </button>
                    </Card.Footer>
                  </Card>
                )
              })}
            </div>
          </section>
          )
        })}
        <Pager
          page={paged.page}
          pages={paged.pages}
          first={paged.first}
          last={paged.last}
          total={allContainers.length}
          onPrev={paged.prev}
          onNext={paged.next}
        />
      </div>

      <ComposeFileViewer
        isOpen={composeViewerOpen}
        onClose={closeComposeViewer}
        projectLabel={selectedCompose?.label ?? ''}
        filePath={selectedCompose?.file ?? ''}
        fetchContent={fetchComposeContent}
        runningServices={runningServices}
      />

      {buildJob && (
        <BuildLog
          jobId={buildJob.jobId}
          projectLabel={buildJob.project}
          onClose={() => setBuildJob(null)}
          onFinished={finishBuild}
        />
      )}
    </div>
  )
}
