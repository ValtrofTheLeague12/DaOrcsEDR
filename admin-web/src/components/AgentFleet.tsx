import { useState, useEffect } from 'react'
import { Alert } from '@heroui/react/alert'
import { Button } from '@heroui/react/button'
import { Card } from '@heroui/react/card'
import { Chip } from '@heroui/react/chip'
import Icon from './Icon'
import CopyButton from './CopyButton'
import Loading from './Loading'
import { api, usePoll } from '../api'
import { ago, shortDuration } from '../lib/format'
import type {
  AgentDetections,
  AgentDeployJob,
  AgentFleetEntry,
  AgentHeartbeat,
} from '../types'

// ---------------------------------------------------------------------------
// Endpoint agent heartbeats.
//
// The agent owns the API; the panel only holds a small address book. Each card
// is one live GET /api/v1/health, so "online" is a point-in-time fact about
// this poll, not a claim that the VM will still be up in a minute. A saved
// agent that is powered off stays in the list with the reason it did not
// answer - deleting it because a VM is rebooting would be the wrong lesson.
//
// There is no Add/Test form: an agent enters the fleet through Deploy. The
// deploy form registers the name (with the endpoint address, when given) and
// builds the per-agent installer package, so the card and its configuration
// exist before the installer has even been run. Terminate/Start drive the
// agent's scan pause via POST /api/v1/control - a stopped Windows service
// listens on nothing, so a remote *service* start is impossible; pausing the
// scan loop is the symmetric pair a fleet page can actually drive, and the
// heartbeat keeps answering while paused.
// ---------------------------------------------------------------------------

type Tone = 'success' | 'warning' | 'danger' | 'default'

function toneOf(entry: AgentFleetEntry): { label: string; tone: Tone } {
  if (!entry.online) {
    if (entry.code === 'auth') return { label: 'needs update', tone: 'warning' }
    if (entry.code === 'http-error' || entry.code === 'invalid-response') {
      return { label: 'bad answer', tone: 'danger' }
    }
    return { label: 'offline', tone: 'default' }
  }
  if (entry.health?.agent.scan_paused) {
    return { label: 'paused', tone: 'warning' }
  }
  const status = entry.health?.status ?? entry.code
  if (status === 'ok') return { label: 'healthy', tone: 'success' }
  if (status === 'degraded') return { label: 'degraded', tone: 'warning' }
  return { label: status, tone: 'warning' }
}

function isoTimestamp(value: string | null | undefined): string {
  if (!value) return 'never'
  const ms = Date.parse(value)
  if (Number.isNaN(ms)) return 'never'
  return `${ago(ms / 1000)}`
}

function Fact({
  label,
  value,
  mono = false,
}: {
  label: string
  value: string | number
  mono?: boolean
}) {
  return (
    <div className="min-w-0">
      <dt className="eyebrow">{label}</dt>
      <dd className={`mt-0.5 truncate text-[12px] ${mono ? 'font-mono' : ''}`}>
        {value}
      </dd>
    </div>
  )
}

function HeartbeatFacts({ health }: { health: AgentHeartbeat }) {
  return (
    <dl className="grid grid-cols-2 gap-x-4 gap-y-2 sm:grid-cols-3 lg:grid-cols-4">
      <Fact label="Version" value={health.agent.version} mono />
      <Fact label="State" value={health.agent.state} />
      <Fact
        label="Service"
        value={health.agent.service ? 'LocalSystem service' : 'interactive'}
      />
      <Fact
        label="Uptime"
        value={shortDuration(health.agent.uptime_seconds)}
      />
      <Fact label="Last scan" value={isoTimestamp(health.last_scan.finished_at)} />
      <Fact
        label="Scan took"
        value={
          health.last_scan.duration_seconds === null
            ? '-'
            : `${health.last_scan.duration_seconds.toFixed(2)}s`
        }
      />
      <Fact
        label="Kafka"
        value={
          health.kafka.last_publish_ok === null
            ? 'not published yet'
            : health.kafka.last_publish_ok ? 'last publish ok' : 'last publish failed'
        }
      />
      <Fact label="Topic" value={health.kafka.topic} mono />
      <Fact label="Samples sent" value={health.counters.samples_published} />
      <Fact label="Publish errors" value={health.counters.publish_errors} />
      <Fact label="Detections logged" value={health.counters.records_logged} />
      <Fact label="Watch dirs" value={health.config.watch_dirs.length} />
    </dl>
  )
}

function DetectionRows({ data }: { data: AgentDetections }) {
  if (data.count === 0) {
    return (
      <p className="text-[11px] text-default-400">
        No detections yet. The file is {data.file}.
      </p>
    )
  }
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-[11px]">
        <thead className="text-default-400">
          <tr>
            <th className="py-1 pr-3 font-medium">Detected</th>
            <th className="py-1 pr-3 font-medium">File</th>
            <th className="py-1 pr-3 font-medium">Host</th>
            <th className="py-1 pr-3 font-medium">SHA-256</th>
          </tr>
        </thead>
        <tbody>
          {data.detections.map((record, index) => {
            const sha = String(record.sha256 ?? '')
            return (
              <tr
                key={`${String(record.sha256 ?? index)}-${index}`}
                className="border-t border-default-100"
              >
                <td className="whitespace-nowrap py-1 pr-3 text-default-500">
                  {isoTimestamp(String(record.detected_at ?? ''))}
                </td>
                <td className="max-w-[16rem] truncate py-1 pr-3">
                  {String(record.file_name ?? '-')}
                </td>
                <td className="py-1 pr-3 text-default-500">
                  {String(record.host ?? '-')}
                </td>
                <td className="py-1 pr-3 font-mono text-default-400">
                  {sha ? `${sha.slice(0, 16)}…` : '-'}
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Installer deploy: build (agent/build.ps1), stage the per-agent package,
// upload to MEGA, share the public link. The link is the deliverable, so it
// survives a reload: the current-job endpoint is fetched once on mount even
// when nothing is running, and a finished job keeps its card on screen.
// ---------------------------------------------------------------------------

const DEPLOY_POLL_MS = 2500
// The tail, not the whole log: the head is pip/npm noise, the end is where a
// failure announces itself.
const DEPLOY_LOG_LINES = 10

const DEPLOY_STATE_TONE = {
  running: 'accent',
  done: 'success',
  error: 'danger',
} as const

function DeployCard({ job }: { job: AgentDeployJob }) {
  const tail = job.log.slice(-DEPLOY_LOG_LINES)
  return (
    <Card className="network-panel-card w-full">
      <Card.Header>
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <Card.Title className="text-sm font-semibold">
              Installer deploy — {job.agent}
            </Card.Title>
            <p className="mt-0.5 text-[11px] text-default-500">
              Builds the agent installer, stages the per-agent package and
              shares it on MEGA.
            </p>
          </div>
          <Chip size="sm" variant="soft" color={DEPLOY_STATE_TONE[job.state]}>
            {job.state === 'running' ? 'building / uploading' : job.state}
          </Chip>
        </div>
      </Card.Header>

      <Card.Content className="flex flex-col gap-3">
        {job.state === 'error' && job.error && (
          <Alert status="danger">
            <Alert.Title>Deploy failed</Alert.Title>
            <Alert.Description>{job.error}</Alert.Description>
          </Alert>
        )}

        {job.state === 'running' && (
          <p className="text-[11px] text-default-500">
            This runs for minutes: PyInstaller packages the agent, then Inno
            Setup compiles the installer, then the folder uploads.
          </p>
        )}

        {job.api_port !== null && (
          <div className="rounded-lg border border-default-100 p-2.5">
            <p className="eyebrow mb-2">Configuration</p>
            <dl className="grid grid-cols-1 gap-x-4 gap-y-2 sm:grid-cols-2">
              <Fact label="API host" value={job.api_host ?? '0.0.0.0'} mono />
              <Fact label="API port" value={job.api_port ?? '-'} mono />
              <Fact label="Brokers" value={job.brokers ?? '-'} mono />
              <Fact label="Topic" value={job.topic ?? '-'} mono />
            </dl>
            <p className="mt-2 text-[11px] leading-relaxed text-default-400">
              Seeded into the package's agent.json on a fresh install: the
              heartbeat binds 0.0.0.0 on this port, so allow inbound TCP{' '}
              <span className="font-mono">{job.api_port}</span> on the endpoint,
              scoped to this panel's address.
            </p>
          </div>
        )}

        {tail.length > 0 && (
          <pre className="max-h-40 overflow-auto rounded-lg border border-default-100 bg-default-50/40 p-2.5 font-mono text-[10px] leading-relaxed text-default-500">
            {tail.join('\n')}
          </pre>
        )}

        {job.state === 'done' && job.link && (
          <div className="flex flex-col gap-2.5 rounded-lg border border-default-100 p-2.5">
            <div className="flex flex-wrap items-center gap-2">
              <a
                href={job.link}
                target="_blank"
                rel="noreferrer"
                className="font-mono text-[12px] underline decoration-default-300 underline-offset-2"
              >
                {job.link}
              </a>
              <CopyButton text={job.link}>Copy link</CopyButton>
            </div>
            <dl className="grid grid-cols-1 gap-x-4 gap-y-2 sm:grid-cols-2">
              <Fact label="Remote path" value={job.remote_path ?? '-'} mono />
              <Fact
                label="SHA-256"
                value={
                  job.sha256
                    ? `${job.sha256.slice(0, 32)}…`
                    : '-'
                }
                mono
              />
              <Fact
                label="Expires"
                value={job.expire ?? 'never (permanent link)'}
              />
              <Fact label="Staged at" value={job.artifact ?? '-'} mono />
            </dl>
            <p className="text-[11px] leading-relaxed text-default-400">
              The package pairs the Setup exe with the agent.json template and
              an install-agent.ps1 that runs it silently for{' '}
              <span className="font-mono">{job.agent}</span>. Run the script on
              the endpoint as Administrator.
            </p>
          </div>
        )}
      </Card.Content>
    </Card>
  )
}

// The agent's default API port. Kept in one place so the placeholder, the
// reset after a save and the URL we build cannot drift apart.
const DEFAULT_PORT = '8787'

// Address and port are two fields in the form, but the address book stores one
// URL per agent, so they are joined here. A pasted full URL keeps its scheme,
// and the port field always wins over any port typed into the address.
function composeTarget(host: string, port: string) {
  const raw = host.trim().replace(/\/+$/, '')
  if (!raw) return ''
  const match = raw.match(/^(https?:\/\/)?(\[[^\]]+\]|[^/:]+)(?::\d+)?$/)
  if (!match) return raw
  return `${match[1] ?? ''}${match[2]}:${port.trim() || DEFAULT_PORT}`
}

export default function AgentFleet() {
  const { data, error, loading, refresh } = usePoll(api.agentFleet, 12000)

  const [name, setName] = useState('')
  const [host, setHost] = useState('')
  const [port, setPort] = useState(DEFAULT_PORT)
  const [notice, setNotice] = useState<{
    tone: 'success' | 'warning' | 'danger'
    title: string
    detail: string
  } | null>(null)

  // One expanded card at a time: the table is the reason someone opens the
  // page, and stacking several of them makes the fleet unreadable.
  const [openFor, setOpenFor] = useState<string | null>(null)
  const [detectionState, setDetectionState] = useState<Record<
    string,
    { data: AgentDetections | null; error: string | null; loading: boolean }
  >>({})

  // The agent whose control request (terminate/start) is in flight, so one
  // click cannot fire twice while the POST is still answering.
  const [controlling, setControlling] = useState<string | null>(null)

  // Deploy state. `deployJobId` is the poll lever (null = nothing running);
  // `deploying` only covers the POST itself, so a second button click cannot
  // start a second job while the first refusal is still in flight.
  const [deployJob, setDeployJob] = useState<AgentDeployJob | null>(null)
  const [deployJobId, setDeployJobId] = useState<string | null>(null)
  const [deploying, setDeploying] = useState<string | null>(null)

  // Reattach: a reload must not orphan a running deploy, and a finished one
  // keeps its link on screen instead of vanishing into the job store.
  useEffect(() => {
    let cancelled = false
    api.agentDeployCurrent().then((job) => {
      if (cancelled || !job) return
      setDeployJob(job)
      if (job.state === 'running') setDeployJobId(job.id)
    }).catch(() => {
      // The panel being up matters more than the deploy card; a failed
      // reattach just means no card until the next deploy.
    })
    return () => {
      cancelled = true
    }
  }, [])

  // Poll the deploy job while it runs. Visibility-gated like every other
  // poll here: a backgrounded tab is not watching the build scroll by.
  useEffect(() => {
    if (!deployJobId) return
    let cancelled = false
    const tick = async () => {
      try {
        const job = await api.agentDeployJob(deployJobId)
        if (cancelled) return
        setDeployJob(job)
        if (job.state === 'done') {
          setDeployJobId(null)
          setNotice({
            tone: 'success',
            title: `Installer shared for ${job.agent}`,
            detail: job.link ?? 'the package is on MEGA',
          })
        } else if (job.state === 'error') {
          setDeployJobId(null)
          setNotice({
            tone: 'danger',
            title: 'Deploy failed',
            detail: job.error ?? 'the deploy job reported an error',
          })
        }
      } catch {
        // One missed poll is not a failed deploy; the next tick retries.
      }
    }
    void tick()
    const id = window.setInterval(() => {
      if (document.visibilityState === 'visible') void tick()
    }, DEPLOY_POLL_MS)
    return () => {
      cancelled = true
      window.clearInterval(id)
    }
  }, [deployJobId])

  const deploy = async (agentName: string, registerUrl?: string) => {
    const trimmed = agentName.trim()
    if (!trimmed) return
    setDeploying(trimmed)
    setNotice(null)
    try {
      // Register the name in the address book first, when the operator gave
      // an endpoint address: the section should exist in the fleet list the
      // moment deploy starts, not only after the installer has been run on
      // the endpoint. Re-saving an existing name just updates its address;
      // a failed save does not block the build.
      if (registerUrl) {
        await api.addAgent(trimmed, registerUrl).catch(() => null)
      }
      const parsed = port.trim()
      const result = await api.agentDeploy(
        trimmed, parsed && parsed !== DEFAULT_PORT ? Number(parsed) : undefined,
      )
      if (!result.ok) {
        setNotice({
          tone: 'danger',
          title: 'Deploy not started',
          detail: result.detail ?? result.error ?? 'the panel refused the request',
        })
        return
      }
      if (result.job_id) {
        setDeployJob(null)
        setDeployJobId(result.job_id)
        setNotice({
          tone: 'success',
          title: `Building installer for ${result.agent ?? trimmed}`,
          detail: 'The link appears here when the upload finishes.',
        })
      }
    } catch (exc) {
      setNotice({
        tone: 'danger',
        title: 'Deploy not started',
        detail: exc instanceof Error ? exc.message : String(exc),
      })
    } finally {
      setDeploying(null)
    }
  }

  const control = async (entry: AgentFleetEntry, action: 'stop' | 'start') => {
    if (action === 'stop' && !window.confirm(
      `Terminate scanning on ${entry.name}?\n\n` +
      'The agent stops watching its folders and sending samples until you ' +
      'press Start agent. The Windows service itself keeps running and the ' +
      'heartbeat stays online - stopping the service itself must be done on ' +
      'the endpoint with windows-service.ps1 -Action stop.',
    )) return
    setControlling(entry.name)
    setNotice(null)
    try {
      const result = await api.agentControl(entry.name, action)
      if (!result.ok) {
        setNotice({
          tone: 'danger',
          title: action === 'stop' ? 'Agent not terminated' : 'Agent not started',
          detail: result.error ?? 'the panel refused the request',
        })
        return
      }
      setNotice({
        tone: action === 'stop' ? 'warning' : 'success',
        title: action === 'stop'
          ? `Scans paused on ${entry.name}`
          : `Scans resumed on ${entry.name}`,
        detail: action === 'stop'
          ? 'The heartbeat stays online; press Start agent to resume.'
          : 'The scan loop is watching the configured folders again.',
      })
      refresh()
    } catch (exc) {
      setNotice({
        tone: 'danger',
        title: action === 'stop' ? 'Agent not terminated' : 'Agent not started',
        detail: exc instanceof Error ? exc.message : String(exc),
      })
    } finally {
      setControlling(null)
    }
  }

  const remove = async (entry: AgentFleetEntry) => {
    if (!window.confirm(
      `Remove ${entry.name} (${entry.url}) from this list? The agent itself is not touched.`,
    )) return
    const result = await api.removeAgent(entry.name)
    if (!result.ok) {
      setNotice({
        tone: 'danger',
        title: 'Agent not removed',
        detail: result.error ?? result.code ?? 'the panel refused the request',
      })
      return
    }
    if (openFor === entry.name) setOpenFor(null)
    setNotice({
      tone: 'success',
      title: `Removed ${entry.name}`,
      detail: 'The saved address is gone; the endpoint is untouched.',
    })
    refresh()
  }

  const toggleDetections = async (entry: AgentFleetEntry) => {
    if (openFor === entry.name) {
      setOpenFor(null)
      return
    }
    setOpenFor(entry.name)
    setDetectionState((prev) => ({
      ...prev,
      [entry.name]: { data: null, error: null, loading: true },
    }))
    try {
      const data = await api.agentDetections(entry.name, 20)
      setDetectionState((prev) => ({
        ...prev,
        [entry.name]: { data, error: null, loading: false },
      }))
    } catch (exc) {
      setDetectionState((prev) => ({
        ...prev,
        [entry.name]: {
          data: null,
          error: exc instanceof Error ? exc.message : String(exc),
          loading: false,
        },
      }))
    }
  }

  if (loading && !data) return <Loading label="endpoint agents" />

  return (
    <div className="flex flex-col gap-3">
      {error && (
        <Alert status="danger">
          <Alert.Title>Cannot read the agent list</Alert.Title>
          <Alert.Description>{error}</Alert.Description>
        </Alert>
      )}

      <Card className="network-panel-card w-full">
        <Card.Header>
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <Card.Title className="text-sm font-semibold">Deploy an agent</Card.Title>
              <p className="mt-1 max-w-2xl text-[11px] text-default-500">
                Builds the installer, stages the per-agent package and shares
                it on MEGA. There is no token to copy: the API is read-only,
                and the endpoint firewall decides who may reach it.
              </p>
            </div>
            <div className="flex items-center gap-2">
              <Chip size="sm" variant="soft" color={data && data.count > 0 ? 'accent' : 'default'}>
                {data?.online ?? 0}/{data?.count ?? 0} online
              </Chip>
              <Button
                size="sm"
                variant="ghost"
                onPress={() => refresh()}
              >
                <Icon name="refresh" size={13} />
                Refresh
              </Button>
            </div>
          </div>
        </Card.Header>

        <Card.Content className="flex flex-col gap-3">
          <div className="flex flex-wrap items-end gap-2">
            <label className="flex flex-col gap-1">
              <span className="eyebrow">Name</span>
              <input
                className="field agent-name-field"
                placeholder="win-user"
                value={name}
                onChange={(e) => setName(e.currentTarget.value)}
                disabled={deploying !== null}
              />
            </label>
            <label className="flex flex-col gap-1">
              <span className="eyebrow">Endpoint address</span>
              <input
                className="field agent-address-field font-mono"
                placeholder="192.168.56.106 (optional)"
                value={host}
                onChange={(e) => setHost(e.currentTarget.value)}
                disabled={deploying !== null}
              />
            </label>
            <label className="flex flex-col gap-1">
              <span className="eyebrow">Port</span>
              <input
                className="field agent-port-field font-mono"
                placeholder={DEFAULT_PORT}
                value={port}
                inputMode="numeric"
                maxLength={5}
                onChange={(e) =>
                  setPort(e.currentTarget.value.replace(/[^0-9]/g, ''))
                }
                disabled={deploying !== null}
              />
            </label>
            <Button
              size="sm"
              variant="primary"
              isDisabled={deploying !== null || !name.trim()}
              onPress={() => void deploy(name, host.trim() ? composeTarget(host, port) : undefined)}
              aria-busy={deploying === name.trim() || undefined}
            >
              <Icon name="rocket" size={13} />
              {deploying === name.trim() ? 'Starting…' : 'Deploy installer'}
            </Button>
          </div>

          <p className="text-[11px] leading-relaxed text-default-400">
            Deploying adds a section for the agent below, with the port and the
            configuration the package seeds. The endpoint address is optional:
            give it and the section probes the heartbeat as soon as the agent
            is installed; leave it blank to fix it later. The port defaults to{' '}
            <code className="font-mono">{DEFAULT_PORT}</code>.
          </p>

          {notice && (
            <Alert status={notice.tone}>
              <Alert.Title>{notice.title}</Alert.Title>
              <Alert.Description>{notice.detail}</Alert.Description>
            </Alert>
          )}
        </Card.Content>
      </Card>

      {deployJob && <DeployCard job={deployJob} />}

      {data && data.count === 0 && (
        <Card className="network-panel-card w-full">
          <Card.Header>
            <Card.Title className="text-sm font-semibold">No agents registered</Card.Title>
          </Card.Header>
          <Card.Content className="flex flex-col gap-2 text-[11px] leading-relaxed text-default-500">
            <p>
              The heartbeat API is on by default and binds loopback until the
              installer configures it.
            </p>
            <ol className="list-decimal pl-4">
              <li>
                On an agent installed by hand, set{' '}
                <code className="font-mono">api.host</code> to{' '}
                <code className="font-mono">0.0.0.0</code> in{' '}
                <code className="font-mono">%ProgramData%\DaOrcs\Agent\agent.json</code>.
              </li>
              <li>
                Run <code className="font-mono">windows-service.ps1 -Action upgrade</code>{' '}
                once: it fills in a missing <code className="font-mono">api</code>{' '}
                block and restarts the service in place.
              </li>
              <li>
                Allow TCP <code className="font-mono">8787</code> in the endpoint
                firewall, scoped to this panel's address, then deploy the agent
                above with that address so a section appears here.
              </li>
            </ol>
            <p>
              <code className="font-mono">windows-service.ps1 -Action status</code>{' '}
              prints the URL and whether the port is open.
            </p>
          </Card.Content>
        </Card>
      )}

      <div className="grid grid-cols-1 gap-3 xl:grid-cols-2">
        {data?.agents.map((entry) => {
          const state = toneOf(entry)
          const health = entry.health
          const paused = health?.agent.scan_paused ?? false
          const det = detectionState[entry.name]
          return (
            <Card key={entry.name} className="network-panel-card w-full">
              <Card.Header>
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div className="min-w-0">
                    <Card.Title className="text-sm font-semibold">{entry.name}</Card.Title>
                    <p className="mt-0.5 truncate font-mono text-[11px] text-default-400">
                      {entry.url}
                    </p>
                  </div>
                  <div className="flex items-center gap-2">
                    {entry.latency_ms !== null && entry.online && (
                      <span className="font-mono text-[10px] text-default-400">
                        {entry.latency_ms} ms
                      </span>
                    )}
                    <Chip size="sm" variant="soft" color={state.tone}>
                      {state.label}
                    </Chip>
                  </div>
                </div>
              </Card.Header>

              <Card.Content className="flex flex-col gap-3">
                {health ? (
                  <>
                    <HeartbeatFacts health={health} />
                    {health.last_sample && (
                      <p className="truncate text-[11px] text-default-500">
                        Last detection: <span className="font-mono">{health.last_sample.file_name}</span>
                        {' · '}
                        {isoTimestamp(health.last_sample.detected_at)}
                        {' · '}
                        {health.last_sample.sha256.slice(0, 16)}…
                      </p>
                    )}
                    {health.last_error && (
                      <Alert status="warning">
                        <Alert.Title>Last error</Alert.Title>
                        <Alert.Description>
                          {health.last_error.message} ({isoTimestamp(health.last_error.at)})
                        </Alert.Description>
                      </Alert>
                    )}
                  </>
                ) : (
                  <p className="text-[11px] leading-relaxed text-default-500">
                    {entry.detail ?? 'The agent did not return a heartbeat.'}
                  </p>
                )}

                <div className="flex flex-wrap gap-2">
                  <Button
                    size="sm"
                    variant="ghost"
                    isDisabled={!entry.online}
                    onPress={() => void toggleDetections(entry)}
                  >
                    <Icon name="logs" size={13} />
                    {openFor === entry.name ? 'Hide logs' : 'Logs'}
                  </Button>
                  <Button
                    size="sm"
                    variant="ghost"
                    isDisabled={!entry.online || paused || controlling !== null}
                    onPress={() => void control(entry, 'stop')}
                    aria-busy={controlling === entry.name || undefined}
                  >
                    <Icon name="x" size={13} />
                    Terminate agent
                  </Button>
                  <Button
                    size="sm"
                    variant="ghost"
                    isDisabled={!entry.online || !paused || controlling !== null}
                    onPress={() => void control(entry, 'start')}
                    aria-busy={controlling === entry.name || undefined}
                  >
                    <Icon name="play" size={13} />
                    Start agent
                  </Button>
                  <Button
                    size="sm"
                    variant="ghost"
                    isDisabled={deploying !== null}
                    onPress={() => void deploy(entry.name)}
                    aria-busy={deploying === entry.name || undefined}
                  >
                    <Icon name="rocket" size={13} />
                    {deploying === entry.name ? 'Starting…' : 'Deploy'}
                  </Button>
                  <Button
                    size="sm"
                    variant="ghost"
                    onPress={() => void remove(entry)}
                  >
                    Remove
                  </Button>
                </div>

                {openFor === entry.name && (
                  <div className="rounded-lg border border-default-100 p-2.5">
                    {det?.loading && <p className="text-[11px] text-default-400">Reading logs…</p>}
                    {det?.error && <p className="text-[11px] text-danger">{det.error}</p>}
                    {det?.data && <DetectionRows data={det.data} />}
                  </div>
                )}
              </Card.Content>
            </Card>
          )
        })}
      </div>
    </div>
  )
}
