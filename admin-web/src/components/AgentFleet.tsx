import { useState } from 'react'
import { Alert } from '@heroui/react/alert'
import { Button } from '@heroui/react/button'
import { Card } from '@heroui/react/card'
import { Chip } from '@heroui/react/chip'
import Icon from './Icon'
import Loading from './Loading'
import { api, usePoll } from '../api'
import { ago, shortDuration } from '../lib/format'
import type {
  AgentDetections,
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
// The agent API is read-only and has no credential. That is a deliberate
// trade: an operator can add an endpoint by typing its address, and nothing
// secret has to be copied between machines. The firewall is what limits who
// can reach the port.
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

export default function AgentFleet() {
  const { data, error, loading, refresh } = usePoll(api.agentFleet, 12000)

  const [name, setName] = useState('')
  const [url, setUrl] = useState('')
  const [busy, setBusy] = useState(false)
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

  const add = async () => {
    setBusy(true)
    setNotice(null)
    try {
      const result = await api.addAgent(name.trim(), url.trim())
      if (!result.ok) {
        setNotice({
          tone: 'danger',
          title: 'Agent not saved',
          detail: result.error ?? result.code ?? 'the panel refused the request',
        })
        return
      }
      setNotice({
        tone: 'success',
        title: `Saved ${result.agent?.name ?? name.trim()}`,
        detail: `Probing ${result.agent?.url ?? url.trim()} now.`,
      })
      setName('')
      setUrl('')
      refresh()
    } catch (exc) {
      setNotice({
        tone: 'danger',
        title: 'Agent not saved',
        detail: exc instanceof Error ? exc.message : String(exc),
      })
    } finally {
      setBusy(false)
    }
  }

  const test = async () => {
    setBusy(true)
    setNotice(null)
    try {
      const probe = await api.testAgent(url.trim())
      if (probe.online) {
        const version = probe.health?.agent.version ?? 'unknown version'
        setNotice({
          tone: 'success',
          title: 'Agent answered',
          detail: `${probe.health?.agent.host ?? url.trim()} · ${version} · ${probe.latency_ms ?? '-'} ms`,
        })
      } else {
        setNotice({
          tone: probe.code === 'auth' ? 'warning' : 'danger',
          title: probe.code === 'auth' ? 'Agent needs an update' : 'Agent did not answer',
          detail: probe.detail ?? probe.code,
        })
      }
    } catch (exc) {
      setNotice({
        tone: 'danger',
        title: 'Probe failed',
        detail: exc instanceof Error ? exc.message : String(exc),
      })
    } finally {
      setBusy(false)
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
              <Card.Title className="text-sm font-semibold">Add an agent</Card.Title>
              <p className="mt-1 max-w-2xl text-[11px] text-default-500">
                Type the address the agent answers on. There is no token to
                copy: the API is read-only, and the endpoint firewall decides
                who may reach it.
              </p>
            </div>
            <div className="flex items-center gap-2">
              <Chip size="sm" variant="soft" color={data && data.count > 0 ? 'accent' : 'default'}>
                {data?.online ?? 0}/{data?.count ?? 0} online
              </Chip>
              <Button
                size="sm"
                variant="ghost"
                isDisabled={busy}
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
                className="field w-44"
                placeholder="win-user"
                value={name}
                onChange={(e) => setName(e.currentTarget.value)}
                disabled={busy}
              />
            </label>
            <label className="flex flex-col gap-1">
              <span className="eyebrow">Address</span>
              <input
                className="field w-64 font-mono"
                placeholder="192.168.56.106:8787"
                value={url}
                onChange={(e) => setUrl(e.currentTarget.value)}
                disabled={busy}
              />
            </label>
            <Button
              size="sm"
              variant="primary"
              isDisabled={busy || !name.trim() || !url.trim()}
              onPress={() => void add()}
              aria-busy={busy || undefined}
            >
              {busy ? 'Working…' : 'Add agent'}
            </Button>
            <Button
              size="sm"
              variant="ghost"
              isDisabled={busy || !url.trim()}
              onPress={() => void test()}
            >
              Test
            </Button>
          </div>

          <p className="text-[11px] leading-relaxed text-default-400">
            The address book is <code className="font-mono">{data?.config_file ?? '…'}</code>.
            Adding an existing name updates its address.
          </p>

          {notice && (
            <Alert status={notice.tone}>
              <Alert.Title>{notice.title}</Alert.Title>
              <Alert.Description>{notice.detail}</Alert.Description>
            </Alert>
          )}
        </Card.Content>
      </Card>

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
                firewall, scoped to this panel's address, then add the endpoint
                above.
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
                    {openFor === entry.name ? 'Hide detections' : 'Detections'}
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
                    {det?.loading && <p className="text-[11px] text-default-400">Reading detections…</p>}
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
