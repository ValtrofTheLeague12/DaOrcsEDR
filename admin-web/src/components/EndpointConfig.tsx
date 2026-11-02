import { useCallback, useEffect, useState } from 'react'
import { Alert } from '@heroui/react/alert'
import { Button } from '@heroui/react/button'
import { Card } from '@heroui/react/card'
import { Chip } from '@heroui/react/chip'
import Checkbox from './Checkbox'
import CopyButton from './CopyButton'
import Icon from './Icon'
import Loading from './Loading'
import { api } from '../api'
import type {
  AgentSaveResult,
  EndpointApplyResult,
  EndpointSnapshot,
  FixedEndpoint,
} from '../types'

// ---------------------------------------------------------------------------
// Configuration - the panel's half of admin-terminal/netcfg.py.
//
// One endpoint is editable, and that is the honest number. The Analyzer API
// reads SA_API_HOST / SA_API_PORT from .env itself, so moving it moves the
// service the panel probes. MalAPI and the ML scorer are launched BY every
// analysis at compiled addresses (http://127.0.0.1:60000 and :60010,
// src/main.cpp); editing their .env keys would move the standalone copy the
// panel starts by hand and leave the next analysis dialling the old address.
// So they are shown with the address that is actually used, `.env` beside it,
// and the reason - not a form that quietly does nothing.
//
// The checks can only be honest about time, too:
//   * an address is accepted only if ifaddr sees it on this host, because an
//     address the machine does not currently have would save and then fail;
//   * a port is tested with a real bind() server-side, and "free now" is the
//     promise - any check is a point-in-time fact;
//   * an off-loopback save widens the bind to 0.0.0.0 (the analyzer's own
//     clients dial 127.0.0.1), and the Analyzer API has no authentication.
//     That warning is stated before the save, not discovered afterwards.
//
// The agent section is deliberately not a transport picker. The endpoint agent
// publishes to Kafka and has no other transport; what the panel can own is the
// broker address (validated against this host's interfaces and reachability),
// the topic, and a filled agent.json to copy beside the agent executable. It
// cannot push that file to installed agents, and the page says so.
// ---------------------------------------------------------------------------

/** Mirrors the server's rule: localhost/127.0.0.0/8/::1 are loopback. */
function isLoopbackHost(value: string) {
  const host = value.trim()
  if (host === 'localhost' || host === '::1') return true
  return /^127\./.test(host)
}

function Bullets({ items }: { items: string[] }) {
  return (
    <ul className="mt-1 list-disc pl-4 text-[11px] leading-relaxed">
      {items.map((item) => <li key={item}>{item}</li>)}
    </ul>
  )
}

function FixedCard({ endpoint }: { endpoint: FixedEndpoint }) {
  return (
    <Card className="network-panel-card w-full">
      <Card.Header>
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0">
            <Card.Title className="text-sm font-semibold">{endpoint.name}</Card.Title>
            <p className="mt-0.5 truncate font-mono text-[11px] text-default-400">
              {endpoint.host}:{endpoint.port}
            </p>
          </div>
          <Chip size="sm" variant="soft" color="default">fixed</Chip>
        </div>
      </Card.Header>
      <Card.Content className="flex flex-col gap-2.5">
        <p className="text-xs leading-relaxed text-default-500">{endpoint.reason}</p>

        {endpoint.ui_url && (
          <a
            href={endpoint.ui_url}
            target="_blank"
            rel="noreferrer noopener"
            className="self-start rounded-full border border-default-200 px-2 py-0.5 text-[10px] font-medium text-default-500 hover:border-accent hover:text-accent"
          >
            open UI ↗
          </a>
        )}
      </Card.Content>
    </Card>
  )
}

export default function EndpointConfig() {
  const [snap, setSnap] = useState<EndpointSnapshot | null>(null)
  const [error, setError] = useState<string | null>(null)

  // Analyzer draft. Kept as strings so a half-typed value is not coerced into
  // a number (and into a different endpoint) while the operator types.
  const [host, setHost] = useState('')
  const [port, setPort] = useState('')
  const [restart, setRestart] = useState(true)
  const [saving, setSaving] = useState(false)
  const [notice, setNotice] = useState<EndpointApplyResult | null>(null)

  // Agent draft.
  const [brokers, setBrokers] = useState('')
  const [topic, setTopic] = useState('')
  const [agentSaving, setAgentSaving] = useState(false)
  const [agentNotice, setAgentNotice] = useState<AgentSaveResult | null>(null)

  const load = useCallback(async () => {
    try {
      const next = await api.endpoints()
      setSnap(next)
      const editable = next.editable[0]
      if (editable) {
        setHost(editable.host)
        setPort(String(editable.port))
      }
      setBrokers(next.agent.brokers)
      setTopic(next.agent.topic)
      setError(null)
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : String(exc))
    }
  }, [])

  useEffect(() => {
    void load()
  }, [load])

  const saveEndpoint = async () => {
    const numeric = Number(port)
    if (!Number.isInteger(numeric) || numeric < 1 || numeric > 65535) {
      setNotice({
        ok: false, key: 'analyzer', code: 'invalid-port',
        detail: 'The port must be a whole number between 1 and 65535.',
      })
      return
    }
    setSaving(true)
    setNotice(null)
    try {
      const result = await api.applyEndpoint(
        'analyzer', host.trim(), numeric, restart)
      setNotice(result)
      // Reload even on refusal: the snapshot is what the page claims is on
      // disk, and `notices` are not allowed to outlive a disagreeing read.
      await load()
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : String(exc))
    } finally {
      setSaving(false)
    }
  }

  const saveAgent = async () => {
    setAgentSaving(true)
    setAgentNotice(null)
    try {
      const result = await api.saveAgent(brokers.trim(), topic.trim())
      setAgentNotice(result)
      if (result.ok && result.agent) {
        const saved = result.agent
        setSnap((prev) => (prev ? { ...prev, agent: saved } : prev))
        setBrokers(saved.brokers)
        setTopic(saved.topic)
      }
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : String(exc))
    } finally {
      setAgentSaving(false)
    }
  }

  const downloadTemplate = () => {
    if (!snap) return
    const blob = new Blob(
      [JSON.stringify(snap.agent.template, null, 2) + '\n'],
      { type: 'application/json' },
    )
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = 'agent.json'
    link.click()
    URL.revokeObjectURL(url)
  }

  if (!snap) {
    return error
      ? (
        <Alert status="danger">
          <Alert.Title>Cannot read the endpoint configuration</Alert.Title>
          <Alert.Description>{error}</Alert.Description>
        </Alert>
      )
      : <Loading label="endpoint configuration" />
  }

  const editable = snap.editable[0]
  const templateText = JSON.stringify(snap.agent.template, null, 2)
  // After a refused save, the draft that was tried is the thing the operator
  // needs judged - not the last accepted values still in the snapshot.
  const agentValidation = agentNotice?.validation ?? snap.agent.validation
  const offLoopback = editable ? !isLoopbackHost(host) : false
  const narrow = editable
    ? host.trim() === editable.host && Number(port) === editable.port
    : false

  return (
    <div className="flex flex-col gap-3">
      {error && (
        <Alert status="danger">
          <Alert.Title>The configuration could not be reloaded</Alert.Title>
          <Alert.Description>{error}</Alert.Description>
        </Alert>
      )}

      <Card className="network-panel-card w-full">
        <Card.Header>
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <Card.Title className="text-sm font-semibold">Service endpoints</Card.Title>
              <p className="mt-1 max-w-2xl text-[11px] text-default-500">
                Written to <code className="font-mono">{snap.env_file}</code>. Only
                the Analyzer API can be moved: it reads these keys itself. MalAPI
                and the ML scorer are launched by each analysis at fixed
                addresses, so they are listed below with the reason instead of a
                form that would be ignored.
              </p>
            </div>
            <Chip size="sm" variant="soft" color="accent">.env</Chip>
          </div>
        </Card.Header>

        <Card.Content className="flex flex-col gap-3">
          {!editable ? (
            <p className="py-4 text-[12px] text-default-400">
              No editable endpoint was reported by the panel.
            </p>
          ) : (
            <>
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div>
                  <h3 className="text-xs font-semibold">{editable.name}</h3>
                  <p className="mt-0.5 font-mono text-[11px] text-default-400">
                    {editable.host}:{editable.port} · binds {editable.bind}
                  </p>
                </div>
                <Chip size="sm" variant="soft" color="success">editable</Chip>
              </div>

              <div className="flex flex-wrap items-end gap-2">
                <label className="flex flex-col gap-1">
                  <span className="eyebrow">Address</span>
                  <input
                    className="field w-56 font-mono"
                    aria-label="Analyzer API address"
                    list="endpoint-address-choices"
                    value={host}
                    onChange={(e) => setHost(e.currentTarget.value)}
                    disabled={saving}
                  />
                </label>
                <label className="flex flex-col gap-1">
                  <span className="eyebrow">Port</span>
                  <input
                    className="field w-28 font-mono"
                    aria-label="Analyzer API port"
                    type="number"
                    min={1}
                    max={65535}
                    value={port}
                    onChange={(e) => setPort(e.currentTarget.value)}
                    disabled={saving}
                  />
                </label>
                <label className="flex items-center gap-2 pb-2 text-[11px] text-default-600">
                  <Checkbox
                    checked={restart}
                    disabled={saving}
                    onChange={setRestart}
                  />
                  restart it after saving
                </label>
                <Button
                  size="sm"
                  variant="primary"
                  isDisabled={saving || !host.trim() || !port}
                  onPress={() => void saveEndpoint()}
                  aria-busy={saving || undefined}
                >
                  {saving ? 'Saving…' : 'Save endpoint'}
                </Button>
                <Button
                  size="sm"
                  variant="ghost"
                  isDisabled={saving}
                  onPress={() => void load()}
                >
                  Reload
                </Button>
              </div>

              <datalist id="endpoint-address-choices">
                {snap.addresses.map((address) => (
                  <option
                    key={address.address}
                    value={address.address}
                    label={`${address.adapter} · ${address.family}`}
                  />
                ))}
              </datalist>

              <p className="text-[11px] leading-relaxed text-default-400">
                Choose an address from the list or type one: an IP literal is
                accepted only when it is on an interface of this host. The port
                is tested with a real bind when you save, so “free now” is a
                point-in-time fact, not a reservation. A first change copies the
                old file to <code className="font-mono">.env.bak</code>.
              </p>

              {/* The restart order matters and the sentence says why: stop has
                  to look up the listener by the port still in .env. */}
              <p className="text-[11px] leading-relaxed text-default-400">
                {restart
                  ? 'A running service is stopped before the file is written and started again afterwards. The stop happens first because it finds the process by the old port; if it cannot stop, nothing is written.'
                  : 'The file is written without touching the running service, so it keeps listening on the old address until its next start.'}
              </p>

              {offLoopback && (
                <Alert status="warning">
                  <Alert.Title>
                    {host.trim() || 'That address'} is not loopback
                  </Alert.Title>
                  <Alert.Description>
                    <p>
                      Saving it binds <code className="font-mono">0.0.0.0</code>,
                      not only {host.trim()}: every interface can reach it.
                    </p>
                    <p className="mt-1">
                      The Analyzer API has no authentication - anyone who can
                      route here can upload samples and start analyses.
                    </p>
                  </Alert.Description>
                </Alert>
              )}

              {editable.warnings.length > 0 && narrow && (
                <Alert status="warning">
                  <Alert.Title>This endpoint is already exposed</Alert.Title>
                  <Alert.Description>
                    <Bullets items={editable.warnings} />
                  </Alert.Description>
                </Alert>
              )}

              {notice && (
                <Alert
                  status={!notice.ok
                    ? 'danger'
                    : notice.code === 'saved-shadowed' ? 'warning' : 'success'}
                >
                  <Alert.Title>
                    {!notice.ok
                      ? 'Endpoint not changed'
                      : notice.code === 'unchanged'
                        ? 'No change needed'
                        : notice.code === 'saved-shadowed'
                          ? 'Saved, but not active yet'
                          : 'Endpoint saved'}
                  </Alert.Title>
                  <Alert.Description>
                    <p>{notice.detail ?? notice.error}</p>
                    {notice.restart && (
                      <p className="mt-1">
                        {notice.restart.ok
                          ? `Restart: ${notice.restart.detail}`
                          : `Restart failed: ${notice.restart.detail}`}
                      </p>
                    )}
                    {notice.warnings && notice.warnings.length > 0 && (
                      <>
                        <p className="mt-2 font-semibold">What changed as well</p>
                        <Bullets items={notice.warnings} />
                      </>
                    )}
                  </Alert.Description>
                </Alert>
              )}
            </>
          )}
        </Card.Content>
      </Card>

      <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
        {snap.fixed.map((endpoint) => (
          <FixedCard key={endpoint.key} endpoint={endpoint} />
        ))}
      </div>

      <Card className="network-panel-card w-full">
        <Card.Header>
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <Card.Title className="text-sm font-semibold">Endpoint agent</Card.Title>
              <p className="mt-1 max-w-2xl text-[11px] text-default-500">
                {snap.agent.transport_note}
              </p>
            </div>
            <Chip size="sm" variant="soft" color="accent">{snap.agent.transport}</Chip>
          </div>
        </Card.Header>

        <Card.Content className="flex flex-col gap-3">
          <div className="flex flex-wrap items-end gap-2">
            <label className="flex flex-col gap-1">
              <span className="eyebrow">Kafka broker(s)</span>
              <input
                className="field w-72 font-mono"
                aria-label="Kafka bootstrap servers"
                placeholder="192.168.56.1:9092"
                value={brokers}
                onChange={(e) => setBrokers(e.currentTarget.value)}
                disabled={agentSaving}
              />
            </label>
            <label className="flex flex-col gap-1">
              <span className="eyebrow">Topic</span>
              <input
                className="field w-56 font-mono"
                aria-label="Kafka topic"
                value={topic}
                onChange={(e) => setTopic(e.currentTarget.value)}
                disabled={agentSaving}
              />
            </label>
            <Button
              size="sm"
              variant="primary"
              isDisabled={agentSaving || !brokers.trim() || !topic.trim()}
              onPress={() => void saveAgent()}
              aria-busy={agentSaving || undefined}
            >
              {agentSaving ? 'Saving…' : 'Save agent config'}
            </Button>
          </div>

          <p className="text-[11px] leading-relaxed text-default-400">
            Comma-separate multiple brokers as <code className="font-mono">host:port</code>.
            An IP literal must be an address of this host, because the broker
            runs here; reachability is reported as a warning, since configuring
            a stopped broker is a normal setup step.
          </p>

          {agentValidation.errors.length > 0 && (
            <Alert status="danger">
              <Alert.Title>The broker or topic is not usable</Alert.Title>
              <Alert.Description>
                <Bullets items={agentValidation.errors} />
              </Alert.Description>
            </Alert>
          )}

          {agentValidation.warnings.length > 0 && (
            <Alert status="warning">
              <Alert.Title>Worth knowing before deploying</Alert.Title>
              <Alert.Description>
                <Bullets items={agentValidation.warnings} />
              </Alert.Description>
            </Alert>
          )}

          {agentValidation.ok &&
            agentValidation.warnings.length === 0 && (
              <p className="text-[11px] text-success">
                Broker address and topic are valid, and the broker accepted a
                connection.
              </p>
            )}

          {agentNotice && (
            <Alert status={agentNotice.ok ? 'success' : 'danger'}>
              <Alert.Title>
                {agentNotice.ok ? 'Agent template updated' : 'Agent config not saved'}
              </Alert.Title>
              <Alert.Description>
                <p>{agentNotice.detail ?? agentNotice.error}</p>
                {agentNotice.ok && (
                  <p className="mt-1">
                    No process on this host restarts: these keys fill the
                    template below, which is what you deploy.
                  </p>
                )}
              </Alert.Description>
            </Alert>
          )}

          <div className="flex flex-wrap items-center gap-2">
            <Button size="sm" variant="outline" onPress={downloadTemplate}>
              <Icon name="artifacts" size={13} />
              Download agent.json
            </Button>
            <CopyButton text={templateText} variant="outline">
              Copy JSON
            </CopyButton>
            {snap.agent.example_file && (
              <span className="font-mono text-[10px] text-default-400">
                from {snap.agent.example_file}
              </span>
            )}
          </div>

          <p className="text-[11px] leading-relaxed text-default-400">
            On Windows, the installer registers the{' '}
            <code className="font-mono">DaOrcsEndpointAgent</code> service.
            Copy this file to{' '}
            <code className="font-mono">%PROGRAMDATA%\DaOrcs\Agent\agent.json</code>{' '}
            on each endpoint, then restart the service to apply the broker and
            topic settings.
          </p>

          <details className="rounded-md border border-default-100 px-3 py-2">
            <summary className="cursor-pointer text-[11px] font-medium text-default-500">
              agent.json template
            </summary>
            <pre className="mt-2 max-h-72 overflow-auto whitespace-pre-wrap break-all font-mono text-[10px] leading-relaxed text-default-600">
              {templateText}
            </pre>
          </details>
        </Card.Content>
      </Card>
    </div>
  )
}
