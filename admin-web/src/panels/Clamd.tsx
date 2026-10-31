import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { Alert } from '@heroui/react/alert'
import { Button } from '@heroui/react/button'
import { Card } from '@heroui/react/card'
import { Chip } from '@heroui/react/chip'
import Console from '../components/Console'
import Loading from '../components/Loading'
import Icon, { type IconName } from '../components/Icon'
import SubNav from '../components/SubNav'
import { StatTile } from '../components/Stat'
import { api, usePoll } from '../api'
import { ago, bytes, shortDuration } from '../lib/format'
import type {
  ClamdCheck,
  ClamdResultDocument,
  ClamdStatus,
  ClamdSubmitJob,
  ClamdTransport,
} from '../types'

// ---------------------------------------------------------------------------
// ClamAV - a GUEST on the Qiling VM, not a service on this host.
//
// Three questions, kept apart because they fail for different reasons:
//
//   Service status  can the SELECTED transport run right now? The transport is
//                   not chosen here: config/dynamic_analysis.json holds it, the
//                   same file the Dynamic Analysis > Configuration page writes.
//                   SFTP selected -> the driver files in python/clamd/ are
//                   checked (no SSH session is opened). TCP selected -> the
//                   operator's socket_validator.py opens the socket and clamd
//                   is asked for PING and VERSION.
//   Submit sample   the one action, down the transport the config names. SFTP
//                   runs python/clamd/scan_remote.py (deploy, scan in the VM,
//                   bring the JSON home); TCP sends clamd's INSTREAM command
//                   over the socket the operator's client opened. Both scripts
//                   are used as-is; the panel never reimplements either.
//   Scan results    every verdict read out of python/clamd/results/*.json,
//                   whichever transport wrote it. None are computed here, and
//                   the document behind a row can be read verbatim.
//
// The layout is deliberately rail + console on every tab: the facts and the
// controls sit in a narrow column, the machine text gets the rest of the width.
// The text is always a <Console>, so the connection test, the scan log and a
// result document scroll, number and copy the same way.
// ---------------------------------------------------------------------------

const INTERVAL = 10000

type VerdictKey = 'infected' | 'clean' | 'failed'
type Filter = 'all' | VerdictKey

const VERDICT: Record<VerdictKey, {
  label: string
  color: 'danger' | 'success' | 'warning'
  icon: IconName
}> = {
  infected: { label: 'Infected', color: 'danger', icon: 'clamd' },
  clean: { label: 'Clean', color: 'success', icon: 'check' },
  failed: { label: 'Failed', color: 'warning', icon: 'alert-circle' },
}

const TRANSPORT_LABEL: Record<'sftp' | 'tcp', string> = {
  sftp: 'SFTP — analysis VM',
  tcp: 'TCP socket — INSTREAM',
}

const TRANSPORT_CLIENT: Record<'sftp' | 'tcp', string> = {
  sftp: 'python/clamd/scan_remote.py',
  tcp: 'panel/utils/socket_validator.py',
}

/** How the same choice reads on the Dynamic Analysis page. */
const TRANSPORT_POLICY: Record<'sftp' | 'tcp', string> = {
  sftp: 'SFTP only',
  tcp: 'TCP/IP allowed',
}

/** The glyphs a check may ask for. A whitelist, so a typo in the server falls
 *  back to a tick instead of rendering an empty <svg>. */
const CHECK_ICONS: Record<string, IconName> = {
  'file-code': 'file-code',
  'file-text': 'file-text',
  code: 'code',
  plug: 'plug',
  wifi: 'wifi',
  activity: 'activity',
  check: 'check',
}

/** One step of the connection test: a number, what it was, how it went. */
function CheckStep({ index, total, name, ok, detail, advisory, icon }: {
  index: number
  total: number
  name: string
  ok: boolean
  detail: string
  advisory?: boolean
  icon?: string
}) {
  const state = ok ? 'ok' : advisory ? 'info' : 'bad'
  return (
    <div className={`check-step is-${state}`}>
      <div className="check-step-rail" aria-hidden="true">
        <span className="check-step-num">{index}</span>
        {index < total && <span className="check-step-spine" />}
      </div>
      <div className="check-step-body">
        <div className="check-step-head">
          <Icon
            name={CHECK_ICONS[icon ?? ''] ?? 'check'}
            size={12}
            className="check-step-ico"
          />
          <span className="check-step-name">{name}</span>
          <span className="check-step-mark">
            <Icon name={ok ? 'check' : advisory ? 'alert-circle' : 'x'} size={10} />
            {ok ? 'ok' : advisory ? 'info' : 'fail'}
          </span>
        </div>
        <p className="check-step-detail" title={detail}>{detail}</p>
      </div>
    </div>
  )
}

/** The same steps as a strip: one segment per step, coloured by outcome. */
function StepStrip({ checks }: { checks: ClamdCheck[] }) {
  return (
    <span className="step-strip" aria-hidden="true">
      {checks.map((c, i) => (
        <span
          key={`${c.name}-${i}`}
          className={`step-strip-seg is-${c.ok ? 'ok' : c.advisory ? 'info' : 'bad'}`}
          title={c.name}
        />
      ))}
    </span>
  )
}

function TransportRow({ transport, selected }: {
  transport: ClamdTransport
  selected: boolean
}) {
  const label = TRANSPORT_LABEL[transport.id as 'sftp' | 'tcp'] ?? transport.id
  return (
    <div className="flex items-start justify-between gap-3 border-b border-default-100 py-2 last:border-0">
      <span className="flex min-w-0 items-center gap-2.5">
        <span className={`transport-ico is-${transport.id} ${transport.available ? '' : 'is-off'}`}>
          <Icon name={transport.id === 'sftp' ? 'server' : 'plug'} size={13} />
        </span>
        <span className="flex min-w-0 flex-col">
          <span className="flex items-center gap-2 truncate text-[11px]">
            {label}
            {selected && (
              <span className="shrink-0 rounded border border-accent/40 bg-accent/10 px-1 font-mono text-[9px] text-accent">
                selected
              </span>
            )}
          </span>
          <span className="truncate font-mono text-[10px] text-default-400"
            title={transport.path}>
            {transport.path.split(/[\\/]/).slice(-2).join('/')}
          </span>
        </span>
      </span>
      <span className="flex shrink-0 flex-col items-end">
        <Chip size="sm" variant="soft" color={transport.available ? 'success' : 'warning'}>
          {transport.available ? 'ready' : 'unavailable'}
        </Chip>
        {transport.reason && (
          <span className="max-w-56 truncate text-[10px] text-warning" title={transport.reason}>
            {transport.reason}
          </span>
        )}
      </span>
    </div>
  )
}

/** One labelled fact in a rail card. */
function Fact({ label, children, title }: {
  label: string
  children: ReactNode
  title?: string
}) {
  return (
    <div className="flex items-baseline justify-between gap-3 border-b border-default-100 py-1.5 last:border-0">
      <span className="shrink-0 text-[11px] text-default-500">{label}</span>
      <span className="min-w-0 truncate font-mono text-[11px]" title={title}>
        {children}
      </span>
    </div>
  )
}

/** One line of the connection-test output, coloured by its marker. */
function statusLineClass(line: string): string {
  if (/^--- not ready/.test(line)) return 'text-danger'
  if (/^--- ready/.test(line)) return 'text-success'
  if (/^\[\d+\/\d+\]/.test(line)) return 'is-step'
  if (/^\[FAIL\]/.test(line)) return 'text-danger'
  if (/^\[info\]/.test(line)) return 'text-default-400'
  if (/^\[ok/.test(line)) return 'text-success'
  if (/^\s{2}(endpoint|note|\d+ steps)/.test(line)) return 'text-default-400'
  if (/^  socket_validator\.py said:/.test(line)) return 'text-default-400'
  if (/^\$ /.test(line)) return 'text-accent'
  return ''
}

/** One line of the submission log, coloured only by the shape it prints. */
function logLineClass(line: string): string {
  if (/^\s*---.*(FAILED|INFECTED)/.test(line)) return 'text-danger'
  if (/^\s*---.*CLEAN/.test(line)) return 'text-success'
  if (/^\s*===/.test(line)) return 'text-accent'
  if (/^\s{4}\$ /.test(line)) return 'text-default-500'
  if (/^\s{4}\*/.test(line)) return 'text-accent'
  if (/^\s{4}!/.test(line)) return 'text-warning'
  return ''
}

/** A result document is JSON; the verdict is the line worth colouring. */
function jsonLineClass(line: string): string {
  if (/"verdict"\s*:\s*"infected"/.test(line)) return 'text-danger'
  if (/"verdict"\s*:\s*"clean"/.test(line)) return 'text-success'
  if (/"verdict"\s*:\s*"failed"/.test(line)) return 'text-warning'
  if (/"signature"\s*:/.test(line)) return 'text-danger'
  return ''
}

export default function Clamd({ onNavigate }: {
  onNavigate?: (panel: 'dynamic-analysis') => void
}) {
  const { data: polledStatus, error: statusErr } = usePoll(api.clamdStatus, INTERVAL)
  const { data: results, error: resultsErr, refresh } = usePoll(api.clamdResults, INTERVAL)
  // The connection test runs on demand as well as on the poll, so the newest
  // result can come from either. One state holds whichever is newer, and the
  // poll keeps it fresh between presses.
  const [status, setStatus] = useState<ClamdStatus | null>(null)
  const [checking, setChecking] = useState(false)
  const [checkError, setCheckError] = useState<string | null>(null)
  useEffect(() => { if (polledStatus) setStatus(polledStatus) }, [polledStatus])
  // The daemon's own health, the action, and the verdicts it produced are
  // different questions. They shared one scroll once, and a long result list
  // buried the connection test that explains why there are no new rows.
  const [tab, setTab] = useState<'status' | 'submit' | 'results'>('status')

  const [job, setJob] = useState<ClamdSubmitJob | null>(null)
  const [file, setFile] = useState<File | null>(null)
  const [starting, setStarting] = useState(false)
  const [notice, setNotice] = useState<{ tone: 'ok' | 'bad'; text: string } | null>(null)
  const fileRef = useRef<HTMLInputElement>(null)

  // Results tab: the filter, the search needle, and the document on the right.
  const [filter, setFilter] = useState<Filter>('all')
  const [needle, setNeedle] = useState('')
  const [selected, setSelected] = useState<string | null>(null)
  const [document, setDocument] = useState<ClamdResultDocument | null>(null)
  const [docError, setDocError] = useState<string | null>(null)
  const [docLoading, setDocLoading] = useState(false)

  const transports = status?.transports
  // There is no transport picker here on purpose: config/dynamic_analysis.json
  // is the one place the choice is made, and this page reads it back. A second
  // control would let the status check and the scan disagree.
  const communication = status?.communication
  const chosen: 'sftp' | 'tcp' = communication?.mode ?? 'sftp'
  const chosenTransport = transports?.[chosen]
  const ready = status?.ready ?? false
  const checks = status?.checks ?? []
  const passed = checks.filter((c) => c.ok).length
  const running = job?.state === 'running'

  // Reattach to a scan this panel started before a reload, rather than showing
  // an idle button while scan_remote.py is still uploading.
  useEffect(() => {
    let cancelled = false
    api.clamdCurrent().then((current) => {
      if (!cancelled && current) setJob(current)
    }).catch(() => { /* no previous scan is not an error */ })
    return () => { cancelled = true }
  }, [])

  // Poll only while a scan is live; the interval stops the moment it finishes.
  useEffect(() => {
    if (!running || !job) return
    const id = window.setInterval(async () => {
      try {
        const next = await api.clamdJob(job.id)
        setJob(next)
        if (next.state !== 'running') refresh()
      } catch {
        // A dropped poll is not a failure; the next tick tries again.
      }
    }, 1200)
    return () => window.clearInterval(id)
  }, [running, job?.id, refresh])

  const submit = async () => {
    if (!file) return
    setStarting(true)
    setNotice(null)
    try {
      const res = await api.clamdSubmit(file)
      if (!res.ok || !res.job_id) {
        setNotice({ tone: 'bad', text: res.error ?? 'the submission was refused' })
        return
      }
      setJob(await api.clamdJob(res.job_id))
      setFile(null)
      if (fileRef.current) fileRef.current.value = ''
    } catch (e) {
      setNotice({ tone: 'bad', text: e instanceof Error ? e.message : String(e) })
    } finally {
      setStarting(false)
    }
  }

  // The explicit check: run the same endpoint the poll uses, immediately, and
  // keep its answer even if the next poll is 10s away.
  const runCheck = async () => {
    setChecking(true)
    setCheckError(null)
    try {
      setStatus(await api.clamdStatus())
    } catch (e) {
      setCheckError(e instanceof Error ? e.message : String(e))
    } finally {
      setChecking(false)
    }
  }

  const error = statusErr ?? resultsErr ?? checkError
  const counts = results?.counts
  const finished = job && job.state !== 'running' ? job : null

  // --- results: the visible rows and the document behind the selected one ---
  const files = results?.files ?? []
  const visible = useMemo(() => {
    const q = needle.trim().toLowerCase()
    return files.filter((f) => {
      if (filter !== 'all' && f.verdict !== filter) return false
      if (!q) return true
      return [f.filename, f.file, f.signature, f.detail]
        .some((v) => (v ?? '').toLowerCase().includes(q))
    })
  }, [files, filter, needle])

  // Follow the list: when the selection is filtered away, show the first row
  // that is still visible rather than a document the list no longer mentions.
  useEffect(() => {
    if (visible.length === 0) return
    if (!selected || !visible.some((f) => f.file === selected)) {
      setSelected(visible[0].file)
    }
  }, [visible, selected])

  useEffect(() => {
    if (!selected) {
      setDocument(null)
      return
    }
    let cancelled = false
    setDocument(null)
    setDocLoading(true)
    setDocError(null)
    api.clamdResult(selected)
      .then((doc) => { if (!cancelled) setDocument(doc) })
      .catch((e) => {
        if (!cancelled) {
          setDocument(null)
          setDocError(e instanceof Error ? e.message : String(e))
        }
      })
      .finally(() => { if (!cancelled) setDocLoading(false) })
    return () => { cancelled = true }
  }, [selected])

  // Pretty-print when the file is valid JSON, otherwise show it untouched -
  // a broken document is exactly what the operator needs to see.
  const docLines = useMemo(() => {
    if (!document || document.raw.trim() === '') return []
    try {
      return JSON.stringify(JSON.parse(document.raw), null, 2).split('\n')
    } catch {
      return document.raw.split('\n')
    }
  }, [document])

  const selectedRow = visible.find((f) => f.file === selected)
    ?? files.find((f) => f.file === selected)

  return (
    <>
      <div className="mb-6">
        <div className="flex items-baseline justify-between gap-4">
          <h2 className="page-title">ClamAV</h2>
          <div className="flex items-center gap-3">
            <span className="font-mono text-[11px] text-default-400">
              guest on the Qiling VM · {status?.endpoint ?? 'probing…'}
            </span>
            <Button size="sm" variant="outline" isDisabled={checking}
              onPress={() => { void runCheck(); refresh() }}>
              {checking ? 'Checking…' : 'Refresh'}
            </Button>
          </div>
        </div>
        <div className="clamd-rule" aria-hidden="true" />
      </div>

      {error && (
        <Alert status="danger" className="mb-4">
          <Alert.Title>Cannot read ClamAV state</Alert.Title>
          <Alert.Description>{error}</Alert.Description>
        </Alert>
      )}

      {!status && !error && (
        <Loading label="Loading ClamAV status…" hint="running the transport checks" />
      )}

      {status && communication?.error && (
        <Alert status="danger" className="mb-4">
          <Alert.Title>Cannot read the transport choice</Alert.Title>
          <Alert.Description>
            <code className="font-mono">{communication.path}</code>: {communication.error}.
            Submission stays disabled until that file is valid - the panel will
            not guess a transport.
          </Alert.Description>
        </Alert>
      )}

      {status && !communication?.error && !ready && (
        <Alert status="warning" className="mb-4">
          <Alert.Title>
            {chosen === 'sftp' ? 'SFTP transport is not ready' : 'TCP transport is not ready'}
          </Alert.Title>
          <Alert.Description>
            {status.checks.filter((c) => !c.ok && !c.advisory).map((c) => c.name).join(', ')
              || status.note}
          </Alert.Description>
        </Alert>
      )}

      <SubNav
        tabs={[
          {
            id: 'status', label: 'Service status', icon: 'clamd',
            tone: status
              ? (communication?.error ? 'bad' : ready ? 'ok' : 'warn')
              : undefined,
          },
          {
            id: 'submit', label: 'Submit sample', icon: 'plus',
            tone: running ? 'warn' : finished?.state === 'failed' ? 'bad'
              : finished?.state === 'passed' ? 'ok' : undefined,
          },
          {
            id: 'results', label: 'Scan results', icon: 'artifacts',
            tone: counts && counts.infected > 0
              ? 'bad'
              : counts && counts.failed > 0 ? 'warn' : undefined,
          },
        ]}
        active={tab}
        onChange={(id) => setTab(id as 'status' | 'submit' | 'results')}
      />

      {/* --- Service status: facts on the left, the test's own text on the right */}
      {tab === 'status' && status && (
        <>
          <div className="grid grid-cols-1 items-start gap-3 xl:grid-cols-[minmax(0,23rem)_minmax(0,1fr)]">
            <Card className="w-full">
              <Card.Header className="flex flex-row items-center justify-between gap-2">
                <Card.Title className="text-sm font-semibold">Connection</Card.Title>
                <Chip size="sm" variant="soft"
                  color={communication?.error ? 'danger' : ready ? 'success' : 'warning'}>
                  {communication?.error ? 'config unreadable' : ready ? 'ready' : 'not ready'}
                </Chip>
              </Card.Header>
              <Card.Content className="flex flex-col">
                <div className="flex items-center justify-between gap-3 border-b border-default-100 py-1.5">
                  <span className="shrink-0 text-[11px] text-default-500">Selected transport</span>
                  <span className="flex min-w-0 items-center gap-2">
                    <span className="truncate font-mono text-[11px]">
                      {TRANSPORT_POLICY[chosen]}
                    </span>
                    {onNavigate && (
                      <Button size="sm" variant="ghost"
                        onPress={() => onNavigate('dynamic-analysis')}>
                        Change…
                      </Button>
                    )}
                  </span>
                </div>
                <Fact label="Configured in" title={communication?.path}>
                  {communication?.path ?? 'config/dynamic_analysis.json'}
                </Fact>
                <Fact label="Endpoint" title={status.endpoint}>{status.endpoint}</Fact>
                <Fact label="clamd mode">{status.mode}</Fact>
                <Fact label="VM">
                  {status.vm.host
                    ? `${status.vm.host}@${status.vm.ip}:${status.vm.port}`
                    : 'not configured'}
                </Fact>
                <Fact label="Version" title={status.version}>{status.version || '—'}</Fact>
                <Fact label="Checked">
                  {status.checked_at
                    ? <span title={new Date(status.checked_at * 1000).toLocaleString()}>
                        {ago(status.checked_at)}
                      </span>
                    : '—'}
                </Fact>
                <p className="mt-2 border-t border-default-100 pt-2 text-[10px] leading-relaxed text-default-400">
                  {status.note}
                </p>
              </Card.Content>
            </Card>

            <Console
              title="Connection test"
              subtitle={chosen === 'sftp'
                ? 'file checks only · no SSH session is opened'
                : 'socket_validator.py · connect, PING, VERSION'}
              status={{
                label: ready ? 'ready' : 'not ready',
                tone: communication?.error ? 'danger' : ready ? 'success' : 'warning',
              }}
              meta={status.checked_at
                ? `${passed}/${checks.length} steps · ${new Date(status.checked_at * 1000).toLocaleTimeString()}`
                : `${passed}/${checks.length} steps`}
              actions={(
                <Button size="sm" variant="outline" isDisabled={checking}
                  onPress={() => void runCheck()}>
                  <Icon name="play" size={12} />
                  {checking ? 'Checking…' : 'Run check'}
                </Button>
              )}
              lines={status.output ?? []}
              lineClass={statusLineClass}
              ariaLabel="Connection test output"
              empty="No output recorded - press Run check."
            />
          </div>

          <div className="mt-3 grid grid-cols-1 gap-3 lg:grid-cols-2">
            <Card className="w-full">
              <Card.Header className="flex flex-row items-center justify-between gap-2">
                <Card.Title className="text-sm font-semibold">
                  {chosen === 'sftp' ? 'SFTP checks' : 'TCP checks'}
                  <span className="ml-2 text-[10px] font-normal text-default-400">
                    {chosen === 'sftp' ? 'python/clamd/ driver files' : 'socket client, then clamd'}
                  </span>
                </Card.Title>
                <span className="flex items-center gap-2">
                  <StepStrip checks={status.checks} />
                  <span className="font-mono text-[10px] text-default-400">
                    {status.checks.filter((c) => c.ok).length}/{status.checks.length} ok
                  </span>
                </span>
              </Card.Header>
              <Card.Content className="flex flex-col">
                {status.checks.map((c, i) => (
                  <CheckStep
                    key={`${c.name}-${i}`}
                    index={i + 1}
                    total={status.checks.length}
                    name={c.name}
                    ok={c.ok}
                    detail={c.detail}
                    advisory={c.advisory}
                    icon={c.icon}
                  />
                ))}
              </Card.Content>
            </Card>

            {transports && (
              <Card className="w-full">
                <Card.Header className="flex flex-row items-center justify-between gap-2">
                  <Card.Title className="text-sm font-semibold">
                    Submission transports
                    <span className="ml-2 text-[10px] font-normal text-default-400">
                      only the selected one is used
                    </span>
                  </Card.Title>
                </Card.Header>
                <Card.Content>
                  <TransportRow transport={transports.sftp} selected={chosen === 'sftp'} />
                  <TransportRow transport={transports.tcp} selected={chosen === 'tcp'} />
                </Card.Content>
              </Card>
            )}
          </div>
        </>
      )}

      {/* --- Submit sample: the form on the left, the live log on the right --- */}
      {tab === 'submit' && (
        <>
          <div className="grid grid-cols-1 gap-3 xl:grid-cols-[minmax(0,23rem)_minmax(0,1fr)]">
            <Card className="w-full self-start">
              <Card.Header className="flex flex-row items-center justify-between gap-2">
                <Card.Title className="text-sm font-semibold">Submit sample</Card.Title>
                {chosenTransport && (
                  <Chip size="sm" variant="soft"
                    color={chosenTransport.available ? 'success' : 'warning'}>
                    {chosenTransport.available ? 'transport ready' : 'unavailable'}
                  </Chip>
                )}
              </Card.Header>
              <Card.Content className="flex flex-col gap-3">
                <div className="flex items-center justify-between gap-2 rounded-md border border-default-200 px-2 py-1.5">
                  <span className="flex min-w-0 items-center gap-2.5">
                    <span className={`transport-ico is-${chosen}`}>
                      <Icon name={chosen === 'sftp' ? 'server' : 'plug'} size={13} />
                    </span>
                    <span className="flex min-w-0 flex-col">
                      <span className="text-[11px]">{TRANSPORT_LABEL[chosen]}</span>
                      <span className="truncate font-mono text-[10px] text-default-400"
                        title={communication?.path}>
                        {TRANSPORT_CLIENT[chosen]}
                      </span>
                    </span>
                  </span>
                  {onNavigate && (
                    <Button size="sm" variant="ghost"
                      onPress={() => onNavigate('dynamic-analysis')}>
                      change
                    </Button>
                  )}
                </div>

                <div className="flex flex-wrap items-center gap-2">
                  <button
                    type="button"
                    className="build-btn is-secondary"
                    disabled={starting || running}
                    onClick={() => fileRef.current?.click()}
                    title="Any file up to 25 MiB - clamd's StreamMaxLength"
                  >
                    <Icon name="plus" size={12} />
                    Choose sample…
                  </button>
                  <input
                    ref={fileRef}
                    type="file"
                    disabled={starting || running}
                    hidden
                    onChange={(e) => {
                      setFile(e.target.files?.[0] ?? null)
                      setNotice(null)
                    }}
                  />
                </div>

                <span className="min-w-0 break-all font-mono text-[11px] text-default-500">
                  {file ? `${file.name} · ${bytes(file.size, 0)}` : 'no file chosen'}
                </span>

                <button
                  type="button"
                  className="build-btn justify-center"
                  disabled={!file || starting || running || !chosenTransport?.available
                    || !!communication?.error}
                  onClick={() => void submit()}
                  title={!file ? 'Choose a sample first' : chosenTransport?.reason ?? 'Upload and scan'}
                >
                  <Icon name="play" size={12} />
                  {running ? 'Scanning…' : starting ? 'Submitting…' : 'Submit and scan'}
                </button>

                <p className="text-[10px] leading-relaxed text-default-400">
                  {chosenTransport ? `${chosenTransport.detail}. ` : ''}
                  Limit 25 MiB; the verdict is written to
                  <code className="font-mono"> python/clamd/results/</code> and appears
                  in Scan results.
                </p>

                {chosenTransport && !chosenTransport.available && (
                  <Alert status="warning">
                    <Alert.Description>{chosenTransport.reason}</Alert.Description>
                  </Alert>
                )}

                {notice && (
                  <Alert status={notice.tone === 'ok' ? 'success' : 'danger'}>
                    <Alert.Description>{notice.text}</Alert.Description>
                  </Alert>
                )}

                {finished?.results?.[0] && finished.results[0].state !== 'pending' && (
                  <div className="flex flex-wrap items-center gap-2 border-t border-default-100 pt-3">
                    <span className="text-[11px] text-default-500">Last submission</span>
                    <Chip
                      size="sm"
                      variant="soft"
                      color={finished.results[0].verdict === 'infected' ? 'danger'
                        : finished.results[0].verdict === 'clean' ? 'success' : 'warning'}
                    >
                      {finished.results[0].verdict ?? finished.results[0].state}
                    </Chip>
                    <span className="min-w-0 truncate font-mono text-[10px] text-default-400"
                      title={finished.results[0].detail ?? ''}>
                      {finished.results[0].detail ?? '—'}
                    </span>
                  </div>
                )}
              </Card.Content>
            </Card>

            <Console
              className="self-start"
              title="Scan log"
              icon="terminal"
              subtitle={job
                ? `${job.mode ?? chosen} · ${TRANSPORT_CLIENT[(job.mode ?? chosen) as 'sftp' | 'tcp']}`
                : TRANSPORT_CLIENT[chosen]}
              status={job?.summary
                ? {
                    label: job.summary,
                    tone: job.state === 'running' ? 'accent'
                      : job.state === 'passed' ? 'success' : 'danger',
                  }
                : job
                  ? { label: job.state, tone: job.state === 'running' ? 'accent' : 'warning' }
                  : undefined}
              meta={job
                ? `${job.log_line_count} line${job.log_line_count === 1 ? '' : 's'}`
                  + (job.exit_code !== null ? ` · exit ${job.exit_code}` : '')
                : undefined}
              actions={finished?.results?.[0]?.state === 'passed' && (
                <span className="flex items-center gap-2 rounded-md border border-default-100 px-2 py-1">
                  <Chip size="sm" variant="soft"
                    color={finished.results[0].verdict === 'infected' ? 'danger' : 'success'}>
                    {finished.results[0].verdict ?? finished.results[0].state}
                  </Chip>
                  {finished.results[0].signature && (
                    <span className="max-w-48 truncate font-mono text-[10px] text-danger"
                      title={finished.results[0].signature}>
                      {finished.results[0].signature}
                    </span>
                  )}
                </span>
              )}
              lines={job?.log ?? []}
              lineClass={logLineClass}
              truncated={job?.log_truncated ?? 0}
              live={running}
              numbered
              size="tall"
              ariaLabel="ClamAV submission output"
              empty={job
                ? 'Waiting for the first line…'
                : 'Nothing has been submitted this session. The uploader and the scanner print here.'}
            />
          </div>
        </>
      )}

      {/* --- Scan results: the list on the left, the document on the right --- */}
      {tab === 'results' && (
        <>
          <p className="section-label mb-2">Scan results</p>
          <div className="mb-3 grid grid-cols-3 gap-3">
            <StatTile
              label="Infected"
              value={counts?.infected ?? 0}
              icon={<Icon name="clamd" size={15} />}
              trendTone="danger"
              onClick={() => setFilter(filter === 'infected' ? 'all' : 'infected')}
            />
            <StatTile
              label="Clean"
              value={counts?.clean ?? 0}
              icon={<Icon name="overview" size={15} />}
              trendTone="success"
              onClick={() => setFilter(filter === 'clean' ? 'all' : 'clean')}
            />
            <StatTile
              label="Failed"
              value={counts?.failed ?? 0}
              icon={<Icon name="logs" size={15} />}
              trendTone="warning"
              onClick={() => setFilter(filter === 'failed' ? 'all' : 'failed')}
            />
          </div>

          <div className="logs-split">
            <Card className="logs-rail">
              <div className="logs-rail-head">
                <input
                  value={needle}
                  onChange={(e) => setNeedle(e.target.value)}
                  placeholder="Filter by sample or signature…"
                  aria-label="Filter result files"
                  className="log-search"
                />
              </div>
              <div className="flex flex-wrap items-center gap-1 border-b border-default-100 px-2 py-1.5"
                role="group" aria-label="Filter by verdict">
                {(['all', 'infected', 'clean', 'failed'] as Filter[]).map((value) => {
                  const count = value === 'all' ? files.length : (counts?.[value] ?? 0)
                  const tone = value === 'all' ? '' : `is-${VERDICT[value].color}`
                  return (
                    <button
                      key={value}
                      type="button"
                      onClick={() => setFilter(value)}
                      aria-pressed={filter === value}
                      className={`logs-pill ${tone} ${filter === value ? 'is-on' : ''}`}
                    >
                      {value === 'all' ? 'All' : VERDICT[value].label}
                      <span className="font-mono text-[9px] opacity-70">{count}</span>
                    </button>
                  )
                })}
              </div>
              <Card.Content className="logs-rail-list">
                {visible.length === 0 ? (
                  <p className="py-6 text-center text-[11px] text-default-400">
                    {files.length === 0
                      ? 'No result files yet. Submit a sample, or run scan_remote.py to produce one.'
                      : 'Nothing matches this filter.'}
                  </p>
                ) : (
                  <div className="flex flex-col">
                    {visible.map((r) => (
                      <button
                        key={r.file}
                        type="button"
                        onClick={() => setSelected(r.file)}
                        className={`flex w-full items-center justify-between gap-2 rounded-md px-2 py-1.5 text-left ${
                          selected === r.file ? 'bg-default-100' : 'hover:bg-default-50'
                        }`}
                      >
                        <span className="flex min-w-0 items-center gap-2">
                          <Icon
                            name={VERDICT[r.verdict].icon}
                            size={12}
                            className={
                              r.verdict === 'infected'
                                ? 'text-danger'
                                : r.verdict === 'clean'
                                  ? 'text-success'
                                  : 'text-default-400'
                            }
                          />
                          <span className="flex min-w-0 flex-col">
                            <span className="truncate font-mono text-[11px]"
                              title={r.filename || r.file}>
                              {r.filename || r.file}
                            </span>
                            <span
                              className={`truncate font-mono text-[9px] ${
                                r.verdict === 'infected' ? 'text-danger' : 'text-default-400'
                              }`}
                              title={r.signature || r.detail || r.file}
                            >
                              {r.signature || r.detail || ago(r.modified)}
                            </span>
                          </span>
                        </span>
                        <Chip size="sm" variant="soft" color={VERDICT[r.verdict].color}>
                          {VERDICT[r.verdict].label}
                        </Chip>
                      </button>
                    ))}
                  </div>
                )}
              </Card.Content>
            </Card>

            <Console
              className="logs-viewer"
              title={document?.name ?? selected ?? 'Result document'}
              subtitle={document
                ? `python/clamd/results · ${bytes(document.bytes, 0)} · ${ago(document.modified)}`
                : 'python/clamd/results'}
              status={selectedRow
                ? {
                    label: VERDICT[selectedRow.verdict].label,
                    tone: VERDICT[selectedRow.verdict].color,
                  }
                : undefined}
              meta={document ? `${docLines.length} lines` : undefined}
              lines={docLines}
              lineClass={jsonLineClass}
              numbered
              copyText={document?.raw ?? ''}
              ariaLabel="Result document"
              empty={docError
                ?? (docLoading
                  ? 'Reading the document…'
                  : document && document.raw.trim() === ''
                    ? 'This document is empty (0 bytes) - an interrupted SFTP download writes nothing.'
                    : 'Select a result on the left to read the document it came from.')}
            />
          </div>

          {selectedRow && (
            <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-1 px-1 font-mono text-[10px] text-default-400">
              <span>
                {selectedRow.seconds != null
                  ? `scanned in ${shortDuration(selectedRow.seconds)}`
                  : `${bytes(selectedRow.bytes)}`}
              </span>
              {selectedRow.endpoint && <span>{selectedRow.endpoint}</span>}
              {selectedRow.clamd_version && <span>{selectedRow.clamd_version}</span>}
              {selectedRow.sha256 && <span title={selectedRow.sha256}>sha256 {selectedRow.sha256.slice(0, 24)}…</span>}
            </div>
          )}
        </>
      )}
    </>
  )
}
