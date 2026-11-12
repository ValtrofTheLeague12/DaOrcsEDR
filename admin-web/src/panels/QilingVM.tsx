import { useEffect, useRef, useState, type ReactNode } from 'react'
import { Alert } from '@heroui/react/alert'
import { Button } from '@heroui/react/button'
import { Card } from '@heroui/react/card'
import { Chip } from '@heroui/react/chip'
import Loading from '../components/Loading'
import ToolHero from '../components/ToolHero'
import Console from '../components/Console'
import CopyButton from '../components/CopyButton'
import Icon, { type IconName } from '../components/Icon'
import SubNav from '../components/SubNav'
import { api, usePoll } from '../api'
import { ago, bytes } from '../lib/format'
import type {
  QilingConnectionCheck,
  QilingGuestMetrics,
  QilingPing,
  QilingRootfsJob,
  QilingRun,
  QilingSubmitInfo,
  QilingSubmitJob,
  QilingTransport,
} from '../types'

// ---------------------------------------------------------------------------
// Qiling - the CPU-emulation harness and its root filesystem. Qiling only.
//
// ClamAV used to live here as a fourth tab. It was moved to its own panel
// because it is a different concern with a different failure mode: clamd is a
// guest daemon answering on a unix socket inside the VM, while Qiling is a
// systemd `oneshot` started per sample. Stacking them implied they were peers.
//
// Three behaviours below are load-bearing and come from the actual scripts,
// not from taste:
//
//  * Generate rootfs runs dll_collector.bat, which gates on `NET SESSIONS`
//    (line 11) and exits 1 if it is not elevated. qiling_setup.py drives it
//    through Start-Process -Verb RunAs, so a Windows UAC prompt WILL appear
//    and the browser cannot see it. The action says so rather than pretending
//    to be a plain button.
//
//  * That batch file ends `EXIT /B 0` (line 160) and never checks the result
//    of REG SAVE, XCOPY or COPY, so its exit code proves nothing.
//    qiling_setup.py re-validates the tree afterwards for that reason. The UI
//    models the action as collect -> validate, not "done".
//
//  * The rootfs is ~111 MB and gets uploaded to the VM, so this is a long job,
//    not a click. Hence the job state and the polled console, not a spinner.
//
// Everything on this page is read from what the harness already produced: run
// bundles in qiling_dlls/results/ and the service log. Submission is the one
// action: it uploads a sample and runs the harness on the VM over the transport
// recorded in config/dynamic_analysis.json, then the same run-bundle reader
// shows the result. The panel spawns the existing CLI or utility client; it
// does not reimplement either path.
// ---------------------------------------------------------------------------

// 10s: the service log is a file on disk that only changes when a run happens,
// and each run is ~20s of emulation, so polling faster just re-reads the tail.
const INTERVAL = 10000

// Submission. The choice itself lives in config/dynamic_analysis.json (the
// Dynamic Analysis > Configuration page); this page reads it back and never
// offers a second switch that could disagree with the one ClamAV uses.
const TRANSPORT_LABEL: Record<'sftp' | 'tcp', string> = {
  sftp: 'SFTP — analysis VM',
  tcp: 'TCP socket — VM utility',
}

const TRANSPORT_CLIENT: Record<'sftp' | 'tcp', string> = {
  sftp: 'admin-terminal/qiling_upload.py',
  tcp: 'panel/utils/vm_utility.py',
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
  artifacts: 'artifacts',
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
function StepStrip({ checks }: { checks: QilingConnectionCheck[] }) {
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

function TransportRow({ transport, selected }: {
  transport: QilingTransport
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

/** Colour a submission log line without fighting the CLI's own ANSI colours. */
function submitLineClass(line: string): string {
  if (/^--- .*FAILED/.test(line)) return 'text-danger'
  if (/^--- .*report ready/.test(line)) return 'text-success'
  if (/^\s{4}\$ /.test(line)) return 'text-accent'
  if (/^\s{4}(transport|socket):/.test(line)) return 'text-default-400'
  return ''
}

// ---------------------------------------------------------------------------
// Run detail helpers.
//
// A run bundle is richer than the old detail card admitted: summary.json also
// carries the API histogram, behaviour tags, IOCs, YARA hits, sample hashes and
// the zip listing. These helpers keep the new detail view readable without
// moving any of that work into the browser twice.
// ---------------------------------------------------------------------------

type RunTone = 'accent' | 'success' | 'warning' | 'danger' | 'muted'

const RUN_TONE: Record<RunTone, {
  text: string
  border: string
  bg: string
  bar: string
}> = {
  accent: { text: 'text-accent', border: 'border-accent/25', bg: 'bg-accent/5', bar: 'bg-accent' },
  success: { text: 'text-success', border: 'border-success/25', bg: 'bg-success/5', bar: 'bg-success' },
  warning: { text: 'text-warning', border: 'border-warning/25', bg: 'bg-warning/5', bar: 'bg-warning' },
  danger: { text: 'text-danger', border: 'border-danger/25', bg: 'bg-danger/5', bar: 'bg-danger' },
  muted: { text: 'text-default-500', border: 'border-default-200', bg: 'bg-default-50', bar: 'bg-default-300' },
}

/** One coloured, labelled number. Used for the summary strip and run metrics. */
function RunMetric({ label, value, hint, tone = 'muted' }: {
  label: string
  value: ReactNode
  hint?: ReactNode
  tone?: RunTone
}) {
  const t = RUN_TONE[tone]
  return (
    <div className={`rounded-lg border px-2.5 py-2 ${t.border} ${t.bg}`}>
      <div className="flex items-baseline justify-between gap-2">
        <span className="truncate text-[10px] uppercase tracking-wide text-default-500">
          {label}
        </span>
        <span className={`shrink-0 font-mono text-xs font-semibold ${t.text}`}>{value}</span>
      </div>
      {hint && (
        <p
          className="mt-0.5 truncate text-[10px] text-default-400"
          title={typeof hint === 'string' ? hint : undefined}
        >
          {hint}
        </p>
      )}
    </div>
  )
}

/** What a trace event says about the sample, mapped onto the palette. */
const TRACE_KIND_TONE: Record<string, RunTone> = {
  fatal: 'danger',
  error: 'danger',
  yara: 'danger',
  inject: 'danger',
  hollow: 'danger',
  persist: 'danger',
  crypto: 'danger',
  load: 'danger',
  evade: 'warning',
  antivm: 'warning',
  timing: 'warning',
  wait: 'warning',
  peb: 'warning',
  net: 'accent',
  ioc: 'accent',
  exec: 'accent',
  file: 'accent',
  dump: 'success',
  start: 'success',
  end: 'success',
  report: 'success',
  summary: 'success',
  discover: 'muted',
  setup: 'muted',
  stub: 'muted',
  sweep: 'muted',
}

const TRACE_LINE = /^\[\s*([\d.]+)\]\s+\[([^\]]+)\]\s?(.*)$/

function traceTone(line: string): RunTone | null {
  const match = TRACE_LINE.exec(line)
  if (!match) return null
  return TRACE_KIND_TONE[match[2].toLowerCase()] ?? 'muted'
}

/** The row rail marks danger/warning events so they are visible when scanning. */
function traceLineClass(line: string): string {
  const tone = traceTone(line)
  return tone === 'danger' || tone === 'warning' ? 'is-notable' : ''
}

/** Timestamp, event class and message rendered as three distinct colours. */
function renderTraceLine(line: string): ReactNode {
  const match = TRACE_LINE.exec(line)
  if (!match) return line
  const [, elapsed, kind, message] = match
  const tone = TRACE_KIND_TONE[kind.toLowerCase()] ?? 'muted'
  const t = RUN_TONE[tone]
  return (
    <span className="flex min-w-0 items-baseline gap-2">
      <span className="shrink-0 font-mono text-[10px] tabular-nums text-default-400">
        {Number(elapsed).toFixed(3)}s
      </span>
      <span className={`shrink-0 rounded px-1 font-mono text-[9px] uppercase tracking-wide ${t.bg} ${t.text}`}>
        {kind}
      </span>
      <span className="min-w-0 break-all">{message || ' '}</span>
    </span>
  )
}

/** Network indicators get their own colour so a hostname is not a file path. */
function iocTone(ioc: string): RunTone {
  if (/^https?:\/\//i.test(ioc)) return 'danger'
  if (/^\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?$/.test(ioc)) return 'warning'
  if (/^[a-z0-9-]+(?:\.[a-z0-9-]+)+(?::\d+)?$/i.test(ioc)) return 'warning'
  return 'accent'
}

function displayValue(value: unknown): string {
  if (typeof value === 'string') return value
  try {
    return JSON.stringify(value)
  } catch {
    return String(value)
  }
}

function runEndTone(run: QilingRun): RunTone {
  if (!run.ok) return 'danger'
  if (run.end === 'completed') return 'success'
  return run.end ? 'warning' : 'muted'
}

// Live CPU / RAM / disk, read from inside the running VM.
function GuestResources({
  metrics,
  onOpenProfiler,
}: {
  metrics: QilingGuestMetrics | null
  onOpenProfiler: () => void
}) {
  const memoryPercent = metrics?.memory.percent
  const diskPercent = metrics?.disk.percent
  const meters = [
    {
      label: 'Memory',
      value: metrics?.memory.used_bytes,
      total: metrics?.memory.total_bytes,
      percent: memoryPercent,
    },
    {
      label: 'Disk',
      value: metrics?.disk.used_bytes,
      total: metrics?.disk.total_bytes,
      percent: diskPercent,
    },
  ]

  return (
    <Card className="mt-4 w-full">
      <Card.Header className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <Card.Title className="text-sm font-semibold">Qiling VM resources</Card.Title>
          <p className="mt-0.5 text-[11px] text-default-500">
            Live guest metrics · separate from the Windows analyzer process
          </p>
        </div>
      </Card.Header>
      <Card.Content>
        {metrics?.available ? (
          <div className="grid gap-4 sm:grid-cols-2">
            {meters.map((meter) => (
              <div key={meter.label}>
                <div className="mb-1.5 flex items-center justify-between gap-2 text-xs">
                  <span className="text-default-600">{meter.label}</span>
                  <span className="font-mono text-default-500">
                    {bytes(meter.value, 0)} / {bytes(meter.total, 0)}
                    {meter.percent !== null && meter.percent !== undefined
                      ? ` · ${Math.round(meter.percent)}%` : ''}
                  </span>
                </div>
                <div
                  className="h-2 overflow-hidden rounded-full bg-default-200"
                  role="meter"
                  aria-label={`Qiling guest ${meter.label.toLowerCase()} usage`}
                  aria-valuemin={0}
                  aria-valuemax={100}
                  aria-valuenow={meter.percent ?? 0}
                >
                  <div
                    className="h-full rounded-full bg-accent transition-[width]"
                    style={{ width: `${Math.min(100, Math.max(0, meter.percent ?? 0))}%` }}
                  />
                </div>
              </div>
            ))}
            <div className="flex items-center justify-between text-xs sm:col-span-2">
              <span className="text-default-600">System load · {metrics.cores ?? '—'} cores</span>
              <span className="font-mono text-default-500">
                {metrics.load['1'] !== null ? metrics.load['1'].toFixed(2) : '—'}
                {' / '}
                {metrics.load['5'] !== null ? metrics.load['5'].toFixed(2) : '—'}
                {' / '}
                {metrics.load['15'] !== null ? metrics.load['15'].toFixed(2) : '—'}
                {' · 1 / 5 / 15 min'}
              </span>
            </div>
          </div>
        ) : (
          <p className="text-xs text-default-500">
            {metrics?.error || 'Guest metrics are not available yet. The VM must be running and reachable.'}
          </p>
        )}
        <div className="mt-3 flex flex-wrap items-center justify-between gap-2 border-t border-default-100 pt-2">
          <p className="text-[10px] text-default-400">
            VMMap captures the Windows analyzer/sample on the panel host, not this guest.
          </p>
          <Button size="sm" variant="ghost" onPress={onOpenProfiler}>
            Windows process profiler
          </Button>
        </div>
      </Card.Content>
    </Card>
  )
}

export default function QilingVM({
  onOpenProfiler,
  onNavigate,
}: {
  onOpenProfiler: () => void
  onNavigate?: (panel: string) => void
}) {
  const { data, error, loading, refresh } = usePoll(api.qilingRuns, INTERVAL)
  const { data: guestMetrics, refresh: refreshGuestMetrics } =
    usePoll(api.qilingVmMetrics, 15000)
  const [selected, setSelected] = useState<string | null>(null)
  // Rootfs generation is on-demand, not auto-polled: each build pops a UAC
  // prompt, so it fires only when clicked. Once it is running the job is
  // polled so the phase lines and collector output arrive in the console.
  const [rootfsJob, setRootfsJob] = useState<QilingRootfsJob | null>(null)
  const [rootfsBusy, setRootfsBusy] = useState(false)
  // Keep the overview, submission form and saved runs in separate screens so
  // the primary VM state stays visible without a second service-log view.
  const [tab, setTab] = useState<'overview' | 'submit' | 'runs'>('overview')

  // Submission. The transport and its availability are read from the backend,
  // which reads config/dynamic_analysis.json - the same file the Dynamic
  // Analysis page writes. The job is polled through the shared build endpoint.
  const [submitInfo, setSubmitInfo] = useState<QilingSubmitInfo | null>(null)
  const [submitError, setSubmitError] = useState<string | null>(null)
  const [job, setJob] = useState<QilingSubmitJob | null>(null)
  const [file, setFile] = useState<File | null>(null)
  const [starting, setStarting] = useState(false)
  const [notice, setNotice] = useState<{ tone: 'ok' | 'bad'; text: string } | null>(null)
  const fileRef = useRef<HTMLInputElement>(null)

  // The connection test runs on demand as well as on mount, so the newest
  // answer can come from either. The ping is its own request: it asks the
  // guest over the VM utility socket, not the 10-second status poll.
  const [checking, setChecking] = useState(false)
  const [ping, setPing] = useState<QilingPing | null>(null)
  const [pinging, setPinging] = useState(false)
  const [pingError, setPingError] = useState<string | null>(null)

  const runs = data?.runs ?? []
  const active = runs.find((r) => r.file === selected) ?? runs[0] ?? null
  const completedRuns = runs.filter((r) => r.ok && r.end === 'completed').length
  const flaggedRuns = runs.filter((r) => !r.ok || (r.end && r.end !== 'completed')).length
  const totalIocs = runs.reduce((sum, r) => sum + r.ioc_count, 0)
  const apiEntries = active
    ? Object.entries(active.api_counts).sort((a, b) => Number(b[1]) - Number(a[1]))
    : []
  const apiMax = apiEntries.length ? Math.max(1, Number(apiEntries[0][1])) : 1
  const communication = submitInfo?.communication
  const chosen: 'sftp' | 'tcp' = communication?.mode ?? 'tcp'
  const chosenTransport = submitInfo?.transports?.[chosen]
  const submitReady = submitInfo?.ready ?? false
  const checks = submitInfo?.checks ?? []
  const passed = checks.filter((c) => c.ok).length
  const running = job?.state === 'running'
  const finished = job && job.state !== 'running' ? job : null
  // The Qiling harness is a systemd oneshot: "inactive" between runs is its
  // normal resting state, not a failure. Only call it down when the guest
  // answers with a state that is not just idle.
  const pingIdle = !!ping && ping.ok && !ping.alive
    && (ping.state === 'inactive' || ping.state === 'dead')

  const loadSubmit = async () => {
    try {
      const info = await api.qilingSubmitInfo()
      setSubmitInfo(info)
      setSubmitError(info.error ?? null)
      if (info.current) setJob(info.current)
    } catch (e) {
      setSubmitError(e instanceof Error ? e.message : String(e))
    }
  }

  // The explicit connection test: re-read the same endpoint the mount uses and
  // keep its answer even if the next refresh is seconds away.
  const runConnectionCheck = async () => {
    setChecking(true)
    try {
      await loadSubmit()
    } finally {
      setChecking(false)
    }
  }

  // Ask the guest directly, through the VM utility server - not the harness's
  // own socket - so this works whichever submission transport is selected.
  const runPing = async () => {
    setPinging(true)
    setPingError(null)
    try {
      setPing(await api.qilingPing())
    } catch (e) {
      setPing(null)
      setPingError(e instanceof Error ? e.message : String(e))
    } finally {
      setPinging(false)
    }
  }

  // One control for the whole page: runs, guest metrics and the connection
  // test. The individual cards no longer carry their own Refresh.
  const refreshAll = () => {
    refresh()
    refreshGuestMetrics()
    void runConnectionCheck()
  }

  const generateRootfs = async () => {
    setRootfsBusy(true)
    try {
      setRootfsJob(await api.qilingGenerateRootfs())
    } catch (e) {
      setRootfsJob({
        job_id: '',
        state: 'error',
        already_running: false,
        detail: e instanceof Error ? e.message : String(e),
        output: [],
      })
    } finally {
      setRootfsBusy(false)
    }
  }

  const submit = async () => {
    if (!file) return
    setStarting(true)
    setNotice(null)
    try {
      const res = await api.qilingSubmit(file)
      if (!res.ok || !res.job_id) {
        setNotice({ tone: 'bad', text: res.error ?? 'the submission was refused' })
        return
      }
      setJob(await api.qilingJob(res.job_id))
      setFile(null)
      if (fileRef.current) fileRef.current.value = ''
    } catch (e) {
      setNotice({ tone: 'bad', text: e instanceof Error ? e.message : String(e) })
    } finally {
      setStarting(false)
    }
  }

  // Read the run state and the submission transport once on mount so the page
  // is populated on first paint. The buttons re-run them.
  useEffect(() => {
    void loadSubmit()
    // A build outlives a page reload because it runs on the panel's worker
    // thread; reattach instead of showing an idle Build button over a live
    // collector and its UAC prompt.
    void (async () => {
      try {
        const active = await api.qilingActiveRootfs()
        if (active.job) setRootfsJob(active.job)
      } catch {
        // No active build, or the panel restarted: nothing to reattach.
      }
    })()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  // Poll only while a run is live; the interval stops the moment it finishes.
  useEffect(() => {
    if (!running || !job) return
    const id = window.setInterval(async () => {
      try {
        const next = await api.qilingJob(job.id)
        setJob(next)
        if (next.state !== 'running') {
          refresh()
          void loadSubmit()
        }
      } catch {
        // A dropped poll is not a failure; the next tick tries again.
      }
    }, 1200)
    return () => window.clearInterval(id)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [running, job?.id, refresh])

  // The rootfs build runs on a worker thread; its phases and the elevated
  // collector's log only advance while this poll is live. Stop the moment the
  // job leaves queued/running.
  const rootfsLive = rootfsJob?.state === 'queued' || rootfsJob?.state === 'running'
  useEffect(() => {
    if (!rootfsLive || !rootfsJob?.job_id) return
    const id = window.setInterval(async () => {
      try {
        const next = await api.qilingRootfsJob(rootfsJob.job_id)
        setRootfsJob(next)
        if (next.state !== 'queued' && next.state !== 'running') refresh()
      } catch {
        // Keep the last phase on screen; the next tick retries.
      }
    }, 1200)
    return () => window.clearInterval(id)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [rootfsLive, rootfsJob?.job_id, refresh])

  if (loading && !data) {
    return (
      <Loading
        label="Loading Qiling state…"
        hint="reading saved run bundles and VM status"
      />
    )
  }

  return (
    <>
      <ToolHero
        eyebrow="DYNAMIC ANALYSIS · GUEST ON THE QILING VM"
        title="Qiling"
        lead="Emulate Windows samples inside the analysis VM and read back hashes, behaviour, IOCs, YARA hits and a colour-coded trace."
        tone={!submitInfo ? 'idle' : communication?.error ? 'bad' : submitReady ? 'ok' : 'warn'}
        state={!submitInfo ? 'Checking…' : communication?.error ? 'Config unreadable' : submitReady ? 'Ready' : 'Not ready'}
        facts={[
          { label: 'Endpoint', value: submitInfo?.endpoint || 'probing…', mono: true },
          { label: 'Harness', value: data?.harness.present ? `v${data.harness.version}` : '—', mono: true },
          { label: 'Transport', value: chosen === 'sftp' ? 'SFTP' : 'TCP' },
          { label: 'Checks', value: checks.length ? `${passed}/${checks.length} passed` : '—' },
          { label: 'Rootfs', value: data ? (data.rootfs.complete ? 'complete' : 'incomplete') : '—' },
        ]}
        actions={(
          <>
          <Button
            size="sm"
            variant="outline"
            onPress={refreshAll}
            isDisabled={checking}
          >
            {checking ? 'Checking…' : 'Refresh'}
          </Button>
          <Button
            size="sm"
            variant={tab === 'submit' ? 'primary' : 'outline'}
            onPress={() => setTab('submit')}
          >
            Submit sample
          </Button>
          <Button
            size="sm"
            variant="primary"
            onPress={generateRootfs}
            isDisabled={rootfsBusy || rootfsLive}
          >
            {rootfsBusy ? 'Starting…' : rootfsLive ? 'Building…' : 'Build rootfs'}
          </Button>
          </>
        )}
      />

      {rootfsJob && (
        <>
          <Alert
            status={
              rootfsJob.state === 'error'
                ? 'danger'
                : rootfsJob.state === 'done'
                  ? 'success'
                  : 'accent'
            }
            className="mb-3"
          >
            <Alert.Title>
              Rootfs build {rootfsJob.state === 'done' ? 'complete' : rootfsJob.state}
              {rootfsJob.job_id && (
                <span className="ml-2 font-mono text-xs font-normal">job {rootfsJob.job_id}</span>
              )}
            </Alert.Title>
            <Alert.Description>
              {rootfsJob.detail ||
                (rootfsLive
                  ? 'Building the x86 + x64 rootfs. A Windows UAC prompt appears on the machine running the panel - accept it there; the browser cannot show that prompt. The collector log is below.'
                  : 'The build job has no detail to report.')}
            </Alert.Description>
          </Alert>
          <Console
            title="Rootfs build output"
            subtitle={rootfsJob.job_id ? `job ${rootfsJob.job_id}` : undefined}
            status={{
              label: rootfsJob.state,
              tone:
                rootfsJob.state === 'error'
                  ? 'danger'
                  : rootfsJob.state === 'done'
                    ? 'success'
                    : rootfsLive
                      ? 'accent'
                      : 'default',
            }}
            lines={rootfsJob.output ?? []}
            live={rootfsLive}
            truncated={rootfsJob.dropped ?? 0}
            size="tall"
            empty={
              rootfsLive
                ? 'Waiting for the build worker…'
                : 'No output was recorded for this job.'
            }
            ariaLabel="Rootfs build output"
            className="mb-4"
          />
        </>
      )}

      {error && (
        <Alert status="danger" className="mb-4">
          <Alert.Title>Cannot read Qiling state</Alert.Title>
          <Alert.Description>{error}</Alert.Description>
        </Alert>
      )}

      {data && !data.rootfs.complete && (
        <Alert status="warning" className="mb-4">
          <Alert.Title>Root filesystem incomplete</Alert.Title>
          <Alert.Description>
            Both x86 and x64 trees are required. Use <b>Build rootfs</b> above;
            Windows may show a UAC prompt on the machine running the panel.
            The browser cannot display that prompt.
          </Alert.Description>
        </Alert>
      )}

      <SubNav
        tabs={[
          { id: 'overview', label: 'Overview', icon: 'qiling' },
          { id: 'submit', label: 'Submit sample', icon: 'play' },
          {
            id: 'runs', label: 'Runs', icon: 'artifacts',
            tone: runs.some((r) => !r.ok) ? 'warn' : undefined,
          },
        ]}
        active={tab}
        onChange={(id) => setTab(id as 'overview' | 'submit' | 'runs')}
      />

      {/* --- overview: connection test, VM health, resources and rootfs ----- */}
      {tab === 'overview' && (
        <>
          <div className="tool-grid">
            <div className="tool-col">
            <Card className="w-full">
              <Card.Header className="flex flex-row items-center justify-between gap-2">
                <Card.Title className="text-sm font-semibold">Connection</Card.Title>
                <Chip
                  size="sm"
                  variant="soft"
                  color={communication?.error ? 'danger' : submitReady ? 'success' : 'warning'}
                >
                  {communication?.error ? 'config unreadable' : submitReady ? 'ready' : 'not ready'}
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
                      <Button
                        size="sm"
                        variant="ghost"
                        onPress={() => onNavigate('dynamic-analysis')}
                      >
                        Change…
                      </Button>
                    )}
                  </span>
                </div>
                <Fact label="Configured in" title={communication?.path}>
                  {communication?.path ?? 'config/dynamic_analysis.json'}
                </Fact>
                <Fact label="Qiling mode">{submitInfo?.mode ?? '—'}</Fact>
                <Fact label="VM">
                  {submitInfo?.vm?.host
                    ? `${submitInfo.vm.host}@${submitInfo.vm.ip}:${submitInfo.vm.port}`
                    : 'not configured'}
                </Fact>
                <div className="mt-2 border-t border-default-100 pt-2">
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-[11px] text-default-500">Service ping</span>
                    <span className="flex min-w-0 items-center gap-2">
                      {ping ? (
                        <Chip
                          size="sm"
                          variant="soft"
                          color={!ping.ok ? 'warning' : ping.alive ? 'success' : pingIdle ? 'default' : 'danger'}
                        >
                          {!ping.ok ? 'no answer' : ping.alive ? 'active' : pingIdle ? 'idle' : 'down'}
                        </Chip>
                      ) : (
                        <span className="text-[10px] text-default-400">
                          {pinging ? 'pinging…' : 'not checked'}
                        </span>
                      )}
                    </span>
                  </div>
                  {ping && (
                    <div className="mt-1 flex flex-col gap-0.5">
                      <span
                        className={`break-words font-mono text-[10px] ${
                          ping.ok && ping.alive ? 'text-success'
                            : pingIdle ? 'text-default-400'
                              : ping.ok ? 'text-danger' : 'text-warning'
                        }`}
                        title={ping.detail}
                      >
                        {ping.detail}
                      </span>
                      <span
                        className="font-mono text-[10px] text-default-400"
                        title={ping.response ? JSON.stringify(ping.response) : undefined}
                      >
                        {ping.endpoint} · {ping.seconds}s
                        {ping.state ? ` · ${ping.state}` : ''}
                        {' · '}{ago(ping.checked_at)}
                      </span>
                    </div>
                  )}
                  {pingError && (
                    <p className="mt-1 break-words text-[10px] text-danger">{pingError}</p>
                  )}
                </div>
                {submitInfo?.note && (
                  <p className="mt-2 border-t border-default-100 pt-2 text-[10px] leading-relaxed text-default-400">
                    {submitInfo.note}
                  </p>
                )}
              </Card.Content>
            </Card>

            {submitInfo?.transports && (
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
                  <TransportRow
                    transport={submitInfo.transports.sftp}
                    selected={chosen === 'sftp'}
                  />
                  <TransportRow
                    transport={submitInfo.transports.tcp}
                    selected={chosen === 'tcp'}
                  />
                </Card.Content>
              </Card>
            )}
            </div>
            <div className="tool-col">
            <Card className="w-full">
              <Card.Header className="flex flex-row items-center justify-between gap-2">
                <Card.Title className="text-sm font-semibold">
                  {chosen === 'sftp' ? 'SFTP checks' : 'TCP checks'}
                  <span className="ml-2 text-[10px] font-normal text-default-400">
                    {chosen === 'sftp' ? 'admin-terminal/ driver files' : 'socket client + connect'}
                  </span>
                </Card.Title>
                <span className="flex items-center gap-2">
                  <StepStrip checks={checks} />
                  <span className="font-mono text-[10px] text-default-400">
                    {passed}/{checks.length} ok
                  </span>
                </span>
              </Card.Header>
              <Card.Content className="flex flex-col">
                {checks.length === 0 ? (
                  <p className="py-4 text-center text-[11px] text-default-400">
                    No checks recorded - press Run check.
                  </p>
                ) : checks.map((c, i) => (
                  <CheckStep
                    key={`${c.name}-${i}`}
                    index={i + 1}
                    total={checks.length}
                    name={c.name}
                    ok={c.ok}
                    detail={c.detail}
                    advisory={c.advisory}
                    icon={c.icon}
                  />
                ))}
              </Card.Content>
            </Card>

            <Console
              title="Connection test"
              subtitle={chosen === 'sftp'
                ? 'file checks only · no SSH session is opened'
                : 'socket_validator.py · connect check · health is the ping'}
              status={{
                label: submitReady ? 'ready' : 'not ready',
                tone: communication?.error ? 'danger' : submitReady ? 'success' : 'warning',
              }}
              meta={submitInfo?.checked_at
                ? `${passed}/${checks.length} steps · ${new Date(submitInfo.checked_at * 1000).toLocaleTimeString()}`
                : `${passed}/${checks.length} steps`}
              actions={(
                <span className="flex items-center gap-2">
                  <Button
                    size="sm"
                    variant="outline"
                    isDisabled={pinging}
                    onPress={() => void runPing()}
                  >
                    <Icon name="activity" size={12} />
                    {pinging ? 'Pinging…' : 'Ping service'}
                  </Button>
                  <Button
                    size="sm"
                    variant="outline"
                    isDisabled={checking}
                    onPress={() => void runConnectionCheck()}
                  >
                    <Icon name="play" size={12} />
                    {checking ? 'Checking…' : 'Run check'}
                  </Button>
                </span>
              )}
              lines={submitInfo?.output ?? []}
              lineClass={statusLineClass}
              ariaLabel="Qiling connection test output"
              empty="No output recorded - press Run check."
            />
            </div>
          </div>

          <GuestResources
            metrics={guestMetrics}
            onOpenProfiler={onOpenProfiler}
          />

          <div className="mb-2 mt-6 flex items-center justify-between gap-3">
            <div>
              <p className="section-label">Environment</p>
              <p className="mt-0.5 text-[11px] text-default-400">
                Root filesystem, harness and service inside the guest
              </p>
            </div>
            {data && (
              <span className="font-mono text-[10px] text-default-400">
                read {ago(data.checked_at)}
              </span>
            )}
          </div>

          {data ? (
            <Card className="w-full">
              <Card.Header className="flex flex-wrap items-center justify-between gap-3">
                <div>
                  <Card.Title className="text-sm font-semibold">Guest readiness</Card.Title>
                  <p className="mt-0.5 text-[10px] text-default-400">
                    {data.present
                      ? `${data.file_count} run bundle${data.file_count === 1 ? '' : 's'} in ${data.path}`
                      : `no results directory at ${data.path}`}
                  </p>
                </div>
                <Chip size="sm" variant="soft" color={data.rootfs.complete && data.harness.present ? 'success' : 'warning'}>
                  {data.rootfs.complete && data.harness.present ? 'ready' : 'incomplete'}
                </Chip>
              </Card.Header>
              <Card.Content className="grid grid-cols-1 gap-5 lg:grid-cols-2">
                <section className="flex min-w-0 flex-col gap-2">
                  <div className="flex items-center justify-between gap-3">
                    <span className="text-xs font-medium">Root filesystem</span>
                    <span className="font-mono text-[10px] text-default-500">
                      archive {bytes(data.rootfs.archive_bytes, 0)}
                    </span>
                  </div>
                  <p
                    className="truncate font-mono text-[10px] text-default-400"
                    title={data.rootfs.archive}
                  >
                    {data.rootfs.archive ?? 'qiling_dlls/rootfs.tar.gz'}
                    {data.rootfs.archive_present ? '' : ' · missing'}
                  </p>
                  <div className="flex flex-col gap-1.5">
                    {data.rootfs.trees.map((tree) => (
                      <div
                        key={tree.arch}
                        className="rounded-lg border border-default-100 bg-default-50/70 px-3 py-2"
                      >
                        <div className="flex items-center justify-between gap-3">
                          <span className="flex min-w-0 items-center gap-2">
                            <Icon
                              name={tree.complete ? 'check' : 'alert-circle'}
                              size={12}
                              className={tree.complete ? 'text-success' : 'text-warning'}
                            />
                            <span className="truncate font-mono text-[11px]">{tree.arch}</span>
                          </span>
                          <span className={`shrink-0 text-[10px] ${tree.complete ? 'text-success' : 'text-warning'}`}>
                            {tree.complete ? 'complete' : 'missing'}
                          </span>
                        </div>
                        <div className="mt-1 flex items-center justify-between gap-3">
                          <span
                            className="truncate font-mono text-[10px] text-default-400"
                            title={tree.path}
                          >
                            {tree.path ?? `${tree.arch}/Windows`}
                          </span>
                          <span className="shrink-0 font-mono text-[10px] text-default-500">
                            {tree.files} files
                            {tree.bytes !== undefined ? ` · ${bytes(tree.bytes, 0)}` : ''}
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>
                </section>

                <section className="flex min-w-0 flex-col">
                  <span className="mb-1 text-xs font-medium">Harness and service</span>
                  <Fact label="Harness" title={data.harness.path}>
                    {data.harness.present ? 'deployed' : 'not found'}
                  </Fact>
                  <Fact label="Version" title={data.harness.version}>
                    {data.harness.version || '—'}
                  </Fact>
                  <Fact label="Harness path" title={data.harness.path}>
                    {data.harness.path}
                  </Fact>
                  <Fact label="Guest service" title={data.harness.service}>
                    {data.harness.service}
                  </Fact>
                  <Fact label="Service type" title={data.harness.service_type}>
                    {data.harness.service_type || '—'}
                  </Fact>
                  <Fact label="Results" title={data.path}>
                    {data.present ? `${data.file_count} bundles` : 'none'}
                  </Fact>
                </section>
              </Card.Content>
            </Card>
          ) : (
            <Card className="w-full">
              <Card.Content className="flex min-h-32 flex-col items-center justify-center gap-2 text-center">
                <Icon name="qiling" size={19} className="text-default-400" />
                <p className="text-xs font-medium">Guest readiness has not been read</p>
                <p className="max-w-sm text-[11px] text-default-400">
                  The rootfs and harness state are read on load. Use Refresh to try again.
                </p>
              </Card.Content>
            </Card>
          )}

        </>
      )}

      {/* --- submit: the form on the left, the live log on the right -------- */}
      {tab === 'submit' && (
        <div className="grid grid-cols-1 gap-3 xl:grid-cols-[minmax(0,23rem)_minmax(0,1fr)]">
          <Card className="w-full self-start">
            <Card.Header className="flex flex-row items-center justify-between gap-2">
              <Card.Title className="text-sm font-semibold">Submit sample</Card.Title>
              {chosenTransport && (
                <Chip
                  size="sm"
                  variant="soft"
                  color={chosenTransport.available ? 'success' : 'warning'}
                >
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
                    <span
                      className="truncate font-mono text-[10px] text-default-400"
                      title={communication?.path}
                    >
                      {TRANSPORT_CLIENT[chosen]}
                    </span>
                  </span>
                </span>
                {onNavigate && (
                  <Button size="sm" variant="ghost" onPress={() => onNavigate('dynamic-analysis')}>
                    change
                  </Button>
                )}
              </div>

              {communication?.error && (
                <Alert status="danger">
                  <Alert.Title>Cannot read the transport choice</Alert.Title>
                  <Alert.Description>
                    <code className="font-mono">{communication.path}</code>: {communication.error}.
                    Submission stays disabled until that file is valid.
                  </Alert.Description>
                </Alert>
              )}

              {submitError && !communication?.error && (
                <Alert status="danger">
                  <Alert.Title>Cannot read submission state</Alert.Title>
                  <Alert.Description>{submitError}</Alert.Description>
                </Alert>
              )}

              {submitInfo?.transports && (
                <div className="rounded-md border border-default-100 px-2">
                  <TransportRow
                    transport={submitInfo.transports.sftp}
                    selected={chosen === 'sftp'}
                  />
                  <TransportRow
                    transport={submitInfo.transports.tcp}
                    selected={chosen === 'tcp'}
                  />
                </div>
              )}

              <div className="flex flex-wrap items-center gap-2">
                <button
                  type="button"
                  className="build-btn is-secondary"
                  disabled={starting || running}
                  onClick={() => fileRef.current?.click()}
                  title="A Windows PE up to 25 MiB"
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
                disabled={
                  !file || starting || running || !submitReady || !!communication?.error
                }
                onClick={() => void submit()}
                title={
                  !file
                    ? 'Choose a sample first'
                    : chosenTransport?.reason ?? 'Upload and run with Qiling'
                }
              >
                <Icon name="play" size={12} />
                {running ? 'Emulating…' : starting ? 'Submitting…' : 'Submit and emulate'}
              </button>

              <p className="text-[10px] leading-relaxed text-default-400">
                {chosenTransport ? `${chosenTransport.detail}. ` : ''}
                Limit 25 MiB; the report zip is written to
                <code className="font-mono"> qiling_dlls/results/</code> and appears in Runs.
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
                    color={finished.results[0].state === 'passed' ? 'success' : 'danger'}
                  >
                    {finished.results[0].state}
                  </Chip>
                  <span
                    className="min-w-0 truncate font-mono text-[10px] text-default-400"
                    title={finished.results[0].detail ?? ''}
                  >
                    {finished.results[0].detail ?? '—'}
                  </span>
                </div>
              )}
            </Card.Content>
          </Card>

          <Console
            className="self-start"
            title="Submission log"
            icon="terminal"
            subtitle={
              job
                ? `${job.mode ?? chosen} · ${TRANSPORT_CLIENT[(job.mode ?? chosen) as 'sftp' | 'tcp']}`
                : TRANSPORT_CLIENT[chosen]
            }
            status={
              job?.summary
                ? {
                    label: job.summary,
                    tone:
                      job.state === 'running'
                        ? 'accent'
                        : job.state === 'passed'
                          ? 'success'
                          : 'danger',
                  }
                : job
                  ? { label: job.state, tone: job.state === 'running' ? 'accent' : 'warning' }
                  : undefined
            }
            meta={
              job
                ? `${job.log_line_count} line${job.log_line_count === 1 ? '' : 's'}` +
                  (job.exit_code !== null ? ` · exit ${job.exit_code}` : '')
                : undefined
            }
            lines={job?.log ?? []}
            lineClass={submitLineClass}
            truncated={job?.log_truncated ?? 0}
            live={running}
            numbered
            size="tall"
            ariaLabel="Qiling submission output"
            empty={
              job
                ? 'Waiting for the first line…'
                : 'Nothing has been submitted this session. The uploader and the harness print here.'
            }
          />
        </div>
      )}

      {/* --- run list + per-run detail -------------------------------------- */}
      {tab === 'runs' && data && runs.length > 0 && (
        <>
          <div className="mb-3 grid grid-cols-2 gap-2 sm:grid-cols-4">
            <RunMetric
              label="Bundles"
              value={runs.length}
              hint={`${data.file_count} on disk`}
              tone="accent"
            />
            <RunMetric
              label="Completed"
              value={completedRuns}
              hint="clean exit"
              tone={completedRuns === runs.length ? 'success' : 'muted'}
            />
            <RunMetric
              label="Flagged"
              value={flaggedRuns}
              hint="errors or non-clean exits"
              tone={flaggedRuns ? 'danger' : 'muted'}
            />
            <RunMetric
              label="IOC hits"
              value={totalIocs}
              hint="across listed bundles"
              tone={totalIocs ? 'warning' : 'muted'}
            />
          </div>

          <div className="grid grid-cols-1 gap-3 xl:grid-cols-[320px_1fr]">
            <Card className="w-full self-start">
              <Card.Header className="flex flex-row items-center justify-between gap-2">
                <div>
                  <Card.Title className="text-sm font-semibold">Run bundles</Card.Title>
                  <p className="mt-0.5 text-[10px] text-default-400">newest first</p>
                </div>
                <Chip size="sm" variant="soft" color="accent">{runs.length}</Chip>
              </Card.Header>
              <Card.Content className="flex max-h-[68vh] flex-col gap-1.5 overflow-y-auto pr-1">
                {runs.map((r) => {
                  const tone = RUN_TONE[runEndTone(r)]
                  const isActive = active?.file === r.file
                  return (
                    <button
                      key={r.file}
                      onClick={() => setSelected(r.file)}
                      className={`flex flex-col gap-1 rounded-lg border px-3 py-2 text-left transition-colors ${
                        isActive
                          ? 'border-accent bg-accent/5'
                          : 'border-default-200 hover:border-default-300 hover:bg-default-50'
                      }`}
                    >
                      <span className="flex items-center justify-between gap-2">
                        <span className="flex min-w-0 items-center gap-2">
                          <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${tone.bar}`} />
                          <span className="truncate font-mono text-[11px]">
                            {r.sample || r.stem}
                          </span>
                        </span>
                        <span className={`shrink-0 font-mono text-[9px] uppercase tracking-wide ${tone.text}`}>
                          {r.ok ? (r.end || 'ok') : 'error'}
                        </span>
                      </span>
                      <span className="flex items-center justify-between gap-2 pl-3.5 font-mono text-[10px] text-default-400">
                        <span>{r.arch || '?'} · {r.elapsed_s ? `${r.elapsed_s.toFixed(1)}s` : '—'}</span>
                        <span>{ago(r.modified)}</span>
                      </span>
                      <span className="flex flex-wrap items-center gap-2 pl-3.5 text-[10px]">
                        <span className="text-default-400">{r.events} events</span>
                        <span className={r.ioc_count ? 'text-warning' : 'text-default-400'}>
                          {r.ioc_count} IOCs
                        </span>
                        <span className={r.yara_hits.length ? 'text-danger' : 'text-default-400'}>
                          {r.yara_hits.length} YARA
                        </span>
                      </span>
                    </button>
                  )
                })}
              </Card.Content>
            </Card>

            {active && (
              <div className="flex flex-col gap-3">
                {!active.ok ? (
                  <Alert status="danger">
                    <Alert.Title>Unreadable run bundle</Alert.Title>
                    <Alert.Description>{active.detail}</Alert.Description>
                  </Alert>
                ) : (
                  <>
                    <Card className="w-full">
                      <Card.Header className="flex flex-wrap items-center justify-between gap-3">
                        <div className="min-w-0">
                          <Card.Title className="truncate font-mono text-sm">
                            {active.sample || active.stem}
                          </Card.Title>
                          <p
                            className="mt-0.5 truncate font-mono text-[10px] text-default-400"
                            title={active.file}
                          >
                            {active.stem} · {bytes(active.bytes, 0)} ·{' '}
                            {new Date(active.modified * 1000).toLocaleString()}
                          </p>
                        </div>
                        <div className="flex shrink-0 flex-wrap items-center gap-2">
                          <Chip size="sm" variant="soft" color="accent">
                            {active.arch || 'unknown'}
                          </Chip>
                          <Chip
                            size="sm"
                            variant="soft"
                            color={
                              active.end === 'completed'
                                ? 'success'
                                : active.end
                                  ? 'warning'
                                  : 'default'
                            }
                          >
                            {active.end || 'unknown'}
                          </Chip>
                        </div>
                      </Card.Header>
                      <Card.Content className="grid grid-cols-2 gap-2 md:grid-cols-4">
                        <RunMetric
                          label="Runtime"
                          value={active.elapsed_s ? `${active.elapsed_s.toFixed(2)}s` : '—'}
                          hint="emulated"
                          tone="accent"
                        />
                        <RunMetric
                          label="Events"
                          value={active.events}
                          hint="in events.jsonl"
                          tone="accent"
                        />
                        <RunMetric
                          label="API calls"
                          value={active.api_calls}
                          hint={`${apiEntries.length} unique`}
                          tone="accent"
                        />
                        <RunMetric
                          label="IOCs"
                          value={active.ioc_count}
                          hint="extracted strings"
                          tone={active.ioc_count ? 'warning' : 'muted'}
                        />
                        <RunMetric
                          label="YARA"
                          value={active.yara_hits.length}
                          hint="rule matches"
                          tone={active.yara_hits.length ? 'danger' : 'muted'}
                        />
                        <RunMetric
                          label="Dumps"
                          value={active.dump_count}
                          hint="memory regions"
                          tone={active.dump_count ? 'accent' : 'muted'}
                        />
                        <RunMetric
                          label="Trace"
                          value={active.trace_tail.length}
                          hint="tail lines"
                          tone="muted"
                        />
                        <RunMetric
                          label="Bundle"
                          value={bytes(active.bytes, 0)}
                          hint={`${active.files.length} files`}
                          tone="muted"
                        />
                      </Card.Content>
                    </Card>

                    {Object.keys(active.hashes).length > 0 && (
                      <Card className="w-full">
                        <Card.Header className="flex flex-wrap items-center justify-between gap-2">
                          <Card.Title className="text-sm font-semibold">Sample hashes</Card.Title>
                          <CopyButton
                            text={Object.entries(active.hashes)
                              .map(([name, digest]) => `${name}: ${digest}`)
                              .join('\n')}
                          />
                        </Card.Header>
                        <Card.Content className="grid grid-cols-1 gap-2 sm:grid-cols-3">
                          {Object.entries(active.hashes).map(([name, digest]) => (
                            <div
                              key={name}
                              className="min-w-0 rounded-lg border border-default-200 bg-default-50/70 px-2.5 py-1.5"
                            >
                              <p className="text-[10px] uppercase tracking-wide text-default-500">
                                {name}
                              </p>
                              <p className="break-all font-mono text-[10px]" title={digest}>
                                {digest}
                              </p>
                            </div>
                          ))}
                        </Card.Content>
                      </Card>
                    )}

                    {(Object.keys(active.behaviour_tags).length > 0
                      || Object.keys(active.attack_hints).length > 0) && (
                      <Card className="w-full">
                        <Card.Header className="flex flex-wrap items-center justify-between gap-2">
                          <Card.Title className="text-sm font-semibold">Behaviour</Card.Title>
                          <span className="font-mono text-[10px] text-default-400">
                            {Object.keys(active.behaviour_tags).length} tags
                          </span>
                        </Card.Header>
                        <Card.Content className="flex flex-col">
                          {Object.entries(active.behaviour_tags)
                            .sort((a, b) => Number(b[1]) - Number(a[1]))
                            .map(([tag, count]) => (
                              <div
                                key={tag}
                                className="flex flex-wrap items-center gap-2 border-b border-default-100 py-1.5 last:border-0"
                              >
                                <span className="rounded border border-warning/25 bg-warning/5 px-1.5 py-0.5 font-mono text-[10px] text-warning">
                                  {tag}
                                </span>
                                <span className="font-mono text-[10px] text-default-400">×{count}</span>
                                <span
                                  className="min-w-0 flex-1 truncate text-right text-[10px] text-default-500"
                                  title={active.attack_hints[tag]}
                                >
                                  {active.attack_hints[tag] ?? 'observed behaviour'}
                                </span>
                              </div>
                            ))}
                          {Object.entries(active.attack_hints)
                            .filter(([tag]) => !(tag in active.behaviour_tags))
                            .map(([tag, hint]) => (
                              <div
                                key={tag}
                                className="flex flex-wrap items-center gap-2 border-b border-default-100 py-1.5 last:border-0"
                              >
                                <span className="rounded border border-warning/25 bg-warning/5 px-1.5 py-0.5 font-mono text-[10px] text-warning">
                                  {tag}
                                </span>
                                <span className="min-w-0 flex-1 truncate text-right text-[10px] text-default-500">
                                  {hint}
                                </span>
                              </div>
                            ))}
                        </Card.Content>
                      </Card>
                    )}

                    <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
                      <Card className="w-full">
                        <Card.Header className="flex flex-wrap items-center justify-between gap-2">
                          <Card.Title className="text-sm font-semibold">Indicators</Card.Title>
                          <Chip
                            size="sm"
                            variant="soft"
                            color={active.ioc_count ? 'warning' : 'default'}
                          >
                            {active.ioc_count} IOCs
                          </Chip>
                        </Card.Header>
                        <Card.Content>
                          {active.iocs.length > 0 ? (
                            <>
                              <div className="flex max-h-52 flex-wrap gap-1.5 overflow-y-auto pr-1">
                                {active.iocs.map((ioc, index) => {
                                  const t = RUN_TONE[iocTone(ioc)]
                                  return (
                                    <span
                                      key={`${ioc}-${index}`}
                                      title={ioc}
                                      className={`max-w-full truncate rounded border px-1.5 py-0.5 font-mono text-[10px] ${t.border} ${t.bg} ${t.text}`}
                                    >
                                      {ioc}
                                    </span>
                                  )
                                })}
                              </div>
                              {active.iocs_truncated && (
                                <p className="mt-2 text-[10px] text-default-400">
                                  Showing the first 100; the bundle holds {active.ioc_count}.
                                </p>
                              )}
                            </>
                          ) : (
                            <p className="py-3 text-center text-[11px] text-default-400">
                              No IOC strings were extracted.
                            </p>
                          )}
                        </Card.Content>
                      </Card>

                      <Card className="w-full">
                        <Card.Header className="flex flex-wrap items-center justify-between gap-2">
                          <Card.Title className="text-sm font-semibold">YARA hits</Card.Title>
                          <Chip
                            size="sm"
                            variant="soft"
                            color={active.yara_hits.length ? 'danger' : 'default'}
                          >
                            {active.yara_hits.length}
                          </Chip>
                        </Card.Header>
                        <Card.Content>
                          {active.yara_hits.length > 0 ? (
                            <div className="flex max-h-52 flex-col gap-1 overflow-y-auto pr-1">
                              {active.yara_hits.map((hit, index) => (
                                <div
                                  key={index}
                                  className="flex items-center gap-2 rounded border border-danger/20 bg-danger/5 px-2 py-1"
                                >
                                  <Icon name="alert-circle" size={11} className="text-danger" />
                                  <span className="min-w-0 break-all font-mono text-[10px] text-danger">
                                    {displayValue(hit)}
                                  </span>
                                </div>
                              ))}
                            </div>
                          ) : (
                            <p className="py-3 text-center text-[11px] text-default-400">
                              No YARA rule matched this sample.
                            </p>
                          )}
                        </Card.Content>
                      </Card>
                    </div>

                    <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
                      <Card className="w-full">
                        <Card.Header className="flex flex-wrap items-center justify-between gap-2">
                          <Card.Title className="text-sm font-semibold">API calls</Card.Title>
                          <span className="font-mono text-[10px] text-default-400">
                            {apiEntries.length} unique
                          </span>
                        </Card.Header>
                        <Card.Content className="flex flex-col gap-1.5">
                          {apiEntries.length > 0 ? (
                            <>
                              {apiEntries.slice(0, 12).map(([name, count]) => (
                                <div key={name} className="flex items-center gap-2">
                                  <span
                                    className="w-32 shrink-0 truncate font-mono text-[10px]"
                                    title={name}
                                  >
                                    {name}
                                  </span>
                                  <span className="h-1.5 min-w-0 flex-1 overflow-hidden rounded-full bg-default-200">
                                    <span
                                      className="block h-full rounded-full bg-accent"
                                      style={{ width: `${Math.max(2, (Number(count) / apiMax) * 100)}%` }}
                                    />
                                  </span>
                                  <span className="w-8 shrink-0 text-right font-mono text-[10px] text-default-500">
                                    {count}
                                  </span>
                                </div>
                              ))}
                              {apiEntries.length > 12 && (
                                <p className="pt-1 text-[10px] text-default-400">
                                  … {apiEntries.length - 12} more APIs
                                </p>
                              )}
                            </>
                          ) : (
                            <p className="py-3 text-center text-[11px] text-default-400">
                              No API calls were observed.
                            </p>
                          )}
                        </Card.Content>
                      </Card>

                      <Card className="w-full">
                        <Card.Header className="flex flex-wrap items-center justify-between gap-2">
                          <Card.Title className="text-sm font-semibold">Bundle contents</Card.Title>
                          <span className="font-mono text-[10px] text-default-400">
                            {active.files.length} files
                          </span>
                        </Card.Header>
                        <Card.Content className="flex max-h-56 flex-col overflow-y-auto pr-1">
                          {active.files.slice(0, 12).map((file) => (
                            <div
                              key={file.path}
                              className="flex items-baseline justify-between gap-3 border-b border-default-100 py-1 last:border-0"
                            >
                              <span
                                className="min-w-0 truncate font-mono text-[10px]"
                                title={file.path}
                              >
                                {file.path}
                              </span>
                              <span className="shrink-0 font-mono text-[10px] text-default-400">
                                {bytes(file.bytes, 0)}
                              </span>
                            </div>
                          ))}
                          {active.files.length > 12 && (
                            <p className="pt-1 text-[10px] text-default-400">
                              … {active.files.length - 12} more files
                            </p>
                          )}
                        </Card.Content>
                      </Card>
                    </div>

                    <Console
                      title="Run trace"
                      subtitle="trace.log · timestamp, event class and message"
                      icon="terminal"
                      meta={`${active.trace_tail.length} lines`}
                      lines={active.trace_tail}
                      lineClass={traceLineClass}
                      renderLine={renderTraceLine}
                      numbered
                      copyText={active.trace_tail.join('\n')}
                      size="tall"
                      ariaLabel="Run trace"
                      empty="This bundle has no trace.log."
                    />
                  </>
                )}
              </div>
            )}
          </div>
        </>
      )}

      {tab === 'runs' && data && runs.length === 0 && (
        <Card className="w-full">
          <Card.Content className="flex min-h-36 flex-col items-center justify-center gap-2 text-center">
            <Icon name="artifacts" size={20} className="text-default-400" />
            <p className="text-xs font-medium">No run bundles yet</p>
            <p className="max-w-md text-[11px] leading-relaxed text-default-400">
              The harness writes one zip per sample into{' '}
              <code className="font-mono">qiling_dlls/results</code>. Submit a
              sample above, or use Refresh once a guest run has finished.
            </p>
          </Card.Content>
        </Card>
      )}
    </>
  )
}
