import { useEffect, useState } from 'react'
import { Alert } from '@heroui/react/alert'
import { Button } from '@heroui/react/button'
import { Card } from '@heroui/react/card'
import { Chip } from '@heroui/react/chip'
import Loading from '../components/Loading'
import Icon, { type IconName } from '../components/Icon'
import Checkbox from '../components/Checkbox'
import SubNav from '../components/SubNav'
import { StatTile } from '../components/Stat'
import { api, usePoll } from '../api'
import { ago, bytes, pct, shortDuration } from '../lib/format'
import type { QilingGuestMetrics, QilingVmStatus } from '../types'

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
//    qiling_setup.py:116-118 re-validates the tree afterwards for that
//    reason. The UI models the action as collect -> validate, not "done".
//
//  * The rootfs is ~111 MB and gets uploaded to the VM, so this is a long job,
//    not a click. Hence the job state, not a spinner.
//
// Everything on this page is READ from what the harness already produced:
// run bundles in qiling_dlls/results/ and the service log. Starting an
// emulation is a subprocess that uploads a sample and runs it on the VM, so it
// stays a CLI action - the panel shows its output, it does not fake running it.
// ---------------------------------------------------------------------------

// 10s: the service log is a file on disk that only changes when a run happens,
// and each run is ~20s of emulation, so polling faster just re-reads the tail.
const INTERVAL = 10000

// The [tag] prefixes _qiling_script.py writes to the service log, so the
// viewer can colour a line by what it is rather than guessing from keywords.
const TAGS: Record<string, { color: string; icon?: IconName }> = {
  dump: { color: 'text-warning' },
  sweep: { color: 'text-accent' },
  ioc: { color: 'text-danger' },
  summary: { color: 'text-success' },
  report: { color: 'text-success' },
  hook: { color: 'text-default-500' },
  api: { color: 'text-default-500' },
  yara: { color: 'text-danger' },
  error: { color: 'text-danger' },
}

function tagOf(line: string): string | null {
  const m = /^\s*(?:\[\s*[\d.]+\s*\]\s*)?\[([a-z_]+)\]/.exec(line)
  return m ? m[1] : null
}

// The output viewer: a read-only <pre> that behaves like a terminal pane.
// Sticky-to-bottom is opt-in because a tail that scrolls while you are reading
// it backwards is worse than one that does not.
function OutputView({
  lines,
  empty,
  autoScroll,
  height = '22rem',
}: {
  lines: string[]
  empty: string
  autoScroll?: boolean
  height?: string
}) {
  const [stick, setStick] = useState(true)
  const scrolling = autoScroll ?? stick
  return (
    <div className="overflow-hidden rounded-lg border border-default-200 bg-default-50/60">
      <div className="flex items-center justify-between gap-2 border-b border-default-200 px-3 py-1.5">
        <span className="font-mono text-[10px] text-default-400">
          {lines.length} line{lines.length === 1 ? '' : 's'}
        </span>
        <label className="flex cursor-pointer items-center gap-1.5 text-[10px] text-default-500">
          <Checkbox
            checked={scrolling}
            onChange={(next) => setStick(next)}
          />
          follow tail
        </label>
      </div>
      {lines.length === 0 ? (
        <p className="py-6 text-center text-[11px] text-default-400">{empty}</p>
      ) : (
        <pre
          className="overflow-auto px-3 py-2 font-mono text-[10.5px] leading-relaxed"
          style={{ height }}
          ref={(el) => {
            if (el && scrolling) el.scrollTop = el.scrollHeight
          }}
        >
          {lines.map((line, i) => {
            const tag = tagOf(line)
            const tone = tag ? TAGS[tag]?.color : undefined
            return (
              <div key={i} className={`whitespace-pre-wrap break-all ${tone ?? 'text-default-600'}`}>
                {line}
              </div>
            )
          })}
        </pre>
      )}
    </div>
  )
}


// ---------------------------------------------------------------------------
// Qiling VM - one machine, three concerns.
//
// Originally this was a single scroll: actions, rootfs, performance and the
// ClamAV guest all stacked, so nothing had emphasis and the page read as a
// wall. ClamAV has its own panel now, and the remaining page is split by what
// the operator is actually doing:
//
//   Overview    am I up, and what is the machine doing right now
//   Emulation   the harness log every run appends to
//   Runs        one bundle at a time, with its trace
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
//    qiling_setup.py:116-118 re-validates the tree afterwards for that
//    reason. The UI models the action as collect -> validate, not "done".
//
//  * The rootfs is ~111 MB and gets uploaded to the VM, so this is a long job,
//    not a click. Hence the job state, not a spinner.
// ---------------------------------------------------------------------------

// A single resource meter: label + value on the first line, a thin bar below.
// Renders like the host Machine panel so CPU/RAM reads the same here.
function Meter({
  label,
  value,
  detail,
}: {
  label: string
  value: number | null
  detail?: string
}) {
  const p = value === null ? 0 : Math.max(0, Math.min(100, value))
  const tone = p >= 85 ? 'bg-danger' : p >= 65 ? 'bg-warning' : 'bg-success'
  return (
    <div>
      <div className="mb-1 flex items-baseline justify-between gap-2">
        <span className="text-xs text-default-500">{label}</span>
        <span className="font-mono text-sm tabular-nums">{value === null ? '—' : `${value}%`}</span>
      </div>
      <div className="h-1.5 w-full overflow-hidden rounded-full bg-default-200">
        <div className={`h-full ${tone}`} style={{ width: `${p}%` }} />
      </div>
      {detail && <div className="mt-1 font-mono text-[11px] text-default-400">{detail}</div>}
    </div>
  )
}

function gb(n: number | null | undefined): string {
  if (n === null || n === undefined) return '—'
  return `${(n / 1024 ** 3).toFixed(1)} GB`
}

// Live CPU / RAM of the running analysis VM, read from inside it over SSH.
// When the VM is powered off or SSH times out the backend returns
// available:false with the reason - shown as a powered-off notice, never as
// meters sitting at 0%.
function GuestCard({ metrics }: { metrics: QilingGuestMetrics }) {
  if (!metrics.available) {
    // `collected_at` is null until the shared collector has returned a sample.
    // That is not the same as "connected but no /proc": the guest may be fine
    // and simply not measured yet, and saying "no /proc data" would blame it.
    const pending = metrics.collected_at == null
    return (
      <Card className="w-full">
        <Card.Header className="flex items-center justify-between gap-3">
          <Card.Title className="text-sm font-semibold">CPU &amp; Memory</Card.Title>
          <Chip size="sm" variant="soft" color={pending ? 'accent' : metrics.reachable ? 'warning' : 'default'}>
            {pending ? 'collecting…' : metrics.reachable ? 'no /proc data' : 'VM unreachable'}
          </Chip>
        </Card.Header>
        <Card.Content>
          <p className="text-[11px] leading-relaxed text-default-400">
            {pending
              ? 'The shared collector has not sampled this guest yet. It runs in the background every 15 seconds and this card fills in when the first sample lands - no SSH handshake is opened for this page.'
              : metrics.reachable
                ? 'Connected but the guest returned no usable /proc data.'
                : 'Start the analysis VM to read live CPU and memory. Metrics come from inside the guest over SSH, so a powered-off VM reports nothing rather than zeros.'}
          </p>
          {metrics.error && (
            <p className="mt-1.5 font-mono text-[10px] text-default-400" title={metrics.error}>
              {metrics.error}
            </p>
          )}
        </Card.Content>
      </Card>
    )
  }
  const mem = metrics.memory
  return (
    <Card className="w-full">
      <Card.Header className="flex items-center justify-between gap-3">
        <Card.Title className="text-sm font-semibold">CPU &amp; Memory</Card.Title>
        <Chip size="sm" variant="soft" color="success">
          {metrics.cores ?? '-'} core{metrics.cores === 1 ? '' : 's'}
          {' · '}
          {metrics.age_seconds == null
            ? 'live'
            : `sampled ${shortDuration(metrics.age_seconds)} ago`}
        </Chip>
      </Card.Header>
      <Card.Content className="flex flex-col gap-4">
        <Meter
          label="Memory"
          value={mem.percent}
          detail={`${gb(mem.used_bytes)} used of ${gb(mem.total_bytes)} · ${gb(mem.available_bytes)} free`}
        />
        <div className="grid grid-cols-3 gap-x-6 gap-y-1 border-t border-default-100 pt-2">
          {(
            [
              ['load 1m', metrics.load['1']?.toFixed(2) ?? '—'],
              ['load 5m', metrics.load['5']?.toFixed(2) ?? '—'],
              ['load 15m', metrics.load['15']?.toFixed(2) ?? '—'],
              ['swap', mem.swap_total_bytes ? `${gb(mem.swap_used_bytes)} / ${gb(mem.swap_total_bytes)}` : 'none'],
              ['disk /', metrics.disk.percent === null ? '—' : pct(metrics.disk.percent)],
              ['disk free', gb(metrics.disk.free_bytes)],
            ] as [string, string][]
          ).map(([k, v]) => (
            <div key={k} className="flex items-baseline justify-between gap-2">
              <span className="text-[11px] text-default-500">{k}</span>
              <span className="truncate font-mono text-[11px]">{v}</span>
            </div>
          ))}
        </div>
        {metrics.uptime_seconds !== null && (
          <p className="font-mono text-[10px] text-default-400">
            guest uptime {shortDuration(metrics.uptime_seconds)}
          </p>
        )}
      </Card.Content>
    </Card>
  )
}

// The VM status checks: VBoxManage, registration, power, TCP. Same facts the
// admin-terminal Qiling VM Control screen shows, so the panel agrees with it.
function StatusChecks({ status }: { status: QilingVmStatus }) {
  if (!status.available) {
    return (
      <Card className="w-full">
        <Card.Header>
          <Card.Title className="text-sm font-semibold">VM status</Card.Title>
        </Card.Header>
        <Card.Content>
          <p className="text-[11px] text-default-400">{status.error || 'unavailable'}</p>
        </Card.Content>
      </Card>
    )
  }
  return (
    <Card className="w-full">
      <Card.Header className="flex items-center justify-between gap-3">
        <Card.Title className="truncate text-sm font-semibold">
          VM status
          {status.vm_name && <span className="ml-2 font-mono text-xs font-normal text-default-400">{status.vm_name}</span>}
        </Card.Title>
        <Chip size="sm" variant="soft" color={status.running ? 'success' : 'default'}>
          {status.running ? 'running' : 'stopped'}
        </Chip>
      </Card.Header>
      <Card.Content className="flex flex-col gap-0.5">
        {status.checks.map((c) => (
          <div key={c.name} className="flex items-center justify-between gap-3 rounded-md px-3 py-1.5 hover:bg-default-50">
            <span className="flex min-w-0 items-center gap-2">
              <Icon name={c.ok ? 'overview' : 'logs'} size={12} className={c.ok ? 'text-success' : 'text-danger'} />
              <span className="truncate text-[11px]">{c.name}</span>
            </span>
            <span className="truncate font-mono text-[10px] text-default-500" title={c.detail}>
              {c.detail}
            </span>
          </div>
        ))}
      </Card.Content>
    </Card>
  )
}

export default function QilingVM() {
  const { data, error, loading, refresh } = usePoll(api.qilingRuns, INTERVAL)
  const [selected, setSelected] = useState<string | null>(null)
  // Check Status / Generate Rootfs are on-demand, not auto-polled: each status
  // check spawns VBoxManage and each rootfs build pops a UAC prompt, so they
  // fire only when clicked and then join the normal refresh cadence.
  const [status, setStatus] = useState<QilingVmStatus | null>(null)
  const [statusBusy, setStatusBusy] = useState(false)
  const [vmMetrics, setVmMetrics] = useState<QilingGuestMetrics | null>(null)
  const [rootfsJob, setRootfsJob] = useState<{ id: string; state: string; detail: string } | null>(null)
  const [rootfsBusy, setRootfsBusy] = useState(false)
  // Three concerns, three screens. Stacked they were one long scroll where the
  // emulation log pushed the VM health off the first screen and the run list
  // sat under both; the header actions still apply to all three.
  const [tab, setTab] = useState<'overview' | 'output' | 'runs'>('overview')

  const runs = data?.runs ?? []
  const active = runs.find((r) => r.file === selected) ?? runs[0] ?? null
  const logLines = data?.service_log.tail ?? []

  const checkStatus = async () => {
    setStatusBusy(true)
    try {
      const s = await api.qilingStatus()
      setStatus(s)
      setVmMetrics(await api.qilingVmMetrics())
    } finally {
      setStatusBusy(false)
    }
  }

  const generateRootfs = async () => {
    setRootfsBusy(true)
    try {
      const job = await api.qilingGenerateRootfs()
      setRootfsJob({ id: job.job_id, state: job.state, detail: job.detail })
    } finally {
      setRootfsBusy(false)
    }
  }

  // Run the status + CPU/RAM probe once on mount so the Analysis VM section is
  // populated on first paint. The button re-runs it on demand thereafter.
  useEffect(() => {
    void checkStatus()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  // Once a probe has run, keep the CPU / memory card fresh while it is on
  // screen. This is cheap now: the endpoint reads vmmetrics' background sample
  // rather than opening its own SSH session, so a 15 s poll costs one cached
  // JSON read instead of a handshake per tick.
  useEffect(() => {
    if (!status || tab !== 'overview') return
    const id = window.setInterval(() => {
      void api.qilingVmMetrics().then(setVmMetrics).catch(() => {
        // A dropped poll is not a failure; the next tick tries again.
      })
    }, 15000)
    return () => window.clearInterval(id)
  }, [status, tab])

  if (loading && !data) {
    return (
      <Loading
        label="Loading Qiling state…"
        hint="reading run bundles and the service log"
      />
    )
  }

  return (
    <>
      <div className="mb-6 flex items-baseline justify-between gap-4">
        <h2 className="page-title">Qiling</h2>
        <div className="flex items-center gap-3">
          <span className="font-mono text-[11px] text-default-400">
            {data?.vm.ip ? `${data.vm.ip}:${data.vm.port} · ${data.harness.version}` : 'emulation harness'}
          </span>
          <Button size="sm" variant="outline" onPress={checkStatus} isDisabled={statusBusy}>
            {statusBusy ? 'Checking…' : 'Check Status'}
          </Button>
          <Button size="sm" variant="outline" onPress={generateRootfs} isDisabled={rootfsBusy}>
            {rootfsBusy ? 'Starting…' : 'Generate Rootfs'}
          </Button>
          <Button size="sm" variant="outline" onPress={refresh}>
            Refresh
          </Button>
        </div>
      </div>

      {rootfsJob && (
        <Alert status={rootfsJob.state === 'error' ? 'danger' : 'accent'} className="mb-4">
          <Alert.Title>
            Rootfs build {rootfsJob.state}
            {rootfsJob.id && <span className="ml-2 font-mono text-xs font-normal">job {rootfsJob.id}</span>}
          </Alert.Title>
          <Alert.Description>
            {rootfsJob.detail || 'A Windows UAC prompt may appear on the machine running the panel; the browser cannot see it. Refresh in a moment to see the new rootfs size.'}
          </Alert.Description>
        </Alert>
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
            Both x86 and x64 trees are required. Generate it from the admin
            terminal (Qiling setup), which runs the DLL collector elevated and
            re-validates the tree afterwards.
          </Alert.Description>
        </Alert>
      )}

      <SubNav
        tabs={[
          { id: 'overview', label: 'Overview', icon: 'qiling' },
          { id: 'output', label: 'Emulation output', icon: 'terminal' },
          {
            id: 'runs', label: 'Runs', icon: 'artifacts',
            tone: runs.some((r) => !r.ok) ? 'warn' : undefined,
          },
        ]}
        active={tab}
        onChange={(id) => setTab(id as 'overview' | 'output' | 'runs')}
      />

      {/* --- overview: headline tiles + VM health --------------------------- */}
      {tab === 'overview' && (
        <>
          {data && (
            <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
              <StatTile
                label="Runs"
                value={data.file_count}
                sub={data.present ? data.path.replace(/.*[\\/]/, '') : 'no results dir'}
                icon={<Icon name="qiling" size={15} />}
                trendTone="accent"
              />
              <StatTile
                label="Rootfs"
                value={bytes(data.rootfs.archive_bytes, 0)}
                sub={data.rootfs.complete ? 'x86 + x64 complete' : 'incomplete'}
                icon={<Icon name="analyze" size={15} />}
                trendTone={data.rootfs.complete ? 'success' : 'warning'}
              />
              <StatTile
                label="Last run"
                value={active && active.elapsed_s ? `${active.elapsed_s.toFixed(1)}s` : '—'}
                sub={active && active.modified ? ago(active.modified) : 'no runs'}
                icon={<Icon name="artifacts" size={15} />}
              />
              <StatTile
                label="Service log"
                value={bytes(data.service_log.bytes, 0)}
                sub={data.harness.service}
                icon={<Icon name="logs" size={15} />}
              />
            </div>
          )}

          <p className="section-label mb-2 mt-6">Analysis VM</p>
          {(status || vmMetrics) ? (
            <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
              {status && <StatusChecks status={status} />}
              {vmMetrics && <GuestCard metrics={vmMetrics} />}
            </div>
          ) : (
            <Card className="w-full">
              <Card.Content>
                <p className="text-[11px] leading-relaxed text-default-400">
                  No probe has run yet this session. <b>Check Status</b> reads
                  the VM’s power and SSH reachability, and the CPU / memory card
                  comes from the collector the Statistics page already runs in
                  the background - it is served from cache, not a fresh SSH
                  handshake.
                </p>
              </Card.Content>
            </Card>
          )}
        </>
      )}

      {/* --- emulation output ---------------------------------------------- */}
      {tab === 'output' && data && (
        <>
          <OutputView
            lines={logLines}
            empty="No service log yet. The harness writes [dump] / [sweep] / [ioc] / [summary] lines here on every run."
          />
          <p className="mt-1.5 font-mono text-[10px] text-default-400">
            tail of config/systemd/qilin-service/artifacts/qilin-service.log
          </p>
        </>
      )}

      {/* --- run list + per-run detail -------------------------------------- */}
      {tab === 'runs' && data && runs.length > 0 && (
        <div className="grid grid-cols-1 gap-3 xl:grid-cols-[320px_1fr]">
          <div className="flex flex-col gap-1.5">
            {runs.map((r) => (
              <button
                key={r.file}
                onClick={() => setSelected(r.file)}
                className={`flex flex-col gap-0.5 rounded-lg border px-3 py-2 text-left transition-colors ${
                  active?.file === r.file
                    ? 'border-accent bg-accent/5'
                    : 'border-default-200 hover:border-default-300'
                }`}
              >
                <span className="flex items-center justify-between gap-2">
                  <span className="truncate font-mono text-[11px]">{r.sample || r.stem}</span>
                  {!r.ok && (
                    <Chip size="sm" variant="soft" color="danger">
                      error
                    </Chip>
                  )}
                </span>
                <span className="font-mono text-[10px] text-default-400">
                  {r.arch || '?'} · {r.elapsed_s ? `${r.elapsed_s.toFixed(1)}s` : '—'} · {ago(r.modified)}
                </span>
              </button>
            ))}
          </div>

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
                    <Card.Header className="flex items-center justify-between gap-3">
                      <Card.Title className="truncate font-mono text-sm">
                        {active.sample || active.stem}
                      </Card.Title>
                      <div className="flex shrink-0 items-center gap-2">
                        <Chip size="sm" variant="soft" color="accent">
                          {active.arch || 'unknown'}
                        </Chip>
                        <Chip size="sm" variant="soft" color={active.end === 'completed' ? 'success' : 'warning'}>
                          {active.end || 'unknown'}
                        </Chip>
                      </div>
                    </Card.Header>
                    <Card.Content className="grid grid-cols-2 gap-x-6 gap-y-1 md:grid-cols-4">
                      {[
                        ['elapsed', active.elapsed_s ? `${active.elapsed_s.toFixed(2)}s` : '—'],
                        ['events', String(active.events)],
                        ['api calls', String(active.api_calls)],
                        ['dumps', String(active.dump_count)],
                        ['iocs', String(active.ioc_count)],
                        ['yara hits', String(active.yara_hits.length)],
                        ['sha256', active.hashes.sha256 ? active.hashes.sha256.slice(0, 12) + '…' : '—'],
                        ['size', bytes(active.bytes, 0)],
                      ].map(([k, v]) => (
                        <div key={k as string} className="flex items-baseline justify-between gap-2 border-b border-default-100 py-1.5">
                          <span className="text-[11px] text-default-500">{k}</span>
                          <span className="truncate font-mono text-[11px]" title={v as string}>
                            {v}
                          </span>
                        </div>
                      ))}
                    </Card.Content>
                  </Card>

                  {Object.keys(active.attack_hints).length > 0 && (
                    <Card className="w-full">
                      <Card.Header>
                        <Card.Title className="text-sm font-semibold">Behaviour</Card.Title>
                      </Card.Header>
                      <Card.Content>
                        <div className="flex flex-wrap gap-1.5">
                          {Object.entries(active.attack_hints).map(([tag, hint]) => (
                            <span
                              key={tag}
                              title={String(hint)}
                              className="rounded bg-danger/12 px-1.5 py-0.5 font-mono text-[10px] text-danger"
                            >
                              {tag} → {String(hint)}
                            </span>
                          ))}
                        </div>
                      </Card.Content>
                    </Card>
                  )}

                  <Card className="w-full">
                    <Card.Header className="flex items-center justify-between">
                      <Card.Title className="text-sm font-semibold">
                        Run trace
                        <span className="ml-2 font-mono text-[10px] font-normal text-default-400">
                          trace.log inside the bundle
                        </span>
                      </Card.Title>
                    </Card.Header>
                    <Card.Content>
                      <OutputView
                        lines={active.trace_tail}
                        empty="This bundle has no trace.log."
                        height="16rem"
                      />
                    </Card.Content>
                  </Card>
                </>
              )}
            </div>
          )}
        </div>
      )}

      {tab === 'runs' && data && runs.length === 0 && (
        <Card className="w-full">
          <Card.Content>
            <p className="py-6 text-center text-[11px] text-default-400">
              No run bundles yet. The harness writes one zip per sample into{' '}
              <code className="font-mono">qiling_dlls/results</code>.
            </p>
          </Card.Content>
        </Card>
      )}
    </>
  )
}

