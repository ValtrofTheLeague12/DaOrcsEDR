import { useEffect, useState } from 'react'
import { Alert } from '@heroui/react/alert'
import { Button } from '@heroui/react/button'
import { Card } from '@heroui/react/card'
import { Chip } from '@heroui/react/chip'
import Loading from '../components/Loading'
import Console from '../components/Console'
import Icon, { type IconName } from '../components/Icon'
import SubNav from '../components/SubNav'
import { StatTile } from '../components/Stat'
import { api, usePoll } from '../api'
import { ago, bytes } from '../lib/format'
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

function GuestResources({
  metrics,
  onRefresh,
  onOpenProfiler,
}: {
  metrics: QilingGuestMetrics | null
  onRefresh: () => void
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
        <Button size="sm" variant="outline" onPress={onRefresh}>Refresh</Button>
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

export default function QilingVM({ onOpenProfiler }: { onOpenProfiler: () => void }) {
  const { data, error, loading, refresh } = usePoll(api.qilingRuns, INTERVAL)
  const { data: guestMetrics, refresh: refreshGuestMetrics } =
    usePoll(api.qilingVmMetrics, 15000)
  const [selected, setSelected] = useState<string | null>(null)
  // Check Status / Generate Rootfs are on-demand, not auto-polled: each status
  // check spawns VBoxManage and each rootfs build pops a UAC prompt, so they
  // fire only when clicked and then join the normal refresh cadence.
  const [status, setStatus] = useState<QilingVmStatus | null>(null)
  const [statusBusy, setStatusBusy] = useState(false)
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
      <div className="mb-4 flex flex-wrap items-start justify-between gap-4 border-b border-default-200 pb-4">
        <div className="min-w-0">
          <div className="mb-2 flex flex-wrap items-center gap-2">
            <span className="eyebrow">DYNAMIC ANALYSIS</span>
            {status && (
              <Chip
                size="sm"
                variant="soft"
                color={status.ok ? 'success' : 'warning'}
              >
                {status.ok ? 'Environment ready' : 'Needs attention'}
              </Chip>
            )}
          </div>
          <h2 className="page-title">Qiling analysis</h2>
          <p className="mt-1 max-w-2xl text-xs leading-relaxed text-default-500">
            Inspect the emulation VM, guest harness output, and saved run
            bundles. Samples execute in the configured analysis VM.
          </p>
          <div className="mt-2 flex flex-wrap gap-x-3 gap-y-1 text-[10px] text-default-400">
            <span>{data?.vm.name || 'VM not configured'}</span>
            <span>{data?.vm.ip ? `${data.vm.ip}:${data.vm.port}` : 'endpoint unavailable'}</span>
            <span>{data?.harness.version || 'harness unavailable'}</span>
          </div>
        </div>
        <div className="flex flex-wrap gap-2">
          <Button size="sm" variant="outline" onPress={refresh}>
            Refresh data
          </Button>
          <Button size="sm" variant="outline" onPress={checkStatus} isDisabled={statusBusy}>
            {statusBusy ? 'Checking…' : 'Check VM'}
          </Button>
          <Button size="sm" variant="primary" onPress={generateRootfs} isDisabled={rootfsBusy}>
            {rootfsBusy ? 'Starting…' : 'Build rootfs'}
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
            Both x86 and x64 trees are required. Use <b>Build rootfs</b> above;
            Windows may show a UAC prompt on the machine running the panel.
            The browser cannot display that prompt.
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

      {/* --- overview: summary, VM health, and rootfs ----------------------- */}
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

          <GuestResources
            metrics={guestMetrics}
            onRefresh={refreshGuestMetrics}
            onOpenProfiler={onOpenProfiler}
          />

          <div className="mb-2 mt-6 flex items-center justify-between gap-3">
            <div>
              <p className="section-label">Environment</p>
              <p className="mt-0.5 text-[11px] text-default-400">
                VM connectivity and the files required by the guest harness
              </p>
            </div>
            {status && (
              <span className="font-mono text-[10px] text-default-400">
                checked {ago(status.checked_at)}
              </span>
            )}
          </div>
          <div className="grid grid-cols-1 gap-3 xl:grid-cols-[1.1fr_0.9fr]">
            {status ? (
              <StatusChecks status={status} />
            ) : (
              <Card className="w-full">
                <Card.Content className="flex min-h-32 flex-col items-center justify-center gap-2 text-center">
                  <Icon name="qiling" size={19} className="text-default-400" />
                  <p className="text-xs font-medium">VM status has not been checked</p>
                  <p className="max-w-sm text-[11px] text-default-400">
                    Check registration, power state, and SSH reachability.
                  </p>
                  <Button size="sm" variant="outline" onPress={checkStatus} isDisabled={statusBusy}>
                    {statusBusy ? 'Checking…' : 'Check VM'}
                  </Button>
                </Card.Content>
              </Card>
            )}

            {data && (
              <Card className="w-full">
                <Card.Header className="flex items-center justify-between gap-3">
                  <div>
                    <Card.Title className="text-sm font-semibold">Guest readiness</Card.Title>
                    <p className="mt-0.5 text-[10px] text-default-400">
                      Root filesystem and harness deployment
                    </p>
                  </div>
                  <Chip size="sm" variant="soft" color={data.rootfs.complete && data.harness.present ? 'success' : 'warning'}>
                    {data.rootfs.complete && data.harness.present ? 'ready' : 'incomplete'}
                  </Chip>
                </Card.Header>
                <Card.Content className="flex flex-col gap-3">
                  <div className="rounded-lg border border-default-100 bg-default-50/70 p-3">
                    <div className="mb-2 flex items-center justify-between gap-3">
                      <span className="text-xs font-medium">Root filesystem</span>
                      <span className="font-mono text-[10px] text-default-500">
                        {bytes(data.rootfs.archive_bytes, 0)}
                      </span>
                    </div>
                    <div className="grid grid-cols-2 gap-2">
                      {data.rootfs.trees.map((tree) => (
                        <div key={tree.arch} className="flex items-center justify-between gap-2">
                          <span className="font-mono text-[10px] text-default-500">{tree.arch}</span>
                          <span className={tree.complete ? 'text-[10px] text-success' : 'text-[10px] text-warning'}>
                            {tree.complete ? `${tree.files} files` : 'missing'}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                  <div className="flex items-center justify-between gap-3 border-b border-default-100 pb-2">
                    <span className="text-[11px] text-default-500">Harness</span>
                    <span className="font-mono text-[10px] text-default-600">
                      {data.harness.present ? data.harness.version : 'not found'}
                    </span>
                  </div>
                  <div className="flex items-center justify-between gap-3">
                    <span className="text-[11px] text-default-500">Guest service</span>
                    <span className="truncate font-mono text-[10px] text-default-600">
                      {data.harness.service}
                    </span>
                  </div>
                </Card.Content>
              </Card>
            )}
          </div>

          {data && logLines.length > 0 && (
            <div className="mt-3">
              <Console
                title="Recent guest activity"
                subtitle="config/systemd/qilin-service/artifacts/qilin-service.log"
                icon="terminal"
                meta={`${logLines.length} lines`}
                actions={
                  <Button size="sm" variant="outline" onPress={refresh}>
                    Refresh
                  </Button>
                }
                lines={logLines}
                lineClass={(line) => {
                  const tag = tagOf(line)
                  return tag ? (TAGS[tag]?.color ?? '') : 'text-default-600'
                }}
                numbered
                size="short"
                ariaLabel="Qiling service log tail"
                empty="No service log yet."
              />
            </div>
          )}
        </>
      )}

      {/* --- emulation output ---------------------------------------------- */}
      {tab === 'output' && data && (
        <>
          <Console
            title="Emulation output"
            subtitle="tail of config/systemd/qilin-service/artifacts/qilin-service.log"
            icon="terminal"
            status={{ label: `${logLines.length} lines`, tone: 'default' }}
            meta={`${bytes(data.service_log.bytes, 0)}`}
            actions={
              <Button size="sm" variant="outline" onPress={refresh}>
                Refresh
              </Button>
            }
            lines={logLines}
            lineClass={(line) => {
              const tag = tagOf(line)
              return tag ? (TAGS[tag]?.color ?? '') : 'text-default-600'
            }}
            numbered
            copyText={logLines.join('\n')}
            size="tall"
            ariaLabel="Qiling emulation output"
            empty="No service log yet. The harness writes [dump] / [sweep] / [ioc] / [summary] lines here on every run."
          />
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

                  <Console
                    title="Run trace"
                    subtitle="trace.log inside the bundle"
                    icon="terminal"
                    meta={`${active.trace_tail.length} lines`}
                    lines={active.trace_tail}
                    numbered
                    copyText={active.trace_tail.join('\n')}
                    size="short"
                    ariaLabel="Run trace"
                    empty="This bundle has no trace.log."
                  />
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
