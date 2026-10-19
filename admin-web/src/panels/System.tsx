import type { ReactNode } from 'react'
import { Card } from '@heroui/react/card'
import { Chip } from '@heroui/react/chip'
import { Alert } from '@heroui/react/alert'
import { api, usePoll } from '../api'
import Icon from '../components/Icon'
import { StatTile, Sparkline } from '../components/Stat'
import Loading from '../components/Loading'
import { bytes, duration, pct, shortDuration } from '../lib/format'
import type { GpuInfo, GpuAdapter } from '../types'

// ---------------------------------------------------------------------------
// Machine - everything this host is doing, on one scroll.
//
// This was a four-tab panel (Overview / Performance / Processes / Storage). The
// tabs hid the obvious: reading "the machine is slow" meant switching to the
// Processes tab, and the answer to "is it the CPU or memory" was a tab switch
// away from the tile that raised it. So it is one page, ordered by the question
// it answers, with each section a heading rather than a hidden panel:
//
//   Headline     is it healthy right now          (4 tiles, sparklined)
//   CPU & Memory what is it doing over time       (the two big charts)
//   Processes    what is causing it               (top-N table)
//   Storage      where is the disk                (per-volume meters)
//   System       what is this box, who serves it  (host + panel facts)
//
// Redundancy was the other cost of merging: the old "Load" card showed the same
// CPU and memory meters the tiles and the charts already show three times over,
// so it is gone. Each number now has exactly one home.
// ---------------------------------------------------------------------------

const INTERVAL = 5000

// Stand-in for a payload that has no `gpu` block at all.
//
// This matters: /api/system is served by a long-running Python process, so a
// freshly-built bundle can be talking to a server that predates the GPU probe -
// and if the UI reads data.gpu.adapters unguarded, that is an unhandled throw
// and React unmounts the whole panel. Degrading to "no adapters reported" keeps
// every other section on the page alive. Same reasoning as a stopped container
// showing "—" rather than taking the list down.
const NO_GPU: GpuInfo = {
  available: false,
  adapters: [],
  count: 0,
  live_count: 0,
  note: 'Not reported by this server.',
}

// An empty-but-valid history, for the same reason: a Sparkline given undefined
// would throw on the first .filter().
const NO_HISTORY: (number | null)[] = []

function gb(n: number | null | undefined): string {
  if (n === null || n === undefined) return '—'
  return `${(n / 1024 ** 3).toFixed(1)} GB`
}

function uptime(sec: number | null | undefined): string {
  if (!sec) return '—'
  return duration(sec)
}

// A section heading. One component so every section on the page has the same
// weight and rhythm - the thing that makes a long scroll readable is that the
// dividers look identical.
function Section({
  title,
  note,
  children,
}: {
  title: string
  note?: ReactNode
  children: ReactNode
}) {
  return (
    <section className="mt-6">
      <div className="mb-2.5 flex items-baseline justify-between gap-3">
        <h3 className="section-label">{title}</h3>
        {note && <span className="font-mono text-[10px] text-default-400">{note}</span>}
      </div>
      {children}
    </section>
  )
}

// A meter is a div with a width. HeroUI ships one, but this value comes from
// a single sample of a machine that is not ours, and a plain bar keeps the
// rendering obvious.
function Meter({
  label,
  value,
  detail,
}: {
  label: string
  value: number | null
  detail?: string
}) {
  const pctVal = value === null ? 0 : Math.max(0, Math.min(100, value))
  const tone = pctVal >= 85 ? 'bg-danger' : pctVal >= 65 ? 'bg-warning' : 'bg-success'
  return (
    <div>
      <div className="mb-1 flex items-baseline justify-between gap-2">
        <span className="text-xs text-default-500">{label}</span>
        <span className="font-mono text-sm tabular-nums">{value === null ? '—' : `${value}%`}</span>
      </div>
      <div className="h-1.5 w-full overflow-hidden rounded-full bg-default-200">
        <div className={`h-full ${tone}`} style={{ width: `${pctVal}%` }} />
      </div>
      {detail && <div className="mt-1 font-mono text-[11px] text-default-400">{detail}</div>}
    </div>
  )
}

function Row({ k, v }: { k: string; v: ReactNode }) {
  return (
    <div className="flex items-baseline justify-between gap-3 border-b border-default-100 py-1.5 last:border-0">
      <span className="text-xs text-default-500">{k}</span>
      <span className="truncate font-mono text-xs" title={typeof v === 'string' ? v : undefined}>
        {v}
      </span>
    </div>
  )
}

// ---------------------------------------------------------------------------
// GPU
//
// One card per adapter. An adapter with live metrics (nvidia-smi) gets meters
// and its utilisation chart; one without gets its inventory and an explicit
// "no live source" line rather than a row of em-dashes that reads as a broken
// sensor. The distinction matters: a box whose only GPU is integrated has real
// hardware and genuinely no cheap way to sample its utilisation on Windows.
// ---------------------------------------------------------------------------

function GpuCard({ adapter }: { adapter: GpuAdapter }) {
  const approx = adapter.vram_source === 'wmi-adapterram-approx'
  const vramTitle = approx
    ? 'AdapterRAM is a uint32 that clamps at 4 GB and reports SHARED system memory for an integrated GPU - treat this as a hint, not a real figure.'
    : 'Dedicated VRAM, from nvidia-smi'

  const facts: [string, ReactNode][] = [
    ['Vendor', adapter.vendor ?? '—'],
    ['Driver', adapter.driver_version ?? '—'],
    [
      'VRAM',
      adapter.vram_bytes === null ? (
        '—'
      ) : (
        <span title={vramTitle}>
          {approx && <span className="text-default-400">~</span>}
          {bytes(adapter.vram_bytes, 0)}
          {approx && <span className="ml-1 text-[10px] text-default-400">approx</span>}
        </span>
      ),
    ],
  ]
  if (adapter.mode) facts.push(['Mode', adapter.mode])

  return (
    <Card className="w-full">
      <Card.Header className="flex items-center justify-between gap-3">
        <Card.Title className="truncate text-sm font-semibold" title={adapter.name}>
          {adapter.name}
        </Card.Title>
        <Chip
          size="sm"
          variant="soft"
          color={adapter.live ? 'success' : 'default'}
          title={
            adapter.live
              ? 'Live metrics from nvidia-smi'
              : 'Inventory only — no nvidia-smi source for this adapter'
          }
        >
          {adapter.live ? 'live' : 'inventory only'}
        </Chip>
      </Card.Header>
      <Card.Content className="flex flex-col gap-3">
        {/* Inventory first, on every adapter: a live card should still say
            what driver it is running, not just what it is doing right now. */}
        <div>
          {facts.map(([k, v]) => (
            <Row key={k} k={k} v={v} />
          ))}
        </div>

        {adapter.live ? (
          <>
            <Meter
              label="GPU utilisation"
              value={adapter.utilization_percent}
              detail={
                adapter.clock_mhz !== null
                  ? `${adapter.memory_utilization_percent ?? 0}% memory controller · ${adapter.clock_mhz} MHz`
                  : `${adapter.memory_utilization_percent ?? 0}% memory controller`
              }
            />
            <Meter
              label="VRAM in use"
              value={adapter.memory_percent}
              detail={`${bytes(adapter.memory_used_bytes)} of ${bytes(adapter.memory_total_bytes, 0)} used`}
            />
            <div className="grid grid-cols-2 gap-x-6 gap-y-1 border-t border-default-100 pt-2">
              {(
                [
                  ['temp', adapter.temperature_c === null ? '—' : `${adapter.temperature_c} °C`],
                  [
                    'power',
                    adapter.power_draw_w === null
                      ? '—'
                      : `${adapter.power_draw_w.toFixed(1)} W${
                          adapter.power_limit_w !== null
                            ? ` / ${adapter.power_limit_w.toFixed(0)} W`
                            : ''
                        }`,
                  ],
                ] as [string, string][]
              ).map(([k, v]) => (
                <div key={k} className="flex items-baseline justify-between gap-2">
                  <span className="text-[11px] text-default-500">{k}</span>
                  <span className="truncate font-mono text-[11px]" title={v}>
                    {v}
                  </span>
                </div>
              ))}
            </div>
          </>
        ) : (
          <p className="rounded-md border border-default-200 bg-default-50/60 px-3 py-2 text-[11px] leading-relaxed text-default-500">
            Live utilisation, VRAM, temperature and power are read from{' '}
            <code>nvidia-smi</code>, which does not cover this adapter. The
            inventory above is all Windows reports for it.
          </p>
        )}
      </Card.Content>
    </Card>
  )
}

export default function System() {
  const { data, error, refresh } = usePoll(api.system, INTERVAL)

  const historyLabel =
    data && data.history.samples > 1
      ? `last ${shortDuration(data.history.window_seconds)} · ${data.history.samples} samples`
      : 'collecting…'

  // Normalise the two fields that are newer than the running server may be, so
  // nothing below has to null-check them one by one.
  const gpu = data?.gpu ?? NO_GPU
  const gpuHistory = data?.history.gpu ?? NO_HISTORY

  // The busiest live adapter - what the tiles and the chart summarise when a
  // box has both an iGPU and a dGPU. Null when nothing has a live source, so
  // the tile reads "—" rather than a confident 0% for a card we cannot sample.
  const topGpu = gpu.adapters
    .filter((a) => a.live)
    .sort((a, b) => (b.utilization_percent ?? -1) - (a.utilization_percent ?? -1))[0]

  return (
    <>
      <div className="mb-4 flex items-baseline justify-between gap-4">
        <h2 className="page-title">Machine</h2>
        <div className="flex items-center gap-3">
          <span className="font-mono text-[11px] text-default-400">
            {data ? `sampled 5s · history ${historyLabel}` : 'live from the OS'}
          </span>
          <button
            onClick={refresh}
            className="rounded-md border border-default-300 px-3 py-1.5 text-xs hover:border-accent hover:text-accent"
          >
            Refresh
          </button>
        </div>
      </div>

      {error && (
        <Alert status="danger" className="mb-4">
          <Alert.Title>Cannot read machine info</Alert.Title>
          <Alert.Description>{error}</Alert.Description>
        </Alert>
      )}

      {!data && !error && (
        <Loading
          label="Loading machine metrics…"
          hint="sampling CPU, memory, GPU, disks and processes"
        />
      )}

      {data && (
        <>
          {/* --- headline: is it healthy right now ------------------------- */}
          <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
            <StatTile
              label="CPU"
              value={pct(data.cpu.load_percent)}
              sub={`${data.cpu.logical_cores ?? '—'} logical cores`}
              icon={<Icon name="machine" size={15} />}
              trend={data.history.cpu}
              trendMax={100}
              trendTone={
                (data.cpu.load_percent ?? 0) > 85
                  ? 'danger'
                  : (data.cpu.load_percent ?? 0) > 65
                    ? 'warning'
                    : 'accent'
              }
            />
            <StatTile
              label="Memory"
              value={pct(data.memory.load_percent)}
              sub={`${gb(data.memory.used_bytes)} of ${gb(data.memory.total_bytes)}`}
              icon={<Icon name="stats" size={15} />}
              trend={data.history.memory}
              trendMax={100}
              trendTone={
                (data.memory.load_percent ?? 0) > 90
                  ? 'danger'
                  : (data.memory.load_percent ?? 0) > 75
                    ? 'warning'
                    : 'accent'
              }
            />
            <StatTile
              label="Uptime"
              value={uptime(data.uptime_seconds)}
              sub={data.host.name}
              icon={<Icon name="refresh" size={15} />}
            />
            <StatTile
              label="GPU"
              value={topGpu ? pct(topGpu.utilization_percent) : '—'}
              sub={
                topGpu
                  ? `${topGpu.temperature_c === null ? '' : `${topGpu.temperature_c} °C · `}${bytes(
                      topGpu.memory_used_bytes,
                      0,
                    )} VRAM`
                  : gpu.count
                    ? `${gpu.count} adapter(s), none live`
                    : 'no GPU'
              }
              icon={<Icon name="model" size={15} />}
              trend={gpuHistory}
              trendMax={100}
              trendTone={
                (topGpu?.utilization_percent ?? 0) > 85
                  ? 'danger'
                  : (topGpu?.utilization_percent ?? 0) > 65
                    ? 'warning'
                    : 'accent'
              }
            />
            {/* No Disk tile here on purpose: the Storage section below lists
                every volume with its own meter, so a fifth tile repeating the
                same number was the duplication, not a useful summary. The
                headline is the four things that are not "space on a disk". */}
          </div>

          {/* --- trends: what is it doing over time ----------------------- */}
          <Section
            title="CPU & memory"
            note={`${data.history.samples} samples · window ${shortDuration(data.history.window_seconds)}`}
          >
            <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
              <Card className="w-full">
                <Card.Header className="flex items-center justify-between gap-3">
                  <Card.Title className="text-sm font-semibold">
                    CPU
                    <span className="ml-2 font-mono text-[11px] font-normal text-default-400">
                      % of {data.cpu.logical_cores ?? '—'} logical cores
                    </span>
                  </Card.Title>
                  <Chip
                    size="sm"
                    variant="soft"
                    color={
                      (data.cpu.load_percent ?? 0) > 85
                        ? 'danger'
                        : (data.cpu.load_percent ?? 0) > 65
                          ? 'warning'
                          : 'success'
                    }
                  >
                    {data.cpu.load_percent === null ? '—' : `${data.cpu.load_percent}%`}
                  </Chip>
                </Card.Header>
                <Card.Content className="flex flex-col gap-2">
                  <Sparkline data={data.history.cpu} tone="accent" max={100} height={140} />
                  <div className="border-t border-default-100 pt-2">
                    <Meter label="Current load" value={data.cpu.load_percent} />
                  </div>
                </Card.Content>
              </Card>

              <Card className="w-full">
                <Card.Header className="flex items-center justify-between gap-3">
                  <Card.Title className="text-sm font-semibold">Memory</Card.Title>
                  <Chip
                    size="sm"
                    variant="soft"
                    color={
                      (data.memory.load_percent ?? 0) > 90
                        ? 'danger'
                        : (data.memory.load_percent ?? 0) > 75
                          ? 'warning'
                          : 'success'
                    }
                  >
                    {data.memory.load_percent === null ? '—' : `${data.memory.load_percent}%`}
                  </Chip>
                </Card.Header>
                <Card.Content className="flex flex-col gap-2">
                  <Sparkline data={data.history.memory} tone="success" max={100} height={140} />
                  <p className="font-mono text-[10px] text-default-400">
                    {gb(data.memory.used_bytes)} used · {gb(data.memory.available_bytes)} free ·{' '}
                    {gb(data.memory.total_bytes)} total
                  </p>
                </Card.Content>
              </Card>
            </div>
          </Section>

          {/* --- what is driving the GPU ----------------------------------- */}
          <Section
            title="Graphics"
            note={
              gpu.available
                ? `${gpu.live_count}/${gpu.count} adapter(s) with live metrics`
                : 'no display adapters reported'
            }
          >
            {gpu.available ? (
              <>
                <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
                  {gpu.adapters.map((a) => (
                    <GpuCard key={a.name} adapter={a} />
                  ))}
                </div>
                {topGpu && (
                  <Card className="mt-3 w-full">
                    <Card.Header className="flex items-center justify-between gap-3">
                      <Card.Title className="truncate text-sm font-semibold" title={topGpu.name}>
                        Utilisation — {topGpu.name}
                      </Card.Title>
                      <Chip size="sm" variant="soft">
                        {topGpu.clock_mhz === null ? '—' : `${topGpu.clock_mhz} MHz`}
                      </Chip>
                    </Card.Header>
                    <Card.Content>
                      <Sparkline data={gpuHistory} tone="accent" max={100} height={90} />
                      <p className="mt-1.5 font-mono text-[10px] text-default-400">
                        busiest adapter per sample · window {shortDuration(data.history.window_seconds)} ·
                        source nvidia-smi (NVIDIA only)
                      </p>
                    </Card.Content>
                  </Card>
                )}
              </>
            ) : (
              <Card className="w-full">
                <Card.Content>
                  <p className="py-4 text-[12px] text-default-400">{gpu.note}</p>
                </Card.Content>
              </Card>
            )}
          </Section>

          {/* --- what is causing it --------------------------------------- */}
          <Section
            title="Top processes"
            note={`by memory · ${data.top_processes.cores} cores · sampled ${data.top_processes.sample_seconds}s`}
          >
            <Card className="w-full">
              <Card.Header className="flex flex-wrap items-center justify-between gap-3">
                <Card.Title className="text-sm font-semibold">
                  Top {data.top_processes.processes.length || 5} consumers
                </Card.Title>
                <Chip
                  size="sm"
                  variant="soft"
                  color={data.top_processes.available ? 'success' : 'default'}
                >
                  {data.top_processes.available ? 'live' : 'unavailable'}
                </Chip>
              </Card.Header>
              <Card.Content>
                {!data.top_processes.available ? (
                  <p className="py-4 text-[12px] text-default-400">{data.top_processes.note}</p>
                ) : (
                  <>
                    <div className="overflow-x-auto">
                      <table className="w-full text-left text-[12px]">
                        <thead>
                          <tr className="border-b border-default-200 text-[11px] uppercase tracking-wider text-default-400">
                            <th className="py-2 pr-3 font-medium">#</th>
                            <th className="py-2 pr-3 font-medium">Process</th>
                            <th className="py-2 pr-3 font-medium">PID</th>
                            <th className="py-2 pr-3 font-medium">Memory</th>
                            <th className="py-2 pr-3 font-medium" style={{ minWidth: 140 }}>Share</th>
                            <th className="py-2 font-medium">CPU ≈</th>
                          </tr>
                        </thead>
                        <tbody>
                          {data.top_processes.processes.map((p, i) => (
                            <tr key={`${p.pid}-${p.name}`} className="border-b border-default-100 last:border-0">
                              <td className="py-2 pr-3 font-mono text-default-400">{i + 1}</td>
                              <td className="max-w-[220px] truncate py-2 pr-3 font-mono" title={p.name}>
                                {p.name}
                              </td>
                              <td className="py-2 pr-3 font-mono text-default-500">{p.pid}</td>
                              <td className="py-2 pr-3 font-mono tabular-nums">
                                {bytes(p.mem_bytes, 0)}
                                <span className="ml-1.5 text-default-400">
                                  {p.mem_percent === null ? '' : `${p.mem_percent}%`}
                                </span>
                              </td>
                              <td className="py-2 pr-3">
                                <div className="h-1.5 w-full min-w-[120px] overflow-hidden rounded-full bg-default-200">
                                  <div
                                    className="h-full rounded-full bg-accent"
                                    style={{ width: `${Math.max(0, Math.min(100, p.mem_percent ?? 0))}%` }}
                                  />
                                </div>
                              </td>
                              <td className="py-2 font-mono tabular-nums">
                                {p.cpu_percent === null ? '—' : `${p.cpu_percent}%`}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                    <p className="mt-3 font-mono text-[10px] leading-relaxed text-default-400">
                      {data.top_processes.note}
                    </p>
                  </>
                )}
              </Card.Content>
            </Card>
          </Section>

          {/* --- where the disk is ----------------------------------------- */}
          <Section title="Storage" note={`${data.disks.length} fixed volume(s)`}>
            <div className="storage-volume-grid">
              {data.disks.map((d) => (
                <Card key={d.path} className="storage-volume-card w-full">
                  <Card.Header className="storage-volume-header flex items-center justify-between gap-3">
                    <div className="min-w-0">
                      {/* Drive letter, not the raw path. "C:" is what an operator
                          recognises; "C:\Users\<you>\Desktop\IAProject" is a
                          detail that belongs in the tooltip. */}
                      <Card.Title className="font-mono" title={d.path}>
                        {d.device ?? d.path}
                      </Card.Title>
                      {d.name && (
                        <p className="truncate text-[11px] text-default-400">{d.name}</p>
                      )}
                    </div>
                    <Chip
                      size="sm"
                      variant="soft"
                      color={
                        d.used_percent === null
                          ? 'default'
                          : d.used_percent >= 90
                            ? 'danger'
                            : d.used_percent >= 75
                              ? 'warning'
                              : 'success'
                      }
                    >
                      {d.used_percent === null ? '—' : `${d.used_percent}% used`}
                    </Chip>
                  </Card.Header>
                  <Card.Content className="storage-volume-content flex flex-col gap-2">
                    <Meter
                      label="Used"
                      value={d.used_percent}
                      detail={`${gb(d.used_bytes)} used · ${gb(d.free_bytes)} free of ${gb(d.total_bytes)}`}
                    />
                    <div className="storage-volume-free flex items-baseline justify-between gap-2 border-t border-default-100 pt-2">
                      <span className="text-[11px] text-default-500">Free</span>
                      <span className="font-mono text-[11px] tabular-nums">
                        {bytes(d.free_bytes)} of {bytes(d.total_bytes, 0)}
                        {d.filesystem && (
                          <span className="ml-2 text-default-400">{d.filesystem}</span>
                        )}
                      </span>
                    </div>
                  </Card.Content>
                </Card>
              ))}
            </div>
          </Section>

          {/* --- what box this is ------------------------------------------ */}
          <Section title="System">
            <Card className="w-full">
              <Card.Header>
                {/* No architecture chip here: "AMD64" is already an OS spelling
                    of what the Platform row says in the same card, and a chip
                    next to a title reads as the card's subject when it is just
                    one attribute. */}
                <Card.Title>Host</Card.Title>
              </Card.Header>
              <Card.Content className="grid grid-cols-1 gap-x-10 sm:grid-cols-2">
                <div>
                  <Row k="Name" v={data.host.name} />
                  <Row k="System" v={`${data.host.system} ${data.host.release}`} />
                  <Row k="Version" v={data.host.version} />
                </div>
                <div>
                  <Row k="Processor" v={data.host.processor ?? '—'} />
                  <Row k="Architecture" v={data.host.machine} />
                  <Row k="CPU cores" v={String(data.cpu.logical_cores ?? '—')} />
                  <Row k="Uptime" v={uptime(data.uptime_seconds)} />
                </div>
              </Card.Content>
            </Card>
          </Section>
        </>
      )}
    </>
  )
}