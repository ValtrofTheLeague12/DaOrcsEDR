import { lazy, Suspense, useEffect, useState } from 'react'
import { Chip } from '@heroui/react/chip'
import { api, auth, usePoll } from './api'
import Icon, { type IconName } from './components/Icon'
import PanelBoundary from './components/PanelBoundary'
import Login from './panels/Login'
import ThemeToggle from './components/ThemeToggle'
import { Placeholder } from './components/ServiceCard'
import { VM_TARGETS } from './lib/vms'

// Every panel is split out of the entry chunk.
//
// These were all static imports, which meant Vite emitted a single bundle
// containing all eleven of them: a reader opening the Artifacts page first
// downloaded, parsed and executed the log reader, the documentation browser,
// the network map and the VM consoles before a single tile could paint. Measured
// on this build that was 508 KB of JS in one file (148 KB gzip) plus a 520 KB
// stylesheet, and the overwhelming majority of it belonged to pages nobody had
// opened yet.
//
// `lazy` gives each panel its own chunk, fetched the first time it is actually
// selected. The sidebar, the header and the theme toggle deliberately stay in
// the entry chunk: they are what makes the shell drawable, so deferring them
// would move the wait rather than shorten it.
//
// Login is the one panel left eager. It can be the very first thing painted -
// when the server requires a token - and spending a network round trip to
// reveal a password box would be a regression dressed up as an optimisation.
const Overview = lazy(() => import('./panels/Overview'))
const Documentation = lazy(() => import('./panels/Documentation'))
const Stats = lazy(() => import('./panels/Stats'))
const System = lazy(() => import('./panels/System'))
const Network = lazy(() => import('./panels/Network'))
const Logs = lazy(() => import('./panels/Logs'))
const Artifacts = lazy(() => import('./panels/Artifacts'))
const AnalysisConfig = lazy(() => import('./panels/AnalysisConfig'))
const Containers = lazy(() => import('./panels/Containers'))
const Build = lazy(() => import('./panels/Build'))
const Utils = lazy(() => import('./panels/Utils'))
const Clamd = lazy(() => import('./panels/Clamd'))
const VM = lazy(() => import('./panels/VM'))
const QilingVM = lazy(() => import('./panels/QilingVM'))

type PanelId =
  | 'overview' | 'docs' | 'stats' | 'system' | 'network' | 'logs' | 'artifacts'
  | 'analyze' | 'build' | 'model' | 'utils'
  | 'containers'
  | 'vm' | 'qiling-vm' | 'cape-vm' | 'clamd' | 'qiling'

interface NavEntry {
  id: PanelId
  label: string
  icon: IconName
  slice?: string
}

// The virtual-machine section is generated from lib/vms.ts, so bringing a new
// sandbox online is an entry in that registry rather than an edit here. That
// is the whole point: this section keeps gaining machines.
const VM_NAV: NavEntry[] = VM_TARGETS.map((t) => ({
  id: t.id as PanelId,
  label: t.label,
  icon: t.icon,
  slice: t.slice,
}))

// Grouped so each concern has a home. ClamAV and Qiling sit under Virtual
// Machines rather than at the top level because they are guests on the Qiling
// VM, not things that run on this host.
const NAV: { group: string; items: NavEntry[] }[] = [
  {
    group: '',
    items: [
      { id: 'stats', label: 'Statistics', icon: 'stats' },
      { id: 'overview', label: 'Services', icon: 'services' },
      { id: 'docs', label: 'Documentation', icon: 'logs' },
      { id: 'system', label: 'Machine', icon: 'machine' },
      { id: 'network', label: 'Networking', icon: 'services' },
    ],
  },
  {
    group: 'Analysis',
    items: [
      { id: 'analyze', label: 'Analysis Configuration', icon: 'analyze' },
      { id: 'artifacts', label: 'Artifacts', icon: 'artifacts' },
      { id: 'build', label: 'Build', icon: 'build' },
      { id: 'model', label: 'Model', icon: 'model', slice: 'slice 6' },
    ],
  },
  {
    // Its own group on purpose. These are upkeep of the tools the analysis runs
    // on, not an analysis stage - two of the four download hundreds of megabytes
    // or run git, and burying that under "Analysis" invites someone to kick one
    // off in the middle of an investigation.
    group: 'Maintenance',
    items: [
      { id: 'utils', label: 'Utils', icon: 'wrench' },
    ],
  },
  {
    group: 'Infrastructure',
    items: [
      { id: 'containers', label: 'Containers', icon: 'containers' },
    ],
  },
  { group: 'Virtual Machines', items: VM_NAV },
  { group: 'Diagnostics', items: [{ id: 'logs', label: 'Logs', icon: 'logs' }] },
]

const ALL_ITEMS = NAV.flatMap((g) => g.items)
const TITLES: Record<PanelId, string> = Object.fromEntries(
  ALL_ITEMS.map((i) => [i.id, i.label]),
) as Record<PanelId, string>

const BUILT: PanelId[] = [
  'stats', 'overview', 'docs', 'system', 'network', 'artifacts', 'analyze',
  'build', 'utils', 'containers', 'logs', 'vm', 'qiling-vm', 'clamd',
]

// Shown while a panel's chunk is in flight.
//
// It reuses the same pulse the login check already draws, so a page switch
// reads as the same kind of wait as everything else in the shell rather than as
// a blank frame. It names the panel because the wait is now a real fetch - on a
// cold cache with no warm chunk there is genuinely a second or so between
// clicking Artifacts and the page appearing, and silence would read as a hang.
function PanelFallback({ label }: { label: string }) {
  return (
    <div
      className="flex h-64 flex-col items-center justify-center gap-3"
      role="status"
      aria-live="polite"
    >
      <div className="h-7 w-7 animate-pulse rounded-full border-2 border-accent/30 border-t-accent" />
      <p className="font-mono text-[10px] text-default-400">
        Loading {label.toLowerCase()}â€¦
      </p>
    </div>
  )
}

export default function App() {
  const [panel, setPanel] = useState<PanelId>('stats')
  const [gate, setGate] = useState<'checking' | 'in' | 'out'>('checking')
  const [state, setState] = useState<Awaited<ReturnType<typeof auth.state>> | null>(null)

  const cfg = usePoll(api.config, 60000)
  const active = ALL_ITEMS.find((i) => i.id === panel)

  const check = () =>
    auth
      .state()
      .then((s) => {
        setState(s)
        // Only intercept when the server actually demands a token. With none
        // configured the panel is open on loopback, which is the default, and
        // forcing a login for it would be theatre.
        setGate(s.required && !s.authorised ? 'out' : 'in')
      })
      .catch(() => setGate('in'))

  useEffect(() => {
    void check()
  }, [])

  if (gate === 'checking') {
    return (
      <div className="flex h-full items-center justify-center">
        <div className="h-8 w-8 animate-pulse rounded-full border-2 border-accent/30 border-t-accent" />
      </div>
    )
  }

  if (gate === 'out') {
    return <Login onOk={() => void check()} />
  }

  return (
    <>
      <div className="ambient" aria-hidden />
      <div className="app-shell relative z-10 grid h-full grid-cols-[236px_1fr]">
        <aside className="sidebar-glass flex flex-col">
          <div className="flex items-center gap-2.5 border-b border-default-200/60 px-4 py-4">
            <span className="flex h-7 w-7 items-center justify-center rounded-lg bg-accent/15 text-accent">
              <Icon name="stats" size={15} />
            </span>
            <div className="min-w-0">
              <h1 className="text-[13px] font-semibold leading-tight tracking-tight">
                Admin Console
              </h1>
              <p className="metric truncate font-mono text-[10px] text-default-400">
                {cfg.data ? `${cfg.data.panel.host}:${cfg.data.panel.port}` : 'connectingâ€¦'}
              </p>
            </div>
          </div>

          <nav className="nav-scroll flex-1 space-y-4 px-3 py-4">
            {NAV.map((g) => (
              <div key={g.group}>
                {g.group && <p className="section-label mb-1.5 px-2">{g.group}</p>}
                <div className="flex flex-col gap-0.5">
                  {g.items.map((it) => (
                    <button
                      key={it.id}
                      onClick={() => setPanel(it.id)}
                      className={`nav-item ${panel === it.id ? 'active' : ''}`}
                      title={it.slice ? `${it.label} â€” planned for ${it.slice}` : it.label}
                    >
                      <Icon name={it.icon} size={15} />
                      <span className="flex-1 truncate">{it.label}</span>
                      {it.slice && (
                        <span className="metric font-mono text-[9px] text-default-400">
                          {it.slice.replace('slice ', 's')}
                        </span>
                      )}
                    </button>
                  ))}
                </div>
              </div>
            ))}
          </nav>

          <div className="flex items-center justify-between gap-2 border-t border-default-200/60 px-3 py-3">
            <ThemeToggle />
            {state?.required && (
              <button
                onClick={() => void auth.logout().then(check)}
                className="btn-ghost"
                title="Sign out"
              >
                <Icon name="logout" size={13} />
              </button>
            )}
          </div>
        </aside>

        <main className="app-main overflow-y-auto px-6 py-6 pb-12">
          {/* The boundary sits around the panel only. The sidebar must never
              unmount while a chunk downloads - a nav that blinks out during a
              page switch reads as the whole app having crashed. */}
          {/* Two boundaries, for two different failures. Suspense covers a chunk
              that has not arrived yet. This one covers a chunk that arrived and
              then threw: without it React unmounts the whole tree, sidebar
              included, and the operator is left with a blank page and no
              explanation. It resets on navigation, so one bad panel cannot lock
              them out of the rest of the console. */}
          <PanelBoundary label={TITLES[panel]}>
            <Suspense fallback={<PanelFallback label={TITLES[panel]} />}>
            {panel === 'stats' && <Stats />}
            {panel === 'overview' && <Overview />}
            {panel === 'docs' && <Documentation />}
            {panel === 'system' && <System />}
            {panel === 'network' && <Network />}
            {panel === 'logs' && <Logs />}
            {panel === 'artifacts' && <Artifacts />}
            {panel === 'analyze' && <AnalysisConfig />}
            {panel === 'build' && <Build />}
            {panel === 'utils' && <Utils />}
            {panel === 'containers' && <Containers />}
            {panel === 'vm' && <VM />}
            {panel === 'qiling-vm' && <QilingVM />}
            {panel === 'clamd' && <Clamd />}
            {!BUILT.includes(panel) && (
              <>
                <div className="mb-6 flex items-baseline justify-between gap-4">
                  <h1 className="page-title">{TITLES[panel]}</h1>
                  {active?.slice && (
                    <Chip size="sm" variant="soft" color="accent">
                      {active.slice}
                    </Chip>
                  )}
                </div>
                <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-3">
                  <Placeholder title={TITLES[panel]} slice={active?.slice ?? ''} />
                </div>
              </>
            )}
          </Suspense>
          </PanelBoundary>
        </main>
      </div>
    </>
  )
}