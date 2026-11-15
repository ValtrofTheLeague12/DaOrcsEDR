import { lazy, Suspense, useEffect, useState } from 'react'
import { api, auth, usePoll } from './api'
import Icon, { type IconName } from './components/Icon'
import PanelBoundary from './components/PanelBoundary'
import Login from './panels/Login'
import BootScreen from './components/BootScreen'
import LogoSpinner from './components/LogoSpinner'
import { LogoMark } from './components/Logo'
import ThemeToggle from './components/ThemeToggle'
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
const EndpointAgents = lazy(() => import('./panels/EndpointAgents'))
const Logs = lazy(() => import('./panels/Logs'))
const Artifacts = lazy(() => import('./panels/Artifacts'))
const ThreatIntelligence = lazy(() => import('./panels/ThreatIntelligence'))
const ThreatIntelligenceBans = lazy(() => import('./panels/ThreatIntelligenceBans'))
const ThreatIntelligenceApis = lazy(() => import('./panels/ThreatIntelligenceApis'))
const Containers = lazy(() => import('./panels/Containers'))
const Build = lazy(() => import('./panels/Build'))
const Utils = lazy(() => import('./panels/Utils'))
const Clamd = lazy(() => import('./panels/Clamd'))
const VM = lazy(() => import('./panels/VM'))
const QilingVM = lazy(() => import('./panels/QilingVM'))
const PipelinesConfig = lazy(() => import('./panels/PipelinesConfig'))
const AnalysisConfig = lazy(() => import('./panels/AnalysisConfig'))
const DynamicAnalysisConfig = lazy(() => import('./panels/DynamicAnalysisConfig'))
const MemoryProfiling = lazy(() => import('./panels/MemoryProfiling'))

// Exported so panels can accept an `onNavigate` prop without importing the
// whole App module graph - the type is all they need.
export type PanelId =
  | 'overview' | 'docs' | 'stats' | 'system' | 'network' | 'endpoint-agents'
  | 'logs' | 'artifacts'
  | 'pipelines' | 'analysis' | 'build' | 'utils' | 'memory-profiling'
  | 'containers'
  | 'dynamic-analysis' | 'threat-intel' | 'threat-intel-bans' | 'threat-intel-apis'
  | 'vm' | 'qiling-vm' | 'clamd' | 'qiling'

interface NavEntry {
  id: PanelId
  label: string
  icon: IconName
}

const BUILT: PanelId[] = [
  'stats', 'overview', 'docs', 'system', 'network', 'endpoint-agents',
  'artifacts', 'pipelines',
  'analysis', 'dynamic-analysis', 'build', 'utils', 'containers', 'logs', 'vm',
  'qiling-vm', 'qiling', 'clamd', 'memory-profiling', 'threat-intel',
  'threat-intel-bans', 'threat-intel-apis',
]

// The virtual-machine section is generated from lib/vms.ts, so bringing a new
// sandbox online is an entry in that registry rather than an edit here. That
// is the whole point: this section keeps gaining machines.
//
// Only the MACHINES are listed there. ClamAV and the Qiling harness are guests
// on the Qiling VM, and they used to be appended to the same group - which
// put "Qiling VM" and "Qiling" one row apart, both opening the same panel, and
// left the guest Qiling entry with no route at all. They now sit under Dynamic
// Analysis, next to the policy that governs them, and this group is machines
// only.
const MACHINE_NAV: NavEntry[] = VM_TARGETS
  .filter((t) => !t.hostedOn && BUILT.includes(t.id as PanelId))
  .map((t) => ({ id: t.id as PanelId, label: t.label, icon: t.icon }))

const GUEST_NAV: NavEntry[] = VM_TARGETS
  .filter((t) => t.hostedOn && BUILT.includes(t.id as PanelId))
  .map((t) => ({ id: t.id as PanelId, label: t.label, icon: t.icon }))

// Grouped so each concern has a home.
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
    // Endpoints get their own section: the fleet is inspected on its own, and
    // it used to be buried as a tab inside Networking next to topology scans.
    group: 'Endpoints',
    items: [
      { id: 'endpoint-agents', label: 'Endpoint agents', icon: 'machine' },
    ],
  },
  {
    group: 'Analysis',
    items: [
      // Two pages, two levels, and the names say which is which:
      //
      //   Analysis Configuration   config/analysis.yaml - what EVERY run does
      //   Pipelines Configuration  pipelines/*.yaml     - what ONE kind of run does
      //
      // They were once one page called "Analysis Configuration" with a second
      // page called "Analysis settings", which is the same word twice for two
      // different scopes - so the pipeline page was named after the whole
      // category it did not own. They stay separate because the precedence
      // between them (.env < pipeline < analysis.yaml) is the confusing part,
      // and it should not look like the same control twice.
      { id: 'analysis', label: 'Analysis Configuration', icon: 'model' },
      { id: 'pipelines', label: 'Pipelines Configuration', icon: 'analyze' },
      { id: 'artifacts', label: 'Artifacts', icon: 'artifacts' },
      { id: 'build', label: 'Build', icon: 'build' },
    ],
  },
  {
    group: 'Threat Intelligence',
    items: [
      { id: 'threat-intel', label: 'Threat Intelligence Server', icon: 'server' },
      { id: 'threat-intel-bans', label: 'Available Users', icon: 'user' },
      { id: 'threat-intel-apis', label: 'API Configuration', icon: 'plug' },
    ],
  },
  {
    // The dynamic side: one policy, then the two things it governs. They are
    // not machines, so they are not in the fleet group above.
    group: 'Dynamic Analysis',
    items: [
      { id: 'dynamic-analysis', label: 'Configuration', icon: 'build' },
      ...GUEST_NAV,
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
      { id: 'memory-profiling', label: 'Memory profiling', icon: 'stats' },
    ],
  },
  {
    group: 'Infrastructure',
    items: [
      { id: 'containers', label: 'Containers', icon: 'containers' },
    ],
  },
  { group: 'Virtual Machines', items: MACHINE_NAV },
  { group: 'Diagnostics', items: [{ id: 'logs', label: 'Logs', icon: 'logs' }] },
]

const GROUP_OF: Partial<Record<PanelId, string>> = Object.fromEntries(
  NAV.flatMap((g) => g.items.map((i) => [i.id, g.group])),
)

const ALL_ITEMS = NAV.flatMap((g) => g.items)
const TITLES: Record<PanelId, string> = Object.fromEntries(
  ALL_ITEMS.map((i) => [i.id, i.label]),
) as Record<PanelId, string>

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
      <LogoSpinner />
      <p className="font-mono text-[10px] text-default-400">
        Loading {label.toLowerCase()}…
      </p>
    </div>
  )
}

export default function App() {
  const [panel, setPanel] = useState<PanelId>('stats')
  const [query, setQuery] = useState('')
  const [closed, setClosed] = useState<Record<string, boolean>>({})
  const [gate, setGate] = useState<'checking' | 'in' | 'out'>('checking')
  const [state, setState] = useState<Awaited<ReturnType<typeof auth.state>> | null>(null)
  // Hold the boot screen for a beat even when the server answers instantly, so
  // the opening reads as a deliberate moment rather than a flash.
  const [booted, setBooted] = useState(false)
  useEffect(() => {
    const t = setTimeout(() => setBooted(true), 1800)
    return () => clearTimeout(t)
  }, [])

  const cfg = usePoll(api.config, 60000)

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

  if (gate === 'checking' || !booted) {
    return <BootScreen />
  }

  if (gate === 'out') {
    return <Login onOk={() => void check()} />
  }

  const q = query.trim().toLowerCase()
  const groups = NAV.map((g) => ({
    ...g,
    items: q ? g.items.filter((it) => it.label.toLowerCase().includes(q)) : g.items,
  })).filter((g) => g.items.length > 0)
  const host = cfg.data ? `${cfg.data.panel.host}:${cfg.data.panel.port}` : null

  return (
    <div className="ui-shell">
      <aside className="ui-sidebar">
        <div className="ui-brand">
          <span className="ui-brand-mark" aria-hidden="true"><LogoMark height={16} /></span>
          <div className="ui-brand-text">
            <span className="ui-brand-name">Da Orks</span>
            <span className="ui-brand-tag">console</span>
          </div>
        </div>

        <label className="ui-search">
          <Icon name="search" size={14} />
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Find a page…"
            aria-label="Find a page"
          />
        </label>

        <nav className="ui-nav">
          {groups.map((g) => {
            const isClosed = !q && g.group && closed[g.group]
            return (
              <div key={g.group || 'main'} className="ui-nav-group">
                {g.group && (
                  <button
                    className="ui-nav-heading"
                    onClick={() => setClosed((c) => ({ ...c, [g.group]: !c[g.group] }))}
                    aria-expanded={!isClosed}
                  >
                    <span>{g.group}</span>
                    <span className={`ui-chev ${isClosed ? '' : 'open'}`}><Icon name="chevron" size={12} /></span>
                  </button>
                )}
                {!isClosed && g.items.map((it) => (
                  <button
                    key={it.id}
                    onClick={() => setPanel(it.id)}
                    className={`ui-nav-item ${panel === it.id ? 'active' : ''}`}
                    aria-current={panel === it.id ? 'page' : undefined}
                  >
                    <Icon name={it.icon} size={16} />
                    <span className="truncate">{it.label}</span>
                  </button>
                ))}
              </div>
            )
          })}
          {groups.length === 0 && <p className="ui-nav-empty">No page matches “{query}”.</p>}
        </nav>

        <div className="ui-sidebar-foot">
          <ThemeToggle />
          {state?.required && (
            <button onClick={() => void auth.logout().then(check)} className="btn-ghost" title="Sign out">
              <Icon name="logout" size={14} />
            </button>
          )}
        </div>
      </aside>

      <main className="ui-main">
        <header className="ui-topbar">
          <div className="ui-crumbs">
            <span>{GROUP_OF[panel] || 'Overview'}</span>
            <Icon name="chevron" size={12} />
            <strong>{TITLES[panel]}</strong>
          </div>
          <span className={`ui-status ${host ? 'ok' : 'down'}`}>
            <span className="ui-dot" />
            {host ? `Connected · ${host}` : 'Server not connected'}
          </span>
        </header>

        {!host && cfg.error && (
          <div className="ui-banner">
            <LogoMark height={16} className="ui-banner-mark" />
            <div>
              <strong>Can’t reach the analysis server.</strong>{' '}
              Pages will fill in with live data once the console runs alongside your server.
            </div>
          </div>
        )}

        <div className="ui-content" key={panel}>
          <PanelBoundary label={TITLES[panel]}>
            <Suspense fallback={<PanelFallback label={TITLES[panel]} />}>
            {panel === 'stats' && <Stats />}
            {panel === 'overview' && <Overview onNavigate={setPanel} />}
            {panel === 'docs' && <Documentation />}
            {panel === 'system' && <System />}
            {panel === 'network' && <Network />}
            {panel === 'endpoint-agents' && <EndpointAgents />}
            {panel === 'logs' && <Logs />}
            {panel === 'artifacts' && <Artifacts />}
            {panel === 'threat-intel' && <ThreatIntelligence />}
            {panel === 'threat-intel-bans' && <ThreatIntelligenceBans />}
            {panel === 'threat-intel-apis' && <ThreatIntelligenceApis />}
            {panel === 'analysis' && <AnalysisConfig />}
            {panel === 'memory-profiling' && <MemoryProfiling />}
            {panel === 'dynamic-analysis' && <DynamicAnalysisConfig />}
            {panel === 'pipelines' && <PipelinesConfig />}
            {panel === 'build' && <Build onNavigate={setPanel} />}
            {panel === 'utils' && <Utils />}
            {panel === 'containers' && <Containers />}
            {panel === 'vm' && <VM />}
            {(panel === 'qiling-vm' || panel === 'qiling') && (
              <QilingVM
                onOpenProfiler={() => setPanel('memory-profiling')}
                onNavigate={(next) => setPanel(next as PanelId)}
              />
            )}
            {panel === 'clamd' && <Clamd onNavigate={setPanel} />}
            </Suspense>
          </PanelBoundary>
        </div>
      </main>
    </div>
  )
}
