import { useEffect, useState } from 'react'
import { Chip } from '@heroui/react'
import { api, auth, usePoll } from './api'
import Icon, { type IconName } from './components/Icon'
import Overview from './panels/Overview'
import Documentation from './panels/Documentation'
import Stats from './panels/Stats'
import System from './panels/System'
import Network from './panels/Network'
import Logs from './panels/Logs'
import Artifacts from './panels/Artifacts'
import Containers from './panels/Containers'
import Clamd from './panels/Clamd'
import VM from './panels/VM'
import QilingVM from './panels/QilingVM'
import Login from './panels/Login'
import ThemeToggle from './components/ThemeToggle'
import { Placeholder } from './components/ServiceCard'
import { VM_TARGETS } from './lib/vms'

type PanelId =
  | 'overview' | 'docs' | 'stats' | 'system' | 'network' | 'logs' | 'artifacts'
  | 'analyze' | 'build' | 'model'
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
      { id: 'analyze', label: 'Analyze', icon: 'analyze', slice: 'slice 3' },
      { id: 'artifacts', label: 'Artifacts', icon: 'artifacts' },
      { id: 'build', label: 'Build', icon: 'build', slice: 'slice 6' },
      { id: 'model', label: 'Model', icon: 'model', slice: 'slice 6' },
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
  'stats', 'overview', 'docs', 'system', 'network', 'artifacts', 'containers', 'logs', 'vm', 'qiling-vm', 'clamd',
]

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
                {cfg.data ? `${cfg.data.panel.host}:${cfg.data.panel.port}` : 'connecting…'}
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
                      title={it.slice ? `${it.label} — planned for ${it.slice}` : it.label}
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
          {panel === 'stats' && <Stats />}
          {panel === 'overview' && <Overview />}
          {panel === 'docs' && <Documentation />}
          {panel === 'system' && <System />}
          {panel === 'network' && <Network />}
          {panel === 'logs' && <Logs />}
          {panel === 'artifacts' && <Artifacts />}
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
        </main>
      </div>
    </>
  )
}