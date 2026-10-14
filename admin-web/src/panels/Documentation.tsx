import { useMemo, useRef, useState } from 'react'
import { Alert, Button, Card, Chip } from '@heroui/react'
import { api, usePoll } from '../api'
import SubNav from '../components/SubNav'
import Loading from '../components/Loading'
import NetFactsPanel from '../components/NetFacts'
import Icon from '../components/Icon'
import { ms } from '../lib/format'
import type { DocCapability, DocRoute, DocService, HttpMethod, RouteParams } from '../types'

// ---------------------------------------------------------------------------
// Documentation - every endpoint this lab exposes, as one browsable reference.
//
// The point is that it is TRUE. The panel's own routes come from introspecting
// the live Flask URL map and pulling each view function's docstring, and the
// analyzer's capabilities are fetched from the running service when it answers.
// So this page cannot describe a route that was deleted or miss one that was
// added - which is the normal failure mode of hand-written API docs.
//
// Three tabs, split by who owns the endpoint:
//   Services   the third-party services and where they answer
//   APIs       every HTTP surface in the lab, tab by service
// ---------------------------------------------------------------------------

// 15s, not 5s: the route tables are static, but the service rows carry live
// probe status, and nothing here changes faster than a service going down.
const INTERVAL = 15000

type Tab = 'services' | 'apis'
type ApiKey = 'panel' | 'analyzer' | 'malapi' | 'ml' | 'cyberchef'
type View = 'list' | 'swagger'

const API_TABS: { key: ApiKey; label: string }[] = [
  { key: 'panel', label: 'Panel' },
  { key: 'analyzer', label: 'Analyzer' },
  { key: 'malapi', label: 'MalAPI' },
  { key: 'ml', label: 'ML scorer' },
  { key: 'cyberchef', label: 'CyberChef' },
]

const METHOD_TONE: Record<HttpMethod, string> = {
  GET: 'bg-success/12 text-success',
  POST: 'bg-accent/12 text-accent',
  PUT: 'bg-warning/12 text-warning',
  PATCH: 'bg-warning/12 text-warning',
  DELETE: 'bg-danger/12 text-danger',
}

// Copy that works on plain HTTP loopback, where navigator.clipboard is absent.
function useCopy() {
  const [copied, setCopied] = useState<string | null>(null)
  const copy = async (text: string, tag: string) => {
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(text)
      } else {
        const el = document.createElement('textarea')
        el.value = text
        el.style.position = 'fixed'
        el.style.opacity = '0'
        document.body.appendChild(el)
        el.select()
        document.execCommand('copy')
        document.body.removeChild(el)
      }
      setCopied(tag)
      window.setTimeout(() => setCopied(null), 1500)
    } catch {
      setCopied(null)
    }
  }
  return { copied, copy }
}

function MethodBadge({ method }: { method: HttpMethod }) {
  return (
    <span
      className={`rounded px-1.5 py-0.5 font-mono text-[10px] font-semibold ${METHOD_TONE[method]}`}
    >
      {method}
    </span>
  )
}

function CopyPill({
  text,
  label,
  onCopy,
  copied,
}: {
  text: string
  label: string
  onCopy: (t: string, tag: string) => void
  copied: string | null
}) {
  const tag = `${label}:${text.length}`
  const isCopied = copied === tag
  return (
    <button
      onClick={(e) => {
        e.stopPropagation()
        onCopy(text, tag)
      }}
      className={`shrink-0 rounded border px-1.5 py-0.5 text-[10px] font-medium transition-colors ${
        isCopied
          ? 'border-success/40 text-success'
          : 'border-default-200 text-default-400 hover:border-accent hover:text-accent'
      }`}
    >
      {isCopied ? 'copied' : label}
    </button>
  )
}

const PARAM_GROUPS: { key: 'path' | 'query' | 'form' | 'fields'; label: string }[] = [
  { key: 'path', label: 'path' },
  { key: 'query', label: 'query' },
  { key: 'form', label: 'form' },
  { key: 'fields', label: 'body' },
]

/**
 * Parameter chips for one route, always visible on the collapsed row.
 *
 * A path placeholder is already in the route string, so it is marked rather than
 * repeated; query/form/body names are not visible anywhere else, which is the
 * gap this closes - `?lines=` and `?pipeline=` were both undiscoverable from the
 * route alone.
 */
function ParamChips({ params }: { params?: RouteParams }) {
  if (!params) return null
  const hasAny =
    params.path?.length ||
    params.query?.length ||
    params.form?.length ||
    params.fields?.length ||
    params.body
  if (!hasAny) {
    return <span className="text-[10px] text-default-400">no parameters</span>
  }
  return (
    <span className="flex flex-wrap items-center gap-1">
      {PARAM_GROUPS.map(({ key, label }) => {
        const values = (params[key] as string[] | undefined) ?? []
        if (!values.length) return null
        return values.map((v) => (
          <span
            key={`${label}-${v}`}
            title={`${label} parameter`}
            className={`rounded px-1.5 py-px font-mono text-[10px] ${
              key === 'path'
                ? 'bg-accent/10 text-accent'
                : key === 'fields'
                  ? 'bg-warning/12 text-warning'
                  : 'bg-default-200 text-default-600'
            }`}
          >
            {key === 'path' ? '‹' : key === 'fields' ? 'body:' : '?'}
            {v}
            {key === 'path' ? '›' : ''}
          </span>
        ))
      })}
      {params.body && !params.fields?.length && (
        <span className="rounded bg-warning/12 px-1.5 py-px text-[10px] text-warning">
          {params.body}
        </span>
      )}
    </span>
  )
}

/** One documented HTTP route. Collapsed to a row; expands to a copyable curl. */
function RouteRow({
  route,
  base,
  onCopy,
  copied,
  open,
  onToggle,
}: {
  route: DocRoute
  base: string
  onCopy: (t: string, tag: string) => void
  copied: string | null
  open: boolean
  onToggle: () => void
}) {
  const url = base + route.path
  // Only reads are offered as an openable link: following a POST with a browser
  // is not something this page should ever make easy.
  const canOpen = route.method === 'GET' && !route.path.includes('<')
  // Show the query keys in the example, so the shape of a real call is visible
  // rather than a bare path that returns the wrong thing when copied.
  const qs = route.params?.query?.length
    ? `?${route.params.query.map((k) => `${k}=`).join('&')}`
    : ''
  const example = route.method === 'GET'
    ? `${url}${qs}`
    : `curl -X ${route.method} "${url}${qs}"${route.params?.body ? ` \\\n  --data '{"...": ...}'` : ''}`
  const curl = route.method === 'GET' ? `curl ${example}` : example

  return (
    <div
      className="cursor-pointer border-b border-default-100 px-3 py-2.5 last:border-0 hover:bg-default-50/50"
      onClick={onToggle}
    >
      <div className="flex items-center gap-3">
        <MethodBadge method={route.method} />
        <code className="min-w-0 flex-1 truncate font-mono text-[12px] text-foreground">
          {route.path}
        </code>
        {canOpen && (
          <a
            href={route.path}
            target="_blank"
            rel="noreferrer noopener"
            onClick={(e) => e.stopPropagation()}
            title="Open in a new tab"
            className="shrink-0 text-default-400 hover:text-accent"
          >
            <Icon name="chevron" size={12} />
          </a>
        )}
        <span className="text-default-400">
          <Icon name={open ? 'chevron' : 'search'} size={11} className={open ? 'rotate-90' : ''} />
        </span>
      </div>

      {route.summary && !open && (
        <p className="mt-1 truncate pl-[4.1rem] text-[11px] text-default-400">
          {route.summary}
        </p>
      )}

      {/* Parameters stay visible when collapsed: a query string is not
          discoverable from the route path, and that is the thing people
          actually need to build a working call. */}
      {!open && (
        <div className="mt-1 pl-[4.1rem]">
          <ParamChips params={route.params} />
        </div>
      )}

      {open && (
        <div className="mt-2 flex flex-col gap-2 pl-[4.1rem]" onClick={(e) => e.stopPropagation()}>
          {route.summary && (
            <p className="text-[12px] leading-relaxed text-default-500">{route.summary}</p>
          )}
          {route.params && <ParamChips params={route.params} />}
          {route.endpoint && (
            <p className="text-[11px] text-default-400">
              <span className="text-default-500">Handler: </span>
              <code className="font-mono">{route.endpoint}</code>
              {route.line ? (
                <span className="ml-2 opacity-60">
                  {route.source === 'code' ? `app.py:${route.line}` : 'described here'}
                </span>
              ) : null}
            </p>
          )}
          <div className="flex items-center gap-2 rounded-md border border-default-200 bg-default-50/50 px-2 py-1.5">
            <code className="min-w-0 flex-1 break-all font-mono text-[11px] text-default-600">
              {curl}
            </code>
            <CopyPill text={curl} label="curl" onCopy={onCopy} copied={copied} />
          </div>
        </div>
      )}
    </div>
  )
}

function ServiceRow({
  s,
  onCopy,
  copied,
  open,
  onToggle,
}: {
  s: DocService
  onCopy: (t: string, tag: string) => void
  copied: string | null
  open: boolean
  onToggle: () => void
}) {
  return (
    <div
      className="cursor-pointer border-b border-default-100 px-3 py-2.5 last:border-0 hover:bg-default-50/50"
      onClick={onToggle}
    >
      <div className="flex items-center gap-3">
        <span
          className={`h-2 w-2 shrink-0 rounded-full ${
            s.up ? (s.code === 'auth' ? 'bg-warning' : 'bg-success') : 'bg-danger'
          }`}
          title={s.up ? `up · ${s.code}` : 'down'}
        />
        <span className="min-w-0 flex-1 truncate text-[13px] font-medium">{s.name}</span>
        <code className="shrink-0 font-mono text-[11px] text-default-400">
          {s.host}:{s.port}
        </code>
        <span className="w-14 shrink-0 text-right font-mono text-[11px] text-default-400">
          {s.up ? ms(s.ms) : '—'}
        </span>
      </div>

      {/* IP/port detail lives on the Services cards, where every endpoint is listed
          without a click. Here it stays in the expanded view - this page is a
          reference, and ten always-visible strips would bury the route list. */}
      {open && (
        <div className="mt-2 flex flex-col gap-2 pl-5" onClick={(e) => e.stopPropagation()}>
          <p className="text-[12px] leading-relaxed text-default-500">{s.description}</p>
          <div className="flex flex-wrap items-center gap-1.5">
            <Chip size="sm" variant="soft">{s.role}</Chip>
            <Chip size="sm" variant="soft">{s.kind === 'tcp' ? 'TCP connect' : 'HTTP GET'}</Chip>
          </div>
          <NetFactsPanel net={s.net} />
          <div className="flex items-center gap-2 rounded-md border border-default-200 bg-default-50/50 px-2 py-1.5">
            <code className="min-w-0 flex-1 truncate font-mono text-[11px] text-default-600">
              {s.endpoint}
            </code>
            <CopyPill text={s.endpoint} label="copy" onCopy={onCopy} copied={copied} />
          </div>
        </div>
      )}
    </div>
  )
}

function CapabilityRow({
  c,
  base,
  onCopy,
  copied,
}: {
  c: DocCapability
  base: string
  onCopy: (t: string, tag: string) => void
  copied: string | null
}) {
  const url = base + (c.endpoint || `/capabilities/${c.name}`)
  return (
    <div className="border-b border-default-100 px-3 py-2.5 last:border-0">
      <div className="flex items-center gap-3">
        <MethodBadge method="POST" />
        <span className="min-w-0 flex-1 truncate font-mono text-[12px] text-foreground">
          {c.endpoint || `/capabilities/${c.name}`}
        </span>
        {c.alias && (
          <code className="shrink-0 font-mono text-[10px] text-default-400">or {c.alias}</code>
        )}
        <CopyPill text={url} label="copy" onCopy={onCopy} copied={copied} />
      </div>
      <p className="mt-1 pl-[4.1rem] text-[11px] text-default-400">{c.summary}</p>
      {c.phases.length > 0 && (
        <p className="mt-0.5 pl-[4.1rem] font-mono text-[10px] text-default-400">
          phases: {c.phases.join(', ')}
        </p>
      )}
    </div>
  )
}

export default function Documentation() {
  const [tab, setTab] = useState<Tab>('services')
  const [apiKey, setApiKey] = useState<ApiKey>('panel')
  const [view, setView] = useState<View>('list')
  const [q, setQ] = useState('')
  const [openKey, setOpenKey] = useState<string | null>(null)
  const searchRef = useRef<HTMLInputElement>(null)
  const { data, error, loading, refresh } = usePoll(api.docs, INTERVAL)
  const { copied, copy } = useCopy()

  const term = q.trim().toLowerCase()

  const services = useMemo(
    () =>
      (data?.services ?? []).filter((s) =>
        !term
          ? true
          : `${s.name} ${s.key} ${s.host} ${s.port} ${s.role} ${s.description} ${s.endpoint}`
              .toLowerCase()
              .includes(term),
      ),
    [data, term],
  )

  const current = data ? data[apiKey] : undefined

  // MalAPI's ~550 routes collapse into two families. The server now sends the
  // list ONCE with a `family` flag on the rows that stand for a pattern, so
  // without a filter the families are the readable view; typing switches to the
  // full list, because "is there a route for CreateProcessWithTokenW" is
  // exactly what the filter is asked and a pattern cannot answer it.
  const routes = useMemo(() => {
    if (!current) return []
    const all = current.routes ?? []
    const source = term ? all : all.filter((r) => !r.family)
    return source.filter((r) =>
      !term ? true : `${r.method} ${r.path} ${r.summary} ${r.handler ?? ''}`.toLowerCase().includes(term),
    )
  }, [current, term])

  const caps = useMemo(
    () =>
      (data?.analyzer.capabilities ?? []).filter((c) =>
        !term ? true : `${c.name} ${c.summary} ${c.endpoint}`.toLowerCase().includes(term),
      ),
    [data, term],
  )

  const shown =
    tab === 'services'
      ? services.length
      : routes.length + (apiKey === 'analyzer' ? caps.length : 0)

  const total =
    tab === 'services'
      ? (data?.services.length ?? 0)
      : (current?.count ?? 0) +
        (apiKey === 'analyzer' ? (data?.analyzer.capabilities?.length ?? 0) : 0)

  return (
    <>
      <div className="mb-4 flex items-baseline justify-between gap-4">
        <h2 className="page-title">Documentation</h2>
        <div className="flex items-center gap-3">
          <span className="font-mono text-[11px] text-default-400">
            introspected from the live routes
          </span>
          <Button size="sm" variant="outline" onPress={refresh}>
            Refresh
          </Button>
        </div>
      </div>

      <SubNav
        tabs={[
          { id: 'services', label: 'Services', icon: 'services' },
          {
            id: 'apis',
            label: 'APIs',
            icon: 'artifacts',
            tone: data && !data.bases.analyzer ? 'warn' : undefined,
          },
        ]}
        active={tab}
        onChange={(id) => setTab(id as Tab)}
      />

      {/* API selector - a tab per HTTP surface, each with its own provenance */}
      {data && tab === 'apis' && (
        <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
          {/* List vs Swagger UI. Swagger is the merged spec for ALL five
              services, so the per-service picker is only meaningful in list
              view - showing it above the UI would imply the UI is filtered. */}
          {view === 'list' ? (
            <div className="flex flex-wrap items-center gap-1.5">
              {API_TABS.map((t) => {
                const svc = data[t.key]
                const on = apiKey === t.key
                return (
                  <button
                    key={t.key}
                    onClick={() => setApiKey(t.key)}
                    className={`flex items-center gap-2 rounded-lg border px-3 py-1.5 text-[12px] font-medium transition-colors ${
                      on
                        ? 'border-accent bg-accent/10 text-foreground'
                        : 'border-default-200 text-default-500 hover:border-default-300 hover:text-foreground'
                    }`}
                  >
                    <span
                      className={`h-1.5 w-1.5 rounded-full ${svc.up ? 'bg-success' : 'bg-default-300'}`}
                      title={svc.up ? 'answering' : 'not answering'}
                    />
                    {t.label}
                    <span className="font-mono text-[10px] text-default-400">{svc.count}</span>
                  </button>
                )
              })}
            </div>
          ) : (
            <span className="font-mono text-[11px] text-default-400">
              merged OpenAPI 3.0 · all services
            </span>
          )}

          <div className="flex items-center gap-2">
            <div className="flex overflow-hidden rounded-lg border border-default-200">
              {(
                [
                  ['list', 'List'],
                  ['swagger', 'Swagger UI'],
                ] as [View, string][]
              ).map(([id, label]) => (
                <button
                  key={id}
                  onClick={() => setView(id)}
                  className={`px-2.5 py-1.5 text-[11px] font-medium transition-colors ${
                    view === id
                      ? 'bg-accent/12 text-foreground'
                      : 'text-default-500 hover:bg-default-100 hover:text-foreground'
                  }`}
                >
                  {label}
                </button>
              ))}
            </div>
            <a
              href="/api/openapi.json"
              target="_blank"
              rel="noreferrer noopener"
              className="rounded-md border border-default-200 px-2 py-1.5 text-[11px] text-default-500 hover:border-accent hover:text-accent"
            >
              raw spec ↗
            </a>
          </div>
        </div>
      )}

      {error && (
        <Alert status="danger" className="mb-4">
          <Alert.Title>Cannot build the endpoint reference</Alert.Title>
          <Alert.Description>{error}</Alert.Description>
        </Alert>
      )}

      {loading && !data && <Loading label="Loading documentation…" hint="walking the live route map" />}

      {data && (
        <>
          {/* toolbar */}
{tab !== 'services' && view === 'list' && (
          <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
            <div className="relative">
              <Icon
                name="search"
                size={13}
                className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-default-400"
              />
              <input
                ref={searchRef}
                value={q}
                onChange={(e) => setQ(e.target.value)}
                placeholder="Filter endpoints…  /"
                aria-label="Filter endpoints"
                className="w-56 rounded-lg border border-default-200 bg-surface/60 py-1.5 pl-8 pr-7 text-xs outline-none transition-colors placeholder:text-default-400 focus:border-accent"
              />
              {q && (
                <button
                  onClick={() => setQ('')}
                  aria-label="Clear filter"
                  className="absolute right-2 top-1/2 -translate-y-1/2 text-default-400 hover:text-foreground"
                >
                  <Icon name="refresh" size={11} />
                </button>
              )}
            </div>
            <p className="font-mono text-[11px] text-default-400">
              showing {shown} of {total}
              {tab === 'apis' && current && (
                <span className="ml-2 text-default-400">· {current.source}</span>
              )}
              {tab === 'apis' && apiKey === 'panel' && (data.panel.spa_shell?.length ?? 0) > 0 && (
                <span className="ml-2 text-default-400">
                  (+ the React bundle at {data.panel.spa_shell?.join(', ')})
                </span>
              )}
              {tab === 'apis' && apiKey === 'malapi' && !term && (
                <span className="ml-2 text-default-400">
                  · search to expand the {current?.count} collapsed routes
                </span>
              )}
            </p>
          </div>
          )}

          {/* --- services --- */}
          {tab === 'services' && (
            <Card className="w-full">
              <Card.Header>
                <Card.Title>Service endpoints</Card.Title>
              </Card.Header>
              <Card.Content className="px-0">
                {services.length === 0 ? (
                  <p className="px-3 py-6 text-center text-[12px] text-default-400">
                    No service matches that filter.
                  </p>
                ) : (
                  services.map((s) => (
                    <ServiceRow
                      key={s.key}
                      s={s}
                      onCopy={copy}
                      copied={copied}
                      open={openKey === `svc-${s.key}`}
                      onToggle={() =>
                        setOpenKey((k) => (k === `svc-${s.key}` ? null : `svc-${s.key}`))
                      }
                    />
                  ))
                )}
              </Card.Content>
            </Card>
          )}

          {/* --- every HTTP surface, one tab per service --- */}
          {tab === 'apis' && view === 'list' && current && (
            <div className="flex flex-col gap-3">
              <Card className="w-full">
                <Card.Header className="flex flex-wrap items-center justify-between gap-3">
                  <Card.Title className="truncate">
                    {API_TABS.find((t) => t.key === apiKey)?.label} API
                    <span className="ml-2 font-mono text-[11px] font-normal text-default-400">
                      {current.base}
                    </span>
                  </Card.Title>
                  <div className="flex items-center gap-2">
                    <Chip size="sm" variant="soft" color={current.up ? 'success' : 'default'}>
                      {current.up ? 'reachable' : 'down'}
                    </Chip>
                    <Chip size="sm" variant="soft">{current.count} routes</Chip>
                    {current.auth && (
                      <Chip size="sm" variant="soft" color="warning" title="Probed with a bearer token">
                        token
                      </Chip>
                    )}
                  </div>
                </Card.Header>
                <Card.Content className="px-0">
                  {routes.length === 0 ? (
                    <p className="px-3 py-6 text-center text-[12px] text-default-400">
                      No route matches that filter.
                    </p>
                  ) : (
                    routes.map((r) => {
                      const key = `${apiKey}-${r.method}-${r.path}`
                      return (
                        <RouteRow
                          key={key}
                          route={r}
                          base={current.base}
                          onCopy={copy}
                          copied={copied}
                          open={openKey === key}
                          onToggle={() => setOpenKey((k) => (k === key ? null : key))}
                        />
                      )
                    })
                  )}
                </Card.Content>
              </Card>

              {apiKey === 'analyzer' && caps.length > 0 && (
                <Card className="w-full">
                  <Card.Header className="flex items-center justify-between gap-3">
                    <Card.Title>Capabilities</Card.Title>
                    <Chip size="sm" variant="soft" color={data.analyzer.capabilities_live ? 'success' : 'warning'}>
                      {data.analyzer.capabilities_live ? 'from live /capabilities' : 'offline fallback'}
                    </Chip>
                  </Card.Header>
                  <Card.Content className="px-0">
                    {caps.map((c) => (
                      <CapabilityRow
                        key={c.name}
                        c={c}
                        base={data.analyzer.base}
                        onCopy={copy}
                        copied={copied}
                      />
                    ))}
                  </Card.Content>
                </Card>
              )}
            </div>
          )}
          {/* --- Swagger UI, embedded in the APIs tab ---------------------- */}
          {tab === 'apis' && view === 'swagger' && (
            <Card className="w-full">
              <Card.Header className="flex flex-wrap items-center justify-between gap-3">
                <Card.Title>
                  Swagger UI
                  <span className="ml-2 font-mono text-[11px] font-normal text-default-400">
                    flasgger · merged spec for every service
                  </span>
                </Card.Title>
                <div className="flex items-center gap-2">
                  <a
                    href="/apispec_1.json"
                    target="_blank"
                    rel="noreferrer noopener"
                    className="rounded-full border border-default-200 px-2 py-0.5 text-[10px] font-medium text-default-500 hover:border-accent hover:text-accent"
                  >
                    raw spec ↗
                  </a>
                  <a
                    href="/apidocs/"
                    target="_blank"
                    rel="noreferrer noopener"
                    className="rounded-full border border-default-200 px-2 py-0.5 text-[10px] font-medium text-default-500 hover:border-accent hover:text-accent"
                  >
                    open full page ↗
                  </a>
                </div>
              </Card.Header>
              <Card.Content>
                {/*
                  flasgger serves the Swagger UI from a CDN by default. On a host
                  with no outbound network the frame below renders blank, so the
                  notice stays visible above it rather than being an empty box
                  that looks like a broken panel - /apispec_1.json always works
                  and is one click away.
                */}
                <p className="mb-3 rounded-md border border-default-200 bg-default-50/60 px-3 py-2 text-[11px] leading-relaxed text-default-500">
                  Rendered from <code>/api/openapi.json</code> — one OpenAPI 3.0
                  document covering the panel, analyzer, ML, CyberChef and
                  MalAPI. Paths are prefixed per service and each operation
                  carries its real base URL, so <strong>Try it out</strong> posts
                  to the right place. MalAPI's 547 generated routes are two
                  documented patterns here; the full names are searchable in
                  List view.
                </p>
                <iframe
                  src="/apidocs/"
                  title="Swagger UI"
                  className="h-[70vh] w-full rounded-lg border border-default-200 bg-white"
                />
              </Card.Content>
            </Card>
          )}
        </>
      )}
    </>
  )
}