import { useEffect, useMemo, useState } from 'react'
import { Button } from '@heroui/react/button'
import { Card } from '@heroui/react/card'
import { Chip } from '@heroui/react/chip'
import Icon, { type IconName } from './Icon'
import Pager, { usePaged } from './Pager'
import YamlView from './YamlView'
import type { ComposeFile, ComposeService } from '../types'

/** Cards per page in the Services tab. Six is two full rows of three, so paging
 *  only ever engages for a compose file with an unusual number of services -
 *  the common three-service case stays a single un-paged screen. */
const SERVICES_PER_PAGE = 6

// ---------------------------------------------------------------------------
// Compose file viewer.
//
// The YAML tab is components/YamlView.tsx, which the analysis-configuration page
// shares: one implementation, so the same file reads the same way wherever it
// is opened.
// ---------------------------------------------------------------------------

// --- services tab ---------------------------------------------------------

/** Icon per known compose key, purely for scanning. Unknown keys still render. */
const FIELD_ICON: Record<string, IconName> = {
  image: 'image',
  build: 'build',
  ports: 'network',
  environment: 'variable',
  volumes: 'database',
  networks: 'link',
  depends_on: 'git-merge',
  restart: 'rotate-cw',
  command: 'terminal',
  entrypoint: 'play',
  working_dir: 'folder',
  user: 'user',
  healthcheck: 'activity',
  deploy: 'rocket',
  labels: 'tag',
}

const scalar = (v: unknown): string =>
  typeof v === 'string' ? v : typeof v === 'object' && v !== null ? JSON.stringify(v) : String(v)

const emptyish = (v: unknown): boolean =>
  v === null || v === undefined || v === '' ||
  (Array.isArray(v) && v.length === 0) ||
  (typeof v === 'object' && v !== null && !Array.isArray(v) && Object.keys(v).length === 0)

/** Render whatever PyYAML gave us, without assuming a shape: scalars as code,
 *  flat lists as chips, and mappings as aligned key/value rows. */
function ValueView({ value }: { value: unknown }) {
  if (value === null || value === undefined) {
    return <span className="text-default-400">—</span>
  }
  if (typeof value !== 'object') {
    return <code>{scalar(value)}</code>
  }
  if (Array.isArray(value)) {
    if (value.length === 0) return <span className="text-default-400">empty</span>
    if (value.every((v) => v === null || typeof v !== 'object')) {
      return (
        <div className="flex flex-wrap gap-1">
          {value.map((v, i) => <code className="compose-chip" key={i} title={scalar(v)}>{scalar(v)}</code>)}
        </div>
      )
    }
    return (
      <dl className="compose-kv">
        {value.map((v, i) => (
          <div className="compose-kv-row" key={i}>
            <dt>{i}</dt>
            <dd title={scalar(v)}>{scalar(v)}</dd>
          </div>
        ))}
      </dl>
    )
  }
  const entries = Object.entries(value as Record<string, unknown>)
  if (entries.length === 0) return <span className="text-default-400">empty</span>
  return (
    <dl className="compose-kv">
      {entries.map(([k, v]) => (
        <div className="compose-kv-row" key={k}>
          <dt title={k}>{k}</dt>
          <dd className={emptyish(v) ? 'text-default-400' : ''} title={scalar(v)}>
            {emptyish(v) ? '—' : scalar(v)}
          </dd>
        </div>
      ))}
    </dl>
  )
}

function ServiceCard({ service, running }: { service: ComposeService; running: boolean }) {
  const entries = Object.entries(service.config)
  const image = typeof service.config.image === 'string' ? service.config.image : null
  const ports = Array.isArray(service.config.ports) ? service.config.ports.length : 0

  return (
    <Card className="compose-service-card w-full">
      <div className="compose-service-card-head">
        <span className="compose-service-card-icon" aria-hidden="true">
          <Icon name="server" size={15} />
        </span>
        <div className="min-w-0 flex-1">
          <h4 className="truncate font-mono" title={service.name}>{service.name}</h4>
          {image && (
            <p className="truncate font-mono text-[10px] text-default-400" title={image}>{image}</p>
          )}
        </div>
        {running && (
          <Chip size="sm" variant="soft" color="success">running</Chip>
        )}
        {ports > 0 && (
          <Chip size="sm" variant="soft">{ports} port{ports === 1 ? '' : 's'}</Chip>
        )}
      </div>

      <div className="compose-service-card-body">
        {entries.length === 0 ? (
          <p className="text-[11px] text-default-400">No configuration.</p>
        ) : (
          entries.map(([key, value]) => (
            <div className="compose-field" key={key}>
              <div className="compose-field-label">
                <Icon name={FIELD_ICON[key] ?? 'chevron'} size={12} />
                <span>{key}</span>
              </div>
              <div className="compose-field-value">
                <ValueView value={value} />
              </div>
            </div>
          ))
        )}
      </div>
    </Card>
  )
}

function ServicesTab({
  services,
  runningServices,
}: {
  services: ComposeService[]
  runningServices: Set<string>
}) {
  const [query, setQuery] = useState('')

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase()
    if (!q) return services
    return services.filter((s) => {
      const image = typeof s.config.image === 'string' ? s.config.image : ''
      return (
        s.name.toLowerCase().includes(q) ||
        image.toLowerCase().includes(q) ||
        Object.keys(s.config).some((k) => k.toLowerCase().includes(q))
      )
    })
  }, [services, query])

  // Paged like every other list on this console. The whole compose file is
  // already in the browser, so this is client-side on purpose - there is no
  // paged endpoint to talk to and a compose file is a few KB, not a table.
  const paged = usePaged(filtered, SERVICES_PER_PAGE)

  // Columns follow the number of cards on this page, capped at 3: past that the
  // cards get too narrow to read, and the dialog stops being allowed to grow.
  const columns = Math.max(1, Math.min(3, paged.slice.length))

  return (
    <div className="compose-viewer-pane">
      <div className="compose-viewer-scroll">
        {services.length > 3 && (
          <div className="compose-viewer-search">
            <Icon name="filter" size={13} className="text-default-400" />
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Filter services, images or keys…"
              aria-label="Filter services"
            />
            {query && (
              <button type="button" onClick={() => setQuery('')} aria-label="Clear filter">
                <Icon name="x" size={12} />
              </button>
            )}
          </div>
        )}

        {paged.slice.length === 0 ? (
          <p className="compose-viewer-empty">
            {services.length === 0
              ? 'No services block found in this file.'
              : `No service matches “${query}”.`}
          </p>
        ) : (
          <>
            <div
              className="compose-service-grid"
              style={{ '--cols': columns } as React.CSSProperties}
            >
              {paged.slice.map((service) => (
                <ServiceCard
                  key={service.name}
                  service={service}
                  running={runningServices.has(service.name)}
                />
              ))}
            </div>
            <Pager
              page={paged.page}
              pages={paged.pages}
              first={paged.first}
              last={paged.last}
              total={filtered.length}
              onPrev={paged.prev}
              onNext={paged.next}
            />
          </>
        )}
      </div>
    </div>
  )
}

// --- modal ----------------------------------------------------------------

export default function ComposeFileViewer({
  isOpen,
  onClose,
  projectLabel,
  filePath,
  fetchContent,
  runningServices,
}: {
  isOpen: boolean
  onClose: () => void
  projectLabel: string
  filePath: string
  fetchContent: () => Promise<ComposeFile | null>
  /** Service names up right now, from the page's own poll - not from the
   *  compose endpoint, which stays a pure file read. */
  runningServices: Set<string>
}) {
  const [raw, setRaw] = useState<ComposeFile | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [tab, setTab] = useState<'services' | 'yaml'>('services')
  const [copied, setCopied] = useState(false)

  // A panel started before this endpoint existed serves the older payload: no
  // `spans`, and services as a flat object rather than {name, config}. Reading
  // those fields unguarded threw inside render and left the dialog blank, which
  // reads as "the content is not showing" rather than as a version mismatch.
  // Normalising here degrades a stale panel to uncoloured YAML instead.
  const content = useMemo(() => {
    if (!raw) return null
    const services = (raw.services ?? []).map((s, i) => {
      // Pre-`config` shape: the allowlisted fields were the config. `undefined`
      // is dropped because it would render as the literal text "undefined";
      // null is kept, since `key: null` is a real YAML value.
      const flat = Object.fromEntries(
        Object.entries(s ?? {}).filter(([k, v]) => k !== 'name' && v !== undefined),
      )
      return {
        name: s?.name ?? `service-${i + 1}`,
        config:
          s && typeof s.config === 'object' && s.config !== null ? s.config : flat,
      }
    })
    return { ...raw, spans: raw.spans ?? [], services }
  }, [raw])

  const load = async () => {
    setLoading(true)
    setError(null)
    try {
      setRaw(await fetchContent())
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not read the compose file')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    if (!isOpen) {
      setRaw(null)
      setError(null)
      setTab('services')
      setCopied(false)
      return
    }
    if (!raw && !loading) void load()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isOpen])

  // Escape closes, matching every other dialog on the console.
  useEffect(() => {
    if (!isOpen) return
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [isOpen, onClose])

  const copy = async () => {
    if (!content) return
    try {
      // navigator.clipboard is unavailable on a non-secure origin, and this
      // panel is plain HTTP on loopback, so the textarea path is the one that
      // actually runs - same fallback ServiceCard uses.
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(content.content)
      } else {
        const el = document.createElement('textarea')
        el.value = content.content
        el.style.position = 'fixed'
        el.style.opacity = '0'
        document.body.appendChild(el)
        el.select()
        document.execCommand('copy')
        document.body.removeChild(el)
      }
      setCopied(true)
      window.setTimeout(() => setCopied(false), 1600)
    } catch {
      setCopied(false)
    }
  }

  if (!isOpen) return null

  const lineCount = content ? content.content.split('\n').length : 0

  return (
    <div
      className="compose-viewer-backdrop"
      role="dialog"
      aria-modal="true"
      aria-labelledby="compose-viewer-title"
      onClick={onClose}
    >
      <div className="compose-viewer-panel" onClick={(e) => e.stopPropagation()}>
        <header className="compose-viewer-header">
          <div className="flex min-w-0 items-center gap-3">
            <span className="compose-file-icon" aria-hidden="true">
              <Icon name="file-code" size={16} />
            </span>
            <div className="min-w-0">
              <p className="text-sm font-semibold" id="compose-viewer-title">{projectLabel}</p>
              <p className="compose-file-path" title={filePath}>{filePath}</p>
            </div>
          </div>
          <div className="flex shrink-0 items-center gap-1.5">
            {content && (
              <>
                <Chip size="sm" variant="soft">{content.services.length} services</Chip>
                <Chip size="sm" variant="soft">{lineCount} lines</Chip>
              </>
            )}
            <button
              type="button"
              onClick={onClose}
              className="compose-viewer-close"
              aria-label="Close viewer"
            >
              <Icon name="x" size={15} />
            </button>
          </div>
        </header>

        {loading && (
          <div className="flex flex-1 flex-col items-center justify-center gap-3 p-12">
            <div className="h-8 w-8 animate-spin rounded-full border-2 border-accent border-t-transparent" />
            <span className="text-xs text-default-500">Reading compose file…</span>
          </div>
        )}

        {error && !loading && (
          <div className="flex flex-1 flex-col items-center justify-center gap-3 p-12 text-center">
            <Icon name="alert-circle" size={28} className="text-danger" />
            <span className="text-xs text-danger">{error}</span>
            <Button size="sm" variant="outline" onPress={load}>Retry</Button>
          </div>
        )}

        {content && !loading && !error && (
          <>
            <div className="compose-viewer-tabs" role="tablist">
              <button
                type="button"
                role="tab"
                aria-selected={tab === 'services'}
                className="compose-viewer-tab"
                onClick={() => setTab('services')}
              >
                Services
                <span className="compose-viewer-tab-count">{content.services.length}</span>
              </button>
              <button
                type="button"
                role="tab"
                aria-selected={tab === 'yaml'}
                className="compose-viewer-tab"
                onClick={() => setTab('yaml')}
              >
                Raw YAML
                <span className="compose-viewer-tab-count">{lineCount}</span>
              </button>
            </div>

            <div className="compose-viewer-body">
              {tab === 'services' ? (
                <ServicesTab services={content.services} runningServices={runningServices} />
              ) : (
                <YamlView content={content.content} spans={content.spans} />
              )}
            </div>

            <footer className="compose-viewer-footer">
              <span className="truncate font-mono text-[10px] text-default-400">
                read-only · parsed by PyYAML
              </span>
              <div className="flex shrink-0 items-center gap-2">
                <Button
                  size="sm"
                  variant={copied ? 'secondary' : 'ghost'}
                  onPress={() => void copy()}
                >
                  <Icon name={copied ? 'check' : 'copy'} size={13} />
                  {copied ? 'Copied' : 'Copy YAML'}
                </Button>
                <Button size="sm" variant="secondary" onPress={onClose}>Close</Button>
              </div>
            </footer>
          </>
        )}
      </div>
    </div>
  )
}