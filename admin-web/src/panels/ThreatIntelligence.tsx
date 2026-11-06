import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Alert } from '@heroui/react/alert'
import { Card } from '@heroui/react/card'
import { Chip } from '@heroui/react/chip'
import { api, usePoll } from '../api'
import CopyButton from '../components/CopyButton'
import Icon from '../components/Icon'
import Loading from '../components/Loading'
import { ago, bytes } from '../lib/format'
import type { EvidenceFile, EvidenceFiles, RemoteBundle } from '../types'

const QUEUE_KEY = 'threat-intelligence.collection-queue'
const SERVER_EXCLUDED_KEY = 'threat-intelligence.server-excluded-bundles'

function readQueue(): string[] {
  try {
    const saved: unknown = JSON.parse(localStorage.getItem(QUEUE_KEY) ?? '[]')
    return Array.isArray(saved)
      ? saved.filter((name): name is string => typeof name === 'string')
      : []
  } catch {
    return []
  }
}

function readExcludedBundles(): string[] {
  try {
    const saved: unknown = JSON.parse(localStorage.getItem(SERVER_EXCLUDED_KEY) ?? '[]')
    return Array.isArray(saved)
      ? saved.filter((name): name is string => typeof name === 'string')
      : []
  } catch {
    return []
  }
}

function remoteTimestamp(bundle: RemoteBundle): string {
  if (bundle.date_text) return bundle.date_text
  return bundle.modified ? new Date(bundle.modified * 1000).toLocaleString() : '—'
}

export default function ThreatIntelligence() {
  const forceRefresh = useRef(false)
  const { data: settings } = usePoll(api.artifactSettings, 120_000)
  const remoteRoot = settings?.artifacts.remote_root?.trim() || '/'
  const { data, error, loading, refresh } = usePoll(
    () => api.artifacts(remoteRoot, forceRefresh.current),
    60_000,
  )
  const [query, setQuery] = useState('')
  const [activeName, setActiveName] = useState<string | null>(null)
  const [selected, setSelected] = useState<string[]>(readQueue)
  const [serverExcluded, setServerExcluded] = useState<string[]>(readExcludedBundles)
  const [evidence, setEvidence] = useState<EvidenceFiles | null>(null)
  const [report, setReport] = useState<EvidenceFile | null>(null)
  const [working, setWorking] = useState(false)
  const [progress, setProgress] = useState('')
  const [actionError, setActionError] = useState<string | null>(null)
  const [actionMessage, setActionMessage] = useState<string | null>(null)
  const [shareLinks, setShareLinks] = useState<Record<string, string>>({})
  const [linkBusy, setLinkBusy] = useState(false)
  const [serverHost, setServerHost] = useState('0.0.0.0')
  const [serverPort, setServerPort] = useState('8765')
  const [serverConfigSaved, setServerConfigSaved] = useState(false)
  const [serverOutput, setServerOutput] = useState<string[]>([
    'Ready. Configure the bind address and port, then select Generate Server.',
  ])
  useEffect(() => {
    try {
      localStorage.setItem(QUEUE_KEY, JSON.stringify(selected))
    } catch {
      // The queue remains usable for this page session when storage is disabled.
    }
  }, [selected])

  useEffect(() => {
    try {
      localStorage.setItem(SERVER_EXCLUDED_KEY, JSON.stringify(serverExcluded))
    } catch {
      // Exclusions remain active for this page session when storage is disabled.
    }
  }, [serverExcluded])

  useEffect(() => {
    if (data) forceRefresh.current = false
  }, [data])

  useEffect(() => {
    if (data && data.remote?.remote_root !== remoteRoot) refresh()
  }, [data, refresh, remoteRoot])

  useEffect(() => {
    if (!data?.remote?.refreshing) return
    const timer = window.setTimeout(refresh, 5000)
    return () => window.clearTimeout(timer)
  }, [data?.generated_at, data?.remote?.refreshing, refresh])

  const remoteBundles = data?.remote?.bundles ?? []
  const activeBundle = remoteBundles.find((bundle) => bundle.name === activeName) ?? null
  const localNames = useMemo(
    () => new Set((data?.local?.bundles ?? []).map((bundle) => bundle.name)),
    [data?.local?.bundles],
  )
  const filteredBundles = useMemo(() => {
    const normalized = query.trim().toLowerCase()
    if (!normalized) return remoteBundles
    return remoteBundles.filter((bundle) =>
      [bundle.name, bundle.dir, ...bundle.files.map((file) => file.name ?? '')]
        .some((value) => value.toLowerCase().includes(normalized)),
    )
  }, [query, remoteBundles])

  const refreshNow = useCallback(() => {
    forceRefresh.current = true
    refresh()
  }, [refresh])

  const toggleSelected = (name: string) => {
    setSelected((current) =>
      current.includes(name)
        ? current.filter((entry) => entry !== name)
        : [...current, name],
    )
  }

  const collect = async (names: string[]) => {
    if (!names.length || working) return
    setWorking(true)
    setActionError(null)
    setActionMessage(null)
    setEvidence(null)
    try {
      for (let index = 0; index < names.length; index += 1) {
        const name = names[index]
        setActiveName(name)
        setProgress(`Collecting ${name} (${index + 1}/${names.length})`)
        if (!localNames.has(name)) {
          await api.recoverArtifact(name, remoteRoot)
        }
        try {
          await api.evidenceFiles(name)
        } catch {
          await api.restoreArtifact(name)
        }
        const files = await api.evidenceFiles(name)
        setEvidence(files)
      }
      setActionMessage(
        names.length === 1
          ? `${names[0]} is verified and ready to inspect.`
          : `${names.length} selected bundles are verified and ready to inspect.`,
      )
      setSelected((current) => current.filter((name) => !names.includes(name)))
      refreshNow()
    } catch (exc) {
      setActionError(exc instanceof Error ? exc.message : String(exc))
    } finally {
      setProgress('')
      setWorking(false)
    }
  }

  useEffect(() => {
    if (!activeName) {
      setEvidence(null)
      return
    }
    let cancelled = false
    api.evidenceFiles(activeName)
      .then((result) => { if (!cancelled) setEvidence(result) })
      .catch(() => { if (!cancelled) setEvidence(null) })
    return () => { cancelled = true }
  }, [activeName])

  const currentFiles = evidence?.name === activeName ? evidence.files : []
  const reports = currentFiles.filter((file) => file.html)
  const activeLink = activeBundle
    ? shareLinks[activeBundle.name] ?? activeBundle.link ?? null
    : null

  const artifactCatalog = useMemo(() => {
    const rows = new Map<string, {
      name: string
      hash: string | null
      submitted: number | null
      link: string | null
    }>()
    for (const bundle of data?.remote?.bundles ?? []) {
      rows.set(bundle.name, {
        name: bundle.name,
        hash: null,
        submitted: bundle.modified,
        link: bundle.link ?? null,
      })
    }
    for (const bundle of data?.local?.bundles ?? []) {
      const previous = rows.get(bundle.name)
      rows.set(bundle.name, {
        name: bundle.name,
        hash: bundle.sha256 ?? previous?.hash ?? null,
        submitted: bundle.generated_at ?? previous?.submitted ?? bundle.modified,
        link: previous?.link ?? null,
      })
    }
    return [...rows.values()].sort(
      (left, right) => (right.submitted ?? 0) - (left.submitted ?? 0),
    )
  }, [data?.local?.bundles, data?.remote?.bundles])
  const includedArtifacts = artifactCatalog.filter(
    (artifact) => !serverExcluded.includes(artifact.name),
  )
  const excludedArtifacts = artifactCatalog.filter(
    (artifact) => serverExcluded.includes(artifact.name),
  )

  const toggleServerArtifact = (name: string) => {
    setServerExcluded((current) =>
      current.includes(name)
        ? current.filter((entry) => entry !== name)
        : [...current, name],
    )
  }

  const createShareLink = async () => {
    if (!activeBundle || linkBusy) return
    setLinkBusy(true)
    setActionError(null)
    try {
      const result = await api.artifactLink(activeBundle.name, remoteRoot)
      setShareLinks((current) => ({ ...current, [activeBundle.name]: result.link }))
    } catch (exc) {
      setActionError(exc instanceof Error ? exc.message : String(exc))
    } finally {
      setLinkBusy(false)
    }
  }

  const generateServerPreview = () => {
    const timestamp = new Date().toLocaleString()
    setServerOutput([
      `[${timestamp}] Starting UI generation preview`,
      `[config] Bind address: ${serverHost}:${serverPort}`,
      `[catalog] Including ${includedArtifacts.length} of ${artifactCatalog.length} bundle(s)`,
      ...includedArtifacts.map((artifact) => `[include] ${artifact.name}`),
      ...excludedArtifacts
        .map((artifact) => `[exclude] ${artifact.name}`),
      '[template] templates/index.html.j2',
      '[template] templates/artifact.html.j2',
      '[server] app.py (Jinja2/Flask) would be generated',
      '[output] exports/threat-intelligence-server/',
      '[status] Preview only — no files were generated and no server was started.',
    ])
  }

  return (
    <div className="threat-page">
      <header className="threat-header">
        <div>
          <p className="eyebrow">Evidence operations</p>
          <h1 className="page-title mt-1">Threat Intelligence Server</h1>
          <p className="mt-2 max-w-3xl text-xs leading-relaxed text-default-500">
            Browse remote evidence bundles, collect only the cases you choose,
            verify and extract them locally, then inspect their files and HTML reports.
          </p>
        </div>
        <div className="threat-header-actions">
          <Chip
            size="sm"
            variant="soft"
            color={data?.remote?.available ? 'success' : 'warning'}
          >
            {data?.remote?.available ? 'MEGA connected' : 'MEGA unavailable'}
          </Chip>
          <button type="button" className="artifact-refresh" onClick={refreshNow} disabled={loading}>
            <Icon name="refresh" size={13} />
            {loading ? 'Refreshing…' : 'Refresh'}
          </button>
        </div>
      </header>

      {error && (
        <Alert status="danger">
          <Alert.Title>Evidence listing failed</Alert.Title>
          <Alert.Description>{error}</Alert.Description>
        </Alert>
      )}
      {data?.remote && !data.remote.available && (
        <Alert status="warning">
          <Alert.Title>Remote evidence is unavailable</Alert.Title>
          <Alert.Description>{data.remote.reason ?? 'Check the MEGAcmd session and remote folder.'}</Alert.Description>
        </Alert>
      )}
      {actionError && (
        <Alert status="danger">
          <Alert.Title>Evidence action failed</Alert.Title>
          <Alert.Description>{actionError}</Alert.Description>
        </Alert>
      )}
      {actionMessage && (
        <Alert status="success">
          <Alert.Description>{actionMessage}</Alert.Description>
        </Alert>
      )}
      {progress && <p className="threat-progress" role="status">{progress}</p>}

      <section className="threat-server-section" aria-label="Artifact server setup">
        <div className="threat-server-heading">
          <div>
            <p className="eyebrow">Artifact catalog</p>
            <h2>Generated server</h2>
            <p>
              Configure the address and port for the Jinja2 artifact catalog.
              The current controls are a UI preview and do not start a server.
            </p>
          </div>
          <button
            type="button"
            className="artifact-action threat-generate-button"
            onClick={generateServerPreview}
          >
            <Icon name="server" size={14} />
            Generate Server
          </button>
        </div>

        <form
          className="threat-server-config"
          onSubmit={(event) => {
            event.preventDefault()
            setServerConfigSaved(true)
          }}
        >
          <label>
            <span>Server IP / bind address</span>
            <input
              value={serverHost}
              onChange={(event) => {
                setServerHost(event.target.value)
                setServerConfigSaved(false)
              }}
              placeholder="0.0.0.0"
              required
              aria-label="Server IP or bind address"
            />
            <small>0.0.0.0 allows LAN access; 127.0.0.1 is local only.</small>
          </label>
          <label>
            <span>Server port</span>
            <input
              type="number"
              min={1}
              max={65535}
              value={serverPort}
              onChange={(event) => {
                setServerPort(event.target.value)
                setServerConfigSaved(false)
              }}
              required
              aria-label="Server port"
            />
            <small>Choose an unused port between 1 and 65535.</small>
          </label>
          <div className="threat-server-config-actions">
            <button type="submit" className="artifact-action">Save configuration</button>
            <Chip size="sm" variant="soft" color={serverConfigSaved ? 'success' : 'accent'}>
              {serverConfigSaved ? 'Configuration saved in this view' : 'Not configured'}
            </Chip>
          </div>
        </form>

        <div className="threat-generation-output" aria-label="Server generation output">
          <div className="threat-generation-output-heading">
            <span>Generation output</span>
            <Chip size="sm" variant="soft" color="warning">UI preview</Chip>
          </div>
          <pre aria-live="polite">{serverOutput.join('\n')}</pre>
        </div>

        <div className="threat-catalog">
          <div className="threat-catalog-heading">
            <div>
              <h3>Collected artifact catalog</h3>
              <p>Choose which bundles the generated catalog should include.</p>
            </div>
            <div className="threat-catalog-counts">
              <Chip size="sm" variant="soft" color="success">{includedArtifacts.length} included</Chip>
              <Chip size="sm" variant="soft">{excludedArtifacts.length} excluded</Chip>
              <button
                type="button"
                className="artifact-action"
                onClick={() => setServerExcluded([])}
                disabled={!serverExcluded.length}
              >
                Include all
              </button>
            </div>
          </div>
          <div className="threat-catalog-table-wrap">
            <table className="threat-catalog-table">
              <thead>
                <tr>
                  <th>Sample name</th>
                  <th>SHA-256</th>
                  <th>Submitted</th>
                  <th>MEGA link</th>
                  <th>Server catalog</th>
                </tr>
              </thead>
              <tbody>
                {artifactCatalog.length ? artifactCatalog.map((artifact) => (
                  <tr key={artifact.name}>
                    <td title={artifact.name}>{artifact.name}</td>
                    <td title={artifact.hash ?? ''}>
                      {artifact.hash
                        ? <code>{artifact.hash}</code>
                        : <span className="threat-catalog-muted">Not available</span>}
                    </td>
                    <td>
                      {artifact.submitted
                        ? new Date(artifact.submitted * 1000).toLocaleString()
                        : <span className="threat-catalog-muted">Unknown</span>}
                    </td>
                    <td>
                      {artifact.link
                        ? <a href={artifact.link} target="_blank" rel="noreferrer">Open MEGA link</a>
                        : <span className="threat-catalog-muted">Not shared</span>}
                    </td>
                    <td>
                      <label className="threat-catalog-inclusion">
                        <input
                          type="checkbox"
                          checked={!serverExcluded.includes(artifact.name)}
                          onChange={() => toggleServerArtifact(artifact.name)}
                          aria-label={`Include ${artifact.name} in generated server`}
                        />
                        <span>{serverExcluded.includes(artifact.name) ? 'Excluded' : 'Included'}</span>
                      </label>
                    </td>
                  </tr>
                )) : (
                  <tr>
                    <td colSpan={5} className="threat-catalog-empty">
                      Artifacts will appear here when available from local bundles or MEGA.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </section>

      {!data && loading ? (
        <Loading label="Loading remote evidence" />
      ) : (
        <>
          <section className="threat-metrics" aria-label="Evidence workspace summary">
            <div className="threat-metric">
              <span className="eyebrow">Remote bundles</span>
              <strong>{data?.remote?.bundles.length ?? 0}</strong>
              <span>under <code>{remoteRoot}</code></span>
            </div>
            <div className="threat-metric">
              <span className="eyebrow">Collection queue</span>
              <strong>{selected.length}</strong>
              <span>chosen for local inspection</span>
            </div>
            <div className="threat-metric">
              <span className="eyebrow">Local bundles</span>
              <strong>{data?.local?.bundles.length ?? 0}</strong>
              <span>downloaded and available</span>
            </div>
            <div className="threat-metric">
              <span className="eyebrow">Selected case</span>
              <strong className="threat-selected-name">{activeName ?? '—'}</strong>
              <span>{evidence?.name === activeName ? `${currentFiles.length} extracted files` : 'Not extracted yet'}</span>
            </div>
          </section>

          <div className="threat-workspace">
            <Card className="threat-browser">
              <Card.Header className="threat-card-header">
                <div>
                  <Card.Title>Remote evidence</Card.Title>
                  <p className="mt-1 text-[11px] text-default-500">
                    MEGA · <span className="font-mono">{data?.remote?.remote_root ?? remoteRoot}</span>
                  </p>
                </div>
                <Chip size="sm" variant="soft">{filteredBundles.length} bundles</Chip>
              </Card.Header>
              <Card.Content className="flex flex-col gap-3">
                <div className="threat-search">
                  <Icon name="search" size={14} />
                  <input
                    value={query}
                    onChange={(event) => setQuery(event.target.value)}
                    placeholder="Search bundles and listed files"
                    aria-label="Search remote evidence"
                  />
                </div>
                <div className="threat-queue-actions">
                  <span>{selected.length} selected</span>
                  <button
                    type="button"
                    className="artifact-action"
                    onClick={() => void collect(selected)}
                    disabled={working || selected.length === 0}
                  >
                    {working ? 'Collecting…' : 'Collect selected'}
                    <span aria-hidden="true">↓</span>
                  </button>
                </div>
                <div className="threat-bundle-list">
                  {filteredBundles.length === 0 ? (
                    <p className="artifact-list-empty">
                      {data?.remote?.available
                        ? 'No remote evidence matches this search.'
                        : 'Connect MEGAcmd to browse remote evidence.'}
                    </p>
                  ) : filteredBundles.map((bundle) => {
                    const checked = selected.includes(bundle.name)
                    const local = localNames.has(bundle.name)
                    return (
                      <article
                        key={bundle.name}
                        className={`threat-bundle ${activeName === bundle.name ? 'active' : ''}`}
                      >
                        <label className="threat-bundle-check">
                          <input
                            type="checkbox"
                            checked={checked}
                            onChange={() => toggleSelected(bundle.name)}
                            aria-label={`Add ${bundle.name} to collection queue`}
                          />
                        </label>
                        <button
                          type="button"
                          className="threat-bundle-select"
                          onClick={() => setActiveName(bundle.name)}
                        >
                          <span className="threat-bundle-name">{bundle.name}</span>
                          <span className="threat-bundle-meta">
                            {bundle.file_count} remote files · {bytes(bundle.total_bytes)} · {ago(bundle.modified)}
                          </span>
                          <span className="threat-bundle-files">
                            {bundle.files.slice(0, 3).map((file) => file.name).filter(Boolean).join(' · ') || 'No file details'}
                          </span>
                        </button>
                        <Chip size="sm" variant="soft" color={local ? 'success' : 'accent'}>
                          {local ? 'Local' : 'Remote'}
                        </Chip>
                      </article>
                    )
                  })}
                </div>
                {data?.remote?.truncated && (
                  <Alert status="warning">
                    <Alert.Description>
                      Partial MEGA listing: {data.remote.truncated}
                    </Alert.Description>
                  </Alert>
                )}
              </Card.Content>
            </Card>

            <Card className="threat-inspector">
              <Card.Header className="threat-card-header">
                <div>
                  <Card.Title>{activeBundle?.name ?? activeName ?? 'Evidence inspector'}</Card.Title>
                  <p className="mt-1 text-[11px] text-default-500">
                    {activeBundle
                      ? `${activeBundle.dir} · last seen ${ago(activeBundle.modified)}`
                      : 'Choose a remote bundle to inspect its evidence.'}
                  </p>
                </div>
                {activeBundle && (
                  <div className="threat-inspector-actions">
                    <button
                      type="button"
                      className="artifact-action"
                      disabled={linkBusy}
                      onClick={() => void createShareLink()}
                    >
                      {linkBusy ? 'Creating link…' : activeLink ? 'Refresh share link' : 'Create share link'}
                    </button>
                    <button
                      type="button"
                      className="artifact-action"
                      disabled={working}
                      onClick={() => void collect([activeBundle.name])}
                    >
                      {evidence?.name === activeBundle.name ? 'Refresh files' : 'Collect & extract'}
                    </button>
                  </div>
                )}
              </Card.Header>
              <Card.Content className="flex flex-col gap-4">
                {activeBundle && (
                  <div className="threat-detail-grid">
                    <div><span>Remote archive</span><strong>{activeBundle.archive ?? 'Not listed'}</strong></div>
                    <div><span>Archive size</span><strong>{bytes(activeBundle.bytes)}</strong></div>
                    <div><span>Bundle contents</span><strong>{activeBundle.file_count} files</strong></div>
                    <div><span>Updated</span><strong>{remoteTimestamp(activeBundle)}</strong></div>
                  </div>
                )}

                {evidence?.name === activeName ? (
                  <>
                    <div className="threat-report-strip">
                      <div>
                        <p className="eyebrow">Extracted evidence</p>
                        <p className="mt-1 text-[11px] text-default-500">
                          Verified archive · {evidence.files.length}{evidence.truncated ? '+' : ''} files
                        </p>
                      </div>
                      {reports.length > 0 && (
                        <button
                          type="button"
                          className="artifact-action"
                          onClick={() => setReport(reports[0])}
                        >
                          <Icon name="file-code" size={13} />
                          Render HTML report
                        </button>
                      )}
                    </div>
                    {reports.length > 0 && (
                      <div className="threat-report-list" aria-label="HTML reports">
                        {reports.map((file) => (
                          <button
                            type="button"
                            key={file.path}
                            className="threat-report-item"
                            onClick={() => setReport(file)}
                          >
                            <Icon name="file-code" size={14} />
                            <span>{file.path}</span>
                            <span>{bytes(file.bytes)}</span>
                          </button>
                        ))}
                      </div>
                    )}
                    <div className="threat-file-heading">
                      <span>Evidence files</span>
                      <span>{evidence.directory}</span>
                    </div>
                    <div className="threat-file-list">
                      {evidence.files.map((file) => (
                        <div className="threat-file-row" key={file.path}>
                          <Icon name={file.html ? 'file-code' : 'file-text'} size={14} />
                          <span className="threat-file-path" title={file.path}>{file.path}</span>
                          <span className="threat-file-size">{bytes(file.bytes)}</span>
                          {file.html && (
                            <button type="button" onClick={() => setReport(file)}>View</button>
                          )}
                          {!file.html && (
                            <a
                              className="threat-file-open"
                              href={api.evidenceFileUrl(activeName, file.path)}
                              target="_blank"
                              rel="noreferrer"
                            >
                              Open
                            </a>
                          )}
                        </div>
                      ))}
                    </div>
                    {evidence.truncated && (
                      <p className="text-[11px] text-warning">File listing capped at 5,000 entries.</p>
                    )}
                  </>
                ) : activeName ? (
                  <div className="threat-empty-inspector">
                    <Icon name="folder" size={24} />
                    <p>Collect and verify this bundle to extract its evidence files.</p>
                    <button
                      type="button"
                      className="artifact-action"
                      onClick={() => void collect([activeName])}
                      disabled={working}
                    >
                      Collect &amp; extract
                    </button>
                  </div>
                ) : (
                  <div className="threat-empty-inspector">
                    <Icon name="file-text" size={24} />
                    <p>Select a case to view its remote bundle contents and evidence.</p>
                  </div>
                )}
              </Card.Content>
            </Card>
          </div>

          {activeLink && (
            <div className="threat-link-row">
              <span className="eyebrow">Existing share link</span>
              <a href={activeLink} target="_blank" rel="noreferrer">{activeLink}</a>
              <CopyButton text={activeLink} variant="ghost">Copy</CopyButton>
            </div>
          )}
        </>
      )}

      {report && activeName && (
        <div className="threat-report-overlay" role="dialog" aria-modal="true" aria-label={report.path}>
          <div className="threat-report-window">
            <div className="threat-report-window-header">
              <div className="min-w-0">
                <p className="eyebrow">Sandboxed evidence report</p>
                <p className="truncate font-mono text-xs">{report.path}</p>
              </div>
              <button
                type="button"
                className="artifact-action"
                onClick={() => setReport(null)}
                aria-label="Close report"
              >
                Close <Icon name="x" size={13} />
              </button>
            </div>
            <iframe
              key={`${activeName}:${report.path}`}
              className="threat-report-frame"
              src={api.evidenceFileUrl(activeName, report.path)}
              title={`Evidence report ${report.path}`}
              sandbox="allow-scripts"
              referrerPolicy="no-referrer"
            />
          </div>
        </div>
      )}
    </div>
  )
}
