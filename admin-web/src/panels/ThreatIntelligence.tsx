import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import type { FormEvent } from 'react'
import { Alert } from '@heroui/react/alert'
import { Card } from '@heroui/react/card'
import { Chip } from '@heroui/react/chip'
import { api, usePoll } from '../api'
import CopyButton from '../components/CopyButton'
import Icon from '../components/Icon'
import Loading from '../components/Loading'
import { ago, bytes } from '../lib/format'
import { renderPieces } from '../lib/logColor'
import type {
  CTIListenerStatus,
  EvidenceFile,
  EvidenceFiles,
  LocalBundle,
  RemoteBundle,
} from '../types'

const QUEUE_KEY = 'threat-intelligence.collection-queue'

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

function remoteTimestamp(bundle: RemoteBundle): string {
  if (bundle.date_text) return bundle.date_text
  return bundle.modified ? new Date(bundle.modified * 1000).toLocaleString() : '—'
}

function localTimestamp(bundle: LocalBundle): number | null {
  return bundle.generated_at ?? bundle.modified
}

function localVerification(bundle: LocalBundle): {
  label: string
  color: 'success' | 'warning' | 'danger' | 'default'
} {
  if (!bundle.present) return { label: 'No archive', color: 'warning' }
  if (bundle.verified === true) return { label: 'Verified', color: 'success' }
  if (bundle.verified === false) return { label: 'Digest mismatch', color: 'danger' }
  return { label: 'Not hashed', color: 'default' }
}

/**
 * Render buffered process output, translating SGR escapes into coloured spans.
 *
 * Generation runs host_server.py with colorized loguru output, so the captured
 * lines contain real ANSI sequences. A plain `<pre>{lines.join('\n')}</pre>`
 * showed them as the literal text `[32m...`; renderPieces() consumes the
 * sequences and keeps the stream's own level colours.
 */
function OutputPre({ lines }: { lines: string[] }) {
  return (
    <pre aria-live="polite">
      {lines.map((line, i) => (
        <span key={i}>
          {renderPieces(line)}
          {i < lines.length - 1 ? '\n' : ''}
        </span>
      ))}
    </pre>
  )
}

type CatalogArtifact = {
  name: string
  remote: RemoteBundle | null
  local: LocalBundle | null
  hash: string | null
  submitted: number | null
  link: string | null
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
  const [banned, setBanned] = useState<{ name: string | null; hash: string | null }[]>([])
  const [publishSelected, setPublishSelected] = useState<string[]>([])
  const [publishing, setPublishing] = useState(false)
  const [publishProgress, setPublishProgress] = useState('')
  const [publishError, setPublishError] = useState<string | null>(null)
  const [publishOutput, setPublishOutput] = useState<string[]>([
    'Ready. Select the local bundles to push to MEGA and include in the catalog.',
  ])
  const [banSaving, setBanSaving] = useState(false)
  const [banError, setBanError] = useState<string | null>(null)
  const [banOutput, setBanOutput] = useState<string[]>([
    'Ready. Ban or unban an artifact to see the result here.',
  ])
  const [evidence, setEvidence] = useState<EvidenceFiles | null>(null)
  const [report, setReport] = useState<EvidenceFile | null>(null)
  const [working, setWorking] = useState(false)
  const [progress, setProgress] = useState('')
  const [actionError, setActionError] = useState<string | null>(null)
  const [actionMessage, setActionMessage] = useState<string | null>(null)
  const [shareLinks, setShareLinks] = useState<Record<string, string>>({})
  const [linksLoaded, setLinksLoaded] = useState(false)
  const [linksError, setLinksError] = useState<string | null>(null)
  const [linkBusy, setLinkBusy] = useState(false)
  const [serverHost, setServerHost] = useState('0.0.0.0')
  const [serverPort, setServerPort] = useState('8765')
  const [serverPath, setServerPath] = useState('stix-server/config/cti_config.json')
  const [serverConfigSaved, setServerConfigSaved] = useState(false)
  const [serverSaving, setServerSaving] = useState(false)
  const [serverConfigError, setServerConfigError] = useState<string | null>(null)
  const [serverOutput, setServerOutput] = useState<string[]>([
    'Ready. Configure the bind address and port, then select Generate Server.',
  ])
  const [listener, setListener] = useState<CTIListenerStatus | null>(null)
  const [listenerBusy, setListenerBusy] = useState<'start' | 'stop' | null>(null)
  const [listenerError, setListenerError] = useState<string | null>(null)
  const [previewOpen, setPreviewOpen] = useState(false)
  const [tab, setTab] = useState<'evidence' | 'catalog' | 'server'>('evidence')
  const [banLogOpen, setBanLogOpen] = useState(false)
  const [generating, setGenerating] = useState(false)
  const [generateError, setGenerateError] = useState<string | null>(null)
  const [generatedPaths, setGeneratedPaths] = useState<{
    catalog: string
    server: string
    index: string
  } | null>(null)
  useEffect(() => {
    let cancelled = false
    api.ctiServerSettings()
      .then((saved) => {
        if (cancelled) return
        setServerHost(saved.ip)
        setServerPort(String(saved.port))
        setServerPath(saved.path)
        setServerConfigSaved(saved.exists)
        setServerConfigError(saved.error)
        setBanned(saved.banned ?? [])
      })
      .catch((exc: unknown) => {
        if (!cancelled) {
          setServerConfigError(exc instanceof Error ? exc.message : String(exc))
        }
      })
    return () => { cancelled = true }
  }, [])
  const refreshListener = useCallback(async () => {
    try {
      setListener(await api.ctiListenerStatus())
      setListenerError(null)
    } catch (exc) {
      setListenerError(exc instanceof Error ? exc.message : String(exc))
    }
  }, [])
  useEffect(() => {
    void refreshListener()
  }, [refreshListener])
  useEffect(() => {
    try {
      localStorage.setItem(QUEUE_KEY, JSON.stringify(selected))
    } catch {
      // The queue remains usable for this page session when storage is disabled.
    }
  }, [selected])

  useEffect(() => {
    if (data) forceRefresh.current = false
  }, [data])

  useEffect(() => {
    if (data && data.remote?.remote_root !== remoteRoot) refresh()
  }, [data, refresh, remoteRoot])

  // The MEGA link is not part of `/api/artifacts`; it has its own read-only
  // endpoint. Seed the table from it once per remote root (and after a
  // Rescan), then keep the same map updated when a link is created here.
  const loadLinks = useCallback(async () => {
    try {
      const result = await api.artifactLinks(remoteRoot)
      if (result.ok) setShareLinks(result.links)
      setLinksError(result.error ?? null)
    } catch (exc) {
      setLinksError(exc instanceof Error ? exc.message : String(exc))
    } finally {
      setLinksLoaded(true)
    }
  }, [remoteRoot])

  useEffect(() => {
    void loadLinks()
  }, [loadLinks])

  useEffect(() => {
    if (!data?.remote?.refreshing) return
    const timer = window.setTimeout(refresh, 5000)
    return () => window.clearTimeout(timer)
  }, [data?.generated_at, data?.remote?.refreshing, refresh])

  const remoteBundles = data?.remote?.bundles ?? []
  const listenerRunning =
    listener?.state === 'running' || listener?.state === 'unhealthy'
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
    void loadLinks()
  }, [loadLinks, refresh])

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
    const rows = new Map<string, CatalogArtifact>()
    for (const bundle of data?.remote?.bundles ?? []) {
      rows.set(bundle.name, {
        name: bundle.name,
        remote: bundle,
        local: null,
        hash: null,
        submitted: bundle.modified,
        link: shareLinks[bundle.name] ?? bundle.link ?? null,
      })
    }
    for (const bundle of data?.local?.bundles ?? []) {
      const previous = rows.get(bundle.name)
      rows.set(bundle.name, {
        name: bundle.name,
        remote: previous?.remote ?? null,
        local: bundle,
        hash: bundle.sha256 ?? previous?.hash ?? null,
        submitted: localTimestamp(bundle) ?? previous?.submitted ?? null,
        link: shareLinks[bundle.name] ?? previous?.link ?? null,
      })
    }
    return [...rows.values()].sort(
      (left, right) => (right.submitted ?? 0) - (left.submitted ?? 0),
    )
  }, [data?.local?.bundles, data?.remote?.bundles, shareLinks])
  const isArtifactBanned = (artifact: CatalogArtifact) =>
    banned.some(
      (entry) =>
        (entry.name && entry.name === artifact.name) ||
        (entry.hash && entry.hash === artifact.hash),
    )
  const includedArtifacts = artifactCatalog.filter(
    (artifact) => !isArtifactBanned(artifact),
  )
  const localArtifactCount = artifactCatalog.filter((artifact) => artifact.local).length
  const remoteArtifactCount = artifactCatalog.filter((artifact) => artifact.remote).length
  const uploadEnabled = settings?.mega_upload ?? true
  const encryptEnabled = settings?.mega_encrypt ?? false
  const passwordReady = settings?.bundle_password?.present ?? false
  const publishableArtifacts = useMemo(
    () => artifactCatalog.filter((artifact) => artifact.local),
    [artifactCatalog],
  )
  const pendingUploadCount = publishableArtifacts.filter(
    (artifact) => !artifact.remote,
  ).length
  const selectedArtifacts = publishableArtifacts.filter((artifact) =>
    publishSelected.includes(artifact.name),
  )
  const uploadNeeded = selectedArtifacts.some((artifact) => !artifact.remote)
  const publishDisabledReason = !uploadEnabled
    ? 'Uploading is disabled in Analysis Configuration → MEGA upload. Bundles already on MEGA can still be included.'
    : encryptEnabled && !passwordReady
      ? 'Set or generate the bundle password on the Analysis Configuration page first.'
      : null

  const appendPublishOutput = useCallback((message: string) => {
    const stamp = new Date().toLocaleTimeString()
    setPublishOutput((current) => [...current, `[${stamp}] ${message}`].slice(-400))
  }, [])

  const togglePublish = (name: string) => {
    setPublishSelected((current) =>
      current.includes(name)
        ? current.filter((entry) => entry !== name)
        : [...current, name],
    )
  }

  /**
   * Publish local bundles, then make them part of the generated catalog.
   *
   * The catalog is built from `stix-server/exported_evidence/`, not from
   * `exports/`, so a local bundle has to exist on MEGA first. Bundles that are
   * not on MEGA yet are uploaded with the same job the Artifacts page uses and
   * waited on here; bundles that are already there are not uploaded again.
   * Only then does host_server.py pull from MEGA and rebuild the catalog.
   */
  const publishAndInclude = async () => {
    if (publishing) return
    const names = publishSelected.filter((name) =>
      publishableArtifacts.some((artifact) => artifact.name === name),
    )
    if (!names.length) return
    const toUpload = names.filter(
      (name) => !publishableArtifacts.find((artifact) => artifact.name === name)?.remote,
    )
    if (toUpload.length && publishDisabledReason) {
      setPublishError(publishDisabledReason)
      return
    }
    setPublishing(true)
    setPublishError(null)
    setActionError(null)
    setActionMessage(null)
    appendPublishOutput(
      `Preparing ${names.length} local bundle(s) for the catalog…`,
    )
    try {
      for (let index = 0; index < names.length; index += 1) {
        const name = names[index]
        const alreadyRemote = publishableArtifacts.find(
          (artifact) => artifact.name === name,
        )?.remote
        if (alreadyRemote) {
          appendPublishOutput(`${name} is already on MEGA; skipping upload.`)
          continue
        }
        setPublishProgress(`Uploading ${name} (${index + 1}/${names.length})`)
        appendPublishOutput(`Upload ${index + 1}/${names.length}: ${name}`)
        const started = await api.exportArtifact(name, remoteRoot)
        if (started.reused) {
          appendPublishOutput(`  reusing running export job ${started.job_id}`)
        }
        let job = await api.artifactExportJob(started.job_id)
        const deadline = Date.now() + 20 * 60_000
        while (job.state === 'running') {
          if (Date.now() > deadline) {
            throw new Error(`upload of ${name} timed out after 20 minutes`)
          }
          await new Promise<void>((resolve) => {
            window.setTimeout(resolve, 2500)
          })
          job = await api.artifactExportJob(started.job_id)
        }
        if (job.state === 'error') {
          const detail = job.lines.slice(-1)[0]
          throw new Error(
            `upload of ${name} failed${detail ? ` — ${detail}` : ` (exit ${job.exit_code ?? '?'})`}`,
          )
        }
        for (const line of job.lines.slice(-6)) {
          appendPublishOutput(`  ${line}`)
        }
        appendPublishOutput(
          `  ${name} is on MEGA${job.link ? ` · ${job.link}` : ''}`,
        )
      }

      setPublishProgress('Pulling from MEGA and rebuilding the CTI catalog…')
      appendPublishOutput(
        'Pulling every bundle from MEGA and rebuilding artifact_catalog.json, server.py and index.html…',
      )
      const result = await api.generateCtiServer(true)
      for (const line of result.output) appendPublishOutput(`  ${line}`)
      if (!result.ok) {
        throw new Error(result.error ?? 'host_server.py failed')
      }
      appendPublishOutput(
        'Catalog rebuilt. The running listener reads the catalog per request, so the selected bundle appears without a restart.',
      )
      setActionMessage(
        toUpload.length
          ? `${toUpload.length} bundle(s) pushed to MEGA and the ${names.length} selected bundle(s) included in the CTI catalog.`
          : `The catalog was rebuilt and ${names.length} selected bundle(s) are included.`,
      )
      setPublishSelected([])
    } catch (exc) {
      const message = exc instanceof Error ? exc.message : String(exc)
      setPublishError(message)
      appendPublishOutput(`FAILED — ${message}`)
    } finally {
      setPublishProgress('')
      setPublishing(false)
      // Any upload that succeeded before a failure is now on MEGA; refresh so
      // the Local/Remote tags describe the real state rather than the old one.
      refreshNow()
    }
  }

  const appendBanOutput = useCallback((message: string) => {
    const stamp = new Date().toLocaleTimeString()
    setBanOutput((current) => [...current, `[${stamp}] ${message}`].slice(-200))
  }, [])

  const saveBanned = async (
    next: { name: string | null; hash: string | null }[],
    action: string,
  ) => {
    if (banSaving) return
    const previous = banned
    setBanned(next)
    setBanSaving(true)
    setBanError(null)
    appendBanOutput(`${action}: saving ${next.length} banned bundle(s)…`)
    try {
      const saved = await api.saveCtiServerSettings({ banned: next })
      const active = saved.banned ?? next
      setBanned(active)
      setServerPath(saved.path)
      setServerConfigSaved(saved.exists)
      setServerConfigError(saved.error)
      appendBanOutput(
        `${action}: saved. ${active.length} bundle(s) in ${saved.path}` +
          (saved.error ? ` — file error: ${saved.error}` : ''),
      )
    } catch (exc) {
      const message = exc instanceof Error ? exc.message : String(exc)
      setBanned(previous)
      setBanError(message)
      appendBanOutput(`${action}: failed — ${message}`)
    } finally {
      setBanSaving(false)
    }
  }

  const toggleServerArtifact = (artifact: CatalogArtifact) => {
    // A bundle is banned by name AND by SHA-256. The name keeps the catalog
    // readable; the hash keeps the ban in force when the same evidence is
    // regenerated under a new folder name, which is the common case after a
    // pipeline rerun. Both keys are written together so a later unban removes
    // exactly what the ban added.
    const entry = {
      name: artifact.name,
      hash: artifact.hash,
    }
    const currentlyBanned = isArtifactBanned(artifact)
    const next = currentlyBanned
      ? banned.filter(
          (e) =>
            !(e.name === entry.name && e.hash === entry.hash),
        )
      : [...banned, entry]
    const label = artifact.hash
      ? `${artifact.name} · sha256 ${artifact.hash}`
      : artifact.name
    void saveBanned(next, `${currentlyBanned ? 'Unban' : 'Ban'} ${label}`)
  }

  const removeBan = (entry: { name: string | null; hash: string | null }) => {
    // Bans are stored as structured {name, hash} pairs. Removing either chip
    // removes the pair, otherwise the bundle would stay banned through its
    // hash and the chip would appear to do nothing.
    const paired = artifactCatalog.find(
      (artifact) =>
        artifact.name === entry.name || artifact.hash === entry.hash,
    )
    const keys = paired
      ? [{ name: paired.name, hash: paired.hash }]
      : [entry]
    void saveBanned(
      banned.filter(
        (b) =>
          !keys.some(
            (k) => (k.name && k.name === b.name) || (k.hash && k.hash === b.hash),
          ),
      ),
      `Unban ${entry.name ?? entry.hash ?? '(unknown)'}`,
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

  const saveServerConfig = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (serverSaving) return
    setServerSaving(true)
    setServerConfigError(null)
    try {
      const saved = await api.saveCtiServerSettings({
        ip: serverHost.trim(),
        port: Number(serverPort),
      })
      setServerHost(saved.ip)
      setServerPort(String(saved.port))
      setServerPath(saved.path)
      setServerConfigSaved(true)
      setServerConfigError(saved.error)
      void refreshListener()
    } catch (exc) {
      setServerConfigSaved(false)
      setServerConfigError(exc instanceof Error ? exc.message : String(exc))
    } finally {
      setServerSaving(false)
    }
  }

  const controlListener = async () => {
    if (listenerBusy) return
    const action = listenerRunning ? 'stop' : 'start'
    const started = new Date().toLocaleTimeString()
    setListenerBusy(action)
    setListenerError(null)
    setPreviewOpen(true)
    setServerOutput((current) => [
      ...current,
      `[${started}] ${action === 'start' ? 'Launching' : 'Stopping'} the generated CTI server…`,
    ].slice(-400))
    try {
      const result = await api.controlCtiListener(action)
      setListener(result.status)
      const finished = new Date().toLocaleTimeString()
      setServerOutput((current) => [
        ...current,
        `[${finished}] ${result.ok
          ? action === 'start' ? 'Listener started' : 'Listener stopped'
          : 'Listener action failed'} — ${result.detail}`,
        ...(result.tail.length ? result.tail : []),
      ].slice(-400))
      if (result.ok) {
        setActionMessage(
          action === 'start'
            ? `The catalog dashboard is serving at ${result.status.url}.`
            : 'The generated CTI server has stopped.',
        )
      } else {
        setListenerError(result.detail)
      }
    } catch (exc) {
      const message = exc instanceof Error ? exc.message : String(exc)
      setListenerError(message)
      setServerOutput((current) => [
        ...current,
        `[${new Date().toLocaleTimeString()}] Listener action failed — ${message}`,
      ].slice(-400))
      void refreshListener()
    } finally {
      setListenerBusy(null)
    }
  }

  const generateServer = async () => {
    if (generating) return
    const started = new Date().toLocaleTimeString()
    setGenerating(true)
    setGenerateError(null)
    setGeneratedPaths(null)
    setPreviewOpen(true)
    setServerOutput((current) => [
      ...current,
      `[${started}] Running stix-server/host_server.py --skip-pull…`,
    ].slice(-400))
    try {
      const result = await api.generateCtiServer(false)
      const finished = new Date().toLocaleTimeString()
      setServerOutput((current) => [
        ...current,
        `[${finished}] ${result.ok ? 'Generation succeeded' : 'Generation failed'} (exit ${result.returncode})`,
        ...result.output,
        `[catalog] ${result.catalog}`,
        `[server] ${result.server}`,
        `[index] ${result.index}`,
      ].slice(-400))
      setGeneratedPaths({
        catalog: result.catalog,
        server: result.server,
        index: result.index,
      })
      if (!result.ok) {
        setGenerateError(result.error ?? 'host_server.py failed')
      } else {
        setActionMessage('The CTI catalog, server.py and index.html were regenerated.')
        refreshNow()
      }
    } catch (exc) {
      const message = exc instanceof Error ? exc.message : String(exc)
      setGenerateError(message)
      setServerOutput((current) => [
        ...current,
        `[${new Date().toLocaleTimeString()}] Generation failed — ${message}`,
      ].slice(-400))
    } finally {
      setGenerating(false)
    }
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
          <button
            type="button"
            className="artifact-refresh"
            onClick={() => {
              setTab('catalog')
              setBanLogOpen(true)
              window.setTimeout(
                () => document
                  .getElementById('threat-ban-output')
                  ?.scrollIntoView({ behavior: 'smooth', block: 'start' }),
                80,
              )
            }}
          >
            <Icon name="terminal" size={13} />
            Ban output
            {banned.length > 0 && (
              <Chip size="sm" variant="soft" color="warning">
                {banned.length}
              </Chip>
            )}
          </button>
        </div>
      </header>

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
          <span className="eyebrow">Banned</span>
          <strong>{banned.length}</strong>
          <span>hidden from the catalog</span>
        </div>
        <div className="threat-metric">
          <span className="eyebrow">Selected case</span>
          <strong className="threat-selected-name">{activeName ?? '—'}</strong>
          <span>{evidence?.name === activeName ? `${currentFiles.length} extracted files` : 'Not extracted yet'}</span>
        </div>
      </section>

      <div className="threat-tabs" role="tablist" aria-label="Threat Intelligence Server sections">
        <button type="button" role="tab" aria-selected={tab === 'evidence'} className={tab === 'evidence' ? 'is-on' : ''} onClick={() => setTab('evidence')}>
          <Icon name="folder" size={13} />
          Evidence
          <small>{data?.remote?.bundles.length ?? 0}</small>
        </button>
        <button type="button" role="tab" aria-selected={tab === 'catalog'} className={tab === 'catalog' ? 'is-on' : ''} onClick={() => setTab('catalog')}>
          <Icon name="tag" size={13} />
          Artifact catalog
          <small>{artifactCatalog.length}</small>
        </button>
        <button type="button" role="tab" aria-selected={tab === 'server'} className={tab === 'server' ? 'is-on' : ''} onClick={() => setTab('server')}>
          <Icon name="server" size={13} />
          Server
          <i className={`threat-dot ${listenerRunning ? 'is-ok' : listener?.state === 'unhealthy' || listener?.state === 'foreign' || listener?.state === 'error' ? 'is-bad' : ''}`} aria-hidden="true" />
        </button>
      </div>

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

      {tab === 'server' && (
      <section id="threat-server" className="threat-server-section" aria-label="Artifact server setup">
        <div className="threat-server-heading">
          <div>
            <p className="eyebrow">Artifact server</p>
            <h2>Generated artifact server</h2>
            <p>
              Configure the listener for the Jinja2 artifact catalog. Listener
              settings are saved to and recovered from{' '}
              <code>{serverPath}</code>. Generate Server rebuilds{' '}
              <code>artifact_catalog.json</code> from{' '}
              <code>stix-server/exported_evidence/</code>, then regenerates{' '}
              <code>server.py</code> and <code>index.html</code>.
            </p>
          </div>
          <div className="threat-server-heading-actions">
            <Chip
              size="sm"
              variant="soft"
              color={
                listener?.state === 'running'
                  ? 'success'
                  : listener?.state === 'stopped' || listener === null
                    ? 'default'
                    : 'danger'
              }
            >
              {listenerBusy
                ? listenerBusy === 'start'
                  ? 'Starting…'
                  : 'Stopping…'
                : listener?.state === 'running'
                  ? `Running :${listener.port}`
                  : listener?.state === 'unhealthy'
                    ? 'Unhealthy'
                    : listener?.state === 'foreign'
                      ? 'Port in use'
                      : listener?.state === 'error'
                        ? 'Config error'
                        : 'Stopped'}
            </Chip>
            {listener?.state === 'running' && listener.url && (
              <a
                className="artifact-action"
                href={listener.url}
                target="_blank"
                rel="noreferrer"
              >
                <Icon name="link" size={14} />
                Open dashboard
              </a>
            )}
            <button
              type="button"
              className="artifact-action threat-generate-button"
              onClick={() => void controlListener()}
              disabled={listenerBusy !== null || listener?.state === 'foreign'}
            >
              <Icon name={listenerRunning ? 'x' : 'play'} size={14} />
              {listenerBusy
                ? listenerBusy === 'start'
                  ? 'Launching…'
                  : 'Stopping…'
                : listenerRunning
                  ? 'Stop Server'
                  : 'Launch Server'}
            </button>
            <button
              type="button"
              className="artifact-action threat-generate-button"
              onClick={() => void generateServer()}
              disabled={generating}
            >
              <Icon name="server" size={14} />
              {generating ? 'Generating…' : 'Generate Server'}
            </button>
          </div>
        </div>

        <div className="threat-subsection">
          <div className="threat-subsection-heading">
            <div>
              <h3>Listener configuration</h3>
              <p>Bind address and port used by the generated catalog server.</p>
            </div>
            <Chip size="sm" variant="soft" color={serverConfigError ? 'danger' : serverConfigSaved ? 'success' : 'accent'}>
              {serverConfigError
                ? 'File error'
                : serverConfigSaved
                  ? 'Saved'
                  : 'Not configured'}
            </Chip>
          </div>
          <form
            className="threat-server-config"
            onSubmit={(event) => void saveServerConfig(event)}
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
              <button type="submit" className="artifact-action" disabled={serverSaving}>
                {serverSaving ? 'Saving…' : 'Save configuration'}
              </button>
            </div>
          </form>
          {listener?.state === 'running' && (
            <p className="threat-listener-note" role="status">
              Serving at <code>{listener.url}</code>
              {listener.pid ? ` · pid ${listener.pid}` : ''}
            </p>
          )}
          {listenerError && (
            <Alert status="danger">
              <Alert.Title>Listener action failed</Alert.Title>
              <Alert.Description>{listenerError}</Alert.Description>
            </Alert>
          )}
        </div>

        <div className="threat-subsection">
          <div className="threat-subsection-heading">
            <div>
              <h3>Configuration file</h3>
              <p>Listener settings and banned artifacts are persisted here.</p>
            </div>
          </div>
          <div className="threat-config-path">
            <code>{serverPath}</code>
            <CopyButton text={serverPath} variant="ghost">Copy path</CopyButton>
          </div>
          {serverConfigError && (
            <Alert status="danger">
              <Alert.Title>Server configuration error</Alert.Title>
              <Alert.Description>{serverConfigError}</Alert.Description>
            </Alert>
          )}
        </div>

        {previewOpen && (
          <div className="threat-subsection">
            <div className="threat-subsection-heading">
              <div>
                <h3>Server output</h3>
                <p>Output from generation, Launch/Stop, and the files written.</p>
              </div>
              <div className="threat-generation-output-actions">
                <Chip
                  size="sm"
                  variant="soft"
                  color={generating ? 'accent' : generateError ? 'danger' : generatedPaths ? 'success' : 'default'}
                >
                  {generating
                    ? 'Generating…'
                    : generateError
                      ? 'Failed'
                      : generatedPaths
                        ? 'Generated'
                        : 'Idle'}
                </Chip>
                <button
                  type="button"
                  className="artifact-action"
                  onClick={() => setPreviewOpen(false)}
                >
                  Hide
                </button>
              </div>
            </div>
            {generateError && (
              <Alert status="danger">
                <Alert.Title>Server generation failed</Alert.Title>
                <Alert.Description>{generateError}</Alert.Description>
              </Alert>
            )}
            {generatedPaths && (
              <div className="threat-config-path">
                <code>
                  {generatedPaths.catalog} · {generatedPaths.server} · {generatedPaths.index}
                </code>
                <CopyButton
                  text={[generatedPaths.catalog, generatedPaths.server, generatedPaths.index].join('\n')}
                  variant="ghost"
                >
                  Copy paths
                </CopyButton>
              </div>
            )}
            <div className="threat-generation-output" aria-label="Server generation output">
              <OutputPre lines={serverOutput} />
            </div>
          </div>
        )}
      </section>
      )}

      {tab !== 'server' && (!data && loading ? (
        <Loading label="Loading remote evidence" />
      ) : (
        <>
          {tab === 'evidence' && (
          <section id="threat-evidence" className="threat-evidence-section" aria-label="Evidence workspace">
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
          </section>
          )}

          {tab === 'catalog' && (
          <section id="threat-catalog" className="threat-catalog-section" aria-label="Artifact catalog and bans">
            <div className="threat-catalog-heading">
              <div>
                <h2>Collected artifacts</h2>
                <p>
                  Local bundles on disk and remote bundles on MEGA, tagged by
                  source. Ban an artifact to hide it from the generated catalog
                  UI without deleting the catalog row.
                </p>
              </div>
              <div className="threat-catalog-counts">
                <Chip size="sm" variant="soft" color="success">{localArtifactCount} local</Chip>
                <Chip size="sm" variant="soft" color="accent">{remoteArtifactCount} remote</Chip>
                <Chip size="sm" variant="soft" color="success">{includedArtifacts.length} visible</Chip>
                <Chip size="sm" variant="soft" color={banned.length ? 'warning' : 'default'}>
                  {banned.length} banned
                </Chip>
                <button
                  type="button"
                  className="artifact-action"
                  onClick={() => void saveBanned([], 'Unban all')}
                  disabled={!banned.length || banSaving}
                >
                  Unban all
                </button>
              </div>
            </div>

            {banError && (
              <Alert status="danger">
                <Alert.Title>Ban list could not be saved</Alert.Title>
                <Alert.Description>{banError}</Alert.Description>
              </Alert>
            )}

            <div className="threat-subsection" id="threat-publish">
              <div className="threat-subsection-heading">
                <div>
                  <p className="eyebrow">Local → MEGA → catalog</p>
                  <h3>Publish local bundles</h3>
                  <p>
                    Select any bundle under <code>exports/</code>. Bundles that
                    are not on MEGA yet are pushed to <code>{remoteRoot || '/'}</code>{' '}
                    first; a bundle already there is not uploaded again. The
                    catalog is then rebuilt from MEGA so the generated server can
                    serve every selected bundle.
                  </p>
                </div>
                <div className="threat-catalog-counts">
                  <Chip
                    size="sm"
                    variant="soft"
                    color={publishableArtifacts.length ? 'accent' : 'default'}
                  >
                    {publishableArtifacts.length} local
                  </Chip>
                  <Chip
                    size="sm"
                    variant="soft"
                    color={pendingUploadCount ? 'warning' : 'success'}
                  >
                    {pendingUploadCount ? `${pendingUploadCount} need MEGA` : 'all on MEGA'}
                  </Chip>
                </div>
              </div>

              {publishDisabledReason && pendingUploadCount > 0 && (
                <Alert status="warning">
                  <Alert.Title>Uploading is unavailable</Alert.Title>
                  <Alert.Description>{publishDisabledReason}</Alert.Description>
                </Alert>
              )}

              {publishableArtifacts.length === 0 ? (
                <p className="artifact-list-empty">
                  No local bundles are available. Create one on the Artifacts
                  page first.
                </p>
              ) : (
                <>
                  <div className="threat-publish-actions">
                    <span>{publishSelected.length} selected</span>
                    <button
                      type="button"
                      className="artifact-action"
                      onClick={() =>
                        setPublishSelected(publishableArtifacts.map((artifact) => artifact.name))
                      }
                      disabled={publishing}
                    >
                      Select all
                    </button>
                    <button
                      type="button"
                      className="artifact-action"
                      onClick={() => setPublishSelected([])}
                      disabled={publishing || !publishSelected.length}
                    >
                      Clear
                    </button>
                    <button
                      type="button"
                      className="artifact-action"
                      onClick={() => void publishAndInclude()}
                      disabled={
                        publishing ||
                        !publishSelected.length ||
                        (uploadNeeded && Boolean(publishDisabledReason))
                      }
                    >
                      {publishing
                        ? 'Publishing…'
                        : uploadNeeded
                          ? 'Push to MEGA & include'
                          : 'Include in catalog'}
                      <span aria-hidden="true">↑</span>
                    </button>
                  </div>

                  {publishProgress && (
                    <p className="threat-progress" role="status">{publishProgress}</p>
                  )}

                  <div className="threat-bundle-list">
                    {publishableArtifacts.map((artifact) => {
                      const bundle = artifact.local
                      if (!bundle) return null
                      const verification = localVerification(bundle)
                      const checked = publishSelected.includes(artifact.name)
                      return (
                        <article
                          key={artifact.name}
                          className={`threat-bundle ${checked ? 'active' : ''}`}
                        >
                          <label className="threat-bundle-check">
                            <input
                              type="checkbox"
                              checked={checked}
                              onChange={() => togglePublish(artifact.name)}
                              disabled={publishing}
                              aria-label={`Publish ${artifact.name}`}
                            />
                          </label>
                          <div className="threat-bundle-select">
                            <span className="threat-bundle-name">{artifact.name}</span>
                            <span className="threat-bundle-meta">
                              {bundle.present
                                ? `${bundle.file_count} files · ${bytes(bundle.bytes)}`
                                : 'archive missing'}
                              {' · '}
                              {bundle.generated_at
                                ? new Date(bundle.generated_at * 1000).toLocaleString()
                                : 'generated time unknown'}
                            </span>
                            <span className="threat-bundle-files" title={bundle.verify_detail}>
                              {bundle.verify_detail}
                            </span>
                          </div>
                          <div className="threat-catalog-counts">
                            {artifact.remote && (
                              <Chip size="sm" variant="soft" color="success">
                                on MEGA
                              </Chip>
                            )}
                            <Chip size="sm" variant="soft" color={verification.color}>
                              {verification.label}
                            </Chip>
                          </div>
                        </article>
                      )
                    })}
                  </div>
                </>
              )}

              {publishError && (
                <Alert status="danger">
                  <Alert.Title>Publish failed</Alert.Title>
                  <Alert.Description>{publishError}</Alert.Description>
                </Alert>
              )}

              {(publishing || publishOutput.length > 1) && (
                <div className="threat-generation-output" aria-label="Publish output">
                  <div className="threat-generation-output-heading">
                    <span>Publish log</span>
                    <button
                      type="button"
                      className="artifact-action"
                      onClick={() => setPublishOutput(['Output cleared.'])}
                      disabled={publishing}
                    >
                      Clear
                    </button>
                  </div>
                  <OutputPre lines={publishOutput} />
                </div>
              )}
            </div>

            {banned.length > 0 && (
              <div className="threat-ban-bar" aria-label="Banned artifact keys">
                <span className="eyebrow">Banned bundles</span>
                <div className="threat-ban-chips">
                  {banned.map((entry) => (
                    <button
                      key={`${entry.name ?? ''}|${entry.hash ?? ''}`}
                      type="button"
                      className="threat-ban-chip"
                      onClick={() => removeBan(entry)}
                      disabled={banSaving}
                      title={`Unban ${entry.name ?? entry.hash ?? '(unknown)'}`}
                    >
                      <code>{entry.name ?? entry.hash ?? '(unknown)'}</code>
                      {entry.hash && (
                        <span className="threat-ban-hash">{entry.hash.slice(0, 12)}…</span>
                      )}
                      <Icon name="x" size={11} />
                    </button>
                  ))}
                </div>
              </div>
            )}

            <div className="threat-catalog-table-wrap">
              <table className="threat-catalog-table">
                <thead>
                  <tr>
                    <th>Sample name</th>
                    <th>Source</th>
                    <th>Contents</th>
                    <th>SHA-256</th>
                    <th>Timeline</th>
                    <th>MEGA link</th>
                    <th>CTI access</th>
                  </tr>
                </thead>
                <tbody>
                  {artifactCatalog.length ? artifactCatalog.map((artifact) => {
                    const verification = artifact.local ? localVerification(artifact.local) : null
                    const generated = artifact.local ? localTimestamp(artifact.local) : null
                    const hidden = isArtifactBanned(artifact)
                    return (
                      <tr key={artifact.name}>
                        <td title={artifact.name}>
                          <span className="threat-catalog-name">{artifact.name}</span>
                          <span
                            className="threat-catalog-sub"
                            title={artifact.local?.dir ?? artifact.remote?.dir ?? ''}
                          >
                            {artifact.local?.dir ?? artifact.remote?.dir ?? 'Directory unknown'}
                          </span>
                        </td>
                        <td>
                          <div className="threat-catalog-tags">
                            {artifact.local && (
                              <Chip size="sm" variant="soft" color="success">Local</Chip>
                            )}
                            {artifact.remote && (
                              <Chip size="sm" variant="soft" color="accent">Remote</Chip>
                            )}
                          </div>
                        </td>
                        <td>
                          <div className="threat-catalog-stack">
                            {artifact.local && (
                              <span>{artifact.local.file_count} files · {bytes(artifact.local.bytes)} local</span>
                            )}
                            {artifact.remote && (
                              <span>{artifact.remote.file_count} files · {bytes(artifact.remote.total_bytes)} on MEGA</span>
                            )}
                          </div>
                        </td>
                        <td>
                          <div className="threat-catalog-hash">
                            {artifact.hash
                              ? <code title={artifact.hash}>{artifact.hash}</code>
                              : <span className="threat-catalog-muted">Not available</span>}
                            {verification && (
                              <Chip
                                size="sm"
                                variant="soft"
                                color={verification.color}
                                title={artifact.local?.verify_detail}
                              >
                                {verification.label}
                              </Chip>
                            )}
                          </div>
                        </td>
                        <td>
                          <div className="threat-catalog-stack">
                            {artifact.remote && (
                              <span>
                                <span className="threat-catalog-muted">MEGA</span>{' '}
                                {remoteTimestamp(artifact.remote)}
                              </span>
                            )}
                            {artifact.local && (
                              <span>
                                <span className="threat-catalog-muted">Generated</span>{' '}
                                {generated
                                  ? new Date(generated * 1000).toLocaleString()
                                  : 'Unknown'}
                              </span>
                            )}
                          </div>
                        </td>
                        <td>
                          {artifact.link
                            ? <a href={artifact.link} target="_blank" rel="noreferrer">Open MEGA link</a>
                            : !linksLoaded
                              ? <span className="threat-catalog-muted">Checking link…</span>
                              : artifact.remote
                                ? <span className="threat-catalog-muted" title={linksError ?? undefined}>Not shared</span>
                                : <span className="threat-catalog-muted">Local only</span>}
                        </td>
                        <td>
                          <div className="threat-catalog-ban-control">
                            <Chip
                              size="sm"
                              variant="soft"
                              color={hidden ? 'warning' : 'success'}
                            >
                              {hidden ? 'Banned' : 'Visible'}
                            </Chip>
                            <button
                              type="button"
                              className="artifact-action threat-ban-button"
                              onClick={() => toggleServerArtifact(artifact)}
                              disabled={banSaving}
                              title={
                                artifact.hash
                                  ? `${hidden ? 'Unban' : 'Ban'} ${artifact.name} and sha256 ${artifact.hash}`
                                  : `${hidden ? 'Unban' : 'Ban'} ${artifact.name}`
                              }
                              aria-label={`${hidden ? 'Unban' : 'Ban'} ${artifact.name}`}
                            >
                              {hidden ? 'Unban' : 'Ban'}
                            </button>
                          </div>
                        </td>
                      </tr>
                    )
                  }) : (
                    <tr>
                      <td colSpan={7} className="threat-catalog-empty">
                        Artifacts will appear here when available from local bundles or MEGA.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>

            <details
              className="threat-log"
              open={banLogOpen}
              onToggle={(event) => setBanLogOpen(event.currentTarget.open)}
            >
              <summary>
                <Icon name="terminal" size={13} />
                Ban / unban activity
                <Chip size="sm" variant="soft" color={banSaving ? 'accent' : 'default'}>
                  {banSaving ? 'Saving…' : `${banned.length} banned`}
                </Chip>
              </summary>
              <div
                id="threat-ban-output"
                className="threat-subsection threat-ban-output-section"
              >
                <div className="threat-subsection-heading">
                  <div>
                    <p className="eyebrow">Ban / unban log</p>
                    <h3>Ban and unban activity</h3>
                    <p>
                      Every Ban, Unban and Unban all action is logged here with
                      the config path that was written.
                    </p>
                  </div>
                  <div className="threat-ban-output-actions">
                    <Chip size="sm" variant="soft" color={banSaving ? 'accent' : 'default'}>
                      {banSaving ? 'Saving…' : `${banned.length} banned`}
                    </Chip>
                    <button
                      type="button"
                      className="artifact-action"
                      onClick={() => setBanOutput(['Output cleared.'])}
                      disabled={banSaving}
                    >
                      Clear
                    </button>
                  </div>
                </div>
                <div className="threat-ban-output" aria-label="Ban and unban output">
                  <OutputPre lines={banOutput} />
                </div>
              </div>
            </details>
          </section>
          )}
        </>
      ))}

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
