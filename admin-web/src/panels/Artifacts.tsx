import { useEffect, useMemo, useRef, useState, type CSSProperties, type ReactNode } from 'react'
import { Alert } from '@heroui/react/alert'
import { Card } from '@heroui/react/card'
import { Chip } from '@heroui/react/chip'
import { api, usePoll } from '../api'
import Icon from '../components/Icon'
import JobLog from '../components/JobLog'
import Loading from '../components/Loading'
import Pager, { usePaged } from '../components/Pager'
import { Sparkline } from '../components/Stat'
import { ago, bytes } from '../lib/format'
import { useMinuteTick } from '../lib/tick'
import type { ArtifactsSnapshot, HistoryBundle, LocalBundle, RemoteBundle, UnifiedBundle } from '../types'

const POLL_MS = 120_000
type Tab = 'local' | 'remote'
type Tone = 'accent' | 'success' | 'warning' | 'danger'

function shortStamp(ts: number | null | undefined): string {
  if (!ts) return '—'
  return new Date(ts * 1000).toISOString().replace('T', ' ').slice(0, 16)
}

/**
 * Colour for `mega/upload.py` output.
 *
 * That script prefixes every step with `[+]`, so its progress lines are told
 * apart by that prefix rather than by matching words like "uploaded" - a bundle
 * whose name contains "error" is a bundle name, not a failure. The state chip
 * carries the verdict; this only makes the steps scannable.
 */
function exportLineClass(line: string): string {
  if (/^\[\+\]/.test(line)) return 'compose-tok-string'
  if (/^\[!\]|^\[x\]|error|failed|refus/i.test(line)) return 'compose-tok-bool'
  if (/^\[#/.test(line)) return 'compose-tok-comment'
  return 'compose-tok-plain'
}

function VerifyMark({ bundle }: { bundle: LocalBundle }) {
  if (!bundle.present) return <Chip size="sm" variant="soft" color="warning">no archive</Chip>
  if (bundle.verified === true) return <Chip size="sm" variant="soft" color="success">verified</Chip>
  if (bundle.verified === false) return <Chip size="sm" variant="soft" color="danger">digest mismatch</Chip>
  return <Chip size="sm" variant="soft" title={bundle.verify_detail}>not hashed</Chip>
}

function MetricTile({
  label,
  value,
  note,
  icon,
  tone = 'accent',
  trend,
  trendMax,
}: {
  label: string
  value: string
  note: string
  icon: ReactNode
  tone?: Tone
  trend?: (number | null)[]
  trendMax?: number | null
}) {
  return (
    <div className="stat-tile artifact-metric">
      <div className="flex items-start justify-between gap-3">
        <span className="eyebrow">{label}</span>
        <span className={`artifact-metric-icon artifact-tone-${tone}`}>{icon}</span>
      </div>
      <div className="metric mt-3 break-words font-mono text-xl font-semibold leading-tight text-foreground">
        {value}
      </div>
      <p className="mt-1.5 min-h-4 text-[11px] text-default-500">{note}</p>
      {trend && trend.length > 1 && (
        <div className="mt-2">
          <Sparkline data={trend} tone={tone} max={trendMax} height={30} />
        </div>
      )}
    </div>
  )
}

type ArtifactStat = {
  name: string
  dir: string
  bytes: number
  timestamp: number | null
}

function HighlightTile({
  label,
  artifact,
  detail,
  icon,
  emptyText,
}: {
  label: string
  artifact: ArtifactStat | null
  detail: string
  icon: ReactNode
  emptyText?: string
}) {
  return (
    <div className="artifact-highlight">
      <div className="flex items-center justify-between gap-3">
        <span className="eyebrow">{label}</span>
        <span className="artifact-metric-icon artifact-tone-accent">{icon}</span>
      </div>
      <p className="mt-3 font-mono text-lg font-semibold leading-tight text-foreground">
        {artifact ? bytes(artifact.bytes, 1) : '—'}
      </p>
      <p className="mt-1 truncate text-xs font-medium text-foreground" title={artifact?.dir}>
        {artifact?.dir ?? emptyText ?? 'No artifact available'}
      </p>
      <p className="mt-1 text-[11px] text-default-500">
        {artifact ? detail : ''}
        {artifact?.timestamp ? ` · ${ago(artifact.timestamp)}` : ''}
      </p>
    </div>
  )
}

function TopArtifacts({
  title,
  artifacts,
  unavailable,
}: {
  title: string
  artifacts: ArtifactStat[]
  unavailable?: string | null
}) {
  const ranked = [...artifacts].sort((a, b) => b.bytes - a.bytes).slice(0, 5)
  return (
    <Card className="artifact-ranking-card w-full">
      <Card.Header className="flex items-start justify-between gap-3">
        <div>
          <Card.Title>{title}</Card.Title>
          <p className="mt-1 text-[11px] text-default-500">Largest archive sizes, first</p>
        </div>
        <Icon name="stats" size={16} />
      </Card.Header>
      <Card.Content>
        {unavailable ? (
          <p className="artifact-ranking-empty">{unavailable}</p>
        ) : ranked.length === 0 ? (
          <p className="artifact-ranking-empty">No artifacts found.</p>
        ) : (
          <ol className="artifact-ranking-list">
            {ranked.map((artifact, index) => (
              <li key={artifact.name} className="artifact-ranking-row">
                <span className="artifact-ranking-position">{String(index + 1).padStart(2, '0')}</span>
                <span className="artifact-ranking-name" title={artifact.dir}>{artifact.dir}</span>
                <span className="artifact-ranking-size">{bytes(artifact.bytes, 1)}</span>
              </li>
            ))}
          </ol>
        )}
      </Card.Content>
    </Card>
  )
}

function ArtifactStats({
  local,
  remote,
  remoteAvailable,
  remoteReason,
}: {
  local: LocalBundle[]
  remote: RemoteBundle[]
  remoteAvailable: boolean
  remoteReason: string | null
}) {
  const localStats: ArtifactStat[] = local.map((bundle) => ({
    name: bundle.name,
    dir: bundle.dir,
    bytes: bundle.bytes,
    timestamp: bundle.generated_at ?? bundle.modified,
  }))
  const remoteStats: ArtifactStat[] = remote.map((bundle) => ({
    name: bundle.name,
    dir: bundle.dir,
    bytes: bundle.bytes,
    timestamp: bundle.modified,
  }))
  const largest = (items: ArtifactStat[]) =>
    items.reduce<ArtifactStat | null>(
      (best, artifact) => !best || artifact.bytes > best.bytes ? artifact : best,
      null,
    )
  const latest = (items: ArtifactStat[]) =>
    items.reduce<ArtifactStat | null>(
      (best, artifact) => artifact.timestamp !== null &&
        (!best || artifact.timestamp > (best.timestamp ?? 0)) ? artifact : best,
      null,
    )
  const remoteUnavailable = remoteAvailable ? null : remoteReason ?? 'Remote listing unavailable.'

  return (
    <section className="artifact-stats" aria-labelledby="artifact-stats-title">
      <div className="artifact-section-heading">
        <div>
          <p className="eyebrow">Artifact overview</p>
          <h2 id="artifact-stats-title" className="mt-1 text-lg font-semibold tracking-tight text-foreground">
            Size &amp; recency
          </h2>
          <p className="mt-1 text-xs text-default-500">
            Local archives and confirmed remote MEGA copies are measured separately.
          </p>
        </div>
        <span className="artifact-section-icon" aria-hidden="true"><Icon name="stats" size={17} /></span>
      </div>

      <div className="artifact-highlight-grid">
        <HighlightTile
          label="Largest local artifact"
          artifact={largest(localStats)}
          detail="Local archive"
          icon={<Icon name="machine" size={15} />}
        />
        <HighlightTile
          label="Latest local artifact"
          artifact={latest(localStats)}
          detail="Most recently generated"
          icon={<Icon name="refresh" size={15} />}
        />
        <HighlightTile
          label="Largest remote artifact"
          artifact={largest(remoteStats)}
          detail="Remote archive"
          icon={<Icon name="artifacts" size={15} />}
          emptyText={remoteAvailable ? 'No remote artifacts' : remoteReason ?? 'Remote listing unavailable'}
        />
        <HighlightTile
          label="Latest remote artifact"
          artifact={latest(remoteStats)}
          detail="Most recently modified on MEGA"
          icon={<Icon name="refresh" size={15} />}
          emptyText={remoteAvailable ? 'No remote artifacts' : remoteReason ?? 'Remote listing unavailable'}
        />
      </div>

      <div className="artifact-ranking-grid">
        <TopArtifacts title="Top 5 sized artifacts · local" artifacts={localStats} />
        <TopArtifacts
          title="Top 5 sized artifacts · remote"
          artifacts={remoteStats}
          unavailable={remote.length === 0 ? remoteUnavailable : null}
        />
      </div>
    </section>
  )
}

function BundleTimelineNote({
  path,
  written,
  updatedAt,
}: {
  path: string
  written: boolean
  updatedAt: number | null
}) {
  return (
    <p className="artifact-cache-note" title={path}>
      Timeline cache: {path || 'not available'}{written ? '' : ' · not written yet'}
      {' · '}updated {ago(updatedAt)}
    </p>
  )
}

function LocalList({
  bundles,
  historyPath,
  historyWritten,
  historyAt,
}: {
  bundles: LocalBundle[]
  historyPath: string
  historyWritten: boolean
  historyAt: number | null
}) {
  const paged = usePaged(bundles)
  return (
    <Card className="w-full">
      <Card.Header className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <Card.Title>Local bundles</Card.Title>
          <p className="mt-1 text-[11px] text-default-500">Evidence archives found under exports/</p>
        </div>
        <Chip size="sm" variant="soft">{bundles.length} found</Chip>
      </Card.Header>
      <Card.Content className="flex flex-col gap-2">
        {bundles.length === 0 ? (
          <p className="artifact-list-empty">No evidence bundles found in <code>exports/</code>.</p>
        ) : (
          <>
            <div className="timeline">
              {paged.slice.map((bundle) => {
                const flagged = bundle.size_matches === false || bundle.digests_match === false
                return (
                  <div key={bundle.name} className="timeline-item mb-2 last:mb-0">
                    <span
                      className="timeline-node"
                      style={{
                        '--node': bundle.verified === true
                          ? 'var(--success)'
                          : bundle.verified === false ? 'var(--danger)' : 'var(--default-400)',
                      } as CSSProperties}
                    />
                    <div
                      className="timeline-card"
                      data-flag={flagged}
                      style={flagged ? { '--flag': 'var(--warning)' } as CSSProperties : undefined}
                    >
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <span className="min-w-0 truncate font-mono text-[12px]" title={bundle.name}>
                          {bundle.dir}
                        </span>
                        <div className="flex flex-wrap items-center justify-end gap-1.5">
                          <VerifyMark bundle={bundle} />
                          <Chip size="sm" variant="soft">{bundle.file_count} files</Chip>
                          <Chip size="sm" variant="soft">{bytes(bundle.bytes)}</Chip>
                          {bundle.present && (
                            <a
                              className="artifact-action"
                              href={api.artifactArchiveUrl(bundle.name)}
                              title={`Open or download ${bundle.archive ?? bundle.name}`}
                            >
                              Open artifact
                              <span aria-hidden="true">↗</span>
                            </a>
                          )}
                        </div>
                      </div>
                      <div className="artifact-bundle-details">
                        <span>Generated</span>
                        <span className="font-mono">{shortStamp(bundle.generated_at)}</span>
                        <span>Archive modified</span>
                        <span className="font-mono">{ago(bundle.modified)}</span>
                      </div>
                    </div>
                  </div>
                )
              })}
            </div>
            <Pager
              page={paged.page}
              pages={paged.pages}
              first={paged.first}
              last={paged.last}
              total={bundles.length}
              onPrev={paged.prev}
              onNext={paged.next}
            />
          </>
        )}
        <BundleTimelineNote path={historyPath} written={historyWritten} updatedAt={historyAt} />
      </Card.Content>
    </Card>
  )
}

function RemoteList({
  bundles,
  truncated,
  notExamined,
  remoteRoot,
  onRecovered,
  historyPath,
  historyWritten,
  historyAt,
  uploadEnabled,
  onExportStarted,
  encryptEnabled,
  recipient,
}: {
  bundles: UnifiedBundle[]
  truncated: string | null
  notExamined: number
  remoteRoot: string
  onRecovered: () => void
  historyPath: string
  historyWritten: boolean
  historyAt: number | null
  /** Whether config/artifacts.yaml permits pushing evidence to MEGA at all.
   *  Read once here rather than per bundle so a disabled account shows one
   *  explanation instead of a button per row that all fail the same way. */
  uploadEnabled: boolean
  /** Whether exports are sealed to a public key first. */
  encryptEnabled: boolean
  /** Which key, when encryptEnabled. */
  recipient: string
  /** Hand the job to the page, which owns the log modal: a running upload must
   *  not be tied to a list the operator can page away from. */
  onExportStarted: (job: { jobId: string; name: string }) => void
}) {
  const paged = usePaged(bundles)
  const missing = bundles.filter((bundle) => !bundle.present).length
  const [recovering, setRecovering] = useState<string | null>(null)
  const [recoverError, setRecoverError] = useState<{ name: string; message: string } | null>(null)
  const [exporting, setExporting] = useState<string | null>(null)
  const [exportError, setExportError] = useState<{ name: string; message: string } | null>(null)

  const recover = async (name: string) => {
    setRecovering(name)
    setRecoverError(null)
    try {
      await api.recoverArtifact(name, remoteRoot)
      onRecovered()
    } catch (error) {
      setRecoverError({
        name,
        message: error instanceof Error ? error.message : String(error),
      })
    } finally {
      setRecovering(null)
    }
  }

  // The mirror of recover: push what is on disk up to MEGA. It is a job, not a
  // request, because sealing a large bundle and pushing it over a consumer link
  // takes minutes - and the log is the part worth watching.
  const exportBundle = async (name: string) => {
    setExporting(name)
    setExportError(null)
    try {
      const res = await api.exportArtifact(name, remoteRoot)
      onExportStarted({ jobId: res.job_id, name })
    } catch (error) {
      setExportError({
        name,
        message: error instanceof Error ? error.message : String(error),
      })
    } finally {
      setExporting(null)
    }
  }

  return (
    <Card className="w-full">
      <Card.Header className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <Card.Title>Remote bundles</Card.Title>
          <p className="mt-1 text-[11px] text-default-500">MEGA uploads and remembered bundle history</p>
        </div>
        <div className="flex flex-wrap gap-2">
          <Chip size="sm" variant="soft">{bundles.length} found</Chip>
          {missing > 0 && <Chip size="sm" variant="soft" color="warning">{missing} not present remotely</Chip>}
        </div>
      </Card.Header>
      <Card.Content className="flex flex-col gap-2">
        {!uploadEnabled && (
          <Alert status="warning">
            <Alert.Title>Export is disabled</Alert.Title>
            <Alert.Description>
              <code className="font-mono">upload_artifacts</code> is false in{' '}
              <code className="font-mono">config/artifacts.yaml</code>, so evidence cannot be
              pushed to MEGA from here - the same option that stops the analyzer doing it on a
              run. Recover still works: pulling evidence down does not send it anywhere. Turn it
              back on under <strong>Analysis → Analysis Configuration → Upload &amp; artifacts</strong>.
            </Alert.Description>
          </Alert>
        )}
        {bundles.length === 0 ? (
          <p className="artifact-list-empty">No bundles on MEGA yet. Local archives are still listed in the Local tab.</p>
        ) : (
          <>
            <div className="timeline">
              {paged.slice.map((bundle) => {
                const tone = bundle.present ? 'var(--success)' : 'var(--danger)'
                return (
                  <div key={bundle.name} className="timeline-item mb-2 last:mb-0">
                    <span className="timeline-node" style={{ '--node': tone } as CSSProperties} />
                    <div className="timeline-card" data-flag={!bundle.present}>
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <span className="min-w-0 truncate font-mono text-[12px]" title={bundle.name}>
                          {bundle.dir}
                        </span>
                        <div className="flex flex-wrap items-center justify-end gap-1.5">
                          <Chip size="sm" variant="soft" color={bundle.present ? 'success' : 'warning'}>
                            {bundle.present ? `${bundle.where} · present` : 'missing remotely'}
                          </Chip>
                          <Chip size="sm" variant="soft">{bundle.file_count} files</Chip>
                          <Chip size="sm" variant="soft">{bytes(bundle.bytes)}</Chip>
                          {bundle.present && bundle.where !== 'remote' && (
                            <a
                              className="artifact-action"
                              href={api.artifactArchiveUrl(bundle.name)}
                              title={`Open or download ${bundle.archive ?? bundle.name}`}
                            >
                              Open artifact
                              <span aria-hidden="true">↗</span>
                            </a>
                          )}
                          {bundle.present &&
                            (bundle.where === 'remote' || bundle.where === 'both') && (
                            <button
                              type="button"
                              className="artifact-action"
                              title={bundle.where === 'both'
                                ? 'This bundle is already available locally; open that copy instead.'
                                : 'Recover this bundle from MEGA'}
                              onClick={() => void recover(bundle.name)}
                              disabled={recovering !== null || bundle.where === 'both'}
                            >
                              {bundle.where === 'both'
                                ? 'Already local'
                                : recovering === bundle.name ? 'Recovering…' : 'Recover from MEGA'}
                              {bundle.where !== 'both' && <span aria-hidden="true">↓</span>}
                            </button>
                          )}
                          {/* Export only where it means something: a bundle that is
                              on disk and not on MEGA. Offering it for one that is
                              already there would re-upload the same bytes under the
                              same name. */}
                          {bundle.present && bundle.where === 'local' && (
                            <button
                              type="button"
                              className="artifact-action"
                              title={uploadEnabled
                                ? (encryptEnabled
                                  ? `Seal this bundle to the '${recipient}' public key and upload it to MEGA ${remoteRoot}`
                                  : `Upload this bundle to MEGA ${remoteRoot} UNSEALED`)
                                : 'Uploading is disabled by upload_artifacts in config/artifacts.yaml'}
                              onClick={() => void exportBundle(bundle.name)}
                              disabled={exporting !== null || !uploadEnabled}
                            >
                              {exporting === bundle.name
                                ? 'Exporting…'
                                : encryptEnabled ? 'Export to MEGA' : 'Export unencrypted'}
                              <span aria-hidden="true">↑</span>
                            </button>
                          )}
                        </div>
                      </div>
                      <div className="artifact-bundle-details">
                        <span>Timestamp</span>
                        <span className="font-mono">{bundle.date_text ?? shortStamp(bundle.modified)}</span>
                        <span>Last seen</span>
                        <span className="font-mono">{ago(bundle.last_seen ?? bundle.modified)}</span>
                      </div>
                      {recoverError?.name === bundle.name && (
                        <Alert status="danger" className="mt-2">
                          <Alert.Title>Recovery failed</Alert.Title>
                          <Alert.Description>{recoverError.message}</Alert.Description>
                        </Alert>
                      )}
                      {exportError?.name === bundle.name && (
                        <Alert status="danger" className="mt-2">
                          <Alert.Title>Export failed</Alert.Title>
                          <Alert.Description>{exportError.message}</Alert.Description>
                        </Alert>
                      )}
                    </div>
                  </div>
                )
              })}
            </div>
            <Pager
              page={paged.page}
              pages={paged.pages}
              first={paged.first}
              last={paged.last}
              total={bundles.length}
              onPrev={paged.prev}
              onNext={paged.next}
            />
          </>
        )}
        {(truncated || notExamined > 0) && (
          <Alert status="warning" className="mt-2">
            <Alert.Title>Remote listing is partial</Alert.Title>
            <Alert.Description>{truncated ?? `${notExamined} bundles were not examined.`}</Alert.Description>
          </Alert>
        )}
        <BundleTimelineNote path={historyPath} written={historyWritten} updatedAt={historyAt} />
      </Card.Content>
    </Card>
  )
}

export default function Artifacts() {
  const [tab, setTab] = useState<Tab>('local')
  const forceRefresh = useRef(false)
  useMinuteTick()
  const { data, error, loading, refresh } = usePoll<ArtifactsSnapshot>(
    () => api.artifacts('/', forceRefresh.current),
    POLL_MS,
  )
  // Whether this lab permits pushing evidence off the host at all. Read from the
  // same config the analyzer reads, so the button and the option cannot disagree
  // - and so the page can explain a disabled button instead of leaving the
  // operator to discover it by clicking.
  const { data: analysis } = usePoll(api.analysisConfig, 120_000)
  const uploadEnabled = analysis?.mega_upload ?? true
  // What an export will actually do, decided server-side from the same config
  // the analyzer reads. Shown on the button because "this leaves the host" and
  // "this leaves the host readable by anyone holding the key" are different
  // claims, and the operator should be able to see which one they are making.
  const encryptEnabled = analysis?.mega_encrypt ?? false
  const recipient = analysis?.encryption_recipient ?? 'user'
  const [exportJob, setExportJob] = useState<{ jobId: string; name: string } | null>(null)

  useEffect(() => {
    if (data) forceRefresh.current = false
  }, [data])

  const localBundles = data?.local?.bundles ?? []
  const summary = useMemo(() => {
    const totalBytes = localBundles.reduce((sum, bundle) => sum + (bundle.bytes ?? 0), 0)
    const verified = localBundles.filter((bundle) => bundle.verified === true).length
    const attention = localBundles.filter(
      (bundle) => !bundle.present || bundle.verified === false ||
        bundle.size_matches === false || bundle.digests_match === false,
    ).length
    return { totalBytes, verified, attention }
  }, [localBundles])

  const remoteBundles: UnifiedBundle[] = data?.unified ?? (data?.history?.bundles ?? []).map(
    (bundle: HistoryBundle) => ({ ...bundle, where: 'remembered' }),
  )
  const refreshNow = () => {
    forceRefresh.current = true
    refresh()
  }

  return (
    <div className="artifact-page">
      <header className="artifact-page-header">
        <div>
          <p className="eyebrow">Evidence management</p>
          <h1 className="page-title mt-1">Artifacts</h1>
          <p className="mt-2 max-w-2xl text-xs text-default-500">
            Local bundle integrity, remote copies, storage totals, and upload activity.
          </p>
        </div>
        <div className="artifact-page-actions">
          <span className="font-mono text-[11px] text-default-400">
            {data?.generated_at ? `Updated ${ago(data.generated_at)}` : 'Waiting for first scan'}
          </span>
          <button type="button" className="artifact-refresh" onClick={refreshNow} disabled={loading}>
            <Icon name="refresh" size={13} />
            {loading ? 'Refreshing…' : 'Refresh'}
          </button>
        </div>
      </header>

      {error && (
        <Alert status="danger" className="mb-4">
          <Alert.Title>Artifact data unavailable</Alert.Title>
          <Alert.Description>{error}</Alert.Description>
        </Alert>
      )}
      {loading && !data && <Loading label="Loading artifacts…" hint="checking local bundles and remote history" />}

      {data && (
        <div className="space-y-5">
          <section aria-label="Artifact summary">
            <div className="artifact-summary-grid">
              <MetricTile
                label="Local artifacts"
                value={String(localBundles.length)}
                note={`${summary.verified} verified`}
                icon={<Icon name="artifacts" size={15} />}
                trend={[localBundles.length, summary.verified]}
                trendMax={Math.max(localBundles.length, 1)}
              />
              <MetricTile
                label="Local storage"
                value={bytes(summary.totalBytes, 0)}
                note="total archive size"
                icon={<Icon name="machine" size={15} />}
                tone="success"
              />
              <MetricTile
                label="Remote artifacts"
                value={data.remote?.available ? String(data.remote.bundles.length) : '—'}
                note={data.remote?.available
                  ? `${bytes(data.remote.counts?.bytes ?? 0, 0)} stored on MEGA`
                  : data.remote?.reason ?? 'Remote listing unavailable'}
                icon={<Icon name="artifacts" size={15} />}
                tone={data.remote?.available ? 'success' : 'warning'}
              />
              <MetricTile
                label="Needs attention"
                value={String(summary.attention)}
                note="missing or integrity check failed"
                icon={<Icon name="overview" size={15} />}
                tone={summary.attention > 0 ? 'warning' : 'success'}
              />
            </div>
          </section>

          <ArtifactStats
            local={localBundles}
            remote={data.remote?.available ? data.remote.bundles : []}
            remoteAvailable={data.remote?.available ?? false}
            remoteReason={data.remote?.reason ?? null}
          />

          <section className="artifact-bundle-section" aria-label="Artifact bundles">
            <div className="artifact-tabs" role="tablist" aria-label="Bundle location">
              {(['local', 'remote'] as const).map((value) => (
                <button
                  key={value}
                  id={`artifact-tab-${value}`}
                  type="button"
                  role="tab"
                  aria-selected={tab === value}
                  aria-controls={`artifact-panel-${value}`}
                  className={`artifact-tab ${tab === value ? 'active' : ''}`}
                  onClick={() => setTab(value)}
                >
                  <Icon name={value === 'local' ? 'machine' : 'artifacts'} size={14} />
                  <span>{value === 'local' ? 'Local' : 'Remote'}</span>
                  <span className="artifact-tab-count">
                    {value === 'local' ? localBundles.length : remoteBundles.length}
                  </span>
                </button>
              ))}
            </div>
            <div
              id={`artifact-panel-${tab}`}
              role="tabpanel"
              aria-labelledby={`artifact-tab-${tab}`}
              className="mt-3"
            >
              {tab === 'local' ? (
                <LocalList
                  bundles={localBundles}
                  historyPath={data.history?.path ?? ''}
                  historyWritten={data.history?.written ?? false}
                  historyAt={data.history?.updated_at ?? null}
                />
              ) : (
                <RemoteList
                  bundles={remoteBundles}
                  truncated={data.remote?.truncated ?? null}
                  notExamined={data.remote?.not_examined ?? 0}
                  remoteRoot={data.remote?.remote_root ?? '/'}
                  onRecovered={refreshNow}
                  historyPath={data.history?.path ?? ''}
                  historyWritten={data.history?.written ?? false}
                  historyAt={data.history?.updated_at ?? null}
                  uploadEnabled={uploadEnabled}
                  encryptEnabled={encryptEnabled}
                  recipient={recipient}
                  onExportStarted={setExportJob}
                />
              )}
            </div>
          </section>

          {data.diff && (data.diff.only_local.length > 0 || data.diff.only_remote.length > 0) && (
            <Card className="w-full">
              <Card.Header><Card.Title>Bundles out of sync</Card.Title></Card.Header>
              <Card.Content className="grid gap-2 text-xs sm:grid-cols-2">
                {data.diff.only_local.length > 0 && (
                  <p className="break-words text-default-500">
                    <span className="text-default-400">Local only: </span>
                    <span className="font-mono">{data.diff.only_local.join(', ')}</span>
                  </p>
                )}
                {data.diff.only_remote.length > 0 && (
                  <p className="break-words text-default-500">
                    <span className="text-default-400">Remote only: </span>
                    <span className="font-mono">{data.diff.only_remote.join(', ')}</span>
                  </p>
                )}
              </Card.Content>
            </Card>
          )}
        </div>
      )}

      {/* Started inside RemoteList, owned here: the job outlives the list it was
          started from - paging or a tab switch must not orphan a running
          upload - and closing the log must not cancel it. */}
      {exportJob && (
        <JobLog
          jobId={exportJob.jobId}
          title={`Exporting ${exportJob.name}`}
          subtitle="mega/upload.py"
          fetchJob={(id) => api.artifactExportJob(id)}
          onClose={() => setExportJob(null)}
          onFinished={(job) => { if (job.state !== 'error') refreshNow() }}
          lineClass={exportLineClass}
        />
      )}
    </div>
  )
}
