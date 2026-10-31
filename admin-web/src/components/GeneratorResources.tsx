import { useState } from 'react'
import { Alert, Card, Chip } from '@heroui/react'
import { api } from '../api'
import Icon, { type IconName } from './Icon'
import Loading from './Loading'
import Checkbox from './Checkbox'
import { ago, bytes } from '../lib/format'
import type {
  SampleResource,
  SampleResourceKind,
  SampleResourceKindInfo,
  SampleResourcesSnapshot,
} from '../types'

// ---------------------------------------------------------------------------
// Generator resources.
//
// One card per pool of BAIT values the sample factory samples from: malicious
// IPs, domains, URLs and file hashes.
// They are integrations with the operator's own feeds (any http(s) host), not
// detection knowledge - the factory copies one sampled value per pool into a
// generated C/C++ literal, in whichever form the IOC encoding option names
// (plain, ROT13, XOR, Base64 or a per-value mix), and nothing is dialled. Every
// card says so, because a list titled "malicious IPs" invites exactly the
// wrong assumption.
//
// The page's job is maintenance, like the YARA and MalAPI cards above it:
// add a source, fetch it, see what it parsed to, see what it last failed at.
// The two facts that matter side by side are "how old is the good data" and
// "when did the last refresh fail" - a failed refresh never empties the pool,
// so the operator can decide whether stale bait is still good enough.
// ---------------------------------------------------------------------------

const KIND_ICON: Record<SampleResourceKind, IconName> = {
  ip: 'server',
  domain: 'link',
  url: 'network',
  hash: 'tag',
}

export default function GeneratorResources({
  snapshot,
  error,
  onReload,
}: {
  snapshot: SampleResourcesSnapshot | null
  error: string | null
  /** Re-read the snapshot after every write, so the pools shown are the file's. */
  onReload: () => Promise<void>
}) {
  if (error && !snapshot) {
    return (
      <Alert status="danger">
        <Alert.Title>The resource pools are unreachable</Alert.Title>
        <Alert.Description>{error}</Alert.Description>
      </Alert>
    )
  }
  if (!snapshot) return <Loading label="reading generator resources" />

  const anySource = snapshot.kinds.some((k) => k.resources.length > 0)

  return (
    <div className="flex flex-col gap-4">
      <Card className="build-card">
        <Card.Content className="build-card-body">
          <p className="text-[11px] text-muted">
            Definitions live in <code>{snapshot.path}</code>; the dumps the
            server serves them from and their parsed values live in{' '}
            <code>{snapshot.dump_dir}/</code>, never in git. Any <code>http(s)</code>{' '}
            URL is accepted, a <code>github.com</code> file page is rewritten to
            its raw URL, and a fetch is capped at{' '}
            {snapshot.limits.max_entries.toLocaleString()} values and{' '}
            {bytes(snapshot.limits.max_bytes, 0)}. Up to{' '}
            {snapshot.limits.max_resources} sources in total.
          </p>
          <p className="mt-1.5 text-[11px] text-muted">
            These are <b>bait literals, not detection rules</b>: the sample
            factory copies a sampled value into a generated source, and nothing
            is dialled. The pools feed <b>Resource IOCs</b> in{' '}
            <b>Build → Sample generation</b>, where the <b>IOC encoding</b>{' '}
            select decides whether each value is stored plain, ROT13-, XOR- or
            Base64-encoded (or a per-value mix). This page only keeps the lists.
          </p>
          {error && (
            <Alert status="danger" className="mt-2">
              <Alert.Description>{error}</Alert.Description>
            </Alert>
          )}
        </Card.Content>
      </Card>

      {snapshot.error ? (
        <Alert status="danger">
          <Alert.Title>The definitions file could not be read</Alert.Title>
          <Alert.Description>
            {snapshot.error} — fix or remove{' '}
            <code>{snapshot.path}</code>; the panel will not overwrite a file it
            cannot understand.
          </Alert.Description>
        </Alert>
      ) : (
        <>
          {!anySource && (
            <Alert status="warning">
              <Alert.Description>
                No sources yet, so the factory's resource checkboxes stay
                disabled. Add a URL below; it is fetched immediately
                and every line is validated for the pool's kind.
              </Alert.Description>
            </Alert>
          )}
          <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
            {snapshot.kinds.map((info) => (
              <KindCard key={info.kind} info={info} onReload={onReload} />
            ))}
          </div>
        </>
      )}
    </div>
  )
}

function KindCard({ info, onReload }: {
  info: SampleResourceKindInfo
  onReload: () => Promise<void>
}) {
  const [label, setLabel] = useState('')
  const [url, setUrl] = useState('')
  const [busy, setBusy] = useState<string | null>(null)
  const [formError, setFormError] = useState<string | null>(null)
  const [notes, setNotes] = useState<Record<string, string>>({})
  const [cardNote, setCardNote] = useState<string | null>(null)

  const submit = async (event: React.FormEvent) => {
    event.preventDefault()
    if (!label.trim() || !url.trim()) return
    setBusy('add')
    setFormError(null)
    setCardNote(null)
    try {
      const res = await api.addSampleResource({
        label: label.trim(), kind: info.kind, url: url.trim(), fetch: true,
      })
      setLabel('')
      setUrl('')
      // The definition was written even when the first fetch failed; say which
      // half succeeded rather than rendering a bare list row with no values.
      if (res.refresh && !res.refresh.ok) {
        setCardNote(`${label.trim()} was added, but its first fetch failed: `
          + `${res.refresh.error}. The source is listed below; fix the link and `
          + 'press Refresh.')
      } else {
        setCardNote(`${label.trim()} added - ${res.refresh?.count ?? 0} values.`)
      }
      await onReload()
    } catch (e) {
      setFormError(e instanceof Error ? e.message : String(e))
    } finally {
      setBusy(null)
    }
  }

  const refresh = async (row: SampleResource) => {
    setBusy(row.id)
    setNotes((n) => ({ ...n, [row.id]: '' }))
    try {
      const res = await api.refreshSampleResource(row.id)
      if (res.ok) {
        const skipped = res.refresh?.invalid ?? 0
        const dupes = res.refresh?.duplicates ?? 0
        const extra = [
          skipped ? `${skipped} line(s) skipped` : '',
          dupes ? `${dupes} duplicate(s) dropped` : '',
          res.refresh?.truncated ? 'the value cap was reached' : '',
        ].filter(Boolean).join(', ')
        setNotes((n) => ({
          ...n,
          [row.id]: `Fetched ${res.refresh?.count ?? 0} values`
            + (extra ? ` - ${extra}.` : '.'),
        }))
      } else {
        setNotes((n) => ({
          ...n,
          [row.id]: `Refresh failed: ${res.refresh?.error ?? 'unknown error'}`
            + ' The previous values are still in use.',
        }))
      }
      await onReload()
    } catch (e) {
      setNotes((n) => ({
        ...n, [row.id]: e instanceof Error ? e.message : String(e),
      }))
    } finally {
      setBusy(null)
    }
  }

  const toggle = async (row: SampleResource, enabled: boolean) => {
    setBusy(row.id)
    setNotes((n) => ({ ...n, [row.id]: '' }))
    try {
      await api.updateSampleResource(row.id, { enabled })
      await onReload()
    } catch (e) {
      setNotes((n) => ({
        ...n, [row.id]: e instanceof Error ? e.message : String(e),
      }))
    } finally {
      setBusy(null)
    }
  }

  const remove = async (row: SampleResource) => {
    setBusy(row.id)
    setNotes((n) => ({ ...n, [row.id]: '' }))
    try {
      await api.deleteSampleResource(row.id)
      setCardNote(`Removed ${row.label} and its cached values.`)
      await onReload()
    } catch (e) {
      setNotes((n) => ({
        ...n, [row.id]: e instanceof Error ? e.message : String(e),
      }))
    } finally {
      setBusy(null)
    }
  }

  const poolTone = info.pool_size > 0 ? 'success' : 'default'
  return (
    <Card className="build-card">
      <Card.Header className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <Card.Title className="flex items-center gap-2">
            <Icon name={KIND_ICON[info.kind]} size={14} />
            {info.label}
          </Card.Title>
          <p className="mt-1 text-[11px] text-muted">{info.detail}</p>
        </div>
        <Chip size="sm" variant="soft" color={poolTone}>
          {info.pool_size > 0
            ? `${info.pool_size.toLocaleString()} values`
            : 'empty pool'}
        </Chip>
      </Card.Header>

      <Card.Content className="build-card-body flex flex-col gap-3">
        <p className="text-[10px] text-muted">
          Feeds the factory's <code>{info.feature}</code> checkbox: {info.format}.
        </p>

        {info.resources.length === 0 && (
          <p className="build-empty">No sources for this pool yet.</p>
        )}

        <div className="flex flex-col gap-2">
          {info.resources.map((row) => {
            const working = busy === row.id
            return (
              <div key={row.id} className="resource-row">
                <div className="flex flex-wrap items-center gap-2">
                  <label className="resource-toggle" title={
                    row.enabled
                      ? 'Values from this source are sampled by the factory'
                      : 'Off: the cached values are kept but never sampled'
                  }>
                    <Checkbox
                      checked={row.enabled}
                      disabled={working}
                      onChange={(next) => void toggle(row, next)}
                    />
                    <span className="resource-name">{row.label}</span>
                  </label>
                  <Chip
                    size="sm"
                    variant="soft"
                    color={!row.current ? 'warning'
                      : row.enabled ? 'success' : 'default'}
                  >
                    {!row.current
                      ? (row.count > 0 ? 'stale cache' : 'not fetched')
                      : `${row.count.toLocaleString()} values`}
                  </Chip>
                  <a
                    className="resource-url"
                    href={row.url}
                    target="_blank"
                    rel="noreferrer"
                    title={row.url}
                  >
                    <Icon name="link" size={10} />
                    {row.url.replace(/^https:\/\//, '')}
                  </a>
                </div>

                <p className="resource-meta">
                  {row.enabled ? 'enabled' : 'disabled - values are not used'}
                  {' · '}
                  {row.fetched_at ? `fetched ${ago(row.fetched_at)}` : 'never fetched'}
                  {row.invalid > 0 && ` · ${row.invalid} line(s) skipped`}
                  {row.duplicates > 0 && ` · ${row.duplicates} duplicate(s)`}
                  {row.truncated && ' · value cap reached'}
                  {row.bytes > 0 && ` · ${bytes(row.bytes, 0)}`}
                  {row.dump && (
                    <>
                      {' · '}
                      <code title="The dump exactly as the server served it">{row.dump}</code>
                    </>
                  )}
                </p>

                {!row.current && row.count > 0 && (
                  <p className="resource-meta">
                    The cached values were fetched for an older URL or kind, so
                    they are shown but not sampled. Press Refresh to replace
                    them.
                  </p>
                )}

                {row.preview.length > 0 && (
                  <div className="resource-preview">
                    {row.preview.map((value) => (
                      <code key={value} className="resource-chip">{value}</code>
                    ))}
                    {row.count > row.preview.length && (
                      <span className="text-[10px] text-muted">
                        +{(row.count - row.preview.length).toLocaleString()} more
                      </span>
                    )}
                  </div>
                )}

                {row.last_error && (
                  <p className="resource-error">
                    Last refresh failed
                    {row.last_error_at ? ` ${ago(row.last_error_at)}` : ''}:{' '}
                    {row.last_error}
                    {row.count > 0 && ' - the previous values are still in use.'}
                  </p>
                )}

                {notes[row.id] && <p className="resource-meta">{notes[row.id]}</p>}

                <div className="flex flex-wrap gap-2">
                  <button
                    type="button"
                    className="build-btn is-secondary"
                    onClick={() => void refresh(row)}
                    disabled={working}
                    title="Download the source now and validate every line"
                  >
                    <Icon name="refresh" size={11} />
                    {working ? 'Working…' : 'Refresh'}
                  </button>
                  <button
                    type="button"
                    className="build-btn is-secondary"
                    onClick={() => void remove(row)}
                    disabled={working}
                    title="Remove the definition and its cached values"
                  >
                    <Icon name="x" size={11} />
                    Remove
                  </button>
                </div>
              </div>
            )
          })}
        </div>

        <form className="resource-add" onSubmit={(e) => void submit(e)}>
          <input
            className="field"
            value={label}
            onChange={(e) => setLabel(e.target.value)}
            placeholder={`Label, e.g. "${info.label} feed"`}
            aria-label={`Label for the new ${info.label} source`}
            maxLength={80}
          />
          <input
            className="field"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://example.com/list.txt"
            aria-label={`URL for the new ${info.label} source`}
            spellCheck={false}
            maxLength={500}
          />
          <button
            type="submit"
            className="build-btn"
            disabled={busy === 'add' || !label.trim() || !url.trim()}
            title="Add the source and fetch its values now"
          >
            <Icon name="plus" size={11} />
            {busy === 'add' ? 'Adding…' : 'Add & fetch'}
          </button>
        </form>

        {formError && <p className="resource-error">{formError}</p>}
        {cardNote && <p className="resource-meta">{cardNote}</p>}
      </Card.Content>
    </Card>
  )
}
