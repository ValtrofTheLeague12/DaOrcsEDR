import { useCallback, useEffect, useState } from 'react'
import { Alert } from '@heroui/react/alert'
import { Button } from '@heroui/react/button'
import { Card } from '@heroui/react/card'
import { Chip } from '@heroui/react/chip'
import { api } from '../api'
import Loading from '../components/Loading'
import MemoryLayout, { type MemoryView } from '../components/MemoryLayout'
import LogoSpinner from '../components/LogoSpinner'
import { LogoMark } from '../components/Logo'
import { ago } from '../lib/format'
import MemoryOutput from '../components/MemoryOutput'
import Switch from '../components/Switch'
import type {
  MemoryProfilingJob,
  MemoryProfilingSnapshot,
  MemoryProfilingTarget,
} from '../types'

export default function MemoryProfiling() {
  const [memory, setMemory] = useState<MemoryProfilingSnapshot | null>(null)
  const [job, setJob] = useState<MemoryProfilingJob | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [saving, setSaving] = useState(false)
  const [tab, setTab] = useState<MemoryView>('overview')

  const load = useCallback(async () => {
    try {
      const snapshot = await api.memoryProfiling()
      setMemory(snapshot)
      setJob(snapshot.current ?? snapshot.last)
      setError(snapshot.error)
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : String(exc))
    }
  }, [])

  useEffect(() => {
    void load()
  }, [load])

  const save = useCallback(async (patch: {
    enabled?: boolean
    target?: MemoryProfilingTarget
    sample?: string | null
    keep_open?: boolean
  }) => {
    setSaving(true)
    setError(null)
    try {
      const response = await api.setMemoryProfiling(patch)
      setMemory(response.snapshot)
    } catch (exc) {
      void load()
      setError(exc instanceof Error ? exc.message : String(exc))
    } finally {
      setSaving(false)
    }
  }, [load])

  const run = useCallback(async () => {
    if (!memory) return
    setError(null)
    try {
      const response = await api.runMemoryProfiling({
        target: memory.settings.target,
        // A capture always needs a sample. When the stored setting is empty,
        // use the first one the picker found rather than sending null and
        // having the request refused.
        sample: memory.settings.sample || memory.samples[0]?.path || null,
      })
      setJob(response.job)
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : String(exc))
    }
  }, [memory])

  useEffect(() => {
    if (!job || job.state !== 'running') return
    let cancelled = false
    const timer = window.setInterval(async () => {
      try {
        const response = await api.memoryProfilingJob(job.id)
        if (cancelled) return
        setJob(response.job)
        if (response.job.state !== 'running') void load()
      } catch (exc) {
        if (!cancelled) {
          setError(exc instanceof Error ? exc.message : String(exc))
        }
      }
    }, 1500)
    return () => {
      cancelled = true
      window.clearInterval(timer)
    }
  }, [job, load])

  if (!memory && !error) {
    return <Loading label="Loading memory profiling…" />
  }

  const current = memory
  // The stored setting starts empty, and the backend refuses to profile either
  // target without a sample. Falling back to the first discovered sample keeps
  // the page usable on a machine that has one instead of showing a permanently
  // disabled Capture button next to the "choose a Windows .exe" placeholder.
  const selectedSample = current?.settings.sample || current?.samples[0]?.path || ''
  const ready = Boolean(
    current?.settings.enabled
    && current.vmmap.installed
    && (current.settings.target !== 'analyzer' || current.vmmap.analyzer_present)
    && selectedSample,
  )

  const targetOk = Boolean(
    current?.vmmap.installed
    && (current.settings.target !== 'analyzer' || current.vmmap.analyzer_present),
  )
  const hasMap = Boolean(job?.csv_path) && job?.state !== 'running'
  const activeTab: MemoryView = hasMap ? tab : 'output'
  const sampleName = (job?.sample || job?.target || '').split(/[\\/]/).pop()

  const tabs: { id: MemoryView; label: string; note?: string }[] = [
    ...(hasMap ? [
      { id: 'overview' as const, label: 'Overview' },
      { id: 'tree' as const, label: 'Memory tree' },
    ] : []),
    { id: 'output', label: 'Output', note: job ? String(job.log_line_count) : undefined },
  ]

  return (
    <div className="mem-page">
      <header className="mem-header">
        <div>
          <p className="eyebrow">MAINTENANCE</p>
          <h2 className="page-title mt-1">Memory profiling</h2>
          <p className="mem-lede">
            Capture a Windows process with Sysinternals VMMap. Completed captures
            show memory totals and address regions, with the original snapshot
            available to download.
          </p>
        </div>
        {current && (
          <Chip size="sm" variant="soft" color={current.settings.enabled ? 'success' : 'default'}>
            {current.settings.enabled ? 'Ready when requested' : 'Disabled'}
          </Chip>
        )}
      </header>

      {error && (
        <Alert status="danger">
          <Alert.Title>Memory profiling needs attention</Alert.Title>
          <Alert.Description>{error}</Alert.Description>
        </Alert>
      )}

      {current ? (
        <div className="mem-grid">
          <Card className="mem-capture">
            <Card.Header>
              <Card.Title className="text-sm font-semibold">Capture</Card.Title>
            </Card.Header>
            <Card.Content className="flex flex-col gap-5">
              <fieldset className="mem-group">
                <legend>Source</legend>
                <label className="flex flex-col gap-1.5">
                  <span className="text-xs font-medium text-default-700">Process to capture</span>
                  <select
                    className="field"
                    value={current.settings.target}
                    disabled={saving}
                    onChange={(event) => void save({
                      target: event.currentTarget.value as MemoryProfilingTarget,
                    })}
                  >
                    {current.targets.map((target) => (
                      <option key={target.id} value={target.id}>{target.label}</option>
                    ))}
                  </select>
                  <span className="text-[11px] text-default-500">
                    {current.targets.find((target) => target.id === current.settings.target)?.detail}
                  </span>
                </label>

                <label className="flex flex-col gap-1.5">
                  <span className="text-xs font-medium text-default-700">
                    {current.settings.target === 'analyzer' ? 'Sample to analyze' : 'Sample to run'}
                  </span>
                  <select
                    className="field font-mono"
                    value={selectedSample}
                    disabled={saving}
                    onChange={(event) => void save({ sample: event.currentTarget.value })}
                  >
                    <option value="">
                      {current.samples.length
                        ? '— choose a Windows .exe —'
                        : '— no Windows .exe samples found —'}
                    </option>
                    {current.samples.map((sample) => (
                      <option key={sample.path} value={sample.path}>{sample.path}</option>
                    ))}
                  </select>
                  <span className="text-[11px] text-default-500">
                    Required for either target. When none is stored, the first
                    sample found is used.
                  </span>
                </label>
              </fieldset>

              <fieldset className="mem-group">
                <legend>Behaviour</legend>
                <Switch
                  label="Enable manual captures"
                  checked={current.settings.enabled}
                  pending={saving}
                  onChange={(value) => void save({ enabled: value })}
                  detail="This does not profile routine analysis runs. Captures start only when requested here or from Sample Factory."
                  footnote={current.path}
                />
                <Switch
                  label="Keep VMMap GUI open"
                  checked={current.settings.keep_open}
                  pending={saving}
                  onChange={(value) => void save({ keep_open: value })}
                  detail="After a successful capture, open the saved .mmp in VMMap's GUI and leave it running. Without this, VMMap only writes the export and exits."
                />
              </fieldset>

              <fieldset className="mem-group">
                <legend>Tooling</legend>
                <div className="mem-tool">
                  <div className="min-w-0">
                    <p className="text-xs font-medium text-default-700">VMMap</p>
                    <p className="mt-0.5 break-all font-mono text-[10px] text-default-500">
                      {current.vmmap.executable || 'Not detected'}
                    </p>
                    {current.settings.target === 'analyzer' && (
                      <p className="mt-0.5 text-[10px] text-default-500">
                        Analyzer {current.vmmap.analyzer_present ? 'built' : 'not built'}
                      </p>
                    )}
                  </div>
                  <Chip size="sm" variant="soft" color={targetOk ? 'success' : 'warning'}>
                    {targetOk ? 'Available' : 'Not ready'}
                  </Chip>
                </div>
                {!current.vmmap.installed && (
                  <p className="text-xs text-warning">
                    Install Sysinternals VMMap or put <code>VMMap64.exe</code> in
                    <code> tools/sysinternals/</code>.
                  </p>
                )}
                {current.vmmap.error && (
                  <p className="text-xs text-warning">{current.vmmap.error}</p>
                )}
              </fieldset>

              <div className="mem-action">
                <Button
                  size="md"
                  variant="primary"
                  className="w-full"
                  onPress={() => void run()}
                  isDisabled={!ready || saving || job?.state === 'running'}
                >
                  {job?.state === 'running' ? 'Capturing…' : 'Capture memory map'}
                </Button>
                <p className="text-[11px] text-default-500">
                  Saved under <code>exports/memory_profiling/</code>
                </p>
              </div>

              {current.settings.target === 'sample' && (
                <p className="mem-caution">
                  The selected executable runs directly on the panel host. Use
                  trusted samples or an isolated VM.
                </p>
              )}
            </Card.Content>
          </Card>

          <Card className="mem-results">
            {job ? (
              <>
                <Card.Header className="mem-results-head">
                  <div className="min-w-0">
                    <Card.Title className="text-sm font-semibold">Latest capture</Card.Title>
                    <p className="mem-results-sub" title={job.sample || job.target}>
                      <span className="truncate">{sampleName}</span>
                      {job.duration_sec !== null && <span>{job.duration_sec}s</span>}
                      {job.finished_at && <span>{ago(job.finished_at)}</span>}
                    </p>
                  </div>
                  <Chip
                    size="sm"
                    variant="soft"
                    color={job.state === 'running' ? 'accent'
                      : job.state === 'failed' ? 'danger'
                        : job.warning ? 'warning' : 'success'}
                  >
                    {job.state === 'running' ? 'Capturing'
                      : job.state === 'failed' ? 'Capture failed'
                        : job.warning ? 'Captured with warning' : 'Captured'}
                  </Chip>
                </Card.Header>
                <Card.Content className="flex flex-col gap-4">
                  {job.error && <p className="text-xs text-danger">{job.error}</p>}
                  {job.warning && <p className="text-xs text-warning">{job.warning}</p>}

                  {job.state === 'running' && (
                    <div className="mem-running">
                      <LogoSpinner size={40} />
                      <div>
                        <p>Capturing with VMMap…</p>
                        <span>Results appear here as soon as the export is written.</span>
                      </div>
                    </div>
                  )}

                  <div className="mem-tabs" role="tablist" aria-label="Capture results">
                    {tabs.map((entry) => (
                      <button
                        key={entry.id}
                        type="button"
                        role="tab"
                        aria-selected={activeTab === entry.id}
                        className={activeTab === entry.id ? 'is-on' : ''}
                        onClick={() => setTab(entry.id)}
                      >
                        {entry.label}
                        {entry.note && <small>{entry.note}</small>}
                      </button>
                    ))}
                  </div>

                  <MemoryLayout job={job} view={activeTab} />
                  {activeTab === 'output' && <MemoryOutput job={job} />}
                </Card.Content>
              </>
            ) : (
              <Card.Content className="mem-blank">
                <LogoMark height={34} className="mem-blank-mark" />
                <p>No capture yet</p>
                <span>Pick a process and sample, then run a capture. Totals, charts and the address tree appear here.</span>
              </Card.Content>
            )}
          </Card>
        </div>
      ) : (
        <Button size="sm" variant="outline" onPress={() => void load()}>Retry</Button>
      )}
    </div>
  )
}
