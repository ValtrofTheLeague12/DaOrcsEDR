import { useCallback, useEffect, useState } from 'react'
import { Alert } from '@heroui/react/alert'
import { Button } from '@heroui/react/button'
import { Card } from '@heroui/react/card'
import { Chip } from '@heroui/react/chip'
import { api } from '../api'
import Loading from '../components/Loading'
import MemoryLayout from '../components/MemoryLayout'
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
        sample: memory.settings.sample || null,
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
  const ready = Boolean(
    current?.settings.enabled
    && current.vmmap.installed
    && (current.settings.target !== 'analyzer' || current.vmmap.analyzer_present)
    && current.settings.sample,
  )

  return (
    <div className="mx-auto flex w-full max-w-5xl flex-col gap-5">
      <header className="flex flex-wrap items-start justify-between gap-4 border-b border-default-200 pb-4">
        <div>
          <p className="eyebrow">MAINTENANCE</p>
          <h2 className="page-title mt-1">Memory profiling</h2>
          <p className="mt-1 max-w-2xl text-sm text-default-500">
            Capture a Windows process with Sysinternals VMMap. Completed captures
            show memory totals and address regions, with the original snapshot
            available to download.
          </p>
        </div>
        {current && (
          <Chip
            size="sm"
            variant="soft"
            color={current.settings.enabled ? 'success' : 'default'}
          >
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
        <>
          <Card className="w-full">
            <Card.Header>
              <Card.Title className="text-sm font-semibold">Capture settings</Card.Title>
            </Card.Header>
            <Card.Content className="flex flex-col gap-5">
              <Switch
                label="Enable manual captures"
                checked={current.settings.enabled}
                pending={saving}
                onChange={(value) => void save({ enabled: value })}
                detail="This does not profile routine analysis runs. Captures start only when requested here or from Sample Factory."
                footnote={current.path}
              />

              <div className="grid gap-4 sm:grid-cols-2">
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
                    value={current.settings.sample}
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
                    Required for either target. The analyzer otherwise defaults
                    to <code>a.exe</code>, which may not exist.
                  </span>
                </label>
              </div>

              <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-default-200 bg-default-50/60 p-3">
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
                <Chip
                  size="sm"
                  variant="soft"
                  color={current.vmmap.installed
                    && (current.settings.target !== 'analyzer' || current.vmmap.analyzer_present)
                    ? 'success' : 'warning'}
                >
                  {current.vmmap.installed
                    && (current.settings.target !== 'analyzer' || current.vmmap.analyzer_present)
                    ? 'Available' : 'Not ready'}
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

              <div className="flex flex-wrap items-center gap-3">
                <Button
                  size="sm"
                  variant="primary"
                  onPress={() => void run()}
                  isDisabled={!ready || saving || job?.state === 'running'}
                >
                  {job?.state === 'running' ? 'Capturing…' : 'Capture memory map'}
                </Button>
                <span className="text-[11px] text-default-500">
                  Saved under <code>exports/memory_profiling/</code>
                </span>
              </div>

              {current.settings.target === 'sample' && (
                <p className="text-xs text-warning">
                  The selected executable runs directly on the panel host. Use
                  trusted samples or an isolated VM.
                </p>
              )}
              <p className="text-[11px] text-default-500">
                VMMap reports process regions and working set; it does not trace
                allocations by function or detect individual leaks.
              </p>
            </Card.Content>
          </Card>

          {job && (
            <Card className="w-full">
              <Card.Header className="flex flex-wrap items-center justify-between gap-3">
                <div>
                  <Card.Title className="text-sm font-semibold">Latest capture</Card.Title>
                  <p className="mt-1 break-all font-mono text-[10px] text-default-500">
                    {job.sample || job.target}
                    {job.duration_sec !== null ? ` · ${job.duration_sec}s` : ''}
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
              <Card.Content>
                {job.error && <p className="mb-2 text-xs text-danger">{job.error}</p>}
                {job.warning && <p className="mb-2 text-xs text-warning">{job.warning}</p>}
                {job.state === 'failed' && job.log.length > 0 && (
                  <details className="mb-3">
                    <summary className="cursor-pointer text-xs text-default-500">Capture log</summary>
                    <pre className="mt-2 max-h-56 overflow-auto rounded-lg bg-default-100 p-3 font-mono text-[10px]">
                      {job.log.join('\n')}
                    </pre>
                  </details>
                )}
                <MemoryLayout job={job} />
              </Card.Content>
            </Card>
          )}
        </>
      ) : (
        <Button size="sm" variant="outline" onPress={() => void load()}>Retry</Button>
      )}
    </div>
  )
}
