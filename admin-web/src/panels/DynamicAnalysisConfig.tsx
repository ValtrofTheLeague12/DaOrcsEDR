import { useCallback, useEffect, useState } from 'react'
import { Alert, Card, Chip } from '@heroui/react'
import { api } from '../api'
import Loading from '../components/Loading'
import { ago } from '../lib/format'
import type { DynamicAnalysisSnapshot, DynamicTransport } from '../types'

// ---------------------------------------------------------------------------
// Dynamic Analysis Configuration.
//
// One question, and it is a question because the two answers are not additive:
// is a sample under dynamic analysis allowed to open TCP/IP sockets itself, or
// is the guest driven over an SFTP session with no raw path out?
//
// It used to be implicit. vmmetrics uploads its collector over SFTP, the Qiling
// harness exposes a virtual NIC, and ClamAV's scanner has its own transport -
// so "is the network on?" had a different answer per tool, and no page said
// which one a given run used. This section records the choice once, in
// config/dynamic_analysis.json, beside the other panel-owned settings.
//
// The page is deliberately short. It is a policy, not a dashboard: one radio
// group, the file it lives in, and a save that happens on selection. There is
// nothing to start here, so there is no "Run" button to mistake for one.
// ---------------------------------------------------------------------------

export default function DynamicAnalysisConfig() {
  const [data, setData] = useState<DynamicAnalysisSnapshot | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [saving, setSaving] = useState(false)
  const [flash, setFlash] = useState<string | null>(null)

  const load = useCallback(async () => {
    try {
      setData(await api.dynamicAnalysis())
      setError(null)
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : String(exc))
    }
  }, [])

  useEffect(() => {
    void load()
  }, [load])

  const choose = useCallback(async (next: DynamicTransport) => {
    if (!data || data.settings.communication === next) return
    setSaving(true)
    setError(null)
    setFlash(null)
    try {
      // The response is the same snapshot the GET returns, so the radio
      // re-renders from what is on disk rather than from what was clicked.
      const saved = await api.setDynamicAnalysis(next)
      setData(saved)
      const label = saved.options.find((o) => o.selected)?.label ?? next
      setFlash(`Saved: ${label}.`)
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : String(exc))
      // Reload so a refusal from the file on disk cannot leave the radio
      // showing a value the backend never accepted.
      void load()
    } finally {
      setSaving(false)
    }
  }, [data, load])

  if (!data) {
    return error
      ? (
        <Alert status="danger">
          <Alert.Title>Cannot read the dynamic-analysis policy</Alert.Title>
          <Alert.Description>{error}</Alert.Description>
        </Alert>
      )
      : <Loading label="dynamic analysis configuration" />
  }

  const selected = data.settings.communication

  return (
    <div className="flex flex-col gap-4">
      <div className="mb-2 flex items-baseline justify-between gap-4">
        <h2 className="page-title">Dynamic Analysis Configuration</h2>
        <div className="flex items-center gap-2">
          <Chip size="sm" variant="soft" color={selected === 'tcp' ? 'accent' : 'success'}>
            {selected === 'tcp' ? 'TCP/IP allowed' : 'SFTP only'}
          </Chip>
          {data.exists && (
            <span className="font-mono text-[10px] text-default-400">
              written {ago(data.modified)}
            </span>
          )}
        </div>
      </div>

      <p className="max-w-3xl text-[12px] leading-relaxed text-default-500">
        One transport for every dynamic run. The two are alternatives rather
        than switches: a guest allowed to open TCP sockets <em>and</em> driven
        over SFTP has two answers to “is the network on?”, and nobody can say
        which one a sample took. Pick the one the investigation needs.
      </p>

      {error && (
        <Alert status="danger">
          <Alert.Title>The policy could not be saved</Alert.Title>
          <Alert.Description>{error}</Alert.Description>
        </Alert>
      )}

      {flash && (
        <Alert status="success">
          <Alert.Description>{flash}</Alert.Description>
        </Alert>
      )}

      <Card className="w-full">
        <Card.Header className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <Card.Title className="text-sm font-semibold">Communication</Card.Title>
            <p className="mt-1 text-[11px] text-default-400">
              Selecting an option writes it immediately. The other one is then
              off - there is no third state. Nothing is started or restarted.
            </p>
          </div>
          {saving && (
            <span className="font-mono text-[10px] text-default-400">saving…</span>
          )}
        </Card.Header>
        <Card.Content>
          <div
            className="factory-feature-grid"
            role="radiogroup"
            aria-label="Dynamic analysis communication"
          >
            {data.options.map((option) => {
              const on = option.id === selected
              return (
                <label
                  key={option.id}
                  className={'factory-feature ' + (on ? 'is-checked' : '')}
                >
                  <input
                    type="radio"
                    name="dynamic-analysis-communication"
                    value={option.id}
                    checked={on}
                    disabled={saving}
                    onChange={() => void choose(option.id)}
                    className="mt-0.5 h-3.5 w-3.5 shrink-0 accent-[var(--accent)]"
                  />
                  <span className="factory-feature-name">{option.label}</span>
                  <span className="factory-feature-note">
                    {option.summary} {option.detail}
                  </span>
                </label>
              )
            })}
          </div>
        </Card.Content>
      </Card>

      <Card className="w-full">
        <Card.Content className="flex flex-wrap items-baseline justify-between gap-3">
          <div className="min-w-0">
            <span className="eyebrow block">stored in</span>
            <span className="block truncate font-mono text-[12px]" title={data.path}>
              {data.path}
            </span>
          </div>
          <p className="max-w-xl text-[11px] text-default-400">
            JSON, beside the other panel-owned settings. It is not part of
            config/analysis.yaml: the static analyzer rejects unknown keys there,
            and this policy belongs to the dynamic side. The default is{' '}
            <span className="font-mono">{data.default}</span>.
          </p>
        </Card.Content>
      </Card>

      {data.error && (
        <Alert status="warning">
          <Alert.Title>The file on disk is not usable</Alert.Title>
          <Alert.Description>{data.error}</Alert.Description>
        </Alert>
      )}
    </div>
  )
}
