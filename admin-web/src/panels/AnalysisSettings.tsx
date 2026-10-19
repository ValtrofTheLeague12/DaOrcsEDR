import { useCallback, useEffect, useMemo, useState } from 'react'
import { Alert } from '@heroui/react/alert'
import { Card } from '@heroui/react/card'
import { Chip } from '@heroui/react/chip'
import { api } from '../api'
import Loading from '../components/Loading'
import Switch, { OptionField } from '../components/Switch'
import { StatTile } from '../components/Stat'
import type { AnalysisSettingsSnapshot } from '../types'

// ---------------------------------------------------------------------------
// Global analysis settings - config/analysis.yaml.
//
// This is the operator's standing answer to "how does an analysis behave on
// this machine", as opposed to the per-pipeline `environment:` block, which is
// for how one kind of run differs from another.
//
// The distinction matters because the two are not equal:
//
//     .env / shell   <   pipeline `environment:`   <   this file
//
// The analyzer applies this file *after* the selected pipeline, so a key set
// here is not outvoted by a pipeline that pins the same one. That inversion is
// the whole reason this page exists. The settings used to live only inside
// pipelines, which meant `pipelines/default.yaml` could pin ML_SKIP and CTI_SKIP
// to 1 - so the default analysis never ran the model or enrichment, decided by
// nobody, and unchangeable from the environment.
//
// "Not set" is a third state, and the one this page has to be clearest about.
// A toggle reads as on/off, but absent means something different from off:
//
//   set here     -> applies to every run, overriding the pipeline
//   not set here -> falls back to the pipeline's value, then the binary default
//
// So every control shows which of the three it is, and clearing is a real
// action with its own button rather than the absence of a click.
// ---------------------------------------------------------------------------

/** Truthy exactly as the C++ and Python readers read these. */
function asBool(raw: string | null, fallback: boolean): boolean {
  if (raw === null) return fallback
  const low = raw.trim().toLowerCase()
  if (['1', 'true', 'yes', 'on'].includes(low)) return true
  if (['0', 'false', 'no', 'off'].includes(low)) return false
  return fallback
}

export default function AnalysisSettings() {
  const [data, setData] = useState<AnalysisSettingsSnapshot | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [saving, setSaving] = useState<string | null>(null)
  const [flash, setFlash] = useState<string | null>(null)

  const load = useCallback(async () => {
    try {
      setData(await api.analysisSettings())
      setError(null)
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : String(exc))
    }
  }, [])

  useEffect(() => {
    load()
  }, [load])

  // A null value removes the key. Sending it is the only way to express
  // "fall back to the pipeline again", which is not the same as writing false -
  // a pipeline saying ML_SKIP: "1" must be able to win again once this is clear.
  const write = useCallback(
    async (patch: Record<string, unknown>) => {
      const label = Object.keys(patch).join(', ')
      setSaving(label)
      setFlash(null)
      try {
        const res = await api.setAnalysisSettings(patch)
        setData(res.settings)
        setError(null)
        setFlash(
          Object.keys(patch).some((k) => patch[k] === null)
            ? `${label} cleared - that setting now follows the pipeline again.`
            : `${label} saved. Takes effect on the analyzer's next run.`,
        )
      } catch (exc) {
        setError(exc instanceof Error ? exc.message : String(exc))
      } finally {
        setSaving(null)
      }
    },
    [],
  )

  const counts = useMemo(() => {
    const all = data?.settings ?? []
    return {
      total: all.length,
      set: all.filter((s) => s.present).length,
    }
  }, [data])

  if (error && !data) {
    return (
      <div className="p-4">
        <Alert status="danger">
          <Alert.Title>Could not read the analysis config</Alert.Title>
          <Alert.Description>{error}</Alert.Description>
        </Alert>
      </div>
    )
  }
  if (!data) return <Loading label="Reading the analysis settings." />

  const flags = data.settings.filter((s) => s.kind === 'flag')
  const values = data.settings.filter((s) => s.kind !== 'flag')

  return (
    <div className="flex flex-col gap-4 p-4">
      {/* Precedence, stated on the page rather than only in the file. Every
          other explanation of this lives in a comment nobody reading the
          console is going to open. */}
      <Card className="p-4">
        <div className="flex items-start justify-between gap-4">
          <div>
            <h2 className="text-sm font-semibold text-default-700">
              Applies to every analysis
            </h2>
            <p className="mt-1 max-w-3xl text-xs text-default-500">
              These settings reach every run, whichever pipeline it uses. When
              one is set here it overrides that pipeline's own value; when it is
              not set, the pipeline decides, and failing that the analyzer's
              built-in default applies.
            </p>
            <p className="mt-2 font-mono text-[11px] text-default-500">
              .env / shell &nbsp;&lt;&nbsp; pipeline environment: &nbsp;&lt;&nbsp;{' '}
              <span className="text-accent-400">{data.path}</span>
            </p>
          </div>
          <div className="flex shrink-0 gap-2">
            <StatTile label="Settings" value={counts.total} />
            <StatTile
              label="Overriding"
              value={counts.set}
              sub={counts.set ? 'overriding a pipeline' : 'all following pipelines'}
            />
          </div>
        </div>
        {!data.exists && (
          <p className="mt-3 text-xs text-default-500">
            <code className="font-mono">{data.path}</code> does not exist yet.
            Setting something here creates it; until then every run follows its
            pipeline.
          </p>
        )}
      </Card>

      {data.unknown.length > 0 && (
        <Alert status="danger">
          <Alert.Description>
          <code className="font-mono">{data.path}</code> contains{' '}
          {data.unknown.length} key{data.unknown.length === 1 ? '' : 's'} the
          analyzer does not read:{' '}
          <span className="font-mono">{data.unknown.join(', ')}</span>. An unknown
          key is a startup error rather than a warning, so it would stop every
          run until it is removed.
          </Alert.Description>
        </Alert>
      )}

      {flash && (
        <Alert status="success">
          <Alert.Title>{flash}</Alert.Title>
        </Alert>
      )}
      {error && (
        <Alert status="danger">
          <Alert.Title>The analyzer would not accept that</Alert.Title>
          <Alert.Description>{error}</Alert.Description>
        </Alert>
      )}

      <Card className="p-4">
        <h3 className="mb-1 text-sm font-semibold text-default-700">Behaviour</h3>
        <p className="mb-4 text-xs text-default-500">
          Whether a phase runs, and how hard the run pushes.
        </p>
        <div className="grid grid-cols-1 gap-2 xl:grid-cols-2">
          {flags.map((option) => (
            <div key={option.key} className="flex flex-col gap-1">
              <Switch
                label={option.label}
                checked={asBool(option.value, Boolean(option.default))}
                onChange={(v) => write({ [option.key]: v })}
                detail={option.detail}
                footnote={option.honoured_by}
              />
              <div className="flex items-center gap-2 pl-1">
                {option.present ? (
                  <>
                    <Chip size="sm" color="warning" variant="soft">
                      overriding the pipeline ({option.value})
                    </Chip>
                    <button
                      type="button"
                      disabled={saving !== null}
                      onClick={() => void write({ [option.key]: null })}
                      className="text-[11px] text-accent-400 underline underline-offset-2 disabled:opacity-40"
                    >
                      Follow the pipeline
                    </button>
                  </>
                ) : (
                  <Chip size="sm" variant="soft" color="default">
                    follows the pipeline
                  </Chip>
                )}
              </div>
            </div>
          ))}
        </div>
      </Card>

      <Card className="p-4">
        <h3 className="mb-1 text-sm font-semibold text-default-700">Values</h3>
        <p className="mb-4 text-xs text-default-500">
          Numbers and paths. An empty field means the setting is not set here.
        </p>
        <div className="grid grid-cols-1 gap-3 xl:grid-cols-2">
          {values.map((option) => (
            <OptionField
              key={option.key}
              label={option.label}
              detail={option.detail}
              footnote={option.honoured_by}
            >
              <div className="flex items-center gap-2">
                <input
                  className="field font-mono"
                  type={option.kind === 'number' ? 'number' : 'text'}
                  min={option.min}
                  max={option.max}
                  step={option.kind === 'number' ? 'any' : undefined}
                  placeholder={String(option.default ?? '')}
                  defaultValue={option.value ?? ''}
                  key={`${option.key}:${option.value}`}
                  onBlur={(e) => {
                    const raw = e.currentTarget.value.trim()
                    if (raw === '') {
                      if (option.present) write({ [option.key]: null })
                      return
                    }
                    if (raw === option.value) return
                    write({ [option.key]: option.kind === 'number' ? Number(raw) : raw })
                  }}
                />
                {option.present && (
                  <button
                    type="button"
                    disabled={saving !== null}
                    onClick={() => void write({ [option.key]: null })}
                    className="shrink-0 text-[11px] text-accent-400 underline underline-offset-2 disabled:opacity-40"
                  >
                    Clear
                  </button>
                )}
              </div>
              <p className="mt-1 text-[11px] text-default-400">
                {option.present
                  ? `Overriding the pipeline (${option.value}).`
                  : 'Not set here; the pipeline decides.'}
              </p>
            </OptionField>
          ))}
        </div>
      </Card>

      <p className="text-[11px] text-default-400">
        Read once at startup by{' '}
        <code className="font-mono">src/main/analysis_config.cpp</code>. Changes
        apply to the next run, not to a run already in progress.
      </p>
    </div>
  )
}