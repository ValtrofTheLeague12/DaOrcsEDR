import { useCallback, useEffect, useMemo, useState } from 'react'
import { Alert } from '@heroui/react/alert'
import { Button } from '@heroui/react/button'
import { Card } from '@heroui/react/card'
import { Chip } from '@heroui/react/chip'
import { api } from '../api'
import CopyButton from '../components/CopyButton'
import Loading from '../components/Loading'
import Switch, { OptionField } from '../components/Switch'
import { StatTile } from '../components/Stat'
import { HardeningCard } from '../components/HardeningCard'
import type { AnalysisConfig, AnalysisSettingsSnapshot, BuildHardening } from '../types'

// ---------------------------------------------------------------------------
// Analysis Configuration - the global layer, config/analysis.yaml.
//
// This is the operator's standing answer to "how does an analysis behave on
// this machine", as opposed to Pipelines Configuration, which is for how one
// kind of run differs from another. The two pages hold disjoint sets of keys: a
// setting that is set here has no editable control there, and the server refuses
// the write, because a key defined in both places is one of them lying.
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
// action with its own button rather than the absence of a click. Clearing is
// also the only way to hand a key back to the pipelines page - which is why the
// button is named after what it does rather than after the file it edits.
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

  // --- hardening ------------------------------------------------------------
  //
  // A build-time setting, not a run-time one: config/hardening.json is read by
  // build.ps1 and takes effect at the next build, never during an analysis. It
  // lives on this page because it describes the binary every analysis runs -
  // "what did I harden the analyzer with" is a standing question about the
  // machine, which is what this page is for.
  //
  // Fetched once per visit. The compliance half reads the binary's PE header,
  // so it is not polled; the one moment the answer changes is a build, which
  // happens on the Build page, and returning here refetches.
  const [hardening, setHardening] = useState<BuildHardening | null>(null)
  const [savingHardening, setSavingHardening] = useState(false)
  const [hardeningError, setHardeningError] = useState<string | null>(null)

  const loadHardening = useCallback(async () => {
    try {
      setHardening(await api.buildHardening())
      setHardeningError(null)
    } catch {
      // A missing report must not take the page down with it: every other card
      // here still works, and the hardening card simply does not render.
    }
  }, [])

  useEffect(() => {
    void loadHardening()
  }, [loadHardening])

  // The response is the same payload as the GET, so the card re-renders from
  // what is on disk rather than from what was asked for - the two differ
  // exactly when the write was refused. A refusal is reported by the card's own
  // alert, which sits next to the toggles it concerns, and by reloading so the
  // toggles cannot keep claiming a value the file does not hold. It is
  // deliberately NOT routed into the page-level `error` state: that alert's
  // title blames the analyzer, and a hardening write is not the analyzer's to
  // accept or refuse - it is the settings file and the build.
  const saveHardening = useCallback(
    async (patch: Record<string, boolean>) => {
      if (Object.keys(patch).length === 0) return
      setSavingHardening(true)
      setFlash(null)
      try {
        setHardening(await api.setBuildHardening(patch))
        setFlash('Hardening settings saved. They take effect at the next build.')
      } catch (exc) {
        // Reload first: if the refusal came from the file on disk, the card
        // re-renders with the real values and its own explanation. The message
        // is kept for the case where nothing readable came back at all.
        void loadHardening()
        setHardeningError(exc instanceof Error ? exc.message : String(exc))
      } finally {
        setSavingHardening(false)
      }
    },
    [loadHardening],
  )

  // Hooks must run unconditionally: this useMemo used to sit below the two
  // early returns, so the first render (no data yet) ran one hook fewer than
  // the render after a successful load - React #310 crashed the panel.
  const mega = useMemo(
    () => (data?.settings ?? []).filter((s) => s.key.startsWith('MEGA_')),
    [data],
  )

  // --- bundle locally -------------------------------------------------------
  //
  // store_artifact is the one artifact option the analyzer still reads from
  // config/artifacts.yaml - it never migrated to analysis.yaml, because
  // building a local bundle is not a per-machine transfer decision - so it is
  // edited through the artifact-writer endpoint rather than the analysis.yaml
  // writer, and fetched once per visit like the hardening card: nothing else
  // on this page can change it, so polling would be motion, not information.
  const [bundle, setBundle] = useState<AnalysisConfig['artifacts'] | null>(null)
  const [savingBundle, setSavingBundle] = useState(false)
  const [bundleError, setBundleError] = useState<string | null>(null)

  const loadBundle = useCallback(async () => {
    try {
      setBundle((await api.analysisConfig()).artifacts)
      setBundleError(null)
    } catch (exc) {
      setBundleError(exc instanceof Error ? exc.message : String(exc))
    }
  }, [])

  useEffect(() => {
    void loadBundle()
  }, [loadBundle])

  const saveBundle = useCallback(
    async (patch: Record<string, boolean>) => {
      if (Object.keys(patch).length === 0) return
      setSavingBundle(true)
      setFlash(null)
      try {
        const res = await api.setArtifactOptions(patch)
        setBundle(res.artifacts)
        setFlash('Bundle setting saved. Takes effect on the analyzer\'s next run.')
      } catch (exc) {
        // Same discipline as the hardening card: re-read what actually landed
        // before saying anything, so the switch cannot keep a value the file
        // refused.
        void loadBundle()
        setBundleError(exc instanceof Error ? exc.message : String(exc))
      } finally {
        setSavingBundle(false)
      }
    },
    [loadBundle],
  )

  // --- bundle password -------------------------------------------------------
  //
  // The password file resource, as the page's last protection control: the zip
  // protection reads the password from one file outside the repo, so this
  // widget manages that file - report, generate, take the operator's own,
  // clear - and never sees the value except in the ONE response a generate
  // produces. It is fetched once per visit like the bundle and hardening
  // cards: the only writer is this page, so a poll would be motion, not
  // information.
  const [pwStatus, setPwStatus] = useState<{ present: boolean; path: string } | null>(null)
  const [pwSaving, setPwSaving] = useState<string | null>(null)
  const [pwError, setPwError] = useState<string | null>(null)
  // Shown exactly once, right after a generate. Cleared on the next action so
  // a token that happened to linger on screen cannot outlive its purpose.
  const [pwGenerated, setPwGenerated] = useState<string | null>(null)
  const [pwCustom, setPwCustom] = useState('')

  const loadPassword = useCallback(async () => {
    try {
      const res = await api.bundlePassword()
      setPwStatus({ present: res.present, path: res.path })
      setPwError(res.error ?? null)
    } catch (exc) {
      setPwError(exc instanceof Error ? exc.message : String(exc))
    }
  }, [])

  useEffect(() => {
    void loadPassword()
  }, [loadPassword])

  const pwAction = useCallback(
    async (label: string, run: () => Promise<void>) => {
      setPwSaving(label)
      setPwError(null)
      setFlash(null)
      try {
        await run()
      } catch (exc) {
        // Re-read what actually landed, so the chip cannot claim a state the
        // server refused - the same discipline the other two cards keep.
        void loadPassword()
        setPwError(exc instanceof Error ? exc.message : String(exc))
      } finally {
        setPwSaving(null)
      }
    },
    [loadPassword],
  )

  const generatePassword = () =>
    pwAction('generate', async () => {
      const res = await api.generateBundlePassword()
      setPwGenerated(res.password)
      setPwStatus({ present: res.present, path: res.path })
      setFlash('Generated password shown below - copy it somewhere real now; it is never displayed again.')
    })

  const saveCustomPassword = () =>
    pwAction('save', async () => {
      const value = pwCustom
      if (!value.trim()) {
        setPwError('Type a password first, or use Generate.')
        return
      }
      const res = await api.setBundlePassword(value)
      setPwCustom('')
      setPwGenerated(null)
      setPwStatus({ present: res.present, path: res.path })
      setFlash('Password saved to the operator password file.')
    })

  const clearPassword = () =>
    pwAction('clear', async () => {
      const res = await api.clearBundlePassword()
      setPwGenerated(null)
      setPwStatus({ present: res.present, path: res.path })
      setFlash('Password file removed. Protected uploads will refuse until a new one is set.')
    })

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
  if (!data) return <Loading label="Reading the analysis configuration." />
  const flags = data.settings.filter(
    (s) => s.kind === 'flag' && !s.key.startsWith('MEGA_'),
  )
  const values = data.settings.filter(
    (s) => s.kind !== 'flag' && !s.key.startsWith('MEGA_'),
  )
  const megaFlags = mega.filter((s) => s.kind === 'flag')
  const megaValues = mega.filter((s) => s.kind !== 'flag')

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

      <Card className="p-4">
        <h3 className="mb-1 text-sm font-semibold text-default-700">
          MEGA upload and protection
        </h3>
        <p className="mb-4 text-xs text-default-500">
          Where finished runs put their evidence, and whether it is wrapped in
          a password-protected zip before it leaves. A key set here overrides{' '}
          <code className="font-mono">config/artifacts.yaml</code>; clear one
          and the file's copy decides again. This page holds the whole upload
          decision - nothing about it is editable anywhere else.
        </p>
        <div className="grid grid-cols-1 gap-2 xl:grid-cols-2">
          {megaFlags.map((option) => (
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
                      overriding artifacts.yaml ({option.value})
                    </Chip>
                    <button
                      type="button"
                      disabled={saving !== null}
                      onClick={() => void write({ [option.key]: null })}
                      className="text-[11px] text-accent-400 underline underline-offset-2 disabled:opacity-40"
                    >
                      Follow artifacts.yaml
                    </button>
                  </>
                ) : (
                  <Chip size="sm" variant="soft" color="default">
                    artifacts.yaml decides
                  </Chip>
                )}
              </div>
            </div>
          ))}
        </div>
        <div className="mt-4 grid grid-cols-1 gap-3 xl:grid-cols-2">
          {megaValues.map((option) => (
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
                  ? `Overriding artifacts.yaml (${option.value}).`
                  : 'Not set here; artifacts.yaml decides.'}
              </p>
            </OptionField>
          ))}
        </div>

        {/* The password half of the protection decision. The toggle above says
            WHETHER a bundle is wrapped; this says what wraps it. The value is
            never stored in config or echoed after its one showing: the file
            below it lives outside the repo, next to the operator credentials. */}
        <div className="mt-4 rounded-medium border border-default-200 p-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <p className="text-xs font-semibold text-default-700">Bundle password</p>
              <p className="mt-0.5 max-w-2xl text-[11px] text-default-500">
                The zip wrapping uses this password (WinZip AES-256). It lives
                outside the repository at{' '}
                <code className="font-mono">{pwStatus?.path || 'the operator profile password file'}</code>{' '}
                — never in a repo config, and it is shown to you exactly once,
                in this card, right after you generate it.
              </p>
            </div>
            <Chip
              size="sm"
              variant="soft"
              color={pwStatus?.present ? 'success' : 'warning'}
            >
              {pwStatus === null ? 'checking…' : pwStatus.present ? 'password file present' : 'no password set'}
            </Chip>
          </div>

          {pwError && (
            <Alert status="danger" className="mt-2">
              <Alert.Title>That password change did not land</Alert.Title>
              <Alert.Description>{pwError}</Alert.Description>
            </Alert>
          )}

          <div className="mt-3 flex flex-wrap items-center gap-2">
            <Button
              size="sm"
              variant="outline"
              isDisabled={pwSaving !== null}
              onPress={() => void generatePassword()}
            >
              {pwSaving === 'generate' ? 'Generating…' : 'Generate password'}
            </Button>
            {pwGenerated && (
              <CopyButton text={pwGenerated} variant="secondary">
                Copy password
              </CopyButton>
            )}
            <Button
              size="sm"
              variant="ghost"
              isDisabled={pwSaving !== null || !(pwStatus?.present ?? false)}
              onPress={() => void clearPassword()}
            >
              {pwSaving === 'clear' ? 'Clearing…' : 'Clear'}
            </Button>
          </div>

          {pwGenerated && (
            <div className="mt-2 rounded-medium bg-warning-50 p-2">
              <p className="text-[11px] text-default-600">
                This is the only showing. Copy it to a password manager or the
                lab vault now — a generated password that is lost is a bundle
                that is gone, by design.
              </p>
              <code className="mt-1 block break-all font-mono text-xs text-default-900 select-all">
                {pwGenerated}
              </code>
            </div>
          )}

          <div className="mt-3 flex flex-wrap items-center gap-2">
            <input
              className="field font-mono max-w-xs"
              type="password"
              placeholder="or type your own password"
              value={pwCustom}
              onChange={(e) => setPwCustom(e.currentTarget.value)}
              disabled={pwSaving !== null}
            />
            <Button
              size="sm"
              variant="outline"
              isDisabled={pwSaving !== null}
              onPress={() => void saveCustomPassword()}
            >
              {pwSaving === 'save' ? 'Saving…' : 'Save password'}
            </Button>
            <span className="text-[11px] text-default-400">minimum 8 bytes; stored byte-exact, no newline</span>
          </div>
        </div>
      </Card>

      <Card className="p-4">
        <h3 className="mb-1 text-sm font-semibold text-default-700">Evidence bundle</h3>
        <p className="mb-4 text-xs text-default-500">
          Whether each run also builds{' '}
          <code className="font-mono">exports/&lt;sample&gt;_artifact/</code> — a
          deterministic tar.gz with a SHA-256, a manifest and a README, the
          package an upload ships. The JSON reports under{' '}
          <code className="font-mono">exports/&lt;sample&gt;_analysis/</code>{' '}
          are written either way. This one is deliberately file-only:{' '}
          <code className="font-mono">config/artifacts.yaml</code> decides it,
          and it is not part of the MEGA transfer settings that may override it.
        </p>
        {bundleError && (
          <Alert status="danger">
            <Alert.Title>That bundle setting was not written</Alert.Title>
            <Alert.Description>{bundleError}</Alert.Description>
          </Alert>
        )}
        {bundle && (
          <Switch
            label="Bundle locally"
            checked={bundle.store_artifact}
            pending={savingBundle}
            onChange={(v) => void saveBundle({ store_artifact: v })}
            detail="On: the deterministic local bundle is built every run, uploaded or not. Off: run exports stay JSON-only. Turning it on is implied whenever an upload setting says so."
            footnote="config/artifacts.yaml"
          />
        )}
      </Card>

      {/* Hardening is the odd one out on this page, and deliberately so: it is
          the only card here that edits a build-time file. It is shown with the
          analysis settings because it answers the same class of question -
          "how is this machine's analyzer configured" - and because the binary
          every analysis runs is what the four rows describe. The heading says
          so rather than leaving the reader to infer it from the file path. */}
      <div className="flex flex-col gap-2">
        <div>
          <h3 className="text-sm font-semibold text-default-700">Hardening</h3>
          <p className="mt-1 max-w-3xl text-xs text-default-500">
            A build-time setting, not a run-time one. These four switches decide
            how the analyzer is compiled; they take effect at the{' '}
            <b>next build</b> and change nothing about a run already in progress.
            They live here because what they describe is the binary every
            analysis on this machine will execute.
          </p>
        </div>
        {hardeningError && (
          <Alert status="danger">
            <Alert.Title>Those hardening settings were not written</Alert.Title>
            <Alert.Description>{hardeningError}</Alert.Description>
          </Alert>
        )}
        {hardening ? (
          <HardeningCard
            hardening={hardening}
            onSave={(patch) => void saveHardening(patch)}
            saving={savingHardening}
          />
        ) : (
          <p className="text-xs text-default-500">
            Reading <code className="font-mono">config/hardening.json</code> and
            the analyzer binary.
          </p>
        )}
      </div>

      <p className="text-[11px] text-default-400">
        Read once at startup by{' '}
        <code className="font-mono">src/main/analysis_config.cpp</code>. Changes
        apply to the next run, not to a run already in progress. A setting
        cleared here becomes editable on <strong>Pipelines Configuration</strong>{' '}
        again — the two pages never offer the same key.
      </p>
    </div>
  )
}