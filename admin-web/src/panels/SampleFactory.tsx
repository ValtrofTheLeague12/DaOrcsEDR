import { useCallback, useEffect, useMemo, useRef, useState, memo } from 'react'
import { Alert, Card, Chip } from '@heroui/react'
import { api } from '../api'
import Icon from '../components/Icon'
import Loading from '../components/Loading'
import CodeBlock from '../components/CodeBlock'
import Checkbox from '../components/Checkbox'
import { bytes } from '../lib/format'
import { parseLine, TONE_CLASS } from '../lib/logColor'
import type {
  EagleState, SampleFactoryCatalog, SamplePreview, SampleShapeOptions,
} from '../types'

// ---------------------------------------------------------------------------
// The test-sample factory.
//
// The Build page answers "can the analyzer be produced"; the run card answers
// "what does a pipeline do on MY sample". This card sits between the two and
// answers the one underneath: where does a sample come from at all.
//
// It works by composition, not freeform editing. The admin either picks one of
// the logged templates or builds the sample from checkboxes - and the checkbox
// list IS the template list, because templates are named bundles of
// checkboxes the backend composes the source from. Whichever way the choice
// is expressed, the same C / C++ `int main()` comes out, with an optional
// noise feature that plants a faulty IP (TEST-NET-3 - unroutable by design)
// and a known benign domain: bait for the IOC miner and the CTI layer that
// provably never dials anything.
//
// The preview is honest about that: the IP, domain and encodings are drawn by
// the server at preview time, and Generate sends the preview's seed back so the
// artefact replays the same draws instead of quietly sampling new values.
// ---------------------------------------------------------------------------

type Lang = 'c' | 'cpp'

/** Human names for the checkbox vocabulary. The names come from the backend;
 *  only the presentation lives here, so an unknown one still renders as-is. */
const FEATURE_LABELS: Record<string, string> = {
  strings: 'Strings',
  wide: 'Wide strings',
  imports: 'Imports',
  sus: 'Use suspicious functions',
  noise: 'Add noise',
  iocs: 'Resource IOCs',
  math: 'Math ops',
  random: 'Random values',
  loop: 'Loop and break',
  buffer_overflow: 'Heap overflow',
  double_free: 'Double free',
  uaf: 'Use after free',
  stack_crash: 'Stack crash',
  integer_overflow: 'Integer overflow',
  socket: 'Loopback socket',
}

/** The encoding select's order and labels. The backend owns the sentences and
 *  the vocabulary; this is presentation, and `mixed` is first because it is the
 *  default the factory treats as "encode each value". */
const ENCODING_ORDER = ['mixed', 'chained', 'plain', 'rot13', 'xor', 'base64']
const ENCODING_LABELS: Record<string, string> = {
  mixed: 'mixed (random per value)',
  chained: 'chained: ROT13 → Base64 → XOR',
  plain: 'plain',
  rot13: 'ROT13',
  xor: 'XOR',
  base64: 'Base64',
}

/** Retired string-pool checkboxes. The pools were removed in favour of
 *  encoding the sampled IP/domain values; a stale backend may still name them.
 *  Never rendered, so the vocabulary on screen matches the one that composes. */
const RETIRED_FEATURES = new Set(['rot13', 'xor', 'base64'])

/** The backend's sample-name rule. An empty name is legal and means "let the
 *  backend choose one"; anything typed must be safe as a file stem. */
const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/

function slugName(value: string) {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '')
}

/** A numeric input's text as an integer inside the backend's bound. Blank
 *  keeps the sentinel (0 = draw one, for the fields that support it). */
function clampInt(text: string, fallback: number, min: number, max: number) {
  const parsed = Number.parseInt(text, 10)
  if (text.trim() === '' || Number.isNaN(parsed)) return fallback
  return Math.max(min, Math.min(max, parsed))
}

/** The compile log, in the same colours the Build page's log speaks.
 *
 *  A compiler's output has the same shapes build.ps1's does - `error:` red,
 *  `Built target` green, the flags-and-includes plumbing dim - and it was
 *  rendered as one grey block before, so a failed compile of a generated
 *  sample looked identical to a succeeded one. parseLine is the same parser
 *  the build log uses; nothing sample-specific is matched here, because gcc
 *  does not know what generated it.
 */
const CompileLog = memo(function CompileLog({ log }: { log: string }) {
  const rows = useMemo(() => log.split('\n').map((l) => parseLine(l)), [log])
  return (
    <pre className="factory-compile-log" spellCheck={false}>
      {rows.map((p, n) => (
        <div key={n} className="code-line">
          {p.pieces
            ? p.pieces.map((seg, k) => (
              <span key={k} className={TONE_CLASS[seg.tone]}>{seg.text}</span>
            ))
            : <span className={TONE_CLASS[p.tone]}>{p.message || ' '}</span>}
        </div>
      ))}
    </pre>
  )
})

interface SampleFactoryCardProps {
  /** Pipeline names from the analyzer's own list, shared with the run card. */
  pipelines: string[]
  /** The run card's selection, shared so both selectors agree. */
  pipeline: string
  onPipelineChange: (pipeline: string) => void
  /** Called with the compiled artefact's repo-relative path. */
  onGenerated: (exePath: string) => void
  /** The "Create pipeline" redirect, to the Pipelines section. */
  onNavigatePipelines: () => void
}

export default function SampleFactoryCard({
  pipelines,
  pipeline,
  onPipelineChange,
  onGenerated,
  onNavigatePipelines,
}: SampleFactoryCardProps) {
  const [catalog, setCatalog] = useState<SampleFactoryCatalog | null>(null)
  const [catalogError, setCatalogError] = useState<string | null>(null)

  const [language, setLanguage] = useState<Lang>('c')
  const [templateId, setTemplateId] = useState<string>('c_minimal')
  const [features, setFeatures] = useState<string[]>([])
  const [sampleName, setSampleName] = useState('')

  // Composition options. Encoding applies to the resource-backed IOCs; each
  // encoding-specific checkbox always carries its own encoding. The sleep is
  // the operator's duration, not a random one - the source says which.
  const [encoding, setEncoding] = useState('mixed')
  const [sleepOn, setSleepOn] = useState(false)
  const [sleepSeconds, setSleepSeconds] = useState('5')

  // A seed pins every draw: noise IP/domain, resource picks, encodings, XOR
  // keys and the generated variable names. Empty means "draw a fresh one",
  // which the preview reports so Generate can replay it.
  const [seedText, setSeedText] = useState('')

  // The CodeFactory knobs. They are passed straight to create_math_ops_c,
  // create_random_vars + gen_instruction, generate_for_loop and the malloc /
  // free archetypes; blank means "let the backend draw one" where supported.
  const [nMath, setNMath] = useState('2')
  const [nVars, setNVars] = useState('4')
  const [loopCount, setLoopCount] = useState('')
  const [loopStep, setLoopStep] = useState('1')
  const [loopBreak, setLoopBreak] = useState('')
  const [instCount, setInstCount] = useState('1')
  const [allocSize, setAllocSize] = useState('8')
  const [nFrees, setNFrees] = useState('2')

  // Post-compile flags. UPX needs the in-tree tool; Instruction Virtualisation
  // needs the in-tree EagleVM build (started from the Utils panel). The
  // Makefile is a build artefact beside the source, not a change to it.
  const [packUpx, setPackUpx] = useState(false)
  const [virtualize, setVirtualize] = useState(false)
  const [writeMakefile, setWriteMakefile] = useState(false)

  const [preview, setPreview] = useState<SamplePreview | null>(null)
  const [previewError, setPreviewError] = useState<string | null>(null)

  const [generating, setGenerating] = useState(false)
  const [result, setResult] = useState<{
    ok: boolean; text: string; detail?: string; log?: string;
    exe?: string; source?: string; command?: string; makefile?: string | null;
    noise?: { ip: string; domain: string } | null;
    virtualized?: { from: string; to: string; log: string } | null
  } | null>(null)

  // --- the offer is read from the analyzer's backend, never invented -------
  useEffect(() => {
    void api.sampleTemplates()
      .then((c) => {
        setCatalog(c)
        // The first template of the current language is the sane default.
        const first = c.templates.find((t) => t.language === language)
        if (first) {
          setTemplateId(first.id)
          setFeatures(first.features)
        }
      })
      .catch((e) => setCatalogError(e instanceof Error ? e.message : String(e)))
  }, [])  // eslint-disable-line react-hooks/exhaustive-deps

  const templates = useMemo(
    () => catalog?.templates?.filter((t) => t.language === language) ?? [],
    [catalog, language],
  )
  // A panel that has not been restarted can still report the three retired
  // string pools. They are filtered here as well as in the backend so the UI
  // removes them on a hard reload alone, instead of making the operator wait
  // for a process restart to stop seeing dead controls.
  const featureNames = (catalog?.features?.[language] ?? [])
    .filter((f) => !RETIRED_FEATURES.has(f))
  const notes = catalog?.feature_notes ?? {}

  const activeTemplate = catalog?.templates.find((t) => t.id === templateId)
  const nameValue = sampleName.trim()
  const nameInvalid = nameValue !== '' && !NAME_RE.test(nameValue)
  const nameExt = language === 'cpp' ? 'cpp' : 'c'
  const nameBase = useMemo(() => {
    const label = activeTemplate?.label
      ?? (templateId === catalog?.custom_id ? 'custom' : templateId)
    return slugName(`${language === 'cpp' ? 'cpp' : 'c'}-${label || 'sample'}`)
      || 'sample'
  }, [activeTemplate, catalog, language, templateId])
  const makeName = useCallback(() => {
    const suffix = Math.floor(Math.random() * 0xffffff)
      .toString(16).padStart(6, '0')
    setSampleName(`${nameBase}-${suffix}`.slice(0, 64))
  }, [nameBase])

  // The preview and the generated source must carry the same stated duration.
  // Clamping here means the input's visible value and the composed code agree
  // even when the operator typed something outside the backend's bound.
  const sleepMax = catalog?.sleep_max ?? 3600
  const sleepValue = sleepOn
    ? Math.max(1, Math.min(sleepMax, Number.parseInt(sleepSeconds, 10) || 5))
    : 0

  const seedValue = useMemo(() => {
    const text = seedText.trim()
    if (!text) return undefined
    const value = Number(text)
    return Number.isInteger(value) && value >= 0 && value <= 0xFFFFFFFF
      ? value
      : undefined
  }, [seedText])
  const seedInvalid = seedText.trim() !== '' && seedValue === undefined

  const shape: SampleShapeOptions = useMemo(() => ({
    n_math: clampInt(nMath, 2, 0, 8),
    n_vars: clampInt(nVars, 4, 0, 24),
    loop_count: clampInt(loopCount, 0, 0, 100),
    loop_step: clampInt(loopStep, 1, 1, 10),
    loop_break_at: loopBreak.trim() === ''
      ? undefined
      : clampInt(loopBreak, 0, 0, 24),
    instruction_count: clampInt(instCount, 1, 1, 12),
    alloc_size: clampInt(allocSize, 8, 1, 1048576),
    n_frees: clampInt(nFrees, 2, 2, 8),
  }), [nMath, nVars, loopCount, loopStep, loopBreak, instCount, allocSize,
       nFrees])

  // Everything the preview was composed from. Generate is only allowed while
  // the shown preview carries the current key, so a press cannot compile a
  // sample the code block never displayed.
  const previewKey = useMemo(
    () => JSON.stringify([language, templateId, features, encoding, sleepValue,
                          seedValue, shape]),
    [language, templateId, features, encoding, sleepValue, seedValue, shape],
  )
  const previewSeq = useRef(0)
  const [shownPreviewKey, setShownPreviewKey] = useState<string | null>(null)

  // --- selection: templates are presets of checkboxes -----------------------
  const pickTemplate = useCallback((id: string) => {
    setTemplateId(id === catalog?.custom_id ? catalog.custom_id : id)
    if (id === catalog?.custom_id) return
    const t = catalog?.templates.find((x) => x.id === id)
    // A picked template sets the checkboxes wholesale: the radio is the
    // faster path, the checkboxes are the fine control.
    if (t) setFeatures(t.features)
  }, [catalog])

  // Toggling anything recomputes which template - if any - the set matches,
  // so the radio keeps answering "what am I on?" instead of lying about a
  // preset that was left behind two toggles ago.
  const toggleFeature = useCallback((f: string) => {
    setFeatures((prev) => {
      const next = prev.includes(f) ? prev.filter((x) => x !== f) : [...prev, f]
      const match = catalog?.templates.find(
        (t) => t.language === language &&
          t.features.length === next.length &&
          t.features.every((x) => next.includes(x)),
      )
      setTemplateId(match ? match.id : (catalog?.custom_id ?? 'custom'))
      return next
    })
  }, [catalog, language])

  // --- preview: composed server-side, debounced, never compiled ------------
  const previewTimer = useRef<number | undefined>(undefined)
  useEffect(() => {
    if (!catalog) return
    const seq = ++previewSeq.current
    window.clearTimeout(previewTimer.current)
    previewTimer.current = window.setTimeout(() => {
      void api.samplePreview(language, templateId, features, encoding, sleepValue, shape, seedValue)
        .then((p) => {
          // A slower earlier request must not overwrite the newer selection.
          if (seq !== previewSeq.current) return
          if (p.ok) {
            setPreview(p)
            setPreviewError(null)
          } else {
            setPreview(null)
            setPreviewError(p.error ?? 'the composition was refused')
          }
          setShownPreviewKey(previewKey)
        })
        .catch((e) => {
          if (seq !== previewSeq.current) return
          setPreviewError(e instanceof Error ? e.message : String(e))
          setShownPreviewKey(previewKey)
        })
    }, 120)
    return () => window.clearTimeout(previewTimer.current)
  }, [catalog, previewKey])  // eslint-disable-line react-hooks/exhaustive-deps

  const previewReady = preview !== null && preview.ok
    && shownPreviewKey === previewKey

  // The encoding select only changes Resource IOCs. Disabled while that
  // checkbox is off (or its pools are empty), with the sentence that says why,
  // rather than sitting there moving a value the source does not contain.
  const encodings = catalog?.encodings ?? {}
  const upx = catalog?.upx ?? {
    ok: false,
    error: 'the running panel did not report UPX',
    detail: 'restart the panel so the backend matches this console',
  }
  const eagle: EagleState = catalog?.eagle ?? {
    ok: false,
    ready: false,
    available: false,
    repo: '',
    repo_exists: false,
    preset: '',
    build_dir: '',
    build_dir_exists: false,
    toolchain: { vcvars64: null, cmake: null, ninja: null },
    artifacts: {},
    missing: [],
    reason: 'the running panel did not report EagleVM',
    note: 'restart the panel so the backend matches this console',
  }
  const catalogOutdated = !catalog?.pools || !catalog?.encodings || !catalog?.upx
    || !catalog?.eagle
  const iocsSelected = features.includes('iocs')
  const faultSelected = features.some((f) =>
    f === 'buffer_overflow' || f === 'double_free' || f === 'uaf')
  const iocsReason = catalog?.feature_unavailable?.iocs
  const encodingUsable = iocsSelected && !iocsReason
    && Object.keys(encodings).length > 0

  // --- generate: compile the preview into a real bait artefact --------------
  const generate = useCallback(async () => {
    if (!preview || preview.seed == null) return
    setGenerating(true)
    setResult(null)
    try {
      const res = await api.generateSample(language, templateId, features, {
        name: nameValue || undefined,
        encoding,
        sleepSeconds: sleepValue,
        upx: packUpx,
        virtualize,
        makefile: writeMakefile,
        seed: preview.seed,
        shape,
      })
      if (res.ok) {
        const size = bytes(res.bytes ?? 0, 1)
        let text = `Compiled - ${res.exe} (${size}).`
        if (res.packed) {
          text += ` UPX packed it from ${bytes(res.packed.before, 1)} to`
            + ` ${bytes(res.packed.after, 1)}`
            + (res.packed.ratio != null
              ? ` (${Math.round(res.packed.ratio * 100)}% of the original).`
              : '.')
          // The run card's gate refuses a packed sample at selection now, so
          // the operator is told here rather than meeting the refusal later.
          text += ' Packed - running it from the panel requires the packed'
            + ' override on Run a pipeline.'
        }
        if (res.virtualized) {
          text += ` Instruction Virtualisation wrapped the marked region and`
            + ` wrote ${res.virtualized.to}; EagleVMStub.dll sits beside it.`
        }
        text += ' The run card below has been set to this sample.'
        setResult({
          ok: true,
          text,
          exe: res.exe,
          source: res.source,
          command: res.command,
          makefile: res.makefile,
          noise: res.noise,
          log: res.log,
          virtualized: res.virtualized,
        })
        if (res.exe) onGenerated(res.exe)
      } else {
        setResult({
          ok: false,
          text: res.error ?? 'the sample was refused',
          detail: res.detail,
          source: res.source,
          command: res.command,
          makefile: res.makefile,
          log: res.log,
        })
      }
    } catch (e) {
      setResult({ ok: false, text: e instanceof Error ? e.message : String(e) })
    } finally {
      setGenerating(false)
    }
  }, [language, templateId, features, nameValue, encoding, sleepValue, packUpx,
      virtualize, writeMakefile, preview, onGenerated, shape])

  if (catalogError && !catalog) {
    return (
      <Card className="build-card">
        <Card.Content className="build-card-body">
          <Alert status="danger">
            <Alert.Title>The sample factory is unreachable</Alert.Title>
            <Alert.Description>{catalogError}</Alert.Description>
          </Alert>
        </Card.Content>
      </Card>
    )
  }
  if (!catalog) return <Loading label="Reading the sample factory templates." />

  const compilerReady = catalog.compiler.ok

  const shapeField = (
    label: string,
    value: string,
    setValue: (next: string) => void,
    min: number,
    max: number,
    placeholder: string,
    title: string,
  ) => (
    <label className="factory-field" key={label}>
      <span className="factory-field-label">{label}</span>
      <input
        type="number"
        className="field"
        min={min}
        max={max}
        step={1}
        placeholder={placeholder}
        value={value}
        onChange={(e) => setValue(e.target.value.replace(/[^0-9]/g, ''))}
        title={title}
        aria-label={title}
      />
    </label>
  )

  return (
    <Card className="build-card">
      <Card.Header className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <Card.Title>Test sample factory</Card.Title>
          <p className="mt-1 text-[11px] text-muted">
            An <code>int main()</code> per template or checkbox - compiled in the same
            UCRT64 tree as the analyzer, ready to feed a pipeline. Every literal
            is read, none is dialled.
          </p>
        </div>
        <div className="flex items-center gap-2">
          {catalog.compiler.error ? (
            <Chip size="sm" variant="soft" color="warning">
              no compiler found
            </Chip>
          ) : (
            <Chip size="sm" variant="soft" color="success">
              compiler found
            </Chip>
          )}
        </div>
      </Card.Header>

      <Card.Content className="build-card-body">
        {catalogOutdated && (
          <Alert status="warning" className="mb-3">
            <Alert.Description>
              The running panel predates this console's sample options.
              Restart the panel so the backend and the console match; Generate
              stays disabled until then.
            </Alert.Description>
          </Alert>
        )}

        {!compilerReady && (
          <Alert status="warning" className="mb-3">
            <Alert.Description>
              <code>{catalog.compiler.error}</code> -{' '}
              {catalog.compiler.detail}. Selection and preview still work;
              Generate does not until the sysroot exists.
            </Alert.Description>
          </Alert>
        )}

        <div className="factory-intro">
          <p>
            Compose one C/C++ <code>int main()</code> from a preset or the
            checkboxes. Every literal is read, never dialled.
          </p>
          <p className="factory-intro-hint">
            Pick a base, tick extra features, then generate. Knobs appear for
            the features they control; the compile record stays below.
          </p>
        </div>

        {/* 1 - the base: language, output name and preset ------------------ */}
        <div className="factory-panel">
          <div className="factory-panel-head">
            <p className="factory-step-label">1 · Base sample</p>
            <span className="factory-panel-note">
              Language, output name and starting point.
            </span>
          </div>

          <div className="factory-identity">
            <div className="factory-field">
              <label className="factory-field-label" htmlFor="factory-name">
                Sample name
              </label>
              <div className="factory-name-row">
                <input
                  id="factory-name"
                  type="text"
                  className={'field' + (nameInvalid ? ' is-invalid' : '')}
                  value={sampleName}
                  onChange={(e) => setSampleName(e.target.value)}
                  placeholder={`auto: ${nameBase}-a1b2c3`}
                  maxLength={64}
                  spellCheck={false}
                  autoComplete="off"
                  aria-invalid={nameInvalid}
                  title="File stem for samples/<name>.c or .cpp"
                />
                <button
                  type="button"
                  className="build-btn is-secondary"
                  onClick={makeName}
                  title="Fill a name from the current template and language"
                >
                  <Icon name="refresh" size={12} />
                  Generate name
                </button>
              </div>
              <span className={'factory-field-note' + (nameInvalid ? ' is-bad' : '')}>
                {nameInvalid
                  ? 'Use letters, digits, dots, dashes or underscores; start with a letter or digit.'
                  : nameValue
                    ? `writes samples/${nameValue}.${nameExt}`
                    : 'blank - the backend names it from the template and timestamp'}
              </span>
            </div>

            <div className="factory-control">
              <span className="factory-field-label">Language</span>
              <div className="factory-segment">
                {(['c', 'cpp'] as Lang[]).map((l) => (
                  <button
                    key={l}
                    type="button"
                    onClick={() => {
                      setLanguage(l)
                      const first = catalog.templates.find((t) => t.language === l)
                      if (first) {
                        setTemplateId(first.id)
                        setFeatures(first.features)
                      }
                    }}
                    className={`build-btn ${language === l ? '' : 'is-secondary'}`}
                    title={l === 'c'
                      ? 'C: stdio literals, plain imports'
                      : 'C++: iostream literals, plain imports'}
                  >
                    {l === 'c' ? 'C' : 'C++'}
                  </button>
                ))}
              </div>
            </div>
          </div>

          <div className="factory-subhead">
            <span className="factory-field-label">Starting point</span>
            <span className="factory-panel-note">
              A preset fills the checkboxes; ticking anything switches to Custom.
            </span>
          </div>
          <div className="factory-template-grid">
            {templates.map((t) => (
              <button
                key={t.id}
                type="button"
                onClick={() => pickTemplate(t.id)}
                className={`factory-template ${templateId === t.id ? 'is-active' : ''}`}
                title={t.description}
              >
                <span className="factory-template-name">{t.label}</span>
                <span className="factory-template-desc">{t.description}</span>
              </button>
            ))}
          </div>
        </div>

        {/* 2 - features: the checkbox vocabulary, in a compact grid -------- */}
        <div className="factory-panel">
          <div className="factory-panel-head">
            <p className="factory-step-label">2 · Features</p>
            <span className="factory-panel-note">
              {activeTemplate?.label ?? 'Custom selection'} · {features.length} selected
            </span>
          </div>
          <div className="factory-feature-grid">
            {featureNames.map((f) => (
              <label key={f} className={'factory-feature ' + (features.includes(f) ? 'is-checked' : '')}>
                <Checkbox
                  checked={features.includes(f)}
                  onChange={() => toggleFeature(f)}
                />
                <span className="factory-feature-name">
                  {FEATURE_LABELS[f] ?? f}
                </span>
                <span className="factory-feature-note">{notes[f]}</span>
              </label>
            ))}
            {/* Resource-backed features whose pools are empty. Shown disabled
                rather than hidden: the vocabulary should not change between
                visits because a feed went down, and the reason is actionable. */}
            {Object.entries(catalog.feature_unavailable ?? {}).map(([f, reason]) => (
              <label key={f} className="factory-feature is-disabled" title={reason}>
                <Checkbox checked={false} disabled onChange={() => {}} />
                <span className="factory-feature-name">
                  {FEATURE_LABELS[f] ?? f}
                </span>
                <span className="factory-feature-note">
                  {reason} - add or refresh a source in Utils → Generator resources.
                </span>
              </label>
            ))}
          </div>
          <p className="factory-pools">
            Pools: {catalog.pools?.ip ?? 0} IPs ·{' '}
            {catalog.pools?.domain ?? 0} domains, downloaded into the
            repo&apos;s <code>ressources/</code> directory and managed in{' '}
            <b>Utils → Generator resources</b>.
          </p>
        </div>

        {/* 3 - only the knobs the selected methods actually use ------------- */}
        <div className="factory-panel">
          <div className="factory-panel-head">
            <p className="factory-step-label">3 · Options</p>
            <span className="factory-panel-note">
              Controls appear for the features they affect; blank fields draw a value.
            </span>
          </div>
          <div className="factory-option-grid">
            <section className="factory-section">
              <header className="factory-section-head">
                <p className="factory-section-title">Seed</p>
                <span className="factory-section-note">
                  Pins every draw, IOC encoding, XOR key and generated C identifier.
                </span>
              </header>
              <div className="factory-field-row">
                <label className="factory-field" htmlFor="factory-seed">
                  <span className="factory-field-label">Seed (empty = draw)</span>
                  <input
                    id="factory-seed"
                    type="number"
                    className={'field' + (seedInvalid ? ' is-invalid' : '')}
                    min={0}
                    max={0xFFFFFFFF}
                    step={1}
                    placeholder="random"
                    value={seedText}
                    onChange={(e) => setSeedText(e.target.value.replace(/[^0-9]/g, ''))}
                    aria-label="Composition seed, 0 to 4294967295"
                    title="Pins the noise pair, IOC picks, encodings, XOR keys and generated C identifiers"
                  />
                </label>
                <button
                  type="button"
                  className="build-btn is-secondary"
                  onClick={() => setSeedText('')}
                  disabled={seedText === ''}
                  title="Clear the seed so the next preview draws a new one"
                >
                  New draw
                </button>
              </div>
              <span className="factory-section-note">
                {seedInvalid
                  ? 'Use a whole number from 0 to 4294967295'
                  : seedValue !== undefined
                    ? `replays exactly - this preview drew ${preview?.seed ?? seedValue}`
                    : preview?.seed != null
                      ? `this preview drew ${preview.seed}; Generate replays it`
                      : 'the preview draws a new 32-bit seed'}
              </span>
            </section>

            {iocsSelected && (
              <section className="factory-section">
                <header className="factory-section-head">
                  <p className="factory-section-title">IOC encoding</p>
                  <span className="factory-section-note">
                    How the Resource IOCs are stored.
                  </span>
                </header>
                <div className="factory-field-row">
                  <select
                    className="field max-w-56"
                    value={encoding}
                    disabled={!encodingUsable}
                    onChange={(e) => setEncoding(e.target.value)}
                    title={iocsReason
                      ? `${iocsReason} - add or refresh a source in Utils → Generator resources`
                      : 'How the Resource IOCs are stored in the source'}
                  >
                    {ENCODING_ORDER.filter((id) => id in encodings).map((id) => (
                      <option key={id} value={id}>
                        {ENCODING_LABELS[id] ?? id}
                      </option>
                    ))}
                  </select>
                  <span className="factory-section-note">
                    {iocsReason ?? encodings[encoding]}
                  </span>
                </div>
              </section>
            )}

            {features.includes('loop') && (
              <section className="factory-section">
                <header className="factory-section-head">
                  <p className="factory-section-title">Loop</p>
                  <span className="factory-section-note">
                    <code>create_random_vars</code> → <code>gen_instruction</code> → <code>generate_for_loop</code>
                  </span>
                </header>
                <div className="factory-grid">
                  {shapeField('Variables', nVars, setNVars, 0, 24, '',
                    'variables from create_random_vars, the loop independent pool')}
                  {shapeField('Iterations', loopCount, setLoopCount, 0, 100, 'auto',
                    'generate_for_loop count_to; blank draws 3-8')}
                  {shapeField('Step', loopStep, setLoopStep, 1, 10, '',
                    'generate_for_loop step')}
                  {shapeField('Break after', loopBreak, setLoopBreak, 0, 24, 'auto',
                    'generate_for_loop break instruction; 0 = never, blank = draw')}
                  {shapeField('Body instructions', instCount, setInstCount, 1, 12, '',
                    'instructions drawn by gen_instruction from the independent pool')}
                </div>
              </section>
            )}

            {faultSelected && (
              <section className="factory-section">
                <header className="factory-section-head">
                  <p className="factory-section-title">Memory faults</p>
                  <span className="factory-section-note">
                    <code>create_malloc_pointer</code> → overflow / double free / UAF
                  </span>
                </header>
                <div className="factory-grid">
                  {shapeField('Malloc size', allocSize, setAllocSize, 1, 1048576, '',
                    'create_malloc_pointer size used by the fault archetypes')}
                  {shapeField('Frees', nFrees, setNFrees, 2, 8, '',
                    'create_double_free_issues free count')}
                </div>
              </section>
            )}

            {features.includes('math') && (
              <section className="factory-section">
                <header className="factory-section-head">
                  <p className="factory-section-title">Math</p>
                  <span className="factory-section-note">
                    <code>create_math_ops_c</code> blocks
                  </span>
                </header>
                <div className="factory-grid">
                  {shapeField('Math blocks', nMath, setNMath, 0, 8, '',
                    'blocks passed to create_math_ops_c')}
                </div>
              </section>
            )}

            <section className="factory-section">
              <header className="factory-section-head">
                <p className="factory-section-title">Timing</p>
                <span className="factory-section-note">
                  Stated <code>Sleep()</code> before exit.
                </span>
              </header>
              <div className="factory-field-row">
                <label className="flex items-center gap-1.5">
                  <Checkbox
                    checked={sleepOn}
                    onChange={() => setSleepOn((v) => !v)}
                  />
                  <span className="factory-field-label">Sleep before exit</span>
                </label>
                <input
                  type="number"
                  className="field w-20"
                  min={1}
                  max={sleepMax}
                  value={sleepSeconds}
                  disabled={!sleepOn}
                  onChange={(e) => setSleepSeconds(e.target.value)}
                  onBlur={() => {
                    if (sleepOn) setSleepSeconds(String(sleepValue))
                  }}
                  aria-label="Sleep duration in seconds"
                  title={`Whole seconds, 1-${sleepMax}`}
                />
                <span className="factory-section-note">
                  seconds - written into the source
                </span>
              </div>
            </section>
          </div>
        </div>

        {/* 4 - the composed source, exactly as Generate will write it */}
        <div className="factory-panel">
          <div className="factory-panel-head">
            <p className="factory-step-label">4 · Source</p>
            <span className="factory-panel-note">
              Exactly what Generate writes.
            </span>
          </div>
          {previewError ? (
            <Alert status="danger">
              <Alert.Description>{previewError}</Alert.Description>
            </Alert>
          ) : (
            <>
              {preview?.noise && (
                <p className="mb-1.5 flex items-center gap-2 text-[10px] text-muted">
                  <Icon name="alert-circle" size={11} />
                  Noise planted in this sample:
                  <code className="text-danger">{preview.noise.ip}</code>
                  <code>{preview.noise.domain}</code>
                  <span className="text-muted">(TEST-NET-3 - never dialled)</span>
                </p>
              )}
              {preview?.resources?.length ? (
                <p className="mb-1.5 flex flex-wrap items-center gap-2 text-[10px] text-muted">
                  <Icon name="database" size={11} />
                  Drawn from resources:
                  {preview.resources.map((r) => (
                    <span key={`${r.feature}-${r.kind}-${r.id}`}
                      className="flex items-center gap-1">
                      <code>{r.value}</code>
                      <span className="text-muted">
                        ({r.label}
                        {r.encoding && r.encoding !== 'plain'
                          ? ` · ${r.encoding}` : ''})
                      </span>
                    </span>
                  ))}
                </p>
              ) : null}
            </>
          )}
          <CodeBlock
            code={preview?.code ?? '// composing…'}
            lang={language === 'c' ? 'c' : 'cpp'}
          />
        </div>

        {/* 5 - build: artefacts, pipeline and the one action ---------------- */}
        <div className="factory-panel">
          <div className="factory-panel-head">
            <p className="factory-step-label">5 · Build</p>
            <span className="factory-panel-note">
              Post-compile flags, pipeline and the generated sample.
            </span>
          </div>

          {/* Post-compile flags. Each is explicit about what it changes. */}
          <div className="factory-flags">
            <label
              className={'factory-feature ' + (packUpx ? 'is-checked' : '')
                + (upx.ok ? '' : ' is-disabled')}
              title={upx.ok
                ? 'Pack the compiled exe with upx/upx.exe --best'
                : [upx.error, upx.detail].filter(Boolean).join(' - ')}
            >
              <Checkbox
                checked={packUpx}
                disabled={!upx.ok}
                onChange={() => setPackUpx((v) => !v)}
              />
              <span className="factory-feature-name">Pack with UPX</span>
              <span className="factory-feature-note">
                {upx.ok
                  ? 'Runs upx/upx.exe --best after compiling and reports the packing ratio.'
                  : `${upx.error} - ${upx.detail}`}
              </span>
            </label>

            <label
              className={'factory-feature ' + (virtualize ? 'is-checked' : '')
                + (eagle.ready ? '' : ' is-disabled')}
              title={eagle.ready
                ? 'Wrap the marked region in EagleVM protected code'
                : [eagle.reason, eagle.note].filter(Boolean).join(' - ')}
            >
              <Checkbox
                checked={virtualize}
                disabled={!eagle.ready}
                onChange={() => setVirtualize((v) => !v)}
              />
              <span className="factory-feature-name">Instruction Virtualisation</span>
              <span className="factory-feature-note">
                {eagle.ready
                  ? 'Runs EagleVM over the compiled sample, emits <name>_protected.exe and copies EagleVMStub.dll beside it.'
                  : [eagle.reason, eagle.note].filter(Boolean).join(' - ')
                    || 'EagleVM is not built - build it from the Utils panel.'}
              </span>
            </label>

            <label className={'factory-feature ' + (writeMakefile ? 'is-checked' : '')}>
              <Checkbox
                checked={writeMakefile}
                onChange={() => setWriteMakefile((v) => !v)}
              />
              <span className="factory-feature-name">Write a Makefile</span>
              <span className="factory-feature-note">
                Writes <code>samples/&lt;name&gt;.mk</code> beside the source
                before compiling, with the same <code>-O0 -g -static</code>{' '}
                flags. Rebuild with <code>make -f samples/&lt;name&gt;.mk</code>.
              </span>
            </label>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              className="build-btn"
              onClick={() => void generate()}
              disabled={generating || !compilerReady || !previewReady
                || catalogOutdated || seedInvalid || nameInvalid}
              title={nameInvalid
                ? 'Fix the sample name in step 1 before generating'
                : catalogOutdated
                  ? 'Restart the panel so the backend matches this console'
                  : !compilerReady
                    ? 'No compiler found - see the note above'
                    : !previewReady
                      ? 'Waiting for the source preview to match the current selection'
                      : 'Write samples/<name>.c|cpp and compile it with UCRT64'}
            >
              <Icon name="plus" size={12} />
              {generating ? 'Generating…' : 'Generate sample'}
            </button>

            <select
              className="field max-w-48"
              value={pipeline}
              disabled={pipelines.length === 0}
              onChange={(e) => onPipelineChange(e.target.value)}
              title="The pipeline this sample will be analyzed with - shared with Run a pipeline, below"
            >
              <option value="">pipeline to test…</option>
              {pipelines.map((p) => (
                <option key={p} value={p}>{p}</option>
              ))}
            </select>

            <button
              type="button"
              className="build-btn is-secondary"
              onClick={onNavigatePipelines}
              title="Open Pipelines Configuration - equip or create the pipeline this sample tests"
            >
              <Icon name="git-merge" size={12} />
              Create pipeline
            </button>
          </div>
          <p className="factory-build-hint">
            The pipeline choice is shared with <b>Run a pipeline</b> below;
            a generated sample lands in its sample box automatically. The
            command, paths and compiler log appear below after the first run.
          </p>
        </div>

        {result && (
          <div className="factory-panel">
            <div className="factory-panel-head">
              <p className="factory-step-label">6 · Output</p>
              <span className="factory-panel-note">
                The compile's own record.
              </span>
            </div>
            <div className={'factory-output ' + (result.ok ? 'is-ok' : 'is-bad')}>
              <div className="factory-output-head">
                <Chip
                  size="sm"
                  variant="soft"
                  color={result.ok ? 'success' : 'danger'}
                >
                  {result.ok ? 'compiled' : 'refused'}
                </Chip>
                <span className="factory-output-text">
                  {result.text}
                  {result.detail && <> — {result.detail}</>}
                </span>
              </div>

              <dl className="factory-output-paths">
                {result.source && (
                  <div>
                    <dt>source</dt>
                    <dd><code>{result.source}</code></dd>
                  </div>
                )}
                {result.exe && (
                  <div>
                    <dt>binary</dt>
                    <dd><code>{result.exe}</code></dd>
                  </div>
                )}
                {result.makefile && (
                  <div>
                    <dt>makefile</dt>
                    <dd><code>{result.makefile}</code></dd>
                  </div>
                )}
                {result.command && (
                  <div>
                    <dt>command</dt>
                    <dd><code>{result.command}</code></dd>
                  </div>
                )}
              </dl>

              {result.noise && result.ok && (
                <p className="factory-output-noise">
                  noise <code>{result.noise.ip}</code> /{' '}
                  <code>{result.noise.domain}</code> - never dialled
                </p>
              )}

              <p className="factory-output-label">compiler &amp; packer output</p>
              {result.log ? (
                <CompileLog log={result.log} />
              ) : (
                <p className="build-empty">
                  The command produced no output; its exit status is in the
                  verdict above.
                </p>
              )}
            </div>
          </div>
        )}
      </Card.Content>
    </Card>
  )
}
