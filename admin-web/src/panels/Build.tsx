import { useCallback, useEffect, useMemo, useRef, useState, memo } from 'react'
import type { ReactNode } from 'react'
import { Alert, Card, Chip } from '@heroui/react'
import { api } from '../api'
import Icon from '../components/Icon'
import Loading from '../components/Loading'
import { parseLine, stripAnsi, TONE_CLASS } from '../lib/logColor'
import { ago, bytes } from '../lib/format'
import Switch from '../components/Switch'
import SubNav from '../components/SubNav'
import { ConfigurationCard, ProvenanceCard, TestPicker } from './BuildChecks'
import SampleFactoryCard from './SampleFactory'
import type {
  AnalyzerBuildJob,
  BuildDependency,
  BuildInspect,
  BuildOverview,
  BuildTestCatalogue,
  PipelineRunState,
  SampleFile,
  SampleInspect,
} from '../types'

// ---------------------------------------------------------------------------
// Building the analyzer.
//
// Two things this page exists to answer, and they are asked in this order every
// time something breaks:
//
//   "Can this build at all?" - the dependency checklist, answered BEFORE a build
//   is started rather than after one fails. A missing library surfaces as a
//   configure error buried under cmake's own output; here it is a red row
//   naming the artefact and where it was looked for.
//
//   "What happened?" - the build log, big and colourised, because a compile is
//   thousands of lines in which four of them are the answer. The colouring is
//   the point: `-- Configuring done` and `Built target` are green, `FAILED:` and
//   `error:` are red with the file:line lifted out of the text, and the 2000
//   `Building CXX object` lines between them are dim so they recede.
//
// Only one build runs at a time and the button says so rather than queueing:
// two concurrent builds would contend for build-ucrt/, and a queued build would
// sit invisible behind a spinner.
// ---------------------------------------------------------------------------

// One row of the log, memoised on the raw line.
//
// The cap is 4000 lines and the poll rewrites the array every two seconds, so
// without this every row is re-rendered twice a minute to produce byte-identical
// output. Strings compare by value, so a line that has not changed fails the
// shallow compare and React skips it entirely; only the handful of lines the
// compiler just appended do any work.
//
// parseLine runs inside the memo rather than being passed in, because passing
// the parsed object would hand every row a fresh identity on every poll and the
// memo would never hit.
const LogRow = memo(function LogRow({ line, n }: { line: string; n: number }) {
  const p = useMemo(() => parseLine(line), [line])
  return (
    <div
      className={`build-log-line ${p.notable ? 'is-notable' : ''}`}
      title={p.stamp ?? undefined}
    >
      <span className="build-log-num">{n}</span>
      <span className="build-log-text">
        {p.pieces
          // ANSI-coloured output (the analyzer annotating its own imports
          // during the post-build smoke test) keeps the colour the process
          // actually chose, rather than one tone per line.
          ? p.pieces.map((seg, k) => (
              <span key={k} className={TONE_CLASS[seg.tone]}>
                {seg.text}
              </span>
            ))
          : <span className={TONE_CLASS[p.tone]}>{p.message || ' '}</span>}
      </span>
    </div>
  )
})

/**
 * The tail of the current build/test job, rendered in the section that owns
 * that action.
 *
 * The page used to have one log tab only, so pressing Build moved the reader
 * away from the environment they had just checked, and a finished test left
 * its output on a tab they were no longer looking at. The full log stays on the
 * Build output tab; this is the same job, last lines first, with a link to it.
 */
function JobTail({ job, kind, onOpen }: {
  job: AnalyzerBuildJob | null
  kind: 'build' | 'tests'
  onOpen: () => void
}) {
  const jobKind = job?.kind ?? 'build'
  const mine = jobKind === kind ? job : null
  const all = mine?.log ?? []
  const tail = all.slice(-40)
  const start = all.length - tail.length
  const noun = kind === 'tests' ? 'test run' : 'build'

  if (!mine) {
    return (
      <p className="build-empty">
        No {noun} this panel session. Start one above; its lines appear here
        and on the <b>Build output</b> tab.
      </p>
    )
  }

  return (
    <div className="build-job-tail">
      <div className="build-job-tail-head">
        <Chip
          size="sm"
          variant="soft"
          color={mine.state === 'running' ? 'accent'
            : mine.state === 'done' || mine.state === 'passed' ? 'success'
              : 'danger'}
        >
          {mine.state}
        </Chip>
        <span className="build-log-meta">
          job {mine.id} · {mine.log_line_count} line
          {mine.log_line_count === 1 ? '' : 's'}
          {mine.exit_code !== null && ` · exit ${mine.exit_code}`}
        </span>
        <button type="button" className="build-link" onClick={onOpen}>
          Open full output
        </button>
      </div>
      {mine.error && (
        <Alert status="danger" className="mb-2">
          <Alert.Description>{mine.error}</Alert.Description>
        </Alert>
      )}
      {tail.length === 0 ? (
        <p className="build-empty">Waiting for the first line…</p>
      ) : (
        <div className="build-log build-log-tail" role="log" aria-live="polite">
          {start > 0 && (
            <div className="build-log-line is-truncated">
              … {start} earlier line{start === 1 ? '' : 's'} - open the full
              output above
            </div>
          )}
          {tail.map((line, i) => (
            <LogRow key={start + i} line={line} n={start + i + 1} />
          ))}
        </div>
      )}
    </div>
  )
}

const POLL_MS = 3000

/** How often the log is refetched while a build is running. */
const LOG_POLL_MS = 2000

/** Toolchain rows sort by how CMake declares them. */
const TOOLCHAIN_ORDER: Record<string, number> = {
  tool: -1, package: 0, archive: 1, library: 2,
  'pkg-config': 3, vendored: 4, header: 5,
}

/**
 * Stack rows sort into groups instead.
 *
 * A flat 25-row list reads as a wall; the question is never "is capa-rules
 * there" on its own but "are the tools, the rule packs, the services and the
 * vendored checkouts all in place". Grouping makes a gap visible as an empty
 * group rather than as one more red row in a list you have already scrolled.
 */
const STACK_GROUPS: Array<{ label: string; kinds: string[] }> = [
  { label: 'Executables', kinds: ['program'] },
  { label: 'Rule packs & data', kinds: ['rules', 'data'] },
  { label: 'Services', kinds: ['service'] },
  { label: 'Subsystems', kinds: ['source'] },
  { label: 'Vendored checkouts', kinds: ['vendored'] },
  { label: 'Python environments', kinds: ['venv', 'manifest'] },
]

function DepRow({ dep }: { dep: BuildDependency }) {
  return (
    <li
      className={`build-dep ${dep.found ? 'is-found' : dep.required ? 'is-missing' : 'is-optional'}`}
      title={dep.path ?? `${dep.note} — not found`}
    >
      <span className="build-dep-mark" aria-hidden="true">
        {dep.found ? <Icon name="check" size={11} /> : <Icon name="x" size={11} />}
      </span>
      <span className="build-dep-name">{dep.name}</span>
      <span className="build-dep-kind">{dep.kind}</span>
      {!dep.required && <span className="build-dep-flag">optional</span>}
    </li>
  )
}

function DepGroup({ label, deps }: { label: string; deps: BuildDependency[] }) {
  if (deps.length === 0) return null
  return (    <>
      <li className="build-dep-group" aria-hidden="true">{label}</li>
      {deps.map((d) => (
        <DepRow key={`${d.kind}:${d.name}`} dep={d} />
      ))}
    </>
  )
}

// ---------------------------------------------------------------------------
// Run a pipeline.
//
// The build answers "can this project compile"; the Tests section answers "do
// the code and the fixtures behave". This section answers the operator's older
// question - "what does my pipeline do on MY sample, live" - by starting the
// analyzer exactly as the CLI would (`--no-curses` because there is no
// terminal to drive the progress screen) and streaming the child's combined
// output into the card.
//
// The two output modes are the same lines, presented differently:
//
//   * cursor ON: the build-log renderer, kept scrolled to the tail, with a
//     caret while the analyzer is speaking - a "live" view;
//   * cursor OFF: the identical text in a plain <textarea>, selectable and
//     copyable without buying any of the log's scrolling behaviour.
//
// The switch is a display preference, so it persists in localStorage rather
// than panel state: it is about how one person reads output, not what a run
// does.
// ---------------------------------------------------------------------------

const RUN_CURSOR_KEY = 'build-run-cursor'

// The run's maximum duration, in seconds, as typed. Persisted for the same
// reason as the cursor switch: it describes a standing preference about how this
// operator runs the analyzer, not the state of one run.
const RUN_DURATION_KEY = 'build-run-duration'

// ---------------------------------------------------------------------------
// The sample-path rules, mirrored.
//
// The server is the authority - pipeline_run.start re-validates every start,
// through the same python/panel/samples.py the inspect endpoint answers from -
// but the Run button has to know the difference between "not chosen yet" and
// "chosen wrong" without a round trip per change. These are the same rules,
// in the same order; a change there is a change here, and the server's
// refusal on start is what catches any drift.
// ---------------------------------------------------------------------------
const SAMPLE_EXT = /\.(exe|dll|bin|sys)$/i

// The same roots python/panel/config.py hands to samples.resolve(). This is a
// UI convenience for choosing a default, not the gate: inspect and start both
// re-validate whatever is selected.
const SAMPLE_ROOTS = ['samples/', 'tests/fixtures/', 'exports/']

function underSampleRoot(path: string): boolean {
  const p = path.replace(/\\/g, '/')
  return SAMPLE_ROOTS.some((root) => p.startsWith(root))
}

// A selected path can contain spaces; the preview quotes those the way a
// shell would. The server's own `job.command` is authoritative once a run
// exists and replaces this string entirely.
function quoteArg(value: string): string {
  return /[\s"]/.test(value) ? `"${value.replace(/"/g, '\\"')}"` : value
}

function localSampleCheck(raw: string):
  { state: 'empty' | 'ok' | 'bad'; why: string } {
  const s = raw.trim()
  if (!s) return { state: 'empty', why: '' }
  if (s.startsWith('--')) {
    return { state: 'bad', why: 'That looks like an option, not a sample path.' }
  }
  if (/[\x00-\x1f]/.test(s)) {
    return { state: 'bad', why: 'Control characters are not allowed in a path.' }
  }
  if (s.split(/[\\/]/).includes('..')) {
    return { state: 'bad', why: 'A sample path may not contain `..` segments.' }
  }
  // Anything past the first drive colon is an NTFS stream or a second colon.
  if (/[^:]:/.test(s.replace(/^[A-Za-z]:/, ''))) {
    return { state: 'bad', why: 'Alternate data streams are not allowed.' }
  }
  // Before the extension rule, as on the server: "new.exe." reads as a dot
  // extension to a naive suffix test, and the real problem is the trailing dot.
  if (/[. ]$/.test(s)) {
    return { state: 'bad', why: 'A file name may not end in a dot or a space.' }
  }
  if (!SAMPLE_EXT.test(s)) {
    return { state: 'bad', why: 'Allowed executable extensions: .exe, .dll, .bin, .sys.' }
  }
  return { state: 'ok', why: '' }
}

// ---------------------------------------------------------------------------
// Sectioning.
//
// The page used to be an undifferentiated stack of cards: identity, stack,
// toolchain, artefacts, log, run, tests. Everything was on the page, but the
// page had lost the answer to "where am I on it" - the numbered order is the
// work-order, identity first (is the binary healthy?), provisioning last
// (points run against it). A Section is the wrapper that says so: a number,
// a name and one line of why it sits where it sits.
// ---------------------------------------------------------------------------

function Section({ n, title, hint, meta, children }: {
  n: number
  title: string
  hint?: string
  meta?: ReactNode
  children: ReactNode
}) {
  return (
    <section className="build-section">
      <header className="build-section-header">
        <span className="build-section-n" aria-hidden="true">{n}</span>
        <div className="min-w-0 flex-1">
          <h2 className="build-section-title">{title}</h2>
          {hint && <p className="build-section-hint">{hint}</p>}
        </div>
        {meta}
      </header>
      <div className="build-section-body">{children}</div>
    </section>
  )
}

// ---------------------------------------------------------------------------
// Sub-sections - the second level of the same answer.
//
// A Section's body can itself be a wall: one numbered block holding three
// dependency checklists reads as one undifferentiated "environment" thing, when
// they are actually three different questions with three different owners. A
// Sub is the Section wrapper at smaller scale: an index ("2.2"), a name, one
// line of why, and a left rail in the sub-section's current health colour so a
// scroll past three lists answers "which one is wrong" without reading:
//
//   * danger  - a gate is down; the build itself is blocked or cannot run;
//   * warning - workable but degraded: optional gaps, nothing built yet;
//   * success - every required thing in place;
//   * accent  - informational, nothing to act on.
//
// The tone is computed from data the page already fetched - the same booleans
// the cards below derive their chips from, not a duplicate verdict machine.
// When the colour and the card's own chip disagree, that is a bug to fix, not
// a decoration to tune.
// ---------------------------------------------------------------------------

type SubTone = 'accent' | 'success' | 'warning' | 'danger'

function Sub({ n, title, hint, tone = 'accent', children }: {
  n: string
  title: string
  hint?: string
  tone?: SubTone
  children: ReactNode
}) {
  return (
    <div className={`build-sub is-${tone}`}>
      <header className="build-sub-header">
        <span className="build-sub-n" aria-hidden="true">{n}</span>
        <div className="min-w-0 flex-1">
          <h3 className="build-sub-title">{title}</h3>
          {hint && <p className="build-sub-hint">{hint}</p>}
        </div>
      </header>
      <div className="build-sub-body">{children}</div>
    </div>
  )
}


function PipelineRunCard({ analyzerReady, pipelines, pipeline, onPipelineChange, sample, onSampleChange }: {
  analyzerReady?: boolean
  /** Pipeline names from the analyzer's own catalog, fetched by the owner. */
  pipelines: string[]
  /** Lifted: the sample factory shares both selectors with this card. */
  pipeline: string
  onPipelineChange: (pipeline: string) => void
  sample: string
  onSampleChange: (sample: string) => void
}) {
  const [job, setJob] = useState<PipelineRunState | null>(null)
  const [starting, setStarting] = useState(false)
  const [notice, setNotice] = useState<{ tone: 'ok' | 'bad'; text: string } | null>(null)
  const [cursor, setCursor] = useState<boolean>(() => {
    try {
      return window.localStorage.getItem(RUN_CURSOR_KEY) !== 'off'
    } catch {
      return true
    }
  })
  const [follow, setFollow] = useState(true)

  // The duration limit, persisted like the cursor toggle so the same bound is
  // still there next visit - an operator who decided their runs should die at
  // 10s does not want to re-enter that every time. An empty string is "no
  // limit" and is the default: the field has to be filled in on purpose.
  const [duration, setDuration] = useState<string>(() => {
    try {
      return window.localStorage.getItem(RUN_DURATION_KEY) ?? ''
    } catch {
      return ''
    }
  })

  const logRef = useRef<HTMLDivElement>(null)
  const taRef = useRef<HTMLTextAreaElement>(null)

  const running = job?.state === 'running'

  // The packed gate's UI half. `inspect` is the server's answer about the
  // selected path - the SAME rules the run gate enforces, one implementation -
  // and `allowPacked` is the single-use override: a new path resets it and it
  // is never persisted, so "run anyway" is always a decision about THIS file,
  // made today, not a standing preference to forget about.
  const [inspect, setInspect] = useState<SampleInspect | null>(null)
  const [allowPacked, setAllowPacked] = useState(false)
  // Selecting the packed sample a live run is already analysing turns Stop
  // into a two-step action: the one run that should not have started is also
  // the one a stray click should not fire by accident.
  const [confirmStop, setConfirmStop] = useState(false)

  // The picker's choices and the upload path into samples/. The listing is
  // metadata only, and never the authority: the run gate re-validates the
  // chosen path, and the upload endpoint applies the same name/root rules.
  const [sampleFiles, setSampleFiles] = useState<SampleFile[]>([])
  const [samplesLoading, setSamplesLoading] = useState(false)
  const [samplesError, setSamplesError] = useState<string | null>(null)
  const [uploading, setUploading] = useState(false)
  const [uploadNotice, setUploadNotice] = useState<{
    tone: 'ok' | 'bad'
    text: string
    /** Only set when the scanner is the thing that refused, so the explicit
        unscanned retry is offered for exactly that refusal. */
    retry?: File
  } | null>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)
  // The card owns its first selection only: once a person picks the placeholder
  // or the factory hands a path over, an empty box is their answer, not a cue.
  const defaultPicked = useRef(false)

  const loadSamples = useCallback(async () => {
    setSamplesLoading(true)
    try {
      const res = await api.listSamples()
      setSampleFiles(res.files)
      setSamplesError(null)
    } catch (e) {
      setSamplesError(e instanceof Error ? e.message : String(e))
    } finally {
      setSamplesLoading(false)
    }
  }, [])

  useEffect(() => {
    void loadSamples()
  }, [loadSamples])

  const uploadSample = useCallback(async (file: File, allowUnscanned = false) => {
    setUploading(true)
    setUploadNotice(null)
    try {
      const res = await api.uploadSample(file, allowUnscanned)
      if (res.ok && res.file) {
        setUploadNotice({
          tone: 'ok',
          text: `Uploaded ${res.file.relative} (${bytes(res.file.bytes)}).`,
        })
        onSampleChange(res.file.relative)
        await loadSamples()
      } else {
        setUploadNotice({
          tone: 'bad',
          text: [res.error, res.detail].filter(Boolean).join(' - ')
            || 'the upload was refused',
          retry: res.code === 'scan-unavailable' ? file : undefined,
        })
      }
    } catch (e) {
      setUploadNotice({ tone: 'bad',
                        text: e instanceof Error ? e.message : String(e) })
    } finally {
      setUploading(false)
    }
  }, [loadSamples, onSampleChange])

  // The current sample is kept in the list even when it came from the factory
  // or from a previous visit: a select whose value is absent would silently
  // render the placeholder while Run still used the path in state.
  const sampleOptions = useMemo(() => {
    const options = [...sampleFiles]
    if (sample && !options.some((f) => f.relative === sample)) {
      options.unshift({
        name: sample.split(/[\\/]/).pop() || sample,
        relative: sample,
        bytes: 0,
        modified: 0,
      })
    }
    return options
  }, [sampleFiles, sample])

  // Seed the empty box from the listed roots. The Tests section's fixture lives
  // at the repo root and is deliberately outside the gate's roots, so it cannot
  // be the default here; prefer the in-tree fixture, then anything listed.
  useEffect(() => {
    if (defaultPicked.current || sample || sampleFiles.length === 0) return
    defaultPicked.current = true
    const preferred = sampleFiles.find(
      (f) => f.relative === 'tests/fixtures/suspicious_sample.exe')
      ?? sampleFiles.find((f) => f.relative.startsWith('tests/fixtures/'))
      ?? sampleFiles[0]
    if (preferred) onSampleChange(preferred.relative)
  }, [sample, sampleFiles, onSampleChange])

  // --- inspect the selected path ------------------------------------------
  //
  // Debounced so a select or factory hand-off does not spawn a request per
  // keystroke, and skipped for paths the local mirror already refuses - the
  // server would refuse the same input for the same reason, and asking it
  // anyway is noise. A path the server refuses lands in `inspect.ok === false`,
  // which disables Run with the server's own sentence under the field.
  const localCheck = localSampleCheck(sample)
  useEffect(() => {
    setAllowPacked(false)      // the override is single-use per path
    setConfirmStop(false)
    if (localCheck.state !== 'ok') {
      setInspect(null)
      return
    }
    let cancelled = false
    const id = window.setTimeout(() => {
      void api.inspectSample(sample)
        .then((res) => { if (!cancelled) setInspect(res) })
        .catch(() => { if (!cancelled) setInspect(null) })  // server down: the
        // start-time gate still protects; inspect is prevention, not authority.
    }, 400)
    return () => { cancelled = true; window.clearTimeout(id) }
  }, [sample, localCheck.state])

  // The confirm-step on Stop self-expires: a stale "Confirm stop" hanging
  // around is a trap for the next run.
  useEffect(() => {
    if (!confirmStop) return
    const id = window.setTimeout(() => setConfirmStop(false), 5000)
    return () => window.clearTimeout(id)
  }, [confirmStop])

  const packedVerdict = inspect?.packed?.packed ? inspect.packed : null
  const packedKnown = packedVerdict !== null
  const refusedByServer = inspect !== null && !inspect.ok
  // What the analyzer will do to an overridden run: with its own tripwire on
  // (IA_INTERRUPT_IF_PACKED), the override only buys a run the analyzer kills
  // at the histogram phase - said on the page, not discovered in the log.
  const analyzerStopOn = inspect?.analyzer_packed_stop?.enabled === true
  // The selected sample is the one the live run is analysing, and it is packed.
  const livePackedRun = running && packedKnown && !!inspect?.path
    && job?.sample === inspect.path

  // A countdown needs the clock to advance even when no new log line arrives,
  // so the remaining time is recomputed on its own 1s tick while a bounded run
  // is live. Without this the number would freeze between polls.
  const [, setTick] = useState(0)
  useEffect(() => {
    if (!running || !job?.deadline) return
    const id = window.setInterval(() => setTick((t) => t + 1), 1000)
    return () => window.clearInterval(id)
  }, [running, job?.deadline])

  // Parsed once and reused by the validation, the hint and the run call, so the
  // three cannot disagree about what was typed.
  const durationSec = useMemo(() => {
    const raw = duration.trim()
    if (raw === '') return { value: null as number | null, ok: true, why: '' }
    if (!/^\d+$/.test(raw)) {
      return { value: null, ok: false, why: 'whole seconds only' }
    }
    const n = Number(raw)
    if (n < 10) return { value: n, ok: false, why: 'minimum is 10s' }
    if (n > 86400) return { value: n, ok: false, why: 'maximum is 24h' }
    return { value: n, ok: true, why: '' }
  }, [duration])

  // What pressing Run will execute, in the same order the server builds argv.
  // Once a job exists its `command` is the exact line - absolute executable,
  // resolved sample path and all - and replaces this preview.
  const commandPreview = useMemo(() => [
    'static_analyzer.exe', '--no-curses', '--pipeline',
    pipeline || '<pipeline>', sample ? quoteArg(sample) : '<sample>',
  ].join(' '), [pipeline, sample])

  // --- attach to an existing run, then poll while one is live ---------------
  useEffect(() => {
    void api.pipelineRun().then((j) => setJob(j)).catch(() => undefined)
  }, [])

  useEffect(() => {
    if (!running) return
    const id = window.setInterval(() => {
      void api.pipelineRun().then((j) => { if (j) setJob(j) }).catch(() => undefined)
    }, LOG_POLL_MS)
    return () => window.clearInterval(id)
  }, [running])

  // --- the dropdown reads the same list Pipelines Config does ---------------
  //
  // Never a local constant: a name the dropdown offers must be one the
  // analyzer's own catalog endpoint acknowledges, or the panel would be an
  // invention machine again. The list is fetched once by Build and handed
  // down here, so this select and the factory's cannot disagree.

  // The selection is lifted: the sample factory's Generate lands its path here
  // and the picker writes it back, so one sample answer lives in one place.
  // The card seeds an empty box from the listed roots; the Tests section's
  // root-level fixture is deliberately not a candidate (the run gate refuses
  // paths outside the sample roots).


  // --- actions --------------------------------------------------------------
  const startRun = useCallback(async () => {
    setStarting(true)
    setNotice(null)
    try {
      const res = await api.startPipelineRun(
        pipeline, sample, durationSec.value, allowPacked)
      if (res.ok) {
        const bound = res.duration_sec
          ? ` with a ${res.duration_sec}s limit`
          : ' with no duration limit'
        // An overridden run the analyzer will kill mid-flight carries its
        // warning on the success payload; shown next to the run it concerns
        // rather than only in the log.
        const warn = res.warning ? ` ${res.warning}.` : ''
        setNotice({ tone: 'ok', text: `Run started on ${sample}${bound}.${warn}` })
        const j = await api.pipelineRun().catch(() => null)
        if (j) setJob(j)
      } else {
        setNotice({ tone: 'bad', text: [res.error, res.detail].filter(Boolean).join(' - ') })
        // A packed refusal may arrive before the debounced inspect has landed
        // (or for a path whose inspect failed); take the verdict from the
        // refusal so the alert and the override cannot be out of date.
        if (res.code === 'sample-packed' && res.packed) {
          setInspect({
            ok: true, path: sample, packed: res.packed,
            analyzer_packed_stop: res.analyzer_packed_stop,
          })
        }
      }
    } catch (e) {
      setNotice({ tone: 'bad', text: e instanceof Error ? e.message : String(e) })
    } finally {
      setStarting(false)
    }
  }, [pipeline, sample, durationSec.value, allowPacked])

  const stopRun = useCallback(async () => {
    if (!job) return
    // Stopping the live run of a packed sample asks once first. Two clicks,
    // the second within five seconds; anything else is the ordinary Stop.
    if (livePackedRun && !confirmStop) {
      setConfirmStop(true)
      return
    }
    setConfirmStop(false)
    const res: { ok: boolean; job_id?: string; state?: string; error?: string } =
      await api.stopPipelineRun(job.id).catch(
        (e) => ({ ok: false, error: e instanceof Error ? e.message : String(e) }),
      )
    setNotice(res.ok
      ? { tone: 'ok', text: `Stop requested for run ${job.id}; it ends when the analyzer exits.` }
      : { tone: 'bad', text: res.error ?? 'could not stop the run' })
    const j = await api.pipelineRun().catch(() => null)
    if (j) setJob(j)
  }, [job, livePackedRun, confirmStop])

  const toggleCursor = useCallback((v: boolean) => {
    setCursor(v)
    try {
      window.localStorage.setItem(RUN_CURSOR_KEY, v ? 'on' : 'off')
    } catch {
      // A private-mode browser refusing localStorage loses only the
      // preference, which resets next visit; the run itself is unaffected.
    }
  }, [])

  const changeDuration = useCallback((raw: string) => {
    setDuration(raw)
    try {
      window.localStorage.setItem(RUN_DURATION_KEY, raw)
    } catch {
      // As with the cursor preference: losing it costs a retype, nothing more.
    }
  }, [])

  // Seconds left on a bounded run, recomputed on every render (the 1s tick
  // above is what makes those renders happen). Null when the run is unbounded
  // or already finished.
  const remaining = running && job?.deadline
    ? Math.max(0, Math.round(job.deadline - Date.now() / 1000))
    : null

  // The cursor-off mode is a plain <textarea>, which cannot paint an SGR
  // sequence - it would show the escape byte as a control glyph and the rest as
  // literal `[36m` text. Strip them: that mode exists so the whole output can
  // be selected and copied, and copied text should not carry terminal control
  // bytes either. The colour is not lost from the page; it is on the cursor-on
  // view and on the Build output tab.
  const plainLog = useMemo(
    () => (job?.log ?? []).map(stripAnsi).join('\n'),
    [job?.log],
  )

  // --- follow the tail (cursor mode) ----------------------------------------
  const onRunScroll = useCallback(() => {
    const el = logRef.current
    if (el) setFollow(el.scrollHeight - el.scrollTop - el.clientHeight < 40)
  }, [])

  useEffect(() => {
    if (!cursor || !follow) return
    const scroll = () => {
      if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight
      else if (taRef.current) taRef.current.scrollTop = taRef.current.scrollHeight
    }
    scroll()
    const raf = window.requestAnimationFrame(scroll)
    return () => window.cancelAnimationFrame(raf)
  }, [cursor, follow, job?.log_line_count])

  // The section still renders while the binary is missing: a card that
  // vanished would read as "gone somewhere else". The Run button is disabled
  // with the reason instead, which is how every other control on this page
  // handles absence.
  // The gate, most specific reason last so the title reads in refusal order:
  // a packed sample the operator has not overridden is refused exactly like
  // the server refuses it, and every earlier reason still says itself first.
  const runDisabled = starting || running || !analyzerReady || !pipeline
    || localCheck.state !== 'ok' || refusedByServer || (packedKnown && !allowPacked)
    || !durationSec.ok
  const runTitle = running
    ? 'A run is already going - stop it or wait'
    : !analyzerReady
      ? 'static_analyzer.exe is not built - build it first, on this page'
      : !pipeline
        ? 'Choose a pipeline'
        : localCheck.state === 'empty'
          ? 'Choose a sample'
          : localCheck.state === 'bad'
            ? localCheck.why
            : refusedByServer
              ? inspect?.error ?? 'The server refused this sample path'
              : packedKnown && !allowPacked
                ? `${sample} is packed (${packedVerdict?.method}) - execution from the panel is prevented; tick the packed override to run it anyway`
                : !durationSec.ok
                  ? `Fix the duration limit: ${durationSec.why}`
                  : durationSec.value
                    ? `Run ${pipeline} on the sample, killed after ${durationSec.value}s`
                    : `Run ${pipeline} on the sample now, with no duration limit`

  return (
    <Card className="build-card">
      <Card.Header className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <Card.Title>Run a pipeline</Card.Title>
          <p className="mt-1 text-[11px] text-muted">
            Starts the analyzer exactly as the terminal would and streams its
            output here. The command line below follows your choices, then
            becomes the server's exact argv once a run starts. Pick a sample
            from the repo's roots or upload one into <code>samples/</code>.
            One run at a time; evidence upload is forced off - the Artifacts
            page owns that.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <label className="build-duration">
            <span className="build-duration-label">Limit</span>
            <input
              className={`field w-20 font-mono text-right${durationSec.ok ? '' : ' is-invalid'}`}
              value={duration}
              disabled={running || starting}
              inputMode="numeric"
              spellCheck={false}
              placeholder="none"
              aria-label="Maximum run duration in seconds"
              aria-invalid={!durationSec.ok}
              onChange={(e) => changeDuration(e.target.value)}
              title={
                durationSec.ok
                  ? durationSec.value
                    ? `The run is killed after ${durationSec.value}s`
                    : 'No limit - the run goes until it finishes or you Stop it'
                  : durationSec.why
              }
            />
            <span className="build-duration-unit">s</span>
          </label>
          <Switch
            label="Cursor"
            checked={cursor}
            pending={false}
            disabled={false}
            onChange={toggleCursor}
            detail={
              cursor
                ? 'Live view with a caret, pinned to the tail.'
                : 'Plain text area - copy the whole output from it.'
            }
          />
        </div>
      </Card.Header>

      <Card.Content className="build-card-body">
        {notice && (
          <Alert status={notice.tone === 'ok' ? 'success' : 'danger'} className="mb-2">
            <Alert.Description>{notice.text}</Alert.Description>
          </Alert>
        )}

        <div className="flex flex-wrap items-center gap-2 pb-2">
          <select
            className="field max-w-40"
            value={pipeline}
            disabled={running || starting}
            onChange={(e) => onPipelineChange(e.target.value)}
            title="The pipeline to run, from the analyzer's own list"
          >
            <option value="">pipeline…</option>
            {pipelines.map((p) => (
              <option key={p} value={p}>{p}</option>
            ))}
          </select>
          <select
            className="field max-w-md flex-1 min-w-56 font-mono"
            value={sample}
            disabled={running || starting || uploading}
            onChange={(e) => onSampleChange(e.target.value)}
            aria-label="Sample to analyse"
            title="Samples come from samples/, tests/fixtures/ and exports/"
          >
            <option value="">sample…</option>
            {sampleOptions.map((f) => (
              <option key={f.relative} value={f.relative}>
                {f.relative}{f.bytes ? ` · ${bytes(f.bytes)}` : ''}
              </option>
            ))}
          </select>
          <button
            type="button"
            className="build-btn is-secondary"
            disabled={running || starting || uploading || samplesLoading}
            onClick={() => void loadSamples()}
            title="Reload the sample list"
          >
            <Icon name="refresh" size={12} />
            {samplesLoading ? 'Loading…' : 'Refresh'}
          </button>
          <button
            type="button"
            className="build-btn is-secondary"
            disabled={running || starting || uploading}
            onClick={() => fileInputRef.current?.click()}
            title="Upload an executable into samples/ - name rules and the clamd scan apply"
          >
            <Icon name="plus" size={12} />
            {uploading ? 'Uploading…' : 'Upload'}
          </button>
          <input
            ref={fileInputRef}
            type="file"
            accept=".exe,.dll,.bin,.sys"
            disabled={running || starting || uploading}
            hidden
            onChange={(e) => {
              const file = e.target.files?.[0] ?? null
              e.target.value = ''
              if (file) void uploadSample(file)
            }}
          />
          <button
            type="button"
            className="build-btn"
            disabled={runDisabled}
            onClick={() => void startRun()}
            title={runTitle}
          >
            <Icon name="play" size={12} />
            {running ? 'Running…' : starting ? 'Starting…' : 'Run'}
          </button>
          {running && (
            <button
              type="button"
              className={`build-btn ${livePackedRun ? 'is-danger' : 'is-secondary'}`}
              onClick={() => void stopRun()}
              title={livePackedRun
                ? confirmStop
                  ? 'End this packed run now - the lines already printed stay'
                  : 'This run analyses a packed sample - press again to confirm the stop'
                : 'Terminate the analyzer; the lines already printed stay'}
            >
              <Icon name="x" size={12} />
              {livePackedRun && confirmStop ? 'Confirm stop' : 'Stop'}
            </button>
          )}
        </div>

        {/* The command, not just a template. Before a run this is the preview
            from the two selectors; once a job exists it is the server's exact
            argv, so the absolute executable and resolved sample path are
            visible without opening the log. */}
        <div className="build-command"
             title={job?.command
               ? 'The exact command the server spawned for this run'
               : 'Preview - the server resolves the sample to an absolute path when the run starts'}>
          <span className="build-command-label">
            {job?.command ? (running ? 'Running' : 'Last run') : 'Will run'}
          </span>
          <code>{job?.command ?? commandPreview}</code>
        </div>

        {/* The picker's own state. A listing failure does not block Upload -
            the endpoint validates independently and the run gate would catch
            anything the list missed. */}
        {samplesError && (
          <p className="build-duration-hint text-[11px] pb-2 text-danger">
            Could not list samples: {samplesError}. Upload still works.
          </p>
        )}
        {uploadNotice && (
          <Alert status={uploadNotice.tone === 'ok' ? 'success' : 'danger'}
                 className="mb-2">
            <Alert.Description>
              {uploadNotice.text}
              {uploadNotice.retry && (
                <button
                  type="button"
                  className="build-btn is-secondary ml-2"
                  disabled={uploading}
                  onClick={() => void uploadSample(uploadNotice.retry!, true)}
                  title="Admit this file without a scan - the decision is logged"
                >
                  Upload without a scan
                </button>
              )}
            </Alert.Description>
          </Alert>
        )}

        {/* The sample-path rules, said where they bite: a selected path that
            breaks one gets the sentence here rather than only as a disabled
            button - a greyed Run with no reason is the most useless control
            there is. */}
        {localCheck.state === 'bad' && (
          <p className="build-duration-hint text-[11px] pb-2 text-danger">
            {localCheck.why}
          </p>
        )}
        {refusedByServer && (
          <Alert status="danger" className="mb-2">
            <Alert.Description>{inspect?.error}</Alert.Description>
          </Alert>
        )}

        {/* The packed gate, at selection rather than at start. Everything on
            this card is derived from what the SERVER said about the file -
            the verdict is recomputed server-side on every start, so this
            alert can never be the reason a packed sample runs. */}
        {packedKnown && (
          <Alert status="danger" className="mb-2">
            <Alert.Title>
              {inspect?.relative ?? sample} is packed (
              {packedVerdict?.method === 'upx' ? 'UPX' : 'high entropy'})
            </Alert.Title>
            <Alert.Description>
              <p>
                Execution from the panel is prevented: a packed executable
                spends the run in unpacking loops, and the phases after the
                histogram cannot be trusted about it.{' '}
                {packedVerdict?.evidence}
              </p>
              {livePackedRun && (
                <p className="mt-2 font-semibold">
                  This packed sample is the one the live run is analysing -
                  stop it above.
                </p>
              )}
              <label className="mt-2 flex items-center gap-2 text-[11px]">
                <input
                  type="checkbox"
                  checked={allowPacked}
                  disabled={running || starting}
                  onChange={(e) => setAllowPacked(e.target.checked)}
                />
                Run anyway (packed override)
              </label>
              <p className="mt-1 text-[11px] opacity-80">
                {analyzerStopOn
                  ? 'IA_INTERRUPT_IF_PACKED is ON in the analyzer config, so an overridden run is still stopped at the histogram phase - switch it off on Analysis Configuration to analyse it fully.'
                  : 'IA_INTERRUPT_IF_PACKED is off, so an overridden run would analyse the sample fully.'}
              </p>
            </Alert.Description>
          </Alert>
        )}

        {/* The hint only appears when it has something to say: a bound is set, or
            the typed value is unusable. "No limit" is the default and needs no
            sentence every visit - a permanent caption under a field nobody
            changed is noise the eye learns to skip past. */}
        {durationSec.value || !durationSec.ok ? (
          <p className={`build-duration-hint text-[11px] pb-2${durationSec.ok ? ' text-muted' : ' text-danger'}`}>
            {durationSec.value
              ? `Bound to ${durationSec.value}s: when the limit is reached the analyzer is `
                + 'terminated, then killed if it will not exit. Leave blank to run '
                + 'unbounded.'
              : durationSec.why}
          </p>
        ) : null}

        {job && (
          <div className="build-log-controls pb-2 text-[10px] text-muted">
            <Chip
              size="sm"
              variant="soft"
              color={job.state === 'running' ? 'accent'
                : job.state === 'done' ? 'success'
                : job.state === 'stopped' ? 'warning' : 'danger'}
            >
              {job.state}
            </Chip>
            {job.packed?.packed && (
              <Chip size="sm" variant="soft" color="danger">
                packed ({job.packed.method})
              </Chip>
            )}
            <span className="build-log-meta">
              run {job.id} · {job.pipeline} · {job.log_line_count} line
              {job.log_line_count === 1 ? '' : 's'}
              {job.exit_code !== null && ` · exit ${job.exit_code}`}
              {job.duration_sec ? ` · limit ${job.duration_sec}s` : ''}
              {remaining !== null && (
                <> · <span className={remaining <= 5 ? 'text-danger' : undefined}>
                  {remaining}s left
                </span></>
              )}
            </span>
          </div>
        )}

        {job?.error && (
          <Alert status={job.timed_out || job.state === 'stopped' ? 'warning' : 'danger'} className="mb-2">
            <Alert.Description>{job.error}</Alert.Description>
          </Alert>
        )}

        {!job ? (
          <p className="build-empty">
            Nothing run from the panel yet. Choose a pipeline, pick a sample
            (or upload one), and press Run - the output appears here as the
            analyzer prints it.
          </p>
        ) : cursor ? (
          <div
            className="build-log"
            role="log"
            aria-label="Pipeline output"
            aria-live="polite"
            ref={logRef}
            onScroll={onRunScroll}
          >
            {job.log_dropped ? (
              <div className="build-log-line is-truncated">
                ... {job.log_dropped} earlier line{job.log_dropped === 1 ? '' : 's'} dropped
              </div>
            ) : null}
            {job.log.map((line, i) => (
              <LogRow key={i} line={line} n={i + 1} />
            ))}
            {running && <span className="run-cursor" aria-hidden="true" />}
          </div>
        ) : (
          <textarea
            ref={taRef}
            className="run-textarea"
            readOnly
            rows={16}
            spellCheck={false}
            aria-label="Pipeline output as plain text"
            value={plainLog}
            placeholder="The run's output appears here, one line per line."
          />
        )}
      </Card.Content>
    </Card>
  )
}

export default function Build({ onNavigate }: {
  /** Where the page is allowed to send the admin - the factory's
      "Create pipeline" hands off to the Pipelines section. */
  onNavigate?: (panel: 'pipelines') => void
}) {
  const [data, setData] = useState<BuildOverview | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [job, setJob] = useState<AnalyzerBuildJob | null>(null)
  const [starting, setStarting] = useState(false)
  const [notice, setNotice] = useState<{ tone: 'ok' | 'bad'; text: string } | null>(null)
  const [follow, setFollow] = useState(true)
  const [showOptional, setShowOptional] = useState(false)
  const [checking, setChecking] = useState(false)
  const [inspect, setInspect] = useState<BuildInspect | null>(null)
  const [catalogue, setCatalogue] = useState<BuildTestCatalogue | null>(null)
  const [runningTests, setRunningTests] = useState(false)

  // The run card's two selections live here, one level up, so the sample
  // factory can land a generated sample and its pipeline choice in the same
  // boxes without a second runner of its own.
  const [runPipeline, setRunPipeline] = useState('')
  const [runSample, setRunSample] = useState('')

  // Sections are tabs, the way Pipelines Configuration does it: one concern on
  // screen at a time, the page keeps one identity and one header. The one
  // deliberate coupling is that pressing Build or running tests switches to
  // the output tab - a button whose only visible effect is on another tab
  // would look like it did nothing.
  type Tab = 'info' | 'deps' | 'log' | 'factory' | 'run' | 'tests'
  const [tab, setTab] = useState<Tab>('info')

  const logRef = useRef<HTMLDivElement>(null)
  const loadedCount = useRef(0)

  // --- overview ------------------------------------------------------------
  const loadOverview = useCallback(async () => {
    try {
      const next = await api.buildOverview()
      setData(next)
      setError(null)
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void loadOverview()
    const id = window.setInterval(() => void loadOverview(), POLL_MS * 4)
    return () => window.clearInterval(id)
  }, [loadOverview])

  // --- identity, freshness, validation -------------------------------------
  //
  // Polled far more slowly than the overview, and deliberately not on the same
  // timer. Each call actually RUNS the analyzer five times - --version,
  // --list-pipelines, --crash-demo and the import walk - and doing that every
  // few seconds would be absurd. It refreshes after a build finishes, when the
  // answer genuinely changes, and slowly otherwise.
  const loadInspect = useCallback(async () => {
    try {
      setInspect(await api.buildInspect())
    } catch {
      // A missing inspection report must not take the build page down with it.
      // The card stays empty; the build controls are unaffected.
    }
  }, [])

  useEffect(() => {
    void loadInspect()
    const id = window.setInterval(() => void loadInspect(), POLL_MS * 30)
    return () => window.clearInterval(id)
  }, [loadInspect])

  // --- the test catalogue ---------------------------------------------------
  //
  // Fetched once per visit. It changes when somebody edits tests/, which is
  // rarer than a build, and it is not worth a poll.
  useEffect(() => {
    void api.buildTests().then(setCatalogue).catch(() => undefined)
  }, [])

  // The pipeline names come from the analyzer's own listing - the same the
  // Pipelines page shows - fetched once and shared by the factory and the
  // run card, so neither select can drift from what the binary knows.
  const [pipelines, setPipelines] = useState<string[]>([])
  useEffect(() => {
    void api.analysisConfig()
      .then((c) => setPipelines(c.pipelines.map((p) => p.name)))
      .catch(() => undefined)
  }, [])

  // The run starts where the page starts, on the repo's own inert fixture:
  // a fresh visit gets "Run" working without demanding a path nobody has to
  // hand. The factory's Generate replaces this the moment it compiles
  // something, so the fixture only ever fills an empty box.
  useEffect(() => {
    // The Tests fixture can live at the repo root, which the run gate rightly
    // refuses; leave the box empty in that case and let the Run card seed it
    // from its own listing instead.
    if (catalogue?.sample && !runSample && underSampleRoot(catalogue.sample)) {
      setRunSample(catalogue.sample)
    }
  }, [catalogue?.sample])  // eslint-disable-line react-hooks/exhaustive-deps

  // --- reattach to a running build ----------------------------------------
  //
  // On mount, and after every build start. Without this a reload would show an
  // idle panel while the compiler worked, which is the worst possible moment for
  // the page to look idle.
  useEffect(() => {
    let cancelled = false
    void api.currentBuild()
      .then((current) => { if (!cancelled && current) setJob(current) })
      .catch(() => undefined)
    return () => { cancelled = true }
  }, [])

  // --- log polling while running ------------------------------------------
  const running = job?.state === 'running'

  useEffect(() => {
    if (!running || !job) return
    const id = window.setInterval(async () => {
      try {
        const next = await api.buildJob(job.id)
        setJob(next)
        if (next.state !== 'running') {
          void loadOverview()
          // A finished build invalidates every freshness and validation fact on
          // the page, so this is the moment to re-ask.
          void loadInspect()
        }
      } catch {
        // A dropped poll is not a failure of the build; the next tick tries
        // again and the job's own terminal state arrives eventually.
      }
    }, LOG_POLL_MS)
    return () => window.clearInterval(id)
  }, [running, job?.id, loadOverview, loadInspect])

  // --- keep the tail in view ----------------------------------------------
  //
  // Only while following. Scrolling up to read an error is the whole point of a
  // log, and a forced scroll would yank the reader back to the bottom every two
  // seconds - so the first scroll away pins the view and following stops until
  // it is switched back on.
  const onLogScroll = useCallback(() => {
    const el = logRef.current
    if (!el) return
    const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 40
    setFollow(atBottom)
  }, [])

  const scrollToTail = useCallback(() => {
    const el = logRef.current
    if (el) el.scrollTop = el.scrollHeight
  }, [])

  useEffect(() => {
    if (!follow) return
    scrollToTail()
    // A second pass on the next frame. The first write is often a no-op: the
    // browser has not finished laying out the rows that were just appended, so
    // scrollHeight is still the pre-append value. Without this, reopening the
    // panel during a build lands on line 1 with a thousand lines below it.
    const raf = window.requestAnimationFrame(scrollToTail)
    return () => window.cancelAnimationFrame(raf)
  }, [job?.log?.length, follow, scrollToTail])

  // --- actions -------------------------------------------------------------
  const start = async (clean: boolean) => {
    setStarting(true)
    setNotice(null)
    try {
      const res = await api.startBuild(clean)
      const fresh = await api.buildJob(res.job_id)
      setJob(fresh)
      loadedCount.current = 0
      setFollow(true)
      // Build output is mirrored inside Build environment (2.4), so the
      // environment the reader just checked and the compiler's answer to it
      // stay on one screen. The full log is one click away.
      setTab('deps')
      setNotice({ tone: 'ok', text: clean ? 'Clean build started.' : 'Build started.' })
    } catch (e) {
      const detail = e instanceof Error ? e.message : String(e)
      setNotice({ tone: 'bad', text: detail })
    } finally {
      setStarting(false)
    }
  }

  // Re-probe both reports on demand.
  //
  // Worth a button because the stack half includes services that come and go:
  // starting MalAPI or the ML scorer from the terminal changes the answer, and
  // a report only recomputed on page load would keep calling them down.
  const checkDeps = async () => {
    setChecking(true)
    setNotice(null)
    try {
      const fresh = await api.checkBuildDeps()
      // Merged rather than replacing the whole overview: the response carries
      // the two reports only, and dropping `artifacts`/`jobs` here would blank
      // the executables list and the log header.
      setData((prev) => (prev ? { ...prev, ...fresh } : prev))
      const missing = fresh.stack.missing_required + fresh.toolchain.missing_required
      setNotice({
        tone: 'ok',
        text: missing === 0
          ? `Checked ${fresh.stack.counts.total + fresh.toolchain.counts.total} items — everything required is present.`
          : `Checked — ${missing} required item${missing === 1 ? '' : 's'} still missing.`,
      })
    } catch (e) {
      setNotice({ tone: 'bad', text: e instanceof Error ? e.message : String(e) })
    } finally {
      setChecking(false)
    }
  }

  // --- run the chosen tests -------------------------------------------------
  //
  // Deliberately shares the job state and the log with builds. The two are the
  // same kind of thing - a long subprocess whose output streams in - and a
  // second log pane would be a second scroll position to lose track of. The
  // job's `kind` is what tells the header which one you are looking at.
  const runTests = async (ids: string[]) => {
    if (ids.length === 0) return
    setRunningTests(true)
    setNotice(null)
    try {
      const res = await api.startBuildTests(ids)
      if (!res.ok || !res.job_id) {
        setNotice({ tone: 'bad', text: res.error ?? 'the test run was refused' })
        return
      }
      const fresh = await api.buildJob(res.job_id)
      setJob(fresh)
      loadedCount.current = 0
      setFollow(true)
      // The picker and the test's output are the same section; the full log
      // remains on Build output.
      setTab('tests')
    } catch (e) {
      setNotice({ tone: 'bad', text: e instanceof Error ? e.message : String(e) })
    } finally {
      setRunningTests(false)
    }
  }

  // --- derived -------------------------------------------------------------
  const toolchain = data?.toolchain
  const stack = data?.stack
  // A test run is a job too; the page has to say which, or "Building…" sits
  // above a log full of pytest output.
  const isTestJob = job?.kind === 'tests'
  const lines = useMemo(() => job?.log ?? [], [job?.log])

  const parsed = useMemo(
    () => lines.map((line) => parseLine(line)),
    [lines],
  )

  const problems = useMemo(
    () => parsed.filter((p) => p.notable).length,
    [parsed],
  )

  const toolchainRows = useMemo<BuildDependency[]>(() => {
    if (!toolchain?.available) return []
    return [
      ...toolchain.tools.map((t) => ({
        name: t.name, kind: 'tool' as const, required: true,
        found: t.found, path: t.path, note: t.why,
      })),
      ...toolchain.dependencies,
    ]
      .filter((d) => showOptional || d.required)
      .sort((a, b) => (TOOLCHAIN_ORDER[a.kind] ?? 9) - (TOOLCHAIN_ORDER[b.kind] ?? 9)
        || a.name.localeCompare(b.name))
  }, [toolchain, showOptional])

  const stackGroups = useMemo(() => {
    if (!stack?.available) return []
    const rows = stack.dependencies.filter((d) => showOptional || d.required)
    return STACK_GROUPS
      .map((g) => ({
        label: g.label,
        deps: rows
          .filter((d) => g.kinds.includes(d.kind))
          .sort((a, b) => a.name.localeCompare(b.name)),
      }))
      .filter((g) => g.deps.length > 0)
  }, [stack, showOptional])

  const toolchainOptional = toolchain?.dependencies.filter((d) => !d.required).length ?? 0
  const stackOptional = stack?.dependencies.filter((d) => !d.required).length ?? 0
  const optionalCount = toolchainOptional + stackOptional

  // --- render --------------------------------------------------------------
  if (loading && !data) return <Loading label="Reading the build configuration…" />

  // Only the toolchain gates a build. A missing capa or a down ML scorer does
  // not stop a compile, so it is reported without disabling the button -
  // blocking here would be a lie about what the build does.
  const blocked = (toolchain?.missing_required ?? 0) > 0

  return (
    <div className="build-page">
      <header className="build-page-header">
        <div>
          <p className="eyebrow">Native analyzer</p>
          <h1 className="page-title mt-1">Build</h1>
          <p className="mt-2 max-w-2xl text-xs text-muted">
            Compiles <code>static_analyzer.exe</code> through <code>build.ps1</code> —
            the same script and presets a terminal uses, so the panel builds the
            binary you would have built by hand.
          </p>
        </div>
        <div className="build-page-actions">
          {data && (
            <Chip size="sm" variant="soft" color={data.artifacts.analyzer_ready ? 'success' : 'warning'}>
              {data.artifacts.analyzer_ready
                ? `analyzer built · ${bytes(data.artifacts.analyzer?.bytes ?? 0, 0)}`
                : 'no analyzer built'}
            </Chip>
          )}
          <button
            type="button"
            className="build-btn is-secondary"
            onClick={() => void checkDeps()}
            disabled={checking}
            title="Re-read CMakeLists.txt and re-probe the stack — MalAPI, capa, the ML scorer — right now"
          >
            <Icon name="refresh" size={12} />
            {checking ? 'Checking…' : 'Check dependencies'}
          </button>
          <button
            type="button"
            className="build-btn"
            onClick={() => void start(false)}
            disabled={starting || running || blocked}
            title={
              running ? 'A build is already running'
                : blocked ? `${toolchain?.missing_required} required build dependencies are missing`
                : 'Compile without reconfiguring'
            }
          >
            <Icon name="play" size={12} />
            {running ? (isTestJob ? 'Running tests…' : 'Building…') : 'Build'}
          </button>
          <button
            type="button"
            className="build-btn is-secondary"
            onClick={() => void start(true)}
            disabled={starting || running || blocked}
            title="Delete build-ucrt/ and reconfigure from scratch — slow, and it discards the current build tree"
          >
            <Icon name="refresh" size={12} />
            Clean build
          </button>
        </div>
      </header>

      {error && (
        <Alert status="danger" className="mb-4">
          <Alert.Title>Cannot read the build configuration</Alert.Title>
          <Alert.Description>{error}</Alert.Description>
        </Alert>
      )}

      {/* Sections as tabs, the Pipelines Configuration pattern. The dots are
          the same facts the content's chips show: identity health, whether the
          build is blocked, and where the last build/test ended up.

          Wrapped so the tab strip can stick: a Build section is tall enough
          that the next step's tab is off-screen by the time you have read to the
          bottom of the current one, which turns a work order back into a scroll.
          Scoped to this page's own wrapper class, not SubNav itself, so no other
          panel silently changes behaviour. */}
      <div className="build-nav">
      <SubNav
        tabs={[
          {
            id: 'info', label: 'Build information', icon: 'machine',
            tone: inspect
              ? (inspect.validation.verdict === 'fail' || inspect.provenance.agrees === false
                ? 'bad' : inspect.freshness.stale ? 'warn' : 'ok')
              : undefined,
          },
          {
            id: 'deps', label: 'Dependencies', icon: 'artifacts',
            tone: data
              ? (blocked ? 'bad' : (stack?.missing_required ?? 0) > 0 ? 'warn' : 'ok')
              : undefined,
          },
          {
            id: 'log', label: 'Build output', icon: 'terminal',
            tone: job
              ? (job.state === 'running' ? 'warn'
                : job.state === 'done' || job.state === 'passed' ? 'ok' : 'bad')
              : undefined,
          },
          { id: 'factory', label: 'Sample generation', icon: 'file-code' },
          { id: 'run', label: 'Run a pipeline', icon: 'play' },
          { id: 'tests', label: 'Automated tests', icon: 'check' },
        ]}
        active={tab}
        onChange={(id) => setTab(id as Tab)}
      />
      </div>

      {notice && (
        <Alert status={notice.tone === 'ok' ? 'success' : 'danger'} className="mb-4">
          <Alert.Description>{notice.text}</Alert.Description>
        </Alert>
      )}

      {/* Blocked builds are called out before the button, because a disabled
          button with no reason is the most useless control there is. */}
      {blocked && (
        <Alert status="danger" className="mb-4">
          <Alert.Title>
            {toolchain?.missing_required} required build{' '}
            {toolchain?.missing_required === 1 ? 'dependency is' : 'dependencies are'} missing
          </Alert.Title>
          <Alert.Description>
            The build is disabled until they resolve — CMake would stop at the
            first one anyway, and failing here tells you which.
          </Alert.Description>
        </Alert>
      )}

      {/* Numbered sections, in work order: identity first - is the binary
          healthy? - environment next, output, then the three things you DO
          with what it produced (mine a sample, run a pipeline, run tests).
          The Section wrapper says so; the page header's buttons stay there
          because building is also worth doing from anywhere. */}
      {tab === 'info' && (
      <Section
        n={1}
        title="Identity & configuration"
        hint="What this binary IS, and what it was built WITH - the two facts every other card's word depends on. A stale binary fails them all while still looking perfectly healthy."
      >
        <Sub
          n="1.1"
          title="Provenance"
          // The same three facts ProvenanceCard's verdict derives from: a
          // failed check or a binary from another commit is danger, a stale
          // build is warning, otherwise this section rail is green.
          tone={inspect
            ? (inspect.validation.verdict === 'fail' || inspect.provenance.agrees === false
              ? 'danger'
              : inspect.freshness.stale ? 'warning' : 'success')
            : 'accent'}
          hint="Which commit, which tree, whether the binary still matches either."
        >
          {inspect && (
            <ProvenanceCard
              provenance={inspect.provenance}
              freshness={inspect.freshness}
              validation={inspect.validation}
            />
          )}
        </Sub>
        <Sub
          n="1.2"
          title="Build configuration"
          tone="accent"
          hint="The flags and presets this binary was compiled with."
        >
          {inspect && <ConfigurationCard config={inspect.configuration} />}
        </Sub>
      </Section>
      )}

      {/* --- analysis stack ------------------------------------------- */}
      {tab === 'deps' && (
      <Section
        n={2}
        title="Build environment"
        hint="What the analyzer uses at analysis time, and what the build depends on. A missing stack entry does not stop a compile - the phase it belongs to silently produces nothing."
      >
        <Sub
          n="2.1"
          title="Built executables"
          tone={data?.artifacts.analyzer_ready ? 'success' : 'warning'}
          hint="What the last build left on disk - the binary everything below acts on."
        >
          <Card className="build-card build-artifacts-card">
            <Card.Header className="flex flex-wrap items-center justify-between gap-2">
              <div>
                <Card.Title>Built executables</Card.Title>
                <p className="mt-1 text-[11px] text-muted">
                  From <code>{data?.artifacts.build_dir}</code> and the repo root
                </p>
              </div>
            </Card.Header>
            <Card.Content className="build-card-body">
              {(data?.artifacts.artifacts.length ?? 0) === 0 ? (
                <p className="build-empty">
                  Nothing built yet. Run a build, or use the CLI.
                </p>
              ) : (
                <ul className="build-artifacts">
                  {data?.artifacts.artifacts.map((a) => (
                    <li key={a.relative} className={a.name === 'static_analyzer.exe' ? 'is-primary' : ''}>
                      <span className="build-artifact-name" title={a.path}>{a.name}</span>
                      <span className="build-artifact-meta">
                        {bytes(a.bytes, 1)} · {ago(a.modified)}
                      </span>
                    </li>
                  ))}
                </ul>
              )}
            </Card.Content>
          </Card>
        </Sub>

        <Sub
          n="2.2"
          title="Build toolchain"
          tone={blocked ? 'danger' : toolchain?.available ? 'success' : 'accent'}
          hint="Read from CMakeLists.txt - the WIN32 branch. Missing required entries disable the build button above."
        >
          <Card className="build-card">
            <Card.Header className="flex flex-wrap items-center justify-between gap-2">
              <div>
                <Card.Title>Build toolchain</Card.Title>
                <p className="mt-1 text-[11px] text-muted">
                  Missing required entries disable the build.
                </p>
              </div>
              {toolchain?.available && (
                <Chip
                  size="sm"
                  variant="soft"
                  color={blocked ? 'danger' : 'success'}
                >
                  {toolchain.counts.found}/{toolchain.counts.total} found
                </Chip>
              )}
            </Card.Header>
            <Card.Content className="build-card-body">
              {!toolchain?.available ? (
                <p className="build-empty">{toolchain?.reason ?? 'no dependency report'}</p>
              ) : (
                <>
                  {!toolchain.sysroot_found && (
                    <Alert status="danger">
                      <Alert.Description>
                        MSYS2 UCRT64 not found at <code>{toolchain.sysroot}</code>. Every
                        library below is checked inside that tree.
                      </Alert.Description>
                    </Alert>
                  )}
                  <ul className="build-deps">
                    {toolchainRows.map((d) => (
                      <DepRow key={`${d.kind}:${d.name}`} dep={d} />
                    ))}
                  </ul>
                </>
              )}
            </Card.Content>
          </Card>
        </Sub>

        <Sub
          n="2.3"
          title="Analysis stack"
          tone={!stack?.available ? 'accent' : stack.missing_required > 0 ? 'warning' : 'success'}
          hint="MalAPI, capa, the rule packs, the ML scorer. A missing one does not stop a build - the phase it belongs to silently produces nothing."
        >
          <Card className="build-card">
            <Card.Header className="flex flex-wrap items-center justify-between gap-2">
              <div>
                <Card.Title>Analysis stack</Card.Title>
                <p className="mt-1 text-[11px] text-muted">
                  A missing one does not stop a build, but the phase it belongs
                  to silently produces nothing.
                </p>
              </div>
              {stack?.available && (
                <div className="flex items-center gap-1.5">
                  <Chip
                    size="sm"
                    variant="soft"
                    color={stack.missing_required > 0 ? 'warning' : 'success'}
                  >
                    {stack.counts.found}/{stack.counts.total} found
                  </Chip>
                  {optionalCount > 0 && (
                    <button
                      type="button"
                      className="build-link"
                      onClick={() => setShowOptional((v) => !v)}
                      title="Optional entries are dimmed and do not gate a build. Shown here collapsed so the required set is readable at a glance."
                    >
                      {showOptional ? 'Hide' : 'Show'} {optionalCount} optional
                    </button>
                  )}
                </div>
              )}
            </Card.Header>
            <Card.Content className="build-card-body">
              {!stack?.available ? (
                <p className="build-empty">no stack report</p>
              ) : (
                <>
                  {!stack.manifest_loaded && (
                    <Alert status="warning">
                      <Alert.Description>
                        <code>{stack.manifest}</code> could not be read, so the
                        vendored checkouts and Python environments below are not
                        verified.
                      </Alert.Description>
                    </Alert>
                  )}
                  <ul className="build-deps">
                    {stackGroups.map((g) => (
                      <DepGroup key={g.label} label={g.label} deps={g.deps} />
                    ))}
                  </ul>
                </>
              )}
            </Card.Content>
          </Card>
        </Sub>

        <Sub
          n="2.4"
          title="Build output"
          tone={job && !isTestJob
            ? (job.state === 'running' ? 'warning'
              : job.state === 'done' ? 'success' : 'danger')
            : 'accent'}
          hint="The compiler's own lines, in this section rather than on another tab. The full log stays under Build output."
        >
          <Card className="build-card">
            <Card.Header className="flex flex-wrap items-center justify-between gap-2">
              <div>
                <Card.Title>Compiler output</Card.Title>
                <p className="mt-1 text-[11px] text-muted">
                  Last 40 lines of this session's build; the complete log is on
                  the <b>Build output</b> tab.
                </p>
              </div>
            </Card.Header>
            <Card.Content className="build-card-body">
              <JobTail job={job} kind="build" onOpen={() => setTab('log')} />
            </Card.Content>
          </Card>
        </Sub>
      </Section>
      )}

      {/* --- the log ---------------------------------------------------- */}
      {tab === 'log' && (
      <Section
        n={3}
        title="Build output"
        hint="Every line the build - or the test run you started from below - has printed so far."
        meta={job && (
          <span className="build-log-meta">
            job {job.id} · {job.log_line_count} line{job.log_line_count === 1 ? '' : 's'}
            {job.exit_code !== null && ` · exit ${job.exit_code}`}
          </span>
        )}
      >
      <Card className="build-card build-log-card">
        <Card.Header className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-baseline gap-2">
            <Card.Title>{isTestJob ? 'Test log' : 'Build log'}</Card.Title>
            {job && (
              <span className="build-log-meta">
                {job.kind === 'tests' && job.summary ? `${job.summary} · ` : ''}
                job {job.id} · {job.log_line_count} line{job.log_line_count === 1 ? '' : 's'}
                {job.exit_code !== null && ` · exit ${job.exit_code}`}
              </span>
            )}
          </div>
          <div className="build-log-controls">
            {job && (
              <Chip
                size="sm"
                variant="soft"
                // A test run reports 'passed', a build reports 'done'. Mapping
                // only 'done' to success would render a green test run red,
                // which is the sort of bug that teaches people to ignore the
                // one chip on the page that means something.
                color={job.state === 'running' ? 'accent'
                  : job.state === 'done' || job.state === 'passed' ? 'success'
                    : 'danger'}
              >
                {job.state}
              </Chip>
            )}
            {problems > 0 && (
              <Chip size="sm" variant="soft" color="warning">{problems} notable line{problems === 1 ? '' : 's'}</Chip>
            )}
            {!follow && (
              <button type="button" className="build-link" onClick={() => setFollow(true)}>
                Jump to tail
              </button>
            )}
          </div>
        </Card.Header>
        <Card.Content className="build-card-body">
          {job?.error && (
            <Alert status="danger" className="mb-2">
              <Alert.Description>{job.error}</Alert.Description>
            </Alert>
          )}
          {!job ? (
            <p className="build-empty">
              No build or test run has happened this panel session. Start one
              above - or pick a test below - and its output streams here.
            </p>
          ) : lines.length === 0 ? (
            <p className="build-empty">
              Waiting for the first line from{' '}
              <code>{isTestJob ? 'the test runner' : 'build.ps1'}</code>…
            </p>
          ) : (
            <div
              className="build-log"
              role="log"
              aria-label={isTestJob ? 'Test output' : 'Build output'}
              aria-live="polite"
              ref={logRef}
              onScroll={onLogScroll}
            >
              {job.log_truncated ? (
                <div className="build-log-line is-truncated">
                  … {job.log_truncated} earlier line{job.log_truncated === 1 ? '' : 's'} dropped
                </div>
              ) : null}
              {lines.map((line, i) => (
                <LogRow key={i} line={line} n={i + 1} />
              ))}
            </div>
          )}
        </Card.Content>
      </Card>
      </Section>
      )}

      {/* --- the sample factory ------------------------------------------ */}
      {tab === 'factory' && (
      <Section
        n={4}
        title="Test sample factory"
        hint="A C or C++ int main(), picked from a template or assembled with checkboxes - noise plants a faulty IP and a known domain for the analyzer to find - then compiled here with the same UCRT64 tree."
        meta={catalogue?.sample ? (
          <span className="build-log-meta">fixture: {catalogue.sample}</span>
        ) : undefined}
      >
        <SampleFactoryCard
          pipelines={pipelines}
          pipeline={runPipeline}
          onPipelineChange={setRunPipeline}
          onGenerated={(exe) => setRunSample(exe)}
          onNavigatePipelines={() => onNavigate?.('pipelines')}
        />
      </Section>
      )}

      {/* Run a pipeline sits before the test picker for the same reason the
          picker sits after the log: run, then read what it printed, in one
          gesture. It shares the log card's renderer so cursor mode looks
          exactly like a build log the admin already knows how to read. */}
      {tab === 'run' && (
      <Section
        n={5}
        title="Run a pipeline"
        hint="Pick a pipeline and a sample from the repo's roots, or upload one into samples/, then watch static_analyzer's own output stream here. One run at a time; evidence upload is forced off - the Artifacts page owns that."
      >
        <PipelineRunCard
          analyzerReady={data?.artifacts.analyzer_ready}
          pipelines={pipelines}
          pipeline={runPipeline}
          onPipelineChange={setRunPipeline}
          sample={runSample}
          onSampleChange={setRunSample}
        />
      </Section>
      )}

      {/* The picker sits at the end rather than the start: choosing a test and
          then reading its output is one gesture against the log above, and the
          answer is never more than a screen away. */}
      {tab === 'tests' && (
      <Section
        n={6}
        title="Automated tests"
        hint="The smoke tests, the pytest suites and the analysis fixture - what each one touches is named before it runs."
      >
        {catalogue ? (
          <TestPicker
            catalogue={catalogue}
            results={isTestJob ? job?.results ?? [] : []}
            running={running}
            onRun={(ids) => void runTests(ids)}
            busy={runningTests}
          />
        ) : (
          <Card className="build-card">
            <Card.Content className="build-card-body">
              <p className="build-empty">no test catalogue</p>
            </Card.Content>
          </Card>
        )}

        <Card className="build-card">
          <Card.Header className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <Card.Title>Test output</Card.Title>
              <p className="mt-1 text-[11px] text-muted">
                The selected tests' output, in the section that started them.
                The complete log is on the <b>Build output</b> tab.
              </p>
            </div>
          </Card.Header>
          <Card.Content className="build-card-body">
            <JobTail job={job} kind="tests" onOpen={() => setTab('log')} />
          </Card.Content>
        </Card>
      </Section>
      )}
    </div>
  )
}