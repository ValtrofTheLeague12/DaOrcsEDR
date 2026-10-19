import { useCallback, useEffect, useMemo, useRef, useState, memo } from 'react'
import { Alert, Card, Chip } from '@heroui/react'
import { api } from '../api'
import Icon from '../components/Icon'
import Loading from '../components/Loading'
import { parseLine, TONE_CLASS } from '../lib/logColor'
import { ago, bytes } from '../lib/format'
import { ConfigurationCard, ProvenanceCard, TestPicker } from './BuildChecks'
import type {
  AnalyzerBuildJob,
  BuildDependency,
  BuildInspect,
  BuildOverview,
  BuildTestCatalogue,
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
  return (
    <>
      <li className="build-dep-group" aria-hidden="true">{label}</li>
      {deps.map((d) => (
        <DepRow key={`${d.kind}:${d.name}`} dep={d} />
      ))}
    </>
  )
}

export default function Build() {
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

      {/* Identity and configuration sit ABOVE everything else on purpose.
          Everything below describes a build environment; this answers whether
          the binary that environment produced is the one you are running. A
          stale binary fails every other card's checks while still looking
          perfectly healthy. */}
      {/* Identity and configuration sit ABOVE everything else on purpose.
          Everything below describes a build environment; this answers whether
          the binary that environment produced is the one you are running. A
          stale binary fails every other card's checks while still looking
          perfectly healthy.

          Inside the grid rather than stacked above it: as full-width bands they
          pushed the checklists and the log a screen and a half down, and the
          page's most actionable content - the build button is already up top,
          but the log and the test picker are not - was furthest from the title.
          Side by side they also read as the pair they are: what this binary IS,
          and what it was built WITH. */}
      <div className="build-grid">
        {inspect && (
          <>
            <ProvenanceCard
              provenance={inspect.provenance}
              freshness={inspect.freshness}
              validation={inspect.validation}
            />
            <ConfigurationCard config={inspect.configuration} />
          </>
        )}

        {/* --- analysis stack ------------------------------------------- */}
        <Card className="build-card">
          <Card.Header className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <Card.Title>Analysis stack</Card.Title>
              <p className="mt-1 text-[11px] text-muted">
                MalAPI, capa, the rule packs, the ML scorer — what the analyzer
                uses at analysis time. A missing one does not stop a build, but
                the phase it belongs to silently produces nothing.
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

        {/* --- build toolchain ------------------------------------------- */}
        <Card className="build-card">
          <Card.Header className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <Card.Title>Build toolchain</Card.Title>
              <p className="mt-1 text-[11px] text-muted">
                Read from <code>CMakeLists.txt</code> — the WIN32 branch where
                both branches declare one. Missing required entries disable the
                build.
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

        {/* --- artefacts ------------------------------------------------ */}
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
      </div>

      {/* --- the log ---------------------------------------------------- */}
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

      {/* The picker sits after the log rather than before it: choosing a test
          and then reading its output is one gesture, and putting the two
          together means the answer is never more than a screen away. */}
      {catalogue && (
        <div className="mt-4">
          <TestPicker
            catalogue={catalogue}
            results={isTestJob ? job?.results ?? [] : []}
            running={running}
            onRun={(ids) => void runTests(ids)}
            busy={runningTests}
          />
        </div>
      )}
    </div>
  )
}