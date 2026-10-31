import { useEffect, useRef, useState } from 'react'
import type {
  AnalysisConfig,
  AnalysisSettingsSnapshot,
  AnalyzerPackedStop,
  ArtifactExportJob,
  ArtifactsSnapshot,
  AnalyzerBuildJob,
  PipelineRunState,
  BuildHardening,
  BuildInspect,
  BuildJob,
  BuildOverview,
  BuildTestCatalogue,
  SampleFactoryCatalog,
  SampleGenerated,
  SampleInspect,
  SampleListing,
  SamplePackedVerdict,
  SamplePreview,
  SampleResourceKind,
  SampleResourcesMutation,
  SampleResourcesSnapshot,
  SampleShapeOptions,
  SampleUploadResult,
  UtilsOverview,
  DepRefresh,
  DynamicAnalysisSnapshot,
  DynamicTransport,
  ClamdResults,
  ClamdResultDocument,
  ClamdStatus,
  ClamdSubmitJob,
  ClamdSubmitStart,
  ComposeFile,
  ContainerList,
  DocsCatalog,
  LogList,
  LogSummary,
  LogTail,
  NetMap,
  Overview,
  PanelConfig,
  PipelineConfig,
  QilingGuestMetrics,
  QilingRootfsJob,
  QilingRuns,
  QilingVmStatus,
  Stats,
  SystemInfo,
  TraceMetrics,
  VmActionResult,
  VmList,
  VmMetrics,
} from './types'

// Every call is same-origin and relative. The dev server proxies /api to the
// Python panel, and in production Flask serves this bundle itself, so there is
// no base URL to configure and no CORS to reason about.
//
// Credentials are sent with `same-origin` so a successful login's session
// cookie is stored and replayed on subsequent calls. Without it the cookie is
// dropped and every poll would bounce on 401.

async function json<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, { credentials: 'same-origin', ...init })
  const body = await res.json().catch(() => ({}))
  if (!res.ok) {
    const detail = body as { error?: string; detail?: string }
    throw new Error(detail.detail ?? detail.error ?? `HTTP ${res.status}`)
  }
  return body as T
}

export interface AuthState {
  required: boolean
  authorised: boolean
  loopback: boolean
}

export const auth = {
  state: () => json<AuthState>('/api/auth/state'),
  login: (token: string) =>
    json<{ ok: boolean }>('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token }),
    }),
  logout: () => json<{ ok: boolean }>('/api/auth/logout', { method: 'POST' }),
}

export const api = {
  overview: () => json<Overview>('/api/overview'),
  config: () => json<PanelConfig>('/api/config'),
  // Pipelines, the phase catalog and the artifact/MEGA upload options - what the
  // analyzer will do, read from the YAML the analyzer itself reads. Static
  // config rather than live state, so it is polled slowly and refreshed by hand.
  analysisConfig: () => json<AnalysisConfig>('/api/analysis/config'),
  system: () => json<SystemInfo>('/api/system'),
  stats: () => json<Stats>('/api/stats'),
  logs: () => json<LogList>('/api/logs'),
  // The id is an opaque server-mangled handle, not a path, so it is safe to
  // interpolate without encoding - but encode anyway; it costs nothing.
  tail: (id: string, lines = 80) =>
    json<LogTail>(`/api/logs/${encodeURIComponent(id)}/tail?lines=${lines}`),
  // Level counts and a per-minute volume histogram over the same bounded
  // window the tail reads, so the header chips and the lines below them can
  // never disagree about what was counted.
  logSummary: (id: string, lines = 2000) =>
    json<LogSummary>(`/api/logs/${encodeURIComponent(id)}/summary?lines=${lines}`),
  // Native analyzer trace metrics. A separate endpoint because a trace is not a
  // log: it has no levels and no timestamps, only ENTER/LEAVE call-graph pairs.
  traceMetrics: (id: string) =>
    json<TraceMetrics>(`/api/trace/${encodeURIComponent(id)}`),
  containers: () => json<ContainerList>('/api/containers'),
  // Topology of the host, its networks, VMs and containers, as a graph.
  netmap: () => json<NetMap>('/api/netmap'),
  // Every endpoint this lab exposes. The panel's own routes are introspected
  // from the live URL map server-side, so this is a reference that cannot drift
  // from the routes actually registered.
  docs: () => json<DocsCatalog>('/api/docs'),
  // ClamAV lives inside the analysis VM. Status and results are read-only
  // views; submission is the one action, and it has two transports: the SFTP
  // driver in python/clamd/ or the operator's TCP socket client in
  // panel/utils/socket_validator.py. It returns a job handle because an SFTP
  // deploy outlives an HTTP request.
  clamdStatus: () => json<ClamdStatus>('/api/clamd/status'),
  clamdResults: () => json<ClamdResults>('/api/clamd/results'),
  /** One result document, unmodified, for the JSON viewer. */
  clamdResult: (name: string) =>
    json<ClamdResultDocument>(`/api/clamd/results/${encodeURIComponent(name)}`),
  /** The scan in progress, or the last one, so a reload reattaches. */
  clamdCurrent: () =>
    json<ClamdSubmitJob | null>('/api/clamd/submit'),
  /** Poll a submission through the same job store as builds and utils. */
  clamdJob: (jobId: string) =>
    json<ClamdSubmitJob>(`/api/build/${encodeURIComponent(jobId)}`),
  /**
   * Upload one sample and start the scan. There is no transport argument: it
   * is read from config/dynamic_analysis.json, so the page cannot submit down
   * a path the Dynamic Analysis page does not record. The refusal payload is
   * returned rather than thrown so the caller can show `code`-specific wording
   * (config-error, transport-unavailable, too-large) instead of a status.
   */
  clamdSubmit: async (file: File):
    Promise<ClamdSubmitStart> => {
    const form = new FormData()
    form.append('file', file)
    const res = await fetch('/api/clamd/submit', {
      method: 'POST', credentials: 'same-origin', body: form,
    })
    return await res.json().catch(
      () => ({ ok: false, error: `HTTP ${res.status}` })) as ClamdSubmitStart
  },
  // The one transport a sample under dynamic analysis may use. Read on page
  // load and after a save, not polled: it is a standing policy, not telemetry.
  dynamicAnalysis: () => json<DynamicAnalysisSnapshot>('/api/dynamic-analysis/config'),
  setDynamicAnalysis: (communication: DynamicTransport) =>
    json<DynamicAnalysisSnapshot>('/api/dynamic-analysis/config', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ communication }),
    }),
  // Qiling emulation runs: summary.json + trace tail read out of each result
  // zip, plus rootfs/harness state. Also read-only.
  qilingRuns: () => json<QilingRuns>('/api/qiling/runs'),
  // VM status: VBoxManage + registration + power + TCP, same checks the
  // admin-terminal Qiling VM Control screen runs.
  qilingStatus: () => json<QilingVmStatus>('/api/qiling/status'),
  // Live CPU / RAM read from inside the running VM over SSH.
  qilingVmMetrics: () => json<QilingGuestMetrics>('/api/qiling/vm'),
  // Rootfs build is a long, interactive job (UAC prompt on the host), so it
  // returns a job handle to poll, not a synchronous result.
  qilingGenerateRootfs: () =>
    json<QilingRootfsJob>('/api/qiling/rootfs', { method: 'POST' }),
  qilingRootfsJob: (jobId: string) =>
    json<QilingRootfsJob & { state: string; complete?: boolean; rootfs?: unknown }>(
      `/api/qiling/rootfs/${encodeURIComponent(jobId)}`),
  // project/service come from the allowlist the backend parses out of the
  // compose files, never from free text - a crafted URL to a 404, not a
  // docker command against an arbitrary container.
  containerAction: (project: string, service: string, action: 'start' | 'stop') =>
    json<{ ok: boolean; detail: string }>(
      `/api/containers/${encodeURIComponent(project)}/${encodeURIComponent(service)}/${action}`,
      { method: 'POST' },
    ),
  // A build runs for minutes and its log is the useful part, so this returns a
// job handle immediately and the UI polls containerBuildJob for output.
containerBuild: (project: string) =>
    json<{ ok: boolean; job_id: string; reused: boolean }>(
      `/api/containers/${encodeURIComponent(project)}/build`,
      { method: 'POST' },
    ),
  containerBuildJob: (jobId: string) =>
    json<BuildJob>(`/api/containers/build/${encodeURIComponent(jobId)}`),
  containerCompose: (project: string) =>
    json<ComposeFile>(
      `/api/containers/${encodeURIComponent(project)}/compose`,
    ),
  // Local evidence bundles, their MEGA copies, and the effective throughput
  // between consecutive uploads. Uploading stays a CLI action; recovery is
  // exposed separately because it downloads and verifies an existing bundle.
  // `refresh` bypasses the server's 5-minute MEGA cache - the Rescan button
  // needs to see an upload that just happened, not one from five minutes ago.
  artifacts: (remoteRoot = '/', refresh = false) =>
    json<ArtifactsSnapshot>(
      `/api/artifacts?remote_root=${encodeURIComponent(remoteRoot)}` +
        (refresh ? '&refresh=1' : ''),
    ),
  artifactArchiveUrl: (name: string) =>
    `/api/artifacts/local/${encodeURIComponent(name)}/archive`,
  recoverArtifact: (name: string, remoteRoot = '/') =>
    json<{ ok: boolean; detail: string }>('/api/artifacts/recover', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, remote_root: remoteRoot }),
    }),
  // The mirror of recover: push a bundle that is on disk up to MEGA. Job-based,
  // because sealing a large bundle and pushing it takes minutes and the log is
  // the useful part. Gated server-side on `upload_artifacts` in
  // config/artifacts.yaml, which is why this can come back 403.
  exportArtifact: (name: string, remoteRoot = '/') =>
    json<{ ok: boolean; job_id: string; reused: boolean }>('/api/artifacts/export', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, remote_root: remoteRoot }),
    }),
  artifactExportJob: (jobId: string) =>
    json<ArtifactExportJob>(`/api/artifacts/export/${encodeURIComponent(jobId)}`),
  // Every registered VirtualBox machine with its address and live services.
  // One showvminfo per machine, so this is heavier than the netmap poll. Guest
  // metrics are already attached per machine from the cached SSH/SFTP
  // collection, so no extra request is needed to draw the gauges.
  vms: () => json<VmList>('/api/vms'),
  // Standalone metrics endpoint, for anything that wants the collector without
  // the whole fleet listing around it.
  vmMetrics: () => json<VmMetrics>('/api/vm-metrics'),
  // The machine name goes in the BODY, not the path. A VirtualBox machine name
  // is free text - it can contain slashes and spaces - so putting it in a URL
  // means encoding problems on the way out and a name that never got quoted on
  // the way in. The backend checks it against the registered list regardless.
  //
  // `headless` is only read for `start`. It is omitted from the body entirely
  // when true, so the default a server-side client would apply is exactly the
  // one being sent - the request for the common case is byte-identical to what
  // it was before this parameter existed.
  vmAction: (name: string, action: 'start' | 'stop', headless = true) =>
    json<VmActionResult>(`/api/vms/${action}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, ...(action === 'start' && !headless ? { headless: false } : {}) }),
    }),

  // --- build: dependencies, artefacts, one build at a time ------------------
  //
  // One call for the overview because both halves answer the same question -
  // "can this be built right now?" - and two calls could render a green
  // toolchain beside a stale binary. startBuild is job-based for the same
  // reason the container build is: a full compile runs for minutes and the log
  // is the part worth watching.
  buildOverview: () => json<BuildOverview>('/api/build'),
  // On demand, because the stack half probes services that can be started
  // after the page is already open - a report computed at load time would keep
  // calling MalAPI down until a manual reload.
  checkBuildDeps: () =>
    json<DepRefresh>('/api/build/check-deps', { method: 'POST' }),
  startBuild: (clean = false) =>
    json<{ ok: boolean; job_id: string; command: string; clean: boolean }>(
      '/api/build', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ clean }),
      }),
  buildJob: (jobId: string) =>
    json<AnalyzerBuildJob>(`/api/build/${encodeURIComponent(jobId)}`),
  // So a reload reattaches to a build that is already going, rather than
  // showing an idle panel while the compiler works.
  currentBuild: () => json<AnalyzerBuildJob | null>('/api/build/current'),

  // --- pipeline runs: watch the analyzer on a chosen sample ------------------
  //
  // One endpoint for the whole feature: the run in progress, or the most
  // recent finished one. Polling while running is the page's job (2s, the
  // build log's cadence); a reload reattaches rather than orphaning.
  pipelineRun: () => json<PipelineRunState | null>('/api/pipeline-run'),
  /**
   * `duration` is a maximum in seconds, or undefined for no limit. Omitted
   * rather than sent as 0: the server reads 0 as "below the 10s floor" and
   * refuses it, which is the right answer for a number nobody meant.
   *
   * `allowPacked` is the explicit packed override - the server refuses a
   * packed sample with `code: "sample-packed"` unless it is exactly true, and
   * says in `detail` what the analyzer's own packed stop will do to an
   * overridden run. A successful overridden start carries a `warning` when
   * that analyzer stop is on.
   */
  startPipelineRun: (pipeline: string, sample: string, duration?: number | null,
                     allowPacked = false) =>
    json<{ ok: boolean; job_id: string; command: string; pipeline: string;
           duration_sec?: number | null; packed?: SamplePackedVerdict | null;
           warning?: string | null; analyzer_packed_stop?: AnalyzerPackedStop;
           code?: string; error?: string; detail?: string }>(
      '/api/pipeline-run', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ pipeline, sample, duration: duration ?? null,
                             allow_packed: allowPacked }),
    }),
  stopPipelineRun: (jobId: string) =>
    json<{ ok: boolean; job_id: string; state: string }>(
      `/api/pipeline-run/${encodeURIComponent(jobId)}/stop`, { method: 'POST' }),
  /**
   * The Run a pipeline picker's choices: executables under the same sample
   * roots the run gate enforces, newest first. Metadata only - inspecting the
   * selected file is a separate call because a packed verdict reads it whole.
   */
  listSamples: () => json<SampleListing>('/api/build/samples'),
  /**
   * Upload an operator's own sample into samples/. Returns the refusal payload
   * instead of throwing so the caller can read `code` and offer the explicit
   * unscanned retry only when the scanner is the thing that refused.
   */
  uploadSample: async (file: File, allowUnscanned = false):
    Promise<SampleUploadResult> => {
    const form = new FormData()
    form.append('file', file)
    if (allowUnscanned) form.append('allow_unscanned', 'true')
    const res = await fetch('/api/build/samples/upload', {
      method: 'POST', credentials: 'same-origin', body: form,
    })
    return await res.json().catch(
      () => ({ ok: false, error: `HTTP ${res.status}` })) as SampleUploadResult
  },
  /**
   * Validate a typed sample path and describe it - same rules the run gate
   * applies server-side, so what this shows is what the gate will enforce:
   * size, mtime, the packed verdict, and the analyzer's own packed-stop state.
   */
  inspectSample: (path: string) =>
    json<SampleInspect>('/api/build/samples/inspect', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ path }),
    }),

  // --- sample factory: compose a bait sample and compile it ------------------
  //
  // Templates, the checkbox vocabulary and the compiler state, so the Build
  // page can render the offer without inventing any of it.
  sampleTemplates: () =>
    json<SampleFactoryCatalog>('/api/build/sample/templates'),
  // The composed source text plus the noise pair it will carry. The preview
  // and the artefact agree because the pair is drawn here, not at generate.
  samplePreview: (language: string, template: string, features: string[],
                  encoding: string, sleepSeconds: number,
                  shape: SampleShapeOptions, seed?: number) =>
    json<SamplePreview>('/api/build/sample/preview', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ language, template, features, encoding,
                             sleep_seconds: sleepSeconds, ...shape, seed }),
    }),
  generateSample: (language: string, template: string, features: string[],
                   options: {
                     name?: string
                     encoding: string
                     sleepSeconds: number
                     upx: boolean
                     virtualize: boolean
                     makefile: boolean
                     seed: number
                     shape: SampleShapeOptions
                   }) =>
    json<SampleGenerated>('/api/build/sample', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        language, template, features,
        name: options.name,
        encoding: options.encoding,
        sleep_seconds: options.sleepSeconds,
        upx: options.upx,
        virtualize: options.virtualize,
        makefile: options.makefile,
        seed: options.seed,
        ...options.shape,
      }),
    }),

  // Operator maintenance for the vendored stack: SBOM, the MalAPI rule
  // checkout, the YARA packs and yarGen-Go. One call for all four so the four
  // cards cannot describe four different moments.
  utilsOverview: () => json<UtilsOverview>('/api/utils'),
  // `options` carries per-utility switches: { ignore_compile_failures } for
  // the YARA check. The backend persists what it is given, so a reload of the
  // page shows the checkbox as the last run left it - a toggle that resets
  // itself teaches you to re-check nothing, which is worse than no toggle.
  runUtils: (ids: string[], options?: Record<string, unknown>) =>
    json<{ ok: boolean; job_id?: string; running?: string[]; error?: string }>(
      '/api/utils', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ids, options: options ?? {} }),
    }),

  // The YARA card's checkbox. A dedicated endpoint rather than reusing a run:
  // the compile check is ~60s and a toggle that forces a minute of
  // compilation each flip would be switched off and stay off.
  setYaraOptions: (options: { ignore_compile_failures: boolean }) =>
    json<{ ok: boolean; ignore_compile_failures?: boolean; error?: string }>(
      '/api/utils/yara-check', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(options),
    }),

  // --- generator resources: value pools the sample factory draws from -------
  //
  // Definitions live in config/sample_resources.json, fetched values in the
  // panel cache. Every mutating call returns the fresh snapshot, so the page's
  // pools cannot disagree with the file for even one render.
  sampleResources: () => json<SampleResourcesSnapshot>('/api/utils/resources'),
  addSampleResource: (body: {
    label: string
    kind: SampleResourceKind
    url: string
    enabled?: boolean
    note?: string
    fetch?: boolean
  }) => json<SampleResourcesMutation>('/api/utils/resources', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  }),
  updateSampleResource: (id: string, body: {
    label?: string
    kind?: SampleResourceKind
    url?: string
    enabled?: boolean
    note?: string
  }) => json<SampleResourcesMutation>(
    `/api/utils/resources/${encodeURIComponent(id)}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    }),
  deleteSampleResource: (id: string) => json<SampleResourcesMutation>(
    `/api/utils/resources/${encodeURIComponent(id)}`, { method: 'DELETE' }),
  // A failed fetch returns ok:false with the snapshot (HTTP 200): the page
  // needs the error AND the last good values, not just the error.
  refreshSampleResource: (id: string) => json<SampleResourcesMutation>(
    `/api/utils/resources/${encodeURIComponent(id)}/refresh`,
    { method: 'POST' }),

  // Provenance, freshness, validation and build configuration. One call,
  // because the three together are one verdict - "can I trust this binary?" -
  // and a page that fetched them separately could render a green check beside a
  // stale commit.
  buildInspect: () => json<BuildInspect>('/api/build/inspect'),

  // The hardening settings (config/hardening.json) and what the finished
  // binary actually carries. One call for the same reason as buildInspect:
  // the card answers "do the settings and the binary agree?", and two calls
  // could render the requested settings beside a binary built before them.
  buildHardening: () => json<BuildHardening>('/api/build/hardening'),
  // A partial write: only the keys in the patch move, and the response is the
  // same payload as the GET, so the card re-renders from what is on disk
  // rather than from what was asked for.
  setBuildHardening: (patch: Record<string, boolean>) =>
    json<BuildHardening>('/api/build/hardening', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(patch),
    }),

  // The test catalogue, and the runner. Selection is explicit because the
  // entries are not equivalent: some write files, one runs the analyzer end to
  // end, and a single "Run tests" button cannot say which it is about to do.
  buildTests: () => json<BuildTestCatalogue>('/api/build/tests'),
  startBuildTests: (ids: string[]) =>
    json<{ ok: boolean; job_id?: string; running?: string[]; error?: string }>(
      '/api/build/tests', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ids }),
    }),

  // --- writing the analysis configuration -----------------------------------
  //
  // The only mutating calls in this client. Each one sends a fixed set of keys
  // the analyzer understands and nothing else - no arbitrary YAML crosses the
  // wire - and each is validated server-side with the rules the analyzer itself
  // enforces, so a bad edit is refused rather than left to fail at startup.
  // config/analysis.yaml - the settings that apply to every run. A null value
  // removes the key, which is how a setting goes back to following the
  // selected pipeline; that is a different outcome from writing false.
  analysisSettings: () => json<AnalysisSettingsSnapshot>('/api/analysis/settings'),
  setAnalysisSettings: (patch: Record<string, unknown>) =>
    json<{ ok: boolean; settings: AnalysisSettingsSnapshot }>('/api/analysis/settings', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(patch),
    }),
  setArtifactOptions: (options: {
    store_artifact?: boolean
    upload_artifacts?: boolean
    remote_root?: string
    timeout_seconds?: number
  }) =>
    json<{ ok: boolean; artifacts: AnalysisConfig['artifacts'] }>(
      '/api/analysis/artifact-options',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(options),
      },
    ),
  // --- the bundle-password resource -------------------------------------------
  //
  // The password never crosses these routes in a config write; the state
  // routes carry only presence and path, and the ONE response that contains
  // the value is a generate. Everything hangs off the operator password file
  // outside the repo, which upload.py reads by path at protection time.
  bundlePassword: () =>
    json<{ ok: boolean; present: boolean; path: string; error?: string | null }>(
      '/api/artifacts/bundle-password',
    ),
  setBundlePassword: (password: string) =>
    json<{ ok: boolean; present: boolean; path: string }>(
      '/api/artifacts/bundle-password',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password }),
      },
    ),
  /** The generated value is returned exactly once; the page shows it with a
   *  copy button and nothing ever echoes it again afterwards. */
  generateBundlePassword: (length?: number) =>
    json<{ ok: boolean; password: string; shown_once: boolean; present: boolean; path: string }>(
      '/api/artifacts/bundle-password/generate',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(length ? { length } : {}),
      },
    ),
  clearBundlePassword: () =>
    json<{ ok: boolean; present: boolean; path: string }>(
      '/api/artifacts/bundle-password',
      { method: 'DELETE' },
    ),
  /** A `null` value clears the key from the block, whatever the option kind. */
  setPipelineEnvironment: (pipeline: string, environment: Record<string, boolean | number | string | null>) =>
    json<{ ok: boolean; pipeline: PipelineConfig }>('/api/analysis/pipeline/environment', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ pipeline, environment }),
    }),

  // The writable form of the yarGen decision. Edits the inline
  // `phases: [...]` list, inserting before `export` so the
  // generated rule file is part of the artifact set rather than written after it.
  setYaraGen: (pipeline: string, enabled: boolean) =>
    json<{ ok: boolean; pipeline?: PipelineConfig; error?: string }>(
      '/api/analysis/pipeline/yara-gen', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ pipeline, enabled }),
    }),

  savePipeline: (name: string, content: string) =>
    json<{ ok: boolean; pipeline: PipelineConfig }>('/api/analysis/pipeline', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, content }),
    }),
}

// Poll a probe-returning endpoint, skipping ticks while the tab is hidden so a
// backgrounded tab is not holding six connection timeouts open every interval.
export function usePoll<T>(
  fn: () => Promise<T>,
  intervalMs: number,
): { data: T | null; error: string | null; loading: boolean; refresh: () => void } {
  const [data, setData] = useState<T | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [tick, setTick] = useState(0)

  // `fn` is held in a ref rather than listed as an effect dependency, and that
  // is the whole point of this hook.
  //
  // Listing it was a live bug: any caller passing an inline arrow - including
  // one that needs an argument, like this page's ?refresh=1 - produced a new
  // function identity on every render. The effect depends on it, so the effect
  // re-ran, which set state, which re-rendered, which made a new `fn` again.
  // The result was not "polling every intervalMs" but polling in a tight loop
  // as fast as the endpoint would answer, which looked exactly like values
  // updating far too fast. The interval was never being respected.
  //
  // A ref makes the call site free to be whatever reads best without changing
  // when this hook fetches. The latest closure is always the one called.
  const fnRef = useRef(fn)
  fnRef.current = fn

  useEffect(() => {
    let cancelled = false
    const run = async () => {
      try {
        const next = await fnRef.current()
        if (!cancelled) {
          setData(next)
          setError(null)
        }
      } catch (e) {
        if (!cancelled) setError(e instanceof Error ? e.message : String(e))
      } finally {
        if (!cancelled) setLoading(false)
      }
    }
    void run()
    const id = window.setInterval(() => {
      if (document.visibilityState === 'visible') void run()
    }, intervalMs)
    return () => {
      cancelled = true
      window.clearInterval(id)
    }
    // `tick` is the manual-refresh lever.
  }, [intervalMs, tick])

  return { data, error, loading, refresh: () => setTick((t) => t + 1) }
}