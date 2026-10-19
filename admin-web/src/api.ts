import { useEffect, useRef, useState } from 'react'
import type {
  AnalysisConfig,
  ArtifactExportJob,
  ArtifactsSnapshot,
  AnalyzerBuildJob,
  BuildInspect,
  BuildJob,
  BuildOverview,
  BuildTestCatalogue,
  UtilsOverview,
  DepRefresh,
  ClamdResults,
  ClamdStatus,
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
  // ClamAV lives inside the analysis VM, so these are read-only views of the
  // result JSONs and the local connection-test checks - nothing here starts a
  // scan or SSHes anywhere. Triggering a run is a subprocess with real side
  // effects (upload + freshclam + scan), so it stays a CLI action.
  clamdStatus: () => json<ClamdStatus>('/api/clamd/status'),
  clamdResults: () => json<ClamdResults>('/api/clamd/results'),
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

  // Operator maintenance for the vendored stack: SBOM, the MalAPI rule
  // checkout, the YARA packs and yarGen-Go. One call for all four so the four
  // cards cannot describe four different moments.
  utilsOverview: () => json<UtilsOverview>('/api/utils'),
  runUtils: (ids: string[]) =>
    json<{ ok: boolean; job_id?: string; running?: string[]; error?: string }>(
      '/api/utils', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ids }),
    }),

  // Provenance, freshness, validation and build configuration. One call,
  // because the three together are one verdict - "can I trust this binary?" -
  // and a page that fetched them separately could render a green check beside a
  // stale commit.
  buildInspect: () => json<BuildInspect>('/api/build/inspect'),

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
  setPipelineEnvironment: (pipeline: string, environment: Record<string, boolean | number | string>) =>
    json<{ ok: boolean; pipeline: PipelineConfig }>('/api/analysis/pipeline/environment', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ pipeline, environment }),
    }),
  setPipelineRush: (pipeline: string, enabled: boolean) =>
    json<{ ok: boolean; pipeline?: PipelineConfig; error?: string }>(
      '/api/analysis/pipeline/rush', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ pipeline, enabled }),
    }),

  // The writable form of the yarGen decision. Edits the same inline
  // `phases: [...]` list as the rush toggle, inserting before `export` so the
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