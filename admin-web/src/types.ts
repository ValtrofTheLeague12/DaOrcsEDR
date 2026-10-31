// Shapes returned by the panel API. Kept hand-written and small rather than
// generated: the panel is the only producer, so a codegen step would add a
// moving part for no benefit.

export interface Probe {
  key: string
  name: string
  endpoint: string
  up: boolean
  code: string
  note: string
  ms: number
  kind: 'http' | 'tcp'
  detail: Record<string, unknown>
  // --- static facts, merged in by the backend --------------------------
  /** What the service is for, in one or two sentences. */
  description: string
  host: string
  port: number
  scheme: string
  /** Groups the cards: 'analysis' | 'pipeline' | 'access' | 'core'. */
  role: string
  /** A page a human can open, when the service publishes one. */
  ui_url: string | null
  /** True when the probe needed a bearer token (the ML scorer does). */
  auth: boolean
  /**
   * Secondary GET routes probed alongside the health check, as path -> status.
   * Empty unless the service was up to begin with - no point re-dialling a host
   * that already refused. Present because a green /health says nothing about
   * whether /capabilities still resolves.
   */
  routes: Record<string, number>
  /** Per-service latency history; ms is null where the service was down. */
  trend: { samples: number; ms: (number | null)[] }
  /** Routing facts for host:port - interface, CIDR, class, port band. */
  net: NetFacts
}

export interface Overview {
  services: Probe[]
  up: number
  total: number
  endpoints: Record<string, string>
  ml_auth: boolean
  /** Distinct role keys present, for grouping the cards. */
  roles: string[]
}

export interface PanelConfig {
  repo: string
  panel: { host: string; port: number }
  analyzer: string
  ml: string
  malapi: string
  ml_auth: boolean
  compose_projects: { label: string; services: string[] }[]
}

export type ServiceState = 'up' | 'down' | 'unknown'

// --- machine -------------------------------------------------------------

/**
 * One display adapter. Inventory fields come from CIM (`Win32_VideoController`);
 * live metrics come from nvidia-smi and are present only on NVIDIA cards, which
 * is what `live` distinguishes.
 */
export interface GpuAdapter {
  name: string
  vendor: string | null
  driver_version: string | null
  /** Active display mode, e.g. "1920 x 1080 x ... couleurs". Often null on dGPU. */
  mode: string | null
  status: string | null
  /** Dedicated VRAM. From nvidia-smi when `live`, else a WMI approximation. */
  vram_bytes: number | null
  /**
   * 'nvidia-smi' = authoritative.
   * 'wmi-adapterram-approx' = AdapterRAM, which is a uint32 that clamps at 4 GB
   * and reports SHARED memory for an iGPU. Treat as a hint, not a figure.
   */
  vram_source: 'nvidia-smi' | 'wmi-adapterram-approx'
  /** True when nvidia-smi answered; the metric fields are null otherwise. */
  live: boolean
  utilization_percent: number | null
  memory_utilization_percent: number | null
  memory_used_bytes: number | null
  memory_total_bytes: number | null
  memory_percent: number | null
  temperature_c: number | null
  power_draw_w: number | null
  power_limit_w: number | null
  clock_mhz: number | null
}

export interface GpuInfo {
  available: boolean
  adapters: GpuAdapter[]
  count: number
  live_count: number
  note: string
}

export interface SystemInfo {
  host: {
    name: string
    system: string
    release: string
    version: string
    machine: string
    processor: string | null
  }
  runtime: { python: string; executable: string; panel_uptime_seconds: number }
  cpu: { logical_cores: number | null; load_percent: number | null }
  memory: {
    load_percent: number | null
    total_bytes: number | null
    available_bytes: number | null
    used_bytes: number | null
  }
  gpu: GpuInfo
  uptime_seconds: number | null
  /**
   * Fixed volumes, one row per physical drive - never one row per arbitrary
   * path. `device` is the drive letter ("C:") that people actually recognise;
   * `path` is the same thing plus a separator, kept so older call sites work.
   * `name`/`filesystem` may be null (unlabelled volume, or the CIM fallback).
   */
  disks: {
    device: string | null
    path: string
    name: string | null
    filesystem: string | null
    total_bytes: number
    used_bytes: number
    free_bytes: number
    used_percent: number | null
  }[]
  panel: { repo: string; env_file_exists: boolean; compose_projects: number }
  history: {
    samples: number
    window_seconds: number
    cpu: (number | null)[]
    memory: (number | null)[]
    /** Highest live-adapter utilisation per sample; null when none answered. */
    gpu: (number | null)[]
  }
  top_processes: {
    available: boolean
    cores: number
    sample_seconds: number
    processes: { name: string; pid: number; mem_bytes: number; mem_percent: number | null; cpu_percent: number | null }[]
    note: string
  }
}

// --- logs ----------------------------------------------------------------

export interface LogFile {
  id: string
  group: string
  name: string
  /**
   * Coarse file type from the server. `trace` is pulled out of the Logs panel
   * into its own tab: trace.txt is ~80 MB of native call-graph records, and
   * dropping it into a generic log viewer is how you get an unreadable page.
   */
  kind: 'log' | 'jsonl' | 'trace' | 'other'
  bytes: number
  modified: number
  age_seconds: number
}

export interface LogGroup {
  key: string
  label: string
  path: string
  present: boolean
  files: LogFile[]
}

export interface LogList {
  groups: LogGroup[]
  file_count: number
  total_bytes: number
  note: string
}

export interface LogTail {
  id?: string
  name?: string
  path?: string
  bytes?: number
  lines?: string[]
  returned?: number
  truncated?: boolean
  empty?: boolean
  error?: string
  // How many SGR escape sequences the server removed before sending. Reported
  // so the viewer can say so rather than silently dropping data.
  ansi_stripped?: number
  // True for .jsonl and .json logs, which get structured rendering.
  jsonl?: boolean
  /** Per-minute line counts over the same window, for the volume chart. */
  timeline?: { minute: string; count: number }[]
}

/** Level counts and volume breakdown over a bounded backward read. */
export interface LogSummary {
  id?: string
  name?: string
  error?: string
  total: number
  sampled_lines: number
  truncated: boolean
  bytes?: number
  levels: Record<string, number>
  timeline: { minute: string; count: number }[]
  sources: { name: string; count: number }[]
  tones: Record<string, string>
}

/**
 * Aggregates over a native analyzer trace.
 *
 * Not a log summary and not interchangeable with one: these files have no
 * levels and no wall-clock timestamps. What is there is a call graph - ENTER /
 * LEAVE pairs, nesting depth, and a duration on every return.
 */
export interface TraceMetrics {
  available: boolean
  name: string | null
  bytes: number
  /** Trace records parsed out of the read window. */
  events: number
  /** Lines that looked like records but did not match. Usually binary bleed. */
  malformed: number
  channels: { name: string; count: number }[]
  depth: { max: number; current: number }
  span: { first_ms: number | null; last_ms: number | null; duration_ms: number | null }
  kinds: Record<string, number>
  duration_ms: {
    count: number
    total: number
    avg: number | null
    p50: number | null
    p95: number | null
    max: number | null
  }
  slowest: { signature: string; depth: number; duration_ms: number }[]
  symbols: { name: string; count: number }[]
  memory: {
    process_id: string | null
    fields: Record<string, { bytes?: number; count?: number; percent?: number; raw: string }>
  } | Record<string, never>
  analyzed_at: number
  /** True when the read window did not reach the start of the file. */
  clipped: boolean
  error: string | null
}

// --- containers -----------------------------------------------------------

export type ContainerState =
  | 'running' | 'exited' | 'created' | 'paused' | 'restarting' | 'missing'

export interface Container {
  project: string // compose project label, e.g. "ia" or "kafka-agent"
  name: string // compose service name
  container_name: string | null // actual docker name, e.g. "iaproject-guacamole-1"
  id: string | null // short container id
  image: string | null
  state: ContainerState
  status: string // docker's own status string, e.g. "Up 2 hours"
  health: 'healthy' | 'unhealthy' | 'starting' | 'none'
  ports: string[]
  // Where a person opens this service. Joined from the panel's own service specs
  // (panel/services.py) on the published host port, so it is the URL that answers
  // rather than a URL derived from the image name. Null for a container the
  // panel has no spec for - a one-off `podman run`, say - and null is rendered
  // as absent rather than guessed at.
  endpoint: {
    key: string
    service: string
    /** http(s) URL, or tcp://host:port for a broker. */
    url: string
    kind: 'http' | 'tcp'
    /** A page a human can actually open, when the service publishes one. */
    ui_url: string | null
  } | null
  compose_file: string
  created: string | null
  running_for: string | null
  networks: string | null
  // --- live resource usage from `docker stats --no-stream` (null when the
  // container is not running, which is exactly when stats has no row) ---
  cpu_percent: number | null // host-normalised: 100 = one core
  mem_percent: number | null
  mem_used_bytes: number | null
  mem_limit_bytes: number | null
  net_rx_bytes: number | null
  net_tx_bytes: number | null
  block_read_bytes: number | null
  block_write_bytes: number | null
  pids: number | null
  size_rw_bytes: number | null
  size_virtual_bytes: number | null
  // False for one-off / external containers: the backend allowlist cannot map
  // them to a compose service, so the start/stop buttons stay disabled.
  controllable: boolean
}

export interface EngineStats {
  version: string | null
  os: string | null
  kernel: string | null
  arch: string | null
  ostype: string | null
  docker_root: string | null
  cpus: number | null
  memory_total_bytes: number | null
  containers_total: number | null
  containers_running: number | null
  containers_paused: number | null
  containers_stopped: number | null
  images: number | null
  // --- summed over running compose containers (docker stats --no-stream) ---
  cpu_percent: number | null
  memory_used_bytes: number | null
  memory_percent: number | null
  net_rx_bytes: number | null
  net_tx_bytes: number | null
  block_read_bytes: number | null
  block_write_bytes: number | null
  pids: number | null
  stats_containers: number
  stats_partial: boolean
}

export interface StorageSection {
  total: string | null
  active: string | null
  size: string | null
  size_bytes: number | null
  reclaimable: string | null
  reclaimable_bytes: number | null
}

export interface ContainerList {
  daemon: {
    available: boolean
    running: boolean
    version: string | null
    error: string | null
  }
  // Docker Desktop overall: host topology (cpus, RAM) plus summed usage.
  engine: EngineStats | null
  // `docker system df`: images / containers / volumes / build cache.
  storage: {
    images: StorageSection | null
    containers: StorageSection | null
    local_volumes: StorageSection | null
    build_cache: StorageSection | null
  } | null
  compose_files?: { label: string; file: string }[]
  projects: { label: string; compose_file: string; containers: Container[] }[]
  stats_available: boolean
  stats_containers: number
  updated_at: number | null
  // Per-container trend history, sampled once per snapshot build (same idea as
  // Stats.history): { "<project>/<name>": { cpu: [...], mem: [...] } } with
  // nulls where the container was not running. Resets on panel restart.
  history: {
    samples: number
    window_seconds: number
    series: Record<string, { cpu: (number | null)[]; mem: (number | null)[] }>
  } | null
}

// --- image builds ---------------------------------------------------------

/** One `docker compose build` running on the panel, polled for its log. */
export interface BuildJob {
  job_id: string
  project: string
  /** 'running' until the process exits, then 'done' or 'error'. */
  state: 'running' | 'done' | 'error'
  /** The whole log so far; it grows with every poll. */
  lines: string[]
  /**
   * Lines the server dropped to stay bounded. Non-zero means the log shown is
   * a tail, not the whole thing - the end of a build log is the part that
   * explains a failure, so that is what is kept.
   */
  dropped: number
  exit_code: number | null
  elapsed: number
}

/**
 * One `mega/upload.py` run started from the Remote artifacts tab.
 *
 * Same shape as a build job because it is the same idea: a process the panel
 * started that the page polls for its log. Sharing the shape is what lets both
 * use the one job modal.
 */
export interface ArtifactExportJob {
  job_id: string
  name: string
  /** MEGA path the bundle was pushed under. */
  remote_root: string
  state: 'running' | 'done' | 'error'
  lines: string[]
  dropped: number
  exit_code: number | null
  elapsed: number
}

// --- clamav (guest on the Qiling VM) --------------------------------------

/** How a run of characters in the raw YAML should be painted. */
export type YamlKind =
  | 'key' | 'string' | 'number' | 'bool' | 'null' | 'comment' | 'punct'

/**
 * A service exactly as PyYAML parsed it.
 *
 * `config` is deliberately not a fixed set of named fields. An allowlist drops
 * whatever it does not name (profiles, cap_add, sysctls, ulimits, extra_hosts),
 * so the viewer would quietly under-report the file it claims to be showing.
 */
export interface ComposeService {
  name: string
  config: Record<string, unknown>
}

export interface ComposeFile {
  label: string
  file: string
  /** The file text, exactly as on disk. */
  content: string
  services: ComposeService[]
  /**
   * `[start, length, kind]` over `content`, taken from PyYAML's node marks and
   * sorted, non-overlapping. The client paints these; it never parses YAML.
   */
  spans: [number, number, YamlKind][]
}

// --- analysis configuration ------------------------------------------------

/**
 * One named pipeline from `pipelines/*.yaml`.
 *
 * `phases` is what the file declares; `resolved` is the order the analyzer will
 * actually run, after prerequisites and the always-appended epilogue. Keeping
 * both is the point of the page - a hand-written config lists the phases the
 * operator picked, not the ones the planner inserts.
 */
export interface PipelineConfig {
  name: string
  description: string
  /** Repo-relative path of the YAML file. */
  file: string
  /** 'repo' for a file in pipelines/, 'shadowed' when a later file reuses the name. */
  source: string
  /** False when the analyzer would refuse this file. `error` says why. */
  ok: boolean
  error: string
  stages: { name: string; phases: string[] }[]
  /** Declared phases, deduplicated, in declared order. */
  phases: string[]
  /**
   * The `environment:` block as written in the file.
   *
   * `shadowed` marks a key that config/analysis.yaml also sets - the analyzer
   * applies the global file after this one, so the line does not happen.
   * `irrelevant` marks a key whose affected phase is not in this pipeline's
   * plan - the line is read and used by nothing. Both are rendered as
   * annotations on the value rather than as editable state that would lie.
   */
  environment: { key: string; value: string; secret: boolean; shadowed: boolean; irrelevant?: boolean }[]
  /**
   * The options as they apply to THIS pipeline: phase-scoped ones only where
   * the plan contains the phase, run-wide ones everywhere. Absent when the
   * phase catalog was unavailable, in which case the page falls back to the
   * unfiltered list rather than filtering on a guess.
   */
  options?: EnvOption[]
  /** Declared + inserted prerequisites + the epilogue: the real run order. */
  resolved: string[]
  /** Phases in `resolved` that are not in `phases`. */
  inserted: string[]
  /** Phase names not in the analyzer's catalog. Non-empty means exit 2. */
  unknown_phases: string[]
  /** 'ok' | 'unknown' | 'unavailable' - whether the catalog could be consulted. */
  phase_check: string
  /** File mtime (unix seconds). When the config itself last changed. */
  mtime: number
  content: string
  spans: [number, number, YamlKind][]
}

/**
 * One `environment:` option the analyzer actually reads.
 *
 * `honoured_by` is a file and line in the analyzer, and it is rendered next to
 * the control on purpose: the panel is making a claim on the operator's behalf,
 * and the claim should be checkable rather than trusted. An option with no
 * reader is not offered.
 */
export interface EnvOption {
  key: string
  label: string
  kind: 'flag' | 'number' | 'text'
  detail: string
  honoured_by: string
  /** Phases this option changes the behaviour of, for the same reason. A
   *  phase-scoped option is machine-wide and lives on Analysis Configuration,
   *  so per-pipeline listings carry the run-wide options only. */
  affects: string[]
  /** flag: whether it is on when the file says nothing. */
  default?: boolean
  /** number: bounds, inclusive. */
  min?: number
  max?: number
}

export interface PhaseInfo {
  name: string
  description: string
  /** Where this phase's output lands; "" when it only prints to the console. */
  artifact: string
  /** Local service it needs; "" when it needs none. */
  service: string
  /** Phases the planner inserts before this one if the config omits them. */
  requires: string[]
}

export interface AnalysisConfig {
  pipelines_dir: string
  pipelines_present: boolean
  pipelines: PipelineConfig[]
  pipeline_count: number
  /** Names of pipelines the analyzer would reject. */
  broken: string[]
  phases: {
    /** False when the analyzer is down and the catalog could not be read. */
    available: boolean
    source: string
    error: string
    items: PhaseInfo[]
    count: number
    /** Always run, not selectable. */
    always_on: string[]
    /** Appended to any config that omits them. */
    epilogue: string[]
  }
  artifacts: {
    present: boolean
    file: string
    store_artifact: boolean
    upload_artifacts: boolean
    remote_root: string
    timeout_seconds: number
    /** Wrap the archive in a password-protected zip before upload. */
    encrypt_artifacts: boolean
    /** Per MEGA-owned option, the file that decided: config/analysis.yaml's
     *  MEGA_* wins over config/artifacts.yaml, mirroring the analyzer. */
    decided_by?: Record<string, string>
    /** MEGA_* settings whose values do not fit their option; the file's value
     *  stands, the same choice the analyzer logs at startup. */
    mega_warnings?: string[]
    /** Anything the analyzer's own loader would reject. */
    errors: string[]
    /** Repo-relative path of mega/upload.py, the MEGA uploader. */
    uploader_script: string
    /** File mtime (unix seconds). */
    mtime: number
    content: string
    spans: [number, number, YamlKind][]
  }
  /** Convenience mirror of artifacts.upload_artifacts: the one option with an
   *  effect outside this host. */
  mega_upload: boolean
  mega_encrypt: boolean
  /** The operator password file's STATE, never its value: the zip protection
   *  reads it from outside the repo, and no payload echoes the password back
   *  except the one response to a generate. */
  bundle_password: { present: boolean; path: string; error?: string | null }
  /** Writable `environment:` options, with the code that reads each one. */
  options: EnvOption[]
  /**
   * What config/analysis.yaml currently defines, as {key: value}.
   *
   * These are off limits to this page: the analyzer applies the global file
   * after the pipeline's `environment:` block, so a pipeline line for one of
   * them does not happen. The option is rendered read-only and pointed at
   * Analysis Configuration rather than hidden, because the key IS on the other
   * page and an operator told "not here" learns where to look.
   */
  global_settings: Record<string, string>
  /** Newest mtime across everything this page reads, unix seconds. The one
   *  label that answers "is what I am looking at current?" honestly - a
   *  `checked_at` on a polled page only ever describes the poll. */
  newest_edit: number
  /** When this payload was assembled, unix seconds. */
  checked_at: number
}

export type DynamicTransport = 'tcp' | 'sftp'

export interface DynamicAnalysisOption {
  id: DynamicTransport
  label: string
  summary: string
  detail: string
  selected: boolean
}

export interface DynamicAnalysisSnapshot {
  path: string
  exists: boolean
  /** last write, unix seconds; null when the file has never been written */
  modified: number | null
  options: DynamicAnalysisOption[]
  settings: { communication: DynamicTransport }
  default: DynamicTransport
  error: string | null
}

export interface ClamdResultFile {
  file: string
  bytes: number
  modified: number
  verdict: 'infected' | 'clean' | 'failed'
  signature: string
  filename: string
  sha256: string
  clamd_version: string
  endpoint: string
  seconds: number | null
  detail: string
}

export interface ClamdCheck {
  name: string
  ok: boolean
  detail: string
  /** Informational checks never fail the test - matching the shell script. */
  advisory: boolean
  /**
   * What the step does, in a sentence. The transcript prints it before the
   * result, the way a shell script echoes each step it is about to run.
   */
  echo?: string
  /**
   * Which glyph the page draws for this kind of step: a driver file, an
   * imported module, an address, a socket. Unknown values fall back to a tick.
   */
  icon?: string
}

/**
 * The transport recorded in config/dynamic_analysis.json - the file the
 * Dynamic Analysis > Configuration page writes. `error` is set when that file
 * could not be read, which makes the choice unknowable rather than defaulting
 * to something the operator did not pick.
 */
export interface ClamdCommunication {
  mode: 'sftp' | 'tcp'
  path: string
  error: string | null
}

export interface ClamdStatus {
  /** Whether the selected transport can run right now. */
  ready?: boolean
  /** A daemon answered (TCP PING). False for SFTP: not probed here. */
  reachable: boolean
  mode: string
  endpoint: string
  version: string
  vm: { ip: string; host: string; port: number }
  checks: ClamdCheck[]
  /** When the checks last ran (epoch seconds). */
  checked_at?: number
  /**
   * The connection test's output as text - the same rows as `checks` plus the
   * socket client's own narration. One source, so the panel and the log cannot
   * disagree about what was tested.
   */
  output?: string[]
  ok: boolean
  note: string
  communication?: ClamdCommunication
  /** How a sample can reach a scanner from this host, and whether it can now. */
  transports?: Record<'sftp' | 'tcp', ClamdTransport>
  default_transport?: 'sftp' | 'tcp' | null
  error?: string
}

/** One way to move a sample to clamd, with the reason it cannot be used. */
export interface ClamdTransport {
  id: string
  available: boolean
  reason: string | null
  /** The script or client that does the work, shown so it is never a black box. */
  path: string
  /** Every file the transport needs, so a missing one is visible by name. */
  files?: string[]
  detail: string
}

/** One result file as the scanner wrote it, for the viewer. */
export interface ClamdResultDocument {
  /** Bare file name under python/clamd/results/. */
  name: string
  bytes: number
  /** last write, unix seconds */
  modified: number
  /** The file's text unchanged. Empty for a zero-byte interrupted download. */
  raw: string
}

/** The job handle a submission returns, and the row it fills in when done. */
export interface ClamdSubmitStart {
  ok: boolean
  job_id?: string
  mode?: 'sftp' | 'tcp'
  filename?: string
  bytes?: number
  sha256?: string
  code?: string
  error?: string
  limit_bytes?: number
}

export interface ClamdScanRow {
  id: string
  label: string
  state: 'pending' | 'running' | 'passed' | 'failed'
  detail: string | null
  duration: number | null
  verdict?: 'clean' | 'infected' | null
  signature?: string | null
  sha256?: string
  bytes?: number
  result_file?: string | null
}

/** A ClamAV submission polled through the shared job endpoint. */
export interface ClamdSubmitJob extends Omit<AnalyzerBuildJob, 'results' | 'kind'> {
  kind?: 'clamd'
  mode?: 'sftp' | 'tcp'
  results?: ClamdScanRow[]
}


export interface ClamdResults {
  present: boolean
  path: string
  file_count: number
  total_bytes: number
  counts: Record<'infected' | 'clean' | 'failed', number>
  files: ClamdResultFile[]
  checked_at: number
  error?: string
}

// --- qiling ---------------------------------------------------------------

export interface QilingRun {
  file: string
  stem: string
  bytes: number
  modified: number
  ok: boolean
  detail: string
  sample: string
  arch: string
  elapsed_s: number | null
  end: string
  events: number
  api_calls: number
  api_counts: Record<string, number>
  behaviour_tags: Record<string, number>
  attack_hints: Record<string, string>
  ioc_count: number
  iocs: string[]
  iocs_truncated: boolean
  yara_hits: unknown[]
  dump_count: number
  hashes: Record<string, string>
  files: { path: string; bytes: number }[]
  trace_tail: string[]
}

export interface QilingRuns {
  present: boolean
  path: string
  file_count: number
  runs: QilingRun[]
  rootfs: {
    archive_present: boolean
    archive_bytes: number
    complete: boolean
    trees: { arch: string; files: number; complete: boolean }[]
  }
  harness: {
    present: boolean
    path: string
    version: string
    service: string
    service_type: string
  }
  service_log: { present: boolean; bytes: number; tail: string[] }
  vm: { name: string; ip: string; port: number }
  checked_at: number
  error?: string
}

// --- qiling VM status / guest metrics / rootfs job -------------------------

export interface QilingVmCheck {
  name: string
  ok: boolean
  detail: string
}

export interface QilingVmStatus {
  checked_at: number
  available: boolean
  checks: QilingVmCheck[]
  ok: boolean
  vm_name: string
  vm_ip: string
  running: boolean
  error?: string
}

export interface QilingGuestMetrics {
  available: boolean
  reachable: boolean
  cores: number | null
  load: { '1': number | null; '5': number | null; '15': number | null }
  memory: {
    total_bytes: number | null
    used_bytes: number | null
    available_bytes: number | null
    percent: number | null
    swap_total_bytes: number | null
    swap_used_bytes: number | null
  }
  disk: { total_bytes: number | null; used_bytes: number | null; free_bytes: number | null; percent: number | null }
  uptime_seconds: number | null
  /** When vmmetrics' background collector sampled the guest, unix seconds. */
  collected_at?: number | null
  /** Seconds since that sample - the card is served from cache. */
  age_seconds?: number | null
  error?: string
}

export interface QilingRootfsJob {
  job_id: string
  state: 'queued' | 'running' | 'done' | 'error'
  already_running: boolean
  detail: string
}

// --- network map -----------------------------------------------------------

export interface NetNode {
  id: string
  label: string
  kind: 'host' | 'adapter' | 'network' | 'vm' | 'container'
  ip?: string
  subnet?: string
  status: 'up' | 'down' | 'running'
  detail: string
}

export interface NetLink {
  source: string
  target: string
  kind: 'adapter' | 'bridge' | 'member' | 'host-only'
}

export interface VmService {
  port: number
  /** 'ssh' covers SFTP too - both are port 22 and are not separately switchable. */
  name: string
  detail: string
  open: boolean
}

export interface VboxStatus {
  checked_at: number
  installed: boolean
  /** Executable basename, e.g. 'VBoxManage.exe'. Never the full path. */
  exe: string | null
  error: string | null
  version: string | null
  digest: {
    /** Null when VBoxManage could not be located or read at all. */
    ok: boolean | null
    /** Actual SHA-256 of the binary on disk. */
    sha256: string | null
    /** SHA-256 this project pins. Equals sha256 on a known-good build. */
    pinned: string | null
    detail: string
  }
  machines: {
    total: number
    running: number
    names: string[]
    running_names?: string[]
  }
  hostonly: {
    available: boolean
    count: number
    networks: { name: string; gateway: string; cidr: string; mask: string }[]
    gateway: string | null
    cidr?: string | null
  }
  vm: {
    name: string | null
    ip: string | null
    port: number
    configured: boolean
    services: VmService[]
  }
  services_open: number
  services_total: number
}

/** One registered VirtualBox machine, as VirtualBox describes it. */
// --- evidence artifacts ---------------------------------------------------

/** One `exports/<artifact>_artifact/` bundle, read off the filesystem. */
export interface LocalBundle {
  name: string
  dir: string
  /** False when the bundle directory exists but the tarball does not. */
  present: boolean
  archive: string | null
  bytes: number
  /** Filesystem mtime of the tarball, epoch seconds. */
  modified: number | null
  /** From manifest.json; the run's own timestamp, not the archive's. */
  generated_at: number | null
  file_count: number
  source: string | null
  sha256: string | null
  sidecar_sha256: string | null
  /** manifest.archive_bytes vs the file on disk. */
  size_matches: boolean | null
  /** manifest.archive_sha256 vs the .sha256 sidecar - two independent writes. */
  digests_match: boolean | null
  /**
   * Null when the archive was not re-hashed (over the byte budget, or
   * missing). `verify_detail` says which.
   */
  verified: boolean | null
  verify_detail: string
}

/** The same bundle, as MEGA reports it. */
export interface RemoteBundle {
  name: string
  dir: string
  present: boolean
  archive: string | null
  bytes: number
  /** Sum of every file in the bundle, not just the tarball. */
  total_bytes: number
  modified: number | null
  date_text: string | null
  file_count: number
  files: { name: string | null; bytes: number; date: string | null }[]
}

export interface RemoteState {
  /** False when MEGAcmd is missing, logged out, or the listing failed. */
  available: boolean
  reason: string | null
  account: string | null
  remote_root: string
  bundles: RemoteBundle[]
  not_examined: number
  /** Set when the listing stopped early; the answer is partial. */
  truncated: string | null
  counts?: { total: number; listed: number; bytes: number }
}

/**
 * One gap between two consecutive uploads, oldest first.
 *
 * NOT a transfer measurement. `rate_bps` is the later bundle's bytes divided by
 * the wall-clock gap between the two MEGA timestamps, which also contains
 * however long the operator waited before starting the next upload. It is an
 * upper bound on line rate and is null when the gap is under MEGAcmd's date
 * granularity, where a division would report a near-infinite speed.
 */
export interface TransferInterval {
  from: string
  to: string
  seconds: number
  bytes: number
  size_delta: number
  rate_bps: number | null
}

export interface TransferSummary {
  intervals: TransferInterval[]
  count: number
  mean_rate_bps: number | null
  max_rate_bps: number | null
  median_gap_s: number | null
  total_bytes: number
}

/**
 * A bundle the panel has seen at some point, kept in the appdata cache so the
 * upload timeline is continuous.
 *
 * `present: false` means it was observed on an earlier poll but MEGA is not
 * listing it now - deleted remotely. It stays on the timeline because the
 * upload happened and the interval it formed is real; dropping it would make
 * the rate jump as though the case had never existed.
 */
export interface HistoryBundle {
  name: string
  dir: string
  present: boolean
  archive: string | null
  bytes: number
  total_bytes: number
  modified: number | null
  date_text: string | null
  file_count: number
  files: { name: string | null; bytes: number; date: string | null }[]
  first_seen?: number
  last_seen?: number
  generated_at?: number | null
}

/**
 * A bundle from either end, with `where` saying which.
 *
 * The Remote tab lists these rather than remote-only, because an empty MEGA
 * account is the normal state of a lab that bundles locally and has not
 * uploaded yet - and "no artifacts" next to a bundle sitting on disk is the
 * most misleading thing this page could show.
 */
export interface UnifiedBundle extends HistoryBundle {
  where: 'both' | 'local' | 'remote' | 'remembered'
}

export interface ArtifactsSnapshot {
  generated_at: number | null
  local: {
    bundles: LocalBundle[]
    counts: { total: number; bytes: number; missing: number }
  } | null
  remote: RemoteState | null
  /**
   * Optional: a panel server predating the merged view omits it, and the UI
   * falls back to `history.bundles` rather than rendering an empty tab.
   */
  history?: {
    bundles: HistoryBundle[]
    count: number
    not_on_remote: string[]
    path: string
    written: boolean
    updated_at: number | null
  }
  transfer: TransferSummary | null
  unified?: UnifiedBundle[]
  unified_counts?: { both: number; local: number; remote: number; remembered: number }
  diff: {
    only_local: string[]
    only_remote: string[]
    both: string[]
  }
  error?: string
}

/**
 * One guest, sampled over SSH + SFTP.
 *
 * `state` is the field to branch on. `pending` means the first collection has
 * not landed, `down` carries the reason in `error`, and `up` is the only state
 * in which the numbers mean anything. A machine with `metrics: null` has no
 * credentials on file - that is not the same as a machine at zero.
 */
export interface VmMetrics {
  state: 'pending' | 'up' | 'down'
  ip: string
  collected_at: number | null
  age_seconds: number | null
  hostname: string | null
  kernel: string | null
  cores: number | null
  uptime_seconds: number | null
  load: { '1': number | null; '5': number | null; '15': number | null }
  cpu_percent: number | null
  memory: {
    total_bytes: number | null
    used_bytes: number | null
    available_bytes: number | null
    percent: number | null
    swap_total_bytes: number | null
    swap_used_bytes: number | null
    swap_percent: number | null
  }
  disk: {
    total_bytes: number | null
    used_bytes: number | null
    free_bytes: number | null
    percent: number | null
  }
  network: {
    rx_bytes: number | null
    tx_bytes: number | null
    ifaces: number | null
    addresses: string[]
  }
  processes: {
    count: number | null
    top: { pid: number | null; name: string; mem_bytes: number; mem_percent: number | null }[]
  }
  /**
   * Rolling trend window, oldest first, up to half an hour.
   *
   * Collected server-side so the chart is already populated when a reader
   * arrives, rather than restarting empty on every page load. Present on
   * anything the panel has measured at least once; absent on a payload the
   * backend never got to measure.
   */
  history?: VmMetricSample[]
  error: string
}

/**
 * One point of the guest's trend series.
 *
 * Every field is nullable, and that is not sloppiness: a failed collection still
 * produces a point with all-null fields, so a gap in the chart reads as "we
 * stopped measuring here" rather than "the machine was idle here". Collapsing
 * those two is how a chart ends up drawing a calm straight line through an
 * outage.
 */
export interface VmMetricSample {
  at: number
  cpu: number | null
  mem: number | null
  disk: number | null
  load1: number | null
  procs: number | null
  rx: number | null
  tx: number | null
}

export interface VmInfo {
  name: string
  uuid: string | null
  os: string | null
  /** Raw VBoxManage state: poweroff, running, saved, starting, paused... */
  state: string
  running: boolean
  /**
   * True when `state` is one a machine can only reach by failing (aborted,
   * baddimage, unavailable). Decided server-side by vms.crashed() so the status
   * chip and the log parser cannot disagree about what counts as a crash.
   */
  crashed?: boolean
  /**
   * Guest address. Null when the machine is off, or running without Guest
   * Additions reporting one - both mean there is nothing to connect to, and
   * both are more useful shown than defaulted to 0.0.0.0.
   */
  ip: string | null
  /**
   * IPv6 as the guest reported it. Kept apart from `ip` because a dual-stack
   * sandbox has both, and showing one while implying that is the only address
   * is a claim about the machine that is simply false.
   */
  ip6?: string | null
  mac: string | null
  adapter: string | null
  /** Megabytes, as VirtualBox reports it. */
  memory_mb: number | null
  cpus: number | null
  /** Empty when not probed - see `probed`. */
  services: VmService[]
  services_open: number
  /** False when the machine is off or has no address, so nothing was checked. */
  probed: boolean
  detail: string
  /** Bounded tail of the VM's latest VirtualBox VBox.log run log. */
  run_log?: string
  /** Null when the panel holds no SSH credentials for this machine. */
  metrics?: VmMetrics | null
  /** Set when showvminfo failed for this one machine. */
  error?: string
  /**
   * What the guest itself reports about itself, via `VBoxManage guestproperty
   * enumerate`.
   *
   * Partial because the backend sends `{}` - an empty object, not a record of
   * null fields - when a machine has no Guest Additions or is powered off.
   * `{}` is a meaningful answer ("the guest said nothing") and is distinct from
   * an absent `guest` ("we did not ask"), so this has to admit that most of
   * its fields may be missing. Reading `guest.net` unguarded is what took the
   * card down once already.
   */
  guest?: Partial<VmGuestInfo>
  /**
   * The address `qiling_dlls/vm_info.json` expects this machine to have, for
   * the one machine it names.
   *
   * Deliberately NOT merged into `ip`. This is where the project's tooling
   * thinks the machine is; `ip` is where the guest says it is. They normally
   * agree, and the times they do not - a re-IP'd sandbox, a config left
   * pointing at a rebuilt machine - are exactly when the difference matters.
   */
  configured?: VmConfiguredEndpoint
}

/** The project's configured SSH endpoint for a machine, from vm_info.json. */
export interface VmConfiguredEndpoint {
  ip: string
  port: number
  source: string
}

// --- build ------------------------------------------------------------------
//
// Two reports, because they answer different questions and a build is only half
// of what can go wrong:
//
//   toolchain - can this project COMPILE. Every entry is a CMake declaration.
//   stack     - what the analyzer shells out to at analysis time: MalAPI, capa,
//               the rule packs, the ML scorer. A build can succeed perfectly
//               while capa.exe is missing, and then every analysis silently
//               comes back with no capa section and no error.

export interface BuildTool {
  name: string
  found: boolean
  path: string | null
  why: string
}

/** How an entry was declared, which decides how it was resolved. */
export type DepKind =
  // toolchain
  | 'tool' | 'package' | 'archive' | 'library' | 'header' | 'pkg-config' | 'vendored'
  // analysis stack
  | 'program' | 'rules' | 'source' | 'data' | 'venv' | 'service' | 'manifest'

export interface BuildDependency {
  name: string
  /** How CMakeLists.txt declares it, or what sort of stack entry it is. */
  kind: DepKind
  /**
   * True when the declaration is REQUIRED - so a miss stops the build rather
   * than warning. Optional entries are shown dimmed and do not block.
   *
   * Only the toolchain report gates the Build button. A missing analysis
   * dependency does not stop a compile, so a stack miss is reported without
   * disabling anything.
   */
  required: boolean
  found: boolean
  /** The exact artefact that satisfied it, or null. */
  path: string | null
  note: string
}

export interface DepCounts {
  total: number
  found: number
  missing: number
}

export interface ToolchainReport {
  available: boolean
  reason: string | null
  sysroot: string
  sysroot_found: boolean
  tools: BuildTool[]
  dependencies: BuildDependency[]
  /** How many REQUIRED entries are absent - the number that decides a build. */
  missing_required: number
  counts: DepCounts
}

export interface StackReport {
  available: boolean
  /** generate_sbom.py, the manifest the vendored and venv rows come from. */
  manifest: string
  /** False when that manifest could not be read; those rows are then unverified. */
  manifest_loaded: boolean
  dependencies: BuildDependency[]
  missing_required: number
  counts: DepCounts
}

export type DepReport = ToolchainReport | StackReport

export interface BuildArtifact {
  name: string
  path: string
  relative: string
  bytes: number
  modified: number
  /** True for the analyzer specifically, and only when it actually linked. */
  ready: boolean
}

/** What the built binary says about itself, and what the working tree says. */
export interface BuildGitIdentity {
  available: boolean
  reason?: string
  commit?: string
  short?: string
  branch?: string
  subject?: string
  author_date?: string
  dirty?: boolean
  dirty_count?: number
}

export interface BuildBakedIdentity {
  available: boolean
  reason?: string
  version?: string
  commit?: string | null
  raw?: string
}

export interface BuildProvenance {
  git: BuildGitIdentity
  baked: BuildBakedIdentity
  /** null when a comparison is not possible; false means they DISAGREE. */
  agrees: boolean | null
  note: string
}

export interface BuildFreshness {
  available: boolean
  reason?: string
  stale: boolean | null
  exe_path?: string
  exe_mtime?: number
  exe_bytes?: number
  newest_source?: string | null
  newest_source_mtime?: number | null
  lag_seconds?: number
  newer_sources?: { path: string; mtime: number }[]
  note: string
}

export interface BuildCheck {
  id: string
  label: string
  /** null = could not determine, which is not the same as failing. */
  ok: boolean | null
  detail: string
}

export interface BuildValidation {
  checks: BuildCheck[]
  verdict: 'pass' | 'fail' | 'unknown'
  ran_at: number
}

export interface BuildConfiguration {
  available: boolean
  reason?: string
  options: Record<string, string>
  generator?: string
  build_type?: string
  compiler?: string
  cache_path?: string
}

/** One protection, as the settings file offers it. */
export interface BuildHardeningOption {
  key: string
  label: string
  summary: string
  detail: string
  /** What the analyzer gets when the settings file says nothing. */
  default: boolean
  /** The effective value - the file's, or the default when it is silent. */
  enabled: boolean
  /** The CMake option that carries this into the configure step. */
  cmake: string
  /** How the protection shows up in the binary. */
  pe_label: string
}

export interface BuildHardeningSnapshot {
  /** Repo-relative, so the page never shows an absolute path it cannot share. */
  path: string
  exists: boolean
  options: BuildHardeningOption[]
  settings: Record<string, boolean>
  /** A malformed file is reported here rather than silently defaulted away. */
  error: string | null
}

/** One protection, requested against present. */
export interface BuildHardeningRow {
  key: string
  label: string
  pe_label: string
  requested: boolean
  present: boolean
  /** requested === present. Turning a protection OFF deliberately is compliance. */
  ok: boolean
  detail: string
}

export interface BuildHardeningCompliance {
  available: boolean
  /** Why there is no report: not built yet, or not a PE this parser reads. */
  reason?: string
  binary?: string
  format?: string
  /** The raw DllCharacteristics word the three header bits were read from. */
  dll_characteristics?: number
  settings: Record<string, boolean>
  settings_error: string | null
  rows: BuildHardeningRow[]
  /** null when nothing could be compared; false means rebuild. */
  compliant: boolean | null
  note: string
}

/** Both halves in one payload: what is asked for, and what the binary carries. */
export interface BuildHardening {
  settings: BuildHardeningSnapshot
  compliance: BuildHardeningCompliance
}

export interface BuildInspect {
  provenance: BuildProvenance
  freshness: BuildFreshness
  validation: BuildValidation
  configuration: BuildConfiguration
}

/** One selectable test. `effects` is what it TOUCHES, not what it checks. */
export interface BuildTestEntry {
  id: string
  label: string
  kind: 'smoke' | 'integration' | 'pytest'
  description: string
  effects: string[]
  available: boolean
  unavailable_reason: string | null
  timeout: number
}

export interface BuildTestCatalogue {
  entries: BuildTestEntry[]
  quick: string[]
  pytest_available: boolean
  sample: string | null
}

export interface BuildTestResult {
  id: string
  label: string
  state: 'pending' | 'running' | 'passed' | 'failed' | 'skipped'
  detail: string | null
  duration: number | null
  code?: number | null
}

// --- Utils ---------------------------------------------------------------

export interface SbomState {
  available: boolean
  reason?: string
  stale: boolean | null
  script_present: boolean
  generated_at?: string | null
  age_days?: number | null
  tool?: string
  format?: string
  spec_version?: string
  project?: string
  total_components?: number
  by_type?: Record<string, number>
  by_origin?: Record<string, number>
  by_language?: Record<string, number>
  unresolved?: string[]
  /**
   * The same list with what each component actually does. A bare name is the
   * thing this exists to stop being - "gnurx" is not a hint, and "POSIX regexp
   * compatibility library shipped with the UCRT" is.
   */
  unresolved_details?: { name: string; description: string }[]
  cyclonedx_bytes?: number
  cyclonedx_present?: boolean
  last_commit?: string | null
  behind_last_commit?: boolean | null
  note?: string
}

export interface MalapiState {
  available: boolean
  reason?: string | null
  /**
   * MalAPI rules are a mirror of malapi.io, not a git checkout, so there is no
   * ahead/behind and nothing to call "up to date". A blocked refresh is a stale
   * httrack lock or a missing mirror tool, not local edits.
   */
  blocked?: boolean
  blocked_reason?: string | null
  source?: string
  mirror_path?: string
  /** Age of the newest scraped page, in days. */
  mirror_age_days?: number | null
  yaml_path?: string
  yaml_count?: number
  /** Age of the newest generated API definition, in days. */
  yaml_age_days?: number | null
  server_path?: string
  /** The generated API predates the mirror, so the analyzer serves stale rules. */
  generated_stale?: boolean
  httrack?: boolean
  lock?: { path: string; age_days: number; age_minutes: number; stale: boolean } | null
  /**
   * memtt/malt, reported under its real name. It is the MalAPI tool, not the
   * rules; nothing the analyzer runs links it.
   */
  malt_tool?: {
    path: string
    commit?: string | null
    short?: string
    remote?: string | null
    used_by_analyzer: boolean
    note: string
  } | null
  note?: string
}

export interface YaraCollection {
  name: string
  rules: number
  bytes: number
}

export interface YaraState {
  available: boolean
  reason?: string
  collections: YaraCollection[]
  total: number
  bytes: number
  largest?: { bytes: number; path: string }[]
  is_git_checkout?: boolean
  can_update?: boolean
  update_reason?: string
  compiler?: string | null
  yara_version?: string | null
  /** Persisted in config/yara_check.json by the backend when the checkbox in
   *  the card is ticked; yara() reports what the last run left there. */
  ignore_compile_failures?: boolean
  note?: string
}

export interface YargenCheck {
  id: string
  label: string
  ok: boolean
  detail: string
  fix?: string | null
}

export interface YargenState {
  available: boolean
  reason?: string
  checks: YargenCheck[]
  ok?: boolean
  commit?: string | null
  remote?: string | null
  update_script?: boolean
  update_script_path?: string | null
  faults?: string[]
  note?: string
}

export interface EagleArtifact {
  name: string
  exists: boolean
  path: string
  bytes: number | null
  modified: number | null
}

export interface EagleState {
  ok: boolean
  ready: boolean
  available: boolean
  repo: string
  repo_exists: boolean
  preset: string
  build_dir: string
  build_dir_exists: boolean
  toolchain: {
    vcvars64: string | null
    cmake: string | null
    ninja: string | null
  }
  artifacts: Record<string, EagleArtifact>
  missing: string[]
  reason: string | null
  note: string
}

export interface UtilEntry {
  id: string
  label: string
  utility: 'sbom' | 'malapi' | 'yara' | 'yargen' | 'eagle'
  description: string
  effects: string[]
  available: boolean
  unavailable_reason: string | null
  timeout: number
}

export interface UtilsOverview {
  entries: UtilEntry[]
  sbom: SbomState
  malapi: MalapiState
  yara: YaraState
  yargen: YargenState
  eagle: EagleState
}

export interface BuildArtifacts {
  artifacts: BuildArtifact[]
  analyzer: BuildArtifact | null
  analyzer_ready: boolean
  build_dir: string
  build_dir_exists: boolean
}

export type AnalyzerBuildState =
  | 'running'
  | 'done'
  | 'failed'
  | 'error'
  /** Test runs report 'passed' when every selected test passed. Distinct from
   *  'done' so the UI can say what actually happened rather than showing a
   *  compile-style completion for a run of tests. */
  | 'passed'

/**
 * One `build.ps1` compile of the analyzer.
 *
 * Named AnalyzerBuildJob rather than BuildJob: `BuildJob` is already the
 * container image build, and two jobs with the same shape-ish name and
 * different meanings is how a poll starts reading the wrong payload.
 *
 * `state` has an extra member over the container build's - `failed` - because
 * build.ps1 distinguishes "the compiler rejected the code" from "the script
 * itself could not run", and an operator debugging the difference needs to be
 * able to tell them apart.
 */
export interface AnalyzerBuildJob {
  id: string
  state: AnalyzerBuildState
  clean: boolean
  started_at: number | null
  finished_at: number | null
  exit_code: number | null
  error: string | null
  command: string
  log_line_count: number
  artifact: string | null
  /** Present on a full fetch; omitted from the job list, which is 10 rows. */
  log?: string[]
  /** How many lines were dropped from the head, when the log outgrew its cap. */
  log_truncated?: number
  /** 'tests' for a test run, 'utils' for a utility run; absent for a build.
   *  All three share one job store (python/panel/build.py), so the log is
   *  fetched from the same endpoint for each - and this is what tells them
   *  apart in the UI. */
  kind?: 'build' | 'tests' | 'utils'
  /** Per-test verdicts. Present only on a test run. */
  results?: BuildTestResult[]
  /** Which tests were chosen, echoed back so the log header can name them. */
  selected?: string[]
  summary?: string
}

export interface BuildJobsState {
  running: string | null
  jobs: Omit<AnalyzerBuildJob, 'log'>[]
  script: string
  script_found: boolean
}

/**
 * The packed verdict for one sample (python/panel/pe_tools.pack_verdict).
 * Computed server-side, always - the page displays it, the run gate re-derives
 * it; nothing here is ever sent back as a claim about a file.
 */
export interface SamplePackedVerdict {
  packed: boolean
  /**
   * "upx" when packer markers were found in the file (a fact), "entropy" when
   * only the whole-file entropy threshold fired (the analyzer's own
   * IA_INTERRUPT_ENTROPY number), null when the file reads as unpacked.
   */
  method: 'upx' | 'entropy' | null
  /** The facts behind the verdict, in a sentence, for the alert. */
  evidence: string
  /** Whole-file entropy in bits/byte, as measured. */
  entropy?: number
  /** Present only when the file could not be read for a verdict. */
  error?: string
}

/**
 * The analyzer's OWN packed tripwire, read from config/analysis.yaml
 * (IA_INTERRUPT_IF_PACKED). Reported, never written by the page: the panel
 * gate stops a packed run BEFORE the spawn, this key stops it INSIDE the
 * analyzer at the histogram phase - so with it on, overriding the panel gate
 * only buys a run the analyzer kills mid-flight. The page says so rather than
 * letting the operator find out from a truncated log.
 */
export interface AnalyzerPackedStop {
  key: string
  /** Whether the key is explicitly set in config/analysis.yaml. */
  present: boolean
  /** The value as written there, or null when absent. */
  value: string | null
  /**
   * What the analyzer will do: only 1/true/yes/on read as enabled (the C++
   * env_flag semantics); absent falls back to the binary default, which is
   * off for this key.
   */
  enabled: boolean
}

/** One executable under a sample root, as listed by GET /api/build/samples. */
export interface SampleFile {
  name: string
  /** Repo-relative path, which is what the picker and the run gate exchange. */
  relative: string
  bytes: number
  modified: number
}

/**
 * GET /api/build/samples — the Run a pipeline picker's choices. Metadata only:
 * the selected file is inspected separately because a packed verdict reads the
 * whole file.
 */
export interface SampleListing {
  ok: boolean
  files: SampleFile[]
  /** Server-side cap for POST /api/build/samples/upload. */
  upload_max_bytes: number
}

/**
 * POST /api/build/samples/upload — an operator's own executable admitted into
 * samples/ after the name rules, size cap and clamd scan. Refusals are
 * payloads with a machine-readable `code`, so the page can offer the explicit
 * unscanned retry only for `scan-unavailable`.
 */
export interface SampleUploadResult {
  ok: boolean
  code?: string
  error?: string
  detail?: string
  file?: SampleFile
  sha256?: string
  scan?: {
    verdict?: 'clean' | 'infected' | 'unavailable'
    signature?: string | null
    error?: string
    seconds?: number
  }
}

/**
 * POST /api/build/samples/inspect — a typed sample path, validated with the
 * same rules the run gate applies and described: resolved path, size, mtime,
 * packed verdict. A refusal is `ok: false` with the rule's sentence.
 */
export interface SampleInspect {
  ok: boolean
  path?: string
  relative?: string
  bytes?: number
  modified?: number
  packed?: SamplePackedVerdict | null
  /** State of the analyzer's own mid-run packed stop, so the override's cost
      is known before it is taken. */
  analyzer_packed_stop?: AnalyzerPackedStop | null
  error?: string
}

/**
 * One pipeline run from the Build page's "Run a pipeline" section
 * (python/panel/pipeline_run.py). Its own endpoint and its own job store, not
 * the build one: a run is a long analysis work item rather than a compile, and
 * the runner keeps it separate so neither page's poll can mistake the other
 * job for its own.
 */
export interface PipelineRunState {
  id: string
  /**
   * `stopped` is separate from `failed` on purpose: a run ended by its duration
   * limit or by the Stop button exits non-zero, and reporting that as a failure
   * would blame the analyzer for a decision the panel made.
   */
  state: 'running' | 'done' | 'failed' | 'error' | 'stopped'
  /** The pipeline as requested, echoed. */
  pipeline: string
  /** The resolved absolute sample path. */
  sample: string
  started_at: number
  finished_at: number | null
  exit_code: number | null
  /** Non-null when the child exited non-zero; names the exit code. */
  error: string | null
  command: string
  log_line_count: number
  /** How many lines were dropped from the head, per build.py's arithmetic. */
  log_dropped?: number
  /** Lines kept by the cap, in order. */
  log: string[]
  /** The limit the run was started with, or null for unbounded. */
  duration_sec?: number | null
  /** Epoch seconds at which the watchdog will kill the run, or null. */
  deadline?: number | null
  /** True when the duration limit is what ended the run. */
  timed_out?: boolean
  /** The packed verdict the run gate recorded at start, on the job so a live
      run can be labelled rather than only a refused one. */
  packed?: SamplePackedVerdict | null
}

// --- Sample factory (python/panel/sample_factory.py) -----------------------

/** One preset bundle of checkboxes; the checkboxes still compose on top. */
export interface SampleTemplate {
  id: string
  language: 'c' | 'cpp'
  features: string[]
  label: string
  description: string
}

export interface SampleFactoryCatalog {
  languages: string[]
  /** Checkbox names valid per language, so the UI can hide the others. */
  features: Record<string, string[]>
  feature_notes: Record<string, string>
  /** Resource-backed features that exist but cannot run right now, with the
   *  sentence that says why. Rendered disabled rather than hidden, so the
   *  vocabulary does not change silently between visits. */
  feature_unavailable: Record<string, string>
  /** Current size of each resource pool: ip, domain. */
  pools: Record<string, number>
  templates: SampleTemplate[]
  custom_id: string
  compiler: { ok: boolean; gcc?: string; sysroot?: string; error?: string; detail?: string }
  /** The in-tree UPX, or the sentence saying why packing is refused. */
  upx: { ok: boolean; path?: string; error?: string; detail?: string }
  /** The in-tree EagleVM, or the sentence saying why virtualisation is refused. */
  eagle: EagleState
  /** Encoding id -> the sentence the select shows beside it. */
  encodings: Record<string, string>
  /** Upper bound on the sleep the operator may ask for, in seconds. */
  sleep_max: number
}

/** The composer knobs that map onto CodeFactory's own parameters. */
export interface SampleShapeOptions {
  /** Blocks passed to create_math_ops_c. */
  n_math: number
  /** Variables passed to create_random_vars (the loop's independent pool). */
  n_vars: number
  /** generate_for_loop count_to; 0 lets the backend draw one. */
  loop_count: number
  /** generate_for_loop step. */
  loop_step: number
  /** generate_for_loop break index; omitted lets the backend draw one. */
  loop_break_at?: number
  /** Number of instructions drawn via gen_instruction for the loop body. */
  instruction_count: number
  /** create_malloc_pointer size used by the fault archetypes. */
  alloc_size: number
  /** create_double_free_issues free count. */
  n_frees: number
}

export interface SamplePreview {
  ok: boolean
  language: string
  template: string | null
  features: string[]
  code: string
  /** Present when the noise checkbox is on: the exact IP/domain Generate plants. */
  noise?: { ip: string; domain: string } | null
  /** Every value drawn from a resource pool, and the source it came from. */
  resources?: SampleResourceUse[]
  /** The encoding the resource-backed IOCs were composed with. */
  encoding?: string
  sleep_seconds?: number
  /** The 32-bit draw seed; send it back to Generate to replay this exact sample. */
  seed?: number
  /** The CodeFactory knobs the source was composed from (loop_break_at null means auto). */
  shape?: SampleShapeOptions & { loop_break_at: number | null }
  error?: string
}

export interface SampleGenerated {
  ok: boolean
  source?: string
  exe?: string
  bytes?: number
  noise?: { ip: string; domain: string } | null
  code?: string
  log?: string
  /** The exact compiler argv, so the Output panel can show what ran. */
  command?: string
  /** samples/<name>.mk when the Makefile checkbox was on. */
  makefile?: string | null
  resources?: SampleResourceUse[]
  encoding?: string
  sleep_seconds?: number
  seed?: number
  /** The CodeFactory knobs the artefact was composed from. */
  shape?: SampleShapeOptions & { loop_break_at: number | null }
  /** Present when UPX ran: the two sizes and the resulting ratio. */
  packed?: { before: number; after: number; ratio: number | null } | null
  /** Present when Instruction Virtualisation ran: the source and result names. */
  virtualized?: { from: string; to: string; log: string } | null
  flags?: { upx: boolean; virtualize: boolean; makefile?: boolean }
  error?: string
  detail?: string
}

/**
 * One sampled value and the GitHub source it came from (sample_factory's
 * `_draw_dynamic`). `value` is the plaintext even when the generated source
 * carries it encoded, because this is what the operator recognises.
 */
export interface SampleResourceUse {
  feature: string
  kind: SampleResourceKind
  id: string
  label: string
  value: string
  /** How the source stores it: plain, rot13, xor, base64 or chained. */
  encoding?: string
}

export type SampleResourceKind = 'ip' | 'domain' | 'url' | 'hash'

/**
 * One GitHub file the factory's pools draw from
 * (python/panel/sample_resources.py). `current` is false when the cached values
 * were fetched for an older URL or kind - they are shown but not sampled.
 */
export interface SampleResource {
  id: string
  label: string
  kind: SampleResourceKind
  /** The normalised URL the panel actually fetches (github.com /blob/ becomes raw). */
  url: string
  enabled: boolean
  note: string
  added_at: number | null
  fetched_at: number | null
  count: number
  preview: string[]
  invalid: number
  duplicates: number
  truncated: boolean
  bytes: number
  current: boolean
  /** Repo-relative path of the raw dump in ressources/, when one was saved. */
  dump: string | null
  last_error: string | null
  last_error_at: number | null
}

export interface SampleResourceKindInfo {
  kind: SampleResourceKind
  label: string
  detail: string
  format: string
  /** The factory checkbox this kind feeds: iocs. */
  feature: string
  /** Values from enabled resources with a current cache. */
  pool_size: number
  resources: SampleResource[]
}

export interface SampleResourceFeature {
  available: boolean
  reason: string | null
  needs: SampleResourceKind[]
}

export interface SampleResourcesSnapshot {
  path: string
  /** The repo directory the raw dumps and parsed values are kept in. */
  dump_dir: string
  exists: boolean
  /** Set when the definitions file exists but could not be read. */
  error: string | null
  kinds: SampleResourceKindInfo[]
  pools: Record<SampleResourceKind, number>
  features: Record<string, SampleResourceFeature>
  limits: {
    max_bytes: number
    max_entries: number
    max_resources: number
  }
}

/** Every mutating resources endpoint returns the fresh snapshot, so a write
 *  and the page's state cannot drift between two requests. `refresh` on an add
 *  or refresh call describes that fetch, not whether the resource exists. */
export interface SampleResourcesMutation extends SampleResourcesSnapshot {
  ok: boolean
  added?: string
  refresh?: {
    ok: boolean
    error?: string
    count?: number
    invalid?: number
    duplicates?: number
    truncated?: boolean
    fetched_at?: number
    source?: string
  }
}



export interface BuildOverview {
  toolchain: ToolchainReport
  stack: StackReport
  artifacts: BuildArtifacts
  jobs: BuildJobsState
}

/** The half of the overview a "Check dependencies" refresh returns. */
export interface DepRefresh {
  toolchain: ToolchainReport
  stack: StackReport
}

/** One adapter as the guest reports it: v4 and v6 are the SAME NIC. */
export interface VmGuestNic {
  index: number
  v4: string | null
  /** Prefix length, not a dotted mask. 24 means /24. */
  v4_prefix: number | null
  v6: string | null
}

export interface VmGuestInfo {
  /** Guest Additions version, the extended string when there is one. */
  additions: string | null
  additions_core: string | null
  product: string | null
  release: string | null
  version: string | null
  service_pack: string | null
  hostname: string | null
  logged_on_users: string[] | null
  net: VmGuestNic[]
}

export interface VmList {
  generated_at: number | null
  vms: VmInfo[]
  counts: { total: number; running: number; duplicates: number }
  /**
   * Registrations the server collapsed away. Reported rather than silently
   * dropped - a machine vanishing from the fleet with no explanation reads as
   * a VirtualBox fault.
   */
  duplicate_names: string[]
  /** False when VirtualBox itself is missing or unreadable. */
  available: boolean
  error: string | null
}

export interface VmActionResult {
  ok: boolean
  detail: string
  name?: string
  action?: string
  /** Echoed back for `start` so the confirmation can name the mode used. */
  headless?: boolean
}

export type HypervisorId = 'virtualbox' | 'qemu' | 'vmware' | 'hyperv'

/**
 * One probed hypervisor. Every field is present whether or not the tool is
 * installed - `detected` is a fixed roster the backend always returns, so the
 * UI maps over it without null-guarding. `installed: false` is a real answer,
 * not a failure, and `detail` says why.
 */
export interface VirtTool {
  id: HypervisorId
  name: string
  installed: boolean
  /** Binary basename only. The panel reports which tool, not where it lives. */
  exe: string | null
  version: string | null
  machines: {
    total: number
    running: number
    names: string[]
    running_names: string[]
  }
  /**
   * Why it is absent, or a caveat about what its numbers mean. QEMU reports 0
   * machines because it cannot count them, not because there are none - this
   * is where that distinction is made visible.
   */
  detail: string
}

export interface VirtStatus {
  checked_at: number
  detected: VirtTool[]
  /** Ids of the tools actually found, in roster order. */
  installed: HypervisorId[]
  /** The tool this lab is wired to, or null if no hypervisor is installed. */
  primary: HypervisorId | null
  count: number
}

export interface NetMap {
  generated_at: number | null
  nodes: NetNode[]
  links: NetLink[]
  host_adapters: { ip: string; alias: string; loopback: boolean }[]
  hostonly: { name: string; gateway: string; cidr: string; mask: string }[]
  docker: { name: string; driver: string; subnet: string; containers: { name: string; ip: string }[] }[]
  qiling_vm: {
    name: string
    ip: string
    port: number
    registered: boolean
    running: boolean
    subnet: string
    reachable: boolean
  } | null
  counts: { networks: number; containers: number; vms: number; adapters: number }
  /** VirtualBox tool + host-only + guest service status. */
  vbox: VboxStatus | null
  /** Which hypervisor this box has. Independent of whether VirtualBox is. */
  virt?: VirtStatus
  error?: string
}

// --- documentation -------------------------------------------------------

export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE'

/** Octet-by-octet breakdown plus the routing facts for a literal address. */
export interface IpFacts {
  ip: string
  /** null when the host is a name (localhost) rather than a literal address. */
  octets: number[] | null
  /** null when the address is not bound to this host, so no prefix is knowable. */
  prefix_length: number | null
  cidr: string | null
  network: string | null
  /** Usable host count implied by the prefix. */
  hosts: number | null
  /** The NIC this address is bound to, e.g. "Ethernet 3". */
  interface: string | null
  /** Windows interface index, for disambiguating same-named adapters. */
  interface_index: number | null
  /** Legacy classful class (A-E). Obsolete since CIDR - the UI says so. */
  class: string | null
  class_legacy: boolean
  scope: 'loopback' | 'private' | 'link-local' | 'multicast' | 'reserved' | 'public' | 'hostname' | 'ipv6'
  scope_meaning?: string
  note?: string | null
}

export interface PortFacts {
  port: number
  /** IANA name, a de-facto convention, or null when genuinely unregistered. */
  service: string | null
  source: 'iana' | 'de-facto' | 'unregistered'
  band: 'well-known' | 'registered' | 'dynamic'
  band_meaning: string
}

export interface NetFacts {
  ip: IpFacts | null
  port: PortFacts | null
}

export interface DocRoute {
  method: HttpMethod
  path: string
  summary: string
  /** Flask endpoint name; present on the introspected panel routes. */
  endpoint?: string
  /** Python handler function, on routes parsed from source. */
  handler?: string
  /** Source line of the declaration, for routes parsed from source. */
  line?: number
  /** Where the summary came from: lifted from a docstring, or written here. */
  source?: 'code' | 'editorial'
  /** Query/body parameters, when the route takes any. */
  params?: RouteParams
  /** True only for reads - a POST here could start a build or stop a container. */
  safe_get?: boolean
  /** Set on a collapsed family (MalAPI's ~550 near-identical routes). */
  family?: boolean
  /** How many routes this pattern stands for. */
  count?: number
}

/** What a view function actually reads off the request. */
export interface RouteParams {
  /** Placeholders from the Flask rule, e.g. ["task_id", "rel"]. */
  path: string[]
  /** request.args.get(...) names, in source order. */
  query: string[]
  /** request.form.get(...) names. */
  form: string[]
  /** "JSON body" / "request body" when the handler expects one. */
  body?: string | null
  /** Body field names, where they are known (CyberChef, from its client). */
  fields?: string[]
  view_args?: boolean
}

/** One HTTP surface, however its routes were discovered. */
export interface DocServiceApi {
  base: string
  routes: DocRoute[]
  count: number
  /** Provenance: how this list was obtained, so it can be judged. */
  source: string
  up: boolean
  /** Panel only: the paths the React bundle is served from. */
  spa_shell?: string[]
  capabilities?: DocCapability[]
  capabilities_live?: boolean
  auth?: boolean
}

export interface DocCapability {
  name: string
  summary: string
  phases: string[]
  endpoint: string
  alias: string
}

export interface DocService {
  key: string
  name: string
  description: string
  endpoint: string
  host: string
  port: number
  scheme: string
  kind: 'http' | 'tcp'
  role: string
  up: boolean
  code: string
  ms: number
  /** Derived routing facts for the host:port this service answers on. */
  net: NetFacts
}

export interface DocsCatalog {
  panel: DocServiceApi
  analyzer: DocServiceApi
  malapi: DocServiceApi
  ml: DocServiceApi
  cyberchef: DocServiceApi
  services: DocService[]
  bases: Record<string, boolean>
}

// --- statistics -----------------------------------------------------------

export interface Stats {
  generated_at: number
  services: {
    up: number
    total: number
    median_ms: number | null
    ml_auth: boolean | null
    items: { key: string; name: string; up: boolean; ms: number | null }[]
  }
  machine: {
    cpu: number | null
    cores: number | null
    memory: number | null
    uptime_seconds: number | null
    host: string | null
    disk_used_percent: number | null
    disk_free_bytes: number | null
    disk_total_bytes: number | null
  }
  logs: {
    files: number
    bytes: number
    sources: number
    largest: { name: string; bytes: number } | null
    by_source: { label: string; files: number; bytes: number }[]
  }
  runs: {
    count: number
    artifacts: number
    bytes: number
    results: Record<string, number>
    last_run_at: number | null
    present: boolean
  }
  containers: {
    available: boolean
    running: boolean
    version: string | null
    reason: string | null
    total: number | null
    running_count: number | null
    stopped: number | null
  }
  history: {
    samples: number
    window_seconds: number
    cpu: (number | null)[]
    memory: (number | null)[]
    up: (number | null)[]
    total: number | null
  }
}
/** One setting in config/analysis.yaml. */
export interface AnalysisSetting extends EnvOption {
  /** False means the key is absent: the pipeline decides, not this file. */
  present: boolean
  /** The raw value as written, or null when absent. */
  value: string | null
}

export interface AnalysisSettingsSnapshot {
  /** Repository-relative, e.g. 'config/analysis.yaml'. */
  path: string
  exists: boolean
  settings: AnalysisSetting[]
  /** Keys in the file the analyzer does not read; it refuses to start on one. */
  unknown: string[]
}
