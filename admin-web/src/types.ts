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

// --- clamav (guest on the Qiling VM) --------------------------------------

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
}

export interface ClamdStatus {
  reachable: boolean
  mode: string
  endpoint: string
  version: string
  vm: { ip: string; host: string; port: number }
  checks: ClamdCheck[]
  ok: boolean
  note: string
  error?: string
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

export interface VmInfo {
  name: string
  uuid: string | null
  os: string | null
  /** Raw VBoxManage state: poweroff, running, saved, starting, paused... */
  state: string
  running: boolean
  /**
   * Guest address. Null when the machine is off, or running without Guest
   * Additions reporting one - both mean there is nothing to connect to, and
   * both are more useful shown than defaulted to 0.0.0.0.
   */
  ip: string | null
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
  /** Set when showvminfo failed for this one machine. */
  error?: string
}

export interface VmList {
  generated_at: number | null
  vms: VmInfo[]
  counts: { total: number; running: number }
  /** False when VirtualBox itself is missing or unreadable. */
  available: boolean
  error: string | null
}

export interface VmActionResult {
  ok: boolean
  detail: string
  name?: string
  action?: string
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