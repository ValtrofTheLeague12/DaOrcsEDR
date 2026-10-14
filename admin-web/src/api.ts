import { useEffect, useRef, useState } from 'react'
import type {
  ArtifactsSnapshot,
  ClamdResults,
  ClamdStatus,
  ContainerList,
  DocsCatalog,
  LogList,
  LogTail,
  NetMap,
  Overview,
  PanelConfig,
  QilingGuestMetrics,
  QilingRootfsJob,
  QilingRuns,
  QilingVmStatus,
  Stats,
  SystemInfo,
  VmActionResult,
  VmList,
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
  system: () => json<SystemInfo>('/api/system'),
  stats: () => json<Stats>('/api/stats'),
  logs: () => json<LogList>('/api/logs'),
  // The id is an opaque server-mangled handle, not a path, so it is safe to
  // interpolate without encoding - but encode anyway; it costs nothing.
  tail: (id: string, lines = 80) =>
    json<LogTail>(`/api/logs/${encodeURIComponent(id)}/tail?lines=${lines}`),
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
  // Local evidence bundles, their MEGA copies, and the effective throughput
  // between consecutive uploads. Read-only; uploading stays a CLI action
  // because it pushes analysis evidence to cloud storage.
  // `refresh` bypasses the server's 5-minute MEGA cache - the Rescan button
  // needs to see an upload that just happened, not one from five minutes ago.
  artifacts: (remoteRoot = '/', refresh = false) =>
    json<ArtifactsSnapshot>(
      `/api/artifacts?remote_root=${encodeURIComponent(remoteRoot)}` +
        (refresh ? '&refresh=1' : ''),
    ),
  // Every registered VirtualBox machine with its address and live services.
  // One showvminfo per machine, so this is heavier than the netmap poll.
  vms: () => json<VmList>('/api/vms'),
  // The machine name goes in the BODY, not the path. A VirtualBox machine name
  // is free text - it can contain slashes and spaces - so putting it in a URL
  // means encoding problems on the way out and a name that never got quoted on
  // the way in. The backend checks it against the registered list regardless.
  vmAction: (name: string, action: 'start' | 'stop') =>
    json<VmActionResult>(`/api/vms/${action}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name }),
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