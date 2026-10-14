import { Alert, Button, Card, Chip } from '@heroui/react'
import Loading from '../components/Loading'
import Icon, { type IconName } from '../components/Icon'
import { StatTile } from '../components/Stat'
import { api, usePoll } from '../api'
import { ago, bytes, shortDuration } from '../lib/format'

// ---------------------------------------------------------------------------
// ClamAV - a GUEST on the Qiling VM, not a service on this host.
//
// The split from the Qiling panel is the point: clamd has no HTTP endpoint
// anywhere in the repo. clamd-python.py is a CLI client that runs INSIDE the
// guest and answers on a unix socket (/var/run/clamav/clamd.ctl); scan_remote.py
// is the host-side SSH driver that uploads a sample, runs it there and pulls
// the JSON back. So a "scan" is a subprocess with real side effects, not a
// request - and the panel shows the results those runs already wrote rather
// than pretending it can start one.
//
// Every verdict below is read out of python/clamd/results/*.json, the exact
// documents clamd-python.py writes. None are computed here.
// ---------------------------------------------------------------------------

const INTERVAL = 10000

const VERDICT: Record<'infected' | 'clean' | 'failed', { label: string; color: 'danger' | 'success' | 'warning'; icon: IconName }> = {
  infected: { label: 'Infected', color: 'danger', icon: 'clamd' },
  clean: { label: 'Clean', color: 'success', icon: 'overview' },
  failed: { label: 'Failed', color: 'warning', icon: 'logs' },
}

function CheckRow({ name, ok, detail, advisory }: { name: string; ok: boolean; detail: string; advisory?: boolean }) {
  return (
    <div className="flex items-center justify-between gap-3 rounded-md px-3 py-2 hover:bg-default-50">
      <span className="flex min-w-0 items-center gap-2">
        <Icon
          name={ok ? 'overview' : 'logs'}
          size={12}
          className={ok ? 'text-success' : advisory ? 'text-default-400' : 'text-danger'}
        />
        <span className="truncate text-[11px]">{name}</span>
        {advisory && (
          <span className="shrink-0 rounded border border-default-200 px-1 font-mono text-[9px] text-default-400">
            info
          </span>
        )}
      </span>
      <span className="truncate font-mono text-[10px] text-default-500" title={detail}>
        {detail}
      </span>
    </div>
  )
}

export default function Clamd() {
  const { data: status, error: statusErr } = usePoll(api.clamdStatus, INTERVAL)
  const { data: results, error: resultsErr, refresh } = usePoll(api.clamdResults, INTERVAL)

  const error = statusErr ?? resultsErr
  const counts = results?.counts

  return (
    <>
      <div className="mb-6 flex items-baseline justify-between gap-4">
        <h2 className="page-title">ClamAV</h2>
        <div className="flex items-center gap-3">
          <span className="font-mono text-[11px] text-default-400">guest on the Qiling VM · unix socket</span>
          <Button size="sm" variant="outline" onPress={refresh}>
            Refresh
          </Button>
        </div>
      </div>

      {error && (
        <Alert status="danger" className="mb-4">
          <Alert.Title>Cannot read ClamAV state</Alert.Title>
          <Alert.Description>{error}</Alert.Description>
        </Alert>
      )}

      {!status && !error && (
        <Loading label="Loading ClamAV status…" hint="probing the local clamd socket" />
      )}

      {status && !status.reachable && (
        <Alert status="warning" className="mb-4">
          <Alert.Title>No clamd answering locally</Alert.Title>
          <Alert.Description>{status.note}</Alert.Description>
        </Alert>
      )}

      {status && (
        <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
          <Card className="w-full">
            <Card.Header className="flex items-center justify-between gap-3">
              <Card.Title className="text-sm font-semibold">Daemon</Card.Title>
              <Chip size="sm" variant="soft" color={status.reachable ? 'success' : 'warning'}>
                {status.reachable ? 'answering' : 'not answering locally'}
              </Chip>
            </Card.Header>
            <Card.Content className="flex flex-col gap-2">
              <div className="flex items-baseline justify-between gap-3 border-b border-default-100 py-1.5">
                <span className="text-[11px] text-default-500">Endpoint</span>
                <span className="truncate font-mono text-[11px]" title={status.endpoint}>
                  {status.endpoint}
                </span>
              </div>
              <div className="flex items-baseline justify-between gap-3 border-b border-default-100 py-1.5">
                <span className="text-[11px] text-default-500">Mode</span>
                <span className="font-mono text-[11px]">{status.mode}</span>
              </div>
              <div className="flex items-baseline justify-between gap-3 border-b border-default-100 py-1.5">
                <span className="text-[11px] text-default-500">VM</span>
                <span className="truncate font-mono text-[11px]">
                  {status.vm.host ? `${status.vm.host}@${status.vm.ip}:${status.vm.port}` : 'not configured'}
                </span>
              </div>
              <div className="flex items-baseline justify-between gap-3 py-1.5">
                <span className="text-[11px] text-default-500">Version</span>
                <span className="truncate font-mono text-[11px]" title={status.version}>
                  {status.version || '—'}
                </span>
              </div>
            </Card.Content>
          </Card>

          <Card className="w-full">
            <Card.Header className="flex items-center justify-between">
              <Card.Title className="text-sm font-semibold">
                Connection test
                <span className="ml-2 text-[10px] font-normal text-default-400">
                  mirrors test_clamd_connection.sh
                </span>
              </Card.Title>
            </Card.Header>
            <Card.Content className="flex flex-col gap-0.5">
              {status.checks.map((c) => (
                <CheckRow key={c.name} {...c} />
              ))}
            </Card.Content>
          </Card>
        </div>
      )}

      {counts && (
        <>
          <p className="section-label mb-2 mt-6">Scan results</p>
          <div className="grid grid-cols-3 gap-3">
            <StatTile label="Infected" value={counts.infected} icon={<Icon name="clamd" size={15} />} trendTone="danger" />
            <StatTile label="Clean" value={counts.clean} icon={<Icon name="overview" size={15} />} trendTone="success" />
            <StatTile label="Failed" value={counts.failed} icon={<Icon name="logs" size={15} />} trendTone="warning" />
          </div>
        </>
      )}

      {results && (
        <Card className="mt-3 w-full">
          <Card.Header className="flex items-center justify-between">
            <Card.Title className="truncate text-sm font-semibold">python/clamd/results</Card.Title>
            <span className="font-mono text-[10px] text-default-400">
              {results.file_count} files · {bytes(results.total_bytes, 0)}
            </span>
          </Card.Header>
          <Card.Content>
            {results.files.length === 0 ? (
              <p className="py-6 text-center text-[11px] text-default-400">
                No result files yet. Run <code className="font-mono">scan_remote.py</code> to produce one.
              </p>
            ) : (
              <div className="flex flex-col">
                {results.files.map((r) => (
                  <div
                    key={r.file}
                    className="flex items-center justify-between gap-3 rounded-md px-3 py-2 hover:bg-default-50"
                  >
                    <span className="flex min-w-0 items-center gap-2">
                      <Icon
                        name={VERDICT[r.verdict].icon}
                        size={12}
                        className={
                          r.verdict === 'infected'
                            ? 'text-danger'
                            : r.verdict === 'clean'
                              ? 'text-success'
                              : 'text-default-400'
                        }
                      />
                      <span className="truncate font-mono text-[11px]" title={r.filename || r.file}>
                        {r.filename || r.file}
                      </span>
                    </span>
                    <span className="flex shrink-0 items-center gap-2">
                      {r.signature && (
                        <span className="hidden truncate font-mono text-[10px] text-danger sm:inline" title={r.signature}>
                          {r.signature}
                        </span>
                      )}
                      {r.detail && (
                        <span title={r.detail} className="hidden text-[10px] text-warning md:inline">
                          {r.detail}
                        </span>
                      )}
                      <span className="metric font-mono text-[10px] text-default-400" title={ago(r.modified)}>
                        {r.seconds ? shortDuration(r.seconds) : bytes(r.bytes)}
                      </span>
                      <Chip size="sm" variant="soft" color={VERDICT[r.verdict].color}>
                        {VERDICT[r.verdict].label}
                      </Chip>
                    </span>
                  </div>
                ))}
              </div>
            )}
          </Card.Content>
        </Card>
      )}
    </>
  )
}

