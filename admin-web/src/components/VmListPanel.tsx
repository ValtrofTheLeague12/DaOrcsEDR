import { useState } from 'react'
import { Card, Chip, Alert } from '@heroui/react'
import { api, usePoll } from '../api'
import Pager, { usePaged } from './Pager'
import type { VmInfo, VmList } from '../types'

// ---------------------------------------------------------------------------
// VirtualBox machines.
//
// The one list on this page with a real chance of being long: a research host
// accumulates VMs, and most of them are not the one you came to look at. So
// every machine gets a row - name, state, address, what is answering on it -
// and the rows are paged rather than scrolled, because a scroll that pushes the
// machine you want below the fold is the problem this is here to solve.
//
// Start and stop live here rather than in the CLI because starting a sandbox is
// a thing you do constantly while debugging why a run failed, and making it a
// terminal detour for every attempt is how people end up with six VMs booted
// at once. The actions are still gated: the backend checks the name against the
// registered machine list before VBoxManage is involved, so the button cannot
// be pointed at anything that is not a real machine on this host.
// ---------------------------------------------------------------------------

const POLL_MS = 10000

function ServiceChips({ vm }: { vm: VmInfo }) {
  const open = vm.services.filter((s) => s.open)
  if (!vm.probed) {
    return (
      <span className="text-[11px] text-default-400">
        {vm.running ? 'no address' : 'not probed'}
      </span>
    )
  }
  if (open.length === 0) {
    return <span className="text-[11px] text-default-400">nothing listening</span>
  }
  return (
    <span className="flex flex-wrap gap-1">
      {open.map((s) => (
        <span
          key={s.port}
          title={`${s.detail} (tcp/${s.port})`}
          className="rounded-full bg-success/12 px-2 py-0.5 font-mono text-[10.5px] text-success"
        >
          {s.name} {s.port}
        </span>
      ))}
    </span>
  )
}

function MachineCard({
  vm,
  busy,
  onAction,
}: {
  vm: VmInfo
  busy: string | null
  onAction: (vm: VmInfo, action: 'start' | 'stop') => void
}) {
  const mine = busy === vm.name
  return (
    <Card className="fleet-vm-card w-full">
      <Card.Header className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <span className={`fleet-vm-indicator ${vm.running ? 'is-running' : ''}`} />
            <Card.Title className="truncate font-mono text-sm" title={vm.name}>
              {vm.name}
            </Card.Title>
            <Chip size="sm" variant="soft" color={vm.running ? 'success' : 'default'}>
              {vm.state}
            </Chip>
          </div>
          <p className="mt-1 truncate text-[11px] text-default-400">{vm.os ?? 'Guest OS not reported'}</p>
        </div>

        {vm.running ? (
          <button
            onClick={() => onAction(vm, 'stop')}
            disabled={busy !== null}
            className="fleet-vm-action stop"
          >
            {mine ? 'Stopping…' : 'Stop VM'}
          </button>
        ) : (
          <button
            onClick={() => onAction(vm, 'start')}
            disabled={busy !== null}
            className="fleet-vm-action start"
          >
            {mine ? 'Starting…' : 'Start VM'}
          </button>
        )}
      </Card.Header>

      <Card.Content className="flex flex-col gap-3">
        <div className="fleet-vm-facts">
          <div><span>Address</span><strong>{vm.ip ?? '—'}</strong></div>
          <div><span>CPU</span><strong>{vm.cpus ? `${vm.cpus} cores` : '—'}</strong></div>
          <div>
            <span>Memory</span>
            <strong>{vm.memory_mb
              ? vm.memory_mb >= 1024
                ? `${(vm.memory_mb / 1024).toFixed(1)} GB`
                : `${vm.memory_mb} MB`
              : '—'}</strong>
          </div>
        </div>

        <div className="fleet-vm-services">
          <span className="eyebrow">Detected services</span>
          <ServiceChips vm={vm} />
        </div>

        <label className="fleet-vm-log-label">
          <span>VM run log</span>
          <span className="font-normal text-default-400">VirtualBox · latest 80 lines</span>
          <textarea
            className="fleet-vm-log"
            aria-label={`VirtualBox run log for ${vm.name}`}
            readOnly
            rows={4}
            value={vm.run_log ?? 'Run log was not returned by the panel.'}
          />
        </label>
      </Card.Content>
    </Card>
  )
}

export default function VmListPanel() {
  const { data, error, refresh } = usePoll<VmList>(api.vms, POLL_MS)
  const paged = usePaged(data?.vms ?? [])
  const [busy, setBusy] = useState<string | null>(null)
  const [notice, setNotice] = useState<{ tone: 'ok' | 'bad'; text: string } | null>(null)

  const onAction = async (vm: VmInfo, action: 'start' | 'stop') => {
    setBusy(vm.name)
    setNotice(null)
    try {
      const res = await api.vmAction(vm.name, action)
      setNotice({ tone: res.ok ? 'ok' : 'bad', text: res.detail })
      refresh()
    } catch (e) {
      const detail = e instanceof Error ? e.message : String(e)
      setNotice({ tone: 'bad', text: detail })
    } finally {
      setBusy(null)
    }
  }

  return (
    <Card className="w-full">
      <Card.Header className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <Card.Title className="text-sm font-semibold">Live VirtualBox fleet</Card.Title>
          <p className="mt-1 text-[11px] text-default-500">
            Paginated inventory, power controls, and this-session action logs.
          </p>
        </div>
        {data?.available && (
          <div className="flex items-center gap-1.5">
            <Chip size="sm" variant="soft" color="success">
              {data.counts.running} running
            </Chip>
            <Chip size="sm" variant="soft">{data.counts.total} registered</Chip>
          </div>
        )}
      </Card.Header>

      <Card.Content className="flex flex-col gap-3">
        {notice && (
          <Alert status={notice.tone === 'ok' ? 'success' : 'danger'}>
            <Alert.Description>{notice.text}</Alert.Description>
          </Alert>
        )}

        {error && (
          <Alert status="danger">
            <Alert.Title>Cannot read machines</Alert.Title>
            <Alert.Description>{error}</Alert.Description>
          </Alert>
        )}

        {data && !data.available && (
          <p className="py-4 text-center text-[12px] text-default-400">
            VirtualBox is not available on this host. {data.error ?? ''}
          </p>
        )}

        {data?.available && data.vms.length === 0 && (
          <p className="py-4 text-center text-[12px] text-default-400">
            No machines registered. Create one in VirtualBox, then rescan.
          </p>
        )}

        {data?.available && data.vms.length > 0 && (
          <div className="fleet-vm-grid">
            {paged.slice.map((vm) => (
              <MachineCard
                key={vm.uuid ?? vm.name}
                vm={vm}
                busy={busy}
                onAction={onAction}
              />
            ))}
          </div>
        )}

        {data?.available && data.vms.length > 0 && (
          <Pager
            page={paged.page}
            pages={paged.pages}
            first={paged.first}
            last={paged.last}
            total={data.vms.length}
            onPrev={paged.prev}
            onNext={paged.next}
          />
        )}
      </Card.Content>
    </Card>
  )
}