import { Card, Chip, Alert } from '@heroui/react'
import Icon from '../components/Icon'
import VmListPanel from '../components/VmListPanel'
import { VM_MACHINES, VM_TARGETS, guestsOf, type VmTarget } from '../lib/vms'

// ---------------------------------------------------------------------------
// Virtual Machines - the fleet view.
//
// This section exists because the lab's tools and the lab's machines are not
// separate concerns: ClamAV and the Qiling harness are GUESTS on the Qiling VM,
// reached over SSH, not services and not machines. Showing them beside the
// machines that host them is the honest arrangement; a flat list of "VM, CAPE,
// ClamAV, Qiling" implies four peers and hides where anything actually runs.
//
// Adding a machine is an entry in lib/vms.ts - nothing here changes.
// ---------------------------------------------------------------------------

const KIND_LABEL: Record<VmTarget['kind'], string> = {
  ssh: 'SSH',
  http: 'HTTP',
  tcp: 'TCP',
  local: 'local',
}

function endpoint(t: VmTarget): string {
  if (!t.host) return 'not configured'
  if (t.kind === 'local') return t.host
  const base = `${t.kind}://${t.host}${t.port ? `:${t.port}` : ''}${t.path ?? ''}`
  return t.username ? `${t.username}@${base.replace(`${t.kind}://`, '')}` : base
}

function MachineCard({ vm }: { vm: VmTarget }) {
  const guests = guestsOf(vm.id)
  return (
    <Card className="w-full">
      <Card.Header className="flex items-start justify-between gap-3">
        <div className="flex min-w-0 items-center gap-2.5">
          <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-default-100 text-default-600">
            <Icon name={vm.icon} size={16} />
          </span>
          <div className="min-w-0">
            <Card.Title className="truncate text-sm font-semibold">{vm.label}</Card.Title>
            <p className="truncate text-[11px] text-default-400">{vm.purpose}</p>
          </div>
        </div>
        <Chip size="sm" variant="soft" color={vm.slice ? 'warning' : 'default'}>
          {vm.slice ?? KIND_LABEL[vm.kind]}
        </Chip>
      </Card.Header>

      <Card.Content className="flex flex-col gap-3">
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="rounded border border-default-200 px-1.5 py-0.5 font-mono text-[10px] text-default-500">
            {KIND_LABEL[vm.kind]}
          </span>
          <span className="truncate font-mono text-[11px] text-default-500">
            {endpoint(vm)}
          </span>
        </div>

        {guests.length > 0 && (
          <div className="border-t border-default-100 pt-2.5">
            <p className="eyebrow mb-1.5">runs on this machine</p>
            <div className="flex flex-col gap-1">
              {guests.map((g) => (
                <div key={g.id} className="flex items-center justify-between gap-2">
                  <span className="flex min-w-0 items-center gap-1.5">
                    <Icon name={g.icon} size={12} className="text-default-400" />
                    <span className="truncate text-[11px] text-default-600">{g.label}</span>
                  </span>
                  <span className="shrink-0 font-mono text-[10px] text-default-400">
                    {g.host.split('/').pop() || g.kind}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}
      </Card.Content>
    </Card>
  )
}

export default function VM() {
  const machines = VM_MACHINES
  const guests = VM_TARGETS.filter((t) => t.hostedOn)

  return (
    <>
      <div className="mb-6 flex items-baseline justify-between gap-4">
        <h1 className="page-title">Virtual Machines</h1>
        <Chip size="sm" variant="soft">
          {machines.length} machines · {guests.length} guests
        </Chip>
      </div>

      <Alert status="accent" className="mb-4">
        <Alert.Title>Tools and machines are not peers</Alert.Title>
        <Alert.Description>
          ClamAV and the Qiling harness are guests on the Qiling VM, reached over
          SSH — not services and not machines of their own. Neither listens on a
          port: clamd answers on a unix socket inside the guest and Qiling is a
          systemd <code>oneshot</code> started per sample.
        </Alert.Description>
      </Alert>

      <section className="mb-6">
        <VmListPanel />
      </section>

      <p className="section-label mb-2">Configured endpoints</p>
      <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-3">
        {machines.map((vm) => (
          <MachineCard key={vm.id} vm={vm} />
        ))}
      </div>

      <p className="section-label mb-2 mt-6">Guests</p>
      <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-3">
        {guests.map((g) => (
          <Card key={g.id} className="w-full">
            <Card.Header className="flex items-start justify-between gap-3">
              <div className="flex min-w-0 items-center gap-2.5">
                <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-default-100 text-default-600">
                  <Icon name={g.icon} size={16} />
                </span>
                <div className="min-w-0">
                  <Card.Title className="truncate text-sm font-semibold">{g.label}</Card.Title>
                  <p className="truncate text-[11px] text-default-400">{g.purpose}</p>
                </div>
              </div>
              <Chip size="sm" variant="soft" color="warning">
                {g.slice}
              </Chip>
            </Card.Header>
            <Card.Content>
              <div className="flex flex-wrap items-center gap-1.5">
                <span className="rounded border border-default-200 px-1.5 py-0.5 font-mono text-[10px] text-default-500">
                  {KIND_LABEL[g.kind]}
                </span>
                <span className="truncate font-mono text-[11px] text-default-500">
                  {endpoint(g)}
                </span>
              </div>
              {g.hostedOn && (
                <p className="mt-2 text-[11px] text-default-400">
                  hosted on{' '}
                  <span className="text-default-600">
                    {VM_TARGETS.find((t) => t.id === g.hostedOn)?.label}
                  </span>
                </p>
              )}
            </Card.Content>
          </Card>
        ))}
      </div>
    </>
  )
}