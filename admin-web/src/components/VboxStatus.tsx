import { Card, Chip } from '@heroui/react'
import Icon from './Icon'
import { NetStrip } from './NetFacts'
import type { VboxStatus } from '../types'

// ---------------------------------------------------------------------------
// VirtualBox detail.
//
// Everything VirtualBox-specific below the hypervisor roster - which covers
// "is a tool installed, which one, how many machines" for every hypervisor at
// once. What is left here is the part no other tool's row can answer: is this
// the pinned build, is the host-only adapter up, and what is the guest actually
// listening on.
//
// The build identity is worth reading carefully. `sha256` and `pinned` are
// shown side by side rather than a single pass/fail, because "matches" on
// its own tells you nothing when it fails - an operator upgrading VirtualBox
// needs to see which side moved. A mismatched build is reported as a warning,
// never as "not installed": the tool works, it is simply not the one this
// project's checks were written against.
// ---------------------------------------------------------------------------

function Row({ k, v, title }: { k: string; v: React.ReactNode; title?: string }) {
  return (
    <div className="flex items-baseline justify-between gap-3 border-b border-default-100 py-1.5 last:border-0">
      <span className="shrink-0 text-xs text-default-500">{k}</span>
      <span className="min-w-0 truncate font-mono text-xs" title={title}>
        {v}
      </span>
    </div>
  )
}

function Short({ value }: { value: string }) {
  return <>{value.slice(0, 8)}…{value.slice(-8)}</>
}

export default function VboxStatusPanel({ vbox }: { vbox: VboxStatus }) {
  const { digest } = vbox
  const digestTone =
    digest.ok === null ? 'default' : digest.ok ? 'success' : 'warning'
  // Only the ports that answered. Derived rather than filtered inline so the
  // empty state and the grid are reading from one source.
  const open = vbox.vm.services.filter((s) => s.open)

  return (
    <div className="vbox-status flex flex-col gap-3">
      {/* --- build identity ---
          Scoped to what ONLY this card knows. Version, executable and the
          machine list moved to the hypervisor roster, which reports them for
          every tool rather than just this one; repeating them here is how two
          cards drift apart and start disagreeing about how many VMs exist. */}
      <Card className="vbox-status-card vbox-build-card w-full">
        <Card.Header className="vbox-card-header flex items-center justify-between gap-3">
          <Card.Title className="vbox-card-title">VirtualBox build</Card.Title>
          <Chip size="sm" variant="soft" color={digestTone}>
            {digest.ok === null ? 'not checked' : digest.ok ? 'pinned build' : 'build differs'}
          </Chip>
        </Card.Header>
        <Card.Content className="vbox-card-content">
          <div className="grid grid-cols-1 gap-x-10 sm:grid-cols-2">
            <div>
              <Row k="Version" v={vbox.version ?? '—'} />
              <Row
                k="SHA-256"
                v={digest.sha256 ? <Short value={digest.sha256} /> : '—'}
                title={digest.sha256 ?? undefined}
              />
            </div>
            <div>
              <Row
                k="Pinned"
                v={digest.pinned ? <Short value={digest.pinned} /> : '—'}
                title={digest.pinned ?? undefined}
              />
              <Row k="Verified" v={digest.detail || '—'} title={digest.detail} />
            </div>
          </div>

          {!vbox.installed && vbox.error && (
            <p className="mt-2 rounded-md border border-danger/25 bg-danger/5 px-3 py-2 text-[11px] leading-relaxed text-danger">
              {vbox.error}
            </p>
          )}
          {vbox.installed && digest.ok === false && (
            <p className="mt-2 rounded-md border border-warning/25 bg-warning/5 px-3 py-2 text-[11px] leading-relaxed text-warning">
              The installed VBoxManage is not the build this project's checks were
              written against. Everything below still works; the digest is how you
              tell which build you are on.
            </p>
          )}
        </Card.Content>
      </Card>

      <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
        {/* --- host-only --- */}
        <Card className="vbox-status-card w-full">
          <Card.Header className="vbox-card-header flex items-center justify-between gap-3">
            <Card.Title className="vbox-card-title">Host-only adapter</Card.Title>
            <Chip size="sm" variant="soft" color={vbox.hostonly.available ? 'success' : 'default'}>
              {vbox.hostonly.available ? `${vbox.hostonly.count} present` : 'none'}
            </Chip>
          </Card.Header>
          <Card.Content className="vbox-card-content flex flex-col gap-2">
            {vbox.hostonly.available ? (
              <>
                <Row k="Gateway" v={vbox.hostonly.gateway ?? '—'} />
                <Row k="Subnet" v={vbox.hostonly.cidr ?? '—'} />
                {vbox.hostonly.networks.map((n) => (
                  <Row key={n.name} k={n.name} v={n.cidr} />
                ))}
              </>
            ) : (
              <p className="py-2 text-[11px] leading-relaxed text-default-400">
                No host-only network. VMs on the lab network need one - create it
                in VirtualBox, Host-only Networks.
              </p>
            )}
          </Card.Content>
        </Card>

{/* --- guest --- */}
            <Card className="vbox-status-card vbox-guest-card w-full">
              <Card.Header className="vbox-card-header flex items-center justify-between gap-3">
                <Card.Title className="vbox-card-title truncate">
                  {vbox.vm.name ?? 'Analysis VM'}
                  <span className="ml-2 font-mono text-[11px] font-normal text-default-400">
                    guest services
                  </span>
                </Card.Title>
                <Chip
                  size="sm"
                  variant="soft"
                  color={vbox.services_open > 0 ? 'success' : 'default'}
                >
                  {vbox.services_open} listening
                </Chip>
              </Card.Header>
              <Card.Content className="vbox-card-content flex flex-col gap-3">
                {!vbox.vm.configured ? (
                  <p className="py-2 text-[11px] leading-relaxed text-default-400">
                    No <code>qiling_dlls/vm_info.json</code>, so there is no guest to
                    probe. Point the panel at a VM to see its open ports.
                  </p>
                ) : (
                  <>
                    <NetStrip
                      net={{
                        ip: {
                          ip: vbox.vm.ip ?? '',
                          octets: (vbox.vm.ip ?? '').split('.').map((n) => Number(n)).length === 4
                            ? (vbox.vm.ip ?? '').split('.').map(Number)
                            : null,
                          prefix_length: null,
                          cidr: null,
                          network: null,
                          hosts: null,
                          interface: null,
                          interface_index: null,
                          class: null,
                          class_legacy: true,
                          scope: 'private',
                        },
                        port: {
                          port: vbox.vm.port,
                          service: 'ssh',
                          source: 'iana',
                          band: 'well-known',
                          band_meaning: 'Ports 0-1023',
                        },
                      }}
                    />

                    {/* Only ports that actually answered. A grid of ten closed
                        ports on a powered-off guest is indistinguishable from a
                        guest that is up but hardened - both render as em-dashes.
                        Showing the closed candidates on their own was burying the
                        one fact that matters here: whether anything is listening
                        at all. The empty state below says which of the two it is. */}
                    {open.length === 0 ? (
                      <div className="rounded-md border border-default-200 bg-default-100/50 px-3 py-3">
                        <p className="text-[11px] leading-relaxed text-default-500">
                          Nothing listening on any of the {vbox.services_total} probed
                          ports.
                        </p>
                        <p className="mt-1 text-[10.5px] leading-relaxed text-default-400">
                          A powered-off guest and a running-but-hardened one look
                          identical to a port scan. Start the VM and rescan to tell
                          them apart.
                        </p>
                      </div>
                    ) : (
                      <>
                        <div className="grid grid-cols-2 gap-1.5 border-t border-default-100 pt-2 sm:grid-cols-3">
                          {open.map((s) => (
                            <div
                              key={s.port}
                              title={s.detail}
                              className="flex items-center justify-between gap-2 rounded-md bg-success/10 px-2 py-1"
                            >
                              <span className="flex items-center gap-1.5">
                                <Icon name="overview" size={11} className="text-success" />
                                <span className="font-mono text-[11px] uppercase text-foreground">
                                  {s.name}
                                </span>
                              </span>
                              <span className="font-mono text-[10px] tabular-nums text-default-400">
                                {s.port}
                              </span>
                            </div>
                          ))}
                        </div>
                        <p className="font-mono text-[10px] text-default-400">
                          TCP connect only - an open port is listening, not proof the
                          service behind it works.
                        </p>
                      </>
                    )}
                  </>
                )}
              </Card.Content>
            </Card>
      </div>
    </div>
  )
}