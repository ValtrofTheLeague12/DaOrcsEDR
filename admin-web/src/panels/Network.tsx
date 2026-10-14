import { useState } from 'react'
import { Card, Chip, Alert } from '@heroui/react'
import { api, usePoll } from '../api'
import Icon from '../components/Icon'
import SubNav from '../components/SubNav'
import NetworkMap, { NetworkLegend } from '../components/NetworkMap'
import VirtRoster from '../components/VirtRoster'
import VboxStatusPanel from '../components/VboxStatus'
import Loading from '../components/Loading'
import { ago } from '../lib/format'

type NetTab = 'map' | 'interfaces' | 'docker' | 'hypervisors'

export default function Network() {
  const [tab, setTab] = useState<NetTab>('map')
  // The topology probe shells out to VBoxManage and `docker network inspect`
  // and does a TCP connect per endpoint, so it is slower than the 5s machine
  // poll - 15s keeps it live without hammering the CLI every few seconds.
  const { data, error, refresh } = usePoll(api.netmap, 15000)

  // Compared as booleans rather than inline. TypeScript narrows `tab` inside a
  // single JSX expression, so a second `tab === '...'` further down the same
  // fragment gets flagged as comparing against an already-exhausted literal.
  const isDocker = tab === 'docker'
  const isHypervisors = tab === 'hypervisors'

  return (
    <div className="network-page">
      <header className="network-page-header">
        <div>
          <p className="eyebrow">Infrastructure</p>
          <h1 className="page-title mt-1">Network &amp; fleet</h1>
          <p className="mt-2 max-w-2xl text-xs text-default-500">
            Live view of host interfaces, virtual networks, hypervisors, and connected machines.
          </p>
        </div>
        <div className="network-page-actions">
          {data?.generated_at && (
            <span className="font-mono text-[11px] text-default-400">
              Scanned {ago(data.generated_at)}
            </span>
          )}
          <button
            onClick={refresh}
            className="network-refresh"
          >
            <Icon name="refresh" size={13} />
            Rescan
          </button>
        </div>
      </header>

      <SubNav
        tabs={[
          { id: 'map', label: 'Network map', icon: 'overview' },
          { id: 'interfaces', label: 'Interfaces', icon: 'machine' },
          { id: 'docker', label: 'Docker networks', icon: 'containers' },
          {
            id: 'hypervisors',
            label: 'Hypervisors',
            icon: 'vm',
            // Amber when there is no hypervisor at all, or when the one in use
            // is not the build the checks were written against - both are states
            // an operator wants to see before blaming the VM.
            tone: !data?.virt
              ? undefined
              : data.virt.count === 0
                ? 'bad'
                : data.vbox?.digest.ok === false
                  ? 'warn'
                  : undefined,
          },
        ]}
        active={tab}
        onChange={(id) => setTab(id as NetTab)}
      />

      {error && (
        <Alert status="danger" className="mb-4">
          <Alert.Title>Cannot read network topology</Alert.Title>
          <Alert.Description>{error}</Alert.Description>
        </Alert>
      )}

      {!data && !error && (
        <Loading
          label="Loading network topology…"
          hint="reading host interfaces, VirtualBox networks and Docker bridges"
        />
      )}

      {data && (
        <section className="network-summary-grid" aria-label="Network inventory summary">
          {[
            { label: 'Host adapters', value: data.counts.adapters, icon: 'machine' as const },
            { label: 'Virtual networks', value: data.counts.networks, icon: 'services' as const },
            { label: 'Containers', value: data.counts.containers, icon: 'containers' as const },
            { label: 'Virtual machines', value: data.counts.vms, icon: 'vm' as const },
          ].map((item) => (
            <div className="network-summary-card" key={item.label}>
              <span className="network-summary-icon"><Icon name={item.icon} size={15} /></span>
              <div>
                <p className="eyebrow">{item.label}</p>
                <p className="network-summary-value">{item.value}</p>
              </div>
            </div>
          ))}
        </section>
      )}

      {data && tab === 'map' && (
        <Card className="network-panel-card w-full">
          <Card.Header className="flex flex-wrap items-center justify-between gap-3">
            <Card.Title className="text-sm font-semibold">Connected machines</Card.Title>
            <NetworkLegend />
          </Card.Header>
          <Card.Content className="network-map-content">
            <NetworkMap data={data} />
          </Card.Content>
        </Card>
      )}

      {data && tab === 'interfaces' && (
        <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
          <Card className="network-panel-card w-full">
            <Card.Header className="flex items-center justify-between gap-3">
              <Card.Title className="text-sm font-semibold">Host interfaces</Card.Title>
              <Chip size="sm" variant="soft">{data.host_adapters.length} found</Chip>
            </Card.Header>
            <Card.Content>
              {data.host_adapters.length === 0 ? (
                <p className="py-4 text-[12px] text-default-400">No host adapters discovered.</p>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-[12px]">
                    <thead>
                      <tr className="border-b border-default-200 text-[11px] uppercase tracking-wider text-default-400">
                        <th className="py-2 pr-3 font-medium">IP</th>
                        <th className="py-2 pr-3 font-medium">Interface</th>
                        <th className="py-2 font-medium">Type</th>
                      </tr>
                    </thead>
                    <tbody>
                      {data.host_adapters.map((a) => (
                        <tr key={a.ip} className="border-b border-default-100 last:border-0">
                          <td className="py-2 pr-3 font-mono tabular-nums">{a.ip}</td>
                          <td className="max-w-[220px] truncate py-2 pr-3 text-default-500" title={a.alias}>
                            {a.alias || '—'}
                          </td>
                          <td className="py-2">
                            <Chip size="sm" variant="soft" color={a.loopback ? 'default' : 'success'}>
                              {a.loopback ? 'loopback' : 'lan'}
                            </Chip>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </Card.Content>
          </Card>

          <div className="flex flex-col gap-3">
            <Card className="network-panel-card w-full">
              <Card.Header className="flex items-center justify-between gap-3">
                <Card.Title className="text-sm font-semibold">VirtualBox host-only</Card.Title>
                <Chip size="sm" variant="soft">{data.hostonly.length} net(s)</Chip>
              </Card.Header>
              <Card.Content>
                {data.hostonly.length === 0 ? (
                  <p className="py-4 text-[12px] text-default-400">
                    No host-only networks. VBoxManage missing or no vboxnet configured.
                  </p>
                ) : (
                  <div className="flex flex-col gap-2">
                    {data.hostonly.map((n) => (
                      <div
                        key={n.name}
                        className="flex items-baseline justify-between gap-3 rounded-md border border-default-100 px-3 py-2"
                      >
                        <div className="min-w-0">
                          <p className="truncate font-mono text-[12px]">{n.name}</p>
                          <p className="font-mono text-[11px] text-default-400">
                            {n.cidr} · gw {n.gateway} · mask {n.mask}
                          </p>
                        </div>
                        <Chip size="sm" variant="soft" color="success">up</Chip>
                      </div>
                    ))}
                  </div>
                )}
              </Card.Content>
            </Card>

            {data.qiling_vm && (
              <Card className="network-panel-card w-full">
                <Card.Header className="flex items-center justify-between gap-3">
                  <Card.Title className="truncate text-sm font-semibold">
                    {data.qiling_vm.name}
                  </Card.Title>
                  <Chip
                    size="sm"
                    variant="soft"
                    color={data.qiling_vm.reachable ? 'success' : data.qiling_vm.running ? 'warning' : 'default'}
                  >
                    {data.qiling_vm.reachable
                      ? 'reachable'
                      : data.qiling_vm.running
                        ? 'running · unreachable'
                        : 'down'}
                  </Chip>
                </Card.Header>
                <Card.Content>
                  <div className="flex items-baseline justify-between gap-2 border-b border-default-100 py-1.5">
                    <span className="text-[11px] text-default-500">Address</span>
                    <span className="font-mono text-[11px]">
                      {data.qiling_vm.ip}:{data.qiling_vm.port}
                    </span>
                  </div>
                  <div className="flex items-baseline justify-between gap-2 border-b border-default-100 py-1.5">
                    <span className="text-[11px] text-default-500">Subnet</span>
                    <span className="font-mono text-[11px]">{data.qiling_vm.subnet || '—'}</span>
                  </div>
                  <div className="flex items-baseline justify-between gap-2 py-1.5">
                    <span className="text-[11px] text-default-500">Registered</span>
                    <span className="font-mono text-[11px]">
                      {String(data.qiling_vm.registered)}
                    </span>
                  </div>
                </Card.Content>
              </Card>
            )}
          </div>
        </div>
      )}

      {data && isDocker && (
        <div>
          {data.docker.length === 0 ? (
            <Card className="network-panel-card w-full">
              <Card.Content>
                <p className="py-4 text-[12px] text-default-400">
                  No Docker networks with containers. Daemon down or nothing attached.
                </p>
              </Card.Content>
            </Card>
          ) : (
            <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
              {data.docker.map((n) => (
                <Card key={n.name} className="network-panel-card w-full">
                  <Card.Header className="flex items-center justify-between gap-3">
                    <Card.Title className="truncate font-mono text-sm" title={n.name}>
                      {n.name}
                    </Card.Title>
                    <Chip size="sm" variant="soft">
                      {n.containers.length} container(s)
                    </Chip>
                  </Card.Header>
                  <Card.Content>
                    <p className="mb-2 font-mono text-[11px] text-default-400">
                      {n.driver || 'bridge'} · {n.subnet || 'no subnet'}
                    </p>
                    <div className="overflow-x-auto">
                      <table className="w-full text-left text-[12px]">
                        <thead>
                          <tr className="border-b border-default-200 text-[11px] uppercase tracking-wider text-default-400">
                            <th className="py-1.5 pr-3 font-medium">Container</th>
                            <th className="py-1.5 font-medium">IP</th>
                          </tr>
                        </thead>
                        <tbody>
                          {n.containers.map((c) => (
                            <tr key={c.name} className="border-b border-default-100 last:border-0">
                              <td className="max-w-[200px] truncate py-1.5 pr-3 font-mono" title={c.name}>
                                {c.name}
                              </td>
                              <td className="py-1.5 font-mono tabular-nums text-default-500">
                                {c.ip || '—'}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </Card.Content>
                </Card>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Hypervisor detection first, then the VirtualBox-specific detail below
          it. The roster is the general answer - "is this even a VirtualBox
          box" - and it has to come before "which build of VirtualBox", because
          on a host with no hypervisor the second question has no answer. */}
      {data && isHypervisors && (
        <div className="flex flex-col gap-3">
          <VirtRoster virt={data.virt} />

          {/* Only when VirtualBox is the tool actually present. QEMU and VMware
              have no `showvminfo` equivalent behind one shared interface here,
              and an empty machine table under a roster that says "QEMU" reads
              as "this lab has no machines" - which would be a lie. */}

          {data.vbox ? (
            <VboxStatusPanel vbox={data.vbox} />
          ) : (
            <Card className="network-panel-card w-full">
              <Card.Content>
                <p className="py-6 text-center text-[12px] text-default-400">
                  VirtualBox status was not returned by the panel.
                </p>
              </Card.Content>
            </Card>
          )}
        </div>
      )}
    </div>
  )
}
