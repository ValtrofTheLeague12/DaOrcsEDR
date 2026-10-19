import { useState } from 'react'
import { Card } from '@heroui/react/card'
import { Chip } from '@heroui/react/chip'
import { Alert } from '@heroui/react/alert'
import { api, usePoll } from '../api'
import Icon from '../components/Icon'
import SubNav from '../components/SubNav'
import NetworkMap, { NetworkLegend } from '../components/NetworkMap'
import VirtRoster from '../components/VirtRoster'
import VboxStatusPanel from '../components/VboxStatus'
import Loading from '../components/Loading'
import { ago } from '../lib/format'
import type { NetMap } from '../types'

type NetTab = 'map' | 'interfaces' | 'docker' | 'hypervisors'

function groupHostInterfaces(adapters: NetMap['host_adapters']) {
  const groups = new Map<string, NetMap['host_adapters']>()
  for (const adapter of adapters) {
    const name = adapter.alias || 'Unidentified interface'
    const addresses = groups.get(name) ?? []
    addresses.push(adapter)
    groups.set(name, addresses)
  }
  return [...groups.entries()]
}

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
  const interfaceGroups = data ? groupHostInterfaces(data.host_adapters) : []

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
              <div>
                <Card.Title className="text-sm font-semibold">Host interfaces</Card.Title>
                <p className="mt-1 text-[11px] text-default-500">
                  Addresses grouped by adapter name
                </p>
              </div>
              <Chip size="sm" variant="soft">{data.host_adapters.length} found</Chip>
            </Card.Header>
            <Card.Content>
              {interfaceGroups.length === 0 ? (
                <p className="py-4 text-[12px] text-default-400">No host adapters discovered.</p>
              ) : (
                <div className="interface-inventory-grid">
                  {interfaceGroups.map(([name, addresses]) => (
                    <article className="interface-inventory-card" key={name}>
                      <div className="interface-inventory-heading">
                        <span className="topology-node-icon is-adapter" aria-hidden="true">IF</span>
                        <div className="min-w-0">
                          <h3 className="truncate" title={name}>{name}</h3>
                          <p>{addresses.length} IPv4 address{addresses.length === 1 ? '' : 'es'}</p>
                        </div>
                      </div>
                      <div className="interface-inventory-addresses">
                        {addresses.map((address) => (
                          <div className="interface-inventory-address" key={address.ip}>
                            <code>{address.ip}</code>
                            <Chip
                              size="sm"
                              variant="soft"
                              color={address.loopback ? 'default' : 'success'}
                            >
                              {address.loopback ? 'loopback' : 'host IP'}
                            </Chip>
                          </div>
                        ))}
                      </div>
                    </article>
                  ))}
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
        <section className="docker-inventory" aria-label="Docker network inventory">
          <header className="docker-inventory-header">
            <div>
              <p className="eyebrow">Container networking</p>
              <h2>Docker networks</h2>
              <p>Attached containers and their addresses, grouped by network.</p>
            </div>
            <div className="docker-inventory-total">
              <span className="network-summary-icon"><Icon name="containers" size={15} /></span>
              <div>
                <strong>{data.counts.containers}</strong>
                <span>attached containers</span>
              </div>
            </div>
          </header>
          {data.docker.length === 0 ? (
            <Card className="network-panel-card w-full">
              <Card.Content>
                <p className="docker-empty-title">No Docker networks discovered</p>
                <p className="docker-empty-detail">
                  The daemon may be unavailable, or there may be no networks with attached containers.
                </p>
              </Card.Content>
            </Card>
          ) : (
            <div className="docker-network-grid">
              {data.docker.map((n) => (
                <Card key={n.name} className="docker-network-card w-full">
                  <Card.Header className="docker-network-header flex items-center justify-between gap-3">
                    <div className="flex min-w-0 items-center gap-3">
                      <span className="docker-network-icon" aria-hidden="true">
                        <Icon name="containers" size={17} />
                      </span>
                      <div className="min-w-0">
                        <Card.Title className="truncate font-mono text-sm" title={n.name}>
                          {n.name}
                        </Card.Title>
                        <p className="docker-network-driver">{n.driver || 'bridge'} driver</p>
                      </div>
                    </div>
                    <span className="docker-network-count">
                      <strong>{n.containers.length}</strong>
                      <span>attached</span>
                    </span>
                  </Card.Header>
                  <Card.Content className="docker-network-content">
                    <div className="docker-subnet">
                      <span>Subnet</span>
                      <code>{n.subnet || 'Not reported'}</code>
                    </div>
                    <div className="docker-container-list">
                      <div className="docker-container-list-heading">
                        <span>Container</span>
                        <span>IPv4 address</span>
                      </div>
                      {n.containers.map((c) => (
                        <div className="docker-container-row" key={c.name}>
                          <span className="docker-container-identity">
                            <span className="docker-container-dot" aria-hidden="true" />
                            <span className="truncate font-mono" title={c.name}>{c.name}</span>
                          </span>
                          <code className={c.ip ? '' : 'is-unassigned'}>
                            {c.ip || 'No address'}
                          </code>
                        </div>
                      ))}
                    </div>
                  </Card.Content>
                </Card>
              ))}
            </div>
          )}
        </section>
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
