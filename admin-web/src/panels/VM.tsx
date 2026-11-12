import { Chip } from '@heroui/react/chip'
import Icon from '../components/Icon'
import VmListPanel from '../components/VmListPanel'
import { VM_MACHINES, VM_TARGETS, guestsOf, type VmTarget } from '../lib/vms'

// ---------------------------------------------------------------------------
// Virtual Machines - the fleet view.
//
// Two questions, in the order an operator asks them: what is running right now
// (the live VirtualBox inventory), and how is the lab wired (which tools live
// on which machine). ClamAV and the Qiling harness are GUESTS on the Qiling VM,
// reached over SSH, so the wiring is drawn as a tree - a machine with its
// guests nested underneath - rather than as a flat list that implies four peers.
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

const plural = (n: number, word: string) => `${n} ${word}${n === 1 ? '' : 's'}`

function Node({ target, guest = false }: { target: VmTarget; guest?: boolean }) {
  return (
    <div className={`topo-node ${guest ? 'is-guest' : ''} ${target.host ? '' : 'is-unset'}`}>
      <span className="topo-icon"><Icon name={target.icon} size={guest ? 13 : 16} /></span>
      <div className="topo-main">
        <p className="topo-name">{target.label}</p>
        <p className="topo-purpose">{target.purpose}</p>
      </div>
      <div className="topo-meta">
        <span className="topo-kind">{KIND_LABEL[target.kind]}</span>
        <code title={endpoint(target)}>{endpoint(target)}</code>
      </div>
      <Chip size="sm" variant="soft" color={target.host ? 'default' : 'warning'}>
        {target.host ? 'Endpoint set' : 'Setup required'}
      </Chip>
    </div>
  )
}

export default function VM() {
  // The live VirtualBox inventory already lists the Qiling VM with real state;
  // the wiring below is the static registry, so it keeps every machine.
  const machines = VM_MACHINES
  const guests = VM_TARGETS.filter((t) => t.hostedOn)
  const unset = [...machines, ...guests].filter((t) => !t.host).length

  return (
    <div className="fleet-page">
      <header className="fleet-header">
        <div>
          <p className="eyebrow">VIRTUAL MACHINES</p>
          <h1 className="page-title mt-1">Fleet</h1>
          <p className="fleet-lede">
            What is running right now, and how the lab is wired together.
          </p>
        </div>
        <div className="fleet-chips">
          <Chip size="sm" variant="soft">{plural(machines.length, 'machine')}</Chip>
          <Chip size="sm" variant="soft">{plural(guests.length, 'guest')}</Chip>
          {unset > 0 && <Chip size="sm" variant="soft" color="warning">{unset} to set up</Chip>}
        </div>
      </header>

      <section className="fleet-section">
        <VmListPanel />
      </section>

      <section className="fleet-section">
        <div className="fleet-section-head">
          <h2>Topology</h2>
          <p>
            Guests run <em>inside</em> a machine and are reached over SSH.
            ClamAV answers on a unix socket in the guest; Qiling is a systemd{' '}
            <code>oneshot</code> started per sample. Neither listens on a port.
          </p>
        </div>

        <div className="topo">
          {machines.map((machine) => {
            const hosted = guestsOf(machine.id)
            return (
              <div key={machine.id} className="topo-group">
                <Node target={machine} />
                {hosted.length > 0 && (
                  <div className="topo-children">
                    {hosted.map((guest) => (
                      <Node key={guest.id} target={guest} guest />
                    ))}
                  </div>
                )}
              </div>
            )
          })}
        </div>
      </section>
    </div>
  )
}
