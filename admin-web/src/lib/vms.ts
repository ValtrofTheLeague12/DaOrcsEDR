import type { IconName } from '../components/Icon'

// ---------------------------------------------------------------------------
// The virtual-machine fleet.
//
// One registry, and the navigation is generated from it - so bringing a new VM
// online is an entry here, not an edit to the sidebar. That matters because
// this section is going to keep growing: CAPEv2 is already configured in
// admin-terminal/vms.json, and the lab tends to acquire one more sandbox at a
// time.
//
// `host` is empty for a target that is not configured yet. Those render as
// "not configured" rather than silently disappearing, so the gap is visible
// instead of looking like it does not exist.
// ---------------------------------------------------------------------------

export type VmKind = 'ssh' | 'http' | 'tcp' | 'local'

export interface VmTarget {
  id: string
  label: string
  icon: IconName
  kind: VmKind
  /** Runs on a VM rather than being one. ClamAV and the Qiling harness are
   *  guests on the Qiling box, not machines in their own right. */
  hostedOn?: string
  host: string
  port?: number
  username?: string
  path?: string
  /** What this target is for - shown so a new VM is self-explanatory. */
  purpose: string
  slice?: string
}

export const VM_TARGETS: VmTarget[] = [
  {
    id: 'vm',
    label: 'Fleet',
    icon: 'vm',
    kind: 'local',
    host: '',
    purpose: 'Power, endpoints and SSH trust for every machine below',
    slice: 'slice 4',
  },
  // --- machines -----------------------------------------------------------
  {
    id: 'qiling-vm',
    label: 'Qiling VM',
    icon: 'qiling',
    kind: 'ssh',
    host: '192.168.56.105',
    port: 22,
    username: 'qilin',
    purpose: 'CPU-emulation sandbox. VirtualBox host-only 192.168.56.0/24',
    slice: 'slice 4',
  },
  {
    id: 'cape-vm',
    label: 'CAPEv2',
    icon: 'analyze',
    kind: 'http',
    host: '127.0.0.1',
    port: 8090,
    path: '/apiv2/',
    purpose: 'Dynamic sandbox. Windows VM driven over its REST API',
    slice: 'slice 4',
  },
  // --- guests running on a machine ----------------------------------------
  {
    id: 'clamd',
    label: 'ClamAV',
    icon: 'clamd',
    kind: 'local',
    hostedOn: 'qiling-vm',
    host: 'unix:/var/run/clamav/clamd.ctl',
    purpose: 'Signature scanner. Guest on the Qiling VM, reached over SSH',
    slice: 'slice 5',
  },
  {
    id: 'qiling',
    label: 'Qiling',
    icon: 'qiling',
    kind: 'ssh',
    hostedOn: 'qiling-vm',
    host: '192.168.56.105',
    port: 22,
    username: 'qilin',
    purpose: 'PE emulation harness. Guest on the Qiling VM, systemd oneshot',
    slice: 'slice 5',
  },
]

/** Machines only - the fleet list, excluding tools hosted on them. */
export const VM_MACHINES = VM_TARGETS.filter((t) => !t.hostedOn && t.id !== 'vm')

/** Tools hosted on a given machine. */
export function guestsOf(machineId: string): VmTarget[] {
  return VM_TARGETS.filter((t) => t.hostedOn === machineId)
}

export function vmById(id: string): VmTarget | undefined {
  return VM_TARGETS.find((t) => t.id === id)
}