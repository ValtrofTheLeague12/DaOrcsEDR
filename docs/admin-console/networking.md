# Networking

<!-- Source: README.md, split by topic. -->

#### Networking

`GET /api/netmap` builds a node/link graph of the host, its adapters, its
VirtualBox host-only network, its Docker bridges and the Qiling VM. A node is
`up` because a TCP connect to it answered, not because a config file says so. A
missing Docker daemon or a missing VirtualBox yields fewer nodes, never a 500.

Hypervisor auto-detection (`python/panel/virt.py`) is reported alongside it,
under `virt`. It probes VirtualBox, QEMU, VMware Workstation and Hyper-V and
reports all four whether or not they are present, because "QEMU is not on this
box" is the answer you want and silence is not. Detection is evidence-based: a
tool counts as installed only if its binary exists *and* prints a version
banner, so a leftover Program Files directory does not report a working
hypervisor. Hyper-V is detected by its `vmms` service rather than by
`vmcompute.exe`, which ships with Windows whether or not the role is enabled.
Results are cached for 30 s.

The **Hypervisors** tab then reports:

- the roster above, one row per tool, absent ones dimmed with the reason they
  were ruled out;
- every registered VirtualBox machine from `GET /api/vms` — name, power state,
  guest address, MAC, CPU/RAM, and the services actually answering on it, one
  `showvminfo` per machine, paginated because a research host accumulates VMs;
- `POST /api/vms/start` and `POST /api/vms/stop`.

The machine name travels in the request **body**, not the path: a VirtualBox
name is free text that can contain slashes and spaces. It is checked against the
registered machine list before VBoxManage is involved, so the buttons cannot be
pointed at anything that is not a real machine on this host. `stop` is a hard
poweroff rather than an ACPI shutdown — malware in the guest can ignore a power
button, and a sandbox that will not power down is worse than one that loses a
snapshot. Start is headless. This is the only part of the panel that changes
state; everything else reports what already exists.

Power control itself is not reimplemented here. Names, running state, start and
stop come from `python/qiling/_check_vm_connection.py`, and the port list and
TCP probe come from `python/panel/netmap.py`, so the machine list and the
network map cannot disagree about what "SSH is open" means. `showvminfo` is the
only thing this layer adds, because it is what turns a name into an address.

