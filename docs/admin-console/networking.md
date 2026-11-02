# Networking

<!-- Source: README.md, split by topic. -->

#### Networking

`GET /api/netmap` builds a node/link graph of the host, its adapters, its
VirtualBox host-only network, its Docker bridges and the Qiling VM. A node is
`up` because a TCP connect to it answered, not because a config file says so. A
missing Docker daemon or a missing VirtualBox yields fewer nodes, never a 500.

Hypervisor auto-detection (`python/panel/network/virt.py`) is reported alongside it,
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
snapshot. Start is headless. The graph itself changes nothing else: the
Configuration tab below is where this page writes settings.

Power control itself is not reimplemented here. Names, running state, start and
stop come from `python/qiling/_check_vm_connection.py`, and the port list and
TCP probe come from `python/panel/network/netmap.py`, so the machine list and the
network map cannot disagree about what "SSH is open" means. `showvminfo` is the
only thing this layer adds, because it is what turns a name into an address.

#### Configuration tab — service endpoints and the agent

`GET /api/network/endpoints` feeds the **Configuration** tab, the panel's half of
`admin-terminal/netcfg.py` and the one place on this page that writes rather than
reports.

Only the **Analyzer API** is editable. `server.py` reads `SA_API_HOST` /
`SA_API_PORT` from `.env` itself, so a save moves the service the panel probes.
MalAPI and the ML scorer are launched *by every analysis* at compiled addresses
(`http://127.0.0.1:60000` and `:60010`, `src/main.cpp`). The tab therefore shows
the compiled address and the reason it is not editable — a form that moved them
would describe a change the next run discards.

`PUT /api/network/endpoints/<key>` validates before it writes anything:

- an IP literal must be on one of this host's interfaces (`ifaddr`), because an
  address an adapter is not currently carrying saves fine and then fails to
  bind. `localhost` and DNS-shaped names are accepted, but a name is not
  resolved, and the response says so;
- the port must be in 1–65535, not another watched service's, and must pass a
  real `socket.bind()` on the address the launcher would use (`0.0.0.0` for a
  non-loopback host). The service's own current port is exempt, or "keep the
  port, change the host" could never be saved. A `409 port-held` names the
  process holding it;
- an off-loopback save states, before it happens, that the bind widens to
  `0.0.0.0` and that the Analyzer API has no authentication.

With restart enabled the running service is stopped **before** `.env` is
written, because the stop path finds its listener by the port still in the file;
writing first would leave the old process on a port the panel no longer knows
about. A failed stop aborts the save (`409 stop-failed`). The first write copies
the previous file to `.env.bak` and every other line is preserved.

Process environment beats `.env` in `config.setting()`, so a key exported before
the panel started would make the save look ineffective. The response then says
`saved-shadowed`, names the keys, and does not restart.

The same tab owns the endpoint agent's broker and topic
(`PUT /api/network/agent`). Kafka is the agent's only transport, so there is no
transport picker. An IP literal must again be one of this host's addresses — the
broker runs here, and a remote agent can only reach an address this host has —
while broker reachability and a non-default port are warnings, not refusals,
because configuring a stopped broker is a normal setup step. Saving writes
`AGENT_KAFKA_BROKERS` / `AGENT_KAFKA_TOPIC` into `.env` and returns a filled
`agent.json` template. The panel cannot push that file to installed agents; it is
downloaded and copied beside the agent executable on each endpoint.

