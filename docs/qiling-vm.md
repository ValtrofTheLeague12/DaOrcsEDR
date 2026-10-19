# Qiling analysis VM

<!-- Source: README.md, split by topic. -->

### Qiling Analysis VM

The Analysis VM connection is configured in `admin-terminal/vms.json`
(`192.168.56.105:22` by default). Set its `username` (the stock VM user is
`qilin`) and, if needed, `identity_file`. Unknown host keys are accepted on
first use (OpenSSH `accept-new`, paramiko `AutoAddPolicy`) and recorded in the
current user's `~/.ssh/known_hosts` (override with `known_hosts_file` in
`vms.json`). Because the CLI runs in BatchMode (no password prompts), the first
connection installs this machine's `~/.ssh/id_ed25519` public key on the VM
using the password from `vms.json` (`password`) or `qiling_dlls/vm_info.json`
(`VM_PASSWORD`); later connections use key login only.

In Admin Terminal → Analysis VMs, choose **q** to collect Windows registry/DLL
files into the local Qiling rootfs (Windows displays a UAC prompt), or **d** to
prepare the rootfs, upload it only if the VM does not already have it, send
`_qiling_script.py` and the selected executable over SFTP, run Qiling over SSH,
and download the result to `qiling_dlls/results/`. If SSH times out, the menu
offers optional, elevated Windows Firewall rules limited to TCP 22/80 and the
`192.168.56.0/24` subnet; it does not change the firewall without confirmation.

The same flow works without the menu:
`py admin-terminal\qiling_upload.py <sample.exe>` packages the local rootfs if
needed, offers to start the VM, uploads the harness and sample (plus the
rootfs when the VM lacks it), runs Qiling with the output streamed live, and
downloads the report to `qiling_dlls/results/<sample>_qiling_out.zip`.
`--timeout`, `--max-insn` and `--no-peb-patch` are forwarded to the harness;
x86 and x64 samples each get their matching rootfs architecture.

`main()` owns the process lifecycle and the stage order; the stages themselves live in `src/main/`. Startup is a fixed sequence:

1. `console::enable_utf8_output()`, `logging::init()` (opens the run-id-scoped log under `logs/`), and the process tracing hooks.
2. `proc::protect_env_var("BW_SESSION")`. This runs before the first child process exists on purpose: marking a variable protected is a process-wide policy, so doing it once here keeps the Bitwarden session token and every CTI key out of all later children.
3. The PDCurses results browser (`curses_ui::session`). Set `STATIC_ANALYZER_CURSES=0` to disable it and get plain terminal output.
4. The local Python API server (`python/api/server.py` via the `py` launcher, CWD `python/`, bound to `127.0.0.1:60000`). It is health-polled with a 10-second startup timeout and serves the MalAPI lookups. A failure here is logged and does not abort the run.

