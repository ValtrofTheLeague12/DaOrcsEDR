#!/usr/bin/env python3
"""Host-side remote scan: deploy a local sample to the analysis VM, run
clamd-python.py inside it against clamd, and bring the result JSON back.

Rebuilds the "deploy -> run -> collect" half of the qiling-style flow that
used to live in _configure_clamd.py (only its .pyc is left in __pycache__).

Usage:
    python scan_remote.py SAMPLE [--vm-info PATH] [--timeout S] [--keep]

    python scan_remote.py "C:\\Program Files (x86)\\EasyAntiCheat_EOS\\EasyAntiCheat_EOS.exe"

Requires: pip install paramiko   (already in python/.venv)
Exit codes: 0 scan ok (clean OR infected), 1 deploy/run/collection failed.
"""

import argparse
import datetime
import json
import pathlib
import sys
import time

HERE = pathlib.Path(__file__).resolve().parent
DEFAULT_VM_INFO = HERE / "vm_info.json"
LOCAL_RESULTS = HERE / "results"
LOCAL_SCANNER = HERE / "clamd-python.py"

EXIT_OK = 0
EXIT_FAIL = 1

try:
    import paramiko
except ImportError:
    print("[-] paramiko not installed (pip install paramiko)", file=sys.stderr)
    sys.exit(EXIT_FAIL)


def log(msg):
    print(msg, flush=True)


class Vm:
    """One SSH session to the analysis VM, reused for every step."""

    def __init__(self, info):
        self.host = str(info.get("VM_IP", "")).strip()
        self.user = str(info.get("VM_HOST", "")).strip()
        self.password = str(info.get("VM_PASSWORD", "") or "")
        try:
            self.port = int(info.get("VM_PORT", 22) or 22)
        except (TypeError, ValueError) as exc:
            raise RuntimeError("VM_PORT must be an integer") from exc
        self.client = paramiko.SSHClient()
        self.client.load_system_host_keys()
        project_keys = HERE / "known_hosts.ssh"
        if project_keys.exists():
            self.client.load_host_keys(str(project_keys.resolve()))
        self.client.set_missing_host_key_policy(paramiko.RejectPolicy())

    def connect(self):
        try:
            self.client.connect(hostname=self.host, username=self.user,
                                port=self.port, password=self.password,
                                timeout=10)
        except paramiko.ssh_exception.AuthenticationException as exc:
            raise RuntimeError(
                f"SSH authentication failed for {self.user}@{self.host}: {exc}"
            ) from exc
        except paramiko.SSHException as exc:
            raise RuntimeError(
                f"SSH to {self.user}@{self.host}:{self.port} failed: {exc}; if "
                "the host key is unknown, add it with: "
                f"ssh-keyscan -p {self.port} {self.host} >> {HERE / 'known_hosts.ssh'}"
            ) from exc
        log(f"[+] SSH connected to {self.user}@{self.host}:{self.port}")

    def close(self):
        self.client.close()

    def run(self, cmd, timeout=300):
        log(f"[*] $ {cmd}")
        stdin, stdout, stderr = self.client.exec_command(cmd, timeout=timeout)
        # sudo -S reads the password from stdin; harmless when no sudo is used
        if "sudo " in cmd:
            stdin.write(self.password + "\n")
            stdin.flush()
        stdin.channel.shutdown_write()
        out = stdout.read().decode("utf-8", "replace")
        err = stderr.read().decode("utf-8", "replace")
        code = stdout.channel.recv_exit_status()
        if out.strip():
            for line in out.rstrip().splitlines():
                log("    " + line)
        if err.strip() and code != 0:
            for line in err.rstrip().splitlines():
                log("    ! " + line)
        return code, out, err

    @staticmethod
    def _ensure_dir(sftp, posix_dir: str):
        p = pathlib.PurePosixPath(posix_dir)
        cur = pathlib.PurePosixPath(p.anchor or "/")
        for part in p.parts[1:]:
            cur = cur / part
            try:
                sftp.stat(str(cur))
            except IOError:
                try:
                    sftp.mkdir(str(cur))
                except IOError:
                    pass  # raced with another client, or no permission

    def upload(self, local: pathlib.Path, remote: str):
        sftp = self.client.open_sftp()
        try:
            self._ensure_dir(sftp, str(pathlib.PurePosixPath(remote).parent))
            sftp.put(str(local), remote)
        finally:
            sftp.close()
        log(f"[+] uploaded {local.name} -> {remote}")

    def download(self, remote: str, local: pathlib.Path):
        local.parent.mkdir(parents=True, exist_ok=True)
        sftp = self.client.open_sftp()
        try:
            sftp.get(remote, str(local))
        finally:
            sftp.close()
        log(f"[+] recovered {local.name}")


def scanner_args(clamd_cfg: dict, mode: str) -> str:
    if mode == "tcp":
        return "--mode tcp --host %s --port %d --timeout %s" % (
            clamd_cfg.get("host", "127.0.0.1"),
            int(clamd_cfg.get("port", 3310)),
            clamd_cfg.get("timeout", 60))
    return "--mode unix --socket %s --timeout %s" % (
        clamd_cfg.get("socket", "/var/run/clamav/clamd.ctl"),
        clamd_cfg.get("timeout", 60))


def ensure_daemon(vm, python: str, scanner_remote: str, clamd_cfg: dict,
                  base: str) -> str:
    """Return endpoint flags for a reachable clamd, starting a user-space
    daemon first when the configured one is down (the VM account has no sudo,
    so /var/run/clamav/clamd.ctl cannot be created by us)."""
    mode = str(clamd_cfg.get("mode", "unix")).strip() or "unix"
    flags = scanner_args(clamd_cfg, mode)

    code, _, _ = vm.run(f"{python} {scanner_remote} dummy --check {flags} --json",
                        timeout=60)
    if code == 0:
        log("[+] clamd reachable with the configured endpoint")
        return flags

    log("[!] configured clamd endpoint is down - starting a user-space clamd")
    user_sock = f"{base}/clamd.sock"
    user_conf = f"{base}/clamd-user.conf"
    config = (
        "# user-space clamd started by scan_remote.py (no sudo in the VM)\n"
        f"LocalSocket {user_sock}\n"
        f"PidFile {base}/clamd.pid\n"
        f"LogFile {base}/clamd.log\n"
        "DatabaseDirectory /var/lib/clamav\n"
        "MaxThreads 12\n"
        "StreamMaxLength 25M\n"
        "FixStaleSocket true\n"
        "LogVerbose false\n"
    )
    conf_remote = pathlib.PurePosixPath(user_conf)
    tmp = pathlib.Path(vm.workdir) / "clamd-user.conf"
    tmp.write_text(config, encoding="utf-8")
    vm.upload(tmp, str(conf_remote))
    tmp.unlink(missing_ok=True)

    vm.run(f"rm -f -- {user_sock} {base}/clamd.pid")
    code, out, err = vm.run(
        f"nohup clamd --config-file={user_conf} >/dev/null 2>&1 & sleep 3; "
        f"test -S {user_sock} && echo SOCKET_UP", timeout=120)
    if code != 0 or "SOCKET_UP" not in out:
        tail = vm.run(f"tail -5 {base}/clamd.log")[2] if False else ""
        raise RuntimeError(
            "user-space clamd did not come up "
            f"(exit={code}); see {base}/clamd.log - {err.strip() or out.strip()}")

    flags = scanner_args({**clamd_cfg, "mode": "unix", "socket": user_sock}, "unix")
    code, _, _ = vm.run(f"{python} {scanner_remote} dummy --check {flags} --json",
                        timeout=60)
    if code != 0:
        raise RuntimeError("user-space clamd started but still not answering PING")
    log(f"[+] clamd up on {user_sock}")
    return flags


def main() -> int:
    ap = argparse.ArgumentParser(
        description="deploy a local sample to the analysis VM and scan it with clamd")
    ap.add_argument("sample", help="absolute path of the sample on THIS host")
    ap.add_argument("--vm-info", default=str(DEFAULT_VM_INFO))
    ap.add_argument("--mode", choices=("unix", "tcp"), default=None,
                    help="override vm_info clamd.mode")
    ap.add_argument("--no-update", action="store_true",
                    help="skip freshclam (signature DB update) before the scan")
    args = ap.parse_args()

    sample = pathlib.Path(args.sample).expanduser()
    if not sample.is_file():
        print(f"[-] sample not found: {sample}", file=sys.stderr)
        return EXIT_FAIL
    if not LOCAL_SCANNER.is_file():
        print(f"[-] scanner missing: {LOCAL_SCANNER}", file=sys.stderr)
        return EXIT_FAIL

    try:
        info = json.loads(pathlib.Path(args.vm_info).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"[-] cannot read vm_info.json: {exc}", file=sys.stderr)
        return EXIT_FAIL

    paths = info.get("paths") or {}
    clamd_cfg = info.get("clamd") or {}
    remote_samples = str(paths.get("samples", "")).strip()
    remote_results = str(paths.get("results", "")).strip()
    remote_script = str(paths.get("script", "")).strip()
    python = str(info.get("python", "python3")).strip() or "python3"
    mode = args.mode or str(clamd_cfg.get("mode", "unix")).strip() or "unix"
    if not (remote_samples and remote_results and remote_script):
        print("[-] vm_info.json: paths.samples / paths.results / paths.script "
              "are required", file=sys.stderr)
        return EXIT_FAIL

    stamp = datetime.datetime.now().strftime("%Y%m%dT%H%M%S")
    remote_sample = f"{remote_samples}/{sample.name}"
    remote_out = f"{remote_results}/{sample.stem}_{stamp}.json"
    local_out = LOCAL_RESULTS / pathlib.Path(remote_out).name

    vm = Vm(info)
    started = time.perf_counter()
    try:
        vm.connect()

        # 1. layout
        for d in (remote_samples, remote_results):
            code, _, err = vm.run(f"mkdir -p -m 700 -- {d}")
            if code != 0:
                raise RuntimeError(f"cannot create {d}: {err.strip()}")

        # 2. keep the in-VM scanner in sync with the local copy
        vm.upload(LOCAL_SCANNER, remote_script)

        # 2b. the in-VM scanner needs the `clamd` pip module
        code, _, _ = vm.run(f'{python} -c "import clamd"')
        if code != 0:
            log("[*] installing the clamd python module inside the VM ...")
            code, _, err = vm.run(
                f"{python} -m pip install --user --break-system-packages clamd "
                f"2>/dev/null || {python} -m pip install --user clamd")
            if code != 0:
                raise RuntimeError("cannot install the clamd module inside "
                                   f"the VM: {err.strip()}")
            log("[+] clamd module installed for the VM user")

        # 3. signature DB freshness (unless skipped)
        if not args.no_update:
            code, out, err = vm.run("sudo -n freshclam --quiet", timeout=600)
            if code != 0:
                log("[!] freshclam skipped (no passwordless sudo) - "
                    "scan runs on the installed signature DB")

        # 4. deploy the sample
        vm.upload(sample, remote_sample)

        # 5. run the scan inside the VM
        cmd = (f"{python} {remote_script} {remote_sample} "
               f"--results-dir {remote_results} --out {remote_out} "
               f"{scanner_args(clamd_cfg, mode)} --json")
        code, out, err = vm.run(cmd, timeout=600)

        # 6. bring the result home
        try:
            vm.download(remote_out, local_out)
        except (IOError, OSError) as exc:
            raise RuntimeError(
                f"scan produced no result file on the VM ({exc}); "
                f"scanner exit={code}, stderr={err.strip()!r}") from exc
    except (RuntimeError, OSError, paramiko.SSHException) as exc:
        print(f"[-] {exc}", file=sys.stderr)
        return EXIT_FAIL
    finally:
        vm.close()

    try:
        doc = json.loads(local_out.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"[-] result file unreadable: {exc}", file=sys.stderr)
        return EXIT_FAIL

    verdict = doc.get("verdict", "?")
    log("")
    log("=" * 68)
    log(f"  sample    : {doc.get('filename', sample.name)}")
    log(f"  sha256    : {doc.get('sha256', '?')}")
    log(f"  endpoint  : {doc.get('endpoint', '?')} (in-VM)")
    log(f"  clamd     : {doc.get('clamd_version', '?')}")
    log(f"  verdict   : {verdict.upper()}"
        + (f"  ({doc.get('signature')})" if doc.get("signature") else ""))
    log(f"  scanned in: {doc.get('seconds', '?')} s")
    log(f"  result    : {local_out}")
    log(f"  wall time : {time.perf_counter() - started:.1f} s")
    log("=" * 68)

    if verdict in ("clean", "infected"):
        return EXIT_OK
    print(f"[-] scan error: {doc.get('detail') or doc.get('error')}",
          file=sys.stderr)
    return EXIT_FAIL


if __name__ == "__main__":
    sys.exit(main())
