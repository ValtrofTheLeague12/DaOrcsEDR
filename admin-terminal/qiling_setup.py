"""Prepare a Qiling rootfs, deploy a sample to the Analysis VM, and run it."""
from __future__ import annotations

import base64
import ipaddress
import os
import re
import shlex
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path, PurePosixPath

import core

QILING_DIR = Path(core.REPO) / "qiling_dlls"
COLLECTOR = QILING_DIR / "dll_collector.bat"
SCRIPT = QILING_DIR / "_qiling_script.py"
ARCHIVE = QILING_DIR / "rootfs.tar.gz"
ROOTFS = QILING_DIR / "examples" / "rootfs"
RESULTS = QILING_DIR / "results"
KNOWN_VM_NETWORK = ipaddress.ip_network("192.168.56.0/24")


class QilingSetupError(RuntimeError):
    """Raised when rootfs collection or remote deployment cannot complete."""


def _ps_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _run_elevated(script: str) -> int:
    encoded_child = base64.b64encode(script.encode("utf-16le")).decode("ascii")
    child_args = ",".join(_ps_quote(part) for part in (
        "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded_child))
    wrapper = (
        f"$p = Start-Process -FilePath 'powershell.exe' "
        f"-ArgumentList @({child_args}) -Verb RunAs -Wait -PassThru; "
        "exit $p.ExitCode"
    )
    powershell = shutil.which("powershell") or "powershell.exe"
    result = subprocess.run(
        [powershell, "-NoProfile", "-NonInteractive", "-Command", wrapper],
        check=False,
    )
    return result.returncode


def rootfs_exists() -> bool:
    for arch in ("x86_windows", "x8664_windows"):
        windows = ROOTFS / arch / "Windows"
        system32 = windows / "System32"
        if not (system32.is_dir() and (system32 / "kernel32.dll").is_file()
                and (system32 / "ntdll.dll").is_file()
                and (windows / "registry" / "SYSTEM").is_file()):
            return False
    return True


def _archive_is_current() -> bool:
    if not ARCHIVE.is_file() or not rootfs_exists():
        return False
    newest = max(path.stat().st_mtime for arch in ("x86_windows", "x8664_windows")
                 for path in (ROOTFS / arch).rglob("*") if path.is_file())
    return ARCHIVE.stat().st_mtime >= newest


def _package_rootfs() -> None:
    if not rootfs_exists():
        raise QilingSetupError("both x86 and x64 rootfs directories are required")
    if _archive_is_current():
        print("  rootfs archive is current")
        return

    fd, temp_name = tempfile.mkstemp(
        prefix="rootfs-", suffix=".tar.gz", dir=str(QILING_DIR))
    os.close(fd)
    temp_path = Path(temp_name)
    try:
        with tarfile.open(temp_path, "w:gz") as archive:
            archive.add(QILING_DIR / "examples", arcname="examples")
        os.replace(temp_path, ARCHIVE)
    finally:
        if temp_path.exists():
            temp_path.unlink()
    print(f"  packaged rootfs: {ARCHIVE.name}")


def _run_elevated_collector() -> None:
    if not COLLECTOR.is_file():
        raise QilingSetupError(f"collector not found: {COLLECTOR}")
    batch_command = f'""{COLLECTOR}""'
    script = (
        "$p = Start-Process -FilePath $env:ComSpec "
        f"-ArgumentList @('/d','/s','/c',{_ps_quote(batch_command)}) "
        f"-WorkingDirectory {_ps_quote(str(QILING_DIR))} "
        "-Verb RunAs -Wait -PassThru; exit $p.ExitCode"
    )
    result = subprocess.run(
        [shutil.which("powershell") or "powershell.exe",
         "-NoProfile", "-NonInteractive", "-Command", script],
        cwd=str(QILING_DIR), check=False,
    )
    if result.returncode:
        raise QilingSetupError(
            "elevated DLL collector failed or its UAC prompt was declined "
            f"(exit {result.returncode})")
    if not rootfs_exists():
        raise QilingSetupError(
            "collector completed but did not create both rootfs System32 trees")


def setup_rootfs() -> None:
    """Collect Windows DLLs with a UAC prompt when rootfs is absent, then tar it."""
    if not rootfs_exists():
        _run_elevated_collector()
    _package_rootfs()


def network_blocked(error: BaseException) -> bool:
    text = str(error).lower()
    return any(marker in text for marker in (
        "timed out", "no route to host", "network is unreachable",
        "host is unreachable", "connection timed out",
    ))


def allow_vm_subnet_firewall() -> None:
    """Ask for elevation to allow only HTTP/SSH to the Analysis VM subnet."""
    script = (
        "$ErrorActionPreference = 'Stop'; "
        "$names = @('IAProject Analysis VM SSH-HTTP In', "
        "'IAProject Analysis VM SSH-HTTP Out'); "
        "Get-NetFirewallRule -DisplayName $names -ErrorAction SilentlyContinue "
        "| Remove-NetFirewallRule; "
        "New-NetFirewallRule -DisplayName $names[0] -Direction Inbound "
        "-Action Allow -Protocol TCP -LocalPort 22,80 "
        "-RemoteAddress 192.168.56.0/24 -Profile Any | Out-Null; "
        "New-NetFirewallRule -DisplayName $names[1] -Direction Outbound "
        "-Action Allow -Protocol TCP -RemotePort 22,80 "
        "-RemoteAddress 192.168.56.0/24 -Profile Any | Out-Null"
    )
    if _run_elevated(script):
        raise QilingSetupError(
            "could not create the scoped HTTP/SSH firewall rules "
            f"(exit {result.returncode})")


def _remote_settings(config: dict) -> tuple[str, str, int, PurePosixPath]:
    host = str(config.get("host", "")).strip()
    try:
        address = ipaddress.ip_address(host)
    except ValueError as exc:
        raise QilingSetupError(f"invalid Analysis VM address: {host!r}") from exc
    if address not in KNOWN_VM_NETWORK:
        raise QilingSetupError(
            f"Analysis VM must be on {KNOWN_VM_NETWORK}, got {host}")

    username = str(config.get("username", "")).strip()
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]*", username) \
            or username.upper().startswith("YOUR_"):
        raise QilingSetupError(
            "set the Analysis VM SSH username in admin-terminal/vms.json")
    try:
        port = int(config.get("port", 22))
    except (TypeError, ValueError) as exc:
        raise QilingSetupError("SSH port must be an integer from 1 to 65535") from exc
    if not 1 <= port <= 65535:
        raise QilingSetupError("SSH port must be an integer from 1 to 65535")

    remote_dir = PurePosixPath(str(config.get("remote_dir", "qiling_dlls")))
    if remote_dir.is_absolute() or not remote_dir.parts or any(
            part in (".", "..") or not re.fullmatch(r"[A-Za-z0-9_.-]+", part)
            for part in remote_dir.parts):
        raise QilingSetupError(
            "remote_dir must be a simple relative path under the VM user's home")
    return host, username, port, remote_dir


def _ssh_base(config: dict) -> tuple[list[str], str, str]:
    host, username, port, remote_dir = _remote_settings(config)
    known_hosts = Path(
        core.known_hosts_path(config.get("known_hosts_file", "")))
    if not known_hosts.is_file():
        raise QilingSetupError(
            f"trusted host-key file missing: {known_hosts}; add the VM's "
            "verified SSH host key before connecting")
    with known_hosts.open(encoding="utf-8", errors="replace") as fh:
        trusted_entries = [
            line for line in fh
            if line.strip() and not line.lstrip().startswith("#")
        ]
    if not trusted_entries:
        raise QilingSetupError(
            f"{known_hosts} has no trusted host keys; verify the VM key "
            "out of band, then add its known_hosts entry")

    options = [
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=yes",
        "-o", f"UserKnownHostsFile={known_hosts.resolve().as_posix()}",
        "-o", "ConnectTimeout=8",
    ]
    identity = str(config.get("identity_file", "")).strip()
    if identity:
        key_path = Path(identity)
        if not key_path.is_absolute():
            key_path = Path(core.REPO) / key_path
        if not key_path.is_file():
            raise QilingSetupError(f"SSH identity file not found: {key_path}")
        options.extend(["-i", str(key_path)])

    destination = f"{username}@{host}"
    ssh = ["ssh", "-p", str(port), *options, destination]
    sftp = ["sftp", "-P", str(port), *options, destination]
    remote_base = '"$HOME"/' + "/".join(shlex.quote(part)
                                         for part in remote_dir.parts)
    return ssh, sftp, remote_base


def _ssh(config: dict, command: str, *, check: bool = True) -> subprocess.CompletedProcess:
    ssh, _, _remote_base = _ssh_base(config)
    result = subprocess.run(
        [*ssh, command], capture_output=True, text=True,
        encoding="utf-8", errors="replace", check=False,
    )
    if check and result.returncode:
        detail = (result.stderr or result.stdout).strip()
        raise QilingSetupError(
            f"SSH command failed (exit {result.returncode})"
            + (f": {detail}" if detail else ""))
    return result


def remote_rootfs_exists(config: dict) -> bool:
    """Check both emulated Windows trees on the VM using verified SSH."""
    _ssh, _sftp, remote_base = _ssh_base(config)
    result = _ssh(
        config,
        f"test -d {remote_base}/examples/rootfs/x86_windows/Windows/System32 "
        f"&& test -d {remote_base}/examples/rootfs/x8664_windows/Windows/System32",
        check=False,
    )
    if result.returncode == 0:
        return True
    if result.returncode == 1:
        return False
    detail = (result.stderr or result.stdout).strip()
    raise QilingSetupError(
        f"could not check remote rootfs (exit {result.returncode})"
        + (f": {detail}" if detail else ""))


def _sftp_quote(path: str) -> str:
    return '"' + path.replace("\\", "/").replace('"', '\\"') + '"'


def _upload(config: dict, files: list[tuple[Path, str]]) -> None:
    _ssh, sftp, _remote_base = _ssh_base(config)
    batch = "".join(
        f"put -p {_sftp_quote(str(local))} {_sftp_quote(remote)}\n"
        for local, remote in files
    )
    result = subprocess.run(
        [*sftp, "-b", "-"], input=batch, capture_output=True, text=True,
        encoding="utf-8", errors="replace", check=False,
    )
    if result.returncode:
        detail = (result.stderr or result.stdout).strip()
        raise QilingSetupError(
            f"SFTP upload failed (exit {result.returncode})"
            + (f": {detail}" if detail else ""))


def _download(config: dict, remote: str, local: Path) -> None:
    _ssh, sftp, _remote_base = _ssh_base(config)
    local.parent.mkdir(parents=True, exist_ok=True)
    batch = f"get {_sftp_quote(remote)} {_sftp_quote(str(local))}\n"
    result = subprocess.run(
        [*sftp, "-b", "-"], input=batch, capture_output=True, text=True,
        encoding="utf-8", errors="replace", check=False,
    )
    if result.returncode:
        detail = (result.stderr or result.stdout).strip()
        raise QilingSetupError(
            f"SFTP download failed (exit {result.returncode})"
            + (f": {detail}" if detail else ""))


def deploy_and_run(config: dict, sample: str) -> str:
    """Upload the harness/sample and missing rootfs, run it remotely, fetch zip."""
    sample_path = Path(sample).expanduser().resolve()
    if not sample_path.is_file():
        raise QilingSetupError(f"executable not found: {sample_path}")
    if not SCRIPT.is_file():
        raise QilingSetupError(f"Qiling harness not found: {SCRIPT}")
    if not rootfs_exists():
        raise QilingSetupError(
            "local rootfs is missing; run Qiling setup before deploying")
    _package_rootfs()

    ssh, _sftp, remote_base = _ssh_base(config)
    _host, _username, _port, remote_rel = _remote_settings(config)
    remote_dir = remote_rel.as_posix()
    rootfs_ready = remote_rootfs_exists(config)
    _ssh(config, f"mkdir -p -- {remote_base}")

    safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", sample_path.name).lstrip(".")
    if not safe_name:
        raise QilingSetupError("sample filename must contain a normal filename")
    remote_sample = f"{remote_dir}/{safe_name}"
    archive_name = f"{remote_dir}/rootfs.tar.gz"
    files = [(SCRIPT, f"{remote_dir}/_qiling_script.py"),
             (sample_path, remote_sample)]
    if not rootfs_ready:
        files.append((ARCHIVE, archive_name))
    _upload(config, files)

    if not rootfs_ready:
        extraction = (
            f"tar -xzf {remote_base}/rootfs.tar.gz -C {remote_base}"
        )
        result = subprocess.run(
            [*ssh, extraction], capture_output=True, text=True,
            encoding="utf-8", errors="replace", check=False,
        )
        if result.returncode:
            detail = (result.stderr or result.stdout).strip()
            raise QilingSetupError(
                f"remote rootfs extraction failed (exit {result.returncode})"
                + (f": {detail}" if detail else ""))

    remote_dir_shell = '"$HOME"/' + "/".join(
        shlex.quote(part) for part in remote_rel.parts)
    remote_python = str(config.get("remote_python", "python3"))
    if not re.fullmatch(r"[A-Za-z0-9_.+-]+", remote_python):
        raise QilingSetupError("remote_python must be an executable name")
    stem = re.sub(r"[^A-Za-z0-9._-]", "_", sample_path.stem).lstrip(".")
    output_name = f"{stem or 'sample'}_qiling_out.zip"
    command = (
        f"cd {remote_dir_shell} && {shlex.quote(remote_python)} "
        f"{remote_dir_shell}/_qiling_script.py --rootfs "
        f"{remote_dir_shell}/examples/rootfs/x8664_windows --out "
        f"{remote_dir_shell}/{shlex.quote(output_name)} "
        f"{remote_dir_shell}/{shlex.quote(safe_name)}"
    )
    log_path = str(core.ensure_admin_logs())
    log_path = os.path.join(log_path, f"qiling_{core.timestamp()}.log")
    print(f"  running Qiling on {config['host']} (log: "
          f"{os.path.relpath(log_path, core.REPO)})")
    if core.run_stream([*ssh, command], core.REPO, log_path) != 0:
        raise QilingSetupError(
            f"remote Qiling process failed; see {os.path.relpath(log_path, core.REPO)}")

    result_path = RESULTS / output_name
    _download(config, f"{remote_dir}/{output_name}", result_path)
    return str(result_path)
