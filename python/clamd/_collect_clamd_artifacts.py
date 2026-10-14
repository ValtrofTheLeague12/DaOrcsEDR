#!/usr/bin/env python3
"""Host-side recovery of ClamAV scan results from the analysis VM (paramiko).

Reads vm_info.json (host-only contract), SSHes into the VM, and downloads
every <stem>_*.json from paths.results into python/clamd/results/ - the
collection half of the qiling-style flow (deploy -> run -> collect).

Usage:
    python python/clamd/_collect_clamd_artifacts.py [--vm-info PATH]

Requires: pip install paramiko
Exit codes: 0 ok (including "nothing to collect"), 1 collection failed.
"""

import argparse
import json
import pathlib
import sys

EXIT_OK = 0
EXIT_FAIL = 1

HERE = pathlib.Path(__file__).resolve().parent
DEFAULT_VM_INFO = HERE / "vm_info.json"
LOCAL_RESULTS = HERE / "results"

try:
    import paramiko
except ImportError:
    print("[-] paramiko not installed (pip install paramiko)", file=sys.stderr)
    sys.exit(EXIT_FAIL)


def load_vm_info(path: pathlib.Path) -> dict:
    if not path.is_file():
        raise RuntimeError(f"vm_info.json not found: {path}")
    with path.open(encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data.get("paths"), dict):
        raise RuntimeError("vm_info.json: missing 'paths' object")
    if not str(data.get("VM_IP", "")).strip() or not str(data.get("VM_HOST", "")).strip():
        raise RuntimeError("vm_info.json: VM_IP and VM_HOST are required")
    return data


def collect(info: dict) -> list[pathlib.Path]:
    host = str(info.get("VM_IP", "")).strip()
    username = str(info.get("VM_HOST", "")).strip()
    password = str(info.get("VM_PASSWORD", "") or "")
    try:
        port = int(info.get("VM_PORT", 22) or 22)
    except (TypeError, ValueError) as exc:
        raise RuntimeError("VM_PORT must be an integer") from exc
    remote_results = str(info["paths"].get("results", "")).strip()
    if not remote_results:
        raise RuntimeError("vm_info.json: paths.results is required")

    # Same connection posture as qiling's check_ssh_connectivity_normal_user.
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    project_keys = HERE / "known_hosts.ssh"
    if project_keys.exists():
        client.load_host_keys(str(project_keys.resolve()))
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    try:
        client.connect(hostname=host, username=username, port=port,
                       password=password, timeout=10)
    except paramiko.SSHException as exc:
        raise RuntimeError(
            f"SSH to {username}@{host}:{port} failed: {exc}; verify the VM "
            "host key is trusted in known_hosts") from exc

    downloaded: list[pathlib.Path] = []
    try:
        sftp = client.open_sftp()
        try:
            try:
                names = sorted(sftp.listdir(remote_results))
            except FileNotFoundError:
                print(f"[*] nothing to collect: {remote_results} is missing "
                      "on the VM")
                return []
            json_names = [n for n in names if n.endswith(".json")]
            if not json_names:
                print(f"[*] nothing to collect in {remote_results}")
                return []
            LOCAL_RESULTS.mkdir(parents=True, exist_ok=True)
            for name in json_names:
                local = LOCAL_RESULTS / name
                sftp.get(f"{remote_results}/{name}", str(local))
                downloaded.append(local)
                print(f"[+] recovered {name}")
        finally:
            sftp.close()
    finally:
        client.close()
    return downloaded


def main() -> int:
    ap = argparse.ArgumentParser(
        description="collect ClamAV scan results from the analysis VM")
    ap.add_argument("--vm-info", default=str(DEFAULT_VM_INFO))
    args = ap.parse_args()

    try:
        info = load_vm_info(pathlib.Path(args.vm_info))
        files = collect(info)
    except (RuntimeError, json.JSONDecodeError, OSError) as exc:
        print(f"[-] {exc}", file=sys.stderr)
        return EXIT_FAIL

    if files:
        print(f"[+] {len(files)} result file(s) under {LOCAL_RESULTS}/")
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
