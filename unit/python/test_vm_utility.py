from __future__ import annotations

import json
import socket
import sys
import threading
import tarfile
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "python"))

from panel.utils.socket_validator import SocketValidator  # noqa: E402
from panel.utils import vm_server as vm_server_module  # noqa: E402
from panel.utils.vm_server import VMUtilityServer  # noqa: E402
from panel.utils.vm_utility import (  # noqa: E402
    Service,
    VirtualUtility,
    detect_pe_architecture,
)


def _write_pe(path: Path, machine: int) -> None:
    data = bytearray(0x100)
    data[:2] = b"MZ"
    data[0x3C:0x40] = (0x80).to_bytes(4, "little")
    data[0x80:0x84] = b"PE\0\0"
    data[0x84:0x86] = machine.to_bytes(2, "little")
    path.write_bytes(data)


def test_vm_utility_round_trip_and_concurrent_clients(tmp_path, monkeypatch):
    class FakeClamd:
        def __init__(self, expected):
            self.expected = expected

        def scan(self, sample_path):
            assert Path(sample_path).read_bytes() == self.expected
            return {sample_path: ("FOUND", "Test-Signature")}

    sample_contents = bytes(range(256)) * 513
    monkeypatch.setattr(
        vm_server_module.clamd,
        "ClamdUnixSocket",
        lambda: FakeClamd(sample_contents),
        raising=False,
    )
    monkeypatch.setattr(
        VMUtilityServer,
        "_service_status",
        staticmethod(lambda service: {
            "service": service,
            "state": "active",
            "active": True,
        }),
    )
    server = VMUtilityServer("127.0.0.1", 0, tmp_path / "vm-samples")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        sample = tmp_path / "sample.bin"
        sample.write_bytes(sample_contents)
        with socket.create_connection(server.address, timeout=3) as sock:
            utility = VirtualUtility(sock)
            assert utility.send_sample_to_vm(sample)
            scan = utility.scan_sample_on_vm("sample.bin")
            assert utility.recover_information_about_services_status(
                Service.CLAMD_SERVICE
            )["active"]
            uploaded = utility.recover_sent_samples(Service.CLAMD_SERVICE)
        assert len(uploaded) == 1
        assert uploaded[0]["name"] == "sample.bin"
        assert uploaded[0]["size"] == len(sample_contents)
        assert scan == {
            "status": "FOUND",
            "signature": "Test-Signature",
            "detail": "",
        }
        assert (tmp_path / "vm-samples" / "sample.bin").read_bytes() == sample_contents
        assert not list((tmp_path / "vm-samples").glob("*.part"))

        def list_samples(_):
            with socket.create_connection(server.address, timeout=3) as sock:
                return VirtualUtility(sock).recover_sent_samples(Service.QILING_SERVICE)

        with ThreadPoolExecutor(max_workers=8) as clients:
            responses = list(clients.map(list_samples, range(8)))
        assert len(responses) == 8
        assert all(response[0]["name"] == "sample.bin" for response in responses)
    finally:
        server.shutdown()
        thread.join(timeout=3)
        assert not thread.is_alive()


def test_socket_validator_rejects_bad_addresses_and_ports():
    with pytest.raises(ValueError, match="Invalid IP address"):
        SocketValidator("not-an-ip")
    validator = SocketValidator("127.0.0.1")
    assert validator.establish_tcp_connection(0) is None
    assert validator.test_connection_using_a_socket(65536) == (False, None)


@pytest.mark.parametrize(
    ("machine", "architecture"),
    [(0x014C, "x86"), (0x8664, "x64")],
)
def test_detect_pe_architecture(tmp_path, machine, architecture):
    sample = tmp_path / "sample.exe"
    _write_pe(sample, machine)
    assert detect_pe_architecture(sample) == architecture


def test_detect_pe_architecture_rejects_non_pe_and_unsupported_machine(tmp_path):
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"not a PE")
    with pytest.raises(ValueError, match="not a Windows PE"):
        detect_pe_architecture(sample)
    _write_pe(sample, 0xAA64)
    with pytest.raises(ValueError, match="Unsupported PE architecture"):
        detect_pe_architecture(sample)


def test_qiling_upload_runs_matching_rootfs_and_downloads_evidence(
        tmp_path, monkeypatch):
    local_rootfs = tmp_path / "collector" / "examples" / "rootfs"
    for arch in ("x86_windows", "x8664_windows"):
        system32 = local_rootfs / arch / "Windows" / "System32"
        system32.mkdir(parents=True)
        (system32 / "kernel32.dll").write_bytes(b"dll")
        (system32 / "ntdll.dll").write_bytes(b"dll")
        registry = local_rootfs / arch / "Windows" / "registry"
        registry.mkdir(parents=True)
        (registry / "SYSTEM").write_bytes(b"registry")
    rootfs_archive = tmp_path / "rootfs.tar.gz"
    with tarfile.open(rootfs_archive, "w:gz") as archive:
        archive.add(local_rootfs.parent, arcname="examples")
    monkeypatch.setattr(
        VirtualUtility, "_ensure_local_rootfs_archive",
        staticmethod(lambda: rootfs_archive),
    )

    harness = tmp_path / "harness.py"
    harness.write_text(
        "import sys, zipfile\n"
        "out = sys.argv[sys.argv.index('--out') + 1]\n"
        "with zipfile.ZipFile(out, 'w') as archive:\n"
        "    archive.writestr('report.txt', 'Qiling evidence')\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        VMUtilityServer,
        "_service_status",
        staticmethod(lambda service: {
            "service": service, "state": "active", "active": True,
            "detail": f"{service} active",
        }),
    )
    server = VMUtilityServer(
        "127.0.0.1", 0, tmp_path / "samples",
        qiling_rootfs=tmp_path / "remote-rootfs",
        qiling_harness=harness,
        qiling_timeout=15,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        sample = tmp_path / "sample.exe"
        _write_pe(sample, 0x014C)
        with socket.create_connection(server.address, timeout=3) as sock:
            result = VirtualUtility(sock).analyze_qiling_sample_vm(
                sample, results_dir=tmp_path / "reports")
        report = Path(result["report"])
        assert result["architecture"] == "x86"
        assert result["exit_code"] == 0
        assert zipfile.is_zipfile(report)
        assert server._rootfs_status("x86")["configured"]
        assert server._rootfs_status("x64")["configured"]
        with zipfile.ZipFile(report) as archive:
            assert archive.read("report.txt") == b"Qiling evidence"
        assert not list((tmp_path / "remote-rootfs" / "x86_windows").glob("sample-*.exe"))
    finally:
        server.shutdown()
        thread.join(timeout=3)
        assert not thread.is_alive()


def test_vm_server_installs_valid_rootfs_archive(tmp_path):
    rootfs_base = tmp_path / "vm-rootfs"
    server = VMUtilityServer(
        "127.0.0.1", 0, tmp_path / "samples", qiling_rootfs=rootfs_base)
    source = tmp_path / "archive-source" / "examples" / "rootfs"
    for arch in ("x86_windows", "x8664_windows"):
        system32 = source / arch / "Windows" / "System32"
        system32.mkdir(parents=True)
        (system32 / "kernel32.dll").write_bytes(b"dll")
        (system32 / "ntdll.dll").write_bytes(b"dll")
        registry = source / arch / "Windows" / "registry"
        registry.mkdir(parents=True)
        (registry / "SYSTEM").write_bytes(b"registry")
    archive_path = tmp_path / "rootfs.tar.gz"
    with tarfile.open(archive_path, "w:gz") as archive:
        archive.add(source.parent, arcname="examples")

    server._install_rootfs_archive(archive_path)
    assert server._rootfs_status("x86")["configured"]
    assert server._rootfs_status("x64")["configured"]


def test_vm_server_reports_binary_data_outside_upload_protocol(tmp_path):
    server = VMUtilityServer("127.0.0.1", 0, tmp_path / "vm-samples")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with socket.create_connection(server.address, timeout=3) as sock:
            sock.sendall(b"\x90\xffsample\n")
            response = bytearray()
            while b"\n" not in response:
                response.extend(sock.recv(1024))
        body = json.loads(response.partition(b"\n")[0])
        assert body["ok"] is False
        assert "outside an active upload" in body["error"]
        assert "90 ff 73 61 6d 70 6c 65" in body["error"]
    finally:
        server.shutdown()
        thread.join(timeout=3)
        assert not thread.is_alive()
