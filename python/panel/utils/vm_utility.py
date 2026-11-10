"""Client for the newline-delimited JSON VM utility protocol."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
import subprocess
import socket
import sys
import uuid
import zipfile
from enum import StrEnum
from typing import Callable

from loguru import logger

MAX_UPLOAD_BYTES = 25 * 1024 * 1024
MAX_ROOTFS_ARCHIVE_BYTES = 1024 * 1024 * 1024
MAX_REPORT_BYTES = 512 * 1024 * 1024
MAX_MESSAGE_BYTES = 36 * 1024 * 1024
_READ_SIZE = 64 * 1024
_UPLOAD_CHUNK_SIZE = 64 * 1024
_SPINNER_FRAMES = "|/-\\"
_DEFAULT_SOCKET_TIMEOUT = 30.0
_SUPPORTED_PE_MACHINES = {0x014C: "x86", 0x8664: "x64"}


def detect_pe_architecture(sample_path: str | os.PathLike[str]) -> str:
    
    """ Should be using LEIF Return x86 or x64 for a supported Windows PE, rejecting unknown files."""
    path = pathlib.Path(sample_path)
    if not path.is_file():
        raise FileNotFoundError(f"Sample file does not exist: {path}")
    with path.open("rb") as stream:
        if stream.read(2) != b"MZ":
            raise ValueError(f"Sample is not a Windows PE executable: {path.name}")
        stream.seek(0x3C)
        offset_bytes = stream.read(4)
        if len(offset_bytes) != 4:
            raise ValueError("PE header is truncated")
        offset = int.from_bytes(offset_bytes, "little")
        if not 0 < offset <= 0x10000:
            raise ValueError("PE header offset is invalid")
        stream.seek(offset)
        if stream.read(4) != b"PE\0\0":
            raise ValueError("PE signature is missing")
        machine_bytes = stream.read(2)
    if len(machine_bytes) != 2:
        raise ValueError("PE machine field is truncated")
    machine = int.from_bytes(machine_bytes, "little")
    try:
        return _SUPPORTED_PE_MACHINES[machine]
    except KeyError as exc:
        raise ValueError(
            f"Unsupported PE architecture (machine 0x{machine:04X}); "
            "Qiling supports x86 and x64 Windows executables"
        ) from exc


def configured_socket_timeout() -> float:
    """Read the socket timeout from config/dynamic_analysis.json, if present."""
    repo = pathlib.Path(__file__).resolve().parents[3]
    path = repo / "config" / "dynamic_analysis.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        value = float(data.get("socket_timeout", _DEFAULT_SOCKET_TIMEOUT))
    except (OSError, ValueError, TypeError):
        return _DEFAULT_SOCKET_TIMEOUT
    return value if value > 0 else _DEFAULT_SOCKET_TIMEOUT


class Service(StrEnum):
    CLAMD_SERVICE = "clamav"
    QILING_SERVICE = "qiling"


class VirtualUtility:
    def __init__(self, sock: socket.socket):
        if not isinstance(sock, socket.socket):
            raise TypeError("A connected socket is required")
        if sock.fileno() < 0:
            raise ValueError("The socket is closed")
        self.__server_socket = sock
        self.__receive_buffer = bytearray()
        try:
            self.__server_socket.settimeout(configured_socket_timeout())
        except (OSError, ValueError):
            logger.warning("Could not apply configured socket timeout")

    def __request(self, request: dict) -> dict:
        encoded = json.dumps(request, separators=(",", ":")).encode("utf-8") + b"\n"
        if len(encoded) > MAX_MESSAGE_BYTES:
            raise ValueError("Request exceeds the maximum protocol message size")
        try:
            self.__server_socket.sendall(encoded)
        except (OSError, ConnectionError):
            logger.exception("VM utility request failed")
            raise

        return self.__read_response()

    def __read_response(self) -> dict:
        try:
            while b"\n" not in self.__receive_buffer:
                chunk = self.__server_socket.recv(_READ_SIZE)
                if not chunk:
                    raise ConnectionError("VM server closed the connection")
                self.__receive_buffer.extend(chunk)
                if len(self.__receive_buffer) > MAX_MESSAGE_BYTES:
                    raise ValueError("VM server response exceeds the message size limit")
        except (OSError, ConnectionError):
            logger.exception("VM utility request failed")
            raise

        response_line, _, remainder = self.__receive_buffer.partition(b"\n")
        self.__receive_buffer = bytearray(remainder)
        try:
            response = json.loads(response_line.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            logger.error("VM server returned invalid JSON: {}", exc)
            raise ValueError("VM server returned an invalid JSON response") from exc
        if not isinstance(response, dict):
            raise ValueError("VM server response must be a JSON object")
        if not response.get("ok"):
            error = str(response.get("error") or "VM server rejected the request")
            logger.warning("VM utility request was rejected: {}", error)
            raise RuntimeError(error)
        return response

    @staticmethod
    def __validate_service(service: Service) -> Service:
        if not isinstance(service, Service):
            raise TypeError("service must be a Service value")
        return service

    def ping_service(self,service:Service) -> dict:
        service = self.__validate_service(service)
        logger.debug("Pinging VM service {}", service.value)
        response = self.__request({
            "command": f"ping {service.value}",
            "service": service.value,
        })
        return response

    def recover_information_about_services_status(self, service: Service) -> dict:
        service = self.__validate_service(service)
        logger.debug("Requesting status for VM service {}", service.value)
        response = self.__request({
            "command": "service_info",
            "service": service.value,
        })
        result = response.get("result")
        if not isinstance(result, dict):
            raise ValueError("VM server returned an invalid service status")
        return result


    def send_analyze_sample_vm(
        self, filename: str | os.PathLike[str], service: Service,
        *, timeout: int = 30, max_insn: int = 1_000_000,
        progress: Callable[[int, int], None] | None = None,
    ) -> dict:
        service = self.__validate_service(service)
        if service == Service.CLAMD_SERVICE:
            path = pathlib.Path(filename)
            self.send_sample_to_vm(path, progress=progress)
            return self.scan_sample_on_vm(path.name)
        if service == Service.QILING_SERVICE:
            return self.analyze_qiling_sample_vm(
                filename, timeout=timeout, max_insn=max_insn, progress=progress)
        raise ValueError(f"unsupported VM service: {service.value}")

    def recover_sent_samples(self, service: Service) -> list[dict]:
        service = self.__validate_service(service)
        logger.debug("Requesting uploaded sample list for {}", service.value)
        response = self.__request({
            "command": "recover_samples",
            "service": service.value,
        })
        samples = response.get("samples")
        if not isinstance(samples, list):
            raise ValueError("VM server returned an invalid sample list")
        return samples

    def scan_sample_on_vm(self, filename: str) -> dict:
        response = self.__request({
            "command": "scan_sample",
            "filename": filename,
        })
        result = response.get("scan")
        if not isinstance(result, dict):
            raise ValueError("VM server returned an invalid sample scan result")
        if result.get("status") not in ("OK", "FOUND"):
            raise ValueError("VM server returned an unknown sample scan status")
        return result


    def check_if_root_fs_found(self):
        request = self.__request({
            "command":"check_root_fs"
        })
        if not request:
            logger.error("Failed to capture the TCP Server reque")
        return request
    def analyze_qiling_sample_vm(
        self,
        sample_path: str | os.PathLike[str],    
        *,
        timeout: int = 30,
        max_insn: int = 1_000_000,
        progress: Callable[[int, int], None] | None = None,
        results_dir: str | os.PathLike[str] | None = None,
    ) -> dict:
        """Check Qiling, upload a PE, run it with the matching rootfs, and fetch evidence."""
        path = pathlib.Path(sample_path)
        arch = detect_pe_architecture(path)
        if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 600:
            raise ValueError("timeout must be an integer from 1 to 600 seconds")
        if (isinstance(max_insn, bool) or not isinstance(max_insn, int)
                or not 1 <= max_insn <= 100_000_000):
            raise ValueError("max_insn must be an integer from 1 to 100000000")

        preflight = self.__request({
            "command": "qiling_preflight",
            "architecture": arch,
        })
        if not preflight.get("ready"):
            service = preflight.get("service") or {}
            if not service.get("active"):
                raise RuntimeError(
                    service.get("detail") or "Qiling service is not running on the VM")

            rootfs = preflight.get("rootfs") or {}
            if not rootfs.get("configured"):
                archive = self._ensure_local_rootfs_archive()
                self._upload_file(
                    archive, "rootfs.tar.gz", kind="rootfs",
                    progress=progress,
                )
                preflight = self.__request({
                    "command": "qiling_preflight",
                    "architecture": arch,
                })
                if not preflight.get("ready"):
                    rootfs = preflight.get("rootfs") or {}
                    raise RuntimeError(
                        "Qiling VM rootfs is not configured: "
                        + ", ".join(rootfs.get("missing") or ["unknown rootfs error"]))

        safe_stem = re.sub(r"[^A-Za-z0-9._-]", "_", path.stem).strip("._-")
        remote_name = f"{safe_stem or 'sample'}-{uuid.uuid4().hex[:12]}{path.suffix.lower()}"
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,199}", remote_name):
            raise ValueError("sample filename cannot be represented safely for upload")
        self._upload_file(path, remote_name, progress=progress)

        previous_timeout = self.__server_socket.gettimeout()
        self.__server_socket.settimeout(max(previous_timeout or 0.0, 700.0))
        try:
            result = self.__request({
                "command": "qiling_run",
                "filename": remote_name,
                "architecture": arch,
                "timeout": timeout,
                "max_insn": max_insn,
            })
        finally:
            self.__server_socket.settimeout(previous_timeout)
        run_id = result.get("run_id")
        size = result.get("size")
        digest = result.get("sha256")
        if (not isinstance(run_id, str) or not re.fullmatch(r"[a-f0-9]{32}", run_id)
                or isinstance(size, bool) or not isinstance(size, int)
                or not 0 < size <= MAX_REPORT_BYTES
                or not isinstance(digest, str)
                or not re.fullmatch(r"[a-f0-9]{64}", digest)):
            raise ValueError("VM server returned invalid Qiling report metadata")
        report_response = self.__request({
            "command": "qiling_report",
            "run_id": run_id,
        })
        if report_response.get("size") != size or report_response.get("sha256") != digest:
            raise ValueError("Qiling report metadata changed during download")
        report_bytes = self.__read_exact(size)
        actual_digest = hashlib.sha256(report_bytes).hexdigest()
        if actual_digest != digest:
            raise ValueError("Qiling evidence archive integrity check failed")

        repo = pathlib.Path(__file__).resolve().parents[3]
        result_dir = pathlib.Path(results_dir) if results_dir else (
            repo / "qiling_dlls" / "results")
        result_dir.mkdir(parents=True, exist_ok=True)
        report_path = result_dir / f"{path.stem}_{run_id[:12]}_qiling_out.zip"
        temp_path = report_path.with_suffix(report_path.suffix + ".part")
        try:
            temp_path.write_bytes(report_bytes)
            if not zipfile.is_zipfile(temp_path):
                raise ValueError("Qiling evidence is not a valid ZIP archive")
            os.replace(temp_path, report_path)
        finally:
            temp_path.unlink(missing_ok=True)
        return {
            "ok": True,
            "architecture": arch,
            "rootfs": (preflight.get("rootfs") or {}).get("rootfs"),
            "report": str(report_path),
            "report_bytes": size,
            "sha256": actual_digest,
            "exit_code": result.get("exit_code"),
            "output": result.get("output", ""),
        }

    @staticmethod
    def _ensure_local_rootfs_archive() -> pathlib.Path:
        repo = pathlib.Path(__file__).resolve().parents[3]
        qiling_dir = repo / "qiling_dlls"
        archive = qiling_dir / "rootfs.tar.gz"
        expected = ("x86_windows", "x8664_windows")
        complete = all(
            (qiling_dir / "examples" / "rootfs" / arch / "Windows" / "System32"
             / "kernel32.dll").is_file()
            and (qiling_dir / "examples" / "rootfs" / arch / "Windows" / "System32"
                 / "ntdll.dll").is_file()
            and (qiling_dir / "examples" / "rootfs" / arch / "Windows" / "registry"
                 / "SYSTEM").is_file()
            for arch in expected
        )
        if not complete or not archive.is_file():
            lib_path = "C:/Users/The4thReich/Desktop/IAProject"
            full_path = pathlib.Path(lib_path).joinpath("admin-terminal")
            sys.path.append(str(full_path.resolve()))
            logger.info("import main qilin utility..")
            try:
                import qiling_setup as qilin_utility

            except ImportError as e:
                logger.error(e)
                sys.exit(1)
            try:
                results = qilin_utility.setup_rootfs()
                logger.info("results of qll collection : {}".format(results))
            except (OSError, subprocess.SubprocessError) as exc:
                raise RuntimeError(f"could not run the elevated Qiling rootfs collector: {exc}") from exc

        if not archive.is_file():
            raise FileNotFoundError(f"Qiling rootfs archive was not created: {archive}")
        size = archive.stat().st_size
        logger.info("check if the size is super to 0 : {} ".format(size))
        if size <= 0 or size > MAX_ROOTFS_ARCHIVE_BYTES:
            raise ValueError("Qiling rootfs archive is empty or exceeds the upload limit")
        return archive

    def send_sample_to_vm(
        self,
        sample_path: str | os.PathLike[str],
        filename: str | None = None,
        progress: Callable[[int, int], None] | None = None,
    ) -> bool:
        path = pathlib.Path(sample_path)
        if not path.is_file():
            raise FileNotFoundError(f"Sample file does not exist: {path}")
        remote_filename = filename or path.name
        return self._upload_file(path, remote_filename, progress=progress)

    def _upload_file(
        self,
        path: pathlib.Path,
        filename: str,
        *,
        kind: str = "sample",
        progress: Callable[[int, int], None] | None = None,
    ) -> bool:
        file_size = path.stat().st_size
        limit = MAX_ROOTFS_ARCHIVE_BYTES if kind == "rootfs" else MAX_UPLOAD_BYTES
        if file_size <= 0:
            raise ValueError("Upload file must not be empty")
        if file_size > limit:
            raise ValueError(f"Upload exceeds the {limit}-byte limit")

        response = self.__request({
            "command": "upload_rootfs" if kind == "rootfs" else "upload_sample",
            "kind": kind,
            "filename": filename,
            "size": file_size,
        })
        if response.get("ready") is not True:
            raise ValueError("VM server did not acknowledge the file upload")

        show_progress = sys.stderr.isatty()
        sent = 0
        chunks_sent = 0
        digest = hashlib.sha256()
        previous_timeout = self.__server_socket.gettimeout()
        if kind == "rootfs":
            self.__server_socket.settimeout(max(previous_timeout or 0.0, 600.0))
        try:
            with path.open("rb") as sample_file:
                while sent < file_size:
                    chunk = sample_file.read(min(_UPLOAD_CHUNK_SIZE, file_size - sent))
                    if not chunk:
                        raise OSError("Upload file changed while it was being read")
                    self.__server_socket.sendall(chunk)
                    digest.update(chunk)
                    sent += len(chunk)
                    chunks_sent += 1
                    if progress is not None:
                        progress(sent, file_size)
                    if show_progress:
                        frame = _SPINNER_FRAMES[(chunks_sent - 1) % len(_SPINNER_FRAMES)]
                        percent = sent * 100 // file_size
                        sys.stderr.write(
                            f"\r{frame} Uploading {path.name}: "
                            f"{sent}/{file_size} bytes ({percent}%)"
                        )
                        sys.stderr.flush()

            if show_progress:
                sys.stderr.write("\n")

            response = self.__read_response()
        finally:
            if kind == "rootfs":
                self.__server_socket.settimeout(previous_timeout)
        if response.get("stored") is not True:
            raise ValueError("VM server did not confirm the file upload")
        expected_digest = digest.hexdigest()
        if response.get("sha256") != expected_digest:
            raise ValueError(
                "VM server upload integrity check failed "
                f"(expected {expected_digest}, got {response.get('sha256')!r})"
            )

        logger.info(
            "Uploaded {} to VM as {} ({} bytes, sha256={})",
            path.name, filename, file_size, expected_digest,
        )
        return True

    def __read_exact(self, size: int) -> bytes:
        data = bytearray()
        if self.__receive_buffer:
            take = min(size, len(self.__receive_buffer))
            data.extend(self.__receive_buffer[:take])
            del self.__receive_buffer[:take]
        while len(data) < size:
            chunk = self.__server_socket.recv(min(_READ_SIZE, size - len(data)))
            if not chunk:
                raise ConnectionError("VM server closed during evidence download")
            data.extend(chunk)
        return bytes(data)


if __name__ == "__main__":
    if __package__:
        from .socket_validator import SocketValidator
    else:
        from socket_validator import SocketValidator

    sock = SocketValidator("192.168.56.105").establish_tcp_connection(3310)
    
    if sock is None:
        raise SystemExit("Could not connect to the VM utility server")
    try:
        v = VirtualUtility(sock).analyze_qiling_sample_vm("./test_sample.exe")
        #v = VirtualUtility(sock).check_if_root_fs_found()
        #print(v)
        #v = VirtualUtility(sock)._upload_file(path=pathlib.Path("C:/Users/The4thReich/Desktop/IAProject/qiling_dlls/rootfs.tar.gz"),
         #                                    filename="rootfs.tar.gz",
          #                                   kind="rootfs"
           #                                  ) 
        logger.info("Command output: {} ".format(v))
    except Exception as e:
        raise e
        logger.error("Something went wrong : {}".format(e))
    try:
        logger.info(
            "ClamAV status: {}",
            VirtualUtility(sock).recover_information_about_services_status(
                Service.QILING_SERVICE
            ),
        )
    finally:
        sock.close()
