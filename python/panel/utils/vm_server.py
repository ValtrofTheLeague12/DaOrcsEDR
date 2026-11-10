"""TCP utility server for ClamAV scans and Qiling emulation on the VM."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import ssl
import os
import re
import shutil
import socket
import socketserver
import subprocess
import sys
import tarfile
import tempfile
import threading
import uuid
from pathlib import Path, PurePosixPath

try:
    import clamd
except ImportError:
    clamd = None

MAX_UPLOAD_BYTES = 25 * 1024 * 1024
MAX_ROOTFS_ARCHIVE_BYTES = 1024 * 1024 * 1024
MAX_ROOTFS_EXPANDED_BYTES = 8 * 1024 * 1024 * 1024
MAX_ROOTFS_ENTRIES = 250_000
MAX_REPORT_BYTES = 512 * 1024 * 1024
UPLOAD_CHUNK_BYTES = 64 * 1024
SUPPORTED_ARCHES = {"x86": "x86_windows", "x64": "x8664_windows"}
SAFE_FILENAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$")
ALLOWED_CLIENT_NETWORK = ipaddress.ip_network(
    os.environ.get("VM_UTILITY_ALLOWED_NETWORK", "192.168.56.0/24"))
logger = logging.getLogger(__name__)


def _pe_arch(path: Path) -> str:
    with path.open("rb") as stream:
        if stream.read(2) != b"MZ":
            raise ValueError("uploaded file is not a Windows PE executable")
        stream.seek(0x3C)
        offset_data = stream.read(4)
        if len(offset_data) != 4:
            raise ValueError("PE header is truncated")
        offset = int.from_bytes(offset_data, "little")
        if not 0 < offset <= 0x10000:
            raise ValueError("PE header offset is invalid")
        stream.seek(offset)
        if stream.read(4) != b"PE\0\0":
            raise ValueError("PE signature is missing")
        machine_data = stream.read(2)
    if len(machine_data) != 2:
        raise ValueError("PE machine field is truncated")
    machine = int.from_bytes(machine_data, "little")
    if machine == 0x014C:
        return "x86"
    if machine == 0x8664:
        return "x64"
    raise ValueError(f"unsupported PE machine 0x{machine:04X}")


class _ThreadingServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


class VMUtilityServer:
    """Serve the line-JSON utility protocol and its bounded binary transfers."""

    def __init__(
        self,
        host: str = "192.168.56.105",
        port: int = 3310,
        samples_dir: str | os.PathLike[str] | None = None,
        *,
        qiling_rootfs: str | os.PathLike[str] | None = None,
        qiling_harness: str | os.PathLike[str] | None = None,
        qiling_service: str = "qiling",
        qiling_timeout: int = 660,
        tls_context: ssl.SSLContext | None = None,
    ):
        base = Path.home() / ".config" /  "qiling" 
        repo = Path(__file__).resolve().parents[2]
        self.samples_dir = Path(samples_dir or os.environ.get(
            "VM_UTILITY_SAMPLES", Path.home() / "vm-samples")).expanduser()
        self.rootfs_dir = Path(qiling_rootfs or os.environ.get(
            "VM_QILING_ROOTFS", base / "examples" / "rootfs")).expanduser()
        self.harness = Path(qiling_harness or os.environ.get(
            "VM_QILING_HARNESS", base / "_qiling_script.py")).expanduser()
        self.results_dir = Path(os.environ.get(
            "VM_QILING_RESULTS", base / "results")).expanduser()
        if not re.fullmatch(r"[A-Za-z0-9_.@-]+", qiling_service):
            raise ValueError("invalid Qiling systemd unit name")
        if qiling_timeout < 1:
            raise ValueError("Qiling timeout must be positive")
        self.qiling_service = qiling_service
        self.qiling_timeout = qiling_timeout
        self.allowed_network = ALLOWED_CLIENT_NETWORK
        self._reports: dict[str, Path] = {}
        self._reports_lock = threading.Lock()
        self._tls_context = tls_context
        self._server = _ThreadingServer((host, port), self._handler_class())
        self._server.owner = self

    @property
    def address(self) -> tuple[str, int]:
        host, port = self._server.server_address[:2]
        return str(host), int(port)

    @staticmethod
    def _handler_class():
        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                owner: VMUtilityServer = self.server.owner
                peer = self.client_address
                conn = self.request
                if owner._tls_context is not None:
                    try:
                        conn = owner._tls_context.wrap_socket(
                            conn, server_side=True
                        )
                    except (ssl.SSLError, OSError):
                        logger.exception("TLS handshake failed from %s", peer)
                        return
                    self.request = conn
                    logger.info(
                        "TLS %s connection from %s using %s",
                        conn.version(), peer, conn.cipher()[0],
                    )
                owner._handle_client(conn)

        return Handler

    def serve_forever(self) -> None:
        self._server.serve_forever()

    def shutdown(self) -> None:
        self._server.shutdown()
        self._server.server_close()

    def _service_status(self, service: str) -> dict:
        unit = {"clamav": "clamav-daemon"}.get(service)
        if service == "qiling":
            unit = self.qiling_service
        if unit is None:
            raise ValueError(f"unsupported VM service: {service}")
        try:
            result = subprocess.run(
                ["systemctl", "is-active", unit],
                capture_output=True, text=True, timeout=5, check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return {"service": service, "state": "unknown", "active": False,
                    "detail": f"could not check systemd unit {unit}: {exc}"}
        state = (result.stdout or result.stderr).strip() or "unknown"
        return {
            "service": service,
            "state": state,
            "active": result.returncode == 0 and state == "active",
            "detail": f"systemd unit {unit} is {state}",
        }

    def _rootfs_status(self, arch: str) -> dict:
        if arch not in SUPPORTED_ARCHES:
            raise ValueError("architecture must be x86 or x64")
        arch_name = SUPPORTED_ARCHES[arch]
        windows = self.rootfs_dir / arch_name / "Windows"
        system32 = windows / "System32"
        missing = [
            str(path.relative_to(self.rootfs_dir / arch_name))
            for path in (
                system32 / "kernel32.dll",
                system32 / "ntdll.dll",
                windows / "registry" / "SYSTEM",
            )
            if not path.is_file()
        ]
        return {
            "architecture": arch,
            "rootfs": str(self.rootfs_dir / arch_name),
            "configured": not missing,
            "missing": missing,
        }

    def _send_json(self, conn: socket.socket, response: dict) -> None:
        conn.sendall(json.dumps(response, separators=(",", ":")).encode() + b"\n")

    @staticmethod
    def _receive_line(conn: socket.socket) -> bytes:
        line = bytearray()
        while len(line) <= 64 * 1024:
            chunk = conn.recv(1)
            if not chunk:
                break
            if chunk == b"\n":
                return bytes(line)
            line.extend(chunk)
        if len(line) > 64 * 1024:
            raise ValueError("request header exceeds 64 KiB")
        return bytes(line)

    @staticmethod
    def _receive_exact(conn: socket.socket, size: int, path: Path) -> str:
        digest = hashlib.sha256()
        remaining = size
        with path.open("wb") as stream:
            while remaining:
                chunk = conn.recv(min(UPLOAD_CHUNK_BYTES, remaining))
                if not chunk:
                    raise ConnectionError("client disconnected during file upload")
                stream.write(chunk)
                digest.update(chunk)
                remaining -= len(chunk)
        return digest.hexdigest()

    def _receive_upload(self, conn: socket.socket, request: dict) -> dict:
        filename = request.get("filename")
        size = request.get("size")
        kind = request.get("kind", "sample")
        if not isinstance(filename, str) or not SAFE_FILENAME.fullmatch(filename):
            raise ValueError("upload filename must be a plain safe filename")
        if isinstance(size, bool) or not isinstance(size, int) or size <= 0:
            raise ValueError("upload size must be a positive integer")
        limit = MAX_ROOTFS_ARCHIVE_BYTES if kind == "rootfs" else MAX_UPLOAD_BYTES
        if kind not in ("sample", "rootfs") or size > limit:
            raise ValueError(f"upload exceeds the {limit}-byte limit")
        self.samples_dir.mkdir(parents=True, exist_ok=True)
        destination = self.samples_dir / filename
        fd, temp_name = tempfile.mkstemp(
            prefix=f".{filename}.", suffix=".part", dir=self.samples_dir)
        os.close(fd)
        temporary = Path(temp_name)
        try:
            self._send_json(conn, {"ok": True, "ready": True})
            digest = self._receive_exact(conn, size, temporary)
            os.replace(temporary, destination)
        finally:
            temporary.unlink(missing_ok=True)
        return {
            "ok": True, "stored": True, "filename": filename,
            "size": size, "sha256": digest,
        }

    def _install_rootfs_archive(self, archive_path: Path) -> None:
        logger.info("Extracting uploaded Qiling rootfs archive")
        prefix = PurePosixPath("examples/rootfs")
        allowed_roots = set(SUPPORTED_ARCHES.values())
        self.rootfs_dir.mkdir(parents=True, exist_ok=True)
        try:
            with tarfile.open(archive_path, "r:gz") as archive:
                members = archive.getmembers()
                if not members:
                    raise ValueError("rootfs archive is empty")
                if len(members) > MAX_ROOTFS_ENTRIES:
                    raise ValueError("rootfs archive contains too many entries")
                expanded_size = sum(member.size for member in members)
                if expanded_size > MAX_ROOTFS_EXPANDED_BYTES:
                    raise ValueError("rootfs archive expands beyond the size limit")
                for member in members:
                    name = PurePosixPath(member.name)
                    parent_directory = name.parts in (("examples",), prefix.parts)
                    inside_rootfs = name.parts[:2] == prefix.parts
                    if ("\\" in member.name or ":" in member.name
                            or name.is_absolute() or ".." in name.parts
                            or not (parent_directory or inside_rootfs)
                            or member.issym() or member.islnk()
                            or not (member.isdir() or member.isfile())
                            or (parent_directory and not member.isdir())):
                        raise ValueError("rootfs archive contains an unsafe entry")
                    relative = name.parts[2:]
                    if relative and relative[0] not in allowed_roots:
                        raise ValueError("rootfs archive contains an unexpected path")
                for member in members:
                    logger.debug("Extracting rootfs archive entry %s", member.name)
                    relative = PurePosixPath(member.name).parts[2:]
                    if not relative:
                        continue
                    destination = self.rootfs_dir.joinpath(*relative)
                    if member.isdir():
                        destination.mkdir(parents=True, exist_ok=True)
                        continue
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    source = archive.extractfile(member)
                    if source is None:
                        raise ValueError("rootfs archive contains an unreadable file")
                    with source, destination.open("wb") as target:
                        shutil.copyfileobj(source, target, length=UPLOAD_CHUNK_BYTES)
                    logger.debug("Extracted rootfs file %s", destination)

        except tarfile.TarError as exc:
            raise ValueError(f"rootfs archive is invalid: {exc}") from exc
        for arch in SUPPORTED_ARCHES:
            if not self._rootfs_status(arch)["configured"]:
                raise ValueError(f"rootfs archive did not configure {arch}")

    def _run_qiling(self, request: dict) -> dict:
        arch = request.get("architecture")
        rootfs = self._rootfs_status(arch)
        if not rootfs["configured"]:
            raise RuntimeError(
                f"Qiling {arch} rootfs is not configured: "
                + ", ".join(rootfs["missing"]))
        filename = request.get("filename")
        if not isinstance(filename, str) or not SAFE_FILENAME.fullmatch(filename):
            raise ValueError("sample filename must be a plain safe filename")
        sample = self.samples_dir / filename
        if not sample.is_file():
            raise FileNotFoundError(f"uploaded sample not found: {filename}")
        detected_arch = _pe_arch(sample)
        if detected_arch != arch:
            raise ValueError(
                f"sample architecture is {detected_arch}, not requested {arch}")
        if not self.harness.is_file():
            raise FileNotFoundError(f"Qiling harness not found: {self.harness}")

        timeout = request.get("timeout", 30)
        max_insn = request.get("max_insn", 1_000_000)
        if (isinstance(timeout, bool) or not isinstance(timeout, int)
                or not 1 <= timeout <= 600):
            raise ValueError("timeout must be an integer from 1 to 600 seconds")
        if (isinstance(max_insn, bool) or not isinstance(max_insn, int)
                or not 1 <= max_insn <= 100_000_000):
            raise ValueError("max_insn must be an integer from 1 to 100000000")

        run_id = uuid.uuid4().hex
        self.results_dir.mkdir(parents=True, exist_ok=True)
        report = self.results_dir / f"{run_id}_qiling_out.zip"
        command = [
            sys.executable, str(self.harness),
            "--rootfs", rootfs["rootfs"], "--out", str(report),
            "--timeout", str(timeout), "--max-insn", str(max_insn),
            str(sample),
        ]
        try:
            result = subprocess.run(
                command, capture_output=True, text=True, timeout=self.qiling_timeout,
                check=False, cwd=str(self.harness.parent),
            )
        except subprocess.TimeoutExpired as exc:
            report.unlink(missing_ok=True)
            raise TimeoutError(
                f"Qiling exceeded the server limit of {self.qiling_timeout}s") from exc
        staged_sample = Path(rootfs["rootfs"]) / sample.name
        staged_sample.unlink(missing_ok=True)
        if not report.is_file():
            detail = (result.stderr or result.stdout or "").strip()[-4000:]
            raise RuntimeError(
                f"Qiling did not produce an evidence archive"
                + (f": {detail}" if detail else f" (exit {result.returncode})"))
        size = report.stat().st_size
        if size <= 0 or size > MAX_REPORT_BYTES:
            report.unlink(missing_ok=True)
            raise ValueError("Qiling evidence archive is empty or exceeds size limit")
        with self._reports_lock:
            self._reports[run_id] = report
        return {
            "ok": True,
            "run_id": run_id,
            "filename": report.name,
            "size": size,
            "sha256": self._sha256(report),
            "architecture": arch,
            "exit_code": result.returncode,
            "output": (result.stdout or "")[-4000:],
        }

    @staticmethod
    def _sha256(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(UPLOAD_CHUNK_BYTES), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def _send_report(self, conn: socket.socket, request: dict) -> None:
        run_id = request.get("run_id")
        if not isinstance(run_id, str) or not re.fullmatch(r"[a-f0-9]{32}", run_id):
            raise ValueError("invalid Qiling report id")
        with self._reports_lock:
            path = self._reports.get(run_id)
        if path is None or not path.is_file():
            raise FileNotFoundError("Qiling report is no longer available")
        size = path.stat().st_size
        self._send_json(conn, {
            "ok": True, "size": size, "sha256": self._sha256(path),
        })
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(UPLOAD_CHUNK_BYTES), b""):
                conn.sendall(chunk)

    def _handle_request(self, conn: socket.socket, request: dict) -> bool:
        command = request.get("command")
        if command in ("upload_sample", "upload_rootfs"):
            logger.info("Handling %s request", command)
            if command == "upload_rootfs":
                request = {**request, "kind": "rootfs"}
                request.setdefault("filename", "rootfs.tar.gz")
            response = self._receive_upload(conn, request)
            if command == "upload_rootfs":
                archive_path = self.samples_dir / "rootfs.tar.gz"
                try:
                    self._install_rootfs_archive(archive_path)
                finally:
                    archive_path.unlink(missing_ok=True)
                response["installed"] = True
            self._send_json(conn, response)
            return True
        if command in ("ping clamav", "ping qiling"):
            service = str(request.get("service", ""))
            if service not in ("clamav", "qiling"):
                service = "clamav" if command.endswith("clamav") else "qiling"
            logger.info("Checking %s service status", service)
            status = self._service_status(service)
            self._send_json(conn, {"ok": True, "result": status})
            return True
        if command == "service_info":
            service = request.get("service")
            if service not in ("clamav", "qiling"):
                raise ValueError("service must be clamav or qiling")
            logger.info("Checking %s service status", service)
            self._send_json(conn, {
                "ok": True, "result": self._service_status(service),
            })
            return True
        if command == "recover_samples":
            service = request.get("service")
            if service not in ("clamav", "qiling"):
                raise ValueError("service must be clamav or qiling")
            logger.info("Listing uploaded samples for %s", service)
            self.samples_dir.mkdir(parents=True, exist_ok=True)
            samples = [
                {"name": path.name, "size": path.stat().st_size}
                for path in sorted(self.samples_dir.iterdir())
                if path.is_file() and not path.name.endswith(".part")
            ]
            self._send_json(conn, {"ok": True, "samples": samples})
            return True
        if command == "scan_sample":
            logger.info("Scanning sample %s", request.get("filename"))
            self._send_json(conn, {
                "ok": True, "scan": self._scan_sample(request),
            })
            return True
        
        if command == "check_root_fs":
            check = self._check_if_root_fs_found()
            check.setdefault("ok",True)
    
            if not check:
                logger.error("Root filesystem check failed")
                check["ok"] = False
            else:
                logger.info("Root filesystem check completed")
                check["ok"] = True
            self._send_json(conn,check)
            return True

        if command == "qiling_preflight":
            logger.info("Running Qiling preflight for architecture %s",
                        request.get("architecture"))
            arch = request.get("architecture")
            service = self._service_status("qiling")
            rootfs = self._rootfs_status(arch)
            self._send_json(conn, {
                "ok": True,
                "ready": rootfs["configured"],
                "service": service, "rootfs": rootfs,
            })
            return True
        if command == "qiling_run":
            logger.info("Starting Qiling run for %s", request.get("filename"))
            self._send_json(conn, self._run_qiling(request))
            return True
        if command == "qiling_report":
            logger.info("Sending Qiling report %s", request.get("run_id"))
            self._send_report(conn, request)
            return True
        raise ValueError(f"unknown VM utility command: {command!r}")

    def _scan_sample(self, request: dict) -> dict:
        filename = request.get("filename")
        if not isinstance(filename, str) or not SAFE_FILENAME.fullmatch(filename):
            raise ValueError("sample filename must be a plain safe filename")
        sample = self.samples_dir / filename
        if not sample.is_file():
            raise FileNotFoundError(f"uploaded sample not found: {filename}")
        if clamd is None:
            raise RuntimeError("Python clamd client is not installed")
        result = clamd.ClamdUnixSocket().scan(str(sample))
        if not isinstance(result, dict) or not result:
            raise RuntimeError("ClamAV returned no scan result")
        status, signature = next(iter(result.values()))
        if status not in ("OK", "FOUND"):
            raise RuntimeError(f"ClamAV returned unknown status: {status}")
        return {
            "status": status, "signature": signature if status == "FOUND" else "",
            "detail": "",
        }

    def _check_if_root_fs_found(self):
        N_OF_EXPECTED_FILES = 102
        count_of_dirs = 0
        response = dict({})
        response.setdefault("remote_path",str(self.rootfs_dir.resolve()))
        response.setdefault("expected_files_count",N_OF_EXPECTED_FILES)
        response.setdefault("found_files",0)
        response.setdefault("does_it_exist",False)
        response.setdefault("files_list",list())
        response.setdefault("are_all_files_there",False)
        if not os.path.exists(str(self.rootfs_dir.resolve())):
            logger.warning("Root filesystem directory does not exist: %s",
                           self.rootfs_dir)
            response["does_it_exist"] = False
            return response
    
        response["does_it_exist"] = True
        filename = str()
        for count,filename in enumerate(self.rootfs_dir.rglob("**/*")):
            logger.debug("Checking root filesystem entry %s", filename)
            if filename.is_dir():
                logger.debug("Ignoring root filesystem directory %s", filename)
                count_of_dirs = count_of_dirs + 1
                continue
            response["files_list"].append(str(filename.name))
            count = count - count_of_dirs + 1
            response["found_files"] = count
        if count == N_OF_EXPECTED_FILES:
            logger.info("All expected root filesystem files were found")
            response["are_all_files_there"] = True
        else:
            missing_files = N_OF_EXPECTED_FILES - count
            logger.warning("Root filesystem is missing %d expected files",
                           missing_files)
            response["missing_files"] = missing_files
            response["are_all_files_there"] = True

        return response
     
    def _handle_client(self, conn: socket.socket) -> None:
        peer = "unknown"
        try:
            conn.settimeout(600)
            peer = ipaddress.ip_address(conn.getpeername()[0])
            if not peer.is_loopback and peer not in self.allowed_network:
                raise PermissionError(f"client {peer} is outside the allowed VM network")
            logger.info("Serving VM utility client %s", peer)
            while True:
                line = self._receive_line(conn)
                if not line:
                    logger.info("Client %s disconnected", peer)
                    return
                try:
                    try:
                        decoded = line.decode("utf-8")
                    except UnicodeDecodeError as exc:
                        sample = " ".join(f"{byte:02x}" for byte in line[:32])
                        raise ValueError(
                            "binary data received outside an active upload"
                            + (f": {sample}" if sample else "")) from exc
                    request = json.loads(decoded)
                    if not isinstance(request, dict):
                        raise ValueError("request must be a JSON object")
                    logger.info("Received %s request from %s",
                                request.get("command", "<missing>"), peer)
                    keep_open = self._handle_request(conn, request)
                    logger.info("Completed %s request from %s",
                                request.get("command", "<missing>"), peer)
                    if not keep_open:
                        return
                except (UnicodeDecodeError, json.JSONDecodeError,
                        OSError, RuntimeError, tarfile.TarError,
                        TypeError, ValueError) as exc:
                    logger.exception("Request from %s failed: %s", peer, exc)
                    try:
                        self._send_json(conn, {"ok": False, "error": str(exc)})
                    except OSError:
                        return
                    if not isinstance(exc, (ValueError, RuntimeError, FileNotFoundError)):
                        return
        except ssl.SSLError:
            logger.exception("TLS error while serving client")
        except (ConnectionError, OSError) as exc:
            logger.info("Connection with %s ended: %s", peer, exc)
        except Exception:
            logger.exception("Unexpected VM utility server failure")


if __name__ == "__main__":
    logging.basicConfig(
        level=os.environ.get("VM_UTILITY_LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    host = os.environ.get("VM_UTILITY_HOST", "192.168.56.105")
    try:
        port = int(os.environ.get("VM_UTILITY_PORT", "3310"))
    except ValueError as exc:
        raise SystemExit("VM_UTILITY_PORT must be an integer") from exc
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_2
    certificate = Path(os.environ.get("VM_UTILITY_CERT_FILE", "certs/server.crt"))
    private_key = Path(os.environ.get("VM_UTILITY_KEY_FILE", "certs/server.key"))
    context.load_cert_chain(str(certificate), str(private_key))
    server = VMUtilityServer(host, port, tls_context=context)
    logger.info(
        "VM utility listening with TLS 1.2 on %s:%s (certificate=%s)",
        server.address[0], server.address[1], certificate,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("VM utility server stopping after keyboard interrupt")
    finally:
        server.shutdown()
        logger.info("VM utility server stopped")
