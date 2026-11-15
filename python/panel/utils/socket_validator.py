"""Validated TCP client helpers used by the panel's VM utilities."""

from __future__ import annotations

import ipaddress
import os
from pathlib import Path
import socket
import ssl
import ifaddr
from loguru import logger


class SocketValidator:
    def __init__(self, ip: str):
        if not isinstance(ip, str) or not ip.strip():
            raise TypeError("A non-empty IP address string is required")
        self.__ip = ip.strip()
        try:
            self.__ip_object = ipaddress.ip_address(self.__ip)
        except ValueError as exc:
            logger.warning("Rejected invalid IP address {!r}: {}", self.__ip, exc)
            raise ValueError(f"Invalid IP address: {self.__ip!r}") from exc

        if not self.__Check_if_ip_belongs_to_interface():
            raise ValueError(
                f"IP address {self.__ip} is not on a local or host-only interface"
            )

    @staticmethod
    def __ValidatePort(port: int) -> bool:
        return isinstance(port, int) and not isinstance(port, bool) and 0 < port <= 65535

    @staticmethod
    def closeConnection(sock: socket.socket | None) -> None:
        if sock is None or sock.fileno() < 0:
            logger.debug("Socket is already closed")
            return
        logger.debug("Closing socket")
        sock.close()

    def establish_tcp_connection(
        self, connection_port: int, timeout: float = 6.0
    ) -> socket.socket | None:
        if not self.__ValidatePort(connection_port):
            logger.warning("Invalid TCP port: {!r}", connection_port)
            return None
        sock = None
        try:
            certificate = Path(os.environ.get(
                "VM_UTILITY_CA_FILE",
                Path(__file__).resolve().with_name("cert") / "server.crt",
            )).expanduser()
            context = ssl.create_default_context(
                ssl.Purpose.SERVER_AUTH, cafile=str(certificate)
            )
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.maximum_version = ssl.TLSVersion.TLSv1_2
            sock = socket.create_connection(
                (self.__ip, connection_port), timeout=timeout
            )
            sock = context.wrap_socket(sock, server_hostname=self.__ip)
            sock.settimeout(120)
        except (OSError, ssl.SSLError) as exc:
            if sock is not None:
                sock.close()
            logger.warning(
                "Could not establish verified TLS 1.2 connection to {}:{}: {}",
                self.__ip, connection_port, exc,
            )
            return None
        logger.info(
            "Established TLS {} connection to {}:{} using {}",
            sock.version(), self.__ip, connection_port, sock.cipher()[0],
        )
        return sock

    def test_connection_using_a_socket(
            self, connection_port: int, grab_banner: bool = False
    ) -> tuple[bool, bytes | None]:
        if not self.__ValidatePort(connection_port):
            logger.warning("Invalid TCP port: {!r}", connection_port)
            return False, None
        try:
            with socket.create_connection(
                (self.__ip, connection_port), timeout=3.0
            ) as sock:
                logger.info("Connected to TCP endpoint {}:{}", self.__ip, connection_port)
                if not grab_banner:
                    return True, None
                try:
                    return True, sock.recv(1024)
                except socket.timeout:
                    logger.warning("Banner read timed out from {}:{}", self.__ip, connection_port)
                    return True, None
        except OSError as exc:
            logger.warning(
                "Could not connect to {}:{}: {}", self.__ip, connection_port, exc
            )
            return False, None

    def return_information_about_ip(self) -> dict[str, str | int]:
        return {
            "ip_addr": self.__ip,
            "version": self.__ip_object.version,
        }

    def __Check_if_ip_belongs_to_interface(self) -> bool:
        logger.debug("Checking whether {} belongs to a local interface", self.__ip)
        # The host-only VM network is reachable even when its guest address is
        # not assigned to a host interface.
        if (self.__ip_object.version == 4
                and self.__ip_object in ipaddress.ip_network("192.168.56.0/24")):
            return True

        for adapter in ifaddr.get_adapters():
            for interface_ip in adapter.ips:
                address = interface_ip.ip
                if isinstance(address, tuple):
                    address = address[0]
                address = str(address).split("%", 1)[0]
                try:
                    if ipaddress.ip_address(address) == self.__ip_object:
                        logger.debug("IP {} found on interface {}", self.__ip, adapter.nice_name)
                        return True
                except ValueError:
                    logger.debug("Ignoring unparseable interface address {!r}", address)
        return False


if __name__ == "__main__":
    validator = SocketValidator("127.0.0.1")
    logger.info("Connection result: {}", validator.test_connection_using_a_socket(22, True))
