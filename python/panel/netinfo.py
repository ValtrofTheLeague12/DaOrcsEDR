"""Routing facts for a host:port pair - what the address and port actually are.

Lives here rather than in docs.py so both services.py (which annotates every
probe) and docs.py (which renders the reference) can use it. Putting it in
docs.py would mean services.py importing docs, and docs already imports
services - so the dependency would run in a circle.

Every value is derived from the address itself, never guessed from a naming
convention, and anything that cannot be determined is None rather than a
plausible-looking default.
"""

from __future__ import annotations

import ipaddress
import json
import socket
import subprocess

from . import config
# IP + port facts
#
# Every service here answers on a literal address, so the panel can say what
# that address actually IS rather than leaving the admin to work it out: is
# 192.168.56.105 on a /24, is it routable, and is 9092 a registered port or one
# this lab made up.
#
# Everything below is derived from the address itself, never guessed from a
# naming convention, and anything that cannot be determined is None rather than
# a plausible-looking default.
# ---------------------------------------------------------------------------

_PREFIX_CACHE: dict[str, int] = {}
_ADDR_CACHE: dict[str, dict] = {}


def local_addresses() -> dict[str, dict]:
    """{ip: {prefix, interface, index}} for every IPv4 address on this host.

    A single CIM call, cached for the process. This is the only way to know the
    real /24 without asking the user to configure a netmask somewhere - Windows
    already knows it, so there is no reason to make it a setting.

    InterfaceAlias is captured alongside it because "which NIC does this address
    belong to" is the first question about a host that is not 127.0.0.1, and the
    OS already has the answer.
    """
    if _ADDR_CACHE:
        return _ADDR_CACHE
    script = (
        "Get-NetIPAddress -AddressFamily IPv4 | "
        "Select-Object IPAddress,PrefixLength,InterfaceAlias,InterfaceIndex | "
        "ConvertTo-Json -Compress"
    )
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, timeout=15,
            encoding="utf-8", errors="replace", check=False,
        )
        data = json.loads((proc.stdout or "").strip())
    except Exception:  # noqa: BLE001 - no CIM, no prefixes; the UI degrades
        return _ADDR_CACHE
    rows = data if isinstance(data, list) else [data]
    for r in rows:
        if not isinstance(r, dict):
            continue
        ip = str(r.get("IPAddress") or "").strip()
        plen = r.get("PrefixLength")
        if not ip or not isinstance(plen, int) or not 0 <= plen <= 32:
            continue
        idx = r.get("InterfaceIndex")
        _ADDR_CACHE[ip] = {
            "prefix_length": plen,
            "interface": str(r.get("InterfaceAlias") or "").strip() or None,
            "interface_index": idx if isinstance(idx, int) else None,
        }
        _PREFIX_CACHE[ip] = plen
    return _ADDR_CACHE


def local_prefixes() -> dict[str, int]:
    """Back-compat view over local_addresses()."""
    local_addresses()
    return _PREFIX_CACHE


def ip_class(addr: ipaddress.IPv4Address) -> str:
    """Legacy classful class (A-E).

    Reported because operators still ask for it, but classful addressing has
    been obsolete since CIDR in 1993 - 137.x and 140.x are the same size. The
    UI says so next to the badge rather than letting a stale model imply the
    prefix length is derived from the class.
    """
    first = int(str(addr).split(".")[0])
    if first == 0:
        return "reserved"
    if first < 127:
        return "A"
    if first < 192:
        return "B"
    if first < 224:
        return "C"
    if first < 240:
        return "D (multicast)"
    return "E (reserved)"


def scope_of(addr: ipaddress.IPv4Address) -> tuple[str, str]:
    """(scope, one-line meaning)."""
    if addr.is_loopback:
        return "loopback", "Never leaves this machine"
    if addr.is_link_local:
        return "link-local", "Auto-configured on the local link; not routable"
    if addr.is_private:
        return "private", "RFC1918 - not routable on the public internet"
    if addr.is_multicast:
        return "multicast", "Group delivery, not a host address"
    if addr.is_reserved:
        return "reserved", "Reserved by IANA"
    if addr.is_unspecified:
        return "unspecified", "0.0.0.0 - every local interface"
    return "public", "Routable on the public internet"


def ip_facts(host: str) -> dict | None:
    """Class, scope, octets and CIDR for one address. None if not an IP."""
    if not host:
        return None
    # 'localhost' and anything else that is not a literal simply has no octets.
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return {
            "ip": host, "octets": None, "cidr": None, "prefix_length": None,
            "network": None, "hosts": None, "interface": None,
            "interface_index": None,
            "class": None, "scope": "hostname",
            "note": "Not a literal address - resolved by the system at connect time",
        }
    if addr.version != 4:
        return {
            "ip": host, "octets": None, "cidr": None, "prefix_length": None,
            "network": None, "hosts": None, "interface": None,
            "interface_index": None,
            "class": None, "scope": "ipv6", "note": "IPv6 address",
        }

    # Prefixes and interface ownership only exist for addresses bound to THIS
    # host; a remote VM's address has neither, and we do not pretend otherwise.
    local = local_addresses().get(str(addr))
    plen = local["prefix_length"] if local else None
    scope, meaning = scope_of(addr)
    return {
        "ip": str(addr),
        "octets": [int(o) for o in str(addr).split(".")],
        "prefix_length": plen,
        "cidr": f"{addr}/{plen}" if plen is not None else None,
        "network": str(ipaddress.ip_network(f"{addr}/{plen}", strict=False)) if plen is not None else None,
        "hosts": (2 ** (32 - plen) - 2) if plen is not None and plen < 31 else None,
        # Which NIC owns this address - the first question about anything that
        # is not loopback.
        "interface": local["interface"] if local else None,
        "interface_index": local["interface_index"] if local else None,
        "class": ip_class(addr),
        "class_legacy": True,
        "scope": scope,
        "scope_meaning": meaning,
        "note": None if local else "Not an address bound to this host, so its prefix and interface are unknown",
    }


# Ports the lab uses that Windows' services database does not carry. These are
# de-facto conventions, not IANA registrations, and are labelled as such.
_DEFACTO_PORTS = {
    2181: "zookeeper (de-facto)",
    3000: "node/express (de-facto)",
    5432: "postgresql (de-facto)",
    9092: "kafka (de-facto)",
    60000: "malapi (this lab)",
    60001: "cyberchef-api (this lab)",
    60010: "ml scorer (this lab)",
    60020: "analyzer default (this lab)",
    60025: "analyzer via .env (this lab)",
    60100: "admin panel (this lab)",
    61000: "guacamole (this lab)",
    8080: "kafka-ui (this lab)",
    8081: "cyberchef-ui (this lab)",
}


def port_facts(port: int) -> dict:
    """IANA registration and the well-known/registered/dynamic band."""
    try:
        name = socket.getservbyport(port)
        source = "iana"
    except OSError:
        name = None
        source = "unknown"

    if name:
        service, src = name, "iana"
    elif port in _DEFACTO_PORTS:
        service, src = _DEFACTO_PORTS[port], "de-facto"
    else:
        service, src = None, "unregistered"

    if port < 1024:
        band, band_meaning = "well-known", "Ports 0-1023"
    elif port < 49152:
        band, band_meaning = "registered", "Ports 1024-49151"
    else:
        band, band_meaning = "dynamic", "Ports 49152-65535"
    return {
        "port": port,
        "service": service,
        "source": src,
        "band": band,
        "band_meaning": band_meaning,
    }

def network_facts(host: str, port: int) -> dict:
    """Both halves in one call - the shape every consumer stores on a row."""
    return {"ip": ip_facts(host), "port": port_facts(port)}