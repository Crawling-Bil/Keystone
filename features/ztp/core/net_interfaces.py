"""Enumerate local network interfaces for the ZTP UI's SFTP bind-IP and
DHCP interface dropdowns, so the user picks from what's actually
present on this machine instead of typing an interface name or IP
address by hand (a wrong interface here is exactly how the DHCP server
becomes a rogue DHCP server on the wrong network -- see dhcp_server.py).

Read-only. Listing interfaces (psutil.net_if_addrs()/net_if_stats())
needs no elevated privileges on Windows, macOS, or Linux. Actually
BINDING dnsmasq to UDP/67 is a separate, later concern handled in
dhcp_server.py -- that does typically need root/administrator
privileges, this module has nothing to do with that.
"""

from __future__ import annotations

import ipaddress
import socket

import psutil


def list_interfaces(include_down=False, include_loopback=False):
    """Return one entry per local network interface that has at least
    one IPv4 address:

        {"name": "en7", "up": True, "mac": "ac:de:48:00:11:22",
         "ipv4_addresses": ["192.168.99.5"]}

    Sorted with "up" interfaces first, then alphabetically by name, so
    the interface someone actually cares about (the one they just
    plugged a switch into) tends to sort near the top.

    include_down: also list interfaces psutil reports as not "up"
        (still occasionally useful -- e.g. right after plugging in a
        USB-Ethernet adapter, before the OS has renegotiated link).
    include_loopback: also list loopback interfaces. Excluded by
        default -- neither the SFTP nor DHCP server is useful bound to
        loopback for a real switch on the other end of a cable.
    """
    stats = psutil.net_if_stats()
    addrs = psutil.net_if_addrs()

    results = []
    for name, addr_list in addrs.items():
        is_up = bool(stats.get(name) and stats[name].isup)
        if not include_down and not is_up:
            continue

        ipv4_addresses = []
        mac = ""
        for addr in addr_list:
            if addr.family == socket.AF_INET:
                ipv4_addresses.append(addr.address)
            elif addr.family == getattr(psutil, "AF_LINK", None):
                mac = addr.address

        if not ipv4_addresses:
            # No IPv4 address means it can't usefully be a DHCP/SFTP
            # bind target for this feature (VRP ZTP over IPv4).
            continue

        is_loopback = name.lower().startswith(("lo", "loopback")) or any(
            _is_loopback_ip(ip) for ip in ipv4_addresses
        )
        if is_loopback and not include_loopback:
            continue

        results.append({
            "name": name,
            "up": is_up,
            "mac": mac,
            "ipv4_addresses": ipv4_addresses,
        })

    results.sort(key=lambda entry: (not entry["up"], entry["name"]))
    return results


def _is_loopback_ip(ip_text):
    try:
        return ipaddress.ip_address(ip_text).is_loopback
    except ValueError:
        return False
