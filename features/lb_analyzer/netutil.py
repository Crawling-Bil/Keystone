"""Address helpers for the Load Balancer Analyzer."""

from __future__ import annotations

import ipaddress

_PRIVATE = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16", "127.0.0.0/8",
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "0.0.0.0/8", "224.0.0.0/4",
)]


def is_public_ip(address: str) -> bool:
    """True for a routable IPv4/IPv6 address.  Documentation ranges count as private on purpose so that
    sample configurations are not reported as internet-facing."""
    text = (address or "").strip().split("/")[0].split("%")[0]
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return False
    if ip.version != 4:
        return not (ip.is_private or ip.is_link_local or ip.is_loopback or ip.is_multicast or ip.is_unspecified)
    return not any(ip in net for net in _PRIVATE)


def is_wildcard(address: str) -> bool:
    return (address or "").strip() in ("0.0.0.0", "::", "any", "*", "0.0.0.0/0", "::/0")


def strip_rd(address: str) -> tuple[str, str]:
    """'10.1.1.1%2' -> ('10.1.1.1', '2') (route domain suffix)."""
    if "%" in address:
        host, _, rd = address.partition("%")
        return host, rd.split("/")[0]
    return address, ""


def parse_destination(raw: str) -> tuple[str, int, str]:
    """'/Common/10.1.1.1%2:443' -> ('10.1.1.1', 443, '2'); 'any' port is 0.  IPv6 uses a dot before the port."""
    body = raw.rsplit("/", 1)[-1]
    if body.count(":") > 1:
        host, _, port = body.rpartition(".")
    else:
        host, _, port = body.rpartition(":")
    host, rd = strip_rd(host)
    if port.isdigit():
        number = int(port)
    else:
        number = 0
    return host, number, rd


def parse_address_member(raw: str) -> tuple[str, int]:
    """Pool member '/Common/10.1.1.11:80' or '/Common/web01:8080' -> (address-or-node-name, port)."""
    host, port, _ = parse_destination(raw)
    return host, port
