"""Small address helpers shared by the firewall analyzers."""

from __future__ import annotations

import ipaddress

_RFC1918_ETC = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16", "127.0.0.0/8",
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "0.0.0.0/8", "224.0.0.0/4",
)]


def to_cidr(address: str, mask: str = "") -> str:
    """'10.0.0.0 255.255.255.0' or ('10.0.0.0', '255.255.255.0') -> '10.0.0.0/24'; unparsable input is returned as is."""
    text = (address or "").strip()
    if not mask and " " in text:
        text, _, mask = text.partition(" ")
    mask = mask.strip()
    try:
        if mask:
            return str(ipaddress.ip_network(f"{text}/{mask}", strict=False)) if "/" not in text else text
        return str(ipaddress.ip_network(text, strict=False)) if "/" in text else text
    except ValueError:
        return f"{text} {mask}".strip()


def to_iface(address: str, mask: str = "") -> str:
    """Like :func:`to_cidr` but keeps the host part: '10.0.0.1 255.255.255.0' -> '10.0.0.1/24'."""
    text = (address or "").strip()
    if not mask and " " in text:
        text, _, mask = text.partition(" ")
    mask = mask.strip()
    try:
        if mask and "/" not in text:
            return str(ipaddress.ip_interface(f"{text}/{mask}"))
        return str(ipaddress.ip_interface(text)) if "/" in text else text
    except ValueError:
        return f"{text} {mask}".strip()


def is_any_network(value: str) -> bool:
    text = (value or "").strip().lower()
    return text in ("0.0.0.0/0", "0.0.0.0 0.0.0.0", "any", "all", "::/0", "")


def is_public_ip(address: str) -> bool:
    """True for a routable (non-private, non-documentation) IPv4 address.  Documentation ranges count as
    private on purpose so that sample configs are not reported as internet-facing."""
    try:
        ip = ipaddress.ip_address(address.split("/")[0].split()[0])
    except (ValueError, IndexError):
        return False
    if ip.version != 4:
        return not (ip.is_private or ip.is_link_local or ip.is_loopback)
    return not any(ip in net for net in _RFC1918_ETC)


def prefix_len(address_with_mask: str) -> int | None:
    try:
        return ipaddress.ip_network(to_cidr(address_with_mask), strict=False).prefixlen
    except ValueError:
        return None
