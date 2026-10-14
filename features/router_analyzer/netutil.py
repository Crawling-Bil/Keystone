"""Small IPv4 helpers shared by the config and runtime parsers."""

from __future__ import annotations

import ipaddress
import re

IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def is_ipv4(text: str) -> bool:
    if not IPV4_RE.match(text or ""):
        return False
    return all(0 <= int(part) <= 255 for part in text.split("."))


def mask_to_len(mask: str) -> int | None:
    """255.255.255.252 -> 30; returns None for non-contiguous / invalid."""
    if not is_ipv4(mask):
        return None
    value = int(ipaddress.IPv4Address(mask))
    binary = f"{value:032b}"
    if "01" in binary:
        return None
    return binary.count("1")


def wildcard_to_len(wildcard: str) -> int | None:
    """0.0.0.255 -> 24 (only for contiguous wildcards)."""
    if not is_ipv4(wildcard):
        return None
    value = int(ipaddress.IPv4Address(wildcard)) ^ 0xFFFFFFFF
    binary = f"{value:032b}"
    if "01" in binary:
        return None
    return binary.count("1")


def cidr(address: str, mask: str) -> str:
    length = mask_to_len(mask)
    return f"{address}/{length}" if length is not None else f"{address} {mask}"


def acl_addr(address: str, wildcard: str | None) -> str:
    """Render an ACL address+wildcard compactly."""
    if wildcard is None:
        return address
    if wildcard == "0.0.0.0":
        return f"{address}/32"
    length = wildcard_to_len(wildcard)
    if length is not None:
        return f"{address}/{length}"
    return f"{address} wildcard {wildcard}"


def prefix_len_of(prefix: str) -> int:
    if "/" in prefix:
        try:
            return int(prefix.split("/")[1])
        except ValueError:
            return 0
    return 32


def is_private(address: str) -> bool:
    try:
        return ipaddress.ip_address(address).is_private
    except ValueError:
        return False


def sort_key_ip(text: str) -> tuple:
    try:
        return (0, int(ipaddress.ip_address(text.split("/")[0])), prefix_len_of(text))
    except ValueError:
        return (1, 0, 0)


def human_bytes(value: int | float | None) -> str:
    """1536 -> '1.5 KB' (1024-based, as the router reports flash and memory)."""
    if value is None:
        return "?"
    value = float(value)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} TB"
