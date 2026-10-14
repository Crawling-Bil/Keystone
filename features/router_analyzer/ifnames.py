"""Cisco interface-name normalisation.

The same interface shows up under different spellings depending on the
command: ``GigabitEthernet0/1/2`` (show ip interface brief), ``Gi0/1/2``
(show interface description), ``BDI735`` vs ``BD735``, ``Sdwan-system-intf``
vs ``Sdwan-intf``.  :func:`canon` maps every spelling to one key so tables
from different commands can be joined.
"""

from __future__ import annotations

import re

# (abbreviation prefix, canonical long name)   -- longest prefixes first
_ALIASES: list[tuple[str, str]] = [
    ("hundredgige", "HundredGigE"),
    ("fortygigabitethernet", "FortyGigabitEthernet"),
    ("twentyfivegige", "TwentyFiveGigE"),
    ("tengigabitethernet", "TenGigabitEthernet"),
    ("gigabitethernet", "GigabitEthernet"),
    ("fastethernet", "FastEthernet"),
    ("port-channel", "Port-channel"),
    ("portchannel", "Port-channel"),
    ("sdwan-system-intf", "Sdwan-system-intf"),
    ("sdwan-intf", "Sdwan-system-intf"),
    ("vmanage_system", "vmanage_system"),
    ("virtual-access", "Virtual-Access"),
    ("virtual-template", "Virtual-Template"),
    ("multilink", "Multilink"),
    ("loopback", "Loopback"),
    ("cellular", "Cellular"),
    ("ethernet", "Ethernet"),
    ("tunnel", "Tunnel"),
    ("serial", "Serial"),
    ("dialer", "Dialer"),
    ("vlan", "Vlan"),
    ("null", "Null"),
    ("bdi", "BDI"),
    ("nvi", "NVI"),
    ("mgmt", "Mgmt"),
    ("atm", "ATM"),
    ("pos", "POS"),
    ("hu", "HundredGigE"),
    ("fo", "FortyGigabitEthernet"),
    ("twe", "TwentyFiveGigE"),
    ("te", "TenGigabitEthernet"),
    ("gig", "GigabitEthernet"),
    ("gi", "GigabitEthernet"),
    ("fa", "FastEthernet"),
    ("eth", "Ethernet"),
    ("et", "Ethernet"),
    ("po", "Port-channel"),
    ("lo", "Loopback"),
    ("tu", "Tunnel"),
    ("se", "Serial"),
    ("di", "Dialer"),
    ("vl", "Vlan"),
    ("nu", "Null"),
    ("nv", "NVI"),
    ("bd", "BDI"),
    ("ce", "Cellular"),
    ("mu", "Multilink"),
    ("vi", "Virtual-Access"),
    ("vt", "Virtual-Template"),
]
_SPLIT = re.compile(r"^([A-Za-z_\-]+?)\s*([0-9].*)?$")


def canon(name: str) -> str:
    """Canonical long form, e.g. ``Gi0/1/2`` -> ``GigabitEthernet0/1/2``."""
    text = (name or "").strip()
    if not text:
        return ""
    text = text.replace(" ", "")
    match = _SPLIT.match(text)
    if not match:
        return text
    prefix, rest = match.group(1), match.group(2) or ""
    low = prefix.lower()
    for alias, long_name in _ALIASES:
        if low == alias or (len(low) >= 3 and alias.startswith(low) and len(alias) > 3):
            return long_name + rest
    return prefix + rest


def short(name: str) -> str:
    """Compact display form (Gi0/1/2) used in cross-reference columns."""
    long_name = canon(name)
    for alias, canonical in (
        ("Gi", "GigabitEthernet"), ("Fa", "FastEthernet"), ("Te", "TenGigabitEthernet"), ("Po", "Port-channel"),
        ("Lo", "Loopback"), ("Tu", "Tunnel"), ("Vl", "Vlan"), ("Se", "Serial"),
    ):
        if long_name.startswith(canonical):
            return alias + long_name[len(canonical):]
    return long_name
