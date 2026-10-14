"""Cisco NX-OS ``show ip route`` (and ``show ip route vrf <name|all>``).

NX-OS prints a route as a prefix line followed by one ``via`` line per next hop, not as one line per route like IOS::

    IP Route Table for VRF "default"
    '*' denotes best ucast next-hop
    '**' denotes best mcast next-hop
    '[x/y]' denotes [preference/metric]

    0.0.0.0/0, ubest/mbest: 1/0
        *via 10.85.3.26, [1/0], 1y6w, static
    10.85.3.24/29, ubest/mbest: 1/0, attached
        *via 10.85.3.29, Vlan205, [0/0], 1y6w, direct
    10.85.3.25/32, ubest/mbest: 1/0, attached
        *via 10.85.3.25, Vlan205, [0/0], 1y6w, hsrp
    172.16.0.0/16, ubest/mbest: 2/0
        *via 10.0.0.1, Eth1/1, [110/41], 3d04h, ospf-1, intra
        *via 10.0.0.5, Eth1/2, [110/41], 3d04h, ospf-1, intra

so the IOS reader (one route per line, a code letter in front) finds nothing in it. This module reads the NX-OS layout and
returns the same row shape as the IOS reader (``protocol``, ``destination``, ``next_hop``, ``interface``) plus ``vrf``,
``distance``, ``metric``, ``age`` and ``detail`` (route type, tag). An equal-cost route with several next hops gives one row
per next hop.

Layout reference (Cisco, "Configure Route Redistribution on Nexus Switches", the Verify section prints this exact layout,
including ``*via 10.12.1.2, Eth1/36, [110/1], 00:00:57, ospf-21, type-2, tag 6500``):
https://www.cisco.com/c/en/us/support/docs/switches/nexus-9000-series-switches/220615-configure-route-redistribution-on-nexus.html
Real capture it was written against: the TTC Nexus 9000 DMZ pair (``fixtures/real_captures/cisco_nxos_9k_routes_arp_masked.txt``).
"""
from __future__ import annotations

import re
from typing import Any

from . import capture_text
from .show_tables import SHOW, _w

PATTERNS = (rf"{SHOW} ip {_w('route', 2)}(?: vrf \S+)?(?: {_w('unicast', 2)})?",)
HEADERS = (r'^IP Route Table for VRF\s+"?[^"\s]+"?',)

_VRF_HEADER = re.compile(r'^IP Route Table for VRF\s+"?([^"\s]+)"?', re.IGNORECASE)
_PREFIX = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}),\s*ubest/mbest:\s*(\d+)/(\d+)(?:,\s*(.*))?$", re.IGNORECASE)
_VIA = re.compile(r"^\*{0,2}via\s+(.+)$", re.IGNORECASE)
_BRACKET = re.compile(r"^\[(\d+)/(\d+)\]$")
_ADDRESS = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3})(?:%(\S+))?$")


def _parse_via(text: str) -> dict[str, Any]:
    """``10.0.0.1, Eth1/1, [110/41], 3d04h, ospf-1, intra`` -> next hop, interface, preference, metric, age, protocol, detail."""
    fields = [part.strip() for part in text.split(",") if part.strip()]
    out: dict[str, Any] = {"next_hop": "", "interface": "", "distance": "", "metric": "", "age": "", "protocol": "", "detail": "", "next_hop_vrf": ""}
    index = 0
    # before the [preference/metric] bracket: next-hop address and/or the outgoing interface
    while index < len(fields) and not _BRACKET.match(fields[index]):
        address = _ADDRESS.match(fields[index])
        if address and not out["next_hop"]:
            out["next_hop"], out["next_hop_vrf"] = address.group(1), address.group(2) or ""
        elif not out["interface"]:
            out["interface"] = fields[index]
        index += 1
    if index < len(fields):
        bracket = _BRACKET.match(fields[index])
        out["distance"], out["metric"] = bracket.group(1), bracket.group(2)
        index += 1
    tail = fields[index:]
    if tail:
        out["age"] = tail[0]
    if len(tail) > 1:
        out["protocol"] = tail[1]
    if len(tail) > 2:
        out["detail"] = ", ".join(tail[2:])
    return out


def parse_block(lines: list[str]) -> dict[str, list[dict[str, Any]]]:
    """One command's output -> ``{vrf: [route rows]}`` (``show ip route vrf all`` holds several tables)."""
    tables: dict[str, list[dict[str, Any]]] = {}
    vrf = "default"
    current: dict[str, Any] | None = None
    for line in lines:
        text = line.strip()
        if not text:
            continue
        header = _VRF_HEADER.match(text)
        if header:
            vrf, current = header.group(1), None
            tables.setdefault(vrf, [])
            continue
        prefix = _PREFIX.match(text)
        if prefix:
            flags = (prefix.group(4) or "").strip()
            current = {"destination": prefix.group(1), "ubest": int(prefix.group(2)), "mbest": int(prefix.group(3)), "flags": flags}
            continue
        via = _VIA.match(text)
        if via and current is not None:
            hop = _parse_via(via.group(1))
            if not (hop["next_hop"] or hop["interface"]):
                continue
            tables.setdefault(vrf, []).append({
                "protocol": hop["protocol"], "destination": current["destination"], "next_hop": hop["next_hop"], "interface": hop["interface"],
                "vrf": vrf, "distance": hop["distance"], "metric": hop["metric"], "age": hop["age"], "detail": hop["detail"],
                "attached": "attached" in current["flags"].lower(),
            })
    return tables


def parse_ip_routes(clean: list[str]) -> list[dict[str, Any]]:
    """Route rows of every VRF found in the capture. When the command was run more than once the fullest run of each VRF wins."""
    best: dict[str, list[dict[str, Any]]] = {}
    for _index, block in capture_text.find_blocks(clean, PATTERNS, HEADERS):
        if block and re.match(r"^\s*(?:%|\^|invalid input|error:)", block[0], re.IGNORECASE):
            continue
        for vrf, rows in parse_block(block).items():
            if len(rows) >= len(best.get(vrf, [])):
                best[vrf] = rows
    out: list[dict[str, Any]] = []
    for vrf in sorted(best, key=lambda name: (name != "default", name)):
        out.extend(best[vrf])
    return out
