"""Sizing Assessment — rolls up one or more already-analyzed Switch
Analyzer results (the same dicts service.analyze() returns) into the
per-device and aggregate numbers a TAM replacement-sizing exercise
actually needs: physical port counts by speed, PoE budget, uplink/
trunk count, VLAN/route/redundancy complexity, and stacking.

Deliberately builds on data already computed elsewhere in this module
rather than re-parsing anything — every field here traces back to a
field runtime_parser.py/service.py already populates and, where
applicable, already verified against real device captures (see
memory-keystone.md Section 1q/1r/1s/1t). The one genuinely new piece
of logic is _categorize_interface_type(), documented below.
"""
from __future__ import annotations

import re
from typing import Any

# Physical port speed, by interface-name prefix. Longest/most-specific
# prefixes are listed first purely for readability — Python's
# str.startswith() is exact-position matching, so e.g. "10GE1/0/1"
# genuinely doesn't start with "GE" (it starts with "1"), and Cisco's
# "GigabitEthernet..." doesn't start with Huawei's "GE" either (case
# sensitive: 'i' != 'E') — there's no real prefix collision here, this
# ordering is just for a human reading the list top to bottom.
#
# Confirmed against real interface names across this project's actual
# captures: Cisco IOS/IOS-XE full names (GigabitEthernet1/0/1,
# TenGigabitEthernet1/1/1, ...) and Huawei VRP's short numeric-prefixed
# names (GE1/0/1, 10GE1/0/1, 25GE1/0/3, 100GE1/0/1 — from real TAM
# draft configs ADM-SWCODI-S5755.txt / TTC-SWCODI-MN-DMZ-S5755.txt).
_PHYSICAL_PORT_TYPE_PREFIXES = [
    ("HundredGigE", "100G"), ("FortyGigabitEthernet", "40G"),
    ("TwentyFiveGigE", "25G"), ("TenGigabitEthernet", "10G"),
    ("GigabitEthernet", "1G"), ("FastEthernet", "100M"),
    ("100GE", "100G"), ("40GE", "40G"), ("25GE", "25G"), ("10GE", "10G"), ("GE", "1G"),
]
# Logical/non-physical interfaces — excluded from physical port counts
# entirely rather than miscounted as a "port".
_LOGICAL_PREFIXES = [
    ("Port-channel", "Port-Channel"), ("Eth-Trunk", "Port-Channel"),
    ("Vlanif", "SVI"), ("Vlan", "SVI"),
    ("Loopback", "Loopback"), ("LoopBack", "Loopback"),
    ("MEth", "Management"), ("mgmt", "Management"),
]
_BARE_ETHERNET_RE = re.compile(r"^(Ethernet|Eth)\d", re.IGNORECASE)
_BARE_NUMBER_RE = re.compile(r"^\d+$")

# Transceiver "type" strings differ in exact spelling between vendors
# for the SAME physical SFP/QSFP class — confirmed on real captures in
# this project: Cisco IOS-XE's "show interface transceiver" calls one
# "1000BaseSX SFP" (GTOPAS-SMG-SWCO-C3650), while ArubaOS-Switch's own
# "show transceiver" table calls the identical transceiver class
# "1000SX" (TTC-SWAC-PABXGA2-2540, port 25) — same purchasable part,
# different vendor's abbreviation. Counting those as two separate line
# items would undercount how many of each real SFP class need
# replacing. Only aliases CONFIRMED on real data here, or the
# textbook-standard short form for the exact same IEEE 802.3/SFF media
# type, are normalized — anything not recognized is left exactly as
# the device reported it rather than guessed at.
_TRANSCEIVER_TYPE_ALIASES = {
    "1000sx": "1000BaseSX SFP",
    "1000lx": "1000BaseLX SFP",
    "1000t": "10/100/1000BaseTX SFP",
    "1000-t": "10/100/1000BaseTX SFP",
}


def _normalize_transceiver_type(raw: str) -> str:
    text = (raw or "").strip()
    if not text:
        return "Unknown"
    return _TRANSCEIVER_TYPE_ALIASES.get(text.lower(), text)


def _categorize_interface_type(name: str) -> str | None:
    """Physical-port speed bucket for `name`, or None if `name` is a
    logical interface (Port-Channel/SVI/Loopback/Management) that
    should be excluded from physical port counts altogether.

    Two real, honestly-unresolvable cases, both confirmed against real
    captures in this project rather than assumed: Cisco NX-OS names
    physical ports "Ethernet1/49" with NO speed encoded in the name at
    all (unlike Catalyst's "GigabitEthernet"/"TenGigabitEthernet" full
    names) — the actual speed only shows up in a per-interface "speed
    <n>" config line, which isn't parsed into the shared model yet;
    ArubaOS-Switch names ports as bare numbers ("interface 15") with
    the same problem. Both are reported as their own explicit "can't
    tell from the name" bucket rather than silently miscounted into
    the wrong speed tier or silently dropped.
    """
    for prefix, label in _LOGICAL_PREFIXES:
        if name.startswith(prefix):
            return None
    for prefix, label in _PHYSICAL_PORT_TYPE_PREFIXES:
        if name.startswith(prefix):
            return label
    if _BARE_ETHERNET_RE.match(name):
        return "Ethernet (speed not in name — check model/config)"
    if _BARE_NUMBER_RE.match(name):
        return "Port (speed not in name — check model)"
    return "Other"


def _device_sizing_row(result: dict[str, Any]) -> dict[str, Any]:
    interfaces = result.get("interfaces", [])
    port_type_counts: dict[str, int] = {}
    physical_up = 0
    physical_down = 0
    trunk_count = 0

    for iface in interfaces:
        label = _categorize_interface_type(iface.get("name", ""))
        if iface.get("mode") == "trunk":
            trunk_count += 1
        if label is None:
            continue
        port_type_counts[label] = port_type_counts.get(label, 0) + 1
        if str(iface.get("status", "")).lower() == "up":
            physical_up += 1
        else:
            physical_down += 1

    poe = result.get("poe", [])
    poe_total_watts = 0.0
    for item in poe:
        try:
            poe_total_watts += float(item.get("power_watts") or 0)
        except (TypeError, ValueError):
            continue

    transceiver_type_counts: dict[str, int] = {}
    for transceiver in result.get("transceivers", []):
        if not transceiver.get("present", True):
            continue
        label = _normalize_transceiver_type(transceiver.get("type", ""))
        transceiver_type_counts[label] = transceiver_type_counts.get(label, 0) + 1

    vpc_mlag = result.get("vpc_mlag") or {}
    vpc_source = vpc_mlag.get("source", "none")

    hsrp_vrrp_svi_count = sum(1 for i in interfaces if i.get("hsrp_vrrp_ip"))

    routing = result.get("routing_protocols") or {}
    stack = (result.get("inventory") or {}).get("stack") or {}

    return {
        "hostname": result.get("hostname", ""),
        "vendor": result.get("vendor", ""),
        "model": (result.get("os_version") or {}).get("model", ""),
        "os_version": (result.get("os_version") or {}).get("os_version", ""),
        "physical_port_count": physical_up + physical_down,
        "physical_ports_up": physical_up,
        "physical_ports_down": physical_down,
        "port_type_counts": port_type_counts,
        "trunk_port_count": trunk_count,
        "port_channel_count": len(result.get("port_channels", [])),
        "poe_port_count": len(poe),
        "poe_total_watts": round(poe_total_watts, 1),
        "poe_source": poe[0].get("source", "") if poe else "",
        "transceiver_count": sum(transceiver_type_counts.values()),
        "transceiver_type_counts": transceiver_type_counts,
        "vlan_count": len(result.get("vlans", [])),
        "static_route_count": len(result.get("routes", [])),
        "ospf_configured": bool(routing.get("ospf")),
        "vpc_mlag_configured": vpc_source in ("live", "config"),
        "vpc_mlag_source": vpc_source,
        "vpc_mlag_member_count": len(vpc_mlag.get("members", [])),
        "hsrp_vrrp_svi_count": hsrp_vrrp_svi_count,
        "stack_mode": stack.get("mode") or "Unknown",
        "stack_member_count": stack.get("member_count") or 1,
    }


def build_sizing_summary(results: list[dict[str, Any]]) -> dict[str, Any]:
    """Per-device rows plus one aggregate/totals row across every
    device in `results` — the batch a Sizing Assessment run is built
    from (see routes.py's /api/sizing and /api/export).
    """
    devices = [_device_sizing_row(result) for result in results]

    unique_vlan_ids: set[Any] = set()
    for result in results:
        for vlan in result.get("vlans", []):
            unique_vlan_ids.add(vlan.get("vlan_id"))

    port_type_totals: dict[str, int] = {}
    transceiver_type_totals: dict[str, int] = {}
    for device in devices:
        for label, count in device["port_type_counts"].items():
            port_type_totals[label] = port_type_totals.get(label, 0) + count
        for label, count in device["transceiver_type_counts"].items():
            transceiver_type_totals[label] = transceiver_type_totals.get(label, 0) + count

    # "What to buy" needs the exact orderable SKU, not just the media
    # class — two transceivers reported under the identical normalized
    # type ("1000BaseSX SFP") can still be different real parts (e.g. a
    # genuine Cisco GLC-SX-MMD vs. a third-party/compatible optic with
    # its own vendor code), confirmed real on this project's own
    # captures where "show inventory"'s PID for an SFP entry
    # (GLC-LH-SMD) is a distinct field from "show interface
    # transceiver"'s type column. Breaks the aggregate down one level
    # further than transceiver_type_totals above (kept as-is for
    # backward compatibility) so a reviewer sees Type + Vendor Part
    # Number + Count together — computed directly from the raw
    # per-result transceiver rows rather than through
    # `devices`/`_device_sizing_row` so this stays JSON-safe (a
    # (type, part_number) tuple can't be a dict key once serialized).
    transceiver_part_totals: dict[tuple[str, str], int] = {}
    for result in results:
        for transceiver in result.get("transceivers", []):
            if not transceiver.get("present", True):
                continue
            label = _normalize_transceiver_type(transceiver.get("type", ""))
            part_number = (transceiver.get("vendor_part_number") or "").strip() or "Unknown"
            key = (label, part_number)
            transceiver_part_totals[key] = transceiver_part_totals.get(key, 0) + 1

    totals = {
        "device_count": len(devices),
        "physical_port_count": sum(d["physical_port_count"] for d in devices),
        "physical_ports_up": sum(d["physical_ports_up"] for d in devices),
        "physical_ports_down": sum(d["physical_ports_down"] for d in devices),
        "port_type_totals": port_type_totals,
        "trunk_port_count": sum(d["trunk_port_count"] for d in devices),
        "port_channel_count": sum(d["port_channel_count"] for d in devices),
        "poe_port_count": sum(d["poe_port_count"] for d in devices),
        "poe_total_watts": round(sum(d["poe_total_watts"] for d in devices), 1),
        "transceiver_count": sum(d["transceiver_count"] for d in devices),
        "transceiver_type_totals": transceiver_type_totals,
        "transceiver_part_totals": [
            {"type": type_label, "vendor_part_number": part_number, "count": count}
            for (type_label, part_number), count in sorted(transceiver_part_totals.items())
        ],
        "unique_vlan_count": len(unique_vlan_ids),
        "static_route_count": sum(d["static_route_count"] for d in devices),
        "ospf_device_count": sum(1 for d in devices if d["ospf_configured"]),
        "vpc_mlag_device_count": sum(1 for d in devices if d["vpc_mlag_configured"]),
        "hsrp_vrrp_svi_count": sum(d["hsrp_vrrp_svi_count"] for d in devices),
        "stacked_device_count": sum(
            1 for d in devices if d["stack_mode"] not in ("Standalone", "Unknown", "")
        ),
    }

    return {"devices": devices, "totals": totals}
