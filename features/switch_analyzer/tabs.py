"""Which tabs of the Single Device page have something to show for one capture.

The Router Analyzer builds its tabs from the sections a capture produced. The Switch Analyzer page
has a fixed set of tabs, so this module decides, per tab, whether the capture gave it data. The page
shows the tabs that have data and lists the others as "not in this capture" with the command that
would fill them, instead of showing sixteen tabs that say "No data".

A tab has data when the parser returned rows **or** the command for that tab is in the capture (an
empty ARP table that was captured is an answer, a missing one is not). ``why`` is the sentence shown
for a hidden tab.
"""
from __future__ import annotations

from typing import Any

from . import coverage

# tab key -> (label, coverage spec keys that fill it)
TAB_ORDER: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("overview", "Overview", ()),
    ("findings", "Findings", ()),
    ("health", "Health", ("stp_summary", "lacp", "env", "licence")),
    ("interfaces", "Interfaces", ("interfaces",)),
    ("routing", "Routing", ("route",)),
    ("arp", "ARP", ("arp",)),
    ("mac", "MAC Table", ("mac",)),
    ("vlans", "VLANs", ("vlan", "vlan_summary")),
    ("neighbors", "CDP/LLDP", ("neighbors",)),
    ("portchannels", "Port-Channel", ("portchannel",)),
    ("trunks", "Trunks", ("trunk",)),
    ("stp", "Spanning Tree", ("stp",)),
    ("transceivers", "Transceivers", ("transceivers",)),
    ("vpcmlag", "vPC/M-LAG", ("vpcmlag",)),
    ("poe", "PoE", ("poe",)),
    ("dns", "DNS", ()),
    ("snmp", "SNMP", ()),
    ("dhcp", "DHCP", ()),
    ("logs", "Logs", ("logs",)),
    ("coverage", "Coverage", ()),
)


# Tabs whose badge is a plain row count. Routing shows the routes of the device's own table, Health /
# DNS / SNMP / DHCP show no number (their "count" would add unlike things together).
_COUNT_TABS = frozenset({"interfaces", "arp", "mac", "vlans", "neighbors", "portchannels", "trunks", "transceivers", "vpcmlag", "poe"})


def _len(value: Any) -> int:
    return len(value) if hasattr(value, "__len__") else 0


def _routing_count(result: dict[str, Any]) -> int:
    l3 = result.get("l3") or {}
    table = l3.get("routing_table") or {}
    acls = l3.get("acls") or {}
    ospf = l3.get("ospf") or {}
    pbr = result.get("pbr") or {}
    return (_len(l3.get("interfaces")) + _len(l3.get("default_routes")) + _len(l3.get("static_routes")) + _len(result.get("routing_table"))
            + _len(ospf.get("processes")) + _len(acls.get("definitions")) + _len(l3.get("other_protocols"))
            + (1 if pbr.get("has_custom_routing") else 0) + (1 if table.get("captured") else 0))


def _counts(result: dict[str, Any]) -> dict[str, int | None]:
    health = result.get("health") or {}
    env = health.get("environment") or {}
    dhcp = result.get("dhcp") or {}
    snooping = dhcp.get("snooping") or {}
    dns = result.get("dns") or {}
    snmp = result.get("snmp") or {}
    vpc = result.get("vpc_mlag") or {}
    health_data = bool(health.get("supported") and (
        health.get("findings") or health.get("stp") or health.get("lacp") or env.get("sensors") or env.get("fans") or env.get("power_supplies") or env.get("rows")
        or (health.get("licence") or {}).get("licenses") or (health.get("licence") or {}).get("smart_account") or health.get("software")
        or ((health.get("licence") or {}).get("detail") or {}).get("captured")
        or any(table.get("tab") == "health" and table.get("rows") for table in result.get("extra_tables") or [])))
    return {
        "interfaces": _len(result.get("interfaces")),
        "routing": _routing_count(result),
        "arp": _len(result.get("arp_table")),
        "mac": _len(result.get("mac_table")),
        "vlans": _len(result.get("vlans")),
        "neighbors": _len(result.get("neighbors")),
        "portchannels": _len(result.get("port_channels")),
        "trunks": _len((result.get("trunks") or {}).get("rows")),
        "stp": _len((result.get("spanning_tree") or {}).get("instances")),
        "transceivers": _len(result.get("transceivers")),
        "vpcmlag": _len(vpc.get("members")) + (1 if vpc.get("summary") else 0),
        "poe": _len(result.get("poe")),
        "dns": _len(dns.get("servers")) + (1 if dns.get("domain") else 0),
        "snmp": (1 if snmp.get("enabled") else 0) + _len(snmp.get("raw_commands")),
        "dhcp": (1 if snooping.get("enabled") else 0) + _len(dhcp.get("pools")) + _len(dhcp.get("helper_addresses")) + _len(snooping.get("trusted_interfaces")) + _len(snooping.get("rate_limited_interfaces")),
        "health": 1 if health_data else 0,
    }


def build_tabs(result: dict[str, Any]) -> list[dict[str, Any]]:
    """``[{key, label, has, count, why}]`` in display order."""
    counts = _counts(result)
    cov = result.get("coverage") or {}
    present = set(cov.get("present") or [])
    findings = result.get("findings") or []
    logs = result.get("logs") or {}
    family = cov.get("family") or coverage.vendor_key(result.get("vendor", ""))   # "aoscx" is a family of its own: its commands differ from ArubaOS-Switch
    nxos = family == "cisco" and (result.get("health") or {}).get("family") == "nxos"
    extra_tabs = {table["tab"] for table in result.get("extra_tables") or [] if table.get("rows")}
    rejected: dict[str, dict[str, Any]] = {}
    for row in cov.get("rows", []):
        if row["status"] == "error" and row.get("tab"):
            rejected.setdefault(row["tab"], row)
    out: list[dict[str, Any]] = []
    for key, label, spec_keys in TAB_ORDER:
        entry: dict[str, Any] = {"key": key, "label": label, "has": False, "count": None, "why": ""}
        if key == "overview":
            entry["has"] = True
        elif key == "findings":
            entry.update(has=True, count=len(findings))
        elif key == "coverage":
            missing = sum(1 for row in cov.get("rows", []) if row["status"] == "missing")
            entry.update(has=True, count=missing or None)
        elif key == "logs":
            entry["has"] = bool(logs.get("captured"))
            entry["count"] = logs.get("message_count") or None
            if not entry["has"]:
                entry["why"] = "No log command in this capture. Add " + coverage.command_for(coverage.BY_KEY["logs"], family, nxos) + "."
        else:
            number = counts.get(key, 0) or 0
            # the Health tab judges only vendors it supports: a captured command alone does not earn the tab
            captured = key != "health" and any(spec in present for spec in spec_keys)
            entry["has"] = bool(number) or captured or key in extra_tabs
            if key in _COUNT_TABS:
                entry["count"] = number or None
            elif key == "routing":
                entry["count"] = len(result.get("routing_table") or []) or None
            if not entry["has"]:
                if key == "health" and not (result.get("health") or {}).get("supported", True):
                    entry["why"] = "Health checks cover Cisco IOS / IOS XE / NX-OS, Huawei VRP, ArubaOS-Switch and ArubaOS-CX only."
                elif key in rejected:
                    entry["why"] = f"{rejected[key]['command']}: {rejected[key]['note']}."
                    if spec_keys:
                        # the device refused this spelling: name the one the collect list uses, unless it is the same command
                        known = coverage.command_for(coverage.BY_KEY[spec_keys[0]], family, nxos)
                        if known.lower() != str(rejected[key]["command"]).strip().lower():
                            entry["why"] += f" Try {known}."
                elif spec_keys:
                    spec = coverage.BY_KEY[spec_keys[0]]
                    entry["why"] = "Not in this capture. Add " + coverage.command_for(spec, family, nxos) + "."
                else:
                    entry["why"] = "Nothing configured or captured."
        out.append(entry)
    return out
