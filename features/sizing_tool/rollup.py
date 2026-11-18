"""From asset records to the picture an architect works from: groups by device type, the bill of materials, features in use, licences, sites, gaps.

Sizing arithmetic is kept plain on purpose so it can be checked by hand: *target* = *today* x (1 + growth %), rounded up.  Today is what the captures hold
(ports with a link, access points joined, policies, virtual servers); the growth margin is the one input of the page (default 25 %, a common planning figure
for a three-to-five-year refresh; set it to the figure the customer's change plan gives).
"""

from __future__ import annotations

import math
from collections import Counter, OrderedDict
from typing import Any

from .catalog import links_for, sizing_inputs
from .classify import DEVICE_TYPES, TYPE_LABELS
from .plan import sites_detail

DEFAULT_GROWTH = 25
# what adds up across devices, and so scales with growth; the others (VLANs, stack members, VDOMs) are shown as the largest value
ADDITIVE = ("Physical ports", "Ports in use", "Ports 1G", "Ports 10G", "Ports 25G", "Ports 40G", "Ports 100G", "Ports 100M", "Ports (speed", "Ports (other)", "PoE ports", "PoE power",
            "Transceivers", "Physical interfaces", "Interfaces", "Routes", "BGP sessions", "IPsec tunnels", "NAT rules", "Firewall policies", "Address objects", "VPN tunnels",
            "Virtual servers", "Pools", "Pool members", "Nodes", "iRules", "Wide IPs", "SSL profiles", "Access points", "SSIDs", "Self IPs", "Trunks", "Client capacity", "Licensed AP")
GROWTH_FREE = ("Stack members", "VDOMs / vsys", "vCMP guests", "VLANs", "VRFs", "Zones", "Access points joined", "Joined", "Software versions in use", "AP groups")


def _is_additive(label: str) -> bool:
    return not any(label.startswith(g) for g in GROWTH_FREE) and any(label.startswith(a) for a in ADDITIVE)


def _target(label: str, value: float, growth: float) -> float:
    if not _is_additive(label):
        return value
    factor = 1 + growth / 100.0
    if isinstance(value, float) and value != int(value):
        return round(value * factor, 1)
    return math.ceil(value * factor - 1e-9)


def _sum_capacity(assets: list[dict[str, Any]]) -> "OrderedDict[str, float]":
    out: "OrderedDict[str, float]" = OrderedDict()
    for asset in assets:
        for label, value in asset["capacity"].items():
            if isinstance(value, (int, float)):
                out[label] = out.get(label, 0) + value
    return out


def _models(assets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[tuple[str, str], dict[str, Any]] = {}
    for asset in assets:
        key = (asset["vendor"], asset["model"] or "Model not in capture")
        item = groups.setdefault(key, {"vendor": key[0], "model": key[1], "qty": 0, "hosts": [], "os": Counter(), "tiers": Counter(), "ha": Counter()})
        qty = int(asset["capacity"].get("Access points", 1)) if asset["device_type"] == "access_point" else 1
        item["qty"] += qty
        item["hosts"].append(asset["hostname"] or asset["source"])
        if asset["os"]:
            item["os"][asset["os"]] += 1
        item["tiers"][asset["tier"]] += 1
        item["ha"][asset["ha"]] += 1
    return [{"vendor": v["vendor"], "model": v["model"], "qty": v["qty"], "hosts": v["hosts"], "os": sorted(v["os"]), "tiers": dict(v["tiers"]), "ha": dict(v["ha"])}
            for v in sorted(groups.values(), key=lambda g: (-g["qty"], g["vendor"], g["model"]))]


def _bom(assets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for asset in assets:
        for comp in asset["components"]:
            key = (comp["category"], asset["vendor"], comp["part"], comp["description"])
            item = groups.setdefault(key, {"category": key[0], "vendor": key[1], "part": key[2], "description": key[3], "qty": 0, "devices": set(), "types": set()})
            item["qty"] += comp["qty"]
            item["devices"].add(asset["id"])
            item["types"].add(asset["device_type"])
    order = {"Chassis": 0, "Access point": 1, "Module": 2, "Power supply": 3, "Fan": 4, "Stack": 5, "Transceiver": 6, "Other": 7}
    return [{"category": g["category"], "vendor": g["vendor"], "part": g["part"], "description": g["description"], "qty": g["qty"], "devices": len(g["devices"]),
             "types": sorted(g["types"])}
            for g in sorted(groups.values(), key=lambda g: (order.get(g["category"], 9), g["vendor"], -g["qty"], g["part"]))]


def _licences(assets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[tuple[str, str, str], dict[str, Any]] = {}
    for asset in assets:
        for lic in asset["licences"]:
            key = (asset["vendor"], lic["name"], lic["state"])
            item = groups.setdefault(key, {"vendor": key[0], "name": key[1], "state": key[2], "devices": [], "expires": set(), "types": set()})
            item["devices"].append(asset["hostname"] or asset["source"])
            if lic["expires"]:
                item["expires"].add(lic["expires"])
            item["types"].add(asset["device_type"])
    return [{"vendor": g["vendor"], "name": g["name"], "state": g["state"], "count": len(g["devices"]), "devices": g["devices"][:50], "expires": sorted(g["expires"]),
             "types": sorted(g["types"])}
            for g in sorted(groups.values(), key=lambda g: (g["vendor"], g["name"], g["state"]))]


def _features(assets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[tuple[str, str], dict[str, Any]] = {}
    for asset in assets:
        for feat in asset["features"]:
            item = groups.setdefault((feat["group"], feat["name"]), {"group": feat["group"], "name": feat["name"], "devices": 0, "objects": 0, "by_type": Counter()})
            item["devices"] += 1
            item["objects"] += feat["count"] or 0
            item["by_type"][asset["device_type"]] += 1
    return [{"group": g["group"], "name": g["name"], "devices": g["devices"], "objects": g["objects"], "by_type": dict(g["by_type"])}
            for g in sorted(groups.values(), key=lambda g: (g["group"], -g["devices"], g["name"]))]


def _gaps(assets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[str, list[str]] = {}
    for asset in assets:
        for note in asset["notes"]:
            groups.setdefault(note.split(" (")[0] if note.startswith("No ") else note, []).append(asset["hostname"] or asset["source"])
    return [{"note": note, "count": len(hosts), "devices": hosts[:50]} for note, hosts in sorted(groups.items(), key=lambda item: (-len(item[1]), item[0]))]


def build(assets: list[dict[str, Any]], growth: float = DEFAULT_GROWTH) -> dict[str, Any]:
    growth = max(0.0, min(float(growth), 500.0))
    groups = []
    for dtype in DEVICE_TYPES:
        mine = [a for a in assets if a["device_type"] == dtype]
        if not mine:
            continue
        today = _sum_capacity(mine)
        peak = {label: max(a["capacity"].get(label, 0) for a in mine if isinstance(a["capacity"].get(label, 0), (int, float))) for label in today}
        sizing = [{"label": label, "today": value, "target": _target(label, value, growth), "largest_single_device": peak[label],
                   "scales": _is_additive(label)} for label, value in today.items() if value]
        vendors = Counter(a["vendor"] for a in mine)
        groups.append({
            "type": dtype, "label": TYPE_LABELS[dtype], "count": len(mine), "units": sum(int(a["capacity"].get("Access points", 1)) for a in mine) if dtype == "access_point" else len(mine),
            "vendors": dict(vendors), "tiers": dict(Counter(a["tier"] for a in mine)), "ha": dict(Counter(a["ha"] for a in mine)),
            "models": _models(mine), "sizing": sizing, "components": _bom(mine), "licences": _licences(mine), "features": _features(mine),
            "gaps": _gaps(mine), "inputs": sizing_inputs(dtype), "links": links_for(dtype, list(vendors)),
            "devices": [a["id"] for a in mine],
        })
    vendors_all = Counter(a["vendor"] for a in assets)
    return {
        "growth": growth,
        "summary": {"devices": len(assets), "by_type": {TYPE_LABELS[t]: sum(1 for a in assets if a["device_type"] == t) for t in DEVICE_TYPES if any(a["device_type"] == t for a in assets)},
                    "by_vendor": dict(vendors_all), "sites": len({a["site"] for a in assets if a["site"]}),
                    "access_points": sum(int(a["capacity"].get("Access points", 0)) for a in assets if a["device_type"] == "access_point"),
                    "with_licence": sum(1 for a in assets if a["licences"]), "with_serial": sum(1 for a in assets if a["serial"])},
        "groups": groups, "bom": _bom(assets), "features": _features(assets), "licences": _licences(assets), "gaps": _gaps(assets), "sites": sites_detail(assets),
        "links": links_for("", list(vendors_all)),
    }
