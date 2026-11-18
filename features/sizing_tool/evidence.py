"""Where every number of a device comes from, and how far to trust it.

A sizing figure is only as good as the capture behind it.  For each quantity of an asset the tool says which command or section produced it and a confidence:

* **high**   -- the device printed it (an inventory, a table of ports with their state, a licence block) or it is a count of configuration objects;
* **medium** -- read correctly but a moment in time (ports with a link at the second of the capture) or from a table that may be partial (a show-only capture);
* **low**    -- the capture lacks the command that would answer it (no link state, no PoE output), so the number is zero or a guess the reader refused to make;
* **entered** -- typed by the architect or imported from a CSV (the tool cannot vouch for it).

The rules are table-driven so a new quantity is one line.  Nothing is stored in the asset: the evidence is recomputed from the asset and its notes.
"""

from __future__ import annotations

from typing import Any

# (device type, label prefix, where the figure comes from)
_SOURCES: tuple[tuple[str, str, str], ...] = (
    ("switch", "Physical ports", "Port list: running configuration plus show interfaces status / brief (display interface brief on Huawei)"),
    ("switch", "Ports in use", "Link state of the port tables at the moment of the capture"),
    ("switch", "Ports ", "Port names, or the Type column of show interface status (NX-OS), or the transceiver table"),
    ("switch", "PoE", "show power inline / display poe power / show power-over-ethernet"),
    ("switch", "Transceivers", "show interface transceiver / display transceiver / inventory"),
    ("switch", "VLANs", "Running configuration"),
    ("switch", "Trunk ports", "Running configuration (switchport mode / port-type trunk)"),
    ("switch", "Port-channels", "Running configuration and port-channel summary"),
    ("switch", "Routed interfaces", "Running configuration (interfaces with an address)"),
    ("switch", "Static routes", "Running configuration"),
    ("switch", "Stack members", "show switch / display stack / show inventory"),
    ("router", "Physical interfaces", "show ip interface brief / interface list"),
    ("router", "Interfaces ", "Interface names"),
    ("router", "Logical interfaces", "Interface list (loopback, tunnel, BDI)"),
    ("router", "Routes", "show ip route summary / routing table"),
    ("router", "BGP sessions", "show ip bgp summary / configuration"),
    ("firewall", "Firewall policies", "Configuration (security rules / firewall policy)"),
    ("firewall", "NAT rules", "Configuration"),
    ("firewall", "Address objects", "Configuration"),
    ("firewall", "VPN tunnels", "Configuration (IPsec phase 1 / tunnels)"),
    ("firewall", "Interfaces", "Configuration"),
    ("load_balancer", "Virtual servers", "tmsh list ltm virtual or show ltm virtual"),
    ("load_balancer", "Pools", "tmsh list ltm pool or show ltm pool"),
    ("load_balancer", "Pool members", "tmsh list / show ltm pool members"),
    ("load_balancer", "Nodes", "tmsh list / show ltm node"),
    ("load_balancer", "Wide IPs", "tmsh list gtm wideip"),
    ("wlc", "Access points", "AP summary of the controller"),
    ("wlc", "Licensed AP capacity", "Licence block of the controller"),
    ("wlc", "Client capacity", "Controller platform table"),
    ("access_point", "Access points", "AP summary of the controller"),
)

# a note (start of text) -> the label prefixes it makes low-confidence
_DOWNGRADES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("No transceiver output", ("Transceivers",)),
    ("No show power-over-ethernet", ("PoE",)),
    ("No port table", ("Physical ports", "Ports ", "VLANs", "Trunk ports")),
    ("Port speed is not in the port names", ("Ports (speed not in name)",)),
    ("No show inventory", ("Chassis",)),
)


def _confidence(asset: dict[str, Any], label: str) -> str:
    notes = " | ".join(asset.get("notes", []))
    for start, prefixes in _DOWNGRADES:
        if start in notes and any(label.startswith(p) for p in prefixes):
            return "low"
    if "ports have no live state" in notes and label.startswith("Ports in use"):
        return "low"
    value = asset.get("capacity", {}).get(label, 0)
    if label.startswith("PoE") and not value and asset.get("device_type") == "switch":
        return "low"
    if label.startswith("Ports in use"):
        return "medium"
    if asset.get("device_type") == "switch" and label.startswith("Physical ports") and "ports have no live state" in notes:
        return "medium"
    return "high"


def evidence(asset: dict[str, Any]) -> list[dict[str, Any]]:
    """One row per quantity: label, value, where it comes from, confidence.  Peak figures follow, with their own source."""
    rows: list[dict[str, Any]] = []
    if len(asset.get("merged_from") or []) > 1:
        rows.append({"label": "Captures merged", "value": len(asset["merged_from"]), "from": "Files: " + ", ".join(asset["merged_from"]), "confidence": "high", "kind": "source"})
    for label, value in asset.get("capacity", {}).items():
        source = next((text for dtype, prefix, text in _SOURCES if dtype == asset.get("device_type") and label.startswith(prefix)), "")
        rows.append({"label": label, "value": value, "from": source or f"{asset.get('analyzer', 'analyzer')} result", "confidence": _confidence(asset, label), "kind": "capacity"})
    for label, peak in asset.get("peaks", {}).items():
        origin = {"capture": "tmsh show sys performance / device statistics in the capture", "manual": "entered by you", "csv": "imported CSV"}.get(peak.get("source", ""), peak.get("source", ""))
        rows.append({"label": label, "value": peak.get("value"), "from": origin + (f" ({peak['window']})" if peak.get("window") else ""),
                     "confidence": "entered" if peak.get("source") in ("manual", "csv") else "high", "kind": "peak"})
    return rows


def confidence_summary(assets: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"high": 0, "medium": 0, "low": 0, "entered": 0}
    for asset in assets:
        for row in evidence(asset):
            counts[row["confidence"]] = counts.get(row["confidence"], 0) + 1
    return counts
