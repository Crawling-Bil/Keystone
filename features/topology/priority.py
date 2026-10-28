"""Which captures to take next: a ranked list of what would add the most to the picture.

Two kinds of row.  ``new capture`` is a device that the captured neighbors see but nobody captured: its capture confirms every
one-sided link to it from the other end, names the ports at its end, and reveals the neighbors that only it can see.  ``capture again`` is a
captured device whose capture lacks the neighbor table (CDP / LLDP), so its cables are drawn from the far end only.

The rank is fixed and explainable (no weights to tune): links that a neighbor table reports, descending (a link only inferred from ARP,
a port description or a route counts after those); then the number of different captured neighbors; then the MAC addresses learned
behind it; then the name.  A device with more cables and more neighbors is the better next capture because
it joins more of the picture; the MAC count breaks the tie between the access switches of one closet.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .graph import Graph
from .names import port_sort_key

COLLECT_DIR = Path(__file__).resolve().parents[2] / "static" / "collect-scripts"
# an uncaptured node is worth a capture only when a person could log in to it
CAPTURABLE = {"router", "firewall", "loadbalancer", "core", "aggregation", "switch", "access", "wlc", "fabric", ""}
_NO_NEIGHBOR_TABLE = ("fortinet", "f5")           # same list as the findings: these configurations have no CDP / LLDP table
_NEXUS = re.compile(r"^(N\d[A-Z]?-|N\dK|NEXUS)", re.I)
_CATALYST = re.compile(r"^(C9\d{3}|C\d{4}|WS-|CBS|CATALYST|IE-)", re.I)
_ROUTER = re.compile(r"^(ISR|ASR|C8\d{3}|CSR|C1[0-9]{3}-|NCS)", re.I)
_HUAWEI_H = re.compile(r"-H\b|S\d{4}-H", re.I)
_ARUBA_CX_VERSION = re.compile(r"^[A-Z]{0,3}\.?10\.\d", re.I)

COLUMNS = ("rank", "action", "device", "role", "vendor", "model", "links", "inferred_links", "captured_neighbors", "behind_macs", "neighbors", "ports_seen", "collect_list", "why")


def collect_lists(node: Any) -> list[str]:
    """The collect list(s) in ``static/collect-scripts`` that fit a device, by vendor / model / role.  Empty when the vendor is not known:
    the caller says so instead of guessing."""
    vendor, model, role, version = (node.vendor or "").lower(), (node.model or "").strip(), node.role_hint or "", (node.os_version or "").strip()
    names: list[str] = []
    if vendor == "fortinet":
        names = ["collect-firewall-fortigate.txt"]
    elif vendor.startswith("palo alto"):
        names = ["collect-firewall-paloalto.txt"]
    elif vendor == "f5":
        names = ["collect-lb-f5-bigip.txt"]
    elif vendor == "aruba" or re.match(r"^(JL|J\d{4}|Aruba|HPE ANW)", model, re.I):
        if _ARUBA_CX_VERSION.match(version):
            names = ["collect-aruba-cx.txt"]
        elif version:
            names = ["collect-aruba-switch.txt"]
        else:
            names = ["collect-aruba-cx.txt", "collect-aruba-switch.txt"]
    elif vendor == "huawei" or re.match(r"^(S\d{4}|CE\d{4}|AR\d{4}|USG)", model, re.I):
        names = ["collect-huawei-h-series.txt" if _HUAWEI_H.search(model) else "collect-huawei-s-l-e-series.txt"]
    elif vendor == "mikrotik":
        names = ["collect-firewall-mikrotik.txt"]
    elif vendor == "cisco" or _NEXUS.match(model) or _CATALYST.match(model) or _ROUTER.match(model):
        if _NEXUS.match(model):
            names = ["collect-cisco-nexus.txt"]
        elif role == "router" or _ROUTER.match(model):
            names = ["collect-router-cisco-ios-xe.txt"]
        elif model:
            names = ["collect-cisco-catalyst.txt"]
        elif role in ("core", "aggregation", "switch", "access"):
            names = ["collect-cisco-catalyst.txt", "collect-cisco-nexus.txt"]
    if not names and not model:                      # nothing but the role is known (a stub named only by its neighbors)
        names = {"firewall": ["collect-firewall-fortigate.txt", "collect-firewall-paloalto.txt", "collect-firewall-mikrotik.txt"],
                 "loadbalancer": ["collect-lb-f5-bigip.txt"]}.get(role, [])
    return [name for name in names if (COLLECT_DIR / name).is_file()]


def _hosts_behind(graph: Graph) -> dict[str, int]:
    counts: dict[str, int] = {}
    for host in graph.hosts:
        via = host.get("via")
        if via:
            counts[via] = counts.get(via, 0) + 1
    return counts


def _label(count: int, word: str, plural: str = "") -> str:
    return f"{count} " + (word if count == 1 else plural or word + "s")


def capture_priority(graph: Graph) -> list[dict[str, Any]]:
    """Ranked rows, best next capture first.  Pure function of the graph: same captures, same list."""
    behind = _hosts_behind(graph)
    seen: dict[str, dict[str, Any]] = {}
    for link in graph.links:
        for far, far_port, near, near_port in ((link.b, link.b_port, link.a, link.a_port), (link.a, link.a_port, link.b, link.b_port)):
            node, peer = graph.nodes.get(far), graph.nodes.get(near)
            if node is None or peer is None or node.captured or not peer.captured:
                continue
            if node.role_hint not in CAPTURABLE or far in graph.hidden_nodes or far.startswith(("HOST:", "HOSTS:")):
                continue
            entry = seen.setdefault(far, {"links": 0, "inferred": 0, "neighbors": set(), "ports": set()})
            entry["links"] += 1
            entry["inferred"] += link.state == "inferred"
            entry["neighbors"].add(peer.hostname)
            entry["ports"].add(f"{peer.hostname} {near_port}")
    rows: list[dict[str, Any]] = []
    for key, entry in seen.items():
        node = graph.nodes[key]
        macs = behind.get(node.hostname, 0) + (behind.get(key, 0) if key != node.hostname else 0)
        lists = collect_lists(node)
        neighbors = sorted(entry["neighbors"])
        reported = entry["links"] - entry["inferred"]
        reasons = [f"{_label(entry['links'], 'link')} from {_label(len(neighbors), 'captured device')} reach it and only those devices report them"]
        if entry["inferred"]:
            reasons[0] = (f"{_label(reported, 'link')} reported by {_label(len(neighbors), 'captured device')} and {entry['inferred']} inferred from ARP, descriptions or routes"
                          if reported else f"{_label(entry['inferred'], 'link')} inferred from ARP, descriptions or routes (no neighbor table lists it)")
        if macs:
            reasons.append(f"{_label(macs, 'MAC address', 'MAC addresses')} learned behind it")
        reasons.append("its capture confirms the links, names its ports and shows the neighbors only it can see")
        rows.append({"rank": 0, "action": "new capture", "device": node.hostname, "role": node.role_hint, "vendor": node.vendor, "model": node.model, "links": entry["links"], "inferred_links": entry["inferred"],
                     "captured_neighbors": len(neighbors), "behind_macs": macs, "neighbors": ", ".join(neighbors),
                     "ports_seen": ", ".join(sorted(entry["ports"], key=lambda p: (p.split(" ")[0], port_sort_key(p.split(" ", 1)[1])))),
                     "collect_list": " or ".join(lists) if lists else "vendor not known from the neighbor tables: choose the collect list that matches it",
                     "why": "; ".join(reasons) + "."})
    rows.sort(key=lambda r: (-(r["links"] - r["inferred_links"]), -r["captured_neighbors"], -r["behind_macs"], -r["inferred_links"], r["device"]))
    again = _recapture(graph, behind)
    for number, row in enumerate(rows + again, 1):
        row["rank"] = number
    return rows + again


def _recapture(graph: Graph, behind: dict[str, int]) -> list[dict[str, Any]]:
    """Captured devices without a neighbor table: the capture is there, the cables are not."""
    link_count: dict[str, int] = {}
    for link in graph.links:
        link_count[link.a] = link_count.get(link.a, 0) + 1
        link_count[link.b] = link_count.get(link.b, 0) + 1
    rows = []
    for key, node in graph.nodes.items():
        if not node.captured or node.vendor.lower() in _NO_NEIGHBOR_TABLE or node.halves or not node.coverage:
            continue
        if node.role_hint not in CAPTURABLE - {""}:
            continue
        lists = collect_lists(node)
        rows.append({"rank": 0, "action": "capture again", "device": node.hostname, "role": node.role_hint, "vendor": node.vendor, "model": node.model,
                     "links": link_count.get(key, 0), "inferred_links": 0, "captured_neighbors": 0, "behind_macs": behind.get(node.hostname, 0), "neighbors": "", "ports_seen": "",
                     "collect_list": " or ".join(lists) if lists else "the collect list of its vendor",
                     "why": "The capture holds no CDP or LLDP neighbor, so its cables are drawn only from what the other devices report. "
                            "Run 'show cdp neighbors detail' and 'show lldp neighbors detail' (display lldp neighbor-information verbose on Huawei) and capture it again."})
    rows.sort(key=lambda r: (-r["links"], -r["behind_macs"], r["device"]))
    return rows
