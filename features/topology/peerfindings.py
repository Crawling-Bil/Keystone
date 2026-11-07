"""Findings that compare what two captured devices say about the same thing: bundles, OSPF adjacencies, first-hop redundancy groups and addresses.

* TOPO-040  the two ends of a port-channel disagree on the protocol (LACP against a static bundle, LACP against PAgP) or sit in modes that never start it
  (LACP passive on both ends, PAgP auto on both ends),
* TOPO-041  both ends of a routed link run OSPF with matching parameters, yet a capture shows no Full adjacency on that interface,
* TOPO-042  an HSRP / VRRP group that two captured switches share but describe differently (virtual address, version, timers) or in which both hold the active role,
* TOPO-043  the same IP address on interfaces of two captured devices in one VRF (the same address at both ends of a point-to-point link, or a gateway address
  that is not an anycast gateway).

Every check needs both captures; a device that did not show the table in question (no ``show ip ospf neighbor``, no ``show standby``) is not judged.

References: IEEE 802.1AX-2020 Link Aggregation (LACP) https://1.ieee802.org/tsn/802-1ax-rev/ ;
Cisco, Troubleshoot Link Aggregation Control Protocol https://www.cisco.com/c/en/us/support/docs/lan-switching/link-aggregation-control-protocol-lacp-8023ad/221051-troubleshoot-link-aggregation-control-pr.html ;
IETF RFC 2328 section 10.3 (neighbor states) https://datatracker.ietf.org/doc/html/rfc2328#section-10.3 ;
IETF RFC 2281 (HSRP) https://datatracker.ietf.org/doc/html/rfc2281 and RFC 5798 (VRRPv3) https://datatracker.ietf.org/doc/html/rfc5798 ;
Cisco, Configuring HSRP https://www.cisco.com/en/US/docs/ios-xml/ios/ipapp_fhrp/configuration/15-0s/fhp-hsrp.html
"""

from __future__ import annotations

import ipaddress
from collections import defaultdict
from typing import Any

from .extract import Device
from .findings import _few, _row
from .graph import Graph
from .paramfindings import _record, _unique_links

DOC_LACP = "https://www.cisco.com/c/en/us/support/docs/lan-switching/link-aggregation-control-protocol-lacp-8023ad/221051-troubleshoot-link-aggregation-control-pr.html"
DOC_OSPF_STATES = "https://datatracker.ietf.org/doc/html/rfc2328#section-10.3"
DOC_OSPF_TROUBLE = "https://www.cisco.com/c/en/us/support/docs/ip/open-shortest-path-first-ospf/12151-trouble-main.html"
DOC_HSRP = "https://www.cisco.com/en/US/docs/ios-xml/ios/ipapp_fhrp/configuration/15-0s/fhp-hsrp.html"
DOC_HSRP_RFC = "https://datatracker.ietf.org/doc/html/rfc2281"

_STATIC = ("", "-", "none", "on", "static")
_ACTIVE_STATES = ("active", "master")
_BAD_OSPF = ("down", "attempt", "init", "exstart", "exchange", "loading")


def _protocol(info: dict[str, str]) -> str:
    text = str((info or {}).get("protocol", "")).strip().lower()
    if text in _STATIC:
        return "static"
    return "LACP" if "lacp" in text else "PAgP" if "pagp" in text else ""


def _modes(node: Device, po: str) -> set[str]:
    members = node.bundles.get(po) or []
    ports = (node.ifparams or {}).get("ports") or {}
    return {str(ports[m]["channel_mode"]).lower() for m in members if m in ports and ports[m].get("channel_mode")}


def _bundle_findings(graph: Graph) -> list[dict[str, Any]]:
    lines: list[str] = []
    devices: set[str] = set()
    seen: set[tuple[str, str, str, str]] = set()
    for conn in graph.connections:
        a, b = graph.nodes.get(conn.a), graph.nodes.get(conn.b)
        if a is None or b is None or not (a.captured and b.captured) or "/" in conn.a_po or "/" in conn.b_po or not (conn.a_po and conn.b_po):
            continue
        key = (conn.a, conn.a_po, conn.b, conn.b_po)
        if key in seen:
            continue
        seen.add(key)
        proto_a, proto_b = _protocol(a.bundle_info.get(conn.a_po, {})), _protocol(b.bundle_info.get(conn.b_po, {}))
        label = f"{a.hostname} {conn.a_po} - {b.hostname} {conn.b_po}"
        if proto_a and proto_b and proto_a != proto_b:
            lines.append(f"{label}: {proto_a} at {a.hostname}, {proto_b} at {b.hostname}")
            devices.update((a.hostname, b.hostname))
            continue
        modes_a, modes_b = _modes(a, conn.a_po), _modes(b, conn.b_po)
        if proto_a == proto_b == "LACP" and modes_a == modes_b == {"passive"}:
            lines.append(f"{label}: LACP passive at both ends, so neither end starts the negotiation")
            devices.update((a.hostname, b.hostname))
        elif proto_a == proto_b == "PAgP" and modes_a == modes_b == {"auto"}:
            lines.append(f"{label}: PAgP auto at both ends, so neither end starts the negotiation")
            devices.update((a.hostname, b.hostname))
    if not lines:
        return []
    return [_row("TOPO-040", "medium", f"{len(lines)} port-channel(s) whose two ends cannot form one bundle", _few(lines, 4), sorted(devices),
                 "A bundle forms only when both ends speak the same protocol and at least one end starts it: LACP needs active on one end (active/active and active/passive work, "
                 "passive/passive does not), PAgP needs desirable on one end, and a static bundle (mode on) never talks to LACP or PAgP. The members stay individual or suspended "
                 "and the traffic uses one link or loops. Make the protocol equal at both ends and set at least one end to active (channel-group N mode active on Cisco, "
                 "lacp mode active on AOS-CX, mode lacp-static on Huawei).", DOC_LACP)]


def _ospf_state(rows: list[dict[str, Any]]) -> list[str]:
    return [str(r.get("state", "")).split("/")[0].lower() for r in rows]


def _adjacency_findings(graph: Graph) -> list[dict[str, Any]]:
    lines: list[str] = []
    devices: set[str] = set()
    for link in _unique_links(graph):
        a, b = graph.nodes[link.a], graph.nodes[link.b]
        rec_a, rec_b = _record(a, link.a_port), _record(b, link.b_port)
        ospf_a, ospf_b = rec_a.get("ospf"), rec_b.get("ospf")
        if not (rec_a.get("ip") and rec_b.get("ip") and ospf_a and ospf_b) or ospf_a.get("assumed") or ospf_b.get("assumed"):
            continue
        if (ospf_a["hello"], ospf_a["dead"], ospf_a["area"], ospf_a["network"]) != (ospf_b["hello"], ospf_b["dead"], ospf_b["area"], ospf_b["network"]):
            continue                                                   # a mismatch of the parameters is TOPO-037 to 039: the adjacency is explained there
        problems = []
        for node, port in ((a, a.bundle_of.get(link.a_port) or link.a_port), (b, b.bundle_of.get(link.b_port) or link.b_port)):
            neighbors = [n for n in (node.l3facts or {}).get("neighbors") or [] if n.get("protocol") == "ospf"]
            if not neighbors:
                continue                                               # no OSPF neighbor table in this capture: nothing to judge
            mine = [n for n in neighbors if n.get("interface") == port]
            if not mine:
                problems.append(f"no OSPF neighbor on {port} at {node.hostname}")
            elif any(state in _BAD_OSPF for state in _ospf_state(mine)):
                problems.append(f"{node.hostname} {port}: {', '.join(sorted(set(str(n.get('state', '')) for n in mine)))}")
        if problems:
            lines.append(f"{a.hostname} {a.bundle_of.get(link.a_port) or link.a_port} - {b.hostname} {b.bundle_of.get(link.b_port) or link.b_port}: " + "; ".join(problems))
            devices.update((a.hostname, b.hostname))
    if not lines:
        return []
    return [_row("TOPO-041", "medium", f"{len(lines)} routed link(s) where both ends run OSPF with the same parameters but there is no Full adjacency", _few(lines, 4), sorted(devices),
                 "The hello and dead intervals, the area and the network type agree, so the usual cause is somewhere else: an MTU mismatch (TOPO-036; the neighbors stay in ExStart or "
                 "Exchange), an authentication mismatch, a different subnet mask, an access list or firewall that drops protocol 89, or a mismatch in the router ID. "
                 "Run show ip ospf neighbor and show ip ospf interface on both ends and compare.", DOC_OSPF_TROUBLE)]


def _fhrp_findings(graph: Graph) -> list[dict[str, Any]]:
    groups: dict[tuple[str, str, str], list[tuple[Device, dict[str, Any]]]] = defaultdict(list)
    for node in graph.nodes.values():
        if not node.captured:
            continue
        for row in (node.l3facts or {}).get("fhrp") or []:
            if row.get("interface") and row.get("group") != "":
                groups[(str(row.get("protocol", "")).lower(), str(row["interface"]), str(row["group"]))].append((node, row))
    lines: list[str] = []
    devices: set[str] = set()
    for (protocol, interface, group), members in sorted(groups.items()):
        if len({n.key for n, _ in members}) < 2:
            continue
        label = f"{protocol.upper() or 'FHRP'} group {group} on {interface}"
        problems = []
        for field, text in (("virtual_ip", "virtual address"), ("version", "version"), ("hello", "hello timer"), ("hold", "hold timer")):
            values = {str(r.get(field, "")) for _, r in members if str(r.get(field, ""))}
            if len(values) > 1:
                problems.append(f"{text} " + " / ".join(f"{n.hostname} {r.get(field)}" for n, r in members if r.get(field)))
        active = [n.hostname for n, r in members if str(r.get("state", "")).lower() in _ACTIVE_STATES]
        if len(active) > 1:
            problems.append(f"{' and '.join(active)} are both {members[0][1].get('state')}")
        if problems:
            lines.append(f"{label}: " + "; ".join(problems))
            devices.update(n.hostname for n, _ in members)
    if not lines:
        return []
    return [_row("TOPO-042", "medium", f"{len(lines)} first-hop redundancy group(s) that the switches describe differently", _few(lines, 4), sorted(devices),
                 "The routers of one HSRP or VRRP group must share the virtual address, the version and the timers. A different virtual address means two gateways for the hosts of "
                 "that VLAN; two routers that are both Active (Master) mean the hellos do not arrive (a blocked VLAN, a different version, a wrong group number) and both answer ARP "
                 "for the gateway, which gives duplicate-address warnings and unstable traffic. Check the group on both switches (show standby, show hsrp, show vrrp).", DOC_HSRP)]


def _point_to_point(prefix_len: Any) -> bool:
    try:
        return int(prefix_len) >= 30
    except (TypeError, ValueError):
        return False


def _address_findings(graph: Graph) -> list[dict[str, Any]]:
    owners: dict[tuple[str, str], list[tuple[Device, dict[str, Any]]]] = defaultdict(list)
    for node in graph.nodes.values():
        if not node.captured:
            continue
        for row in node.l3 or []:
            ip = str(row.get("ip", ""))
            if not ip or row.get("shutdown") or str(row.get("kind", "")).lower() in ("management",):
                continue
            try:
                address = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if address.is_loopback or address.is_link_local or address.is_unspecified:
                continue
            owners[(str(row.get("vrf", "")) or "global", ip)].append((node, row))
    lines: list[str] = []
    medium = False
    devices: set[str] = set()
    for (vrf, ip), items in sorted(owners.items()):
        hosts = {n.key for n, _ in items}
        if len(hosts) < 2:
            continue
        point = all(_point_to_point(r.get("prefix_len")) for _, r in items)
        if not point and len(hosts) > 2:
            continue                                      # the same gateway address on three or more switches is the anycast-gateway pattern, not a clash
        where = ", ".join(f"{n.hostname} {r.get('name')}" for n, r in items[:4])
        lines.append(f"{ip}{'' if vrf == 'global' else ' (VRF ' + vrf + ')'}: {where}" + ("" if point else " (an anycast or active gateway shares an address on purpose)"))
        medium = medium or point
        devices.update(n.hostname for n, _ in items)
    if not lines:
        return []
    return [_row("TOPO-043", "medium" if medium else "low", f"{len(lines)} IP address(es) configured on interfaces of more than one captured device", _few(lines, 4), sorted(devices),
                 "Two interfaces in one VRF with the same address make the ARP and routing tables flip between them. On a point-to-point /30 or /31 it is a plain mistake (both ends "
                 "were given the first address). On a gateway VLAN it is correct only when the platform shares the address on purpose (Nexus anycast gateway, Aruba active gateway "
                 "on VSX, VARP); otherwise change one of them. HSRP and VRRP virtual addresses are not interface addresses and do not appear here.", DOC_HSRP_RFC)]


def peer_findings(graph: Graph) -> list[dict[str, Any]]:
    return _bundle_findings(graph) + _adjacency_findings(graph) + _fhrp_findings(graph) + _address_findings(graph)
