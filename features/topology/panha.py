"""The high-availability links of Palo Alto firewalls: the other unit of the pair and the ports the HA links leave on.

A PAN-OS configuration names the HA peer by address (``peer-ip``, the other unit's HA1 address) and the ports of the links:
HA1 is the control link, HA2 the data link that synchronises sessions, HA3 the packet-forwarding link of an active/active pair, and HA1 / HA2 can have a backup
(https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-admin/high-availability/ha-concepts/ha-links-and-backup-links).  A configuration does not say what is between the two ports, so the
links are drawn as direct cables (that is how the dedicated HA ports are used) and labelled ``inferred HA``; capture the switch in between and the
line is replaced by the real cables.

* both units uploaded: the unit whose own HA1 address is the other's ``peer-ip`` is its peer; the two are joined once, each port of one unit to the same
  HA role port of the other;
* one unit uploaded: a grey firewall "HA peer of <host>" stands beside it (named by the peer address) with one line per HA port.
"""

from __future__ import annotations

from typing import Any

from .extract import Device
from .graph import Connection, Graph, Link

VENDOR = "Palo Alto Networks"


def _ha(node: Device) -> dict[str, Any]:
    return node.l3facts.get("pan_ha") or {}


def _peer_of(graph: Graph, key: str) -> str:
    """The captured firewall that is the HA peer of ``key`` (its own HA1 address equals the peer-ip), or ''."""
    mine = _ha(graph.nodes[key])
    wanted = {mine.get("peer_ip"), mine.get("peer_ip_backup")} - {"", None}
    for other, node in sorted(graph.nodes.items()):
        if other == key or not node.captured or node.vendor != VENDOR:
            continue
        theirs = _ha(node)
        own = {theirs.get("own_ip"), theirs.get("own_ip_backup")} - {"", None}
        if wanted & own:
            return other
    return ""


def _assumed_peer(graph: Graph, key: str) -> str:
    node, mine = graph.nodes[key], _ha(graph.nodes[key])
    ip = str(mine.get("peer_ip") or mine.get("peer_ip_backup") or "")
    peer_key = f"HAPEER-{key}"
    if peer_key not in graph.nodes:
        peer = Device(key=peer_key, hostname=f"HA peer of {node.hostname}", captured=False, mgmt_ip="", vendor=VENDOR, role_hint="firewall",
                      model=f"HA1 address {ip}" if ip else "assumed HA peer")
        if ip:
            peer.ips.add(ip)
        graph.nodes[peer_key] = peer
    return peer_key


def _taken(graph: Graph, key: str, port: str) -> bool:
    return any((l.a == key and l.a_port == port) or (l.b == key and l.b_port == port) for l in graph.links)


def assume_pan_ha(graph: Graph) -> list[dict[str, Any]]:
    """Add the HA peer and the HA links of every captured Palo Alto firewall that has high availability enabled.  Returns the facts for TOPO-027."""
    facts: list[dict[str, Any]] = []
    done: set[frozenset] = set()
    for key in sorted(k for k, n in graph.nodes.items() if n.captured and n.vendor == VENDOR and _ha(n)):
        mine = _ha(graph.nodes[key])
        if not mine.get("ports"):
            continue
        peer = _peer_of(graph, key)
        if peer and frozenset((key, peer)) in done:
            continue
        far_ports = {role: port for role, port in _ha(graph.nodes[peer]).get("ports", [])} if peer else {}
        if not peer:
            peer = _assumed_peer(graph, key)
        done.add(frozenset((key, peer)))
        for role, port in mine["ports"]:
            far_port = far_ports.get(role, "")
            if _taken(graph, key, port) or any({l.a, l.b} == {key, peer} and (l.a_port == port or l.b_port == port) for l in graph.links):
                continue
            note = f"{role} port {port} in the high-availability settings; the peer is {mine.get('peer_ip') or 'not named'}, the cable between the two ports is assumed"
            link = Link(key, port, peer, far_port, "inferred", {"HA"}, note)
            graph.links.append(link)
            joined = [c for c in graph.connections if c.kind == "inferred" and {c.a, c.b} == {key, peer}]
            if joined:
                joined[0].links.append(link)
            else:
                graph.connections.append(Connection(key, peer, [link], kind="inferred"))
            facts.append({"type": "inferred-link", "a": key, "a_port": port, "b": peer, "b_port": far_port, "evidence": "HA", "ip": str(mine.get("peer_ip") or ""), "conflict": ""})
    return facts
