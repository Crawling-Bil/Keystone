"""The high-availability links of Palo Alto firewalls: the other unit of the pair and the ports the HA links leave on.

A PAN-OS configuration names the HA peer by address (``peer-ip``, the other unit's HA1 address) and the ports of the links:
HA1 is the control link, HA2 the data link that synchronises sessions, HA3 the packet-forwarding link of an active/active pair, and HA1 / HA2 can have a backup
(https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-admin/high-availability/ha-concepts/ha-links-and-backup-links).  A configuration does not say what is between the two ports, so the
links are drawn as direct cables (that is how the dedicated HA ports are used) and labelled ``inferred HA``; capture the switch in between and the
line is replaced by the real cables.

* both units uploaded: the unit whose own HA1 address is the other's ``peer-ip`` is its peer when the two agree on the HA mode and the Group ID and nothing fits better
  (an HA1 address is local to a pair: every pair of a site can use 1.1.1.1 and 1.1.1.2, then the closed loop of addresses, the shared HA ports and the alike host
  names decide, and a unit with no single best fit gets an assumed peer, never a wrong real one); the two are joined once, each port of one unit to the same
  HA role port of the other;
* one unit uploaded: a grey firewall "HA peer of <host>" stands beside it (named by the peer address) with one line per HA port.
"""

from __future__ import annotations

from difflib import SequenceMatcher
from typing import Any

from .extract import Device
from .graph import Connection, Graph, Link

VENDOR = "Palo Alto Networks"


def _ha(node: Device) -> dict[str, Any]:
    return node.l3facts.get("pan_ha") or {}


def _addresses(facts: dict[str, Any], *names: str) -> set[str]:
    return {str(facts.get(name)) for name in names if facts.get(name)}


def _is_candidate(mine: dict[str, Any], theirs: dict[str, Any]) -> bool:
    """Could the unit with the facts ``theirs`` be the peer of the one with ``mine``?  The peer-ip of one is an HA1 address of the other, and the two agree on what PAN-OS
    needs identical on both firewalls: the HA mode and the Group ID (https://docs.paloaltonetworks.com/pan-os/9-1/pan-os-admin/high-availability/set-up-activepassive-ha/configuration-guidelines-for-activepassive-ha)."""
    if not _addresses(mine, "peer_ip", "peer_ip_backup") & _addresses(theirs, "own_ip", "own_ip_backup"):
        return False
    return all(not (mine.get(field) and theirs.get(field)) or str(mine[field]) == str(theirs[field]) for field in ("mode", "group"))


def _score(graph: Graph, a: str, b: str) -> tuple[int, int, float]:
    """How well two candidate units fit as a pair, most telling first: each one names the other's address (a pair is a closed loop of addresses), the number of HA links that
    leave on the same port in the same role, and how alike the host names are (HQPAFW1 beside HQPAFW2, not beside DRPAFW2)."""
    mine, theirs = _ha(graph.nodes[a]), _ha(graph.nodes[b])
    closed = int(bool(_addresses(theirs, "peer_ip", "peer_ip_backup") & _addresses(mine, "own_ip", "own_ip_backup")))
    shared = len({tuple(p) for p in mine.get("ports", [])} & {tuple(p) for p in theirs.get("ports", [])})
    like = SequenceMatcher(None, graph.nodes[a].hostname.upper(), graph.nodes[b].hostname.upper()).ratio()
    return closed, shared, like


def pair_units(graph: Graph) -> dict[str, str]:
    """The captured firewalls that are each other's HA peer.  An HA1 address is configured on each unit alone and a dedicated cable joins the two, so the same pair of addresses
    (1.1.1.1 and 1.1.1.2) is normal on every pair of a site, and on every site: an address alone names several units.  A unit is paired with another only when each is the
    other's single best fit (``_score``); a unit with no single best fit is left unpaired and gets an assumed peer, never the wrong real one."""
    units = [k for k, n in sorted(graph.nodes.items()) if n.captured and n.vendor == VENDOR and _ha(n).get("ports")]
    pool, pairs = set(units), {}

    def best(key: str) -> str:
        scored = sorted(((_score(graph, key, o), o) for o in pool if o != key and _is_candidate(_ha(graph.nodes[key]), _ha(graph.nodes[o]))), reverse=True)
        return scored[0][1] if scored and (len(scored) == 1 or scored[0][0] > scored[1][0]) else ""

    while True:
        for key in sorted(pool):
            other = best(key)
            if other and best(other) == key:
                pairs[key], pairs[other] = other, key
                pool -= {key, other}
                break
        else:
            return pairs


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
    pairs = pair_units(graph)
    for key in sorted(k for k, n in graph.nodes.items() if n.captured and n.vendor == VENDOR and _ha(n)):
        mine = _ha(graph.nodes[key])
        if not mine.get("ports"):
            continue
        peer = pairs.get(key, "")
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
