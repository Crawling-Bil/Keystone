"""Neighbors that a switch lists on a port they are not plugged into: CDP crossing a switch that does not speak CDP.

CDP frames go to a multicast address (01-00-0c-cc-cc-cc).  A Cisco switch consumes them; a switch that does not run CDP (a Huawei or any other
vendor, an unmanaged switch) treats them as ordinary multicast and floods them out of every port.  An access point or an IP phone that sends
CDP therefore shows up in the CDP table of the *next* Cisco switch up the trunk, on the uplink port, as if it were plugged into that switch.
LLDP frames (01-80-c2-00-00-0e) are never forwarded by a bridge, so the same port also lists the one real neighbor, the switch in between.

Read as cables this draws every access point twice: once on the switch it is really plugged into (the LLDP table of that switch) and once on
the switch above.  The second set of lines crosses the picture, gives each access point two attachments (so it can no longer be framed under its
switch) and, when the switch in between was not captured, hangs the access points of one switch under another.

A port has one cable, so one real neighbor.  Two signatures tell which one it is:

* LLDP.  Only the device at the far end of the cable can send LLDP to this port, so when exactly one neighbor on the port was learned by LLDP, it is
  the real one and every neighbor that only CDP reported is behind it (a Cisco switch above a Huawei switch above another Cisco switch).
* Roles, when no LLDP is there to say: a port that lists one network device (switch, router, firewall, load balancer) and, beside it, end points
  (access points, phones, hosts).  A Cisco switch does not pass CDP on, so an end point reported next to a switch is behind a bridge that does.

The neighbors that are behind the real one get this:

* an end point that is also attached somewhere else keeps that attachment, the lines through the port are dropped;
* an end point with no other attachment is attached to the network device on that port (a single-sided link, noted as seen through).

Nothing here depends on a vendor name: any port with this shape is treated the same way, in every view.  Documentation: the behavior of a
switch that does not support CDP (it floods the frames) is described in
https://community.cisco.com/t5/switching/cisco-cdp-with-indirect-link/td-p/1955398 ; LLDP is link-local and not forwarded (IEEE 802.1AB)
https://1.ieee802.org/maintenance/p802-1ab-2016-revision-station-and-media-access-control-connectivity-discovery/
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from .graph import Graph, Link, _connections

ENDPOINT_ROLES = ("ap", "phone", "host", "server")
NETWORK_ROLES = ("access", "aggregation", "core", "switch", "router", "firewall", "loadbalancer", "wlc", "fabric")
MIN_ENDPOINTS = 1                       # neighbors behind the real one that make a port a "through" port


def _far(link: Link, key: str) -> tuple[str, str, str]:
    """(far node, own port, far port) of ``link`` seen from ``key``."""
    if link.a == key:
        return link.b, link.a_port, link.b_port
    return link.a, link.b_port, link.a_port


def _ports(graph: Graph) -> dict[tuple[str, str], list[Link]]:
    """Links at every (captured node, port)."""
    found: dict[tuple[str, str], list[Link]] = defaultdict(list)
    for link in graph.links:
        for node, port in ((link.a, link.a_port), (link.b, link.b_port)):
            if port and graph.nodes[node].captured:
                found[(node, port)].append(link)
    return found


def apply(graph: Graph) -> list[dict[str, Any]]:
    """Fix the links of ``graph`` in place (roles must be known) and return the ``seen-through`` issues, one per switch and the device in
    front of its ports.  Connections are rebuilt when anything changed."""
    through: list[tuple[str, str, str, Link]] = []                      # (switch, port, real neighbor, link to a neighbor that is behind it)
    for (key, port), links in _ports(graph).items():
        if len(links) < 2:
            continue
        far = {id(link): _far(link, key)[0] for link in links}
        by_lldp = {far[id(link)] for link in links if "LLDP" in link.protocols}
        if len(by_lldp) == 1:
            anchor = next(iter(by_lldp))
            behind = [link for link in links if far[id(link)] != anchor and "LLDP" not in link.protocols]
        else:
            anchors = {name for name in far.values() if graph.nodes[name].role_hint in NETWORK_ROLES}
            behind = [link for link in links if graph.nodes[far[id(link)]].role_hint in ENDPOINT_ROLES]
            anchor = next(iter(anchors)) if len(anchors) == 1 else ""
        if not anchor or graph.nodes[anchor].role_hint not in NETWORK_ROLES or len(behind) < MIN_ENDPOINTS:
            continue
        through += [(key, port, anchor, link) for link in behind]
    if not through:
        return []

    by_end: dict[str, list[tuple[str, str, str, Link]]] = defaultdict(list)
    for item in through:
        key, _port, _anchor, link = item
        by_end[_far(link, key)[0]].append(item)
    flooded = {id(item[3]) for item in through}
    drop: set[int] = set()
    new_links: list[Link] = []
    rehomed: dict[tuple[str, str], list[str]] = defaultdict(list)
    dropped: dict[tuple[str, str], list[str]] = defaultdict(list)
    for end, items in by_end.items():
        direct = [l for l in graph.links if end in (l.a, l.b) and id(l) not in flooded]
        for key, _port, anchor, link in items:
            drop.add(id(link))
        if direct:                                                       # plugged in somewhere we can see: that cable is the real one
            for key, port, anchor, link in items:
                dropped[(key, anchor)].append(end)
            continue
        best = max(items, key=lambda item: sum(1 for other in items if other[2] == item[2]))
        key, port, anchor, link = best
        end_port = _far(link, key)[2]
        protocols = set().union(*(item[3].protocols for item in items))
        new_links.append(Link(anchor, "", end, end_port, "single", protocols,
                              f"seen through {anchor}: {key} lists it on a port that faces {anchor}, which does not send CDP"))
        for key, port, anchor, link in items:
            rehomed[(key, anchor)].append(end)
    graph.links = [link for link in graph.links if id(link) not in drop] + new_links
    graph.connections = []
    graph.vpc_pairs = []
    _connections(graph)

    ports: dict[tuple[str, str], set[str]] = defaultdict(set)
    for key, port, anchor, _link in through:
        ports[(key, anchor)].add(port)
    handled = {(key, port) for key, port, _anchor, _link in through}
    graph.issues = [i for i in graph.issues if not (i.get("type") == "proto-disagree" and (i.get("node"), i.get("port")) in handled)]
    return [{"type": "seen-through", "node": key, "anchor": anchor, "ports": sorted(found),
             "rehomed": sorted(set(rehomed.get((key, anchor), []))), "dropped": sorted(set(dropped.get((key, anchor), [])))}
            for (key, anchor), found in sorted(ports.items())]
