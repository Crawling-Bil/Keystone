"""The links of a management switch drawn as notes: a management switch is cabled to every tier (routers, firewalls, racks), so its lines run across the whole picture
and are the longest and the most crossed on the page.  The picture of the data path does not need them: the management network is a network of its own, kept apart
from the data path (Cisco, Out of band best practices: https://www.cisco.com/c/en/us/solutions/collateral/service-provider/out-of-band-best-practices-wp.html ; Cisco Campus LAN and
Wireless LAN Design Guide: https://www.cisco.com/c/en/us/td/docs/solutions/CVD/Campus/cisco-campus-lan-wlan-design-guide.html).

With ``graph.mgmt_notes`` on, every link from a management switch (``functions.py``) to a router, firewall, load balancer or other switch that is NOT its uplink becomes
the kind ``mgmt-note``: it is left out of the pictures (like the ``mgmt`` kind of ``hide_mgmt``) but stays in links.csv, in the findings and in the tables, and the device at the
far end carries a fourth line under its icon: ``MGMT: SW-MGMT1-DC Gi1/0/12``.  The uplinks (links to a core or aggregation switch) and the links between management
switches stay drawn, so the management switch is still joined to the picture; a management switch that would be left with no drawn link keeps its best one.
"""

from __future__ import annotations

from .graph import Graph

NOTE_KIND = "mgmt-note"
KEEP_ROLES = ("core", "aggregation")                       # the uplinks of the management switch
NOTE_ROLES = ("router", "firewall", "loadbalancer", "access", "switch")
DRAWN_KINDS = ("link", "bundle", "parallel", "inferred")
BEST_ROLE = {"core": 0, "aggregation": 1, "access": 2, "switch": 2, "router": 3, "firewall": 3, "loadbalancer": 3}


def _port_of(conn, key: str) -> str:
    """The port of ``key`` on the first cable of the connection."""
    for link in conn.links:
        return link.a_port if link.a == key else link.b_port
    return ""


def apply(graph: Graph) -> list[str]:
    """Turn the links described above into notes; return one notice per management switch (what was moved and how to draw it again).  Nothing changes when ``graph.mgmt_notes`` is off."""
    for node in graph.nodes.values():
        node.mgmt_note = ""                                                       # type: ignore[attr-defined]
    if not getattr(graph, "mgmt_notes", False):
        return []
    notices: list[str] = []
    notes: dict[str, list[str]] = {}
    for key, node in graph.nodes.items():
        if not getattr(node, "management_why", "") or not node.captured:
            continue
        mine = [c for c in graph.connections if key in (c.a, c.b) and c.kind in DRAWN_KINDS]
        moved = []
        for conn in mine:
            other = conn.b if conn.a == key else conn.a
            peer = graph.nodes[other]
            if getattr(peer, "management_why", "") or peer.role_hint in KEEP_ROLES or peer.role_hint not in NOTE_ROLES:
                continue
            moved.append((conn, other))
        if not moved:
            continue
        kept = [c for c in mine if c not in [m[0] for m in moved]]
        if not kept:                                                              # never leave the management switch with no line at all
            best = min(moved, key=lambda m: (BEST_ROLE.get(graph.nodes[m[1]].role_hint, 9), graph.nodes[m[1]].hostname))
            moved.remove(best)
        for conn, other in moved:
            conn.kind = NOTE_KIND
            notes.setdefault(other, []).append(f"MGMT: {node.hostname} {_port_of(conn, key)}".strip())
        notes.setdefault(key, []).append(f"MGMT: {len(moved)} link(s) as notes")
        notices.append(f"Management switch {node.hostname}: {len(moved)} of its {len(mine)} links (to routers, firewalls and other switches) are drawn as a note on the device at the other end, not as lines; "
                       f"they stay in links.csv and in the findings.  Untick 'Draw management switch links as notes' to draw them.")
    if notes:
        graph.hidden_kinds.add(NOTE_KIND)
    for key, lines in notes.items():
        graph.nodes[key].mgmt_note = lines[0] + (f" (+{len(lines) - 1})" if len(lines) > 1 else "")      # type: ignore[attr-defined]
    return notices
