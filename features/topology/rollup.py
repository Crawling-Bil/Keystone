"""Collapse many endpoint stubs (access points, phones, servers) that hang off one device into one node.

The full list stays in the node's data and in links.csv; the diagram stays readable.
"""

from __future__ import annotations

from collections import defaultdict

from .extract import Device
from .graph import Connection, Graph

ROLLUP_ROLES = {"ap": "access points", "phone": "phones", "host": "hosts", "server": "servers"}


ENDPOINT_ROLES = ("phone", "host", "server")


def hide_endpoints(graph: Graph) -> int:
    """Option "exclude IP phones and PCs": leave every phone, host and server (and the boxes that stand for several) out of the pictures."""
    hidden = {key for key, node in graph.nodes.items() if node.role_hint in ENDPOINT_ROLES and not node.captured}
    graph.hidden_nodes |= hidden
    return len(hidden)


def rollup(graph: Graph, threshold: int = 3, roles: set[str] | None = None) -> None:
    """Fold endpoint stubs into one box per switch. ``roles`` limits it to some of ROLLUP_ROLES (access points kept apart, say)."""
    allowed = set(ROLLUP_ROLES) if roles is None else set(roles)
    buckets: dict[tuple[str, str], list[Connection]] = defaultdict(list)
    for conn in graph.connections:
        for near, far in ((conn.a, conn.b), (conn.b, conn.a)):
            node = graph.nodes[far]
            if not node.captured and node.role_hint in allowed and node.role_hint != "server" and graph.nodes[near].captured:
                degree = sum(1 for c in graph.connections if far in (c.a, c.b))
                if degree == 1:
                    buckets[(near, node.role_hint)].append(conn)
    for (parent, role), conns in buckets.items():
        if len(conns) < threshold:
            continue
        members = []
        for conn in conns:
            far = conn.b if conn.a == parent else conn.a
            members.append(far)
        key = f"{parent}::{role}"
        label = f"{len(members)} {ROLLUP_ROLES[role]}"
        stub = Device(key=key, hostname=label, captured=False, role_hint=role,
                      model=", ".join(sorted(graph.nodes[m].hostname for m in members)[:3]) + (" ..." if len(members) > 3 else ""))
        stub.rolled_up = members  # type: ignore[attr-defined]
        graph.nodes[key] = stub
        links = [link for conn in conns for link in conn.links]
        for link in links:   # orient parent first
            if link.b == parent:
                link.swap()
        merged = Connection(parent, key, links, kind="rollup")
        graph.connections = [c for c in graph.connections if c not in conns] + [merged]
        for member in members:
            graph.rolled_roles[member] = role
            graph.nodes.pop(member, None)
