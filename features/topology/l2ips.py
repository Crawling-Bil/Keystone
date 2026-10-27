"""Key IP addresses on the L2 links: the address of a routed port or routed port-channel is written next to its name.

An L2 line says which port is cabled to which port.  When a port is a routed interface (``no switchport`` with an address, or a
port-channel with an address) the address is the fastest way to see how the cable relates to the L3 picture, so it is added to the
port label: ``Gi0/0/1 10.0.0.1/30``.  Ports without an address (trunks, access ports) are unchanged.
"""

from __future__ import annotations

from .graph import Graph


def _address(graph: Graph, key: str, port: str) -> str:
    node = graph.nodes.get(key)
    if node is None or not port:
        return ""
    for row in node.l3:
        if row.get("name") == port and row.get("ip") and not row.get("shutdown"):
            plen = row.get("prefix_len")
            return f"{row['ip']}/{plen}" if plen else str(row["ip"])
    return ""


def annotate_link_ips(graph: Graph) -> int:
    """Fill ``Link.a_ip`` / ``b_ip`` and ``Connection.po_ip_a`` / ``po_ip_b``; returns how many ends got an address."""
    count = 0
    for link in graph.links:
        link.a_ip, link.b_ip = _address(graph, link.a, link.a_port), _address(graph, link.b, link.b_port)
        count += bool(link.a_ip) + bool(link.b_ip)
    for conn in graph.connections:
        if conn.a_po:
            conn.po_ip_a = _address(graph, conn.a, conn.a_po.split("/")[0])
            count += bool(conn.po_ip_a)
        if conn.b_po:
            conn.po_ip_b = _address(graph, conn.b, conn.b_po.split("/")[0])
            count += bool(conn.po_ip_b)
    return count
