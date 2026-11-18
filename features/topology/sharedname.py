"""One neighbor name on many separate attachments is not one device: it is every server on those ports.

A NIC or hypervisor LLDP agent that sends its vendor string ("BROADCOM ADV", "Intel Corporation", "localhost") as the system name is merged into one box by the name,
and that box is then drawn with long lines to every rack where a server of that kind stands.  ``split_shared_names`` gives each attachment (a port-channel, or one plain
cable) its own node under its own switch, so the box of ten ports becomes ten end points, each under the switch it is plugged into.  TOPO-045 (``findings``) reports it.

What is split, and why that is safe (a real device is never cut apart):

* a neighbor nobody captured whose role says it is an end point (host, server, unknown) with at least ``SPLIT_MIN_UNITS`` separate attachments of which at least
  ``SPLIT_MIN_ON_ONE_SWITCH`` are on one switch: no single server hangs from three or more separate unbundled cables of one switch, and a hub (an uncaptured aggregation
  switch with one cable to each of eight access switches) never has more than one attachment on a switch;
* or a neighbor whose name is a vendor string (``VENDOR_STRING``) with at least ``VENDOR_MIN_UNITS`` attachments of which two are on one switch: the string says the name is
  not a host name.  A vendor string with one cable to each of two switches is left alone: it can be one server on two switches.

Port-channels count once however many members they have (``Device.bundle_of``), plain cables once each.  Standard: IEEE 802.1AB (LLDP: the system name is a free text field the sender chooses), https://1.ieee802.org/maintenance/p802-1ab-2016-revision-station-and-media-access-control-connectivity-discovery/
"""

from __future__ import annotations

import copy
import re
from dataclasses import replace

from .graph import Connection, Graph

SPLIT_MIN_UNITS = 6                 # separate attachments of one neighbor name from which it is taken for several hosts (also the limit of TOPO-045)
SPLIT_MIN_ON_ONE_SWITCH = 3         # ... when at least this many of them are on one switch
VENDOR_MIN_UNITS = 3                # a vendor string needs fewer attachments: the name already says it is not a host name
VENDOR_MIN_ON_ONE_SWITCH = 2
SPLIT_ROLES = ("host", "server", "")                                  # roles that may be several hosts
VENDOR_ROLES = ("host", "server", "access", "switch", "")             # a vendor string is no switch name either, whatever the role guess says
VENDOR_STRING = re.compile(r"^(BROADCOM|INTEL|MELLANOX|EMULEX|QLOGIC|REALTEK|MARVELL|CAVIUM|CHELSIO|SOLARFLARE|LOCALHOST|NOT ADVERTISED|UNKNOWN|DEFAULT)\b", re.I)


def attachments(graph: Graph, key: str) -> dict[str, list[tuple[Connection, str]]]:
    """The separate attachments of ``key`` per captured switch: ``{switch: [(connection, unit)]}``; ``unit`` is the port-channel, or the port of one plain cable
    (a connection of several plain cables is one entry per cable, the ``connection`` is the same object)."""
    found: dict[str, list[tuple[Connection, str]]] = {}
    for conn in graph.connections:
        if key not in (conn.a, conn.b) or conn.kind in graph.hidden_kinds or conn.kind == "rollup":
            continue
        near = conn.b if conn.a == key else conn.a
        if not graph.nodes[near].captured or near == key:
            continue
        if conn.a_po or conn.b_po:
            found.setdefault(near, []).append((conn, conn.a_po if conn.a == near else conn.b_po))
        else:
            for link in conn.links:
                found.setdefault(near, []).append((conn, link.a_port if link.a == near else link.b_port))
    return found


def is_shared(node, per_switch: dict[str, list]) -> bool:
    """Does this uncaptured neighbor stand for several hosts (see the module text for the two rules)?"""
    if node.captured or "::" in node.key or "@" in node.key or not per_switch:
        return False
    total = sum(len(v) for v in per_switch.values())
    biggest = max(len(v) for v in per_switch.values())
    if node.role_hint in SPLIT_ROLES and total >= SPLIT_MIN_UNITS and biggest >= SPLIT_MIN_ON_ONE_SWITCH:
        return True
    return bool(VENDOR_STRING.match(node.hostname or "")) and node.role_hint in VENDOR_ROLES and total >= VENDOR_MIN_UNITS and biggest >= VENDOR_MIN_ON_ONE_SWITCH


def split_shared_names(graph: Graph) -> int:
    """Give every attachment of a shared neighbor name its own node.  Returns the number of names that were split; each one is also written to ``graph.issues`` as
    ``{"type": "shared-name", "name", "units": {switch: attachments}, "nodes": [keys], "model"}`` for TOPO-045."""
    split = 0
    for key in sorted(graph.nodes):
        node = graph.nodes.get(key)
        if node is None:
            continue
        per_switch = attachments(graph, key)
        if not is_shared(node, per_switch):
            continue
        made: list[str] = []
        new_conns: list[Connection] = []
        old = {id(conn) for rows in per_switch.values() for conn, _ in rows}
        for near, rows in sorted(per_switch.items()):
            for conn, unit in rows:
                bundled = bool(conn.a_po or conn.b_po)
                twin_key = f"{key}@{near}:{unit}"
                twin = copy.deepcopy(node)
                twin.key = twin_key
                twin.split_from = key                                   # type: ignore[attr-defined]
                twin.role_hint = "server"                                # a server (roles.classify keeps it: LLDP capabilities of a NIC string say bridge)
                graph.nodes[twin_key] = twin
                made.append(twin_key)
                if bundled:
                    links = list(conn.links)
                    fresh = replace(conn, a=twin_key if conn.a == key else conn.a, b=twin_key if conn.b == key else conn.b, links=links)
                else:
                    links = [link for link in conn.links if (link.a_port if link.a == near else link.b_port) == unit]
                    fresh = replace(conn, a=twin_key if conn.a == key else conn.a, b=twin_key if conn.b == key else conn.b, links=links, kind="link" if conn.kind == "parallel" else conn.kind)
                for link in links:
                    if link.a == key:
                        link.a = twin_key
                    if link.b == key:
                        link.b = twin_key
                new_conns.append(fresh)
        graph.connections = [c for c in graph.connections if id(c) not in old] + new_conns
        del graph.nodes[key]
        graph.issues.append({"type": "shared-name", "name": node.hostname, "model": node.model, "nodes": made,
                             "units": {near: len(rows) for near, rows in sorted(per_switch.items())}})
        split += 1
    return split
