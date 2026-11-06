"""Layer-2 consistency findings that need facts from both ends of a link, or from the whole tier plan.

* TOPO-031  a trunk allows different VLANs at its two ends (the VLANs one end sends and the other end does not allow are dropped),
* TOPO-032  the spanning-tree root bridge is an access switch although the captures include a core or distribution switch,
* TOPO-033  a root bridge that runs the factory-default priority, so the lowest MAC address on the network decides who is root,
* TOPO-035  an access switch that reaches the core or distribution layer through one device only, although the picture holds a second one (a single point
  of failure: the one upper switch, or the one cable to it, isolates the access switch and everything behind it),
* TOPO-034  a switch whose active edge ports can offer more traffic than its uplinks carry, above the campus design guideline
  (20:1 at the access layer, 4:1 at the distribution layer).

Everything is read from the captures through ``Device`` (``port_allowed``, ``port_active``, ``stp_root_for``, ``stp_root_default``,
``actual_speeds``, ``port_state``) and the graph; nothing here parses a capture.  A fact a capture does not hold (a trunk table, a
spanning-tree table, interface speeds) is not a finding.
"""

from __future__ import annotations

import re
from typing import Any

from .extract import Device
from .findings import _few, _row
from .graph import Connection, Graph, link_speed
from .names import canon_port, speed_text
from .roles import ROLE_TIER

DOC_TRUNK = "https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-15/configuration_guide/vlan/b_1715_vlan_9300_cg/configuring_vlan_trunks.html"
DOC_STP_ROOT = "https://www.cisco.com/c/en/us/support/docs/lan-switching/spanning-tree-protocol/10556-16.html"
DOC_STP_GUIDE = "https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-12/configuration_guide/lyr2/b_1712_lyr2_9300_cg/configuring_spanning_tree_protocol.html"
DOC_OVERSUBSCRIPTION = "https://www.cisco.com/c/en/us/td/docs/solutions/Enterprise/Campus/HA_campus_DG/hacampusdg.html"

DOC_REDUNDANCY = "https://www.cisco.com/c/en/us/td/docs/solutions/Enterprise/Campus/HA_campus_DG/hacampusdg.html"

OVERSUBSCRIPTION_LIMIT = {2: 4.0, 3: 20.0}        # by tier (roles.ROLE_TIER): distribution 4:1, access 20:1
_IGNORED_PORTS = ("po", "vlan", "lo", "mgmt", "tunnel", "null", "nve", "bridge-aggregation", "eth-trunk", "lag", "irb")
ALL_VLANS = frozenset(range(1, 4095))


def vlan_set(text: str) -> frozenset[int] | None:
    """The VLANs of a list as printed by ``show interfaces trunk`` ("1-4094", "10,21-23", "none"); None when the text is not a list."""
    value = re.sub(r"\s+", "", text or "").lower()
    if not value:
        return None
    if value in ("all", "any"):
        return ALL_VLANS
    if value == "none":
        return frozenset()
    found: set[int] = set()
    for part in value.split(","):
        match = re.fullmatch(r"(\d{1,4})(?:-(\d{1,4}))?", part)
        if not match:
            return None
        low, high = int(match.group(1)), int(match.group(2) or match.group(1))
        if low > high or high > 4094:
            return None
        found.update(range(low, high + 1))
    return frozenset(found)


def ranges(values) -> str:
    """{10, 11, 12, 20} -> '10-12,20'."""
    items = sorted(values)
    out: list[str] = []
    start = previous = None
    for number in items:
        if start is None:
            start = previous = number
        elif number == previous + 1:
            previous = number
        else:
            out.append(str(start) if start == previous else f"{start}-{previous}")
            start = previous = number
    if start is not None:
        out.append(str(start) if start == previous else f"{start}-{previous}")
    return ",".join(out)


def _end(node: Device, bundle: str, ports: list[str]) -> tuple[str, str, str]:
    """(port name, allowed text, active text) of one end of a connection: the port-channel when the capture lists it, else the first member port."""
    for name in ([bundle, canon_port(bundle)] if bundle else []) + ports:
        if name in node.port_allowed:
            return name, node.port_allowed[name], node.port_active.get(name, "")
    return "", "", ""


def _trunk_findings(graph: Graph) -> list[dict[str, Any]]:
    """TOPO-031."""
    found: list[str] = []
    devices: set[str] = set()
    proven = False
    for conn in graph.connections:
        if conn.kind in ("rollup", "host", "routed"):
            continue
        a, b = graph.nodes.get(conn.a), graph.nodes.get(conn.b)
        if a is None or b is None or not (a.captured and b.captured):
            continue
        port_a, allowed_a, active_a = _end(a, conn.a_po, [link.a_port for link in conn.links])
        port_b, allowed_b, active_b = _end(b, conn.b_po, [link.b_port for link in conn.links])
        set_a, set_b = vlan_set(allowed_a), vlan_set(allowed_b)
        if set_a is None or set_b is None or set_a == set_b:
            continue
        lost: list[str] = []
        for (name, port, allowed, active), (other, other_port, other_allowed) in (((a.hostname, port_a, set_a, vlan_set(active_a)), (b.hostname, port_b, set_b)),
                                                                                  ((b.hostname, port_b, set_b, vlan_set(active_b)), (a.hostname, port_a, set_a))):
            if active is not None:
                missing = active - other_allowed                  # VLANs this end really carries (allowed and active) that the other end does not allow
                if missing:
                    proven = True
                    lost.append(f"VLAN {ranges(missing)} (active on {name}) is dropped at {other}")
            elif allowed != ALL_VLANS and other_allowed != ALL_VLANS:
                missing = allowed - other_allowed                 # both lists are explicit: what one end allows and the other does not
                if missing:
                    lost.append(f"VLAN {ranges(missing)} (allowed on {name}) is not allowed at {other}")
        if lost:
            found.append(f"{a.hostname} {port_a} - {b.hostname} {port_b}: {'; '.join(lost)}")
            devices.update((a.hostname, b.hostname))
    if not found:
        return []
    return [_row("TOPO-031", "medium" if proven else "low", f"{len(found)} trunk(s) allow different VLANs at the two ends", _few(found, 4), sorted(devices),
                 "A frame of a VLAN that the receiving end does not allow on its trunk is dropped, so hosts of that VLAN behind one switch cannot reach the other. "
                 "Make the two allowed lists equal (switchport trunk allowed vlan on Cisco, port trunk allow-pass vlan on Huawei, vlan trunk allowed on AOS-CX), "
                 "or remove the VLAN where it is sent. 'Active' VLANs are those that exist on the switch and are allowed on the trunk (show interfaces trunk); "
                 "a finding marked low compares the configured lists only.", DOC_TRUNK)]


def _tier(node: Device) -> int:
    return ROLE_TIER.get(node.role_hint or "switch", 3)


def _root_findings(graph: Graph) -> list[dict[str, Any]]:
    """TOPO-032 and TOPO-033."""
    switches = [n for n in graph.nodes.values() if n.captured and n.stp_root_for]
    upper = sorted(n.hostname for n in graph.nodes.values() if n.captured and n.role_hint in ("core", "aggregation"))
    rows: list[dict[str, Any]] = []
    wrong = [n for n in switches if n.role_hint in ("access", "switch")] if upper else []
    if wrong:
        lines = [f"{n.hostname} ({n.role_hint}) is the root of {_few(sorted(n.stp_root_for), 4)}" for n in sorted(wrong, key=lambda n: n.hostname)]
        rows.append(_row("TOPO-032", "medium" if any(n.role_hint == "access" for n in wrong) else "low",
                         f"{len(wrong)} switch(es) at the access layer are spanning-tree root bridges", _few(lines, 4), sorted(n.hostname for n in wrong),
                         "Every path between two switches goes through the root, so a root at the edge sends the traffic of the whole network over an access uplink. "
                         f"Put the root on the core or distribution layer ({', '.join(upper[:4])}{' ...' if len(upper) > 4 else ''}): set its priority explicitly "
                         "(spanning-tree vlan 1-4094 priority 4096, or root primary) and give the second core a higher value (8192, or root secondary).", DOC_STP_ROOT))
    default = [n for n in switches if n.stp_root_default]
    if default:
        lines = [f"{n.hostname}: {_few(sorted(n.stp_root_default), 4)}" for n in sorted(default, key=lambda n: n.hostname)]
        rows.append(_row("TOPO-033", "low", f"{len(default)} root bridge(s) run the factory-default priority", _few(lines, 4), sorted(n.hostname for n in default),
                         "With the default priority (32768 plus the VLAN number) the switch with the lowest MAC address becomes root, usually the oldest one, wherever it is. "
                         "Set the priority on the switch that should be root and on the one that takes over (spanning-tree vlan N root primary / root secondary, or priority 4096 / 8192; "
                         "on Huawei stp priority 4096, on AOS-CX spanning-tree priority 1).", DOC_STP_GUIDE))
    return rows


def _is_physical(port: str) -> bool:
    return bool(port) and not canon_port(port).lower().startswith(_IGNORED_PORTS)


def _links_of(graph: Graph, key: str) -> list[tuple[Connection, str, list[str]]]:
    """(connection, the other node, my ports) for every connection of a node."""
    out = []
    for conn in graph.connections:
        if conn.kind in ("rollup", "host"):
            continue
        if conn.a == key:
            out.append((conn, conn.b, [link.a_port for link in conn.links]))
        elif conn.b == key:
            out.append((conn, conn.a, [link.b_port for link in conn.links]))
    return out


def _oversubscription_findings(graph: Graph) -> list[dict[str, Any]]:
    """TOPO-034: the speed of the up ports that are not uplinks or peer links, against the speed of the uplinks."""
    lines: list[tuple[float, str, str]] = []
    for key, node in graph.nodes.items():
        tier = _tier(node)
        limit = OVERSUBSCRIPTION_LIMIT.get(tier)
        if not node.captured or limit is None or not node.actual_speeds:
            continue
        uplink_ports: set[str] = set()
        peer_ports: set[str] = set()
        uplink_capacity = 0
        for conn, other_key, ports in _links_of(graph, key):
            other = graph.nodes.get(other_key)
            if other is None:
                continue
            other_tier = _tier(other)
            if other_tier < tier and other.role_hint not in ("server", "host", "phone", "ap", "fabric"):
                for link in conn.links:
                    port = link.a_port if link.a == key else link.b_port
                    if node.port_state.get(port) == "down":
                        continue
                    uplink_ports.add(port)
                    uplink_capacity += link_speed(graph, link)
            elif other_tier == tier and other.role_hint in ("core", "aggregation", "access", "switch"):
                peer_ports.update(ports)
        downstream = sum(speed for port, speed in node.actual_speeds.items()
                         if _is_physical(port) and port not in uplink_ports and port not in peer_ports and node.port_state.get(port, "up") == "up")
        if uplink_capacity <= 0 or downstream <= 0:
            continue
        ratio = downstream / uplink_capacity
        if ratio > limit:
            lines.append((ratio, node.hostname, f"{node.hostname}: {speed_text(downstream)} of active ports behind {speed_text(uplink_capacity)} of uplink "
                                                f"({ratio:.0f}:1, guideline {limit:.0f}:1)"))
    if not lines:
        return []
    lines.sort(key=lambda item: (-item[0], item[1]))
    severe = any(ratio > 2 * OVERSUBSCRIPTION_LIMIT[_tier(next(n for n in graph.nodes.values() if n.hostname == name))] for ratio, name, _ in lines)
    return [_row("TOPO-034", "low" if severe else "info", f"{len(lines)} switch(es) with more edge bandwidth behind their uplinks than the design guideline allows",
                 _few([text for _, _, text in lines], 4), sorted(name for _, name, _ in lines),
                 "The figure is the worst case: every active port at line rate at the same time. Campus design practice is about 20:1 for access ports behind the uplinks of an access "
                 "switch and 4:1 for the distribution layer towards the core. Real traffic is lower, so look at the uplink utilization (show interfaces counters, "
                 "or the 5-minute rate) before adding links; a bundle or faster uplink fixes it.", DOC_OVERSUBSCRIPTION)]


UPPER_ROLES = ("core", "aggregation")
LOWER_ROLES = ("access", "switch")
SECOND_UPLINK_HOPS = 2          # a second upper switch the access switch could really be wired to: a vPC / VSS peer (1 hop) or a sibling under the same core (2 hops)


def _near_upper(graph: Graph, start: str, hops: int = SECOND_UPLINK_HOPS) -> set[str]:
    """The core or distribution switches within ``hops`` links of ``start`` (itself left out).  A core of another branch, reached over a WAN, is not one of them."""
    seen = {start}
    frontier = [start]
    for _ in range(hops):
        step: list[str] = []
        for key in frontier:
            for _conn, other, _ports in _links_of(graph, key):
                if other not in seen:
                    seen.add(other)
                    step.append(other)
        frontier = step
    return {key for key in seen if key != start and graph.nodes[key].role_hint in UPPER_ROLES}


def _single_uplink_findings(graph: Graph) -> list[dict[str, Any]]:
    """TOPO-035: a captured access switch whose live uplinks all end on the same single upper-layer chassis while a second upper-layer switch stands within
    reach of it (``_near_upper``: not a core of another site).  A port-channel split over a vPC pair reaches two chassis and so counts as two paths; two or more ports into one stack count as redundant (the member of each port is not in the capture); a port that is down does not count."""
    if sum(1 for node in graph.nodes.values() if node.role_hint in UPPER_ROLES) < 2:
        return []                                       # nothing else to dual-home to in this picture
    found: list[tuple[str, str, int]] = []              # access switch, its only upper switch, live uplink ports
    upper_set: set[str] = set()                         # the upper switches of the findings and the ones they could also have used
    for key, node in graph.nodes.items():
        if not node.captured or node.role_hint not in LOWER_ROLES:
            continue
        chassis: set[str] = set()
        ports = 0
        redundant = False
        for conn, other_key, _mine in _links_of(graph, key):
            other = graph.nodes.get(other_key)
            if other is None or other.role_hint not in UPPER_ROLES:
                continue
            live = [link.a_port if link.a == key else link.b_port for link in conn.links]
            live = [port for port in live if node.port_state.get(port) != "down"]
            if not live:
                continue
            chassis.add(other_key)
            ports += len(live)
            if other.stack_members > 1 and len(live) > 1:        # two or more ports into a stack: assume they sit on different members
                redundant = True
        if len(chassis) == 1 and not redundant:
            only = next(iter(chassis))
            spare = _near_upper(graph, only)
            if spare:
                found.append((node.hostname, graph.nodes[only].hostname, ports))
                upper_set.update(spare | {only})
    if not found:
        return []
    found.sort()
    lines = [f"{name}: only {upper_name} ({plural_ports(ports)})" for name, upper_name, ports in found]
    pairs = sorted({name for name, _, _ in found} | {upper_name for _, upper_name, _ in found})
    return [_row("TOPO-035", "medium", f"{len(found)} access switch(es) reach the core or distribution layer through one device only", _few(lines, 6), pairs,
                 f"The picture holds {len(upper_set)} core or distribution switches in reach ({_few(sorted(graph.nodes[k].hostname for k in upper_set), 4)}), but these access switches use one of them. "
                 "If that switch, its linecard or the one cable fails, the access switch and every device behind it lose the network. Connect the second uplink to the other "
                 "upper switch (a port-channel split over a vPC pair, a VSS or a stack gives the same without a spanning-tree blocked port), then capture both ends again. "
                 "If the single uplink is intended (a lab, a small branch), the finding can stay as a reminder. A port that was down when the capture was taken counts as no path.",
                 DOC_REDUNDANCY)]


def plural_ports(count: int) -> str:
    return f"{count} port" + ("" if count == 1 else "s")


def l2_findings(graph: Graph) -> list[dict[str, Any]]:
    return _trunk_findings(graph) + _root_findings(graph) + _oversubscription_findings(graph) + _single_uplink_findings(graph)
