"""The map between the zones of the drawing and the security zones of the firewalls, and the cables that go round a firewall.

A firewall separates networks by *zone*: PAN-OS puts every interface in a security zone, FortiOS puts an interface in a zone or lets it be its own zone in a policy.  What the
firewall does with traffic between two zones is the rulebase; that the traffic goes *through* the firewall at all is a fact of the cabling.  Both are in the captures:

* ``zone_map`` lists, for every firewall interface that sits in a zone, the cable it uses (the port, or the aggregate it belongs to, or the port under a VLAN sub-interface), the
  device on the other end, and the zone of the drawing that device stands in.  It is the table an engineer fills in by hand to show which firewall zone faces which part of the network.
* ``bypasses`` finds the cabling that defeats the separation.  From the device on the far end of each interface, the network is followed through switches only (a router, another
  firewall, a load balancer or a cloud ends the walk: those are places where traffic is handled on purpose), one VLAN at a time: a trunk that does not carry the VLAN stops it.  When the walks
  of two interfaces of the **same firewall** in **different zones** reach the same switch in the **same VLAN**, a frame can pass from one zone to the other without the firewall.  If the VLAN is
  tagged on both firewall interfaces the VLAN is known and the finding is firm; if an interface is untagged the VLAN comes from the native / access VLAN of the switch port when the capture
  shows it, and the finding is a *possible* path when it does not (``certain`` is False).

The walk uses what the captures hold (cables, trunk VLAN lists, native VLANs) and nothing else: a switch that was not captured is a device the walk reaches but cannot leave, a trunk whose list is
unknown is taken as carrying every VLAN, and an access port's VLAN that no capture printed is unknown.  The finding says so.

The same walk finds the **routed** way round a firewall, which a Layer 2 meeting does not show: a Layer 3 switch that carries the VLAN of one zone *and* the VLAN of another and has a
routed interface (SVI) in both, in the same VRF, routes between the zones by itself (``routed_bypasses``, kind ``svi``, firm because both VLANs and both SVIs are in the captures); and a router
that is cabled into both zones (kind ``router``, *possible*: only its routing table and access lists say whether it forwards between them).

Segmentation of the cardholder data environment is a PCI DSS requirement (network security controls between trusted and untrusted networks, v4.0 requirement 1) and IEC 62443-3-2 asks for zones
and conduits in industrial networks; NIST SP 800-41 Rev. 1 describes the placement of firewalls between zones.
NIST SP 800-41 Rev. 1: https://csrc.nist.gov/pubs/sp/800/41/r1/final
PAN-OS security zones: https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-web-interface-help/network/network-zones/security-zone-overview
FortiOS zones: https://docs.fortinet.com/document/fortigate/7.2.10/administration-guide/116821/zone
"""

from __future__ import annotations

import re
from collections import deque
from typing import Any

from .graph import Connection, Graph
from .l2findings import _end, vlan_set
from .names import canon_port

SWITCHING = ("core", "aggregation", "distribution", "access", "switch", "fabric")     # the walk goes through these only
CABLE_KINDS = ("link", "bundle", "parallel", "peer-link", "vpc", "sitebundle")        # not the management port, not the routed, host or roll-up lines
UNKNOWN = "?"                                                                          # the VLAN of an untagged firewall interface whose switch port is not described


def _base(iface: dict[str, Any], by_name: dict[str, dict[str, Any]]) -> tuple[str, Any]:
    """(port or aggregate that carries the interface, VLAN tag): a VLAN sub-interface is carried by its parent, which may itself be an aggregate."""
    name, vlan, seen = iface["name"], iface.get("vlan"), set()
    while by_name.get(name, {}).get("parent") and name not in seen:
        seen.add(name)
        vlan = vlan if vlan else by_name[name].get("vlan")
        name = by_name[name]["parent"]
    return name, vlan


def _cables(graph: Graph, key: str, carrier: str) -> list[tuple[Connection, str, str]]:
    """The connections of firewall ``key`` that use ``carrier`` (an aggregate name, or a port): (connection, far device, port on the far end)."""
    found = []
    wanted = canon_port(carrier)
    for conn in graph.connections:
        if conn.kind not in CABLE_KINDS or key not in (conn.a, conn.b):
            continue
        mine = conn.a == key
        po = conn.a_po if mine else conn.b_po
        ports = [link.a_port if mine else link.b_port for link in conn.links]
        if (po and po in (carrier, wanted)) or any(canon_port(p) == wanted or p == carrier for p in ports):
            far = conn.b if mine else conn.a
            found.append((conn, far, (conn.links[0].b_port if mine else conn.links[0].a_port) if conn.links else ""))
    return found


def _passes(graph: Graph, conn: Connection, vlan: Any) -> bool:
    """A cable carries ``vlan`` unless both ends print a trunk list that leaves it out; an unknown list passes everything."""
    if vlan in (None, UNKNOWN):
        return True
    for key, bundle in ((conn.a, conn.a_po), (conn.b, conn.b_po)):
        node = graph.nodes.get(key)
        ports = [link.a_port if key == conn.a else link.b_port for link in conn.links]
        _name, allowed, _active = _end(node, bundle, ports) if node is not None else ("", "", "")
        listed = vlan_set(allowed)
        if listed is not None and int(vlan) not in listed:
            return False
    return True


def _walk(graph: Graph, start: str, vlan: Any, skip: set[str]) -> set[tuple[str, Any]]:
    """The (switch, VLAN) pairs reached from ``start`` through switches only."""
    seen = {(start, vlan)}
    todo = deque([start])
    while todo:
        key = todo.popleft()
        if graph.nodes[key].role_hint not in SWITCHING:
            continue
        for conn in graph.connections:
            if conn.kind not in CABLE_KINDS or key not in (conn.a, conn.b):
                continue
            far = conn.b if conn.a == key else conn.a
            node = graph.nodes.get(far)
            if node is None or far in skip or (far, vlan) in seen or not _passes(graph, conn, vlan):
                continue
            seen.add((far, vlan))
            todo.append(far)
    return seen


def _port_vlan(graph: Graph, far: str, far_port: str) -> Any:
    """The native / access VLAN printed for the switch port that an untagged firewall interface is cabled to; ``UNKNOWN`` when no capture shows it."""
    node = graph.nodes.get(far)
    value = (node.port_native.get(canon_port(far_port)) if node is not None else "") or ""
    return int(value) if str(value).isdigit() else UNKNOWN


def _legs(graph: Graph) -> list[dict[str, Any]]:
    legs: list[dict[str, Any]] = []
    for key, node in graph.nodes.items():
        if node.role_hint != "firewall" or not getattr(node, "fw_ifaces", None):
            continue
        by_name = {i["name"]: i for i in node.fw_ifaces}
        for iface in node.fw_ifaces:
            if canon_port(iface["name"]) in node.bundle_of or iface["name"] in node.bundle_of:
                continue                                                      # a member of an aggregate / redundant interface is not an interface of its own: the aggregate is
            carrier, tag = _base(iface, by_name)
            for conn, far, far_port in _cables(graph, key, carrier):
                legs.append({"firewall": key, "interface": iface["name"], "zone": iface["zone"], "carrier": carrier, "vlan": tag, "far": far, "far_port": far_port, "conn": conn})
    return legs


def zone_map(graph: Graph, pages: list | None = None) -> list[dict[str, Any]]:
    """One row per firewall interface cable: firewall, interface, firewall zone, VLAN, cable (port or aggregate), the device on the far end and the zone of the drawing it stands in."""
    drawn: dict[str, str] = {}
    for page in (pages or [])[::-1]:                              # the pages in reverse: the Overview first, so that a page of one site (more exact) overwrites it
        for key, placed in page.nodes.items():
            if getattr(placed, "zone", ""):
                drawn[key] = placed.zone
    rows = []
    for leg in sorted(_legs(graph), key=lambda l: (graph.nodes[l["firewall"]].hostname, l["zone"], l["interface"])):
        far = graph.nodes[leg["far"]]
        rows.append({"firewall": graph.nodes[leg["firewall"]].hostname, "firewall_zone": leg["zone"], "interface": leg["interface"], "vlan": leg["vlan"] or "",
                     "cable": leg["carrier"], "neighbor": far.hostname, "neighbor_role": far.role_hint, "neighbor_port": leg["far_port"],
                     "drawing_zone": drawn.get(leg["far"], ""), "evidence": ", ".join(sorted({p for l in leg["conn"].links for p in l.protocols})) or leg["conn"].state})
    return rows


def bypasses(graph: Graph) -> list[dict[str, Any]]:
    """Pairs of interfaces of one firewall, in two zones, whose far sides meet in a switch in the same VLAN (see the module text)."""
    legs = _legs(graph)
    firewalls = {l["firewall"] for l in legs}
    found: dict[tuple, dict[str, Any]] = {}
    for key in sorted(firewalls):
        mine = [l for l in legs if l["firewall"] == key]
        reach = []
        for leg in mine:
            vlan = leg["vlan"] if leg["vlan"] else _port_vlan(graph, leg["far"], leg["far_port"])
            leg["known"] = vlan != UNKNOWN
            reach.append((leg, vlan, _walk(graph, leg["far"], vlan, firewalls | {key})))
        for i, (a, va, wa) in enumerate(reach):
            for b, vb, wb in reach[i + 1:]:
                if a["zone"] == b["zone"]:
                    continue
                if va != vb:
                    continue                                              # another VLAN, or a tagged interface against an untagged one: the tagged frames and the native ones do not meet
                meet = {k for k, _ in wa} & {k for k, _ in wb} if va == UNKNOWN else {k for k, v in wa if (k, v) in wb}
                shared = sorted(k for k in meet if graph.nodes[k].role_hint in SWITCHING)       # a router or a cloud that both reach is a place where traffic is handled, not a meeting of two zones
                if not shared:
                    continue
                pair = tuple(sorted(((a["zone"], a["interface"]), (b["zone"], b["interface"]))))
                certain = a["known"] and b["known"]
                row = {"firewall": graph.nodes[key].hostname, "zone_a": pair[0][0], "interface_a": pair[0][1], "zone_b": pair[1][0], "interface_b": pair[1][1],
                       "vlan": va, "through": ", ".join(graph.nodes[k].hostname for k in shared[:4]) + (" ..." if len(shared) > 4 else ""),
                       "certain": certain, "devices": sorted({graph.nodes[key].hostname} | {graph.nodes[k].hostname for k in shared})}
                old = found.get(pair)
                if old is None or (certain and not old["certain"]):
                    found[pair] = row
    return sorted(found.values(), key=lambda r: (not r["certain"], r["firewall"], r["zone_a"], r["zone_b"]))


def _svi_vrfs(node) -> dict[int, set[str]]:
    """VLAN number -> VRFs in which the device has a routed VLAN interface that is not shut down (``Vlan10``, ``Vlanif10``, ``vlan 10``)."""
    out: dict[int, set[str]] = {}
    for row in getattr(node, "l3", None) or []:
        match = re.fullmatch(r"(?:vlan|vlanif|vl)\s*(\d{1,4})", str(row.get("name", "")).strip().lower())
        if match and not row.get("shutdown"):
            out.setdefault(int(match.group(1)), set()).add(str(row.get("vrf") or "") or "global")
    return out


def routed_bypasses(graph: Graph) -> list[dict[str, Any]]:
    """Pairs of interfaces of one firewall, in two zones, that a Layer 3 device joins: ``svi`` (a switch with an SVI in the VLAN of each zone in one VRF, firm) or ``router`` (a router cabled into both zones, possible)."""
    legs = _legs(graph)
    firewalls = {l["firewall"] for l in legs}
    found: dict[tuple, dict[str, Any]] = {}
    for key in sorted(firewalls):
        reach = []
        names = {i["name"] for i in graph.nodes[key].fw_ifaces}
        parents = {i.get("parent") for i in graph.nodes[key].fw_ifaces if i.get("parent") in names}
        for leg in (l for l in legs if l["firewall"] == key):
            if leg["interface"] in parents and not leg["vlan"]:
                continue                                                      # the untagged parent of VLAN sub-interfaces only carries them: the sub-interfaces are the zones
            vlan = leg["vlan"] if leg["vlan"] else _port_vlan(graph, leg["far"], leg["far_port"])
            reach.append((leg, vlan, _walk(graph, leg["far"], vlan, firewalls | {key})))
        for i, (a, va, wa) in enumerate(reach):
            for b, vb, wb in reach[i + 1:]:
                if a["zone"] == b["zone"]:
                    continue
                pair = tuple(sorted(((a["zone"], a["interface"]), (b["zone"], b["interface"]))))
                for node_key in sorted({k for k, _ in wa} & {k for k, _ in wb}):
                    node = graph.nodes[node_key]
                    if node.role_hint in SWITCHING:
                        if not (isinstance(va, int) and isinstance(vb, int) and va != vb and (node_key, va) in wa and (node_key, vb) in wb):
                            continue
                        svi = _svi_vrfs(node)
                        vrfs = svi.get(va, set()) & svi.get(vb, set())
                        if not vrfs:
                            continue
                        kind, certain, detail = "svi", True, f"VLAN {va} and VLAN {vb}" + (f" (VRF {sorted(vrfs)[0]})" if sorted(vrfs)[0] != "global" else "")
                    elif node.role_hint == "router":
                        if any(v in (None, UNKNOWN) and node_key != leg["far"] for leg, v in ((a, va), (b, vb))):
                            continue                                          # an untagged leg of unknown VLAN would reach everything: only a router cabled to it directly counts
                        kind, certain, detail = "router", False, "cabled into both zones"
                    else:
                        continue
                    row_key = (pair, node_key)
                    found.setdefault(row_key, {"firewall": graph.nodes[key].hostname, "zone_a": pair[0][0], "interface_a": pair[0][1], "zone_b": pair[1][0], "interface_b": pair[1][1],
                                               "via": node.hostname, "kind": kind, "detail": detail, "certain": certain, "devices": sorted({graph.nodes[key].hostname, node.hostname})})
    return sorted(found.values(), key=lambda r: (not r["certain"], r["firewall"], r["zone_a"], r["zone_b"], r["via"]))


def all_bypasses(graph: Graph) -> list[dict[str, Any]]:
    """The Layer 2 and the routed ways round a firewall in one table (the CSV): one row per pair of interfaces and path."""
    rows = [{"firewall": r["firewall"], "zone_a": r["zone_a"], "interface_a": r["interface_a"], "zone_b": r["zone_b"], "interface_b": r["interface_b"],
             "path": "layer 2 (same VLAN)", "vlan": r["vlan"], "through": r["through"], "certain": r["certain"], "devices": r["devices"]} for r in bypasses(graph)]
    rows += [{"firewall": r["firewall"], "zone_a": r["zone_a"], "interface_a": r["interface_a"], "zone_b": r["zone_b"], "interface_b": r["interface_b"],
              "path": "layer 3 switch (SVIs)" if r["kind"] == "svi" else "router", "vlan": r["detail"], "through": r["via"], "certain": r["certain"], "devices": r["devices"]}
             for r in routed_bypasses(graph)]
    return rows
