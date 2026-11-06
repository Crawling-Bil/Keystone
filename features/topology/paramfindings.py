"""Parameter mismatches between the two ends of a link: MTU and OSPF.

* TOPO-036  the two ends of a link have a different MTU (routed ports: also what it does to OSPF; layer-2 ports: only when both ends say it),
* TOPO-037  the OSPF hello or dead interval differs, so the two routers never become neighbors,
* TOPO-038  the OSPF network type differs (broadcast on one end, point-to-point on the other): the adjacency may come up, but the routes are wrong,
* TOPO-039  the two ends of a link put it in different OSPF areas, so the Hello packets are dropped.

Each end is read from the configuration in its own capture (``ifparams.py``), so a check needs both captures; a link with one uncaptured end is never
a finding.  A value that a capture does not state is the platform default, except where the default is not known (a device with a global jumbo setting): then the
end is left out instead of guessed.  The link is judged on the interface that holds the address: a bundle member is looked at through its port-channel.

References: IETF RFC 2328 sections 10.5 and 10.6 https://datatracker.ietf.org/doc/html/rfc2328#section-10.5 ;
Cisco, OSPF Neighbor Relationship Troubleshooting https://www.cisco.com/c/en/us/support/docs/ip/open-shortest-path-first-ospf/12151-trouble-main.html ;
Cisco, Troubleshoot OSPF Neighbors Stuck in Exstart/Exchange State https://www.cisco.com/c/en/us/support/docs/ip/open-shortest-path-first-ospf/13684-12.html
"""

from __future__ import annotations

from typing import Any

from .extract import Device
from .findings import _few, _row
from .graph import Graph, Link
from .ifparams import DEFAULT_MTU

DOC_RFC2328 = "https://datatracker.ietf.org/doc/html/rfc2328#section-10.5"
DOC_OSPF_TROUBLE = "https://www.cisco.com/c/en/us/support/docs/ip/open-shortest-path-first-ospf/12151-trouble-main.html"
DOC_OSPF_EXSTART = "https://www.cisco.com/c/en/us/support/docs/ip/open-shortest-path-first-ospf/13684-12.html"


def _record(node: Device, port: str) -> dict[str, Any]:
    """What the capture says about the interface that carries the link: the port-channel when the port is a bundle member, over the port itself."""
    ports = (node.ifparams or {}).get("ports") or {}
    own = dict(ports.get(port) or {})
    bundle = node.bundle_of.get(port)
    if bundle and ports.get(bundle):
        own.update(ports[bundle])
    return own


def _mtu(node: Device, record: dict[str, Any]) -> int | None:
    """The MTU a routed end uses for its IP packets, or None when it cannot be told (a layer-2 port that does not say, a global jumbo setting)."""
    explicit = record.get("ip_mtu") or record.get("mtu")
    if record.get("ip"):
        if explicit:
            return int(explicit)
        return None if (node.ifparams or {}).get("global_mtu") else DEFAULT_MTU
    return int(record["mtu"]) if record.get("mtu") else None          # a layer-2 port is compared only when both ends say it


def _unique_links(graph: Graph) -> list[Link]:
    seen: set[tuple[str, str, str, str]] = set()
    out: list[Link] = []
    for link in graph.links:
        a, b = graph.nodes.get(link.a), graph.nodes.get(link.b)
        if a is None or b is None or not (a.captured and b.captured) or not (a.ifparams and b.ifparams):
            continue
        key_a = a.bundle_of.get(link.a_port) or link.a_port
        key_b = b.bundle_of.get(link.b_port) or link.b_port
        key = (link.a, key_a, link.b, key_b)
        if key in seen:
            continue
        seen.add(key)
        out.append(link)
    return out


def _label(a: Device, port_a: str, b: Device, port_b: str) -> str:
    return f"{a.hostname} {a.bundle_of.get(port_a) or port_a} - {b.hostname} {b.bundle_of.get(port_b) or port_b}"


def param_findings(graph: Graph) -> list[dict[str, Any]]:
    mtu_lines: list[str] = []
    mtu_devices: set[str] = set()
    mtu_ospf = False
    timers: list[str] = []
    types: list[str] = []
    areas: list[str] = []
    ospf_devices: dict[str, set[str]] = {"timers": set(), "types": set(), "areas": set()}
    for link in _unique_links(graph):
        a, b = graph.nodes[link.a], graph.nodes[link.b]
        rec_a, rec_b = _record(a, link.a_port), _record(b, link.b_port)
        label = _label(a, link.a_port, b, link.b_port)
        mtu_a, mtu_b = _mtu(a, rec_a), _mtu(b, rec_b)
        if mtu_a and mtu_b and mtu_a != mtu_b:
            ospf_here = bool(rec_a.get("ospf") and rec_b.get("ospf"))
            mtu_ospf = mtu_ospf or (ospf_here and not (rec_a["ospf"].get("mtu_ignore") or rec_b["ospf"].get("mtu_ignore")))
            mtu_lines.append(f"{label}: {mtu_a} bytes at {a.hostname}, {mtu_b} bytes at {b.hostname}" + (" (OSPF runs on both)" if ospf_here else ""))
            mtu_devices.update((a.hostname, b.hostname))
        ospf_a, ospf_b = rec_a.get("ospf"), rec_b.get("ospf")
        if not (ospf_a and ospf_b) or ospf_a.get("assumed") or ospf_b.get("assumed"):
            continue
        if ospf_a["area"] and ospf_b["area"] and ospf_a["area"] != ospf_b["area"]:
            areas.append(f"{label}: area {ospf_a['area']} at {a.hostname}, area {ospf_b['area']} at {b.hostname}")
            ospf_devices["areas"].update((a.hostname, b.hostname))
        if (ospf_a["hello"], ospf_a["dead"]) != (ospf_b["hello"], ospf_b["dead"]):
            timers.append(f"{label}: hello {ospf_a['hello']} s / dead {ospf_a['dead']} s at {a.hostname}, hello {ospf_b['hello']} s / dead {ospf_b['dead']} s at {b.hostname}")
            ospf_devices["timers"].update((a.hostname, b.hostname))
        if ospf_a["network"] != ospf_b["network"]:
            types.append(f"{label}: {ospf_a['network']} at {a.hostname}, {ospf_b['network']} at {b.hostname}")
            ospf_devices["types"].update((a.hostname, b.hostname))
    rows: list[dict[str, Any]] = []
    if mtu_lines:
        rows.append(_row(
            "TOPO-036", "medium", f"{len(mtu_lines)} link(s) with a different MTU at the two ends", _few(mtu_lines, 4), sorted(mtu_devices),
            "A packet larger than the smaller MTU is dropped (or fragmented) at that end, and with the Don't-Fragment bit set the sender is told to send smaller ones, so large "
            "transfers stall while pings work. " + ("OSPF compares the interface MTU in its Database Description packets: the two routers stay in ExStart or Exchange and never "
                                                    "reach Full, unless the MTU is made equal (or ip ospf mtu-ignore is set on both). " if mtu_ospf else "")
            + "Set the same MTU on both ends (mtu / ip mtu on Cisco and AOS-CX, mtu on Huawei).", DOC_OSPF_EXSTART if mtu_ospf else DOC_RFC2328))
    if timers:
        rows.append(_row(
            "TOPO-037", "medium", f"{len(timers)} link(s) where the OSPF hello or dead interval differs", _few(timers, 4), sorted(ospf_devices["timers"]),
            "OSPF routers become neighbors only when the hello interval and the dead interval are equal (RFC 2328 section 10.5): a Hello with other timers is dropped, so no "
            "adjacency forms and the routes of that link are missing. Set the same timers on both interfaces (ip ospf hello-interval and ip ospf dead-interval on Cisco and AOS-CX, "
            "ospf timer hello and ospf timer dead on Huawei).", DOC_OSPF_TROUBLE))
    if types:
        rows.append(_row(
            "TOPO-038", "medium", f"{len(types)} link(s) with a different OSPF network type at the two ends", _few(types, 4), sorted(ospf_devices["types"]),
            "A broadcast end elects a designated router and advertises the link as a transit network; a point-to-point end does neither. With equal timers the adjacency can "
            "still come up, but the link is described differently by its two routers and the routes through it can be wrong or flap. Use the same network type on both ends "
            "(ip ospf network point-to-point on Cisco and AOS-CX, ospf network-type p2p on Huawei).", DOC_OSPF_TROUBLE))
    if areas:
        rows.append(_row(
            "TOPO-039", "medium", f"{len(areas)} link(s) where the two ends are in different OSPF areas", _few(areas, 4), sorted(ospf_devices["areas"]),
            "The Hello packet carries the area ID and a router drops a Hello from another area (RFC 2328 section 10.5), so the two routers do not become neighbors. Put both "
            "interfaces in the same area, or move the area border to a router that has a link in each area.", DOC_OSPF_TROUBLE))
    return rows
