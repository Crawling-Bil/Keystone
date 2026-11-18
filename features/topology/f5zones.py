"""The F5 L4-L7 table tied to the network: virtual server -> pool member -> BIG-IP VLAN -> cable -> neighbor -> zone of the drawing.

The F5 map page draws what a BIG-IP serves (virtual servers, pools, members).  This module answers the questions an engineer asks next, from the same capture and the cabling already
read: on which VLAN does the BIG-IP reach each member and each virtual address (the self IP whose subnet holds the address), what is cabled to the ports of that VLAN, and in which zone of
the drawing does that device stand.  The shape of the deployment follows from two columns:

* the virtual address and the member on the **same** VLAN is a one-armed deployment: return traffic must come back through the BIG-IP (source NAT, or the BIG-IP as the member's gateway)
  or the client is answered directly and the connection breaks;
* on **different** VLANs the BIG-IP routes between them (two-armed, inline);
* a member in **no** self IP subnet is reached by a route of the BIG-IP: the table says "routed".

The table also answers whether the answer finds its way back.  A one-armed virtual server without source address translation (SNAT) sends the client's address to the member, which answers
a client on its own VLAN directly, past the BIG-IP: the connection fails.  With SNAT (automap or a SNAT pool) the member answers the BIG-IP.  A two-armed (in-line) virtual server works without
SNAT only when the member's default gateway is the BIG-IP, which the capture of the member would show and the BIG-IP's does not: the table says so instead of guessing.

BIG-IP SNATs: https://techdocs.f5.com/kb/en-us/products/big-ip_ltm/manuals/product/ltm-concepts-11-5-1/17.html
BIG-IP: virtual servers, pools and self IPs: https://techdocs.f5.com/kb/en-us/products/big-ip_ltm/manuals/product/big-ip-local-traffic-management-basics-14-0-0/01.html
"""

from __future__ import annotations

import ipaddress
from typing import Any

from .fwzones import _cables
from .graph import Graph


def _network(text: str):
    try:
        return ipaddress.ip_interface(str(text).split("%")[0]).network
    except ValueError:
        return None


def _address(text: str):
    try:
        return ipaddress.ip_address(str(text).split("%")[0].strip("[]"))
    except ValueError:
        return None


def _vlan_of(address: str, vlans: list[dict[str, Any]]) -> dict[str, Any] | None:
    """The VLAN of the BIG-IP with a self IP whose subnet holds ``address`` (the longest prefix wins)."""
    ip = _address(address)
    best, best_len = None, -1
    for row in vlans:
        for text in list(row.get("self_ips") or []) + list(row.get("floating_ips") or []):
            net = _network(text)
            if ip is not None and net is not None and ip.version == net.version and ip in net and net.prefixlen > best_len:
                best, best_len = row, net.prefixlen
    return best


def _carriers(row: dict[str, Any]) -> list[str]:
    return [str(i).split(" (")[0] for i in row.get("interfaces") or []]


def _neighbors(graph: Graph, key: str, row: dict[str, Any]) -> list[str]:
    found: list[str] = []
    for carrier in _carriers(row):
        for _conn, far, _port in _cables(graph, key, carrier):
            if far not in found:
                found.append(far)
    return found


def _return_path(shape: str, snat: str) -> tuple[str, bool]:
    """(what to say about the way back, True when the connection will fail unless something outside the capture fixes it)."""
    translated = snat not in ("", "none")
    if shape.startswith("one-armed"):
        return (f"source NAT ({snat}): the member answers the BIG-IP", False) if translated else ("no source NAT on the client's VLAN: the member answers the client directly, past the BIG-IP", True)
    if shape.startswith("two-armed"):
        return (f"source NAT ({snat})", False) if translated else ("in-line: the member's default gateway must be the BIG-IP", False)
    if shape.startswith("routed"):
        return (f"source NAT ({snat})", False) if translated else ("routed: the member needs a route back to the client through the BIG-IP", False)
    return "", False


def rows(graph: Graph, pages: list | None = None) -> list[dict[str, Any]]:
    """One row per virtual server x pool member of every captured BIG-IP (a virtual server without a pool or member gets one row with the member columns empty)."""
    drawn: dict[str, str] = {}
    for page in (pages or [])[::-1]:
        for key, placed in page.nodes.items():
            if getattr(placed, "zone", ""):
                drawn[key] = placed.zone
    out: list[dict[str, Any]] = []
    for key, node in graph.nodes.items():
        facts = (node.l3facts or {}).get("f5") if node.captured else None
        if not facts or not facts.get("map"):
            continue
        vlans = facts.get("vlans") or []
        tree = facts["map"]
        children: dict[str, list[dict[str, Any]]] = {}
        for item in tree:
            children.setdefault(item["parent"], []).append(item)
        for virtual in (n for n in tree if n["type"] == "virtual" and not n["parent"]):
            destination = str((virtual.get("facts") or {}).get("Destination", virtual.get("badge", "")))
            vip = destination.rsplit(":", 1)[0] if ":" in destination and destination.count(":") == 1 else destination
            vip_vlan = _vlan_of(vip, vlans)
            vip_via = _neighbors(graph, key, vip_vlan) if vip_vlan else []
            members = [(pool, member) for pool in children.get(virtual["id"], []) if pool["type"] == "pool" for member in children.get(pool["id"], []) if member["type"] == "member"] or [(None, None)]
            for pool, member in members:
                address = str((member or {}).get("facts", {}).get("Address", "")) if member else ""
                m_vlan = _vlan_of(address, vlans) if address else None
                via = _neighbors(graph, key, m_vlan) if m_vlan else []
                if not member:
                    shape = ""
                elif m_vlan is None:
                    shape = "routed (no self IP in the member's subnet)"
                elif vip_vlan is not None and m_vlan["vlan"] == vip_vlan["vlan"]:
                    shape = "one-armed (virtual address and member on the same VLAN)"
                else:
                    shape = "two-armed (the BIG-IP routes between the VLANs)"
                snat = str((virtual.get("facts") or {}).get("SNAT", "")).strip()
                way_back, at_risk = _return_path(shape, snat)
                out.append({"bigip": node.hostname, "virtual_server": virtual["name"], "destination": destination, "virtual_vlan": vip_vlan["vlan"] if vip_vlan else "",
                            "virtual_neighbors": ", ".join(graph.nodes[k].hostname for k in vip_via), "virtual_zone": ", ".join(sorted({drawn[k] for k in vip_via if k in drawn})),
                            "pool": pool["name"] if pool else "", "member": member["name"] if member else "", "member_vlan": m_vlan["vlan"] if m_vlan else "",
                            "member_neighbors": ", ".join(graph.nodes[k].hostname for k in via), "member_zone": ", ".join(sorted({drawn[k] for k in via if k in drawn})),
                            "deployment": shape, "snat": snat, "return_path": way_back, "return_path_at_risk": at_risk, "member_status": member["status"] if member else ""})
    return sorted(out, key=lambda r: (r["bigip"], r["virtual_server"], r["pool"], r["member"]))
