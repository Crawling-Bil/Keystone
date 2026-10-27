"""Layer-3 facts of a switch capture (NX-OS, AOS-CX, IOS XE switches ...) from the Switch Analyzer's reading.

The Router Analyzer's reader (``l3facts.read``) understands IOS / IOS XE routers.  A Nexus or an Aruba CX switch prints its routing
table, OSPF neighbors, ARP table and first-hop-redundancy groups in other formats that the Switch Analyzer already parses, so the
facts come from its result instead of a second parser.  The shape is the one ``l3facts`` produces: routes grouped by next hop, routing
neighbors, ARP, plus ``fhrp`` (HSRP / VRRP groups with their virtual address, which are not owned by one device).

References: Cisco NX-OS Unicast Routing Configuration Guide
https://www.cisco.com/c/en/us/td/docs/dcn/nx-os/nexus9000/104x/unicast-routing/cisco-nexus-9000-series-nx-os-unicast-routing-configuration-guide-release-104x.html,
HSRP (RFC 2281) https://www.rfc-editor.org/rfc/rfc2281, VRRP (RFC 5798) https://www.rfc-editor.org/rfc/rfc5798,
AOS-CX IP routing guide https://arubanetworking.hpe.com/techdocs/AOS-CX/10.13/HTML/ip_routing_cx_10.13/index.html.
"""

from __future__ import annotations

from collections import OrderedDict
from typing import Any

from .names import canon_port

MAX_PREFIXES = 3000
_LOCAL = {"direct", "local", "connected", "c", "l", "hsrp", "vrrp", "vrrpv3", "glbp", "attached", "broadcast"}
_LETTERS = {"s": "static", "o": "ospf", "b": "bgp", "r": "rip", "e": "eigrp", "i": "isis", "d": "eigrp"}


def _protocol(text: str) -> str:
    low = str(text or "").strip().lower()
    for word in ("ospf", "bgp", "eigrp", "isis", "rip", "static"):
        if low.startswith(word):
            return word
    return _LETTERS.get(low[:1], low) if len(low) <= 3 else low


def _vrf(name: Any) -> str:
    text = str(name or "")
    return "global" if text.lower() in ("", "default", "global") else text


def _routes(result: dict[str, Any]) -> list[dict[str, Any]]:
    groups: OrderedDict[tuple[str, str, str, str], dict[str, Any]] = OrderedDict()
    for row in result.get("routing_table") or result.get("routes") or []:
        protocol = _protocol(row.get("protocol") or row.get("origin_name") or "")
        hop = str(row.get("next_hop") or "")
        prefix = str(row.get("destination") or row.get("prefix") or "")
        if protocol in _LOCAL or str(row.get("group", "")).lower() in ("connected", "local", "fhrp") or not hop or hop[0] not in "0123456789" or "/" not in prefix:
            continue
        key = (_vrf(row.get("vrf")), protocol, hop, canon_port(str(row.get("interface") or "")))
        entry = groups.setdefault(key, {"vrf": key[0], "protocol": protocol, "next_hop": hop, "interface": key[3], "count": 0, "prefixes": [], "default": False})
        entry["count"] += 1
        if prefix == "0.0.0.0/0":
            entry["default"] = True
        if len(entry["prefixes"]) < MAX_PREFIXES:
            entry["prefixes"].append(prefix)
    return list(groups.values())


def _neighbors(result: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for row in (result.get("ospf_live") or {}).get("neighbors") or []:
        role = str(row.get("role", ""))
        out.append({"protocol": "ospf", "address": str(row.get("address", "")), "id": str(row.get("neighbor_id", "")), "interface": canon_port(str(row.get("interface", ""))),
                    "state": f"{row.get('state', '')}/{role}" if role else str(row.get("state", "")), "vrf": _vrf(row.get("vrf")), "process": str(row.get("process", ""))})
    for row in (result.get("l3") or {}).get("bgp_neighbors") or result.get("bgp_neighbors") or []:
        out.append({"protocol": "bgp", "address": str(row.get("neighbor") or row.get("address") or ""), "id": "", "interface": "", "state": str(row.get("state", "")),
                    "vrf": _vrf(row.get("vrf")), "remote_as": str(row.get("remote_as") or row.get("asn") or "")})
    return [n for n in out if n["address"]]


def _fhrp(result: dict[str, Any]) -> list[dict[str, Any]]:
    """HSRP / VRRP groups: the virtual address is shared by the pair, so the L3 model keeps it as an address nobody owns alone."""
    groups = []
    for row in (result.get("fhrp") or {}).get("groups") or []:
        vip = str(row.get("virtual_ip", ""))
        if not vip:
            continue
        groups.append({"interface": canon_port(str(row.get("interface", ""))), "group": str(row.get("group", "")), "virtual_ip": vip, "state": str(row.get("state", "")),
                       "priority": str(row.get("priority", "")), "active": str(row.get("active", "")), "standby": str(row.get("standby", "")), "protocol": str(row.get("protocol") or row.get("type") or "hsrp"),
                       "name": str(row.get("name", ""))})
    return groups


def facts(result: dict[str, Any]) -> dict[str, Any]:
    """The L3 facts of one switch result; keys as ``l3facts.read`` returns them (``interfaces`` stay with ``Device.l3``)."""
    state = {}
    for row in (result.get("l3") or {}).get("interfaces") or []:
        status = str(row.get("status") or "")
        if status:
            state[canon_port(str(row.get("name", "")))] = "admin down" if row.get("shutdown") else ("up/up" if status == "up" else f"{status}/{status}")
    arp = [{"ip_address": str(r.get("ip_address", "")), "mac_address": str(r.get("mac_address", "")), "interface": canon_port(str(r.get("interface", ""))), "vrf": _vrf(r.get("vrf"))}
           for r in (result.get("arp_table") or []) if r.get("ip_address")]
    arp += [{"ip_address": str(r.get("ip_address", "")), "mac_address": str(r.get("mac_address", "")), "interface": canon_port(str(r.get("interface", ""))), "vrf": _vrf(r.get("vrf"))}
            for r in (result.get("arp_vrf_table") or []) if r.get("ip_address")]
    return {"hostname": str(result.get("hostname", "")), "model": "", "release": "", "interfaces": [], "routes": _routes(result), "neighbors": _neighbors(result), "overlay": [], "tunnels": [],
            "state": state, "wan_colour": {}, "system_ip": "", "site_id": "", "gateway": [], "arp": arp, "fhrp": _fhrp(result)}


def merge(base: dict[str, Any], extra: dict[str, Any]) -> dict[str, Any]:
    """``extra`` fills what ``base`` (the Router Analyzer's reading, may be empty) does not have; a list already present in ``base`` is kept."""
    if not base:
        return dict(extra)
    merged = dict(base)
    for key, value in extra.items():
        if key == "interfaces":
            continue
        if not merged.get(key) and value:
            merged[key] = value
    return merged
