"""An F5 BIG-IP configuration (UCS, ``tmsh list`` capture, ``bigip.conf``) as a topology device.

The Load Balancer Analyzer's reader (``bigip_extract``) already turns a BIG-IP configuration into VLANs, self IPs, routes, trunks and
route domains, and ``bigip_runtime`` reads the ``show`` output of a prompted capture.  This module reduces that to what the drawing needs:

* a **self IP** is a routed interface: it carries the name of the self IP, the VLAN it belongs to as description and ``vlan_id``, and the
  member port (or trunk) of that VLAN as ``parent``, which the L3 over L2 view uses to find the cable;
* a **floating self IP** (traffic group other than ``traffic-group-local-only``) is shared by the two units of a pair, like an HSRP / VRRP
  address, so it is reported as a first-hop-redundancy group (``fhrp``) and the L3 views resolve "next hop = the BIG-IP pair" the same way;
* a **route domain** is a virtual router (``%N`` after an address): its name becomes the VRF, the default domain is ``global``;
* a **trunk** is a bundle of its member interfaces (``bundles``), LACP or static;
* static routes (``net route``) are grouped by route domain and gateway like every other router's routes; the management route is left out;
* with a prompted capture (``show net interface``, ``show net arp``) the ports get their state and negotiated speed and the ARP table
  becomes ``arp_table``; without it the L3 evidence of a BIG-IP is configuration only (dashed lines).

References: F5 tmsh reference for ``net self`` https://clouddocs.f5.com/cli/tmsh-reference/latest/modules/net/net_self.html and
``net route-domain`` https://clouddocs.f5.com/cli/tmsh-reference/latest/modules/net/net_route-domain.html (the ``%N`` suffix),
``net trunk`` https://clouddocs.f5.com/cli/tmsh-reference/latest/modules/net/net_trunk.html.
"""

from __future__ import annotations

import ipaddress
import re
from collections import OrderedDict
from typing import Any

from .extract import Device
from .names import canon_port, short_host

MAX_PREFIXES = 3000
_RD = re.compile(r"%(\d+)")
_MEDIA_SPEED = re.compile(r"^(\d+)")


def _split(address: str) -> tuple[str, int | None, str]:
    """'172.17.1.3%2/24' -> ('172.17.1.3', 24, '2'); an IPv6 address is returned empty (the L3 views are IPv4)."""
    text = str(address or "").strip()
    domain = ""
    found = _RD.search(text)
    if found:
        domain = found.group(1)
        text = _RD.sub("", text, count=1)
    ip, _, plen = text.partition("/")
    try:
        parsed = ipaddress.ip_address(ip)
    except ValueError:
        return "", None, domain
    if parsed.version != 4:
        return "", None, domain
    return str(parsed), int(plen) if plen.isdigit() else (32 if "/" not in text else None), domain


def _domains(data: dict[str, Any]) -> dict[str, str]:
    return {str(d.get("id")): str(d.get("short") or f"rd{d.get('id')}") for d in data.get("route_domains") or [] if d.get("id") not in (None, "", "0")}


def _vrf(domain: str, names: dict[str, str]) -> str:
    return names.get(domain, f"rd{domain}") if domain and domain != "0" else "global"


def _speed(media: str) -> int:
    found = _MEDIA_SPEED.match(str(media or ""))
    return int(found.group(1)) if found else 0


def _vlan_ports(data: dict[str, Any]) -> dict[str, list[str]]:
    """VLAN short name -> its member ports / trunks (without the tagged / untagged note)."""
    out: dict[str, list[str]] = {}
    for vlan in data.get("vlans") or []:
        out[str(vlan["short"])] = [re.sub(r"\s*\(.*\)$", "", str(i)) for i in vlan.get("interfaces") or []]
    return out


def _port_up(port: str, bundles: dict[str, list[str]], state: dict[str, str]) -> bool:
    """A VLAN member is a port, or a trunk that is up when any of its member ports is."""
    return any(state.get(m) == "up/up" for m in bundles[port]) if port in bundles else state.get(port) == "up/up"


def _routes(data: dict[str, Any], names: dict[str, str]) -> list[dict[str, Any]]:
    groups: OrderedDict[tuple[str, str], dict[str, Any]] = OrderedDict()
    for row in data.get("routes") or []:
        hop, _, domain = _split(row.get("gateway", ""))
        prefix = str(row.get("network", ""))
        if not hop or "/" not in prefix:
            continue
        prefix = _RD.sub("", prefix)
        key = (_vrf(domain, names), hop)
        entry = groups.setdefault(key, {"vrf": key[0], "protocol": "static", "next_hop": hop, "interface": "", "count": 0, "prefixes": [], "default": False})
        entry["count"] += 1
        if prefix == "0.0.0.0/0":
            entry["default"] = True
        if len(entry["prefixes"]) < MAX_PREFIXES:
            entry["prefixes"].append(prefix)
    return list(groups.values())


_MAP_FACTS = ("Destination", "Protocol", "Address", "Port", "Pool", "Node", "Used by", "Reached", "Load-balancing method", "Members", "Default pool", "Type", "Description")


def _map_nodes(data: dict[str, Any], runtime: dict[str, Any]) -> list[dict[str, Any]]:
    """The Load Balancer Analyzer's Network Map (virtual server -> pool -> pool member, wide IP -> GTM pool -> member) reduced to what the F5 map page draws.
    Monitors are left out (they are leaves of every member and would bury the picture); the full tree stays in the Load Balancer Analyzer."""
    from ..lb_analyzer import bigip_map
    found = bigip_map.sections(data, runtime)
    if not found:
        return []
    out = []
    for node in found[0].get("nodes") or []:
        if node.get("type") in ("monitor", "gtmmonitor"):
            continue
        facts = {str(d["label"]): (", ".join(map(str, d["value"])) if isinstance(d["value"], (list, tuple)) else str(d["value"])) for d in node.get("detail") or [] if d.get("label") in _MAP_FACTS}
        out.append({"id": node["id"], "parent": node.get("parent", ""), "type": node.get("type", ""), "name": node.get("name", ""), "status": node.get("status", ""), "badge": node.get("badge", ""),
                    "source": node.get("source", ""), "reason": node.get("reason", ""), "facts": facts})
    return out


def _vlan_rows(data: dict[str, Any], result: Device, names: dict[str, str]) -> list[dict[str, Any]]:
    """One row per VLAN: tag, member ports (with tagged / untagged), the self IPs on it, floating ones apart, and the route domain."""
    selfs: dict[str, list[dict[str, Any]]] = {}
    for row in data.get("selfs") or []:
        selfs.setdefault(str(row.get("vlan") or "").rsplit("/", 1)[-1], []).append(row)
    rows = []
    for vlan in data.get("vlans") or []:
        short = str(vlan["short"])
        mine = selfs.get(short, [])
        fixed = [f"{r.get('address', '')}" for r in mine if not r.get("floating")]
        floating = [f"{r.get('address', '')}" for r in mine if r.get("floating")]
        domains = sorted({_vrf(_split(r.get("address", ""))[2], names) for r in mine})
        members = [str(i) for i in vlan.get("interfaces") or []]
        rows.append({"vlan": short, "tag": vlan.get("tag") or "", "interfaces": members, "self_ips": fixed, "floating_ips": floating, "route_domain": ", ".join(domains), "description": str(vlan.get("description") or "")})
    return rows


def device(data: dict[str, Any], runtime: dict[str, Any], source: str) -> Device:
    """The topology device of one extracted BIG-IP configuration (``bigip_extract.extract`` output) and its optional ``show`` output."""
    info = data.get("info") or {}
    fqdn = str(info.get("hostname") or runtime.get("hostname") or "") or source.rsplit(".", 1)[0]
    version = str(info.get("version") or (runtime.get("version") or {}).get("version") or "")
    result = Device(key="", hostname=short_host(fqdn) or fqdn, fqdn=fqdn, source=source, vendor="F5", model=str(info.get("platform") or info.get("platform_id") or "BIG-IP"),
                    os_version=f"TMOS {version}".strip(), role_hint="loadbalancer")
    names = _domains(data)
    ports = _vlan_ports(data)
    tags = {str(v["short"]): v.get("tag") for v in data.get("vlans") or []}
    live = {str(r["name"]): r for r in runtime.get("interfaces") or []}
    state_of_port = {name: ("up/up" if str(r["status"]).lower() == "up" else ("admin down" if str(r["status"]).lower() == "disabled" else "down/down")) for name, r in live.items() if name != "mgmt"}

    for trunk in data.get("trunks") or []:
        members = [str(m) for m in trunk.get("interfaces") or []]
        if members:
            result.bundles[trunk["short"]] = members
            result.bundle_info[trunk["short"]] = {"protocol": "LACP" if trunk.get("lacp") == "enabled" else "static", "status": "up", "description": ""}
            for member in members:
                result.bundle_of[member] = trunk["short"]
    for name, row in live.items():
        port = canon_port(name)
        if name == "mgmt":
            continue
        result.port_state[port] = "up" if str(row["status"]).lower() == "up" else "down"
        speed = _speed(row.get("media", ""))
        if speed and str(row["status"]).lower() == "up":
            result.speeds[port] = speed
            result.actual_speeds[port] = speed
            result.duplex[port] = "full" if str(row.get("media", "")).upper().endswith("FD") else "half"

    l3: list[dict[str, Any]] = []
    fhrp: list[dict[str, Any]] = []
    state: dict[str, str] = {}
    failover = str((runtime.get("failover") or {}).get("status") or "").lower()
    for row in data.get("selfs") or []:
        ip, plen, domain = _split(row.get("address", ""))
        if not ip or plen is None:
            continue
        vlan = str(row.get("vlan") or "")
        vlan_short = vlan.rsplit("/", 1)[-1]
        member = (ports.get(vlan_short) or [""])[0]
        group = str(row.get("traffic_group") or "").rsplit("/", 1)[-1]
        if row.get("floating"):
            fhrp.append({"interface": vlan_short, "group": group, "virtual_ip": ip, "state": failover or "", "priority": "", "active": "", "standby": "", "protocol": "f5 traffic group", "name": row.get("short", "")})
            continue
        up = any(_port_up(p, result.bundles, state_of_port) for p in ports.get(vlan_short, []))
        status = "up" if up else ""
        l3.append({"name": str(row.get("short") or ip), "ip": ip, "prefix_len": plen, "vrf": _vrf(domain, names), "kind": "Sub-interface" if tags.get(vlan_short) else "Routed", "shutdown": False,
                   "description": f"VLAN {vlan_short}" + (f" ({tags[vlan_short]})" if tags.get(vlan_short) else ""), "status": status, "secondary": [], "parent": member, "vlan_id": tags.get(vlan_short) or None,
                   "role": ""})
        if up:
            state[str(row.get("short") or ip)] = "up/up"
        result.ips.add(ip)
    result.l3 = l3
    managed = next((str(d.get("management_ip") or "") for d in data.get("devices") or [] if d.get("self")), "") or ""
    result.mgmt_ip = managed or (l3[0]["ip"] if l3 else "")
    if managed:
        result.ips.add(managed)
    arp = [{"ip_address": r["address"], "mac_address": r["mac"], "interface": r["vlan"], "vrf": "global"} for r in runtime.get("arp") or [] if r["mac"] != "incomplete"]
    result.arp_table = [dict(r) for r in arp]
    routes = _routes(data, names)
    result.l3facts = {"hostname": fqdn, "model": result.model, "release": result.os_version, "interfaces": [], "routes": routes, "neighbors": [], "overlay": [], "tunnels": [], "state": state,
                      "wan_colour": {}, "system_ip": "", "site_id": "", "gateway": [], "arp": arp, "fhrp": fhrp, "ha": failover}
    result.coverage = {"routes": bool(routes), "neighbors": False, "overlay": False, "arp": bool(arp)}
    try:
        tree = _map_nodes(data, runtime)
    except Exception:                    # the map is an addition: a configuration it cannot read still has its routed interfaces
        tree = []
    result.l3facts["f5"] = {"map": tree, "vlans": _vlan_rows(data, result, names),
                            "interfaces": [{"name": n, "status": str(r.get("status", "")), "media": str(r.get("media", "")), "trunk": str(r.get("trunk", ""))} for n, r in live.items() if n != "mgmt"],
                            "trunks": {k: list(v) for k, v in result.bundles.items()}, "failover": failover, "gtm": bool(data.get("gtm"))}
    return result


def _ports_of(vlan: dict[str, Any], trunks: dict[str, list[str]]) -> tuple[set[str], set[str]]:
    """(canonical port names, trunk names) a VLAN of the host reaches the outside through."""
    ports: set[str] = set()
    used: set[str] = set()
    for member in vlan.get("interfaces") or []:
        name = re.sub(r"\s*\(.*\)$", "", str(member)).strip()
        if name in trunks:
            used.add(name)
            ports.update(canon_port(m) for m in trunks[name])
            ports.add(name)
        elif name:
            ports.add(canon_port(name))
    return ports, used


def guests(data: dict[str, Any], source: str) -> list[Device]:
    """A vCMP **host** configuration as one load-balancer node per guest.

    A guest is a complete BIG-IP of its own (its own TMOS, self IPs, virtual servers); the host owns the physical ports and hands VLANs to the guests
    (https://techdocs.f5.com/kb/en-us/products/big-ip_ltm/manuals/product/vcmp-administration-viprion-13-1-0/6.html).  The host configuration therefore knows
    each guest's name, management address and VLANs but not its self IPs: the node carries the VLANs and ports the guest uses, so a neighbor's cable lands
    on the guest whose VLANs ride the remote port (``Device.unit_ports``), and the guest's own UCS - when uploaded as well - replaces this node."""
    info = data.get("info") or {}
    host_fqdn = str(info.get("hostname") or "") or source.rsplit(".", 1)[0]
    chassis = short_host(host_fqdn) or host_fqdn
    trunks = {str(t["short"]): [str(m) for m in t.get("interfaces") or []] for t in data.get("trunks") or []}
    vlans = {str(v["short"]): v for v in data.get("vlans") or []}
    out: list[Device] = []
    for guest in data.get("vcmp_guests") or []:
        fqdn = str(guest.get("hostname") or guest["short"])
        mine = [vlans[v.rsplit("/", 1)[-1]] for v in guest.get("vlans") or [] if v.rsplit("/", 1)[-1] in vlans]
        node = Device(key="", hostname=short_host(fqdn) or fqdn, fqdn=fqdn, source=source, vendor="F5", model=f"vCMP guest · {guest['cores_per_slot']} core(s)/slot" if guest.get("cores_per_slot") else "vCMP guest",
                      role_hint="loadbalancer", chassis=chassis, unit=str(guest["short"]))
        used_trunks: set[str] = set()
        for vlan in mine:
            ports, used = _ports_of(vlan, trunks)
            node.unit_ports |= ports
            used_trunks |= used
        for trunk in sorted(used_trunks):
            node.bundles[trunk] = list(trunks[trunk])
            node.bundle_info[trunk] = {"protocol": "LACP", "status": "up", "description": ""}
            for member in trunks[trunk]:
                node.bundle_of[member] = trunk
        ip = str(guest.get("management_ip") or "").split("/")[0]
        node.mgmt_ip = ip
        if ip:
            node.ips.add(ip)
        rows = [{"vlan": v["short"], "tag": v.get("tag") or "", "interfaces": [str(i) for i in v.get("interfaces") or []], "self_ips": [], "floating_ips": [], "route_domain": "", "description": str(v.get("description") or "")} for v in mine]
        node.l3facts = {"hostname": fqdn, "model": node.model, "release": "", "interfaces": [], "routes": [], "neighbors": [], "overlay": [], "tunnels": [], "state": {}, "wan_colour": {}, "system_ip": "",
                        "site_id": "", "gateway": [], "arp": [], "fhrp": [], "ha": "",
                        "f5": {"map": [], "vlans": rows, "interfaces": [], "trunks": {k: list(v) for k, v in node.bundles.items()}, "failover": "", "gtm": False,
                               "vcmp": {"host": host_fqdn, "guest": str(guest["short"]), "state": str(guest.get("state") or ""), "cores_per_slot": str(guest.get("cores_per_slot") or ""),
                                        "slots": str(guest.get("slots") or ""), "management_ip": str(guest.get("management_ip") or ""), "image": str(guest.get("initial_image") or "")}}}
        node.coverage = {"routes": False, "neighbors": False, "overlay": False, "arp": False}
        out.append(node)
    return out


def read_units(text: str, source: str) -> list[Device]:
    """One device per vCMP guest of a vCMP host configuration, else the one device of ``read``."""
    from ..lb_analyzer import bigip_extract, bigip_runtime
    from ..lb_analyzer.tmsh_tree import parse_tmsh
    live = getattr(text, "live", "")
    runtime = bigip_runtime.gather(live or text)
    config = (str(text) if live else runtime["config_text"]) or str(text)
    data = bigip_extract.extract(parse_tmsh(config))
    if data.get("vcmp_guests"):
        return guests(data, source)
    return [device(data, runtime, source)]


def read(text: str, source: str) -> Device:
    """A BIG-IP configuration text, a UCS archive (``UcsText``), or a UCS merged with the capture of the same unit."""
    return read_units(text, source)[0]
