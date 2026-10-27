"""A FortiGate configuration as a topology device.

The Firewall Analyzer's reader (``forti_extract``) already turns a ``show full-configuration`` / backup file into interfaces, static
routes, BGP / OSPF settings and IPsec phase-1 interfaces.  This module reduces that to what the drawing needs:

* a **VDOM is a virtual router**: every routed interface carries its VDOM name in ``vrf``, so the L3 views colour the VDOMs like VRFs
  and a static route is attributed to the VDOM that holds it (FortiOS VDOM guide
  https://docs.fortinet.com/document/fortigate/7.4.7/administration-guide/597835/virtual-domains);
* a **redundant** or **aggregate** interface is a bundle of its member ports (``bundles`` / ``bundle_of``), so the L2 views draw it as one
  line with the port names at the ends (https://docs.fortinet.com/document/fortigate/7.4.7/administration-guide/822100/interface-settings);
* a VLAN sub-interface has a ``parent`` (the bundle or port that carries it), which the L3 over L2 view uses to find the cable;
* the **alias** of a port (``to HQEDGNX1 - Eth1/39``) is kept as the port description, which the neighbor inference reads, because a
  configuration file has no CDP / LLDP table;
* static routes are grouped by VDOM and next hop like every other router's routes.

A FortiGate is a firewall: the device gets ``role_hint = "firewall"``.  Live state (routing table, OSPF neighbors, ARP) is not in a
configuration backup, so the L3 evidence of a FortiGate is configuration only (dashed lines) unless a capture of ``get router info`` is added later.
"""

from __future__ import annotations

import ipaddress
import re
from collections import OrderedDict
from typing import Any

from .extract import Device, HalfEdge
from .names import canon_port, short_host

MAX_PREFIXES = 3000
_SPEED = re.compile(r"^(\d+)(?:auto|full|half)?$", re.I)


def _speed(text: str) -> int:
    found = _SPEED.match(str(text or ""))
    return int(found.group(1)) if found and found.group(1) != "0" else 0


def _address(text: str) -> tuple[str, int | None]:
    """'172.17.60.190/26' or '172.17.60.190 255.255.255.192' -> (ip, prefix length)."""
    parts = str(text or "").replace("/", " ").split()
    if len(parts) < 2:
        return "", None
    try:
        ip = ipaddress.ip_address(parts[0])
        if "." in parts[1]:
            return str(ip), ipaddress.ip_network(f"0.0.0.0/{parts[1]}").prefixlen
        return str(ip), int(parts[1])
    except ValueError:
        return "", None


def _kind(row: dict[str, Any]) -> str:
    kind = str(row.get("type", "")).lower()
    if kind == "loopback":
        return "Loopback"
    if kind == "tunnel":
        return "Tunnel"
    return "Sub-interface" if row.get("parent") and row.get("vlanid") else "Routed"


def _transparent(data: dict[str, Any]) -> set[str]:
    """VDOMs in transparent mode: they bridge, they do not route, and their static routes only serve the FortiGate's own management traffic."""
    return {str(v.get("name", "")) for v in data.get("vdoms") or [] if str(v.get("mode", "")).lower() == "transparent"}


def _routes(data: dict[str, Any], vdom: str | None = None) -> list[dict[str, Any]]:
    groups: OrderedDict[tuple[str, str, str], dict[str, Any]] = OrderedDict()
    quiet = _transparent(data)
    for row in data.get("routes") or []:
        if str(row.get("vdom") or "root") in quiet or (vdom is not None and str(row.get("vdom") or "root") != vdom):
            continue
        hop, prefix = str(row.get("gateway", "")), str(row.get("dst", ""))
        if row.get("blackhole") or str(row.get("status", "enable")) == "disable" or not hop or not hop[0].isdigit() or "/" not in prefix:
            continue
        key = (str(row.get("vdom") or "root"), hop, str(row.get("device", "")))
        entry = groups.setdefault(key, {"vrf": key[0], "protocol": "static", "next_hop": hop, "interface": key[2], "count": 0, "prefixes": [], "default": False})
        entry["count"] += 1
        if prefix == "0.0.0.0/0":
            entry["default"] = True
        if len(entry["prefixes"]) < MAX_PREFIXES:
            entry["prefixes"].append(prefix)
    return list(groups.values())


def _neighbors(data: dict[str, Any], vdom: str | None = None) -> list[dict[str, Any]]:
    out = []
    for process in data.get("bgp") or []:
        if vdom is not None and str(process.get("vdom") or "root") != vdom:
            continue
        for neighbor in process.get("neighbors") or []:
            address = str(neighbor.get("ip") or neighbor.get("address") or "")
            if address:
                out.append({"protocol": "bgp", "address": address, "id": "", "interface": "", "state": "configured", "vrf": str(process.get("vdom") or "root"),
                            "remote_as": str(neighbor.get("remote_as") or neighbor.get("remote-as") or "")})
    return out


def _tunnels(data: dict[str, Any], vdom: str | None = None) -> list[dict[str, Any]]:
    out = []
    for phase in data.get("ipsec_p1") or []:
        if vdom is not None and str(phase.get("vdom") or "root") != vdom:
            continue
        destination = str(phase.get("remote_gw") or phase.get("remote-gw") or "")
        if destination and destination[0].isdigit():
            out.append({"name": str(phase.get("name", "")), "source": str(phase.get("interface", "")), "destination": destination, "mode": "ipsec",
                        "vrf": str(phase.get("vdom") or "root"), "description": str(phase.get("comments", "")), "ip": ""})
    return out


def device(data: dict[str, Any], source: str, vdom: str | None = None) -> Device:
    """The topology device of one extracted FortiGate configuration (``forti_extract.extract`` output).

    With ``vdom`` the device is that one virtual domain of the chassis: its own interfaces, routes, BGP neighbors and tunnels only, named
    ``HOST [vdom]``; ``chassis`` and ``unit_ports`` let the graph send a neighbor's cable to the VDOM that owns the port (see ``units``).
    """
    glob = data.get("global") or {}
    header = data.get("header") or {}
    fqdn = str(glob.get("hostname") or "") or source.rsplit(".", 1)[0]
    rows = [r for r in data.get("interfaces") or [] if vdom is None or str(r.get("vdom") or "root") == vdom]
    base = short_host(fqdn) or fqdn
    device = Device(key="", hostname=base if vdom is None else f"{base} [{vdom}]", fqdn=fqdn, chassis="" if vdom is None else base, unit="" if vdom is None else vdom, source=source, vendor="Fortinet", model=str(glob.get("alias") or header.get("model") or "FortiGate"),
                    os_version=f"FortiOS {header.get('version', '')}".strip(), role_hint="firewall")
    l3: list[dict[str, Any]] = []
    state: dict[str, str] = {}
    for row in rows:
        name = str(row.get("name", ""))
        alias = str(row.get("alias") or row.get("description") or "")
        status = "up/up" if str(row.get("status", "up")) == "up" else "admin down"
        state[name] = status
        device.unit_ports.add(canon_port(name) if str(row.get("type")) == "physical" else name)
        device.unit_ports.update(canon_port(str(m)) for m in row.get("members") or [])
        members = [canon_port(str(m)) for m in row.get("members") or []]
        if str(row.get("type")) in ("redundant", "aggregate") and members:
            device.bundles[name] = members
            device.bundle_info[name] = {"protocol": "LACP" if row.get("type") == "aggregate" else "redundant", "status": "up" if status == "up/up" else "down", "description": alias}
            for member in members:
                device.bundle_of[member] = name
        if str(row.get("type")) in ("physical",) and not row.get("parent") and not _address(row.get("ip", ""))[0]:
            port = canon_port(name)
            device.port_state[port] = "up" if status == "up/up" else "down"
            device.speeds.update({port: _speed(row.get("speed", ""))} if _speed(row.get("speed", "")) else {})
        if alias:
            device.descriptions[canon_port(name) if str(row.get("type")) == "physical" else name] = alias
        ip, plen = _address(row.get("ip", ""))
        if ip and plen is not None and plen > 0:
            l3.append({"name": name, "ip": ip, "prefix_len": plen, "vrf": str(row.get("vdom") or "root"), "kind": _kind(row), "shutdown": status == "admin down",
                       "description": alias, "status": "up" if status == "up/up" else "admin down", "secondary": [], "parent": str(row.get("parent", "")), "vlan_id": row.get("vlanid") or None,
                       "role": str(row.get("role", ""))})
            device.ips.add(ip)
    device.l3 = l3
    device.mgmt_ip = next((r["ip"] for r in l3 if r["name"].lower().startswith("mgmt")), "") or (l3[0]["ip"] if l3 else "")
    vdoms = [str(v.get("name", "")) for v in data.get("vdoms") or []]
    device.l3facts = {"hostname": device.hostname, "model": device.model, "release": device.os_version, "interfaces": [], "routes": _routes(data, vdom), "neighbors": _neighbors(data, vdom), "overlay": [],
                      "tunnels": _tunnels(data, vdom), "state": state, "wan_colour": {}, "system_ip": "", "site_id": "", "gateway": [], "arp": [], "fhrp": [],
                      "vdoms": vdoms if vdom is None else [vdom], "transparent": sorted(_transparent(data)) if vdom is None else sorted(_transparent(data) & {vdom}),
                      "ha": str((data.get("ha") or {}).get("mode", ""))}
    device.coverage = {"routes": bool(device.l3facts["routes"]), "neighbors": False, "overlay": False}
    return device


# Ports that exist on every FortiGate VDOM-wise but carry no data traffic of their own: management, HA heartbeat, modem, the NPU inter-VDOM link
# ends and the per-VDOM SSL-VPN / NAF / L2TP tunnel interfaces.  A VDOM with nothing else is the management VDOM and is not drawn as a node.
_INFRA = re.compile(r"^(?:ha\d*|mgmt\d*|modem\d*|npu\d+_vlink\d+|(?:ssl|naf|l2t)\.[^ ]+|fortilink|fortilink\d*)$", re.I)
_VLINK = re.compile(r"^(npu\d+_vlink)([01])$", re.I)


def _vdom_names(data: dict[str, Any]) -> list[str]:
    names = [str(v.get("name", "")) for v in data.get("vdoms") or [] if v.get("name")]
    for row in data.get("interfaces") or []:
        name = str(row.get("vdom") or "root")
        if name not in names:
            names.append(name)
    return names


def units(data: dict[str, Any], source: str) -> list[Device]:
    """A multi-VDOM FortiGate as one firewall device **per VDOM**.

    Each VDOM is its own routing and policy domain with its own interfaces and cables (FortiOS VDOM guide
    https://docs.fortinet.com/document/fortigate/7.4.7/administration-guide/597835/virtual-domains), so the diagram shows each as a node named
    ``HOST [vdom]``.  The management VDOM that owns only mgmt / HA / tunnel interfaces is not drawn as a node (its addresses stay with the first
    node, so a management address still names the chassis).  A VDOM-less or single-working-VDOM configuration stays one device, as before.
    An NPU inter-VDOM link whose two ends sit in different VDOMs is a cable between the two nodes."""
    names = _vdom_names(data)
    rows = data.get("interfaces") or []
    working = [v for v in names if any(str(r.get("vdom") or "root") == v and not _INFRA.match(str(r.get("name", ""))) for r in rows)]
    if not data.get("multi_vdom") and len(names) < 2 or len(working) < 2:
        return [device(data, source)]
    found = [device(data, source, v) for v in working]
    for gone in (v for v in names if v not in working):
        for row in rows:
            ip, _ = _address(row.get("ip", ""))
            if ip and str(row.get("vdom") or "root") == gone:
                found[0].ips.add(ip)
                found[0].mgmt_ip = found[0].mgmt_ip or ip
    ends: dict[str, dict[str, str]] = {}
    for row in rows:
        match = _VLINK.match(str(row.get("name", "")))
        if match:
            ends.setdefault(match.group(1).lower(), {})[match.group(2)] = str(row.get("vdom") or "root")
    by_unit = {d.unit: d for d in found}
    for stem, pair in sorted(ends.items()):
        a, b = by_unit.get(pair.get("0", "")), by_unit.get(pair.get("1", ""))
        if a is not None and b is not None and a is not b:
            end0, end1 = canon_port(f"{stem}0"), canon_port(f"{stem}1")
            # the remote name is the chassis: the graph picks the node that owns the remote port, as it does for a switch's LLDP neighbor
            a.halves.append(HalfEdge(local_port=end0, remote_name=a.chassis, remote_port=end1, protocols={"VDOM-LINK"}))
            b.halves.append(HalfEdge(local_port=end1, remote_name=b.chassis, remote_port=end0, protocols={"VDOM-LINK"}))
            a.unit_ports.add(end0)
            b.unit_ports.add(end1)
    return found


def read(text: str, source: str) -> Device:
    from ..firewall_analyzer import forti_extract
    from ..firewall_analyzer.forti_tree import parse_forti
    return device(forti_extract.extract(parse_forti(text)), source)


def read_units(text: str, source: str) -> list[Device]:
    from ..firewall_analyzer import forti_extract
    from ..firewall_analyzer.forti_tree import parse_forti
    return units(forti_extract.extract(parse_forti(text)), source)
