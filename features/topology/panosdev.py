"""A Palo Alto Networks PAN-OS configuration as topology devices - one firewall node per virtual system.

The Configuration Studio parsers (XML export, ``show config running`` curly text, ``set`` commands) already turn a PAN-OS file into interfaces,
virtual routers, static routes, zones and IPsec tunnels, each interface and router stamped with the virtual system that imports it.  This module
reduces that to what the drawing needs:

* a **virtual system (vsys) is its own firewall**: it has its own zones, rulebase and imported interfaces
  (https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-admin/virtual-systems/virtual-systems-overview), so a multi-vsys box is drawn as one node
  per vsys, named ``HOST [vsys2]``, and a neighbor's cable lands on the node that imports the port (see ``Device.unit_ports`` and ``graph.pick_unit``);
* the **virtual router** an interface belongs to is its VRF, so the L3 views colour virtual routers like VRFs; a VLAN sub-interface (``ethernet1/3.100``)
  has the physical port as ``parent`` (the cable the L3 over L2 view looks for) and the zone as ``role``;
* a configuration has no LLDP neighbor table, so the cables are drawn from the other end's CDP / LLDP and from interface comments written
  'HOST - port', exactly as for a FortiGate;
* a single-vsys (or vsys-less) configuration stays one device named after the host.

* an **aggregate-ethernet** group (``ae1``) is a bundle of its member ports (``aggregate-group ae1`` on each port): the L2 views draw it as one
  line (``bundles`` / ``bundle_of``, LACP when ``lacp enable yes``), the group's own address and sub-interfaces (``ae1.100``) stay on the group, and in a
  multi-vsys box the members follow the vsys that imports the group
  (https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-networking-admin/configure-interfaces/configure-an-aggregate-interface-group).
"""

from __future__ import annotations

import ipaddress
import re
import tempfile
from collections import OrderedDict
from pathlib import Path
from typing import Any

from .extract import Device
from .names import canon_port, short_host

MAX_PREFIXES = 3000
_KIND = {"loopback": "Loopback", "tunnel": "Tunnel", "vlan": "SVI", "subinterface": "Sub-interface", "aggregate": "Routed"}


def _address(text: str) -> tuple[str, int | None]:
    try:
        found = ipaddress.ip_interface(str(text or "").strip())
    except ValueError:
        return "", None
    return str(found.ip), found.network.prefixlen


def _owned(iface: Any) -> str:
    return str(getattr(iface, "vsys", "") or "")


def _owner(iface: Any, groups: dict[str, str]) -> str:
    """The vsys of an interface; a member port of an aggregate group belongs to the vsys of the group."""
    return _owned(iface) or groups.get(str(getattr(iface, "aggregate_group", "") or ""), "")


def _vr_of(config: Any) -> dict[str, str]:
    """Interface name -> virtual router name (a sub-interface follows its parent port)."""
    out: dict[str, str] = {}
    for router in getattr(config, "virtual_routers", []):
        for name in router.interfaces:
            out.setdefault(name, router.name)
    for iface in getattr(config, "interfaces", []):
        if iface.name not in out and iface.parent_interface in out:
            out[iface.name] = out[iface.parent_interface]
    return out


def _routes(config: Any, routers: set[str]) -> list[dict[str, Any]]:
    groups: OrderedDict[tuple[str, str, str], dict[str, Any]] = OrderedDict()
    for router in getattr(config, "virtual_routers", []):
        if router.name not in routers:
            continue
        for route in router.static_routes:
            hop, prefix = str(route.nexthop or ""), str(route.destination or "")
            if not hop or not hop[0].isdigit() or "/" not in prefix:
                continue
            key = (router.name, hop, str(route.interface or ""))
            entry = groups.setdefault(key, {"vrf": key[0], "protocol": "static", "next_hop": hop, "interface": key[2], "count": 0, "prefixes": [], "default": False})
            entry["count"] += 1
            if prefix == "0.0.0.0/0":
                entry["default"] = True
            if len(entry["prefixes"]) < MAX_PREFIXES:
                entry["prefixes"].append(prefix)
    return list(groups.values())


def _tunnels(config: Any, names: set[str], vr_of: dict[str, str]) -> list[dict[str, Any]]:
    gateways = {g.name: g for g in getattr(config, "ike_gateways", [])}
    out = []
    for tunnel in getattr(config, "ipsec_tunnels", []):
        if tunnel.tunnel_interface not in names:
            continue
        peer = str(getattr(gateways.get(tunnel.ike_gateway), "peer_address", "") or "")
        if peer and peer[0].isdigit():
            out.append({"name": tunnel.name, "source": tunnel.tunnel_interface, "destination": peer, "mode": "ipsec", "vrf": vr_of.get(tunnel.tunnel_interface, ""),
                        "description": "", "ip": ""})
    return out


def _device(config: Any, source: str, vsys: str | None, interfaces: list[Any], vr_of: dict[str, str], multi: bool) -> Device:
    all_interfaces = interfaces
    host = str(config.hostname or "") or source.rsplit(".", 1)[0]
    base = short_host(host) or host
    info = getattr(config, "device_info", None)
    device = Device(key="", hostname=base if vsys is None else f"{base} [{vsys}]", fqdn=host, source=source, vendor="Palo Alto Networks",
                    model=str(getattr(config, "source_model", "") or "PAN-OS firewall"), role_hint="firewall",
                    chassis="" if vsys is None else base, unit="" if vsys is None else vsys)
    l3: list[dict[str, Any]] = []
    state: dict[str, str] = {}
    for iface in interfaces:
        name = iface.name
        physical = iface.interface_type == "ethernet"
        port = canon_port(name) if physical else name
        device.unit_ports.add(port)
        if iface.interface_type == "aggregate":
            members = [canon_port(m.name) for m in all_interfaces if getattr(m, "aggregate_group", "") == name]
            device.unit_ports.update(members)
            if members:
                device.bundles[name] = members
                device.bundle_info[name] = {"protocol": "LACP" if iface.lacp_enabled else "static", "status": "down" if str(iface.link_state or "").lower() == "down" else "up",
                                            "description": str(iface.comment or "")}
                for member in members:
                    device.bundle_of[member] = name
        down = str(iface.link_state or "").lower() == "down"
        state[name] = "admin down" if down else "up/up"
        if physical:
            device.port_state[port] = "down" if down else "up"
        if iface.comment:
            device.descriptions[port] = str(iface.comment)
        row: dict[str, Any] | None = None
        for text in iface.ip_addresses or []:
            ip, plen = _address(text)
            if not ip or plen is None:
                continue
            if row is None:
                row = {"name": name, "ip": ip, "prefix_len": plen, "vrf": vr_of.get(name, ""), "kind": _KIND.get(iface.interface_type, "Routed"), "shutdown": down,
                           "description": str(iface.comment or ""), "status": "admin down" if down else "up", "secondary": [], "parent": str(iface.parent_interface or ""),
                           "vlan_id": iface.tag, "role": str(iface.zone or "")}
                l3.append(row)
            else:
                row["secondary"].append(f"{ip}/{plen}")
            device.ips.add(ip)
    device.l3 = l3
    defined = {i.name for i in all_interfaces if i.interface_type == "aggregate"}
    for group in OrderedDict.fromkeys(str(getattr(m, "aggregate_group", "") or "") for m in all_interfaces):
        if group and group not in defined:
            # a Panorama-managed firewall keeps the group itself (ae1) in the template; the ports that join it are local, so the bundle is read from them
            members = [canon_port(m.name) for m in all_interfaces if getattr(m, "aggregate_group", "") == group]
            device.unit_ports.add(group)
            device.bundles[group] = members
            device.bundle_info[group] = {"protocol": "", "status": "up", "description": "aggregate group defined in the Panorama template"}
            for member in members:
                device.bundle_of[member] = group
    ha = getattr(config, "ha", None)
    pan_ha: dict[str, Any] = {}
    if ha is not None and ha.enabled and not multi:
        pan_ha = {"mode": ha.mode, "group": ha.group_id, "peer_ip": ha.peer_ip, "peer_ip_backup": ha.peer_ip_backup, "own_ip": ha.ha1_ip, "own_ip_backup": ha.ha1_backup_ip,
                  "priority": ha.priority, "description": ha.description,
                  "ports": [(role, canon_port(port)) for role, port in (("HA1", ha.ha1_port), ("HA1-backup", ha.ha1_backup_port), ("HA2", ha.ha2_port),
                                                                     ("HA2-backup", ha.ha2_backup_port), ("HA3", ha.ha3_port)) if port]}
        device.unit_ports.update(port for _, port in pan_ha["ports"])
    mgmt = str(getattr(info, "mgmt_ip", "") or "")
    device.mgmt_ip = (mgmt if vsys is None or not multi else "") or (l3[0]["ip"] if l3 else mgmt)
    if mgmt and (vsys is None or not multi):
        device.ips.add(mgmt)
    routers = {vr_of.get(i.name, "") for i in interfaces} - {""}
    if vsys is not None:
        routers |= {r.name for r in getattr(config, "virtual_routers", []) if getattr(r, "vsys", "") == vsys}
    elif not multi:
        routers = {r.name for r in getattr(config, "virtual_routers", [])}
    device.l3facts = {"hostname": device.hostname, "model": device.model, "release": "PAN-OS", "interfaces": [], "routes": _routes(config, routers), "neighbors": [], "overlay": [],
                      "tunnels": _tunnels(config, {i.name for i in interfaces}, vr_of), "state": state, "wan_colour": {}, "system_ip": "", "site_id": "", "gateway": [], "arp": [],
                      "fhrp": [], "vdoms": [] if vsys is None else [vsys], "transparent": [], "ha": str(pan_ha.get("mode") or ("enabled" if pan_ha else "")), "pan_ha": pan_ha}
    device.coverage = {"routes": bool(device.l3facts["routes"]), "neighbors": False, "overlay": False}
    return device


def units(config: Any, source: str) -> list[Device]:
    """The parsed ``PaloAltoNativeConfig`` as one device per virtual system that imports at least one interface, or one device for the whole box
    when it has no vsys level or only one working vsys."""
    interfaces = list(getattr(config, "interfaces", []))
    vr_of = _vr_of(config)
    groups = {i.name: _owned(i) for i in interfaces if i.interface_type == "aggregate" and _owned(i)}
    names = [v for v in OrderedDict.fromkeys(_owner(i, groups) for i in interfaces) if v and v != "shared"]
    if len(names) < 2:
        return [_device(config, source, None, interfaces, vr_of, False)]
    return [_device(config, source, v, [i for i in interfaces if _owner(i, groups) == v], vr_of, True) for v in names]


def read_units(text: str, source: str) -> list[Device]:
    from ..configuration_studio.service import create_engine
    engine = create_engine()
    with tempfile.TemporaryDirectory() as folder:
        path = Path(folder) / (re.sub(r"[^A-Za-z0-9._-]", "_", Path(source).name) or "pan.txt")
        path.write_text(text, encoding="utf-8")
        config = engine.parse(path, source_vendor="Auto Detect", source_device_type="Firewall")
    if str(getattr(config, "source_vendor", "")).strip().lower() != "palo alto":
        raise ValueError("not a PAN-OS configuration")
    found = units(config, source)
    model = re.search(r"^model:\s*(\S+)", text, re.M)               # 'show system info' in a prompted capture; a bare configuration has no model
    version = re.search(r"^sw-version:\s*(\S+)", text, re.M)
    for device in found:
        if model:
            device.model = model.group(1)
        if version:
            device.os_version = f"PAN-OS {version.group(1)}"
    return found
