"""End hosts from MAC and ARP tables: a MAC learned on a port that is not an inter-switch link is a host on that switch."""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Any

from .extract import Device, mac12
from .graph import Connection, Graph, Link
from .names import canon_port, port_sort_key

ENDPOINT_ROLES = {"ap", "phone", "host", "server"}
SKIP_PORTS = re.compile(r"^(cpu|vlan|vpc|sup-eth|router|nve|vxlan|mgmt|eobc|null|sw|bridge)", re.IGNORECASE)
VIRTUAL_MAC = re.compile(r"^(00000c07ac|00000c9ff|00005e0001|00005e0002|0007b400|00005e00)")
# MAC prefixes assigned to hypervisor vendors (IEEE OUI registry; see https://macaddress.io/faq/how-to-recognise-a-vmwares-virtual-machine-by-its-mac-address).
# A match is a hint, not proof: an administrator can give a virtual machine any MAC address.
OUI_KIND = {"005056": "VMware", "000c29": "VMware", "001c14": "VMware", "000569": "VMware", "00155d": "Hyper-V"}
MANY_PER_PORT = 8
INDIVIDUAL_LIMIT = 3


def _infra_ports(graph: Graph, key: str) -> tuple[set[str], dict[str, str]]:
    """Ports that face another network device, and for those facing a device that was not captured the name of that device
    (the MACs learned there live behind it, for example the virtual machines behind a UCS fabric interconnect)."""
    node = graph.nodes[key]
    ports: set[str] = set()
    behind: dict[str, str] = {}
    for link in graph.links:
        for near, port, far in ((link.a, link.a_port, link.b), (link.b, link.b_port, link.a)):
            if near == key and far in graph.nodes and graph.nodes[far].role_hint not in ENDPOINT_ROLES and link.state != "inferred":
                ports.add(port)
                if not graph.nodes[far].captured:
                    behind[port] = graph.nodes[far].hostname
    for port in list(ports):
        po = node.bundle_of.get(port)
        if po:
            ports.add(po)
            ports.update(node.bundles.get(po, []))
            if port in behind:
                behind.setdefault(po, behind[port])
                for member in node.bundles.get(po, []):
                    behind.setdefault(member, behind[port])
    for po in ([node.vpc_peer_link] if node.vpc_peer_link else []):
        ports.add(po)
        ports.update(node.bundles.get(po, []))
        for name in [po, *node.bundles.get(po, [])]:
            behind.pop(name, None)
    return ports, behind


def _ap_ports(graph: Graph, key: str) -> dict[str, str]:
    """Ports of ``key`` that face an access point (drawn alone or rolled up into one box), with the access point's name.
    The MACs learned there are wireless clients (FlexConnect / local switching) or the access point itself, not wired hosts."""
    ports: dict[str, str] = {}
    for link in graph.links:
        for near, port, far in ((link.a, link.a_port, link.b), (link.b, link.b_port, link.a)):
            if near != key or link.state == "inferred":
                continue
            node = graph.nodes.get(far)
            if node is not None and node.role_hint == "ap":
                ports[port] = node.hostname
            elif node is None and far in graph.rolled_roles and graph.rolled_roles[far] == "ap":
                ports[port] = far
    return ports


def collect(graph: Graph, devices: dict[str, Device]) -> None:
    """Fill graph.hosts (one row per MAC at its edge port) and graph.issues (many MACs behind a port, MAC on two switches)."""
    own: set[str] = set()
    for node in graph.nodes.values():
        own |= node.macs
    ip_by_mac: dict[str, set[str]] = defaultdict(set)
    for device in devices.values():
        for row in device.arp_table:
            mac = mac12(str(row.get("mac_address", "")))
            ip = str(row.get("ip_address", ""))
            if mac and ip and ip != "0.0.0.0" and str(row.get("age", "")) != "-":
                ip_by_mac[mac].add(ip)
            elif mac:
                own.add(mac)                  # age "-" is the device's own interface address
    seen: dict[str, dict[str, Any]] = {}
    per_port: dict[tuple[str, str], list[str]] = defaultdict(list)
    for key in sorted(devices):
        device = devices[key]
        if not device.mac_table:
            continue
        infra, behind = _infra_ports(graph, key)
        access_points = _ap_ports(graph, key)
        for row in device.mac_table:
            mac = mac12(str(row.get("mac_address", "")))
            raw = str(row.get("interface", "")).strip()
            port = canon_port(raw)
            if not mac or row.get("system") or not port or SKIP_PORTS.match(port) or mac in own:
                continue
            if int(mac[1], 16) & 1 or VIRTUAL_MAC.match(mac) or mac == "ffffffffffff":
                continue
            if port in infra and port not in behind:
                continue                                # a link to a captured device: its own table lists the hosts
            entry = {"mac": mac, "device": key, "port": port, "vlan": str(row.get("vlan", "")), "ips": sorted(ip_by_mac.get(mac, [])), "note": "",
                     "via": behind.get(port, ""), "kind": OUI_KIND.get(mac[:6], "")}
            if port in access_points:
                entry["via"], entry["via_role"] = access_points[port], "ap"
                device.wireless_clients[port] = device.wireless_clients.get(port, 0) + 1
            if entry["via"]:
                entry["note"] = f"behind {entry['via']}"
            if mac in seen:
                other = seen[mac]
                roaming = entry.get("via_role") == "ap" and other.get("via_role") == "ap"       # a client that moved between two access points
                if other["device"] != key and not roaming and not _vpc_member_on_both(graph, other, key, port):
                    if not other["note"].startswith("also learned"):
                        other["note"] = f"also learned on {key} {port}"
                        graph.issues.append({"type": "mac-twice", "mac": mac, "a": other["device"], "a_port": other["port"], "b": key, "b_port": port})
                continue
            seen[mac] = entry
            graph.hosts.append(entry)
            if not entry["via"]:
                per_port[(key, port)].append(mac)
    for (key, port), macs in per_port.items():
        if len(macs) >= MANY_PER_PORT:
            graph.issues.append({"type": "many-macs", "node": key, "port": port, "count": len(macs)})


def _vpc_member_on_both(graph: Graph, first: dict[str, Any], key: str, port: str) -> bool:
    """The same MAC behind a vPC port-channel is learned on both peers by design; that is no finding."""
    a, b = graph.nodes.get(first["device"]), graph.nodes.get(key)
    return bool(a and b and a.vpc_domain and a.vpc_domain == b.vpc_domain and port.lower().startswith("po") and first["port"] == port)


def dotted(mac: str) -> str:
    return f"{mac[0:4]}.{mac[4:8]}.{mac[8:12]}"


def draw(graph: Graph) -> None:
    """Add host nodes (up to 3 per port, otherwise one summary node) and their lines to the graph."""
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for host in graph.hosts:
        if not host.get("via"):                       # hosts behind another network device are listed, not drawn
            grouped[(host["device"], host["port"])].append(host)
    for (key, port), hosts in sorted(grouped.items(), key=lambda item: (item[0][0], port_sort_key(item[0][1]))):
        if key not in graph.nodes:
            continue
        if len(hosts) <= INDIVIDUAL_LIMIT:
            for host in hosts:
                node_key = f"HOST:{host['mac']}"
                label = host["ips"][0] if host["ips"] else dotted(host["mac"])
                node = Device(key=node_key, hostname=label, captured=False, role_hint="host", mgmt_ip=host["ips"][0] if host["ips"] else "",
                              model=f"{dotted(host['mac'])} VLAN {host['vlan']}" if host["ips"] else f"VLAN {host['vlan']}")
                graph.nodes[node_key] = node
                link = Link(key, port, node_key, "", "inferred", {"MAC"}, "learned from the MAC table")
                graph.links.append(link)
                graph.connections.append(Connection(key, node_key, [link], kind="host"))
        else:
            vlans = sorted({h["vlan"] for h in hosts if h["vlan"]}, key=lambda v: int(v) if v.isdigit() else 0)
            node_key = f"HOSTS:{key}:{port}"
            node = Device(key=node_key, hostname=f"{len(hosts)} hosts", captured=False, role_hint="host",
                          model="VLAN " + ", ".join(vlans[:4]) + (" ..." if len(vlans) > 4 else ""))
            node.rolled_up = [dotted(h["mac"]) for h in hosts]  # type: ignore[attr-defined]
            graph.nodes[node_key] = node
            link = Link(key, port, node_key, "", "inferred", {"MAC"}, f"{len(hosts)} MAC addresses on one port")
            graph.links.append(link)
            graph.connections.append(Connection(key, node_key, [link], kind="host"))
