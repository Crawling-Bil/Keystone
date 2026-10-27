"""The neighbors of an F5 BIG-IP that CDP / LLDP did not report: assumed from its ARP table, its routes and its VLANs.

A BIG-IP seldom has LLDP neighbors: the feature is off on many data-centre switches and the F5 only listens to what the far end sends.  What it always has is

* the **VLAN table**: which port or trunk carries which VLAN, so the port a neighbor must be behind (a VLAN on two ports is put on the lower one and says so);
* the **ARP table** (``show net arp``): IP address and MAC address of everything on each VLAN, which tells three things apart:
  - a **first-hop-redundancy virtual MAC** (HSRP ``0000.0c07.acXX`` / ``0000.0c9f.fXXX``, VRRP ``0000.5e00.01XX``, GLBP ``0007.b400.xxxx``) is the *gateway* of that VLAN,
    and for HSRP and VRRP the group number is in the MAC (HSRP: https://www.cisco.com/c/en/us/td/docs/switches/datacenter/nexus3000/sw/unicast/503_u1_2/nexus3000_unicast_config_gd_503_u1_2/l3_hsrp.html ,
    RFC 2281; VRRP: RFC 5798 section 7.3, https://www.rfc-editor.org/rfc/rfc5798; GLBP: the Cisco guide only gives the prefix and examples, so no group is read from it);
  - the **next hop of a static route** (the default gateway too) is a gateway even when its MAC is a plain one;
  - on a **small subnet** (a /29 to /31 between the BIG-IP and one provider or firewall) every other address is the router on the far end of that cable;
  - everything else is a **host** (a pool member, a client): listed in the host table, drawn only when end hosts are drawn;
* the **name of the VLAN**: ``SYNC``, ``FAILOVER``, ``HA`` mark the cable to the other unit of the pair, ``ISP`` / ``MPLS`` / ``WAN`` a provider.

Everything drawn from this is *assumed*, not read from a neighbor table: the node is grey like every device nobody captured, the line is dashed and labelled
with its evidence (``inferred ARP+HSRP``), and the finding that lists inferred links (TOPO-027) says so.  Order of trust is unchanged: a port that has a
CDP/LLDP link is left alone, and a neighbor that is a captured device (the other unit of the pair, the core that owns the gateway address) is joined to it, not to a new node.
The generic ARP inference of ``inferred.py`` skips a BIG-IP: its ARP table names VLANs, not ports.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from .extract import Device, mac12
from .graph import Connection, Graph, Link
from .hosts import OUI_KIND
from .inferred import _ip_index, _is_physical
from .names import canon_port

MAX_GATEWAYS = 4                        # gateways behind the same ports drawn one by one; more become one node (the default gateway and route next hops stay apart)
SMALL_PREFIX = 29                       # a self IP with at least this prefix length faces one provider / firewall / peer, not a LAN
_HA_WORDS = re.compile(r"(^|[-_ ])(SYNC|FAILOVER|HA|HEARTBEAT|MIRROR|CONFIGSYNC)([-_ ]|\d|$)", re.I)
_PROVIDER_WORDS = re.compile(r"(^|[-_ ])(ISP|INET|INTERNET|WAN|MPLS|METRO|PROVIDER|TELCO)([-_ ]|\d|$)", re.I)
_FHRP = (("HSRP", re.compile(r"^00000c07ac([0-9a-f]{2})$"), lambda m: int(m.group(1), 16)),
         ("HSRPv2", re.compile(r"^00000c9ff([0-9a-f]{3})$"), lambda m: int(m.group(1), 16)),
         ("VRRP", re.compile(r"^00005e0001([0-9a-f]{2})$"), lambda m: int(m.group(1), 16)),
         ("GLBP", re.compile(r"^0007b400[0-9a-f]{4}$"), lambda m: 0))      # Cisco documents only the 0007.b400 prefix and examples (0101, 0102): no group is read from it


def fhrp_of(mac: str) -> tuple[str, int] | None:
    """('HSRP', 1) for 00:00:0c:07:ac:01; None for a MAC that is not a first-hop-redundancy virtual address."""
    text = mac12(mac)
    for name, pattern, group in _FHRP:
        found = pattern.match(text)
        if found:
            return name, group(found)
    return None


def _vlan_ports(node: Device, vlan: dict[str, Any]) -> tuple[list[str], bool]:
    """(ports a VLAN reaches the outside through, True when that is more than one cable).  A trunk counts through its member ports; a port that is down is
    left out when another one is up (a spare uplink that is not cabled yet does not face anybody)."""
    members = [re.sub(r"\s*\(.*\)$", "", str(i)).strip() for i in vlan.get("interfaces") or []]
    ports: list[str] = []
    for name in members:
        for port in ([canon_port(m) for m in node.bundles[name]] if name in node.bundles else [canon_port(name)] if name else []):
            if port not in ports:
                ports.append(port)
    up = [p for p in ports if node.port_state.get(p, "up") == "up"]
    chosen = sorted(up or ports, key=lambda p: [int(x) if x.isdigit() else x for x in re.split(r"[.\-/]", p)])
    return chosen, len(chosen) > 1


def _network(vlan: dict[str, Any], ip: str) -> ipaddress.IPv4Network | None:
    """The subnet of the own (non-floating) self IP of the VLAN that contains ``ip``."""
    try:
        target = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for own in vlan.get("self_ips") or []:
        try:
            net = ipaddress.ip_interface(str(own).split("%")[0]).network
        except ValueError:
            continue
        if target in net:
            return net  # type: ignore[return-value]
    return None


def _own_ips(node: Device, rows: list[dict[str, Any]]) -> set[str]:
    own = set(node.ips)
    for vlan in rows:
        for address in list(vlan.get("self_ips") or []) + list(vlan.get("floating_ips") or []):
            own.add(str(address).split("/")[0].split("%")[0])
    return own


def _gateway_node(graph: Graph, ip: str, note: str) -> str:
    key = f"GATEWAY-{ip.replace('.', '-')}"
    node = graph.nodes.get(key)
    if node is None:
        node = Device(key=key, hostname=f"Gateway {ip}", captured=False, mgmt_ip=ip, caps="Router", role_hint="router", model=note)
        node.ips.add(ip)
        graph.nodes[key] = node
    elif note and note not in node.model:
        node.model = f"{node.model}, {note}"[:60]
    return key


def _router_node(graph: Graph, ip: str, label: str, cloud: bool) -> str:
    key = ip.replace(".", "-")
    node = graph.nodes.get(key)
    if node is None:
        node = Device(key=key, hostname=label if cloud else key, captured=False, mgmt_ip=ip, caps="" if cloud else "Router", role_hint="cloud" if cloud else "router")
        node.ips.add(ip)
        graph.nodes[key] = node
    return key


def _peer_node(graph: Graph, ip: str) -> str:
    key = f"PEER-{ip.replace('.', '-')}"
    node = graph.nodes.get(key)
    if node is None:
        node = Device(key=key, hostname=f"Peer {ip}", captured=False, mgmt_ip=ip, vendor="F5", role_hint="loadbalancer", model="BIG-IP, assumed HA peer")
        node.ips.add(ip)
        graph.nodes[key] = node
    return key


def _upstream_node(graph: Graph, owner: str, ports: tuple[str, ...], notes: list[str]) -> str:
    key = f"UPSTREAM-{owner}-{'-'.join(ports)}".replace(".", "-").replace("/", "-")
    node = graph.nodes.get(key)
    if node is None:
        text = ", ".join(sorted(set(notes)))
        node = Device(key=key, hostname=f"{len(notes)} gateways", captured=False, caps="Router", role_hint="router", model=(text[:57] + "...") if len(text) > 60 else text)
        graph.nodes[key] = node
    return key


def _far_port(graph: Graph, far: str, ip: str, vlan_name: str) -> str:
    """The port of a captured neighbor that this cable ends on: the same VLAN's port on the other BIG-IP, the routed interface that owns the address elsewhere."""
    node = graph.nodes.get(far)
    if node is None or not node.captured:
        return ""
    if node.vendor == "F5":
        row = next((v for v in (node.l3facts.get("f5") or {}).get("vlans") or [] if v.get("vlan") == vlan_name), None)
        ports = _vlan_ports(node, row)[0] if row else []
        return ports[0] if ports else ""
    name = next((str(r["name"]) for r in node.l3 if r.get("ip") == ip), "")
    return canon_port(name) if name and _is_physical(name) else ""


def _same_cable(graph: Graph, key: str, port: str, far: str, far_port: str) -> bool:
    for link in graph.links:
        if {link.a, link.b} != {key, far}:
            continue
        mine = (link.a == key and link.a_port == port) or (link.b == key and link.b_port == port)
        theirs = bool(far_port) and ((link.a == far and link.a_port == far_port) or (link.b == far and link.b_port == far_port))
        if mine or theirs:
            return True
    return False


def _port_taken(graph: Graph, key: str, port: str) -> bool:
    """A port that already carries a CDP / LLDP link is left alone (the inferred links of this module share a trunk port: one cable, several neighbors behind it)."""
    for link in graph.links:
        if link.state != "inferred" and ((link.a == key and link.a_port == port) or (link.b == key and link.b_port == port)):
            return True
    return False


def assume_f5_neighbors(graph: Graph) -> list[dict[str, Any]]:
    """Add the assumed neighbors of every captured BIG-IP (see the module text).  Returns the facts for TOPO-027, like ``infer_neighbors``."""
    owner = _ip_index(graph)
    facts: list[dict[str, Any]] = []
    graph.f5_hosts = []
    for key in sorted(k for k, n in graph.nodes.items() if n.captured and n.vendor == "F5" and n.arp_table):
        node = graph.nodes[key]
        rows = (node.l3facts.get("f5") or {}).get("vlans") or []
        by_vlan = {str(v["vlan"]): v for v in rows}
        if not by_vlan:
            continue
        own = _own_ips(node, rows)
        hops = {str(r.get("next_hop", "")): bool(r.get("default")) for r in node.l3facts.get("routes") or []}
        wanted: dict[tuple[str, str], dict[str, Any]] = {}                      # (far reference, own port) -> what we know about it
        listed: set[tuple[str, str]] = set()

        def ask(ref: str, ports: list[str], vlan_name: str, ip: str, how: set[str], note: str, label: str = "") -> None:
            for port in ports:
                slot = wanted.setdefault((ref, port), {"vlan": vlan_name, "ip": ip, "how": set(), "note": note, "label": label})
                slot["how"].update(how)

        for row in node.arp_table:
            ip, mac, vlan_name = str(row.get("ip_address", "")), mac12(str(row.get("mac_address", ""))), str(row.get("interface", ""))
            vlan = by_vlan.get(vlan_name)
            if not ip or not mac or ip in own or vlan is None:
                continue
            ports, many = _vlan_ports(node, vlan)
            if not ports:
                continue
            known = owner.get(ip, "")
            known = known if known != key else ""
            fhrp = fhrp_of(mac)
            net = _network(vlan, ip)
            where = f" (the VLAN is on {' and '.join(ports)}: one cable each)" if many else ""
            if _HA_WORDS.search(vlan_name) and not fhrp and ip not in hops:
                ask(known or f"~peer:{ip}", ports, vlan_name, ip, {"ARP", "VLAN"}, f"VLAN {vlan_name} is an HA / sync VLAN and {ip} answers ARP on it{where}")
            elif fhrp or ip in hops:
                label = (f"{fhrp[0]} group {fhrp[1]}" if fhrp[1] else fhrp[0]) if fhrp else ("default gateway" if hops.get(ip) else "static route next hop")
                how = {"ARP", fhrp[0].replace("v2", "")} if fhrp else {"ARP", "ROUTE"}
                ask(known or f"~gateway:{ip}", ports, vlan_name, ip, how, f"{label} on VLAN {vlan_name}: {ip} ({mac[:4]}.{mac[4:8]}.{mac[8:]}){where}", label)
            elif net is not None and net.prefixlen >= SMALL_PREFIX:
                ask(known or f"~router:{ip}", ports, vlan_name, ip, {"ARP"}, f"{ip} is the only other address of {net} on VLAN {vlan_name}{where}", vlan_name)
            elif not known and (vlan_name, ip) not in listed:                      # a host: listed, drawn only when end hosts are drawn
                listed.add((vlan_name, ip))
                graph.f5_hosts.append({"mac": mac, "device": key, "port": ports[0], "vlan": vlan_name, "ips": [ip], "note": f"ARP on VLAN {vlan_name}", "via": "",
                                       "kind": OUI_KIND.get(mac[:6], "")})
        for ip, is_default in hops.items():                                      # a next hop that no ARP entry shows (expired): still the neighbor on that VLAN
            if not ip or ip in own or any(ref in (f"~gateway:{ip}", owner.get(ip, "")) for ref, _ in wanted):
                continue
            for vlan_name, vlan in by_vlan.items():
                if _network(vlan, ip) is None:
                    continue
                label = "default gateway" if is_default else "static route next hop"
                known = owner.get(ip, "")
                ask(known if known and known != key else f"~gateway:{ip}", _vlan_ports(node, vlan)[0], vlan_name, ip, {"ROUTE"}, f"{label} on VLAN {vlan_name}: {ip}", label)
                break
        _fold_gateways(wanted, hops)
        for (ref, port), item in sorted(wanted.items()):
            if _port_taken(graph, key, port):
                continue
            far = _make(graph, key, ref, item)
            if far == key or far not in graph.nodes:
                continue
            far_port = _far_port(graph, far, item["ip"], item["vlan"])
            if _same_cable(graph, key, port, far, far_port):
                continue
            if any(c.kind != "inferred" and {c.a, c.b} == {key, far} for c in graph.connections):
                continue                                                           # already one line between the two (CDP / LLDP): its other cables are TOPO-015's business
            link = Link(key, port, far, far_port, "inferred", set(item["how"]), f"assumed from the ARP table, the routes and the VLAN table: {item['note']}")
            graph.links.append(link)
            joined = [c for c in graph.connections if c.kind == "inferred" and {c.a, c.b} == {key, far}]
            if joined:
                joined[0].links.append(link)
            else:
                graph.connections.append(Connection(key, far, [link], kind="inferred"))
            facts.append({"type": "inferred-link", "a": key, "a_port": port, "b": far, "b_port": far_port, "evidence": "+".join(sorted(item["how"])), "ip": item["ip"], "conflict": ""})
    return facts


def _fold_gateways(wanted: dict[tuple[str, str], dict[str, Any]], hops: dict[str, bool]) -> None:
    """A BIG-IP with a gateway on every VLAN would draw forty grey routers: more than MAX_GATEWAYS gateways behind the same ports become one node.
    The default gateway and the next hop of a static route keep their own node (those are the ones an engineer looks for)."""
    groups: dict[tuple[str, ...], list[str]] = {}
    for ref, port in wanted:
        if ref.startswith("~gateway:") and ref[9:] not in hops:
            groups.setdefault(tuple(sorted({p for r, p in wanted if r == ref})), []).append(ref)
    for ports, refs in groups.items():
        refs = sorted(set(refs))
        if len(refs) <= MAX_GATEWAYS:
            continue
        new = f"~upstream:{'+'.join(ports)}:{len(refs)}"
        notes = [wanted[(r, ports[0])]["label"] for r in refs]
        merged: dict[str, Any] = {"vlan": "", "ip": "", "how": set(), "label": "", "note": f"{len(refs)} first-hop gateways ({', '.join(r[9:] for r in refs[:6])}{' ...' if len(refs) > 6 else ''}) answer ARP behind {' and '.join(ports)}", "notes": notes}
        for ref in refs:
            for port in ports:
                item = wanted.pop((ref, port))
                merged["how"] |= item["how"]
                merged["vlan"] = merged["vlan"] or item["vlan"]
                merged["ip"] = merged["ip"] or item["ip"]
        for port in ports:
            wanted[(new, port)] = dict(merged)


def _make(graph: Graph, key: str, ref: str, item: dict[str, Any]) -> str:
    """The node a reference stands for: an existing device key as it is, ``~kind:value`` is created now."""
    if not ref.startswith("~"):
        return ref
    kind, _, value = ref[1:].partition(":")
    if kind == "gateway":
        return _gateway_node(graph, value, item["label"])
    if kind == "router":
        return _router_node(graph, value, item["label"], bool(_PROVIDER_WORDS.search(item["label"])))
    if kind == "peer":
        return _peer_node(graph, value)
    ports, _, count = value.rpartition(":")
    return _upstream_node(graph, key, tuple(ports.split("+")), item.get("notes") or [])
