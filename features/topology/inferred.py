"""Neighbors that CDP and LLDP did not report: read from ARP tables and interface descriptions.

A router that has no CDP/LLDP neighbors (a WAN edge facing a provider, an SD-WAN edge) still tells who is on its ports:

* the interface description often names the far device and its port (``WANR2 G0/1/2``);
* the ARP table lists the IP and MAC address of the device on the other end of a routed port (the entries with age ``-`` are the
  router's own addresses and are skipped).

Order of trust: CDP/LLDP (a neighbor table, never overridden) > ARP (the address on the far end belongs to a known device) > MAC address (every MAC
learned on the port belongs to one device) > port description (the name a person typed).  When a lower source names another device than the
one chosen, the finding says so.

All of them are weaker evidence than a neighbor table, so the lines they add are *inferred*: dashed, labelled with the evidence (ARP,
description or both) and listed in finding TOPO-027 so the engineer can confirm them.  A port that already has a CDP/LLDP link is never touched.

ARP: https://www.rfc-editor.org/rfc/rfc826
"""

from __future__ import annotations

import re
from typing import Any

from .extract import Device, mac12
from .graph import Connection, Graph, Link, pick_unit
from .names import canon_port
from .roles import _WORD_RULES, _by_rules

_NETWORK_WORDS = {"firewall", "router", "loadbalancer", "wlc", "core", "aggregation", "access", "fabric", "ap"}

_NOT_PHYSICAL = re.compile(r"^(vlan|vl\d|lo\d|loopback|tu\d|tunnel|nve|mgmt|null|cpu|sdwan|vmanage|nvi|bdi|irb|vxlan)", re.I)
_PREFIX = re.compile(r"^(?:(?:up|down)?link\s*(?:to|-)?|to|link\s+to|connect(?:ed|ion)\s+to|conn(?:ect)?\s+to|trunk\s+to|->|>>|=>)\s*[-:_>]*\s*", re.I)
# "... - Port Eth1/17", "connected to HQEDGNX1 port eth 1/50", "to SW1 interface Gi0/1": the far port named after the word port / interface
_PORT_WORD = re.compile(r"\b(?:port|interface|intf|int)\.?\s*[:#-]?\s*(?P<port>[A-Za-z][A-Za-z-]*\s?\d+(?:/\d+)+(?:\.\d+)?)\s*$", re.I)
_NAME_PORT = re.compile(r"^(?P<name>[A-Za-z][A-Za-z0-9_.-]{2,})(?:\s+[-–]\s+|[\s:_,;]+)(?P<port>(?:[A-Za-z]{1,}[A-Za-z-]*)?\d+(?:/\d+)*(?:\.\d+)?)\s*$")
_STOP = {"LAN", "WAN", "UPLINK", "DOWNLINK", "LINK", "TRUNK", "ACCESS", "MGMT", "MANAGEMENT", "USER", "USERS", "SERVER", "SERVERS", "VOICE", "DATA",
         "PRINTER", "SPARE", "UNUSED", "TEST", "BACKUP", "PRIMARY", "SECONDARY", "INSIDE", "OUTSIDE", "DMZ", "CORE", "HA", "SYNC", "PEER", "VLAN",
         "SHUTDOWN", "RESERVED", "FREE", "NOT-USED", "NOUSE", "CLIENT", "CLIENTS", "STACK", "VSF", "VSX", "ISL", "KEEPALIVE"}
_CLOUD_WORDS = {"INTERNET", "ISP", "PROVIDER", "TELCO", "MPLS", "METRO", "METRO-E", "VPN"}
_ROUTER_NAME = re.compile(r"(^|[-_])(RT|RTR|ROU|ROUTER|WANR|WANRT|CE|PE|ISR|ASR|SDW|EDGE|GW|GATEWAY)\d*", re.I)


def _norm(text: str) -> str:
    return re.sub(r"[^A-Z0-9]+", "-", (text or "").upper()).strip("-")


def _strip_prefix(text: str) -> str:
    previous = None
    text = (text or "").strip()
    while previous != text:
        previous = text
        text = _PREFIX.sub("", text).strip()
    return text


def parse_description(text: str) -> tuple[str, str]:
    """('WANR2 G0/1/2') -> ('WANR2', 'G0/1/2'); ('TO-JKT-CORE-01') -> ('JKT-CORE-01', ''); free text -> ('', '')."""
    cleaned = _strip_prefix(text)
    if not cleaned:
        return "", ""
    found = _NAME_PORT.match(cleaned)
    if found:
        return found.group("name"), found.group("port")
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{2,}", cleaned):
        return cleaned, ""
    return "", ""


def port_hint(text: str) -> str:
    """The far port a description names after the word 'port' ('Connection to HQPAIBFW1 - Port Eth1/17' -> 'Eth1/17'), canonical, or ''."""
    found = _PORT_WORD.search((text or "").strip())
    return canon_port(re.sub(r"\s+", "", found.group("port"))) if found else ""


def _is_physical(port: str) -> bool:
    return bool(port) and not _NOT_PHYSICAL.match(port)


def _evidence(graph: Graph) -> dict[str, set[str]]:
    """Ports of every node that already carry a link (and the bundle they belong to)."""
    taken: dict[str, set[str]] = {}
    for link in graph.links:
        for near, port in ((link.a, link.a_port), (link.b, link.b_port)):
            node = graph.nodes.get(near)
            names = {port}
            if node is not None:
                po = node.bundle_of.get(port)
                if po:
                    names.add(po)
                    names.update(node.bundles.get(po, []))
            taken.setdefault(near, set()).update(names)
    return taken


def _find_by_name(graph: Graph, text: str, own: str) -> str:
    """Key of the node whose hostname appears in ``text`` as a whole word (longest name first), else ''."""
    haystack = f"-{_norm(text)}-"
    best = ""
    for key, node in graph.nodes.items():
        name = node.chassis or node.hostname                 # a firewall drawn per VDOM is named by its chassis in a description
        if key == own or len(name) < 4 or node.role_hint in ("host", "phone", "server") or key in graph.hidden_nodes:
            continue
        needle = f"-{_norm(name)}-"
        if needle in haystack and len(name) > len((graph.nodes[best].chassis or graph.nodes[best].hostname) if best else ""):
            best = key
    return best


def _find_by_fragment(graph: Graph, token: str, own: str) -> str:
    """A description often carries the hostname without its site prefix and suffix ('SW-1-LT-1A' for SITE-HQ-SW-1-LT-1A-STC6): it names
    a node when that fragment sits between hyphens in exactly one hostname."""
    fragment = f"-{_norm(token)}-"
    if len(fragment) < 8 or not re.search(r"\d", fragment):
        return ""
    hits = [key for key, node in graph.nodes.items()
            if key != own and node.role_hint not in ("host", "phone", "server") and fragment in f"-{_norm(node.hostname)}-"]
    return hits[0] if len(hits) == 1 else ""


def _ip_index(graph: Graph) -> dict[str, str]:
    index: dict[str, str] = {}
    for key, node in graph.nodes.items():
        for ip in node.ips | ({node.mgmt_ip} if node.mgmt_ip else set()):
            index.setdefault(ip, key)
    return index


def fill_addresses_from_arp(graph: Graph) -> int:
    """Give a device nobody captured (an access point seen by LLDP) the IP address its MAC address has in someone's ARP table."""
    by_mac: dict[str, str] = {}
    for device in graph.nodes.values():
        if not device.captured:
            continue
        for row in device.arp_table:
            mac, ip = mac12(str(row.get("mac_address", ""))), str(row.get("ip_address", ""))
            if mac and ip and ip != "0.0.0.0" and str(row.get("age", "")) != "-":
                by_mac.setdefault(mac, ip)
    filled = 0
    for node in graph.nodes.values():
        if node.captured or node.mgmt_ip:
            continue
        for mac in node.macs:
            ip = by_mac.get(mac12(mac))
            if ip:
                node.mgmt_ip = ip
                node.ips.add(ip)
                filled += 1
                break
    return filled


def _routed_names(device: Device) -> dict[str, dict[str, Any]]:
    """Physical routed interfaces of a device (own IP, not an SVI, loopback or tunnel) by canonical name."""
    out: dict[str, dict[str, Any]] = {}
    for row in device.l3:
        name = row["name"]
        if _is_physical(name) and not row.get("shutdown") and not str(row.get("kind", "")).lower() in ("svi", "loopback", "tunnel"):
            out.setdefault(name, row)
    return out


def _arp_peers(device: Device) -> dict[str, list[dict[str, str]]]:
    peers: dict[str, list[dict[str, str]]] = {}
    if device.vendor == "F5":
        return peers                          # a BIG-IP ARP table names VLANs, not ports: f5neighbors.py reads it with the VLAN table
    own = set(device.ips) | ({device.mgmt_ip} if device.mgmt_ip else set())
    for row in device.arp_table:
        ip, mac = str(row.get("ip_address", "")), mac12(str(row.get("mac_address", "")))
        port = canon_port(str(row.get("interface", "")))
        if not ip or not mac or ip in own or str(row.get("age", "")) == "-" or ip == "0.0.0.0" or not port:
            continue
        peers.setdefault(port, []).append({"ip": ip, "mac": mac, "vrf": str(row.get("vrf", ""))})
    return peers


def _new_node(graph: Graph, name: str, ip: str, mac: str, role_caps: str) -> str:
    key = _norm(name) or name.upper()
    node = graph.nodes.get(key)
    if node is None:
        node = Device(key=key, hostname=key, captured=False, mgmt_ip=ip, caps=role_caps)
        graph.nodes[key] = node
    if ip and not node.mgmt_ip:
        node.mgmt_ip = ip
    if ip:
        node.ips.add(ip)
    if mac:
        node.macs.add(mac)
    return key


def _macs_by_port(device: Device) -> dict[str, set[str]]:
    """MAC addresses the device learned on each port (its own and static entries left out)."""
    own = {mac12(m) for m in device.macs}
    out: dict[str, set[str]] = {}
    for row in device.mac_table:
        mac, port = mac12(str(row.get("mac_address", ""))), canon_port(str(row.get("interface", "")))
        if mac and port and mac not in own and str(row.get("type", "")).lower() != "static":
            out.setdefault(port, set()).add(mac)
    return out


def _mac_index(graph: Graph, ip_owner: dict[str, str]) -> dict[str, str]:
    """MAC address -> device: the chassis MACs a device reports, plus any MAC that some captured ARP table pairs with an address a device owns."""
    owner: dict[str, str] = {}
    for key, node in graph.nodes.items():
        for mac in node.macs:
            owner.setdefault(mac12(mac), key)
    for node in graph.nodes.values():
        for row in node.arp_table if node.captured else []:
            mac, ip = mac12(str(row.get("mac_address", ""))), str(row.get("ip_address", ""))
            if mac and ip_owner.get(ip):
                owner.setdefault(mac, ip_owner[ip])
    owner.pop("", None)
    return owner


def _mac_owner_of_port(macs: set[str], index: dict[str, str], own: str) -> str:
    """The device behind a port when every MAC learned there (at most 8) belongs to that one device; a port that also carries hosts says nothing."""
    if not macs or len(macs) > 8:
        return ""
    owners = {index.get(m, "") for m in macs}
    return next(iter(owners)) if len(owners) == 1 and "" not in owners and own not in owners else ""


def description_drift(graph: Graph) -> list[dict[str, Any]]:
    """Ports whose CDP/LLDP neighbor is not the device the port description names (a description nobody updated after a move)."""
    facts: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for link in graph.links:
        if link.state == "inferred":
            continue
        for near, port, far in ((link.a, link.a_port, link.b), (link.b, link.b_port, link.a)):
            node = graph.nodes.get(near)
            if node is None or not node.captured or far not in graph.nodes or (near, port) in seen:
                continue
            seen.add((near, port))
            text = node.descriptions.get(port, "") or node.bundle_info.get(node.bundle_of.get(port, ""), {}).get("description", "")
            if not text:
                continue
            named = _find_by_name(graph, text, near)
            far_name = graph.nodes[far].hostname
            if named and named != far and f"-{_norm(far_name)}-" not in f"-{_norm(text)}-":
                facts.append({"type": "description-drift", "a": near, "a_port": port, "b": far, "b_port": "", "a_host": node.hostname, "b_host": far_name, "says": graph.nodes[named].hostname, "description": text})
    return facts


def infer_neighbors(graph: Graph) -> list[dict[str, Any]]:
    """Add inferred links for ports that have no CDP/LLDP link. Order of trust: ARP, then MAC address, then port description. Returns the facts for TOPO-027."""
    taken = _evidence(graph)
    ip_owner = _ip_index(graph)
    mac_owner = _mac_index(graph, ip_owner)
    facts: list[dict[str, Any]] = []
    claimed: dict[tuple[str, str], str] = {}                # (device, port) -> the device a description of this run put on the other end
    for key in sorted(k for k, n in graph.nodes.items() if n.captured):
        device = graph.nodes[key]
        routed = _routed_names(device)
        peers = _arp_peers(device)
        macs_on = _macs_by_port(device)
        ports = set(device.descriptions) | set(peers) | set(macs_on)
        for port in sorted(ports):
            if not _is_physical(port) or (port in taken.get(key, set()) and (key, port) not in claimed) or port in device.bundles:
                continue
            vrf = str(routed.get(port, {}).get("vrf", "")).lower()
            if "mgmt" in vrf or "management" in vrf:
                continue
            description = device.descriptions.get(port, "")
            name, far_port = parse_description(description)
            desc_key = (_find_by_name(graph, description, key) or (_find_by_fragment(graph, name, key) if name else "")) if description else ""
            if desc_key and not far_port:
                far_port = port_hint(description)
            arp = peers.get(port, [])
            far_key, how, far_ip, far_mac = "", set(), "", ""
            # Order of trust after CDP/LLDP (those ports never get here): 1 ARP owner, 2 MAC owner, 3 description naming a known device,
            # then (weaker, they invent a new box) 4 a lone ARP peer on a routed port, 5 a description that looks like a device name.
            owned = [(p["ip"], ip_owner[p["ip"]], p["mac"]) for p in arp if ip_owner.get(p["ip"]) not in (None, key)]
            mac_key = _mac_owner_of_port(macs_on.get(port, set()), mac_owner, key)
            if len({o for _, o, _ in owned}) == 1:
                far_ip, far_key, far_mac = owned[0]
                how = {"ARP"}
            elif mac_key:
                far_key, how = mac_key, {"MAC"}
            elif desc_key:
                far_key, how = desc_key, {"DESC"}
            if far_key:
                if desc_key == far_key:
                    how.add("DESC")
                if mac_key == far_key:
                    how.add("MAC")
                if not far_ip:
                    far_ip = next((p["ip"] for p in arp if ip_owner.get(p["ip"]) == far_key), "")
                    far_mac = next((p["mac"] for p in arp if ip_owner.get(p["ip"]) == far_key), "")
                    if far_ip:
                        how.add("ARP")
            elif len(arp) == 1 and port in routed and (name or _prefix_len(routed[port]) >= 29) and (not name or _norm(name) in _STOP or _looks_like_device(name, far_port, True)):
                far_ip, far_mac = arp[0]["ip"], arp[0]["mac"]
                label = name if name and _norm(name) not in _STOP else far_ip
                if _norm(label) in _CLOUD_WORDS:
                    far_key = _new_node(graph, label, far_ip, far_mac, "")
                    graph.nodes[far_key].role_hint = "cloud"
                else:
                    far_key = _new_node(graph, label, far_ip, far_mac, "Router")
                how = {"ARP"} | ({"DESC"} if name and _norm(name) not in _STOP else set())
            if not far_key and name and (far_port or port in routed) and _norm(name) not in _STOP and _looks_like_device(name, far_port, port in routed):
                far_key = _new_node(graph, name, "", "", "Router" if port in routed else "")
                how = {"DESC"}
            if far_key:
                far_key = pick_unit(graph, far_key, far_port)       # a description names the chassis and the port: the VDOM that owns that port
            if not far_key or far_key == key:
                continue
            if (key, port) in claimed:
                if claimed[(key, port)] == far_key:
                    continue                    # the same cable again, said from the other end
                facts.append({"type": "port-claimed-twice", "a": key, "a_port": port, "first": claimed[(key, port)], "second": far_key})
            joined = [c for c in graph.connections if far_key in (c.a, c.b) and key in (c.a, c.b)]
            if any(c.kind != "inferred" for c in joined):
                continue                        # the two devices are already joined by a line (the other ports of that bundle are TOPO-015's business)
            far_name = canon_port(far_port) if far_port else ""
            if far_ip and far_key in graph.nodes and graph.nodes[far_key].l3 and not far_name:
                far_name = next((r["name"] for r in graph.nodes[far_key].l3 if r["ip"] == far_ip), "")
            if joined and _same_cable(joined, key, port, far_key, far_name):
                taken.setdefault(key, set()).add(port)
                continue                        # the other end of this cable was inferred already (from the far device's own description or ARP)
            evidence = "+".join(sorted(how))
            note = f"inferred from {evidence}" + (f": port description '{description}'" if "DESC" in how else "") + (f", ARP {far_ip}" if far_ip else "")
            link = Link(key, port, far_key, far_name, "inferred", set(how), note)
            graph.links.append(link)
            if joined:
                joined[0].links.append(link)    # one more cable between the same two devices (a FortiGate with three ports to one Nexus)
            else:
                graph.connections.append(Connection(key, far_key, [link], kind="inferred"))
            taken.setdefault(key, set()).add(port)
            claimed[(key, port)] = far_key
            if far_name:
                taken.setdefault(far_key, set()).add(far_name)
                if "DESC" in how and not (how - {"DESC"}):
                    claimed.setdefault((far_key, far_name), key)       # a description names the port on the far end too: another description claiming it is a conflict
            said = next((graph.nodes[k].hostname for k in (desc_key, mac_key) if k and k != far_key and k in graph.nodes), "")
            facts.append({"type": "inferred-link", "a": key, "a_port": port, "b": far_key, "b_port": far_name, "evidence": evidence, "ip": far_ip, "conflict": said})
    return facts


def _same_cable(joined: list[Connection], key: str, port: str, far_key: str, far_name: str) -> bool:
    """Is this port already one end of a link inferred between the same two devices?

    The far device's own description of the cable counts (its port is then ``far_name``), and so does a link made from the far side whose
    port on this side was still unknown: that port is filled in here.
    """
    for conn in joined:
        for link in conn.links:
            mine = link.a == key and link.b == far_key
            theirs = link.a == far_key and link.b == key
            if not (mine or theirs):
                continue
            near, far = (link.a_port, link.b_port) if mine else (link.b_port, link.a_port)      # port on this device, port on the far device
            if near == port:
                return True
            if far_name and far == far_name:
                if not near and theirs:
                    link.b_port = port
                return True
            if not far_name and theirs and not near:
                link.b_port = port
                return True
    return False


def _prefix_len(row: dict[str, Any]) -> int:
    try:
        return int(row.get("prefix_len") or 0)
    except (TypeError, ValueError):
        return 0


def _looks_like_device(name: str, far_port: str, routed: bool) -> bool:
    """A description such as 'WANR2 G0/1/2' or 'JKT-RT-01' names a device; 'Finance printer' does not."""
    token = _norm(name)
    if len(token) < 4 or token in _STOP or re.search(r"(^|-)(SVR|SRV|SERVER|PC|WKS|PRINTER|CAM|CCTV|DVR|NAS|SAN|ATM|PHONE|PABX|TELLER)\d*(-|$)", token):
        return False
    named = _by_rules(_WORD_RULES, token) in _NETWORK_WORDS
    return named or bool(_ROUTER_NAME.search(token)) or (routed and bool(re.search(r"\d", token)))
