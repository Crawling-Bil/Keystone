"""Turn a parsed IOS configuration tree into structured router facts.

Every function takes a :class:`ConfigTree` and returns plain dicts/lists so
the result is JSON-serialisable and trivially testable.  Credentials are
never returned: only their *type* (see features.analyzer_core.redaction).

Covers the three dialects seen on Cisco routers:
  * classic IOS 12.4 / 15.x (ISR G1/G2, 3825)
  * IOS-XE (ASR1000, ISR4000) including EVC bridge-domain/BDI interfaces
  * IOS-XE SD-WAN (cEdge: C8200, ISR1100/4000 in controller mode)
"""

from __future__ import annotations

import os
import re
from typing import Any

from features.analyzer_core.redaction import secret_strength

from . import ipsec as ipsecmod, nat as natmod, ospf as ospfmod
from .config_tree import ConfigTree, Node
from .ifnames import canon
from .netutil import acl_addr, cidr, is_ipv4, mask_to_len

_INTF_WORDS = (
    "gigabitethernet", "fastethernet", "tengigabitethernet", "ethernet", "loopback", "tunnel", "serial", "vlan",
    "null", "bdi", "dialer", "cellular", "port-channel", "multilink", "virtual-template", "nve", "atm", "pos", "gi", "fa", "te", "lo", "tu", "se", "vl",
)


def _looks_like_interface(token: str) -> bool:
    low = token.lower()
    return any(low.startswith(word) for word in _INTF_WORDS) and any(ch.isdigit() for ch in token)


def _flag(tree: ConfigTree, name: str, default: bool | None = None) -> bool | None:
    """True if ``name`` is configured, False if ``no name`` is, else default."""
    if tree.has(name):
        return True
    if tree.has("no " + name):
        return False
    return default


# --------------------------------------------------------------------------
# System
# --------------------------------------------------------------------------


def extract_system(tree: ConfigTree) -> dict[str, Any]:
    enable_secret = tree.top_first("enable secret")
    enable_password = tree.top_first("enable password")
    secret_desc = secret_class = ""
    if enable_secret:
        parts = enable_secret.text.split()
        type_code = parts[2] if len(parts) > 3 and parts[2].isdigit() else None
        secret_desc, secret_class = secret_strength(type_code)
    stamps = {"last_change": "", "nvram_updated": ""}
    for comment in tree.comments:
        if comment.startswith("Last configuration change"):
            stamps["last_change"] = comment.replace("Last configuration change at", "").strip()
        elif comment.startswith("NVRAM config last updated"):
            stamps["nvram_updated"] = comment.replace("NVRAM config last updated at", "").strip()
    udi = tree.get("license udi pid")
    license_pid = license_sn = ""
    if udi:
        m = re.match(r"(\S+)\s+sn\s+(\S+)", udi)
        if m:
            license_pid, license_sn = m.group(1), m.group(2)
    boot_images = [text for text in tree.all("boot system")]
    return {
        "hostname": tree.get("hostname"),
        "version": tree.get("version"),
        "boot_images": boot_images,
        "domain_name": tree.get("ip domain name") or tree.get("ip domain-name"),
        "name_servers": [item for text in tree.all("ip name-server") for item in text.split() if is_ipv4(item)],
        "timezone": tree.get("clock timezone"),
        "declared_bytes": tree.declared_bytes,
        "last_change": stamps["last_change"],
        "nvram_updated": stamps["nvram_updated"],
        "license_pid": license_pid,
        "license_sn": license_sn,
        "service_password_encryption": _flag(tree, "service password-encryption"),
        "enable_secret": bool(enable_secret),
        "enable_secret_type": secret_desc,
        "enable_secret_strength": secret_class,
        "enable_password": bool(enable_password),
        "aaa_new_model": tree.has("aaa new-model"),
        "cdp_run": _flag(tree, "cdp run"),
        "lldp_run": _flag(tree, "lldp run"),
        "ip_cef": _flag(tree, "ip cef"),
        "ipv6_unicast_routing": _flag(tree, "ipv6 unicast-routing"),
        "source_route": _flag(tree, "ip source-route"),
        "domain_lookup": _flag(tree, "ip domain lookup") if tree.has("ip domain lookup") or tree.has("no ip domain lookup") else None,
        "http_server": _flag(tree, "ip http server"),
        "http_secure_server": _flag(tree, "ip http secure-server"),
        "bootp_server": _flag(tree, "ip bootp server"),
        "finger": _flag(tree, "ip finger"),
        "tcp_small_servers": _flag(tree, "service tcp-small-servers"),
        "udp_small_servers": _flag(tree, "service udp-small-servers"),
        "pad": _flag(tree, "service pad"),
        "ssh_version": tree.get("ip ssh version"),
        "ssh_timeout": tree.get("ip ssh time-out"),
        "tcp_keepalives_in": tree.has("service tcp-keepalives-in"),
        "timestamps_log": tree.get("service timestamps log"),
        "timestamps_debug": tree.get("service timestamps debug"),
        "redundancy_mode": (tree.top_first("redundancy").get("mode") if tree.top_first("redundancy") else ""),
        "proxy_arp_disabled": tree.has("ip arp proxy disable"),
        "spanning_tree": tree.all("spanning-tree"),
        "has_banner": any(node.text.startswith("banner ") for node in tree.root.children),
        "control_plane_policy": _control_plane_policy(tree),
        "call_home": tree.has("call-home"),
        "netconf": tree.has("netconf-yang"),
        "archive": tree.has("archive"),
        "memory_watermark": tree.get("memory free low-watermark processor"),
        "ip_forward_protocol": tree.get("ip forward-protocol"),
    }


def _control_plane_policy(tree: ConfigTree) -> str:
    cp = tree.top_first("control-plane")
    if not cp:
        return ""
    policies = cp.all("service-policy input") + cp.all("service-policy output")
    return ", ".join(policies)


# --------------------------------------------------------------------------
# VRFs
# --------------------------------------------------------------------------


def extract_vrfs(tree: ConfigTree) -> list[dict[str, Any]]:
    vrfs: list[dict[str, Any]] = []
    for node in tree.top("vrf definition") + tree.top("ip vrf"):
        name = node.text.split()[-1] if node.text.startswith("vrf definition") or node.text.startswith("ip vrf") else ""
        rts_export, rts_import, families = [], [], []
        for child in node.walk():
            if child.text.startswith("route-target export"):
                rts_export.append(child.text.split()[-1])
            elif child.text.startswith("route-target import"):
                rts_import.append(child.text.split()[-1])
            elif child.text.startswith("route-target both"):
                rts_export.append(child.text.split()[-1])
                rts_import.append(child.text.split()[-1])
            elif child.text.startswith("address-family"):
                families.append(child.text.replace("address-family", "").strip())
        vrfs.append({
            "name": name,
            "description": node.get("description"),
            "rd": node.get("rd"),
            "route_targets_export": rts_export,
            "route_targets_import": rts_import,
            "address_families": families,
        })
    return vrfs


# --------------------------------------------------------------------------
# Interfaces
# --------------------------------------------------------------------------


def _ip_from(node: Node) -> tuple[str, list[str], str]:
    primary, secondary, mode = "", [], ""
    for child in node.find("ip address"):
        tokens = child.text.split()[2:]
        if not tokens:
            continue
        if tokens[0] in ("dhcp", "negotiated", "pool"):
            mode = tokens[0]
            continue
        if len(tokens) >= 2 and is_ipv4(tokens[0]):
            value = cidr(tokens[0], tokens[1])
            if "secondary" in tokens[2:]:
                secondary.append(value)
            else:
                primary = value
    return primary, secondary, mode


def _service_instances(node: Node) -> list[dict[str, str]]:
    out = []
    for child in node.find("service instance"):
        parts = child.text.split()
        out.append({
            "id": parts[2] if len(parts) > 2 else "",
            "kind": " ".join(parts[3:]),
            "encapsulation": child.get("encapsulation"),
            "rewrite": child.get("rewrite"),
            "bridge_domain": child.get("bridge-domain"),
        })
    return out


def _hsrp(node: Node) -> list[dict[str, Any]]:
    groups: dict[str, dict[str, Any]] = {}
    version = node.get("standby version")
    for child in node.find("standby"):
        parts = child.text.split()
        if len(parts) < 3 or not parts[1].isdigit():
            continue
        group = groups.setdefault(parts[1], {"group": parts[1], "ip": [], "priority": "", "preempt": False, "track": [], "auth": False, "version": version})
        sub = parts[2]
        if sub == "ip" and len(parts) > 3:
            group["ip"].append(parts[3] + (" secondary" if "secondary" in parts[4:] else ""))
        elif sub == "priority" and len(parts) > 3:
            group["priority"] = parts[3]
        elif sub == "preempt":
            group["preempt"] = True
        elif sub == "track" and len(parts) > 3:
            group["track"].append(" ".join(parts[3:]))
        elif sub == "authentication":
            group["auth"] = True
    return list(groups.values())


def _vrrp(node: Node) -> list[dict[str, Any]]:
    groups: dict[str, dict[str, Any]] = {}
    for child in node.find("vrrp"):
        parts = child.text.split()
        if len(parts) < 3 or not parts[1].isdigit():
            continue
        group = groups.setdefault(parts[1], {"group": parts[1], "ip": [], "priority": "", "preempt": True, "track": [], "auth": False})
        sub = parts[2]
        if sub == "ip" and len(parts) > 3:
            group["ip"].append(parts[3])
        elif sub == "priority" and len(parts) > 3:
            group["priority"] = parts[3]
        elif sub == "preempt":
            group["preempt"] = True
        elif sub == "no" and len(parts) > 3 and parts[3] == "preempt":
            group["preempt"] = False
        elif sub == "authentication":
            group["auth"] = True
    return list(groups.values())


def extract_interfaces(tree: ConfigTree) -> list[dict[str, Any]]:
    interfaces: list[dict[str, Any]] = []
    for node in tree.top("interface"):
        raw_name = node.text.split(None, 1)[1] if " " in node.text else ""
        primary, secondary, ip_mode = _ip_from(node)
        nat = ""
        if node.has("ip nat inside"):
            nat = "inside"
        elif node.has("ip nat outside"):
            nat = "outside"
        acl_in = acl_out = ""
        for child in node.find("ip access-group"):
            parts = child.text.split()
            if len(parts) >= 4 and parts[3] == "in":
                acl_in = parts[2]
            elif len(parts) >= 4 and parts[3] == "out":
                acl_out = parts[2]
        policy_in = node.get("service-policy input")
        policy_out = node.get("service-policy output")
        flow_monitors = []
        for child in node.find("ip flow monitor"):
            flow_monitors.append(child.text.replace("ip flow monitor", "").strip())
        ip_flow = [child.text.replace("ip flow", "").strip() for child in node.find("ip flow") if not child.text.startswith("ip flow monitor")]
        ospf: dict[str, str] = {}
        for key in ("cost", "priority", "network", "hello-interval", "dead-interval", "authentication", "message-digest-key", "authentication-key", "bfd"):
            value = node.get(f"ip ospf {key}")
            if value:
                ospf[key] = "<set>" if key in ("message-digest-key", "authentication-key") else value
        ospf_area = ""
        ospf_enable: dict[str, str] = {}
        for child in node.find("ip ospf"):
            m = re.match(r"ip ospf (\d+) area (\S+)", child.text)
            if m:
                ospf_area = f"{m.group(2)} (process {m.group(1)})"
                ospf_enable = {"process": m.group(1), "area": m.group(2)}
        if node.has("ip ospf bfd") and "bfd" not in ospf:
            ospf["bfd"] = "enabled"
        tunnel = {}
        for key in ("source", "destination", "mode", "protection", "key", "vrf"):
            value = node.get(f"tunnel {key}")
            if value:
                tunnel[key] = "<set>" if key == "key" else value
        switchport = {}
        if node.has("switchport"):
            switchport = {
                "mode": node.get("switchport mode"),
                "access_vlan": node.get("switchport access vlan"),
                "trunk_allowed": node.get("switchport trunk allowed vlan"),
            }
        interfaces.append({
            "name": canon(raw_name),
            "raw_name": raw_name,
            "description": node.get("description"),
            "vrf": node.get("vrf forwarding") or node.get("ip vrf forwarding"),
            "ip_address": primary,
            "ip_secondary": secondary,
            "ip_mode": ip_mode,
            "ip_unnumbered": node.get("ip unnumbered"),
            "ipv6": node.all("ipv6 address"),
            "shutdown": node.has("shutdown") and not node.has("no shutdown"),
            "bandwidth_kbps": node.get("bandwidth"),
            "mtu": node.get("mtu"),
            "ip_mtu": node.get("ip mtu"),
            "duplex": node.get("duplex"),
            "speed": node.get("speed"),
            "negotiation": node.get("negotiation"),
            "encapsulation": node.get("encapsulation"),
            "service_instances": _service_instances(node),
            "acl_in": acl_in,
            "acl_out": acl_out,
            "policy_in": policy_in,
            "policy_out": policy_out,
            "pbr_route_map": node.get("ip policy route-map"),
            "nat": nat,
            "crypto_map": node.get("crypto map"),
            "tunnel_protection": node.get("tunnel protection"),
            "zone_member": node.get("zone-member security"),
            "ip_inspect": node.get("ip inspect"),
            "ospf": ospf,
            "ospf_area": ospf_area,
            "ospf_enable": ospf_enable,
            "hsrp": _hsrp(node),
            "vrrp": _vrrp(node),
            "helpers": node.all("ip helper-address"),
            "flow_monitors": flow_monitors,
            "ip_flow": ip_flow,
            "tunnel": tunnel,
            "cdp": False if node.has("no cdp enable") else (True if node.has("cdp enable") else None),
            "lldp_transmit": False if node.has("no lldp transmit") else None,
            "no_ip_redirects": node.has("no ip redirects"),
            "no_ip_unreachables": node.has("no ip unreachables"),
            "no_proxy_arp": node.has("no ip proxy-arp"),
            "urpf": node.get("ip verify unicast"),
            "load_interval": node.get("load-interval"),
            "nbar": node.has("ip nbar protocol-discovery"),
            "switchport": switchport,
            "channel_group": node.get("channel-group"),
            "line": node.line,
        })
    return interfaces


# --------------------------------------------------------------------------
# Static routes
# --------------------------------------------------------------------------

_ROUTE_RE = re.compile(r"^ip route (?:vrf (?P<vrf>\S+) )?(?P<net>\d+\.\d+\.\d+\.\d+) (?P<mask>\d+\.\d+\.\d+\.\d+) (?P<rest>.+)$")


def extract_static_routes(tree: ConfigTree) -> list[dict[str, Any]]:
    routes: list[dict[str, Any]] = []
    for node in tree.top("ip route"):
        m = _ROUTE_RE.match(node.text)
        if not m:
            continue
        tokens = m.group("rest").split()
        next_hop = iface = name = tag = track = ""
        distance = ""
        permanent = False
        i = 0
        while i < len(tokens):
            token = tokens[i]
            if token == "name" and i + 1 < len(tokens):
                name = tokens[i + 1]
                i += 2
                continue
            if token == "tag" and i + 1 < len(tokens):
                tag = tokens[i + 1]
                i += 2
                continue
            if token == "track" and i + 1 < len(tokens):
                track = tokens[i + 1]
                i += 2
                continue
            if token == "permanent":
                permanent = True
            elif token == "global":
                pass
            elif is_ipv4(token) and not next_hop:
                next_hop = token
            elif _looks_like_interface(token) or token.lower().startswith("null"):
                iface = token
            elif token.isdigit() and (next_hop or iface):
                distance = token
            i += 1
        routes.append({
            "vrf": m.group("vrf") or "",
            "prefix": cidr(m.group("net"), m.group("mask")),
            "next_hop": next_hop,
            "interface": canon(iface) if iface else "",
            "distance": distance or "1",
            "name": name,
            "tag": tag,
            "track": track,
            "permanent": permanent,
            "discard": iface.lower().startswith("null") if iface else False,
        })
    for node in tree.top("ipv6 route"):
        parts = node.text.split()
        if len(parts) >= 4:
            routes.append({
                "vrf": parts[3] if len(parts) > 4 and parts[2] == "vrf" else "",
                "prefix": parts[-3] if parts[2] == "vrf" else parts[2],
                "next_hop": parts[-1],
                "interface": "",
                "distance": "1",
                "name": "",
                "tag": "",
                "track": "",
                "permanent": False,
                "discard": False,
            })
    return routes


# --------------------------------------------------------------------------
# Routing protocols
# --------------------------------------------------------------------------


def extract_ospf(tree: ConfigTree) -> list[dict[str, Any]]:
    processes: list[dict[str, Any]] = []
    for node in tree.top("router ospf"):
        parts = node.text.split()
        pid = parts[2] if len(parts) > 2 else ""
        vrf = parts[4] if len(parts) > 4 and parts[3] == "vrf" else ""
        networks = []
        for child in node.find("network"):
            m = re.match(r"network (\S+) (\S+) area (\S+)", child.text)
            if m:
                networks.append({"network": acl_addr(m.group(1), m.group(2)), "area": m.group(3), "address": m.group(1), "wildcard": m.group(2)})
        passive_default = node.has("passive-interface default")
        passive = [t for t in node.all("passive-interface") if t != "default"]
        active_exceptions = node.all("no passive-interface")
        areas = []
        for child in node.find("area"):
            areas.append(child.text.replace("area", "", 1).strip())
        process = {
            "process": pid,
            "vrf": vrf,
            "router_id": node.get("router-id"),
            "networks": networks,
            "passive_default": passive_default,
            "passive": passive,
            "active_exceptions": active_exceptions,
            "redistribute": node.all("redistribute"),
            "redistribute_detail": [ospfmod.parse_redistribute(t) for t in node.all("redistribute")],
            "default_originate": node.get("default-information originate"),
            "areas": areas,
            "auto_cost": node.get("auto-cost reference-bandwidth"),
            # IOS / IOS-XE log adjacency changes by default and do not print the line, so only an explicit 'no' is a finding
            "log_adjacency": False if node.has("no log-adjacency-changes") else (True if node.has("log-adjacency-changes") else None),
            "log_adjacency_detail": "detail" in node.get("log-adjacency-changes"),
            "bfd": node.has("bfd all-interfaces"),
            "max_paths": node.get("maximum-paths"),
            "summary": node.all("summary-address"),
            "authentication": node.get("area") if any("authentication" in a for a in areas) else "",
            "distribute_lists": node.all("distribute-list"),
            "timers": node.all("timers"),
            "nsf": node.has("nsf") or node.has("nsr"),
        }
        processes.append(process)
    return processes


def _tri(node, keyword: str):
    """True when ``keyword`` is configured, False when ``no keyword`` is, None
    when the running-config says nothing (the default depends on the IOS
    release, so absence must not be read as either)."""
    if node.has("no " + keyword):
        return False
    if node.has(keyword):
        return True
    return None


def extract_eigrp(tree: ConfigTree) -> list[dict[str, Any]]:
    out = []
    for node in tree.top("router eigrp"):
        parts = node.text.split()
        out.append({
            "process": parts[2] if len(parts) > 2 else "",
            "networks": node.all("network"),
            "passive": node.all("passive-interface"),
            "redistribute": node.all("redistribute"),
            "router_id": node.get("eigrp router-id"),
            "auto_summary": _tri(node, "auto-summary"),
            "address_families": [c.text for c in node.find("address-family")],
        })
    return out


def extract_other_igps(tree: ConfigTree) -> list[dict[str, Any]]:
    out = []
    for kind in ("router rip", "router isis", "router ospfv3", "router odr", "router lisp", "router omp"):
        for node in tree.top(kind):
            out.append({"protocol": node.text, "children": len(node.children), "lines": [c.text for c in node.children][:12]})
    return out


def _bgp_neighbor_rows(node: Node, neighbors: dict[str, dict[str, Any]], peer_groups: dict[str, dict[str, Any]], family: str) -> None:
    for child in node.find("neighbor"):
        parts = child.text.split()
        if len(parts) < 3:
            continue
        key = parts[1]
        rest = parts[2:]
        entry = neighbors.setdefault(key, _empty_neighbor(key))
        if rest[0] == "peer-group" and len(rest) == 1:
            peer_groups.setdefault(key, {})
            entry["is_peer_group"] = True
            continue
        if rest[0] == "peer-group" and len(rest) > 1:
            entry["peer_group"] = rest[1]
        elif rest[0] == "remote-as" and len(rest) > 1:
            entry["remote_as"] = rest[1]
        elif rest[0] == "description":
            entry["description"] = " ".join(rest[1:])
        elif rest[0] == "shutdown":
            entry["shutdown"] = True
        elif rest[0] == "activate":
            entry["families"].append(family or "ipv4 unicast")
        elif rest[0] == "route-map" and len(rest) >= 3:
            entry["route_map_in" if rest[2] == "in" else "route_map_out"] = rest[1]
        elif rest[0] == "prefix-list" and len(rest) >= 3:
            entry["prefix_list_in" if rest[2] == "in" else "prefix_list_out"] = rest[1]
        elif rest[0] == "filter-list" and len(rest) >= 3:
            entry["filter_list_in" if rest[2] == "in" else "filter_list_out"] = rest[1]
        elif rest[0] == "distribute-list" and len(rest) >= 3:
            entry["distribute_list_in" if rest[2] == "in" else "distribute_list_out"] = rest[1]
        elif rest[0] == "password":
            entry["password"] = True
        elif rest[0] == "ebgp-multihop":
            entry["ebgp_multihop"] = rest[1] if len(rest) > 1 else "255"
        elif rest[0] == "update-source" and len(rest) > 1:
            entry["update_source"] = rest[1]
        elif rest[0] == "next-hop-self":
            entry["next_hop_self"] = True
        elif rest[0] == "send-community":
            entry["send_community"] = " ".join(rest[1:]) or "standard"
        elif rest[0] == "soft-reconfiguration":
            entry["soft_reconfig"] = True
        elif rest[0] == "maximum-prefix" and len(rest) > 1:
            entry["maximum_prefix"] = rest[1]
        elif rest[0] == "weight" and len(rest) > 1:
            entry["weight"] = rest[1]
        elif rest[0] == "timers":
            entry["timers"] = " ".join(rest[1:])
        elif rest[0] == "ttl-security":
            entry["ttl_security"] = True
        elif rest[0] == "default-originate":
            entry["default_originate"] = True
        elif rest[0] == "remove-private-as":
            entry["remove_private_as"] = True
        elif rest[0] == "local-as" and len(rest) > 1:
            entry["local_as"] = rest[1]
        elif rest[0] == "fall-over":
            entry["fall_over_bfd"] = True
        elif rest[0] == "route-reflector-client":
            entry["rr_client"] = True


def _empty_neighbor(key: str) -> dict[str, Any]:
    return {
        "neighbor": key, "remote_as": "", "description": "", "shutdown": False, "families": [], "peer_group": "", "is_peer_group": False,
        "route_map_in": "", "route_map_out": "", "prefix_list_in": "", "prefix_list_out": "", "filter_list_in": "", "filter_list_out": "",
        "distribute_list_in": "", "distribute_list_out": "", "password": False, "ebgp_multihop": "", "update_source": "", "next_hop_self": False,
        "send_community": "", "soft_reconfig": False, "maximum_prefix": "", "weight": "", "timers": "", "ttl_security": False,
        "default_originate": False, "remove_private_as": False, "local_as": "", "fall_over_bfd": False, "rr_client": False, "vrf": "",
    }


def extract_bgp(tree: ConfigTree) -> list[dict[str, Any]]:
    processes: list[dict[str, Any]] = []
    for node in tree.top("router bgp"):
        asn = node.text.split()[2] if len(node.text.split()) > 2 else ""
        neighbors: dict[str, dict[str, Any]] = {}
        peer_groups: dict[str, dict[str, Any]] = {}
        networks: list[str] = []
        redistribute: list[str] = []
        aggregates: list[str] = []
        families: list[str] = []
        _bgp_neighbor_rows(node, neighbors, peer_groups, "")
        for child in node.find("network"):
            m = re.match(r"network (\S+)(?: mask (\S+))?(?: route-map (\S+))?", child.text)
            if m:
                networks.append((cidr(m.group(1), m.group(2)) if m.group(2) else m.group(1)) + (f" (route-map {m.group(3)})" if m.group(3) else ""))
        redistribute += node.all("redistribute")
        aggregates += node.all("aggregate-address")
        for family in node.find("address-family"):
            fam_name = family.text.replace("address-family", "").strip()
            families.append(fam_name)
            vrf = ""
            m = re.search(r"vrf (\S+)", fam_name)
            if m:
                vrf = m.group(1)
            before = set(neighbors)
            _bgp_neighbor_rows(family, neighbors, peer_groups, fam_name)
            for key in neighbors:
                if key not in before and vrf:
                    neighbors[key]["vrf"] = vrf
            for child in family.find("network"):
                m2 = re.match(r"network (\S+)(?: mask (\S+))?", child.text)
                if m2:
                    networks.append((cidr(m2.group(1), m2.group(2)) if m2.group(2) else m2.group(1)) + (f" [{vrf}]" if vrf else ""))
            redistribute += [r + (f" [{vrf}]" if vrf else "") for r in family.all("redistribute")]
        # inherit peer-group settings
        for entry in neighbors.values():
            group = neighbors.get(entry["peer_group"]) if entry["peer_group"] else None
            if group:
                for field_name, value in group.items():
                    if field_name in ("neighbor", "is_peer_group", "peer_group", "families", "description"):
                        continue
                    if value and not entry.get(field_name):
                        entry[field_name] = value
                        entry.setdefault("inherited", []).append(field_name)
        members = [e for e in neighbors.values() if not e["is_peer_group"]]
        for entry in members:
            entry["type"] = "iBGP" if entry["remote_as"] == asn else ("eBGP" if entry["remote_as"] else "")
        processes.append({
            "asn": asn,
            "router_id": node.get("bgp router-id"),
            "log_neighbor_changes": node.has("bgp log-neighbor-changes"),
            "synchronization": _tri(node, "synchronization"),
            "auto_summary": _tri(node, "auto-summary"),
            "default_local_pref": node.get("bgp default local-preference"),
            "max_paths": node.get("maximum-paths"),
            "neighbors": members,
            "peer_groups": [e for e in neighbors.values() if e["is_peer_group"]],
            "networks": networks,
            "redistribute": redistribute,
            "aggregates": aggregates,
            "families": families,
            "default_information": node.has("default-information originate"),
            "bestpath": node.all("bgp bestpath"),
            "graceful_restart": node.has("bgp graceful-restart"),
        })
    return processes


# --------------------------------------------------------------------------
# Routing policy objects
# --------------------------------------------------------------------------


def extract_route_maps(tree: ConfigTree) -> list[dict[str, Any]]:
    clauses = []
    for node in tree.top("route-map"):
        m = re.match(r"route-map (\S+)(?: (permit|deny))?(?: (\d+))?", node.text)
        if not m:
            continue
        clauses.append({
            "name": m.group(1),
            "action": m.group(2) or "permit",
            "seq": int(m.group(3)) if m.group(3) else 10,
            "match": [c.text[len("match "):] for c in node.find("match")],
            "set": [c.text[len("set "):] for c in node.find("set")],
            "continue": node.get("continue"),
            "description": node.get("description"),
            "line": node.line,
        })
    return clauses


_PL_RE = re.compile(r"^ip(?:v6)? prefix-list (\S+)(?: seq (\d+))? (permit|deny) (\S+)(.*)$")


def extract_prefix_lists(tree: ConfigTree) -> list[dict[str, Any]]:
    rows = []
    for node in tree.top("ip prefix-list") + tree.top("ipv6 prefix-list"):
        m = _PL_RE.match(node.text)
        if not m:
            continue
        opts = m.group(5).split()
        ge = le = ""
        for i, token in enumerate(opts):
            if token == "ge" and i + 1 < len(opts):
                ge = opts[i + 1]
            if token == "le" and i + 1 < len(opts):
                le = opts[i + 1]
        rows.append({"name": m.group(1), "seq": int(m.group(2)) if m.group(2) else 0, "action": m.group(3), "prefix": m.group(4), "ge": ge, "le": le,
                     "family": "ipv6" if node.text.startswith("ipv6") else "ipv4"})
    return rows


def extract_as_path_lists(tree: ConfigTree) -> list[dict[str, Any]]:
    rows = []
    for node in tree.top("ip as-path access-list"):
        m = re.match(r"ip as-path access-list (\S+) (permit|deny) (.*)$", node.text)
        if m:
            rows.append({"name": m.group(1), "action": m.group(2), "regex": m.group(3)})
    return rows


def extract_community_lists(tree: ConfigTree) -> list[dict[str, Any]]:
    rows = []
    for node in tree.top("ip community-list"):
        m = re.match(r"ip community-list (?:(standard|expanded) )?(\S+) (permit|deny) (.*)$", node.text)
        if m:
            rows.append({"name": m.group(2), "kind": m.group(1) or "numbered", "action": m.group(3), "communities": m.group(4)})
    return rows


# --------------------------------------------------------------------------
# ACLs
# --------------------------------------------------------------------------

_PROTO_WORDS = {"ip", "tcp", "udp", "icmp", "esp", "ahp", "ahd", "gre", "ospf", "eigrp", "pim", "igmp", "ipinip", "sctp", "pcp", "nos"}
_PORT_OPS = {"eq", "neq", "gt", "lt", "range"}


def _take_addr(tokens: list[str], i: int) -> tuple[str, int]:
    if i >= len(tokens):
        return "", i
    token = tokens[i]
    if token == "any":
        return "any", i + 1
    if token == "host" and i + 1 < len(tokens):
        return tokens[i + 1] + "/32", i + 2
    if token == "object-group" and i + 1 < len(tokens):
        return f"object-group {tokens[i + 1]}", i + 2
    if token == "addrgroup" and i + 1 < len(tokens):
        return f"addrgroup {tokens[i + 1]}", i + 2
    if is_ipv4(token):
        if i + 1 < len(tokens) and is_ipv4(tokens[i + 1]):
            return acl_addr(token, tokens[i + 1]), i + 2
        return token + "/32", i + 1
    return token, i + 1


def _take_ports(tokens: list[str], i: int) -> tuple[str, int]:
    if i < len(tokens) and tokens[i] in _PORT_OPS:
        op = tokens[i]
        if op == "range" and i + 2 < len(tokens):
            return f"range {tokens[i + 1]}-{tokens[i + 2]}", i + 3
        if i + 1 < len(tokens):
            j = i + 1
            values = [tokens[j]]
            # eq can list several ports
            while op in ("eq", "neq") and j + 1 < len(tokens) and (tokens[j + 1].isdigit() or tokens[j + 1].isalpha()) and tokens[j + 1] not in ("log", "log-input", "established", "established", "reflect", "time-range", "dscp", "precedence", "fragments", "ttl", "any", "host") and not is_ipv4(tokens[j + 1]) and tokens[j + 1] not in _PORT_OPS and tokens[j + 1] not in _PROTO_WORDS:
                j += 1
                values.append(tokens[j])
            return f"{op} {' '.join(values)}", j + 1
    return "", i


def parse_ace(text: str, standard: bool = False) -> dict[str, Any]:
    """Parse one access-list entry (without the ``access-list N`` prefix)."""
    tokens = text.split()
    seq = ""
    if tokens and tokens[0].isdigit():
        seq = tokens.pop(0)
    if not tokens:
        return {"seq": seq, "action": "", "protocol": "", "source": "", "src_port": "", "destination": "", "dst_port": "", "options": "", "text": text}
    action = tokens[0]
    if action == "remark":
        return {"seq": seq, "action": "remark", "protocol": "", "source": "", "src_port": "", "destination": "", "dst_port": "", "options": " ".join(tokens[1:]), "text": text}
    if action not in ("permit", "deny", "evaluate"):
        return {"seq": seq, "action": action, "protocol": "", "source": "", "src_port": "", "destination": "", "dst_port": "", "options": " ".join(tokens[1:]), "text": text}
    i = 1
    protocol = ""
    if standard:
        src, i = _take_addr(tokens, i)
        return {"seq": seq, "action": action, "protocol": "ip", "source": src, "src_port": "", "destination": "any", "dst_port": "", "options": " ".join(tokens[i:]), "text": text}
    if i < len(tokens):
        protocol = tokens[i]
        i += 1
    src, i = _take_addr(tokens, i)
    src_port, i = _take_ports(tokens, i)
    dst, i = _take_addr(tokens, i)
    dst_port, i = _take_ports(tokens, i)
    options = " ".join(tokens[i:])
    return {"seq": seq, "action": action, "protocol": protocol, "source": src, "src_port": src_port, "destination": dst, "dst_port": dst_port, "options": options, "text": text}


def extract_acls(tree: ConfigTree) -> list[dict[str, Any]]:
    """All IPv4 ACLs from the configuration, named and numbered."""
    acls: dict[str, dict[str, Any]] = {}
    order: list[str] = []

    def get(name: str, kind: str) -> dict[str, Any]:
        if name not in acls:
            acls[name] = {"name": name, "kind": kind, "entries": [], "family": "ipv4", "line": 0}
            order.append(name)
        return acls[name]

    for node in tree.top("ip access-list") + tree.top("ipv6 access-list"):
        parts = node.text.split()
        family = "ipv6" if parts[0] == "ipv6" else "ipv4"
        if family == "ipv4" and len(parts) >= 4 and parts[2] in ("standard", "extended", "resequence"):
            kind, name = parts[2], parts[3]
        else:
            kind, name = ("extended", parts[-1])
        acl = get(name, kind)
        acl["family"] = family
        acl["line"] = node.line
        for child in node.children:
            entry = parse_ace(child.text, standard=(kind == "standard"))
            acl["entries"].append(entry)
    for node in tree.top("access-list"):
        parts = node.text.split(None, 2)
        if len(parts) < 3:
            continue
        name = parts[1]
        number = int(name) if name.isdigit() else 0
        kind = "standard" if (1 <= number <= 99 or 1300 <= number <= 1999) else "extended"
        acl = get(name, kind)
        acl["line"] = acl["line"] or node.line
        acl["entries"].append(parse_ace(parts[2], standard=(kind == "standard")))
    return [acls[name] for name in order]


# --------------------------------------------------------------------------
# QoS (class-map / policy-map)
# --------------------------------------------------------------------------


def extract_class_maps(tree: ConfigTree) -> list[dict[str, Any]]:
    out = []
    for node in tree.top("class-map"):
        parts = node.text.split()
        kind = "qos"
        idx = 1
        if parts[1] == "type":
            kind = parts[2]
            idx = 3
        mode = parts[idx] if idx < len(parts) and parts[idx] in ("match-any", "match-all") else "match-all"
        name = parts[-1]
        out.append({
            "name": name,
            "kind": kind,
            "mode": mode,
            "matches": [c.text[len("match "):] for c in node.find("match")],
            "acl_refs": [m.split()[-1] for m in (c.text[len("match "):] for c in node.find("match")) if m.startswith("access-group")],
            "description": node.get("description"),
        })
    return out


def extract_policy_maps(tree: ConfigTree) -> list[dict[str, Any]]:
    out = []
    for node in tree.top("policy-map"):
        parts = node.text.split()
        kind = "qos"
        if len(parts) > 2 and parts[1] == "type":
            kind = parts[2]
        name = parts[-1]
        classes = []
        for child in node.find("class"):
            cparts = child.text.split()
            if len(cparts) > 2 and cparts[1] == "type":
                cname = cparts[-1]
            else:
                cname = cparts[-1]
            actions = [c.text for c in child.children]
            classes.append({"class": cname, "actions": actions})
        out.append({"name": name, "kind": kind, "classes": classes, "description": node.get("description")})
    return out


# --------------------------------------------------------------------------
# Crypto / VPN
# --------------------------------------------------------------------------

def _storage_of(type_code: str | None) -> tuple[str, str]:
    if type_code in (None, "", "0"):
        return ("clear text", "weak")
    return secret_strength(type_code)


_ISAKMP_DEFAULTS = {"encryption": "des", "hash": "sha", "authentication": "rsa-sig", "group": "1", "lifetime": "86400"}


def extract_crypto(tree: ConfigTree) -> dict[str, Any]:
    policies = []
    for node in tree.top("crypto isakmp policy"):
        number = node.text.split()[-1]
        values = dict(_ISAKMP_DEFAULTS)
        defaults = set(values)
        for child in node.children:
            parts = child.text.split()
            if parts[0] == "encr" or parts[0] == "encryption":
                values["encryption"] = " ".join(parts[1:])
                defaults.discard("encryption")
            elif parts[0] == "hash":
                values["hash"] = parts[1] if len(parts) > 1 else ""
                defaults.discard("hash")
            elif parts[0] == "authentication":
                values["authentication"] = parts[1] if len(parts) > 1 else ""
                defaults.discard("authentication")
            elif parts[0] == "group":
                values["group"] = parts[1] if len(parts) > 1 else ""
                defaults.discard("group")
            elif parts[0] == "lifetime":
                values["lifetime"] = parts[1] if len(parts) > 1 else ""
                defaults.discard("lifetime")
        policies.append({"priority": number, **values, "defaults": sorted(defaults)})

    salt = os.urandom(16)   # keyed-hash salt for the "same key on several peers" check; never stored
    keys = []
    for node in tree.top("crypto isakmp key"):
        parts = node.text.split()
        # crypto isakmp key [0|6] KEY address X [mask] | hostname H
        idx = 3
        key_type = None
        if len(parts) > idx and parts[idx] in ("0", "6"):
            key_type = parts[idx]
            idx += 1
        secret = parts[idx] if idx < len(parts) else ""
        idx += 1  # the key itself -- never stored
        peer = " ".join(parts[idx:]) if idx < len(parts) else ""
        desc, strength = secret_strength(key_type) if key_type == "6" else ("clear text" if key_type in (None, "0") else "?", "weak" if key_type in (None, "0") else "ok")
        address = peer.replace("address ", "", 1).strip() if peer.startswith("address ") else ("host " + peer.replace("hostname ", "", 1).strip())
        keys.append({"peer": peer.replace("address ", "").replace("hostname ", "host "), "storage": desc, "strength": strength, "address": address,
                     "token": ipsecmod.psk_token(salt, secret) if secret else "", "source": "crypto isakmp key"})
    for node in tree.top("crypto keyring"):
        ring = node.text.split()[-1]
        for child in node.find("pre-shared-key"):
            parts = child.text.split()
            # pre-shared-key address A [mask] key [0|6|7] K   |   hostname H key K
            if "key" in parts:
                at = parts.index("key")
                rest = parts[at + 1:]
                key_type = rest[0] if len(rest) > 1 and rest[0] in ("0", "6", "7") else None
                secret = rest[1] if key_type else (rest[0] if rest else "")
                where = " ".join(parts[1:at]).replace("address ", "", 1)
                desc, strength = _storage_of(key_type)
                keys.append({"peer": where, "storage": desc, "strength": strength, "address": where, "token": ipsecmod.psk_token(salt, secret) if secret else "", "source": f"crypto keyring {ring}"})

    gdoi = []
    for node in tree.top("crypto gdoi group"):
        gdoi.append({
            "group": node.text.split()[-1],
            "identity": node.get("identity number"),
            "key_servers": node.all("server address ipv4"),
            "registration_interface": node.get("client registration interface"),
            "rekey_authenticate": node.has("client rekey authenticate"),
            "rekey_transport": node.get("client rekey transport"),
            "children": len(node.children),
        })

    maps: dict[str, dict[str, Any]] = {}
    for node in tree.top("crypto map"):
        parts = node.text.split()
        if len(parts) < 3:
            continue
        name = parts[2]
        entry = maps.setdefault(name, {"name": name, "local_address": "", "entries": []})
        if parts[3:4] == ["local-address"]:
            entry["local_address"] = parts[4] if len(parts) > 4 else ""
            continue
        if len(parts) >= 5 and parts[3].isdigit():
            entry["entries"].append(ipsecmod.extract_map_entry(node, parts))

    transform_sets = []
    for node in tree.top("crypto ipsec transform-set"):
        parts = node.text.split()
        transform_sets.append({"name": parts[3] if len(parts) > 3 else "", "transforms": " ".join(parts[4:]), "mode": node.get("mode")})
    profiles = []
    for node in tree.top("crypto ipsec profile"):
        profiles.append({"name": node.text.split()[-1], "transform_sets": node.all("set transform-set"), "pfs": node.get("set pfs"), "ikev2_profile": node.get("set ikev2-profile")})

    ikev2 = ipsecmod.extract_ikev2(tree, salt)
    return {
        "isakmp_policies": policies,
        "isakmp_keys": keys,
        "isakmp_keepalive": tree.get("crypto isakmp keepalive"),
        "gdoi_groups": gdoi,
        "crypto_maps": list(maps.values()),
        "transform_sets": transform_sets,
        "ipsec_profiles": profiles,
        "ikev2": ikev2,
        "trustpoints": [n.text.split()[-1] for n in tree.top("crypto pki trustpoint")],
        "key_config_key": tree.has("key config-key password-encrypt"),
        "password_encryption_aes": tree.has("password encryption aes"),
        "sa_lifetime": tree.get("crypto ipsec security-association lifetime"),
        "aggressive_mode_disabled": tree.has("crypto isakmp aggressive-mode disable"),
        "dynamic_maps": [n.text.split()[3] for n in tree.top("crypto dynamic-map") if len(n.text.split()) > 3],
    }


# --------------------------------------------------------------------------
# Management plane: AAA, users, lines, SNMP, logging, NTP
# --------------------------------------------------------------------------

_GUESSABLE_COMMUNITIES = {"public", "private", "cisco", "test", "snmp", "snmpd", "default", "secret", "admin", "community", "manager", "monitor", "write", "read"}


def extract_aaa(tree: ConfigTree) -> dict[str, Any]:
    methods = []
    for node in tree.top("aaa authentication") + tree.top("aaa authorization") + tree.top("aaa accounting"):
        parts = node.text.split()
        methods.append({
            "kind": " ".join(parts[:3]),
            "list": parts[3] if len(parts) > 3 else "",
            "methods": " ".join(parts[4:]) if len(parts) > 4 else " ".join(c.text for c in node.children),
        })
    groups = []
    for node in tree.top("aaa group server"):
        parts = node.text.split()
        servers = [c.text.split()[1] for c in node.children if c.text.startswith(("server-private", "server "))]
        groups.append({"kind": parts[3] if len(parts) > 3 else "", "name": parts[4] if len(parts) > 4 else "", "servers": servers,
                       "vrf": node.get("ip vrf forwarding"), "source": node.get("ip tacacs source-interface") or node.get("ip radius source-interface")})
    tacacs = []
    for node in tree.top("tacacs server") + tree.top("radius server"):
        tacacs.append({
            "kind": node.text.split()[0], "name": node.text.split()[-1], "address": node.get("address ipv4") or node.get("address"),
            "key": bool(node.first("key")), "key_type": (node.get("key").split()[0] if node.get("key") and node.get("key").split()[0].isdigit() else ""),
        })
    for node in tree.top("tacacs-server host") + tree.top("radius-server host"):
        parts = node.text.split()
        tacacs.append({"kind": parts[0].split("-")[0] + " (legacy)", "name": "", "address": parts[2] if len(parts) > 2 else "", "key": "key" in parts, "key_type": ""})
    legacy_key = tree.top_first("tacacs-server key") or tree.top_first("radius-server key")
    if legacy_key:
        parts = legacy_key.text.split()
        key_type = parts[2] if len(parts) > 3 and parts[2].isdigit() else None
        for t in tacacs:
            if "legacy" in t["kind"]:
                t["key"] = True
                t["key_type"] = key_type or "0"
    return {"new_model": tree.has("aaa new-model"), "methods": methods, "groups": groups, "servers": tacacs,
            "session_id": tree.get("aaa session-id")}


def extract_users(tree: ConfigTree) -> list[dict[str, Any]]:
    users = []
    for node in tree.top("username"):
        parts = node.text.split()
        if len(parts) < 2:
            continue
        name = parts[1]
        privilege = ""
        secret_kind = ""
        stype: str | None = None
        for i, token in enumerate(parts):
            if token == "privilege" and i + 1 < len(parts):
                privilege = parts[i + 1]
            if token in ("password", "secret") and i + 1 < len(parts):
                secret_kind = token
                nxt = parts[i + 1]
                stype = nxt if nxt in ("0", "5", "6", "7", "8", "9") and i + 2 < len(parts) else None
        desc, strength = secret_strength(stype) if secret_kind else ("no password", "none")
        if secret_kind == "password" and stype in (None,):
            desc, strength = "clear text", "weak"
        users.append({"user": name, "privilege": privilege or "1", "credential": secret_kind or "none", "storage": desc, "strength": strength})
    return users


def extract_lines(tree: ConfigTree) -> list[dict[str, Any]]:
    out = []
    for node in tree.top("line"):
        parts = node.text.split()
        kind = parts[1] if len(parts) > 1 else ""
        rng = " ".join(parts[2:])
        pw = node.first("password")
        pw_type = None
        if pw:
            p = pw.text.split()
            pw_type = p[1] if len(p) > 2 and p[1].isdigit() else None
        pw_desc = secret_strength(pw_type)[0] if pw else ""
        acl = node.get("access-class")
        out.append({
            "line": f"{kind} {rng}".strip(),
            "transport_input": node.get("transport input") or "(default)",
            "transport_output": node.get("transport output"),
            "access_class": acl,
            "exec_timeout": node.get("exec-timeout"),
            "login": node.get("login") or ("(local line password)" if pw else ""),
            "password": pw_desc,
            "privilege": node.get("privilege level"),
            "authorization": node.get("authorization exec"),
            "accounting": node.get("accounting exec"),
            "logging_sync": node.has("logging synchronous"),
        })
    return out


def extract_snmp(tree: ConfigTree) -> dict[str, Any]:
    communities = []
    for index, node in enumerate(tree.top("snmp-server community"), start=1):
        parts = node.text.split()
        name = parts[2] if len(parts) > 2 else ""
        rest = parts[3:]
        mode = next((x for x in rest if x.upper() in ("RO", "RW")), "")
        acl = ""
        view = ""
        for i, token in enumerate(rest):
            if token == "view" and i + 1 < len(rest):
                view = rest[i + 1]
        tail = [x for x in rest if x.upper() not in ("RO", "RW") and x != "view" and x != view]
        if tail:
            acl = tail[-1]
        communities.append({
            "index": index, "mode": mode.upper(), "acl": acl, "view": view,
            "guessable": name.lower() in _GUESSABLE_COMMUNITIES, "length": len(name),
        })
    groups = []
    for node in tree.top("snmp-server group"):
        parts = node.text.split()
        groups.append({"name": parts[2] if len(parts) > 2 else "", "version": parts[3] if len(parts) > 3 else "", "level": parts[4] if len(parts) > 4 else "",
                       "detail": " ".join(parts[5:])})
    users = []
    for node in tree.top("snmp-server user"):
        parts = node.text.split()
        users.append({"user": parts[2] if len(parts) > 2 else "", "group": parts[3] if len(parts) > 3 else "", "version": parts[4] if len(parts) > 4 else "",
                      "auth": "sha" if "sha" in parts else ("md5" if "md5" in parts else ""), "priv": next((parts[i + 1] for i, x in enumerate(parts) if x == "priv" and i + 1 < len(parts)), "")})
    hosts = []
    for node in tree.top("snmp-server host"):
        parts = node.text.split()
        host = parts[2] if len(parts) > 2 else ""
        vrf = ""
        version = ""
        level = ""
        i = 3
        while i < len(parts):
            if parts[i] == "vrf" and i + 1 < len(parts):
                vrf = parts[i + 1]
                i += 2
                continue
            if parts[i] == "version" and i + 1 < len(parts):
                version = parts[i + 1]
                i += 2
                if i < len(parts) and parts[i] in ("auth", "priv", "noauth"):
                    level = parts[i]
                    i += 1
                continue
            i += 1
        hosts.append({"host": host, "vrf": vrf, "version": version, "level": level})
    traps = [n.text for n in tree.top("snmp-server enable traps")]
    return {
        "communities": communities, "groups": groups, "users": users, "hosts": hosts, "trap_lines": len(traps),
        "trap_source": tree.get("snmp-server trap-source") or tree.get("snmp-server source-interface traps"),
        "location": bool(tree.get("snmp-server location")), "contact": bool(tree.get("snmp-server contact")),
        "views": [n.text.replace("snmp-server view", "").strip() for n in tree.top("snmp-server view")],
    }


def extract_logging(tree: ConfigTree) -> dict[str, Any]:
    hosts = []
    for node in tree.top("logging host"):
        parts = node.text.split()
        hosts.append(parts[2] if len(parts) > 2 else "")
    for node in tree.top("logging"):
        parts = node.text.split()
        if len(parts) > 1 and is_ipv4(parts[1]):
            hosts.append(parts[1])
    return {
        "hosts": hosts,
        "buffered": tree.get("logging buffered"),
        "console": tree.get("logging console"),
        "monitor": tree.get("logging monitor"),
        "trap": tree.get("logging trap"),
        "source": tree.get("logging source-interface"),
        "facility": tree.get("logging facility"),
        "persistent": tree.get("logging persistent"),
        "userinfo": tree.has("logging userinfo"),
        "no_console": tree.has("no logging console"),
        "no_monitor": tree.has("no logging monitor"),
    }


def extract_ntp(tree: ConfigTree) -> dict[str, Any]:
    servers = []
    for node in tree.top("ntp server"):
        parts = node.text.split()
        rest = parts[2:]
        vrf = ""
        if rest and rest[0] == "vrf" and len(rest) > 1:
            vrf = rest[1]
            rest = rest[2:]
        address = rest[0] if rest else ""
        servers.append({
            "server": address, "vrf": vrf, "prefer": "prefer" in rest,
            "source": next((rest[i + 1] for i, x in enumerate(rest) if x == "source" and i + 1 < len(rest)), ""),
            "key": next((rest[i + 1] for i, x in enumerate(rest) if x == "key" and i + 1 < len(rest)), ""),
            "version": next((rest[i + 1] for i, x in enumerate(rest) if x == "version" and i + 1 < len(rest)), ""),
        })
    return {
        "servers": servers, "authenticate": tree.has("ntp authenticate"), "source": tree.get("ntp source"),
        "access_groups": tree.all("ntp access-group"), "master": tree.has("ntp master"),
        "auth_keys": len(tree.top("ntp authentication-key")), "trusted_keys": tree.all("ntp trusted-key"),
    }


# --------------------------------------------------------------------------
# Services: NAT, IP SLA/track, NetFlow, ZBF, EEM, DHCP
# --------------------------------------------------------------------------


def extract_nat(tree: ConfigTree) -> dict[str, Any]:
    rules = []
    for node in tree.top("ip nat"):
        parts = node.text.split()
        if len(parts) < 3:
            continue
        if parts[2] in ("inside", "outside") and len(parts) > 3 and parts[3] in ("source", "destination"):
            rules.append({"kind": f"{parts[2]} {parts[3]}", "detail": " ".join(parts[4:])})
        elif parts[2] == "pool":
            rules.append({"kind": "pool", "detail": " ".join(parts[3:])})
        elif parts[2] == "route":
            rules.append({"kind": "nat route", "detail": " ".join(parts[3:])})
    return {"rules": rules, **natmod.extract(tree)}


def extract_sla_track(tree: ConfigTree) -> dict[str, Any]:
    slas = []
    schedules = {n.text.split()[3] for n in tree.top("ip sla schedule") if len(n.text.split()) > 3}
    for node in tree.top("ip sla"):
        parts = node.text.split()
        if len(parts) < 3 or not parts[2].isdigit():
            continue
        if parts[2] in schedules and node.text.startswith("ip sla schedule"):
            continue
        operation = ""
        target = ""
        for child in node.children:
            first = child.text.split()[0]
            if first in ("icmp-echo", "tcp-connect", "udp-jitter", "udp-echo", "http", "dns", "path-jitter", "icmp-jitter", "dhcp", "ftp"):
                operation = first
                target = child.text[len(first):].strip()
        slas.append({
            "id": parts[2], "operation": operation, "target": target,
            "frequency": node.get("frequency"), "timeout": node.get("timeout"), "threshold": node.get("threshold"),
            "scheduled": parts[2] in schedules,
        })
    tracks = []
    for node in tree.top("track"):
        parts = node.text.split()
        if len(parts) < 3 or not parts[1].isdigit():
            continue
        tracks.append({"id": parts[1], "object": " ".join(parts[2:]), "delay": node.get("delay"), "children": [c.text for c in node.children]})
    return {"ip_sla": slas, "tracks": tracks}


def extract_netflow(tree: ConfigTree) -> dict[str, Any]:
    exporters = []
    for node in tree.top("flow exporter"):
        exporters.append({"name": node.text.split()[-1], "destination": node.get("destination"), "transport": node.get("transport"),
                          "source": node.get("source"), "version": node.get("export-protocol") or node.get("template data timeout")})
    monitors = [{"name": n.text.split()[-1], "exporter": n.get("exporter"), "record": n.get("record")} for n in tree.top("flow monitor")]
    records = [{"name": n.text.split()[-1], "matches": len(n.find("match")), "collects": len(n.find("collect"))} for n in tree.top("flow record")]
    legacy = {
        "destinations": tree.all("ip flow-export destination"),
        "version": tree.get("ip flow-export version"),
        "source": tree.get("ip flow-export source"),
        "top_talkers": tree.has("ip flow-top-talkers"),
        "cache_active_timeout": tree.get("ip flow-cache timeout active"),
    }
    return {"exporters": exporters, "monitors": monitors, "records": records, "legacy": legacy}


def extract_zbf(tree: ConfigTree) -> dict[str, Any]:
    zones = [n.text.split()[-1] for n in tree.top("zone security")]
    pairs = []
    for node in tree.top("zone-pair security"):
        m = re.match(r"zone-pair security (\S+) source (\S+) destination (\S+)", node.text)
        if m:
            pairs.append({"name": m.group(1), "source": m.group(2), "destination": m.group(3), "policy": node.get("service-policy type inspect")})
    return {"zones": zones, "zone_pairs": pairs, "ip_inspect": [n.text for n in tree.top("ip inspect")]}


def extract_eem(tree: ConfigTree) -> list[dict[str, Any]]:
    out = []
    for node in tree.top("event manager applet"):
        events = [c.text for c in node.children if c.text.startswith("event")]
        actions = [c.text for c in node.children if c.text.startswith("action")]
        out.append({"name": node.text.split()[3] if len(node.text.split()) > 3 else node.text, "events": events, "actions": len(actions),
                    "touches_routing": any(re.search(r"ip route|route-map|ip policy", a) for a in actions)})
    return out


def extract_dhcp(tree: ConfigTree) -> dict[str, Any]:
    pools = []
    for node in tree.top("ip dhcp pool"):
        pools.append({"name": node.text.split()[-1], "network": node.get("network"), "default_router": node.get("default-router"), "dns": node.get("dns-server")})
    return {"pools": pools, "excluded": tree.all("ip dhcp excluded-address"), "relay_disabled": tree.has("no service dhcp")}


def extract_misc(tree: ConfigTree) -> dict[str, Any]:
    return {
        "ip_hosts": tree.all("ip host"),
        "multicast_routing": tree.has("ip multicast-routing"),
        "mpls": tree.has("mpls ip") or any(n.has("mpls ip") for n in tree.top("interface")),
        "pim": any(n.has("ip pim") for n in tree.top("interface")),
        "stun": tree.all("stun peer-name") + tree.all("stun protocol-group"),
        "dialer_watch": tree.all("dialer watch-list"),
        "voice": tree.has("voice-card 0") or tree.has("voice service voip"),
        "archive": [c.text for n in tree.top("archive") for c in n.children],
        "ip_classless": _flag(tree, "ip classless"),
        "ip_cef": _flag(tree, "ip cef"),
    }


def extract_config(tree: ConfigTree) -> dict[str, Any]:
    """One call that runs every extractor."""
    return {
        "system": extract_system(tree),
        "vrfs": extract_vrfs(tree),
        "interfaces": extract_interfaces(tree),
        "static_routes": extract_static_routes(tree),
        "ospf": extract_ospf(tree),
        "eigrp": extract_eigrp(tree),
        "other_igps": extract_other_igps(tree),
        "bgp": extract_bgp(tree),
        "route_maps": extract_route_maps(tree),
        "prefix_lists": extract_prefix_lists(tree),
        "as_path_lists": extract_as_path_lists(tree),
        "community_lists": extract_community_lists(tree),
        "acls": extract_acls(tree),
        "class_maps": extract_class_maps(tree),
        "policy_maps": extract_policy_maps(tree),
        "crypto": extract_crypto(tree),
        "aaa": extract_aaa(tree),
        "users": extract_users(tree),
        "lines": extract_lines(tree),
        "snmp": extract_snmp(tree),
        "logging": extract_logging(tree),
        "ntp": extract_ntp(tree),
        "nat": extract_nat(tree),
        "sla_track": extract_sla_track(tree),
        "netflow": extract_netflow(tree),
        "zbf": extract_zbf(tree),
        "eem": extract_eem(tree),
        "dhcp": extract_dhcp(tree),
        "misc": extract_misc(tree),
    }
