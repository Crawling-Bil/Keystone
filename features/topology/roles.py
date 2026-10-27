"""Role and tier of each node: from the hostname words, the model, the CDP/LLDP capabilities, then the graph shape.

Tiers (top to bottom): 0 wan/internet edge, 1 core, 2 aggregation/distribution, 3 access, 4 endpoints.
"""

from __future__ import annotations

import re

from .graph import Graph

ROLE_TIER = {"cloud": 0, "router": 0, "firewall": 1, "loadbalancer": 1, "core": 1, "aggregation": 2, "switch": 3, "access": 3,
             "wlc": 3, "fabric": 4, "ap": 4, "phone": 4, "server": 4, "host": 4, "segment": 3}
# what the label under an icon says when the device reports no model
ROLE_LABEL = {"cloud": "Provider / WAN", "router": "Router", "firewall": "Firewall", "loadbalancer": "Load balancer", "core": "Core switch",
              "aggregation": "L3 switch", "switch": "Switch", "access": "Access switch", "wlc": "Wireless controller", "fabric": "Fabric interconnect",
              "ap": "Access point", "phone": "IP phone", "server": "Server", "host": "Host"}
NETWORK_ROLES = {"cloud", "router", "firewall", "loadbalancer", "core", "aggregation", "switch", "access", "wlc", "fabric", "ap"}
ICONS = {"cloud": "cloud", "router": "router", "firewall": "firewall", "loadbalancer": "load_balancer", "core": "l3_switch", "aggregation": "l3_switch",
         "switch": "l2_switch", "access": "l2_switch", "wlc": "wireless_lan_controller", "ap": "ap", "phone": "phone",
         "fabric": "l2_switch", "server": "server", "host": "host"}

_WORD_RULES = (
    ("firewall", r"(^|[-_])(FW|FWL|FIREWALL|NGFW|PA|FG|FGT|ASA|FTD|INETFW|NSF)\d*([-_]|$)"),
    ("loadbalancer", r"(^|[-_])(LB|SLB|GSLB|LTM|GTM|ADC|BIGIP|BIG-IP|F5|NETSCALER)\d*([-_]|$)"),
    ("router", r"(^|[-_])(RT|RTR|RTR\d|ROU|ROUTER|WANRT|SDW-?RT|CE|PE|ISR|ASR)\d*([-_]|$)|SDW-RT"),
    ("wlc", r"(^|[-_])(WLC|WC)\d*([-_]|$)"),
    ("ap", r"(^|[-_])(AP|APS|WAP)\d*([-_]|$)"),
    ("fabric", r"(^|[-_])FI[-_]|^FI\d|UCS-FI|(^|[-_])UCS[-_]?FI"),
    ("server", r"(^|[-_])(FI|UCS|SRV|SERVER|ESX|ESXI|HV)\d*([-_]|$)|^FI-"),
    ("core", r"(^|[-_])(CORE|CR|SPINE|BACKBONE)\d*([-_]|$)"),
    ("aggregation", r"(^|[-_])(AGG|AGGR|DS|DIST|DISTRIBUTION|EDGE|EXT)\d*([-_]|$)"),
    ("access", r"(^|[-_])(TOR|ACC|ACCESS|LAN|SW|MGT|MGMT|AS)\d*[A-Z]?([-_]|$)"),
)
_MODEL_RULES = (
    ("firewall", r"^(PA-|FG|FORTIGATE|ASA|FPR|FIREPOWER|NSF|USG|SRX)"),
    ("loadbalancer", r"^(BIG-?IP|F5-|VIPRION|ADC-|NETSCALER)"),
    ("router", r"^(ISR|ASR|C8[0-9]{3}|CSR|ISR4|NCS|MX|AR[0-9])"),
    ("fabric", r"^UCS-FI"),
    ("wlc", r"(AIR-CT|C9800|WLC|AC6|AC66)"),
    ("ap", r"(^AIR-[A-Z]*AP|^C91[0-9]{2}AX|^CW9|AIR-AP|APS|AP-[0-9])"),
    ("phone", r"(IP Phone|CP-[0-9])"),
    ("core", r"^(N9K-C95|N7K|N77|C95[0-9]{2}|S12|S77|CE128|CE68)"),
    ("aggregation", r"^(N9K-C93|N9K-C92|N5K|N3K|C3850|C3750)"),
    ("access", r"^(C92|C93|C2960|C1000|C3560|C2960|WS-C|S53|S57|S67|CE5)"),
    ("switch", r"^(HPE ANW |ARUBA |HP )?(JL|JH|J[0-9]{4}|R[0-9]{4}|Q[0-9]{4})[0-9A-Z]*\b|^(HPE ANW|ARUBA|HP ProCurve|PROCURVE)"),
)
_CAP_WORDS = (("ap", r"Trans-Bridge|WLAN|Access Point|Wireless"), ("phone", r"Phone"), ("router", r"\bRouter\b"),
              ("switch", r"Switch|Bridge"))


def role_from_caps(caps: str) -> str:
    """Role named by CDP / LLDP capability words.  A device that advertises Router and Bridge/Switch together is a layer-3 switch
    (AOS-CX, Catalyst and VRP all do), not a router; a router that also lists Source-Route-Bridge (the Cisco ISR style) stays a router."""
    text = caps or ""
    if re.search(r"(?i:Trans-Bridge|WLAN|Access Point|Wireless)|\bW\b", text):
        return "ap"
    if re.search(r"(?i:Phone)", text) and not re.search(r"(?i:Router|Switch)", text):
        return "phone"
    router = bool(re.search(r"(?i:\brouter\b)|\bR\b", text))
    bridge = bool(re.search(r"(?i:switch|(?<!Source-Route-)\bbridge\b)|\bB\b|\bS\b", text))
    if router and re.search(r"(?i:Source-Route-Bridge)", text):
        return "router"
    if router and bridge:
        return "switch"
    return "router" if router else "switch" if bridge else ""


def _by_rules(rules, text: str) -> str:
    for role, pattern in rules:
        if re.search(pattern, text, re.I):
            return role
    return ""


def classify(graph: Graph) -> None:
    degree = {key: 0 for key in graph.nodes}
    for conn in graph.connections:
        degree[conn.a] += 1
        degree[conn.b] += 1
    for key, node in graph.nodes.items():
        if node.role_hint == "cloud" and not node.captured:
            continue                                       # a provider named by a port description keeps its cloud icon
        if node.role_hint in ("firewall", "loadbalancer") and node.vendor:
            continue                                       # a FortiGate / PAN-OS / BIG-IP reader knows what the box is, whatever it is called (HQPAIBFW1)
        by_name = _by_rules(_WORD_RULES, node.hostname.upper())
        node.role_from_name = bool(by_name)  # type: ignore[attr-defined]
        role = by_name or _by_rules(_MODEL_RULES, node.model.upper())
        if not role and node.caps:
            role = role_from_caps(node.caps)
        if not role:
            role = "switch" if node.captured else "host"
        if role in ("access", "switch") and node.vpc_domain and degree[key] >= 8 and not by_name:
            role = "aggregation"
        node.role_hint = role
    # An access-looking switch that links many other network devices (not endpoints) is acting as aggregation.
    endpoint = {"ap", "phone", "host", "server"}
    infra = {key: 0 for key in graph.nodes}
    for conn in graph.connections:
        if graph.nodes[conn.b].role_hint not in endpoint:
            infra[conn.a] += 1
        if graph.nodes[conn.a].role_hint not in endpoint:
            infra[conn.b] += 1
    for key, node in graph.nodes.items():
        if node.role_hint in ("access", "switch") and node.captured and infra[key] >= 6 and not getattr(node, "role_from_name", False):
            node.role_hint = "aggregation"


def tier_of(role: str) -> int:
    return ROLE_TIER.get(role, 3)
