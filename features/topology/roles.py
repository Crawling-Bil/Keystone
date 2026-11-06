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
    ("core", r"(^|[-_])(CORE|CR|SPINE|BACKBONE)\d*([-_]|$)|(^|[-_])(SWCO|SWCODI|SWCORE|CORESW|CSW|COSW)\d*[A-Z]?([-_]|$)"),
    ("aggregation", r"(^|[-_])(AGG|AGGR|DS|DIST|DISTRIBUTION|EDGE|EXT)\d*([-_]|$)|(^|[-_])(SWDI|SWDS|SWDIST|SWAGG|DSW|DISTSW|AGGSW)\d*[A-Z]?([-_]|$)"),
    ("access", r"(^|[-_])(TOR|ACC|ACCESS|LAN|SW|MGT|MGMT|AS)\d*[A-Z]?([-_]|$)|(^|[-_])(SWAC|SWAS|SWACC|SWACCESS|ASW|ACCSW)\d*[A-Z]?([-_]|$)"),
)
# "SW" says that the device is a switch, not where it stands (MKS-SW1, BAL-SW2).  A name whose only role word is SW leaves the tier to the shape of the network
# (``infer_hierarchy``), the same as a name with no role word at all; a name that says TOR, ACC, ASW ... still gives the tier.
_TIER_WORDS = re.compile(dict(_WORD_RULES)["access"].replace("|SW|", "|", 1), re.I)

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
        if re.search(r"\bR\b", text) and re.search(r"\bS\b", text) and re.search(r"\bB\b", text):
            return "server"                                      # Bridge, WLAN, Router and Station together is a Linux host with a software bridge (lldpd, Nutanix AHV, KVM), not an access point
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


# What a neighbor's LLDP system description says it is, for the kinds a capability word cannot tell (a Cisco access point advertises "bridge" only).  Only words
# that name the kind of device outright; a switch is not listed, the capabilities and the shape of the network decide that.
_DESCRIPTION_RULES = (
    ("wlc", r"Wireless (?:LAN )?Controller|\bC9800\b|Catalyst 9800|\bAireOS\b|\bAIR-CT\d|Cisco Controller"),
    ("ap", r"\bAP Software\b|\bCisco AP\b|Access Point|\bAironet\b|\bAIR-C?AP|\bC91\d{2}AX|\bMeraki MR\d|\bAruba (?:Instant|AP)\b|\bArubaOS .*\bAP-?\d{2,3}\b|\bCW9\d{3}|\bUAP-[A-Z0-9]|\bU6-[A-Za-z]|\bUniFi AP\b|\bEAP\d{3}\b"),
    ("phone", r"\bIP Phone\b|\bSIP Phone\b|\bPolycom\b|\bYealink\b|\bGrandstream\b|\bCisco CP-\d|\bPoly VVX"),
    ("server", r"Nutanix|\bAHV\b|\bVMware ESXi?\b|\bProxmox\b|\bXenServer\b|\bXCP-ng\b|\boVirt\b|\bHyper-V\b|\bKVM\b|\blibvirt\b|^(?:Ubuntu|Debian|CentOS|Red Hat|Rocky|Alma ?Linux|Fedora|openSUSE|SUSE|Oracle Linux|Linux \d)|\bGNU/Linux\b|\bWindows Server\b|^Microsoft Windows|\bFreeBSD\b"),          # a hypervisor host: Linux bridges advertise Bridge, WLAN, Router and Station all at once
    ("firewall", r"\bFortiGate\b|\bFortiOS\b|Palo Alto|\bPAN-OS\b|Adaptive Security Appliance|\bFirepower\b|\bSonicWALL\b|\bCheck Point\b|\bSRX\d|\bUSG\d"),
    ("loadbalancer", r"\bBIG-IP\b|\bF5 Networks\b|\bNetScaler\b|\bCitrix ADC\b|\bVIPRION\b"),
)


def role_from_description(text: str) -> str:
    """Role a neighbor's LLDP system description names outright ('Cisco AP Software, ap3g3-k9w8 ...' is an access point); '' when it names none."""
    return _by_rules(_DESCRIPTION_RULES, (text or "")[:240])


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
        node.role_from_name = bool(by_name) and not (by_name == "access" and not _TIER_WORDS.search(node.hostname.upper()))  # type: ignore[attr-defined]
        role = by_name or _by_rules(_MODEL_RULES, node.model.upper())
        if not role and not node.captured:
            role = role_from_description(node.descr)               # a neighbor that was never captured: what it said about itself in LLDP
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
    infer_hierarchy(graph)


LEVEL_ROLES = ("core", "aggregation", "access", "switch")
UPPER_ROLES = ("router", "firewall", "loadbalancer")


def _eccentricity(near: dict[str, set[str]], group: set[str], start: str) -> int:
    """Hops from ``start`` to the farthest switch of its group: the middle of a hierarchy has the smallest."""
    seen = {start: 0}
    todo = [start]
    while todo:
        key = todo.pop(0)
        for other in near[key] & group:
            if other not in seen:
                seen[other] = seen[key] + 1
                todo.append(other)
    return max(seen.values())


def infer_hierarchy(graph: Graph) -> None:
    """Core, distribution and access from the shape of the network, for the switches whose name and model say nothing about it.

    A group of at least three linked switches is a hierarchy.  Its core is a switch that is already known as one (name or model) or, failing that, the
    one switch that stands out: linked to a router, firewall or load balancer, else in the middle of the group (the fewest hops to its farthest switch), else linked to more of the group than any other (two vPC / MLAG peers
    that tie are both the core; any other tie leaves the group alone, because a guess would draw it wrong).  From the core the group is walked outwards:
    a switch that has another switch below it (one hop further from the core) is a distribution switch, a switch with none below it is an access switch.
    A role that the host name gave (``SWCO`` core, ``SWDI`` distribution, ``SWAC`` access, ``CORE-1``, ``DS2``) is never changed."""
    nodes = graph.nodes
    for node in nodes.values():
        node.hier_depth = None                                                       # type: ignore[attr-defined]
    near: dict[str, set[str]] = {key: set() for key in nodes}
    for conn in graph.connections:
        if conn.kind in graph.hidden_kinds or conn.a not in nodes or conn.b not in nodes:
            continue
        near[conn.a].add(conn.b)
        near[conn.b].add(conn.a)
    switches = {key for key, node in nodes.items() if node.role_hint in LEVEL_ROLES}
    weak = {key for key in switches if nodes[key].role_hint in ("switch", "access") and not getattr(nodes[key], "role_from_name", False)}
    if not switches:
        return
    pairs = {frozenset((a, b)) for a, b, _ in graph.vpc_pairs}
    seen: set[str] = set()
    for first in sorted(switches):
        if first in seen:
            continue
        group, todo = {first}, [first]
        while todo:
            for other in near[todo.pop()] & switches:
                if other not in group:
                    group.add(other)
                    todo.append(other)
        seen |= group
        roots = {key for key in group if nodes[key].role_hint == "core"}
        if len(group) < (2 if roots else 3) or not (group & weak or roots):
            continue
        if not roots:
            score = {key: (any(nodes[m].role_hint in UPPER_ROLES for m in near[key]), -_eccentricity(near, group, key), len(near[key] & group), nodes[key].captured)
                     for key in group & weak}
            best = max(score.values())
            top = [key for key, value in score.items() if value == best]
            if best[2] < 2 or not (len(top) == 1 or (len(top) == 2 and frozenset(top) in pairs)):
                continue
            roots = set(top)
        depth = {key: 0 for key in roots}
        todo = sorted(roots)
        while todo:
            key = todo.pop(0)
            for other in sorted(near[key] & group):
                if other not in depth:
                    depth[other] = depth[key] + 1
                    todo.append(other)
        for key in group:
            nodes[key].hier_depth = depth[key] if key in depth else None          # type: ignore[attr-defined]
        for key in group & weak:
            if key in roots:
                nodes[key].role_hint = "core"
            elif key in depth:
                below = any(depth.get(m, -1) == depth[key] + 1 for m in near[key] & group)
                nodes[key].role_hint = "aggregation" if below else "access"


DEPTH_ROWS = (1.0, 2.0, 3.0, 3.34, 3.67, 3.9)       # row of a switch 0, 1, 2 ... hops from its core; the rows of the end points start at 4


def depth_row(depth: int) -> float:
    return DEPTH_ROWS[min(depth, len(DEPTH_ROWS) - 1)]


def tier_of(role: str) -> int:
    return ROLE_TIER.get(role, 3)
