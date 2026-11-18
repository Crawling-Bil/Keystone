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
    ("server", r"(^|[-_/ ])(FI|UCS|SRV|SERVER|ESX|ESXI|HV|HCI|NTNX|NUTANIX|VXRAIL|VSAN|CVM|AHV|PVE|PROXMOX|KVM|VMHOST|HYPERV|BLADE)\d*([-_/ ]|$)|^FI-"),          # a hyper-converged (HCI) node, a hypervisor host, a blade: a server
    ("core", r"(^|[-_])(CORE|CR|SPINE|BACKBONE)\d*([-_]|$)|(^|[-_])(SWCO|SWCODI|SWCORE|CORESW|CSW|COSW)\d*[A-Z]?([-_]|$)"),
    ("aggregation", r"(^|[-_])(AGG|AGGR|DS|DIST|DISTRIBUTION|EDGE|EXT)\d*([-_]|$)|(^|[-_])(SWDI|SWDS|SWDIST|SWAGG|DSW|DISTSW|AGGSW)\d*[A-Z]?([-_]|$)"),
    ("access", r"(^|[-_])(TOR|ACC|ACCESS|LAN|SW|MGT|MGMT|AS)\d*[A-Z]?([-_]|$)|(^|[-_])(SWAC|SWAS|SWACC|SWACCESS|ASW|ACCSW)\d*[A-Z]?([-_]|$)"),
)
# "SW" says that the device is a switch, not where it stands (MKS-SW1, BAL-SW2).  A name whose only role word is SW leaves the tier to the shape of the network
# (``infer_hierarchy``), the same as a name with no role word at all; a name that says TOR, ACC, ASW ... still gives the tier.
_TIER_WORDS = re.compile(dict(_WORD_RULES)["access"].replace("|SW|", "|", 1), re.I)

# A role word that is written into a longer name without a separator (HQCORENX1, JKTCORE01, DCEDGSW2): looked for only when the words between separators say nothing.
# "CORE" is not taken inside ENCORE / SCORE; the word must end the name, a digit, or a device-type suffix, so CORELLA or HARDCORE are left alone.
_EMBEDDED_RULES = (
    ("core", r"(?<!EN)(?<!S)(?<!HARD)CORE(?:NX|SW|SWITCH|N?[0-9]+|$)"),
    ("aggregation", r"(?:EDG|EDGE|AGG|DIST)(?:NX|SW|SWITCH)[0-9]*(?:[A-Z]?$|[-_])|(?:EDGE|AGG)[0-9]+$"),
)

_MODEL_RULES = (
    ("firewall", r"^(PA-|FG|FORTIGATE|ASA|FPR|FIREPOWER|NSF|USG|SRX)"),
    ("loadbalancer", r"^(BIG-?IP|F5-|VIPRION|ADC-|NETSCALER)"),
    ("router", r"^(ISR|ASR|C8[0-9]{3}|C11[0-9]{2}|CSR|ISR4|NCS|MX|AR[0-9])|^(CISCO)?(19|29|39)[0-9]{2}(/K9|-CHASSIS|$)|^C9[0-9]{2}-[0-9]"),
    ("fabric", r"^UCS-FI"),
    ("server", r"^(PROLIANT|DL[0-9]{3}|POWEREDGE|PRIMERGY|THINKSYSTEM|UCS-?[BC][0-9]|VXRAIL|NX-[0-9]{4}|HX[0-9]{3})"),
    ("wlc", r"(AIR-CT|C9800|WLC|AC6|AC66)"),
    ("ap", r"(^AIR-[A-Z]*AP|^C91[0-9]{2}AX|^CW9|AIR-AP|APS|AP-[0-9])"),
    ("phone", r"(IP Phone|CP-[0-9])"),
    ("core", r"^(N9K-C95|N7K|N77|C95[0-9]{2}|S12|S77|CE128|CE88)"),
    ("aggregation", r"^(N9K-C93|N9K-C92|N5K|N3K|C3850|C3750)"),
    ("access", r"^(C92|C93|C2960|C1000|C3560|C2960|WS-C|S53|S57|S67|CE5|CE68)"),
    ("switch", r"^(HPE ANW |ARUBA |HP )?(JL|JH|J[0-9]{4}|R[0-9]{4}|Q[0-9]{4})[0-9A-Z]*\b|^(HPE ANW|ARUBA|HP ProCurve|PROCURVE)"),
)
_CAP_WORDS = (("ap", r"Trans-Bridge|WLAN|Access Point|Wireless"), ("phone", r"Phone"), ("router", r"\bRouter\b"),
              ("switch", r"Switch|Bridge"))


# The system name of a NIC or hypervisor LLDP agent is often the vendor of the adapter ("BROADCOM ADV", "Intel Corporation"): never a switch, always a server port.
NIC_VENDOR = re.compile(r"^(BROADCOM|INTEL|MELLANOX|EMULEX|QLOGIC|REALTEK|MARVELL|CAVIUM|CHELSIO|SOLARFLARE)\b", re.I)


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
        if getattr(node, "split_from", ""):
            node.role_hint = "server"                                # one attachment of a shared neighbor name (sharedname.py): a server, whatever its LLDP capabilities say
            continue
        if node.role_hint == "cloud" and not node.captured:
            continue                                       # a provider named by a port description keeps its cloud icon
        if node.role_hint in ("firewall", "loadbalancer") and node.vendor:
            continue                                       # a FortiGate / PAN-OS / BIG-IP reader knows what the box is, whatever it is called (HQPAIBFW1)
        by_name = _by_rules(_WORD_RULES, node.hostname.upper()) or _by_rules(_EMBEDDED_RULES, node.hostname.upper())
        if not node.captured and NIC_VENDOR.match(node.hostname or ""):
            by_name = "server"                                     # an adapter vendor string is a server whatever its LLDP capabilities say (they say Bridge)
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
    from . import functions
    functions.mark_management(graph)                           # before the promotion and the hierarchy: a management switch is cabled to every tier and is none of them
    # An access-looking switch that links many other network devices (not endpoints) is acting as aggregation.
    endpoint = {"ap", "phone", "host", "server"}
    infra = {key: 0 for key in graph.nodes}
    for conn in graph.connections:
        if graph.nodes[conn.b].role_hint not in endpoint:
            infra[conn.a] += 1
        if graph.nodes[conn.a].role_hint not in endpoint:
            infra[conn.b] += 1
    for key, node in graph.nodes.items():
        if node.role_hint in ("access", "switch") and node.captured and infra[key] >= 6 and not getattr(node, "role_from_name", False) and not getattr(node, "management_why", ""):
            node.role_hint = "aggregation"
    infer_hierarchy(graph)
    functions.assign(graph)                                   # after the hierarchy: the call uses the depth of a switch below its core


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


def _below_a_core(graph: Graph, near: dict[str, set[str]], roots: set[str], pairs: set[frozenset]) -> set[str]:
    """Switches that the model calls a core but that stand under the real core of their group, which become aggregation switches: a Catalyst 9500 that serves
    the campus below the Catalyst 9500 that the WAN routers plug into.  The real core is the one linked to a router, firewall or load balancer that was captured (else to any); the one below it is linked
    to that core, to no router, firewall or load balancer, and has at least two neighbours of its own that the real core does not touch.  A name that says CORE keeps the role,
    and so does a vPC / M-LAG pair of cores (they are one core)."""
    nodes = graph.nodes
    seen_router = {k: [m for m in near[k] if nodes[m].role_hint in UPPER_ROLES] for k in roots}
    outside = {k for k, ups in seen_router.items() if any(nodes[m].captured for m in ups)} or {k for k, ups in seen_router.items() if ups}       # a router that was captured is the stronger evidence
    lower: set[str] = set()
    for key in sorted(roots - outside):
        if not outside or getattr(nodes[key], "role_from_name", False) or not near[key] & outside:
            continue
        if any(frozenset((key, o)) in pairs for o in outside):
            continue
        own = {m for m in near[key] if m not in roots and nodes[m].role_hint not in ("ap", "phone", "host", "server") and not any(m in near[o] for o in outside)}
        if len(own) >= 2:
            lower.add(key)
            nodes[key].role_hint = "aggregation"
    return lower


TWIN_OVERLAP = 0.34             # twins by name must share this part of their neighbours (Jaccard) to be one logical device; two units that serve other devices are no pair


def twin_clusters(graph: Graph, keys: set[str], pairs: set[frozenset], near: dict[str, set[str]] | None = None) -> list[frozenset]:
    """The devices of ``keys`` grouped into the units of one logical device: vPC / M-LAG peers, and the same model under names that differ only in their numbers
    (HQCORENX1, HQCORENX2; DC1-CORE1, DC1-CORE2), up to four together.  A device with no twin is a cluster of its own."""
    nodes = graph.nodes
    parent = {k: k for k in keys}

    def find(k: str) -> str:
        while parent[k] != k:
            parent[k] = parent[parent[k]]
            k = parent[k]
        return k
    families: dict[tuple[str, str], list[str]] = {}
    for k in sorted(keys):
        stem = re.sub(r"\d+", "", nodes[k].hostname.upper())
        if nodes[k].model and len(stem) >= 3:
            families.setdefault((nodes[k].model, stem), []).append(k)
    def alike(a: str, b: str) -> bool:
        if near is None:
            return True
        weak_unit = any(nodes[k].role_hint in ("access", "switch") for k in (a, b))
        if weak_unit and b not in near.get(a, set()):
            return False                                          # closets that only share their uplinks are a row of switches; units of one device that are not core-class are cabled to each other
        na, nb = near.get(a, set()) - {b}, near.get(b, set()) - {a}
        return bool(na | nb) and len(na & nb) / len(na | nb) >= TWIN_OVERLAP
    for members in families.values():
        if len(members) > 8:
            continue                                              # a floor of identical access switches is a row, not a device
        for i, first in enumerate(members):
            for other in members[i + 1:]:
                if alike(first, other):
                    parent[find(other)] = find(first)
    for pair in pairs:
        a, b = tuple(pair) if len(pair) == 2 else (None, None)
        if a in parent and b in parent:
            parent[find(a)] = find(b)
    clusters: dict[str, set[str]] = {}
    for k in keys:
        clusters.setdefault(find(k), set()).add(k)
    return [frozenset(c) for c in clusters.values() if len(c) <= 4] + [frozenset((k,)) for c in clusters.values() if len(c) > 4 for k in c]


def _family_class(node) -> int:
    """How much a device looks like a centre by what it is: a core family or a core name 2, an aggregation role 1, the rest 0."""
    if node.role_hint == "core":
        return 2
    return 1 if node.role_hint == "aggregation" else 0


def inferred_centre(graph: Graph, near: dict[str, set[str]], group: set[str], pairs: set[frozenset]) -> set[str]:
    """The centre of a group of switches that has no switch named or modelled as a core: the unit of one logical device (a twin pair, a vPC pair, a stack) that
    stands out.  Candidates are all the switches of the group, not only the ones whose role is a guess: a pair of aggregation switches that every access switch hangs from is the centre
    even when its names say nothing about a core, and an access switch that happens to have the most links is not.  The unit wins that is linked to a router, firewall or load balancer, then
    is in the middle of the group (the fewest hops to the farthest switch), then reaches more switches of the group than any other, then is the bigger family, has more chassis (a stack
    counts each member) and was captured.  Two units that tie on all of it leave the group alone: a guess would draw it wrong."""
    nodes = graph.nodes
    clusters = twin_clusters(graph, group, pairs, {k: near[k] & group for k in group})

    def rank(cluster: frozenset) -> tuple:
        reach = set().union(*(near[k] & group for k in cluster)) - cluster
        return (any(nodes[m].role_hint in UPPER_ROLES for k in cluster for m in near[k]), -min(_eccentricity(near, group, k) for k in cluster), len(reach),
                max(_family_class(nodes[k]) for k in cluster), sum(max(1, getattr(nodes[k], "stack_members", 1)) for k in cluster), any(nodes[k].captured for k in cluster))
    scored = {cluster: rank(cluster) for cluster in clusters}
    best = max(scored.values())
    top = [cluster for cluster, value in scored.items() if value == best]
    if best[2] < 2 or len(top) != 1:
        return set()
    return set(top[0]) if _transit(graph, near, group, top[0]) else set()


CENTRE_OWN_ENDS = 12                     # a hub with at least this many end points of its own (a frame as wide as the closets below it) is a switch that serves people, not only the others


def _transit(graph: Graph, near: dict[str, set[str]], group: set[str], cluster: frozenset) -> bool:
    """Is the candidate a real centre, one that the other switches go through?  A hub that serves end points itself and whose neighbours are only leaf switches (a collapsed
    core: one big switch with its own users and four closets that each have users) is no tier above them: put in a row of its own, its end points would stand between it and the closets and
    every uplink would run through them.  Such a group is left as a flat row, where the hub stands among the closets.  A centre that serves few end points, a pair of units, or one
    that has a switch with switches of its own below it, is a tier."""
    nodes = graph.nodes
    if len(cluster) > 1:
        return True
    key = next(iter(cluster))
    own = sum(1 for m in near[key] if nodes[m].role_hint in ("host", "server", "phone", "ap"))
    if own < CENTRE_OWN_ENDS:
        return True
    return any((near[m] & group) - {key} - near[key] for m in near[key] & group)       # a neighbour has a switch below it that the hub does not touch (links between two closets do not count)


def infer_hierarchy(graph: Graph) -> None:
    """Core, distribution and access from the shape of the network, for the switches whose name and model say nothing about it.

    A group of at least three linked switches is a hierarchy.  Its core is a switch that is already known as one (name or model) or, failing that, the
    one switch that stands out: linked to a router, firewall or load balancer, else in the middle of the group (the fewest hops to its farthest switch), else linked to more of the group than any other (two vPC / MLAG peers
    that tie are both the core; any other tie leaves the group alone, because a guess would draw it wrong).  From the core the group is walked outwards:
    a switch that has another switch below it (one hop further from the core) is a distribution switch, a switch with none below it is an access switch.
    A role that the host name gave (``SWCO`` core, ``SWDI`` distribution, ``SWAC`` access, ``CORE-1``, ``DS2``) is never changed."""
    nodes = graph.nodes
    graph.centres = []                                                               # type: ignore[attr-defined]
    for node in nodes.values():
        node.hier_depth = None                                                       # type: ignore[attr-defined]
    near: dict[str, set[str]] = {key: set() for key in nodes}
    for conn in graph.connections:
        if conn.kind in graph.hidden_kinds or conn.a not in nodes or conn.b not in nodes:
            continue
        if getattr(nodes[conn.a], "management_why", "") or getattr(nodes[conn.b], "management_why", ""):
            continue                                                                 # the cables of a management switch are not steps of the hierarchy
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
        roots -= _below_a_core(graph, near, roots, pairs)
        if len(group) < (2 if roots else 3) or not (group & weak or roots):
            continue
        if not roots:
            roots = inferred_centre(graph, near, group, pairs)
            if not roots:
                continue
        graph.centres.append({"members": sorted(roots), "named": bool(group and any(nodes[k].role_hint == "core" and getattr(nodes[k], "role_from_name", False) for k in roots))})   # type: ignore[attr-defined]
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
