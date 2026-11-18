"""What a device does in the network, finer than its role row: edge, core, aggregation, distribution, top-of-rack, access, management, internet, partner.

``roles.classify`` gives every node a coarse ``role_hint`` (router, firewall, core, aggregation, access, ...) that picks its row.  This module adds the
``function`` of a node and the ``function_why`` that says on what evidence, so a reader can check the call and the layout can treat a management switch
(cabled to every tier, out of the data path) and an edge switch (between the WAN routers and the core) differently from the rows around them.

Evidence, strongest first: the host-name words (EDGE, MGMT, TOR, DIST ...), the model family (a Catalyst 9500 is a core family, a CE68 is a data-center
leaf), then the cabling (a switch linked to routers and to the core is an edge switch; a 1 Gbit switch linked to every tier is a management switch; a
switch pair under the aggregation pair with the same uplinks is top-of-rack), then the configuration (vPC / M-LAG peer-link).  Nothing here changes a role the
name gave; a function is a label with its reason, and a call that cannot be made stays the plain role.

References (found by search at cisco.com): Cisco, "Campus LAN and Wireless LAN Solution Design Guide" (core / distribution / access)
https://www.cisco.com/c/en/us/td/docs/solutions/CVD/Campus/cisco-campus-lan-wlan-design-guide.html and Cisco, "Massively Scalable Data Center Network Fabric Design and Operation"
(spine / leaf) https://www.cisco.com/c/en/us/products/collateral/switches/nexus-9000-series-switches/white-paper-c11-743245.html
"""

from __future__ import annotations

import re

from .graph import Graph

FUNCTIONS = ("edge", "core", "aggregation", "distribution", "tor", "access", "management", "internet", "partner", "wan")
FUNCTION_LABEL = {"edge": "Edge switch", "core": "Core", "aggregation": "Aggregation", "distribution": "Distribution", "tor": "Top-of-rack",
                  "access": "Access", "management": "Management switch", "internet": "Internet edge", "partner": "Partner edge", "wan": "WAN edge"}

# the words of a host name that name a function; a word may carry a number and a side letter (EDGE1, TOR6A, MGMT2)
_NAME_WORDS = (
    ("management", ("MGMT", "MGT", "MGMNT", "MANAGEMENT", "OOB", "OOBM")),
    ("internet", ("INET", "INTERNET", "ISP", "DIA")),
    ("partner", ("PTNR", "PARTNER", "EXTRANET", "B2B")),
    ("edge", ("EDGE", "BORDER")),
    ("tor", ("TOR", "LEAF")),
    ("distribution", ("DIST", "DISTRIBUTION", "DS", "DSW", "SWDI", "SWDS", "SWDIST", "DISTSW")),
    ("aggregation", ("AGG", "AGGR", "AGGREGATION", "AGGSW", "SWAGG")),
    ("core", ("CORE", "CR", "SPINE", "BACKBONE", "SWCO", "SWCORE", "CORESW", "CSW", "COSW")),
    ("access", ("ACC", "ACCESS", "ASW", "AS", "SWAC", "SWAS", "SWACC", "ACCSW", "LAN")),
)
_WORD = re.compile(r"^([A-Z]+?)(\d+[A-Z]?)?$")

# model families that say what a switch is for, whatever it is called: (function, pattern, text for the reason)
_MODEL_FUNCTIONS = (
    ("core", r"^(C95[0-9]{2}|N9K-C95|N7K|N77|S12[0-9]{3}|S77|CE128|CE88)", "a core / chassis switch family"),
    ("tor", r"^(CE68|CE58)", "a CloudEngine fixed data-center switch, normally the leaf (top-of-rack)"),
)


def _word_of(token: str) -> str:
    match = _WORD.match(token)
    return match.group(1) if match else ""


def name_function(hostname: str) -> tuple[str, str]:
    """(function, word) a host name says; ('', '') when it names none.  The words are looked for between - _ . so ``SW-TOR6A-DC``, ``DC-SW-MGMT1`` and ``AGG1.site`` all read."""
    for token in re.split(r"[-_. ]+", hostname.upper()):
        word = _word_of(token)
        if not word:
            continue
        for function, words in _NAME_WORDS:
            if word in words:
                return function, word
    return "", ""


def _neighbours(graph: Graph) -> dict[str, dict[str, list]]:
    near: dict[str, dict[str, list]] = {key: {} for key in graph.nodes}
    for conn in graph.connections:
        if conn.kind in graph.hidden_kinds and conn.kind != "mgmt":
            continue
        if conn.a in near and conn.b in near and conn.a != conn.b:
            near[conn.a].setdefault(conn.b, []).append(conn)
            near[conn.b].setdefault(conn.a, []).append(conn)
    return near


_MGMT_DESCRIPTION = re.compile(r"^(MGMT|MGT|OOB|OOBM|MANAGEMENT)([-_ :./]|$)", re.I)
_MGMT_PORT = re.compile(r"^(mgmt|management|meth|me|fxp|em)\d*([/.]\d+)*$", re.I)          # mgmt0 (Nexus), Management1 (Arista), MEth0/0/0 (VRP), me0 / fxp0 (Junos)
_MGMT_PORT_SWITCH = re.compile(r"^(gi|gigabitethernet)0/0$", re.I)                       # the management port of a Catalyst switch (a router's Gi0/0 is a data port)


def _management_ends(graph: Graph, other: str, conns: list) -> bool:
    """One of the cables lands on a management port of ``other`` or carries a description that starts with MGMT / OOB at either end."""
    peer = graph.nodes[other]
    switch_like = peer.role_hint in ("core", "aggregation", "access", "switch")
    for conn in conns:
        for link in conn.links:
            for device, port in ((link.a, link.a_port), (link.b, link.b_port)):
                owner = graph.nodes.get(device)
                if owner is None or not port:
                    continue
                if _MGMT_DESCRIPTION.match(owner.descriptions.get(port, "") or ""):
                    return True
                if owner is peer and (_MGMT_PORT.match(port) or (switch_like and _MGMT_PORT_SWITCH.match(port))):
                    return True
    return False


_GIGABIT_PORT = re.compile(r"^(gi|gigabitethernet|fa|fastethernet|ge|gige)\d", re.I)         # a 1 Gbit port or slower by its name (Te / Eth / XGE / 10GE are faster)
_TIERS = {"core": "core", "aggregation": "aggregation", "access": "access", "switch": "access", "router": "router", "firewall": "router"}
TIER_NEIGHBOURS = 5          # a management switch reached over single 1 Gbit cables has at least this many infrastructure neighbours ...
TIER_KINDS = 3               # ... in at least this many different tiers (core, aggregation, access, router / firewall)


def _cabled_to_every_tier(graph: Graph, key: str, infra: dict[str, list]) -> str:
    """The cabling alone: a switch with at least ``TIER_NEIGHBOURS`` infrastructure neighbours in at least ``TIER_KINDS`` tiers, every one reached over one 1 Gbit cable that is no port channel,
    is out of the data path and is the management switch even when no port is described MGMT (a data path joins tiers with faster, bundled links; a campus switch has two tiers around it)."""
    if len(infra) < TIER_NEIGHBOURS:
        return ""
    tiers = {_TIERS.get(graph.nodes[k].role_hint, "") for k in infra} - {""}
    if len(tiers) < TIER_KINDS:
        return ""
    for other, conns in infra.items():
        if len(conns) != 1 or len(conns[0].links) != 1 or conns[0].a_po or conns[0].b_po:
            return ""
        link = conns[0].links[0]
        mine = link.a_port if link.a == key else link.b_port
        theirs = link.b_port if link.a == key else link.a_port
        if not (_GIGABIT_PORT.match(mine or "") and _GIGABIT_PORT.match(theirs or "")):
            return ""
    return f"cabled with single 1 Gbit links to {len(infra)} infrastructure devices in {len(tiers)} tiers ({', '.join(sorted(tiers))}): out of the data path"


def _is_management(graph: Graph, key: str, near: dict[str, dict[str, list]]) -> str:
    """Reason when the switch is the management switch: three or more devices reach it through their management port, or through a port described MGMT / OOB
    at either end, and that is at least half of its infrastructure neighbours (a core that one device manages through a port described MGMT is not a management switch)."""
    node = graph.nodes[key]
    if node.role_hint not in ("switch", "access", "aggregation") or not node.captured:
        return ""
    infra = {k: c for k, c in near[key].items() if graph.nodes[k].role_hint not in ("ap", "phone", "host", "server", "segment")}
    managed = [k for k, c in infra.items() if _management_ends(graph, k, c)]
    if len(managed) < 3 or 2 * len(managed) < len(infra):
        return _cabled_to_every_tier(graph, key, infra)
    return f"{len(managed)} of its {len(infra)} infrastructure neighbours reach it through a management port or a port described MGMT / OOB"


def mark_management(graph: Graph) -> None:
    """Set ``management_why`` on the management switches.  Run by ``roles.classify`` right after the first role pass, before the hierarchy: a management switch is cabled
    to every tier but is not a tier, so it must not count as an aggregation switch nor as a step between the core and the racks."""
    near = _neighbours(graph)
    for node in graph.nodes.values():
        node.management_why = ""                                                    # type: ignore[attr-defined]
    for key, node in graph.nodes.items():
        word, text = name_function(node.hostname)
        if word == "management" and node.role_hint in ("switch", "access", "aggregation") and node.captured:
            node.management_why = f"host name word {text}"                           # type: ignore[attr-defined]
        else:
            node.management_why = _is_management(graph, key, near)                  # type: ignore[attr-defined]


def _is_edge(graph: Graph, key: str, near: dict[str, dict[str, list]]) -> str:
    """A switch linked to two or more routers / firewalls (the WAN side) and to a core or aggregation switch is the edge between them."""
    node = graph.nodes[key]
    if node.role_hint not in ("switch", "access", "aggregation") or not node.captured:
        return ""
    outside = [k for k in near[key] if graph.nodes[k].role_hint in ("router", "firewall")]
    inside = [k for k in near[key] if graph.nodes[k].role_hint in ("core", "aggregation")]
    if len(outside) >= 2 and inside:
        return f"cabled to {len(outside)} routers / firewalls and to {len(inside)} core / aggregation switch(es)"
    return ""


def _top_of_rack(graph: Graph, key: str, near: dict[str, dict[str, list]], pairs: set[frozenset]) -> str:
    """An access switch whose only switch uplinks go to the same two aggregation switches as at least two other access switches (a rack row under one pair)."""
    node = graph.nodes[key]
    if node.role_hint not in ("access", "switch", "aggregation") or not node.captured:
        return ""
    up = frozenset(k for k in near[key] if graph.nodes[k].role_hint in ("aggregation", "core"))
    if len(up) != 2 or frozenset(up) not in pairs:
        return ""
    siblings = [k for k, other in graph.nodes.items() if k != key and other.captured and other.role_hint in ("access", "switch", "aggregation")
                and frozenset(j for j in near[k] if graph.nodes[j].role_hint in ("aggregation", "core")) == up]
    if len(siblings) < 2:
        return ""
    names = sorted(graph.nodes[k].hostname for k in up)
    return f"uplinks go to the vPC / M-LAG pair {names[0]} + {names[1]}, as do {len(siblings)} other access switch(es)"


def _downstream(graph: Graph, key: str, near: dict[str, dict[str, list]]) -> list[str]:
    """Switches one step further from the core than this one (by ``hier_depth``), captured or not."""
    depth = getattr(graph.nodes[key], "hier_depth", None)
    if depth is None:
        return []
    return [k for k in near[key] if getattr(graph.nodes[k], "hier_depth", None) == depth + 1 and graph.nodes[k].role_hint not in ("ap", "phone", "host", "server")]


def assign(graph: Graph) -> None:
    """Set ``function`` and ``function_why`` on every node.  Run after ``roles.classify``; it never changes ``role_hint``."""
    near = _neighbours(graph)
    pairs = {frozenset((a, b)) for a, b, _ in graph.vpc_pairs}
    for key, node in graph.nodes.items():
        node.function = ""                                                          # type: ignore[attr-defined]
        node.function_why = ""                                                      # type: ignore[attr-defined]
    for key, node in graph.nodes.items():
        if node.role_hint in ("ap", "phone", "host", "server", "segment", "cloud"):
            continue
        function, why = "", ""
        word_function, word = name_function(node.hostname)
        if getattr(node, "management_why", ""):
            node.function, node.function_why = "management", node.management_why   # type: ignore[attr-defined]
            continue
        if word_function:
            function, why = word_function, f"host name word {word}"
        if node.role_hint in ("router", "firewall", "loadbalancer", "wlc", "fabric"):
            if function in ("internet", "partner", "edge"):
                node.function, node.function_why = function, why                    # type: ignore[attr-defined]
            elif node.role_hint == "router" and any(graph.nodes[k].role_hint in ("core", "aggregation", "switch", "access") for k in near[key]):
                node.function, node.function_why = "wan", "router cabled to the switching side"   # type: ignore[attr-defined]
            continue
        if not function:
            for candidate, pattern, text in _MODEL_FUNCTIONS:
                if candidate == "core" and node.role_hint != "core":
                    continue                                                        # the shape of the network put it below a core (roles._below_a_core)
                if node.model and re.search(pattern, node.model.upper()):
                    function, why = candidate, f"model {node.model} is {text}"
                    break
        if not function:
            edge = _is_edge(graph, key, near)
            if edge:
                function, why = "edge", edge
        if not function:
            tor = _top_of_rack(graph, key, near, pairs)
            if tor:
                function, why = "tor", tor
        if not function and node.vpc_domain and node.role_hint == "core":
            function, why = "core", f"vPC / M-LAG domain {node.vpc_domain} with a peer-link"
        if not function and node.role_hint != "aggregation":                            # an aggregation role waits for the second pass
            function = node.role_hint if node.role_hint in FUNCTIONS else ""
            why = "role from the model or the capabilities or the shape of the network" if function else ""
        node.function, node.function_why = function, why                            # type: ignore[attr-defined]
    for key, node in graph.nodes.items():                                           # aggregation or distribution: what sits below decides (racks below = data-center aggregation)
        if node.function or node.role_hint != "aggregation" or not node.captured:     # type: ignore[attr-defined]
            continue
        down = _downstream(graph, key, near)
        racks = [k for k in down if graph.nodes[k].function == "tor"]               # type: ignore[attr-defined]
        if getattr(node, "hier_depth", None) is None:
            node.function, node.function_why = "aggregation", "role from the model or the capabilities or the shape of the network"   # type: ignore[attr-defined]
        elif len(racks) >= 2 or (node.vpc_domain and racks):
            node.function, node.function_why = "aggregation", f"{len(racks)} top-of-rack switch(es) below it"      # type: ignore[attr-defined]
        else:
            node.function, node.function_why = "distribution", f"{len(down)} switch(es) below it in the hierarchy; none is a rack row"   # type: ignore[attr-defined]
    for a, b, domain in graph.vpc_pairs:                                              # the two peers of a vPC / M-LAG pair do the same job: one cabled to the routers is the edge pair
        for here, there in ((a, b), (b, a)):
            if getattr(graph.nodes[here], "function", "") == "edge" and getattr(graph.nodes[there], "function", "") in ("", "access", "aggregation", "distribution", "switch") \
                    and graph.nodes[there].captured and not name_function(graph.nodes[there].hostname)[0]:
                graph.nodes[there].function, graph.nodes[there].function_why = "edge", f"vPC / M-LAG peer of {graph.nodes[here].hostname}, which is cabled to the routers"      # type: ignore[attr-defined]
