"""Zones: the blocks a site is made of, found from the cables, so that the page can put the core in the middle and the other blocks around it.

A production network is built round a core (a pair or a stack of switches, ``roles.infer_hierarchy`` finds it).  Everything else hangs from it in blocks, each with a head
(the device pair that the core is cabled to) and the devices below that head: the edge pair with the WAN routers and the providers, the firewall pair with the user LAN under it,
the aggregation pair with the top-of-rack switches and the servers.  This module finds those blocks and says where each one belongs round the core:

* **external** (top): routers, providers and partners; they are the way out, so they stand above the core.
* **internal** (bottom): the user LAN, the server farm and everything else that serves end points; it stands under the core.
* **tall** (left or right): a block that has both an outside (routers, providers) and its own end points below (a DMZ with its own WAN link and its servers); it keeps its own chain
  from the outside to the servers and stands beside the core.
* **management**: the management switch is cabled to every block and belongs to none; it stands beside the core.

Rules, not names: a block is the set of devices nearest to one head (hops from the core, a tie goes to the head that most of the device's neighbours already belong to, then to the
head that already holds devices of the same kind).  Names only title a block (DMZ, INTERNET, EXTRANET, WAN, LAN, SERVER FARM) when the host names say so.
Reference for the shape (core in the centre, zones around it, external above, internal below): Cisco, "Campus LAN and Wireless LAN Solution Design Guide"
https://www.cisco.com/c/en/us/td/docs/solutions/CVD/Campus/cisco-campus-lan-wlan-design-guide.html and, for the spine and leaf blocks of a data center, Cisco, "Massively Scalable Data
Center (MSDC) Design and Implementation Guide" https://www.cisco.com/c/en/us/products/collateral/switches/nexus-9000-series-switches/white-paper-c11-743245.html .
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field

from .graph import Graph
from .roles import twin_clusters

END_ROLES = ("ap", "phone", "host", "server", "segment")
OUTER_ROLES = ("router", "cloud")
ZONES_MIN_INFRA = 3                # a page with fewer network devices (without the core) is not split into blocks: it is a row or two
ZONES_MIN = 2                      # ... and at least this many blocks round the core
HUB_ENDS = 12                   # an internal block in which one switch has this many end points of its own (a frame) is drawn as a zone even when it holds nearly every switch: the zone box is what centres the hub over its users
BIGGEST_SHARE = 0.65               # ... and none of them holds more than this share of the network devices (one block with nearly everything is no picture of zones)
TALL_MIN_INNER = 2                 # a block with routers or providers is a "tall" one when at least this many switches or end point frames stand below them
TALL_MIN_SPLIT = 20                # ... and at least this many devices (a small DMZ with its own way out stays one block)
TALL_MAX_SHARE = 0.30              # a "tall" block stands at the side of the core with its whole chain: when it holds more than this share of the page it is split in an outer part (above) and an inner part (below)

DEDICATED_SHARE = 0.7                            # a head switch whose routers are this share of one way out is the switch of that way out and stays in its zone
GROUP_ORDER = ("wan", "internet", "partner")     # the ways out that are their own zone: a router, the neighbours that hang from it, and the switch that serves it (a tie goes to the first)
KEY_TITLES = {"INTERNET / PUBLIC": "internet", "EXTRANET / 3RD PARTY": "partner", "WAN / BRANCH": "wan"}

TITLE_WORDS = (                    # (title, words in host names) in the order they are tried
    ("DMZ", ("DMZ",)),
    ("INTERNET / PUBLIC", ("INET", "INTERNET", "ISP", "PUBLIC", "DIA")),
    ("EXTRANET / 3RD PARTY", ("EXTRANET", "PARTNER", "PTNR", "B2B", "EXTR", "VENDOR")),
    ("WAN / BRANCH", ("WAN", "MPLS", "BRANCH", "XBI", "METRO", "SDWAN")),
)


@dataclass
class Zone:
    key: str
    head: frozenset                                    # the units of the head device (the pair, the stack) that the core is cabled to
    members: set[str] = field(default_factory=set)     # network devices of the block
    ends: set[str] = field(default_factory=set)        # end points that follow them
    kind: str = "internal"                             # external | internal | tall | management | other | ghost
    title: str = ""
    side: int = 0                                      # ghost blocks: -1 left, +1 right (the side the other site has on the picture of all sites)

    @property
    def keys(self) -> set[str]:
        return self.members | self.ends


@dataclass
class ZonePlan:
    centre: frozenset
    centre_ends: set[str]
    zones: list[Zone]


def _near(graph: Graph, members: set[str]) -> dict[str, set[str]]:
    near: dict[str, set[str]] = {k: set() for k in members}
    for conn in graph.connections:
        if conn.a in members and conn.b in members and conn.a != conn.b and conn.kind not in graph.hidden_kinds:
            near[conn.a].add(conn.b)
            near[conn.b].add(conn.a)
    return near


def _hostnames(graph: Graph, keys) -> list[str]:
    return [graph.nodes[k].hostname.upper() for k in keys]


def _has_word(names: list[str], words: tuple[str, ...]) -> bool:
    for name in names:
        for token in re.split(r"[-_. \[\]]+", name):
            stem = re.sub(r"\d+[A-Z]?$", "", token)
            if stem in words:
                return True
    return False


def _title_from_names(graph: Graph, keys) -> str:
    names = _hostnames(graph, keys)
    for title, words in TITLE_WORDS:
        if _has_word(names, words):
            return title
    return ""


def centres_on(graph: Graph, members: set[str]) -> list[frozenset]:
    """Every centre (``roles.infer_hierarchy``) that has devices on this page, each as the set of its devices that are here."""
    found = []
    for centre in getattr(graph, "centres", []):
        mine = frozenset(k for k in centre["members"] if k in members)
        if mine:
            found.append(mine)
    return found


def find_centre(graph: Graph, members: set[str]) -> frozenset | None:
    """The centre of this page: the centre found by ``roles.infer_hierarchy`` that has most of its devices here.  None when there is none, or two (two sites on one page)."""
    found = []
    for centre in getattr(graph, "centres", []):
        mine = frozenset(k for k in centre["members"] if k in members)
        if mine:
            found.append(mine)
    if len(found) != 1:
        return None
    return found[0]


def virtual_centre(graph: Graph, infra: set[str], near: dict[str, set[str]], pairs: set[frozenset]) -> frozenset | None:
    """A centre for a page whose network has none that ``roles.infer_hierarchy`` could name (a branch with one stack and a router, a group of switches that tie): the network device that the
    most paths between the others go through (betweenness on the cables between network devices), with its vPC / M-LAG peer when it has one.  It must be cabled to at least two other
    network devices, else it is a leaf and there is no middle."""
    if len(infra) < ZONES_MIN_INFRA + 1:
        return None
    score: dict[str, float] = {k: 0.0 for k in infra}
    for source in sorted(infra):
        order: list[str] = []
        parents: dict[str, list[str]] = {k: [] for k in infra}
        sigma = {k: 0.0 for k in infra}
        sigma[source] = 1.0
        dist = {source: 0}
        queue = [source]
        while queue:
            nxt = []
            for v in queue:
                order.append(v)
                for w in sorted(near[v] & infra):
                    if w not in dist:
                        dist[w] = dist[v] + 1
                        nxt.append(w)
                    if dist[w] == dist[v] + 1:
                        sigma[w] += sigma[v]
                        parents[w].append(v)
            queue = nxt
        delta = {k: 0.0 for k in infra}
        for w in reversed(order):
            for v in parents[w]:
                delta[v] += sigma[v] / sigma[w] * (1 + delta[w])
            if w != source:
                score[w] += delta[w]
    nodes = graph.nodes
    ranked = sorted(infra, key=lambda k: (-score[k], -len(near[k]), nodes[k].hostname))
    best = ranked[0]
    if score[best] <= 0 or len(near[best] & infra) < 2:
        return None
    return frozenset({best} | {x for x in infra if frozenset((best, x)) in pairs})


def floor_centre(graph: Graph, base: set[str], near: dict[str, set[str]], members: set[str], pairs: set[frozenset]) -> frozenset | None:
    """The centre of a floor or a small site (one stack with its access points and phones, perhaps a switch or two below it and the uplink at another site): the switch with the most end points
    and neighbours, with its stack or vPC peer.  Used when the cables give no middle (``virtual_centre``)."""
    nodes = graph.nodes
    ends_of = {k: sum(1 for m in near.get(k, ()) if nodes[m].role_hint in END_ROLES) for k in base}
    best = sorted(base, key=lambda k: (-(ends_of[k] + len(near[k] & base) + len(near[k] & members)), nodes[k].hostname))
    if not best:
        return None
    first = best[0]
    return frozenset({first} | {x for x in base if frozenset((first, x)) in pairs})


def plan(graph: Graph, keys: list[str], ghosts: set[str] | frozenset[str] = frozenset(), ghost_side: dict[str, int] | None = None, why: list[str] | None = None) -> ZonePlan | None:
    """The zones of a page, or None (and the reason, in plain words, appended to ``why``) when the network has no picture in zones."""
    def no(reason: str) -> None:
        if why is not None:
            why.append(reason)
        return None
    members = set(keys)
    nodes = graph.nodes
    near = _near(graph, members)
    near_all = {k: set() for k in members}                                  # every neighbour, end points too
    for conn in graph.connections:
        if conn.a in members and conn.b in members and conn.a != conn.b and conn.kind not in graph.hidden_kinds:
            near_all[conn.a].add(conn.b)
            near_all[conn.b].add(conn.a)
    managed = {k for k in members if getattr(nodes[k], "management_why", "") or getattr(nodes[k], "function", "") == "management"}
    foreign = {k for k in members if k in ghosts}                       # devices of another site: they stand at the side, not in a block of this site
    uplink_out = any((conn.a in members) != (conn.b in members) and conn.kind not in graph.hidden_kinds and conn.a in nodes and conn.b in nodes
                     and conn.a not in graph.hidden_nodes and conn.b not in graph.hidden_nodes for conn in graph.connections)         # a site drawn alone in the Overview of several: its uplink is at another site, as on its own page, where that device is a ghost
    centre = find_centre(graph, members - set(ghosts))
    if centre is None:
        base = {k for k in members if nodes[k].role_hint not in END_ROLES and k not in managed and k not in foreign}
        pairs0 = {frozenset((a, b)) for a, b, _ in graph.vpc_pairs}
        centre = virtual_centre(graph, base, near, pairs0) or (floor_centre(graph, base, near, members, pairs0) if foreign or uplink_out else None)       # a floor is told by its uplink at another site: a small network with no core of its own keeps the plain rows
        if centre is None:
            return no("no core found, and no network device in the middle of the cables")
    infra = {k for k in members if nodes[k].role_hint not in END_ROLES and k not in centre and k not in managed and k not in foreign}
    small = bool(foreign) or uplink_out                                               # a floor: its uplink is at another site (the page shows it as a box of that site)
    if len(infra) < ZONES_MIN_INFRA and not small:
        return no(f"only {len(infra)} network devices besides the core")
    pairs = {frozenset((a, b)) for a, b, _ in graph.vpc_pairs}
    heads = {k for c in centre for k in near[c] if k in infra}
    if not heads and not small:
        return no("the core is cabled to no other network device")
    clusters = sorted(twin_clusters(graph, heads, pairs, near), key=lambda c: sorted(nodes[k].hostname for k in c)[0])
    zones = [Zone(key=f"z{i}", head=frozenset(c)) for i, c in enumerate(clusters)]
    owner: dict[str, Zone] = {}
    for zone in zones:
        for k in zone.head:
            owner[k] = zone
            zone.members.add(k)
    frontier = list(heads)
    while frontier:
        wanted: dict[str, Counter] = defaultdict(Counter)
        for k in frontier:
            for m in near[k]:
                if m in infra and m not in owner:
                    wanted[m][owner[k].key] += 1
        by_key = {z.key: z for z in zones}
        taken: list[str] = []
        for m in sorted(wanted, key=lambda x: nodes[x].hostname):
            votes = wanted[m]
            top = max(votes.values())
            tied = [by_key[z] for z, v in votes.items() if v == top]
            if len(tied) > 1:                                  # a tie: the block that already holds devices of the same kind, then the larger block, then the first
                tied.sort(key=lambda z: (-sum(1 for x in z.members if nodes[x].role_hint == nodes[m].role_hint), -len(z.members), z.key))
            owner[m] = tied[0]
            taken.append(m)
        for m in taken:
            owner[m].members.add(m)
        frontier = taken
    leftover = [k for k in infra if k not in owner]
    seen: set[str] = set()
    for k in sorted(leftover, key=lambda x: nodes[x].hostname):          # devices the core's cables never reach: one block per connected group, beside the core
        if k in seen:
            continue
        comp, stack = [], [k]
        seen.add(k)
        while stack:
            x = stack.pop()
            comp.append(x)
            for y in near[x]:
                if y in infra and y not in owner and y not in seen:
                    seen.add(y)
                    stack.append(y)
        zone = Zone(key=f"z{len(zones)}", head=frozenset(), members=set(comp), kind="other")
        if any(nodes[m].role_hint in END_ROLES for x in comp for m in near_all[x]):
            zone.kind = "internal"                                         # a stack of its own with end points under it (a second stack of a floor): a LAN zone, not a leftover
        zones.append(zone)
        for x in comp:
            owner[x] = zone
    if managed:
        zone = Zone(key=f"z{len(zones)}", head=frozenset(), members=set(managed), kind="management")
        zones.append(zone)
        for x in managed:
            owner[x] = zone
    for side in (-1, 1):                                                 # the devices of other sites: one block on each side
        mine = {k for k in foreign if (ghost_side or {}).get(k, 1) == side}
        if mine:
            zone = Zone(key=f"z{len(zones)}", head=frozenset(), members=mine, kind="ghost", side=side)
            zones.append(zone)
            for x in mine:
                owner[x] = zone
    zones = split_groups(graph, zones, owner, near)
    centre_ends: set[str] = set()
    for k in sorted(members):
        if nodes[k].role_hint not in END_ROLES or k in foreign:
            continue
        votes: Counter = Counter()
        for m in near[k]:
            if m in centre:
                votes["centre"] += 1
            elif m in owner:
                votes[owner[m].key] += 1
        if not votes:
            continue
        top = max(votes.values())
        pick = sorted(z for z, v in votes.items() if v == top)[0]
        if pick == "centre":
            centre_ends.add(k)
        else:
            next(z for z in zones if z.key == pick).ends.add(k)
    zones = [z for z in zones if z.members]
    for zone in zones:
        classify(graph, zone, ghosts)
    zones = merge_ways_out(graph, zones)
    zones = merge_leaf_zones(merge_ways_out(graph, split_tall(graph, zones, near)))
    zones = split_big(graph, zones, near, ghosts)
    real = [z for z in zones if z.kind not in ("management", "ghost")]
    if not real and not small:
        return no("all the network devices hang from one device of the core")
    infra_total = sum(len(z.members) for z in real)
    mixed = [len(z.members) for z in real if not (z.kind == "internal" and _own_ends(z, near) >= HUB_ENDS) and not all(nodes[k].role_hint in OUTER_ROLES for k in z.members)]      # a way out made of routers only (the WAN routers and every router that hangs from them) is one row, not a block that hides the structure; an internal block that carries a crowd of its own end points (one distribution hub with its closets and its users) is the LAN under the core and is drawn as such even when it holds every switch; an internal block without them that holds nearly everything says nothing about the structure
    if infra_total and mixed and max(mixed) > BIGGEST_SHARE * infra_total and infra_total >= 2 * ZONES_MIN_INFRA:
        return no("one block holds nearly all the network devices")
    for zone in zones:
        zone.title = title_of(graph, zone)
    return ZonePlan(centre, centre_ends, zones)


def outer_key(graph: Graph, k: str) -> str:
    """The way out a router belongs to (``wan``, ``internet`` or ``partner``): the function the engine gave it (from names, model and cabling), else the words in its name.  Empty when neither says."""
    function = getattr(graph.nodes[k], "function", "")
    if function in GROUP_ORDER:
        return function
    return KEY_TITLES.get(_title_from_names(graph, [k]), "")


def split_groups(graph: Graph, zones: list[Zone], owner: dict[str, Zone], near: dict[str, set[str]]) -> list[Zone]:
    """A block with several ways out (an edge switch with the internet router, the extranet router, the WAN routers and the branch routers cabled to it) is cut by the way out: the WAN routers
    with the switch that serves them, the internet routers with their provider gateways, the extranet routers with their partner routers are each their own zone.  A neighbour with no way out
    of its own (a provider gateway, a partner router nobody named) follows the router it hangs from, whatever it is called; one that hangs only from the head stays with the head."""
    nodes = graph.nodes
    out: list[Zone] = []
    for zone in zones:
        if zone.kind in ("management", "other", "ghost"):
            out.append(zone)
            continue
        routers = {k for k in zone.members if nodes[k].role_hint in OUTER_ROLES and k not in zone.head}
        keyed = {k: outer_key(graph, k) for k in routers}
        present = Counter(v for v in keyed.values() if v)
        if len(present) < 2:
            out.append(zone)
            continue
        key_of = {k: v for k, v in keyed.items() if v}
        for _ in range(3):                                           # a neighbour without a key takes the key of the routers it hangs from
            for k in sorted(routers):
                if k not in key_of:
                    votes = Counter(key_of[m] for m in near[k] if m in key_of)
                    if votes:
                        key_of[k] = sorted(votes, key=lambda v: (-votes[v], GROUP_ORDER.index(v)))[0]
        direct = Counter(key_of[k] for k in routers if k in key_of and near[k] & zone.head)       # the routers cabled to the head decide whether it is the switch of one way out or a hub for all of them
        total = sum(direct.values())
        keep = max(direct, key=lambda v: (direct[v], -GROUP_ORDER.index(v))) if total else ""
        if total and direct[keep] < DEDICATED_SHARE * total:
            keep = ""                                                # a hub (the edge switch of the internet, the extranet and the WAN): it is a zone of its own
        count = Counter(key_of.values())
        out.append(zone)                                             # what stays in the block is the head, the switches under it and, for a switch of one way out, that way out
        for key in GROUP_ORDER:
            if key not in count or key == keep:
                continue
            group = {k for k, v in key_of.items() if v == key}
            ends = {k for k in zone.ends if near[k] and near[k] & zone.members <= group}
            new = Zone(key=f"{zone.key}{key[0]}", head=frozenset(k for k in group if near[k] - group), members=group, ends=ends)
            zone.members -= group
            zone.ends -= ends
            for k in group:
                owner[k] = new
            out.append(new)
    return out


def _own_ends(zone: Zone, near: dict[str, set[str]]) -> int:
    """The most end points (frames) that one switch of the zone has under it: a hub with its own users has many, a block of closets each with a few users has none worth a zone of its own."""
    count: Counter = Counter(switch for end in zone.ends for switch in near.get(end, ()) if switch in zone.members)
    return max(count.values(), default=0)


def split_big(graph: Graph, zones: list[Zone], near: dict[str, set[str]], ghosts) -> list[Zone]:
    """A block that still holds nearly all the network devices of the page (one edge switch pair with the WAN routers, their branch routers and a few switches, all cabled through it) is no
    picture of zones.  It is cut where the outside begins, as ``split_tall`` does for a tall block: the routers (with the routers that hang from them) become a zone of their own, the way
    out above, and the head with the switches below it stay the other zone.  A block that has no router, or only routers, is kept."""
    nodes = graph.nodes
    real = [z for z in zones if z.kind not in ("management", "ghost")]
    total = sum(len(z.members) for z in real)
    if total < 2 * ZONES_MIN_INFRA:
        return zones
    out: list[Zone] = []
    for zone in zones:
        if zone.kind in ("management", "other", "ghost") or len(zone.members) <= BIGGEST_SHARE * total:
            out.append(zone)
            continue
        routers = {k for k in zone.members if nodes[k].role_hint in OUTER_ROLES and k not in zone.head}
        rest = zone.members - routers
        if not routers or not rest or not zone.head:
            out.append(zone)
            continue
        ends = {k for k in zone.ends if near[k] and near[k] <= routers | zone.members and not near[k] & rest}
        way = Zone(key=f"{zone.key}r", head=frozenset(k for k in routers if near[k] & rest) or frozenset(routers), members=routers, ends=ends, kind="external")
        zone.members = rest
        zone.ends = zone.ends - ends
        classify(graph, zone, ghosts)
        out.extend((zone, way))
    return out


def merge_ways_out(graph: Graph, zones: list[Zone]) -> list[Zone]:
    """Zones that are the same way out are one zone: the WAN router that hangs from the core and the WAN routers cut from the edge switch's block, the internet router that only the management switch
    reaches and the internet router next to it.  A block of routers nobody cabled to the core (kind ``other``) joins the way out of its own kind, or is a way out of its own."""
    nodes = graph.nodes

    def key_of(zone: Zone) -> str:
        votes = Counter(outer_key(graph, k) for k in zone.members if nodes[k].role_hint in OUTER_ROLES and outer_key(graph, k))
        return sorted(votes, key=lambda v: (-votes[v], GROUP_ORDER.index(v)))[0] if votes else ""

    for zone in zones:
        if zone.kind == "other" and zone.members and all(nodes[k].role_hint in OUTER_ROLES for k in zone.members):
            zone.kind = "external"
    base: dict[str, Zone] = {}
    out: list[Zone] = []
    for zone in zones:
        key = key_of(zone) if zone.kind == "external" else ""
        if key and key in base:
            first = base[key]
            first.members |= zone.members
            first.ends |= zone.ends
            first.head = first.head | zone.head
            continue
        if key:
            base[key] = zone
        out.append(zone)
    return out


LEAF_ZONES_MIN = 2                 # this many single switches under the centre (no end points, nothing below them) stand in one box


def merge_leaf_zones(zones: list[Zone]) -> list[Zone]:
    """Single switches under the centre that have nothing below them (the access switches of other floors, the little L2 switches of a branch) are one block: one box with the switches side by side
    under their parent, not one box each."""
    singles = [z for z in zones if z.kind == "internal" and len(z.members) == 1 and not z.ends and z.head and z.head == frozenset(z.members)]
    if len(singles) < LEAF_ZONES_MIN:
        return zones
    first = singles[0]
    for zone in singles[1:]:
        first.members |= zone.members
        first.head = first.head | zone.head
    return [z for z in zones if z is first or z not in singles]


def classify(graph: Graph, zone: Zone, ghosts) -> None:
    if zone.kind in ("management", "other", "ghost"):
        return
    nodes = graph.nodes
    outer = [k for k in zone.members if nodes[k].role_hint in OUTER_ROLES]
    inner = [k for k in zone.members if nodes[k].role_hint in ("access", "switch", "wlc")]
    framed = bool(zone.ends)
    inner_count = len(inner) + (1 if framed else 0)
    outward = bool(zone.head) and any(getattr(nodes[k], "function", "") in OUTWARD_FUNCTIONS for k in zone.head) and not _lan_head(nodes, zone)
    if outer and inner_count >= TALL_MIN_INNER and not outward:
        zone.kind = "tall"
    elif outer:
        zone.kind = "external"
    elif zone.head and any(getattr(nodes[k], "function", "") in OUTWARD_FUNCTIONS for k in zone.head) and not _lan_head(nodes, zone):
        zone.kind = "external"                                  # an edge, internet or partner switch pair with what hangs from it (firewalls, an extranet switch): the way out, whatever stands below it
    else:
        zone.kind = "internal"


OUTWARD_FUNCTIONS = ("edge", "internet", "partner", "wan")


def _lan_head(nodes, zone: Zone) -> bool:
    """True when the end points of the block say that it is a LAN (users, phones, access points under its switches): an edge pair with a user LAN below it is a distribution, not a way out."""
    users = sum(1 for k in zone.ends if nodes[k].role_hint in ("host", "phone", "ap"))
    return users >= 3 and users > len(zone.members)


def split_tall(graph: Graph, zones: list[Zone], near: dict[str, set[str]]) -> list[Zone]:
    """A tall block that holds a large share of the page (a server farm with the extranet routers behind its firewall) cannot stand at the side: the page would be twice as wide as the rows
    it is made of.  It is cut where the outside begins: the routers and providers, with the firewalls and load balancers cabled to them, become an external block of their own (above the
    core), and the switches and end points stay one internal block under the head (below the core).  A block whose head is itself one of the outer devices is kept as it is."""
    nodes = graph.nodes
    total = sum(len(z.members) + len(z.ends) for z in zones if z.kind not in ("ghost", "management"))
    out: list[Zone] = []
    for zone in zones:
        if zone.kind != "tall" or not total or len(zone.members) + len(zone.ends) <= max(TALL_MIN_SPLIT, TALL_MAX_SHARE * total):
            out.append(zone)
            continue
        routers = {k for k in zone.members if nodes[k].role_hint in OUTER_ROLES}
        gates = {k for k in zone.members if nodes[k].role_hint in ("firewall", "loadbalancer") and k not in zone.head and near[k] & routers}
        outer = routers | gates
        if not outer or zone.head & outer or not (zone.members - outer):
            out.append(zone)
            continue
        inner = Zone(key=zone.key, head=zone.head, members=zone.members - outer, ends={k for k in zone.ends if not (near[k] & outer) or near[k] & (zone.members - outer)}, kind="internal")
        way_out = Zone(key=f"{zone.key}x", head=frozenset(k for k in outer if near[k] - outer), members=set(outer), ends=zone.ends - inner.ends, kind="external")
        out.extend((inner, way_out))
    return out


def _behind_routers(graph: Graph, zone: Zone) -> bool:
    """More than half of the switches of an internal block below its head have a router of a way out as neighbour (the branch switches behind the WAN routers)."""
    below = [k for k in zone.members if k not in zone.head]
    if len(below) < 2:
        return False
    near = _near(graph, set(graph.nodes))                              # the routers stand in another zone: look at the whole graph
    hit = [k for k in below if any(graph.nodes[m].role_hint in OUTER_ROLES and outer_key(graph, m) for m in near.get(k, ()))]
    return len(hit) * 2 > len(below)


def title_of(graph: Graph, zone: Zone) -> str:
    nodes = graph.nodes
    named = _title_from_names(graph, zone.members)
    functions = Counter(getattr(nodes[k], "function", "") for k in zone.members)
    servers = sum(1 for k in zone.ends if nodes[k].role_hint == "server")
    users = sum(1 for k in zone.ends if nodes[k].role_hint in ("host", "phone", "ap"))
    if zone.kind == "management":
        return "MANAGEMENT"
    if zone.kind == "other":
        return named or "OTHER DEVICES"
    if zone.kind == "ghost":
        return "OTHER SITE"
    if zone.kind == "internal" and _behind_routers(graph, zone):
        return "BRANCH SWITCHES"                                               # switches cabled to WAN or branch routers, not to the core: a branch, whatever their users are
    inner = ""
    if servers > users or functions.get("tor"):
        inner = "SERVER FARM"
    elif zone.ends or functions.get("access") or functions.get("distribution"):
        inner = "LAN / USER"
    outer = named
    routers = [k for k in zone.members if nodes[k].role_hint in OUTER_ROLES and outer_key(graph, k)]
    if routers and zone.kind in ("external", "tall"):                   # the way out the routers belong to titles the zone (a firewall named PUBLIC in a WAN zone does not make it the internet)
        votes = Counter(outer_key(graph, k) for k in routers)
        dominant = sorted(votes, key=lambda v: (-votes[v], GROUP_ORDER.index(v)))[0]
        outer = next(t for t, key in KEY_TITLES.items() if key == dominant)
    elif zone.kind == "external" and zone.head and all(getattr(nodes[k], "function", "") in OUTWARD_FUNCTIONS for k in zone.head) and not routers:
        outer = "EDGE"                                                   # the switch that serves several ways out is the edge, whatever its neighbours are called
    if not outer:
        for function, text in (("internet", "INTERNET / PUBLIC"), ("partner", "EXTRANET / 3RD PARTY"), ("wan", "WAN / BRANCH"), ("edge", "EDGE")):
            if functions.get(function):
                outer = text
                break
    if zone.kind == "tall":
        return f"{inner} + {outer}" if inner and outer else (inner or outer or "DMZ")
    if zone.kind == "external":
        return outer or "EXTERNAL / WAN"
    return named or inner or "INTERNAL"


def block_rows(graph: Graph, zone: Zone) -> dict[str, float]:
    """The row of every device of an internal block, counted from its head (the devices the core is cabled to): it hangs from its head, row 0 on top, and the end points stand in
    the row under their switch.  (The plain layout would put a server farm's top-of-rack switches above the firewall pair that the core is cabled to, because of their role.)
    An external block and a tall one (outside and inside in one block) keep the rows of the plain layout, which reads from the providers down.  Empty for a block without a head."""
    if zone.kind != "internal" or not zone.head:
        return {}
    near = _near(graph, zone.keys)
    depth: dict[str, int] = {k: 0 for k in zone.head if k in zone.members}
    queue = list(depth)
    while queue:
        nxt: list[str] = []
        for k in queue:
            for m in sorted(near[k]):
                if m in zone.members and m not in depth:
                    depth[m] = depth[k] + 1
                    nxt.append(m)
        queue = nxt
    for k in zone.members:
        depth.setdefault(k, max(depth.values(), default=0) + 1)
    for k in sorted(zone.ends):
        parents = [depth[m] for m in near[k] if m in depth and m in zone.members]
        depth[k] = (max(parents) + 1) if parents else max(depth.values(), default=0) + 1
    return {k: float(v) for k, v in depth.items()}
