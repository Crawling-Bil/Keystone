"""Sites from the hostnames and the cables ("Sites (smart)" grouping, and what "Automatic" uses when the names are not tidy).

The plain prefix grouping cuts the first one, two or three hostname words and trusts them.  Real networks are not that tidy:

* ``HQWANR1``, ``HQSDWANR2``, ``HQKSR1`` have no separator: each name is its own "site".  A *site code* is learned from the names themselves: a short start
  that many longer first words share and that is followed by different role letters (HQ + WAN, HQ + SDWAN, HQ + KS ...), and that the devices carrying it are cabled
  to each other.
* ``LT02`` and ``LT2``, ``SW01`` and ``SW1`` are one word with and without a zero.  Letter case does not matter either.
* A device with a name of its own (a WLC ``JLN-WLC-GF-01``, a MikroTik ``MIKROTIK-JAS``) belongs where its cables or the last word of its name lead (``JAS`` is the last word
  of ``KCU-SENAYAN-JAS``), not in a "site" of one.
* One name family that falls into parts with no cable between them (two buildings that carry the same first words) is more than one site.

Everything is decided from what is in the graph (names, captured or not, the cables); nothing here is a list of customers or site names.
"""

from __future__ import annotations

import math
import re
from collections import Counter, defaultdict
from dataclasses import dataclass

from .graph import Graph

ENDPOINTS = ("ap", "phone", "host", "server")
OTHER = "Other devices"
CODE_MIN_LEN = 2                 # a learned site code has at least this many letters
CODE_MIN_HEADS = 3               # ... and starts at least this many different longer first words
CODE_MIN_NEXT = 3                # ... which continue with at least this many different letters
CODE_MIN_CABLED = 0.25           # ... and at least this share of the devices that carry it has a cable to another one that carries it
AFFINITY_MIN_LEN = 3             # a word of a device name that names its site (JAS) has at least this many characters
SMALL_SITE = 2                   # a name family of at most this many network devices follows the one site its cables lead to
CONNECTED_SPLIT_MIN = 100        # the connected sites of a deeper name level (the floors of one building) are pages of their own from this many devices drawn
CONNECTED_SHARE = 0.8            # ... "connected" = this share of them hangs together by cables
PEERS = 2                       # a family with this many others that differ only in the last word of the name is one of a row of equals (floors, buildings)
HOST_SITE_MIN = 3                # ... if that site has at least this many network devices
SPLIT_MIN_SITE = 4               # a site with fewer network devices is never split by its cables
UNCABLED_PART = 3                # a part of at most this many network devices that no cable joins to the rest of the site (a firewall pair captured from its manager) is no site of its own
SPLIT_MIN_PART = 2               # every part of a split site has at least this many network devices, one of them captured
SMART_MIN_CAPTURED = 3           # "Automatic" draws a small network by sites when two sites have at least this many captured network devices
SMART_MIN_DEVICES = 15           # ... and the picture has at least this many devices
NEAR_MIN_LEN = 4                 # two site names that differ by one letter in a word of this many letters or more, and are cabled together, are one site (SENAYAN, SENAYN)
LEAD_MIN_DEVICES = 3             # a first word that is a role (SW, RTR, FW) starts at least this many names
LEAD_MIN_SITES = 3               # ... in front of at least this many different site words (letters, not counters: SW1, SW2 is one word) ...
LEAD_DOMINANT = 0.6              # ... and one such word alone may start this share of the names when each site word follows it more than once
ROLE_WORDS = {"SW", "RTR", "RT", "FW", "SWITCH", "ROUTER", "CSW", "DSW", "ASW", "ESW", "TOR", "SPINE", "LEAF", "PE", "CE", "GW", "WLC", "AP", "LB"}   # first words that name a role: only these may stand in front of a floor or building word (A02, LT3)
LEAD_MIN_UNIT_DEVICES = 2        # a floor / building word (letters and a number: A02, B01, LT3) must name at least this many devices to count as a site word
ROLE_NAMES = {"AGG", "AGGR", "DS", "DSW", "DIST", "DISTRIBUTION", "CORE", "EDGE", "ACC", "ACCESS", "TOR", "MGMT", "MGT", "OOB", "INET", "INTERNET", "WAN", "LAN", "SPINE", "LEAF", "BORDER", "EXT", "PTNR", "PARTNER", "SVC", "SERVICE", "DMZ"}   # words that name what a device does
GENERIC = {"SW", "RTR", "RT", "FW", "SWITCH", "ROUTER", "CORE", "DIST", "ACC", "ACCESS", "EDGE", "WAN", "LAN", "AP", "WLC", "LB", "OFF", "OFFICE", "MGT", "MGMT", "SDWAN", "BO", "DC", "DR", "HQ"}


RECOVERY = {"DR", "DRC", "DRS", "DRP", "BCP", "SDC"}         # a word of a site name that says the site takes over when the main one fails: it is drawn after the main site
QUALIFIERS = {"DC", "DR", "DRC", "DRS", "DRP", "BCP", "PDC", "SDC", "NDC"}   # a word right after the site word that says which part of the place the devices are (HQ-DC-CORE1, HQ-DR-CORE1): it is part of the site's name


QUALIFIED_MIN = 2                 # a zone word splits a site only when at least this many captured devices spell it


def _zone_word(graph: Graph, key: str, depth: int) -> str | None:
    """The word after the ``depth`` words of the site in the hostname of a captured, named device ("" when the name stops there); None for any other device."""
    host = _host(graph, key)
    if not (graph.nodes[key].captured and "::" not in key and is_named(host)):
        return None
    parts = [p for p in re.split(r"[-_\s]+", re.sub(r"\s*\[.*?\]\s*", " ", host).strip()) if p]
    return parts[depth] if len(parts) > depth + 1 else ""


def qualify(graph: Graph, groups: dict[str, list[str]]) -> dict[str, list[str]]:
    """Name a site ``HQ-DC`` and not ``HQ`` when every captured device of it spells HQ-DC-... : the second word is a zone word (``QUALIFIERS``), not a role (CORE) or a counter (SW1),
    so it says where the devices are.  When the captured devices spell *different* zone words and no other (HQ-DC-CORE1 beside HQ-DR-CORE1, each word on at least
    ``QUALIFIED_MIN`` devices), the first word has joined two places: the site is split into HQ-DC and HQ-DR, a device nobody captured following the part it is cabled to most.
    A site whose devices spell any other word keeps its name; so does a site whose qualified name is already taken."""
    out: dict[str, list[str]] = {}
    for name, keys in groups.items():
        parts_out: dict[str, list[str]] = {name: keys}
        if name != OTHER:
            depth = len(words(name))
            zone = {key: _zone_word(graph, key, depth) for key in keys}
            spelled = {w for w in zone.values() if w is not None}
            counts = {w: sum(1 for v in zone.values() if v == w) for w in spelled}
            if len(spelled) == 1 and next(iter(spelled)).upper() in QUALIFIERS:
                parts_out = {f"{name}-{next(iter(spelled))}": keys}
            elif len(spelled) >= 2 and all(w.upper() in QUALIFIERS and counts[w] >= QUALIFIED_MIN for w in spelled):
                labels = {w: f"{name}-{w}" for w in sorted(spelled, key=lambda w: (w.upper() in RECOVERY, w.upper()))}
                if all(label not in groups and label not in out for label in labels.values()):
                    owner = {key: w for key, w in zone.items() if w is not None}
                    loose = [key for key in keys if key not in owner]
                    near: dict[str, list[str]] = {key: [] for key in loose}
                    for conn in graph.connections:
                        if conn.a in near and conn.b in keys:
                            near[conn.a].append(conn.b)
                        if conn.b in near and conn.a in keys:
                            near[conn.b].append(conn.a)
                    first = next(iter(labels))
                    for _ in range(3):                              # a loose device follows what it is cabled to; a chain of them follows the first one that has an owner
                        for key in loose:
                            votes = Counter(owner[o] for o in near[key] if o in owner)
                            if key not in owner and votes:
                                owner[key] = max(votes, key=lambda w: (votes[w], w == first, w))
                    parts_out = {label: [k for k in keys if owner.get(k, first) == w] for w, label in labels.items()}
        for label, members in parts_out.items():
            out[label if label not in out and (label == name or label not in groups) else name] = members
    return out


def is_recovery(site: str) -> bool:
    """Does the name of a site say it is the recovery site (HQ-DR, DRC, BDG-DRC)?"""
    return any(word in RECOVERY for word in words(site))


def words(host: str) -> list[str]:
    """The words of a hostname, upper case, separated by - _ or a space; a ``[vdom]`` tail is not a word."""
    text = re.sub(r"\s*\[.*?\]\s*", " ", host or "").upper()
    return [w for w in re.split(r"[-_\s]+", text) if w]


def _pad(word: str) -> str:
    """LT02 -> LT2, 01 -> 1: a zero in front of a number does not make another word."""
    return re.sub(r"(?<=[A-Z])0+(?=\d)|^0+(?=\d)", "", word)


def is_named(host: str) -> bool:
    """A hostname a person gave the device (not an address, not a MAC address, not an address written with dashes)."""
    text = (host or "").strip()
    parts = words(text)
    if not parts or not any(re.search(r"[A-Z]", p) for p in parts):
        return False
    if re.fullmatch(r"(?:[0-9A-Fa-f]{2}[:.-]?){5}[0-9A-Fa-f]{2}|(?:[0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4}", text):
        return False
    return not all(p.isdigit() for p in parts)


def _host(graph: Graph, key: str) -> str:
    node = graph.nodes[key]
    if "::" in key and key.split("::")[0] in graph.nodes:
        node = graph.nodes[key.split("::")[0]]
    return node.chassis or node.hostname or key


def _is_network(graph: Graph, key: str) -> bool:
    return graph.nodes[key].role_hint not in ENDPOINTS and "::" not in key


def _guessed_between_devices(graph: Graph, conn) -> bool:
    """A line between two network devices that no capture confirms: the two ends of a WAN circuit found from a shared point-to-point subnet, or a neighbor guessed from a route.
    It says the two are reachable, not that they stand in one building."""
    return (conn.kind == "inferred" or (bool(conn.links) and all(l.state == "inferred" for l in conn.links))) and _is_network(graph, conn.a) and _is_network(graph, conn.b)


def _near(graph: Graph, keys: set[str], cabled: bool = False) -> dict[str, set[str]]:
    """The devices each device has a line to.  ``cabled`` leaves out the lines between two network devices that were only inferred (a WAN circuit between a head office and a branch)."""
    near: dict[str, set[str]] = {key: set() for key in keys}
    for conn in graph.connections:
        if conn.kind in graph.hidden_kinds or conn.a not in near or conn.b not in near or conn.a == conn.b:
            continue
        if cabled and _guessed_between_devices(graph, conn):
            continue
        near[conn.a].add(conn.b)
        near[conn.b].add(conn.a)
    return near


def learn_codes(graph: Graph, keys: list[str], near: dict[str, set[str]]) -> set[str]:
    """Site codes that are glued to the role in the first word: HQ in HQWANR1, HQEDGNX1, HQKSR1 ...  A code is the shortest start (CODE_MIN_LEN letters or more) of a first word
    that CODE_MIN_HEADS or more different longer first words share, which those words continue with CODE_MIN_NEXT or more different letters (a role word after the code, not a
    counter), and whose devices are cabled to each other (a start shared by unrelated names is not a site)."""
    heads: dict[str, set[str]] = defaultdict(set)
    for key in keys:
        parts = words(_host(graph, key))
        if parts and is_named(_host(graph, key)):
            head = re.sub(r"\d+$", "", parts[0])
            if len(head) >= CODE_MIN_LEN and head.isalpha():
                heads[head].add(key)
    codes: set[str] = set()
    for head in sorted(heads, key=len):
        if any(head.startswith(code) for code in codes):
            continue
        for n in range(CODE_MIN_LEN, len(head)):
            prefix = head[:n]
            longer = [h for h in heads if h.startswith(prefix) and len(h) > n]
            if len(longer) < CODE_MIN_HEADS or len({h[n] for h in longer}) < CODE_MIN_NEXT:
                continue
            members = {k for h in heads if h.startswith(prefix) for k in heads[h]}
            cabled = {k for k in members if near.get(k, set()) & (members - {k})}
            if len(cabled) >= max(2, math.ceil(CODE_MIN_CABLED * len(members))):
                codes.add(prefix)
                break
    return codes


def _stem(word: str) -> str:
    return re.sub(r"\d+$", "", word)


def learn_leads(graph: Graph, keys: list[str]) -> set[str]:
    """First words that are roles, not sites (``SW-JKT-1``, ``RTR-JKT-1``, ``FW-BDG-1``: the site is the second word).  Two evidences, both from the names:

    * several first words (SW, RTR, FW) are followed by the same site words, and there are more site words than first words (a grid of roles by sites);
    * one first word starts most of the names and is followed by at least ``LEAD_MIN_SITES`` different site words, each more than once, that are not role words themselves.

    A site word is a word of letters: ``SW1``, ``SW2`` after ``JKT``, ``BDG`` is a counter on a role, which says the first word is the site."""
    after: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    named = 0
    for key in keys:
        host = _host(graph, key)
        if not is_named(host):
            continue
        parts = [_pad(p) for p in words(host)]
        named += 1
        if len(parts) >= 2:
            after[parts[0]][parts[1]] += 1
    eligible = {w: seconds for w, seconds in after.items() if sum(seconds.values()) >= LEAD_MIN_DEVICES and len(_stem(w)) >= 1}
    leads: set[str] = set()
    # a grid: the second words that stand after two or more first words
    carried: dict[str, set[str]] = defaultdict(set)
    for w, seconds in eligible.items():
        for second in seconds:
            if len(_stem(second)) >= 2:
                carried[_stem(second)].add(w)
    shared = {stem for stem, firsts in carried.items() if len(firsts) >= 2}
    if len(shared) >= LEAD_MIN_SITES and len(shared) > len(eligible):
        for w, seconds in eligible.items():
            mine = {_stem(x) for x in seconds if len(_stem(x)) >= 2}
            if len(mine & shared) >= 2 and len(mine & shared) >= 0.5 * len(mine):
                leads.add(w)
    # one dominant first word followed by many sites
    for w, seconds in eligible.items():
        if w in leads or sum(seconds.values()) < LEAD_DOMINANT * named:
            continue
        stems: dict[str, int] = defaultdict(int)
        for second, count in seconds.items():
            if len(_stem(second)) >= 2:
                stems[_stem(second)] += count
        many = [st for st, count in stems.items() if count >= 2 and st not in GENERIC]
        if len(many) >= LEAD_MIN_SITES and len(many) >= 0.5 * len(stems):
            leads.add(w)
    return leads | _learn_unit_leads(after, eligible, leads)


def _learn_unit_leads(after: dict[str, dict[str, int]], eligible: dict[str, dict[str, int]], found: set[str]) -> set[str]:
    """Role words in front of floors or buildings (``SW-A02-1``, ``RTR-A02-1``, ``SW-LT3-2``).  The site word is a letter and a number, so the stem that the first
    evidence compares (A02 and A08 are both ``A``) cannot tell the sites apart; here every such word is a site of its own.  Because a city and a floor read the same
    way (``KCU-LT1``, ``BDG-LT1``), this only counts after a first word that names a role (``ROLE_WORDS``), never after a word that might be a site."""
    roles = {w for w in eligible if _stem(w) in ROLE_WORDS and w not in found}
    if not roles:
        return set()
    units: dict[str, dict[str, int]] = {w: defaultdict(int) for w in roles}
    for w in roles:
        for second, count in after[w].items():
            if re.fullmatch(r"[A-Z]+\d+", second) and _stem(second) not in ROLE_WORDS and _stem(second) not in GENERIC:
                units[w][second] += count
    named = {u for per in units.values() for u, count in per.items() if sum(p.get(u, 0) for p in units.values()) >= LEAD_MIN_UNIT_DEVICES}
    if len(named) < LEAD_MIN_SITES:
        return set()
    leads = set()
    for w in roles:
        mine = sum(count for u, count in units[w].items() if u in named)
        if mine >= 0.5 * sum(after[w].values()) and len([u for u in units[w] if u in named]) >= 2:
            leads.add(w)
    return leads if len({u for w in leads for u in units[w] if u in named}) >= LEAD_MIN_SITES else set()


def site_words(host: str, codes: set[str]) -> list[str]:
    """The words of a hostname with the glued site code cut off the first word (HQWANR1 -> HQ, WANR1) and the zeros of numbers dropped."""
    parts = words(host)
    leads = {c[1:] for c in codes if c.startswith("^")}
    if len(parts) > 1 and _pad(parts[0]) in leads:
        parts = parts[1:]                                       # a role in front of the site word (SW-JKT-1): the site is the next word
    if parts:
        head = re.sub(r"\d+$", "", parts[0])
        for code in sorted(codes, key=len):
            if head.startswith(code) and len(parts[0]) > len(code):
                parts = [code, parts[0][len(code):]] + parts[1:]
                break
    return [_pad(p) for p in parts]


def name_key(host: str, take: int, codes: set[str]) -> str:
    """The site name a hostname gives at ``take`` words; a name with no more words than that is its own name (as the plain prefix grouping has it)."""
    parts = site_words(host, codes)
    return "-".join(parts[:take]) if len(parts) > take else "-".join(parts)


def _one_letter_apart(a: str, b: str) -> bool:
    """One letter added, dropped or changed (never a digit: LANTAI1 and LANTAI2 are two floors), both words long enough to be a name and not a counter."""
    if min(len(a), len(b)) < NEAR_MIN_LEN or abs(len(a) - len(b)) > 1 or a == b:
        return False
    i = 0
    while i < min(len(a), len(b)) and a[i] == b[i]:
        i += 1
    for rest_a, rest_b in ((a[i + 1:], b[i + 1:]), (a[i:], b[i + 1:]), (a[i + 1:], b[i:])):
        if rest_a == rest_b:
            changed = {a[i:i + 1], b[i:i + 1]} - {""}
            return not any(ch.isdigit() for ch in changed)
    return False


def _merge_near_names(groups: dict[str, list[str]], near: dict[str, set[str]]) -> None:
    """Two sites whose names differ by one letter in one word (KCU-SENAYAN-JAS and KCU-SENAYN-JAS) and that have a cable between them are one site: somebody mistyped."""
    names = [n for n in groups if n != OTHER]
    owner = {k: n for n, keys in groups.items() for k in keys}
    for a in names:
        for b in names:
            if a >= b or not groups.get(a) or not groups.get(b):
                continue
            wa, wb = a.split("-"), b.split("-")
            apart = [(x, y) for x, y in zip(wa, wb) if x != y]
            if len(wa) != len(wb) or len(apart) != 1 or not _one_letter_apart(*apart[0]):
                continue
            if not any(owner.get(m) == b for k in groups[a] for m in near.get(k, ())):
                continue
            keep, lose = (a, b) if len(groups[a]) >= len(groups[b]) else (b, a)
            groups[keep].extend(groups.pop(lose))
            for k in groups[keep]:
                owner[k] = keep


@dataclass
class Sites:
    take: int
    codes: set[str]
    groups: dict[str, list[str]]


def _spelled(graph: Graph, groups: dict[str, list[str]], take: int, codes: set[str]) -> dict[str, list[str]]:
    """A site is named as its devices spell it (JKT-A02), not as the zero-less key it was matched by (JKT-A2): the most common spelling of its first ``take`` words."""
    out: dict[str, list[str]] = {}
    for name, keys in groups.items():
        if name == OTHER:
            out[name] = keys
            continue
        count: dict[str, int] = defaultdict(int)
        for key in keys:
            parts = words(_host(graph, key))
            if parts and is_named(_host(graph, key)):
                head = re.sub(r"\d+$", "", parts[0])
                for code in sorted(codes, key=len):
                    if head.startswith(code) and len(parts[0]) > len(code):
                        parts = [code, parts[0][len(code):]] + parts[1:]
                        break
                if "-".join(_pad(p) for p in parts[:take]) == name or (len(parts) <= take and "-".join(_pad(p) for p in parts) == name):
                    count[("-".join(parts[:take]) if len(parts) > take else "-".join(parts))] += 1
        label = max(count, key=lambda t: (count[t], -len(t))) if count else name
        out[label if label not in out else name] = keys
    return out


def _components(members: list[str], near: dict[str, set[str]]) -> list[list[str]]:
    left, parts = set(members), []
    for start in members:
        if start not in left:
            continue
        part, stack = [], [start]
        left.discard(start)
        while stack:
            cur = stack.pop()
            part.append(cur)
            for nb in near.get(cur, ()):
                if nb in left:
                    left.discard(nb)
                    stack.append(nb)
        parts.append(part)
    return parts


def _lcp(graph: Graph, members: list[str], codes: set[str]) -> list[str]:
    paths = [site_words(_host(graph, k), codes) for k in members if is_named(_host(graph, k))]
    if not paths:
        return []
    out: list[str] = []
    for column in zip(*paths):
        if len(set(column)) != 1:
            break
        out.append(column[0])
    return out


def detect(graph: Graph, take: int, follow: bool = True) -> Sites:
    """Group the visible devices into sites at ``take`` hostname words, then let the evidence of the cables and of the names correct it (module doc)."""
    visible = [key for key in graph.nodes if key not in graph.hidden_nodes]
    near = _near(graph, set(visible))
    network = [k for k in visible if _is_network(graph, k)]
    codes = learn_codes(graph, network, near) | {"^" + w for w in learn_leads(graph, visible)}          # "^SW": a role word that stands before the site word
    groups: dict[str, list[str]] = {}
    for key in visible:
        host = _host(graph, key)
        name = name_key(host, take, codes)
        groups.setdefault(name, []).append(key)
    _merge_near_names(groups, near)
    # a "site" made only of devices nobody captured (a firewall, a server, a stray MAC name) is not a site
    loose = [k for name, keys in list(groups.items()) if all(not graph.nodes[k].captured for k in keys) for k in groups.pop(name)]
    if loose:
        groups.setdefault(OTHER, []).extend(loose)
    owner = {key: name for name, keys in groups.items() for key in keys}

    def network(name: str) -> list[str]:
        return [k for k in groups.get(name, []) if _is_network(graph, k)]

    def move(key: str, to: str) -> None:
        groups[owner[key]].remove(key)
        groups.setdefault(to, []).append(key)
        owner[key] = to

    if follow:
        _adopt_by_word(graph, groups, owner, near, move)
        _adopt_by_cable(graph, groups, owner, _near(graph, set(visible), cabled=True), move, network)
        _follow(graph, groups, owner, near, move)
    _split(graph, groups, owner, near, codes, take)
    for name in [n for n, keys in groups.items() if not keys]:
        groups.pop(name)
    return Sites(take, codes, _spelled(graph, groups, take, codes))


def _adopt_by_word(graph: Graph, groups, owner, near, move) -> None:
    """A device with a name of its own that no site gathered (MIKROTIK-JAS) joins the one site whose name has the same word (KCU-SENAYAN-JAS), when its cables do not
    lead to another site."""
    holders: dict[str, set[str]] = defaultdict(set)
    for name in groups:
        if name != OTHER:
            for part in re.split(r"[-]+", name):
                if len(part) >= AFFINITY_MIN_LEN and not part.isdigit() and part not in GENERIC:
                    holders[part].add(name)
    for key in list(owner):
        if owner[key] != OTHER or not is_named(_host(graph, key)):
            continue
        hits = {name for part in site_words(_host(graph, key), set()) if len(part) >= AFFINITY_MIN_LEN for name in holders.get(part, ())}
        if len(hits) != 1:
            continue
        site = next(iter(hits))
        elsewhere = {owner[m] for m in near[key]} - {OTHER, site}
        if not elsewhere:
            move(key, site)


def _is_peer(name: str, groups: dict[str, list[str]]) -> bool:
    """A family that has at least PEERS others with the same name but for the last word (the floors JKT-A02, JKT-A08, JKT-A09 of one building) is one of a row of equals, not a
    stray: its cables to the rest of the building are the building's uplinks, so it is never taken into a neighbour."""
    if "-" not in name:
        return False
    parent = name.rsplit("-", 1)[0]
    return sum(1 for n in groups if n != name and n != OTHER and "-" in n and n.rsplit("-", 1)[0] == parent) >= PEERS


def _adopt_by_cable(graph: Graph, groups, owner, near, move, network) -> None:
    """A name family of SMALL_SITE network devices or fewer (a WLC named after its vendor) whose cables all lead to one bigger site is part of that site."""
    for name in sorted(groups, key=lambda n: len(network(n))):
        if name == OTHER or not groups.get(name):
            continue
        if _is_peer(name, groups):
            continue
        members = network(name)
        if not members or len(members) > SMALL_SITE:
            continue
        out = {owner[m] for k in groups[name] for m in near[k]} - {name, OTHER}
        if len(out) == 1:
            site = next(iter(out))
            if len(network(site)) >= HOST_SITE_MIN:
                for key in list(groups[name]):
                    move(key, site)


def _follow(graph: Graph, groups, owner, near, move) -> None:
    """Devices still in "Other devices" go where all their cables lead (the rule of the plain grouping, a few passes for a chain)."""
    for _ in range(4):
        moved = {}
        for key in groups.get(OTHER, []):
            sites = {owner[m] for m in near[key]} - {OTHER}
            if len(sites) == 1:
                moved[key] = next(iter(sites))
        if not moved:
            break
        for key, name in moved.items():
            move(key, name)
    if not groups.get(OTHER):
        groups.pop(OTHER, None)


def _join_by_shared_uplink(graph: Graph, parts: list[list[str]], near: dict[str, set[str]], inside: set[str]) -> list[list[str]]:
    """Two parts of a site that have no cable between them but are both cabled to one captured device outside the site (the aggregation switch of the building, the core
    of the floor above) hang from the same place: they are one site, as the access switches of one floor are.  Parts that share only devices nobody captured (a provider's
    router) stay apart."""
    parts = [list(p) for p in parts]
    changed = True
    while changed:
        changed = False
        for i in range(len(parts)):
            for j in range(i + 1, len(parts)):
                up_i = {m for k in parts[i] for m in near.get(k, ())} - inside
                up_j = {m for k in parts[j] for m in near.get(k, ())} - inside
                if any(graph.nodes[m].captured and _is_network(graph, m) for m in up_i & up_j):
                    parts[i] += parts.pop(j)
                    changed = True
                    break
            if changed:
                break
    return parts


def _uncabled(graph: Graph, part: list[str], near: dict[str, set[str]]) -> bool:
    """A small part with no cable to any captured network device outside itself: a firewall pair read from its manager's configuration shows no neighbours at all."""
    return len(part) <= UNCABLED_PART and not any(m not in part and graph.nodes[m].captured and _is_network(graph, m) for k in part for m in near.get(k, ()))


def _split(graph: Graph, groups, owner, near, codes: set[str], take: int) -> None:
    """A site whose network devices fall into parts with no cable between them is more than one site: each part is named by the words its devices share."""
    for name in [n for n in groups if n != OTHER]:
        members = [k for k in groups[name] if _is_network(graph, k) and is_named(_host(graph, k))]
        if len(members) < SPLIT_MIN_SITE:
            continue
        inside = {k: near[k] & set(members) for k in members}
        parts = _components(members, inside)
        parts = _join_by_shared_uplink(graph, parts, near, set(members))
        big = [p for p in parts if len(p) >= SPLIT_MIN_PART and any(graph.nodes[k].captured for k in p)]
        loose = [p for p in big if _uncabled(graph, p, near)]
        if loose and len(loose) < len(big):             # ... it joins the largest part of the site: the names say it is there, no cable says it is anywhere else
            big = [p for p in big if p not in loose]
            max(big, key=len).extend(k for p in loose for k in p)
        if len(big) < 2:
            continue
        used = {name}
        for number, part in enumerate(sorted(big, key=lambda p: min(site_words(_host(graph, k), codes) for k in p)), 1):
            words_ = _lcp(graph, part, codes)
            text = "-".join(words_) if len(words_) > take else ""
            if not text or text in used:
                text = f"{name}-{number}"
            used.add(text)
            if text != name:
                for key in part:
                    groups[name].remove(key)
                    groups.setdefault(text, []).append(key)
                    owner[key] = text
        # end points follow the part their switch is in; the rest stay where they were
        for key in list(groups.get(name, [])):
            if _is_network(graph, key):
                continue
            sites = {owner[m] for m in near[key] if _is_network(graph, m)} - {OTHER}
            if len(sites) == 1 and next(iter(sites)) != name:
                site = next(iter(sites))
                groups[name].remove(key)
                groups.setdefault(site, []).append(key)
                owner[key] = site


def comparable(groups: dict[str, list[str]], graph: Graph) -> frozenset:
    """The partition of the network devices, to tell whether two groupings give the same sites."""
    return frozenset(frozenset(k for k in keys if _is_network(graph, k)) for name, keys in groups.items() if name != OTHER and any(_is_network(graph, k) for k in keys))


def joined(graph: Graph, found: Sites) -> bool:
    """Are the sites of ``found`` cabled to each other (network device to network device, across two sites)?  The floors of one building hang from the same aggregation
    switch: they are.  Independent sites (a head quarter and its branches, which meet only at a provider) are not."""
    named = {n: keys for n, keys in found.groups.items() if n != OTHER and len(keys) >= 2}
    owner = {k: n for n, keys in named.items() for k in keys if _is_network(graph, k)}
    parent = {n: n for n in named}

    def root(n: str) -> str:
        while parent[n] != n:
            parent[n] = parent[parent[n]]
            n = parent[n]
        return n

    for conn in graph.connections:
        if conn.kind in graph.hidden_kinds:
            continue
        a, b = owner.get(conn.a), owner.get(conn.b)
        if a and b and a != b:
            parent[root(a)] = root(b)
    sizes: dict[str, int] = defaultdict(int)
    for n in named:
        sizes[root(n)] += 1
    return bool(named) and max(sizes.values()) >= CONNECTED_SHARE * len(named)


def _sized(graph: Graph, found: Sites) -> dict[str, int]:
    """Network devices of every named site (the phones and access points of a site do not count towards its size)."""
    return {n: sum(1 for k in keys if _is_network(graph, k)) for n, keys in found.groups.items() if n != OTHER}


ZONE_SUFFIX_SHARE = 0.7         # a zone at the END of the name (SW-AGG1-DC, SW-AGG1-DRC) is the site when this share of the CAPTURED named network devices spells one, ...
ZONE_SUFFIX_DEVICES = 3         # ... and at least two zones each hold this many network devices, ZONE_SUFFIX_CAPTURED of them captured
ZONE_SUFFIX_CAPTURED = 2
ZONE_SUFFIX_WORDS = 3           # a name of fewer words (HQ-DC) has the zone as its site word already, the prefix grouping reads it


def zone_suffix(host: str) -> tuple[str, str] | None:
    """(site word in front, zone word) of a name that ends in a zone word and has a role and a counter before it (SW-AGG1-DC, SW-TOR2A-DRC, BGR-AGG1-DC), else None.  A first
    word that is a role (SW, FW) or a place everything shares (HQ) is not a site word: the zone alone is then the site (DC, DRC)."""
    parts = words(host)
    if len(parts) < ZONE_SUFFIX_WORDS or parts[-1] not in QUALIFIERS:
        return None
    lead = parts[0] if parts[0] not in ROLE_WORDS and parts[0] not in GENERIC and not re.search(r"\d", parts[0]) else ""
    return lead, parts[-1]


def detect_zones(graph: Graph) -> Sites | None:
    """Sites named by the zone word at the end of the hostnames, for a network whose names say the role first and the zone last (SW-AGG1-DC beside SW-AGG1-DRC): the prefix
    grouping would put the DC and the DRC switch with the same role in one box ("SW-AGG1") and no site would be a data center.  None unless most named network devices spell a zone
    word and at least two zones are real sites; the devices that spell no zone (a firewall named after its vendor, an end point) follow the cables."""
    visible = [key for key in graph.nodes if key not in graph.hidden_nodes]
    named = [k for k in visible if _is_network(graph, k) and is_named(_host(graph, k))]
    zoned = {k: zone_suffix(_host(graph, k)) for k in named}
    zoned = {k: v for k, v in zoned.items() if v}
    judged = [k for k in named if graph.nodes[k].captured]          # the captures are the evidence: the neighbours nobody captured (branch routers, a fabric interconnect) spell what they like
    if not judged or sum(1 for k in judged if k in zoned) < ZONE_SUFFIX_SHARE * len(judged):
        return None
    groups: dict[str, list[str]] = {}
    for key, (lead, zone) in zoned.items():
        groups.setdefault(f"{lead}-{zone}" if lead else zone, []).append(key)
    real = {n for n, keys in groups.items() if len(keys) >= ZONE_SUFFIX_DEVICES and sum(1 for k in keys if graph.nodes[k].captured) >= ZONE_SUFFIX_CAPTURED}
    if len(real) < 2:
        return None
    groups = {n: keys for n, keys in groups.items() if n in real}
    placed = {k for keys in groups.values() for k in keys}
    groups[OTHER] = [k for k in visible if k not in placed]
    owner = {key: name for name, keys in groups.items() for key in keys}
    near = _near(graph, set(visible))

    def move(key: str, to: str) -> None:
        groups[owner[key]].remove(key)
        groups.setdefault(to, []).append(key)
        owner[key] = to

    _follow(graph, groups, owner, near, move)
    for name in [n for n, keys in groups.items() if not keys]:
        groups.pop(name)
    return Sites(0, set(), groups)


GLUED_ZONES = ("DRC", "DRS", "DRP", "BCP", "PDC", "SDC", "NDC", "HQ", "DR", "DC")   # zone words that can be written in front of the rest of a name with no separator (HQPAFW1, DRPAFW1)
GLUED_REST_MIN = 3                # ... with at least this many characters after it (a letter first)
GLUED_TWINS = 2                   # a zone prefix is believed when this many names are the same behind it and behind another zone prefix (HQPASVCFW1, DRPASVCFW1)
GLUED_SHARE = 0.6                 # ... and most named network devices carry one
GLUED_FRAGMENT = 4                # the zone word replaces the sites of the names only when none of them holds more network devices than this (fragments no cable joins)


def _glued_options(host: str) -> list[tuple[str, str]]:
    """(zone, rest of the name) for each zone word the first word of a name begins with and continues with letters (DRCORENX1 is DR + CORENX1 or DRC + ORENX1: the twins decide)."""
    parts = words(host)
    if not parts or not is_named(host):
        return []
    first, tail = parts[0], parts[1:]
    return [(zone, "-".join([_pad(first[len(zone):])] + [_pad(p) for p in tail])) for zone in GLUED_ZONES
            if first.startswith(zone) and len(first) - len(zone) >= GLUED_REST_MIN and first[len(zone)].isalpha()]


def glued_zones(graph: Graph) -> dict[str, str]:
    """Device -> zone word, for a network whose names write the zone in front of the rest with no separator (HQPAFW1, DRPAFW1), learned from the names alone so that a set with
    no cable in it (the firewalls of one Panorama) is read too.  A zone word is believed only when at least ``GLUED_TWINS`` names are the same behind it and behind another zone
    word (a word like DRAGON or DCS7050 has no twin); {} unless at least two zones are believed and most named network devices carry one."""
    visible = [key for key in graph.nodes if key not in graph.hidden_nodes]
    named = {k: _glued_options(_host(graph, k)) for k in visible if _is_network(graph, k) and is_named(_host(graph, k))}
    behind: dict[str, set[str]] = defaultdict(set)
    for options in named.values():
        for zone, rest in options:
            behind[rest].add(zone)
    twins = Counter(zone for zones in behind.values() if len(zones) >= 2 for zone in zones)
    believed = {zone for zone, n in twins.items() if n >= GLUED_TWINS}
    zoned: dict[str, str] = {}
    for key, options in named.items():
        pick = [z for z, rest in options if z in believed and len(behind[rest]) >= 2] or [z for z, _ in options if z in believed]
        if pick:
            zoned[key] = pick[0]
    if len(zoned) < GLUED_SHARE * max(len(named), 1):
        return {}
    sizes = Counter(zoned.values())
    real = {z for z, n in sizes.items() if n >= ZONE_SUFFIX_DEVICES and sum(1 for k, v in zoned.items() if v == z and graph.nodes[k].captured) >= ZONE_SUFFIX_CAPTURED}
    return {k: z for k, z in zoned.items() if z in real} if len(real) >= 2 else {}


def detect_glued(graph: Graph) -> Sites | None:
    """Sites named by the zone word written in front of the names (HQ, DR); the devices that spell none follow the cables.  For a set whose cables say nothing (``glued_zones``)."""
    zoned = glued_zones(graph)
    if not zoned:
        return None
    visible = [key for key in graph.nodes if key not in graph.hidden_nodes]
    groups: dict[str, list[str]] = {}
    for key, zone in zoned.items():
        groups.setdefault(zone, []).append(key)
    groups[OTHER] = [k for k in visible if k not in zoned]
    owner = {key: name for name, keys in groups.items() for key in keys}
    near = _near(graph, set(visible))

    def move(key: str, to: str) -> None:
        groups[owner[key]].remove(key)
        groups.setdefault(to, []).append(key)
        owner[key] = to

    _follow(graph, groups, owner, near, move)
    for name in [n for n, keys in groups.items() if not keys]:
        groups.pop(name)
    return Sites(0, set(), groups)


def choose(graph: Graph) -> Sites | None:
    """The hostname depth (1, 2 or 3 words) whose sites fit a page, with at least two sites of two or more network devices; None when no depth gives readable sites.
    The same test as the plain "Automatic" (``layout.auto_mode``), applied to the sites ``detect`` finds after the evidence of the cables and of the names."""
    from .layout import AUTO_MAX_SITE, AUTO_MAX_SITES

    stamp = (len(graph.nodes), len(graph.connections), len(graph.hidden_nodes), len(graph.hidden_kinds))
    cache = graph.__dict__.get("_sites_cache")
    if cache and cache[0] == stamp:
        return cache[1]
    found = _choose(graph, AUTO_MAX_SITE, AUTO_MAX_SITES)
    graph.__dict__["_sites_cache"] = (stamp, found)
    return found


def _sites_of_two(found: Sites | None, max_sites: int) -> bool:
    return found is not None and sum(1 for n, keys in found.groups.items() if n != OTHER and len(keys) >= 2) >= 2 and len(found.groups) <= max_sites


def _choose(graph: Graph, max_site: int, max_sites: int) -> Sites | None:
    zones = detect_zones(graph)
    if _sites_of_two(zones, max_sites):
        return zones
    found = _choose_by_names(graph, max_site, max_sites)
    if found is not None and max(_sized(graph, found).values(), default=0) > GLUED_FRAGMENT:
        return found
    glued = detect_glued(graph)                    # the names cut the set into pairs and quads because no cable joins them, and they say HQ and DR: the zone word is the better evidence
    fits = glued is not None and max(_sized(graph, glued).values(), default=0) <= max_site
    return glued if fits and _sites_of_two(glued, max_sites) and readable(graph, glued) else found


def _named_by_role(found: Sites) -> bool:
    """Every site of a grouping is named only by what the devices ARE (SW, RTR, SW-AGG1, SW-TOR1A, SW-CORE): role words, counters and zone words, and no word that could name a place
    (SW-JKT has one).  Such names tell the role of a device and nothing says where it stands, so they are not sites."""
    names = [n for n in found.groups if n != OTHER]
    return bool(names) and all(not any(_place_word(w) for w in words(n)) for n in names)


def _place_word(word: str) -> bool:
    """A word that may name a place: letters (JKT, SENAYAN), or one or two letters and a number (S01, LT3, A02: a floor, a building), and neither a role nor a zone word.  Three letters
    or more with a number (AGG1, ASR1, TOR10A) are a counter on a role or a model."""
    found = re.fullmatch(r"([A-Z]+)(\d+[A-Z]?)?", word)
    if not found:
        return False
    stem, number = found.group(1), found.group(2)
    if stem in ROLE_WORDS or stem in ROLE_NAMES or stem in QUALIFIERS or stem == "SDWAN":              # HQ, BO and OFFICE are places, whatever GENERIC says about them alone
        return False
    return len(stem) >= 2 if not number else len(stem) <= 2


def _choose_by_names(graph: Graph, max_site: int, max_sites: int) -> Sites | None:
    fallback: tuple[int, Sites] | None = None
    for take in (1, 2, 3):
        found = detect(graph, take)
        sized = _sized(graph, found)
        if sum(1 for n, keys in found.groups.items() if n != OTHER and len(keys) >= 2) < 2 or len(found.groups) > max_sites:
            continue
        if _named_by_role(found):
            continue                       # SW and RTR, or SW-AGG1 and SW-TOR1A, are what the devices ARE, not where they stand: no site
        if take > 1 and joined(graph, found) and len([k for k in graph.nodes if k not in graph.hidden_nodes]) < CONNECTED_SPLIT_MIN:
            continue                       # parts of one connected site (the floors of one building) are pages of their own only when the whole is too big for one diagram
        biggest = max(sized.values())
        if biggest <= max_site:
            return found
        if fallback is None or biggest < fallback[0]:
            fallback = (biggest, found)
    return fallback[1] if fallback else None


def readable(graph: Graph, found: Sites | None) -> bool:
    """A small network is drawn by sites when two sites each hold SMART_MIN_CAPTURED captured network devices and the picture has SMART_MIN_DEVICES devices."""
    if found is None or len([k for k in graph.nodes if k not in graph.hidden_nodes]) < SMART_MIN_DEVICES:
        return False
    count = [sum(1 for k in keys if _is_network(graph, k) and graph.nodes[k].captured) for n, keys in found.groups.items() if n != OTHER]
    return sum(1 for c in count if c >= SMART_MIN_CAPTURED) >= 2


def quality(graph: Graph, found: Sites) -> tuple[int, int]:
    """(network devices in a site of two or more, network devices left in "Other devices"): the first is higher and the second lower for a better grouping."""
    sized = _sized(graph, found)
    inside = sum(n for n in sized.values() if n >= 2)
    other = sum(1 for k in found.groups.get(OTHER, []) if _is_network(graph, k))
    return inside, other


def one_site(graph: Graph, take: int) -> bool:
    """With the evidence of the cables and of the names, the devices of the plain grouping at ``take`` words are one site (or none that holds two devices)."""
    found = detect(graph, take)
    return sum(1 for n in _sized(graph, found).values() if n >= 1) <= 1


# ---- the engineer's own rules: "this is one site" -------------------------------------------------------------------------------------------------------------------

RULES_MAX = 60


def parse_rules(text: str) -> list[tuple[str, list[str]]]:
    """Site rules typed on the page, one per line: ``Label = start, start, ...``.  Every device whose hostname starts with one of the starts (letter case and spaces do not matter)
    is in the site ``Label``.  Empty lines, lines starting with # and lines without a label or a start are ignored."""
    rules: list[tuple[str, list[str]]] = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        label, _, rest = line.partition("=")
        starts = [re.sub(r"\s+", "", part).upper() for part in rest.split(",")]
        starts = [part for part in starts if part]
        if label.strip() and starts:
            rules.append((label.strip()[:40], starts))
    return rules[:RULES_MAX]


def apply_rules(graph: Graph, groups: dict[str, list[str]], rules: list[tuple[str, list[str]]]) -> dict[str, list[str]]:
    """The sites after the engineer's rules: a device whose hostname starts with a start of a rule moves to the site of that rule (the first rule that fits), and an end point
    whose network devices are now all in one site follows them.  Nothing else changes, so a rule only says what the names could not."""
    if not rules:
        return groups
    owner = {key: name for name, keys in groups.items() for key in keys}
    target: dict[str, str] = {}
    for key in owner:
        host = re.sub(r"\s+", "", _host(graph, key)).upper()
        for label, starts in rules:
            if any(host.startswith(start) for start in starts):
                target[key] = label
                break
    final = {key: target.get(key, owner[key]) for key in owner}
    near: dict[str, set[str]] = defaultdict(set)
    for conn in graph.connections:
        if conn.kind in graph.hidden_kinds or conn.a not in final or conn.b not in final:
            continue
        near[conn.a].add(conn.b)
        near[conn.b].add(conn.a)
    for key in owner:
        if key in target or _is_network(graph, key):
            continue
        sites = {final[m] for m in near[key] if _is_network(graph, m)}
        if len(sites) == 1 and next(iter(sites)) != final[key] and any(target.get(m) for m in near[key] if _is_network(graph, m)):
            final[key] = next(iter(sites))              # an end point of a switch the rules moved goes with it
    result: dict[str, list[str]] = {}
    for name, keys in groups.items():
        for key in keys:
            result.setdefault(final[key], []).append(key)
    return {name: keys for name, keys in result.items() if keys}
