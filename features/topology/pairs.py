"""The vPC / M-LAG pair that no neighbor table shows: two switches whose configurations say that they are the two peers of one domain.

Huawei CloudEngine captures hold no LLDP table (``display lldp neighbor`` is rarely collected), so the M-LAG peer-link (``dfs-group 1`` and ``peer-link 1`` on Eth-Trunk0)
is not a cable that anybody reported, and the two ToR switches of a pair stood side by side with no line between them.  The configuration is the evidence: the same
domain number, the same vendor and model, the same peer-link members, and where the configuration has them the keepalive addresses that point at each other.

The line is drawn like any peer-link (kind ``peer-link``, thick, counted in ``graph.vpc_pairs``) but its links are ``inferred`` and say where they come from, and it is added only for two
switches that have no peer-link connection yet.  Two switches of one model in one domain are not paired when a third has the same domain number (two sites reuse "domain 1"): that is ambiguous.

Huawei, "Configuring M-LAG" (CloudEngine data center switches):
https://support.huawei.com/enterprise/en/doc/EDOC1000039339/1e944f12/configuring-m-lag-and-vrrp-vrrp6-across-data-centers
Cisco, "Understand and Configure Nexus 9000 vPC":
https://www.cisco.com/c/en/us/support/docs/switches/nexus-9000-series-switches/218333-understand-and-configure-nexus-9000-vpc.html
"""

from __future__ import annotations

import re

from .graph import Connection, Graph, Link
from .names import canon_port, short_host

NOTE_DESCRIBED = "peer-link read from the configuration of both switches (same domain, model and peer-link members); the port descriptions name each other, no neighbor table showed the cable"
NOTE_ORDER = "peer-link read from the configuration of both switches (same domain, model and peer-link members); the members are paired in the order of their names, which is a guess: no neighbor table or description showed which cable goes where"
NOTE = "peer-link read from the configuration of both switches (same domain, model and peer-link members); no neighbor table showed the cable"

NOTES = {"description": NOTE_DESCRIBED, "same port": NOTE, "order": NOTE_ORDER}


def _members(graph: Graph, key: str) -> list[str]:
    node = graph.nodes[key]
    return sorted(node.bundles.get(node.vpc_peer_link, []))


def _addresses(graph: Graph, key: str) -> set[str]:
    node = graph.nodes[key]
    return set(node.ips) | ({node.mgmt_ip} if node.mgmt_ip else set())


def _words(text: str) -> set[str]:
    return {w for w in re.split(r"[^a-z0-9]+", text.lower()) if len(w) >= 3}


def _mentions(graph: Graph, owner: str, port: str, other: str) -> bool:
    """The description of ``port`` on ``owner`` names ``other`` (its host name, or the name before its first dot)."""
    text = graph.nodes[owner].descriptions.get(port) or graph.nodes[owner].descriptions.get(canon_port(port)) or ""
    name = graph.nodes[other].hostname.lower()
    return bool(text) and (name in text.lower() or short_host(name).lower() in _words(text))


def pair_members(graph: Graph, a: str, b: str, ma: list[str], mb: list[str]) -> list[tuple[str, str, str]]:
    """The cable behind each peer-link member of ``a`` and ``b``: (port of a, port of b, evidence).  Evidence in this order: a description that names the other switch (``description``),
    the same port name on both (the usual way a pair is cabled, ``same port``), then the order of the names (``order``, a guess; the members of one side are paired with what is left)."""
    pairs: list[tuple[str, str, str]] = []
    left_a, left_b = list(ma), list(mb)
    for pa in list(left_a):
        for pb in list(left_b):
            if _mentions(graph, a, pa, b) and _mentions(graph, b, pb, a) or (_mentions(graph, a, pa, b) and canon_port(pa) == canon_port(pb)):
                pairs.append((pa, pb, "description"))
                left_a.remove(pa)
                left_b.remove(pb)
                break
    for pa in list(left_a):
        same = next((pb for pb in left_b if canon_port(pb) == canon_port(pa)), None)
        if same is not None:
            pairs.append((pa, same, "same port"))
            left_a.remove(pa)
            left_b.remove(same)
    pairs += [(pa, pb, "order") for pa, pb in zip(left_a, left_b)]
    return pairs


def config_pairs(graph: Graph) -> None:
    paired = {key for a, b, _ in graph.vpc_pairs for key in (a, b)}
    loose = sorted(key for key, node in graph.nodes.items() if node.captured and node.vpc_domain and node.vpc_peer_link and key not in paired)
    chosen: list[tuple[str, str]] = []
    for i, a in enumerate(loose):                                                    # keepalive addresses that point at each other: the strongest evidence, any model
        for b in loose[i + 1:]:
            na, nb = graph.nodes[a], graph.nodes[b]
            if na.vpc_domain == nb.vpc_domain and na.vpc_keepalive and nb.vpc_keepalive and na.vpc_keepalive in _addresses(graph, b) and nb.vpc_keepalive in _addresses(graph, a):
                chosen.append((a, b))
    used = {key for pair in chosen for key in pair}
    groups: dict[tuple[str, str, str], list[str]] = {}
    for key in loose:
        node = graph.nodes[key]
        if key not in used:
            groups.setdefault((node.vendor, node.vpc_domain, node.model), []).append(key)
    for (vendor, domain, model), keys in groups.items():
        same_domain = [k for k in loose if k not in used and graph.nodes[k].vendor == vendor and graph.nodes[k].vpc_domain == domain]
        if len(keys) == 2 and len(same_domain) == 2 and _members(graph, keys[0]) and _members(graph, keys[0]) == _members(graph, keys[1]):
            chosen.append((keys[0], keys[1]))
    for a, b in chosen:
        na, nb = graph.nodes[a], graph.nodes[b]
        ma, mb = _members(graph, a), _members(graph, b)
        links = [Link(a, pa, b, pb, "inferred", {"CONFIG"}, NOTES[why]) for pa, pb, why in pair_members(graph, a, b, ma, mb)]
        if not links:
            continue
        graph.links += links
        graph.connections.append(Connection(a, b, links, na.vpc_peer_link, nb.vpc_peer_link, kind="peer-link"))
        graph.vpc_pairs.append((a, b, na.vpc_domain))
