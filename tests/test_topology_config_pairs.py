"""A vPC / M-LAG pair that no neighbor table shows is drawn from the two configurations (features/topology/pairs.py).

A Huawei CloudEngine capture holds no LLDP table, so the two ToR switches of an M-LAG pair stood side by side with no peer-link between them.  Invented names and ports.
"""

from __future__ import annotations

from features.topology.extract import Device
from features.topology.graph import build

MEMBERS = ["XGE1/0/47", "XGE1/0/48"]


def _tor(name, domain="1", model="CE6881-48S6CQ", members=MEMBERS, vendor="Huawei", keepalive="", ips=()):
    return Device(key=name, hostname=name, captured=True, vendor=vendor, model=model, vpc_domain=domain, vpc_peer_link="Po0" if members else "",
                  bundles={"Po0": list(members)} if members else {}, vpc_keepalive=keepalive, ips=set(ips))


def _peer_links(graph):
    return [c for c in graph.connections if c.kind == "peer-link"]


def test_two_switches_of_one_domain_and_model_with_the_same_peer_link_members_are_a_pair():
    graph = build([_tor("LAB-TOR1A"), _tor("LAB-TOR1B")])
    assert [(graph.nodes[a].hostname, graph.nodes[b].hostname, d) for a, b, d in graph.vpc_pairs] == [("LAB-TOR1A", "LAB-TOR1B", "1")]
    (conn,) = _peer_links(graph)
    assert (conn.a_po, conn.b_po) == ("Po0", "Po0") and [(l.a_port, l.b_port) for l in conn.links] == list(zip(MEMBERS, MEMBERS))
    assert all(l.state == "inferred" and "configuration" in l.note and l.protocols == {"CONFIG"} for l in conn.links)      # drawn as a peer-link, marked as read from the configuration


def test_a_domain_number_that_two_sites_reuse_pairs_nothing():
    graph = build([_tor("LAB-TOR1A"), _tor("LAB-TOR1B"), _tor("OTH-TOR1A"), _tor("OTH-TOR1B")])
    assert graph.vpc_pairs == [] and _peer_links(graph) == []


def test_other_models_other_members_or_no_members_are_no_pair():
    assert build([_tor("LAB-TOR1A"), _tor("LAB-TOR1B", model="CE6865-48S8CQ")]).vpc_pairs == []
    assert build([_tor("LAB-TOR1A"), _tor("LAB-TOR1B", members=["XGE1/0/45", "XGE1/0/46"])]).vpc_pairs == []
    assert build([_tor("LAB-TOR1A", members=[]), _tor("LAB-TOR1B", members=[])]).vpc_pairs == []


def test_keepalive_addresses_that_point_at_each_other_pair_switches_of_different_models():
    a = _tor("LAB-AGG1", domain="140", vendor="Cisco", model="N9K-C93180YC-FX", keepalive="10.0.0.2", ips={"10.0.0.1"})
    b = _tor("LAB-AGG2", domain="140", vendor="Cisco", model="N9K-C93240YC-FX2", keepalive="10.0.0.1", ips={"10.0.0.2"})
    graph = build([a, b])
    assert len(graph.vpc_pairs) == 1 and len(_peer_links(graph)) == 1


def test_a_pair_that_a_neighbor_table_shows_gets_no_second_peer_link():
    from tests.test_topology_config_only_pairs_and_models import _pair
    graph = _pair()["graph"]
    assert len(graph.vpc_pairs) == 1 and len(_peer_links(graph)) == 1
    assert all(l.state != "inferred" for l in _peer_links(graph)[0].links)


def test_a_third_switch_in_the_domain_makes_the_pairing_ambiguous():
    graph = build([_tor("LAB-TOR1A"), _tor("LAB-TOR1B"), _tor("OTH-AGG1", model="CE12804", members=["100GE1/0/1"])])
    assert graph.vpc_pairs == []


def test_keepalive_addresses_of_two_different_domains_pair_nothing():
    a = _tor("LAB-AGG1", domain="140", vendor="Cisco", model="N9K-C93180YC-FX", keepalive="10.0.0.2", ips={"10.0.0.1"})
    b = _tor("LAB-AGG2", domain="141", vendor="Cisco", model="N9K-C93240YC-FX2", keepalive="10.0.0.1", ips={"10.0.0.2"})
    assert build([a, b]).vpc_pairs == []
