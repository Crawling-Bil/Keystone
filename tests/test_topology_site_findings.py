"""Findings about a main site and its recovery site (TOPO-047 to 051), on the invented DC / DR demo with one thing changed in memory at a time."""

from __future__ import annotations

import copy
from functools import lru_cache

from features.topology import corpus, demo, service as S, sitefindings as SF
from features.topology.layout import auto_mode, groups_of


@lru_cache(maxsize=1)
def _built():
    item = next(i for i in demo.list_sets() if i["id"] == "dcdrc")
    files = [(f["name"], demo.read_file("dcdrc", f["name"]).decode("utf-8")) for f in item["files"]]
    built = S.build_topology(files, **{**corpus.BUILD, "group": item["group"]})
    return built["graph"], built["l3_pages"][0].l3["model"]


def _fresh():
    graph, model = _built()
    return copy.deepcopy(graph), model


def _ids(rows):
    return {r["id"]: r for r in rows}


def test_the_symmetric_demo_has_nothing_to_report():
    graph, model = _fresh()
    assert SF.site_findings(graph, model) == []


def test_the_pair_is_found_from_the_names_and_the_cables():
    graph, _ = _fresh()
    groups = groups_of(graph, auto_mode(graph))
    assert SF.twin_sites(graph, groups) == [("HQ-DC", "DRC")]
    small = {**groups, "DRC": groups["DRC"][:2]}                         # a recovery site of two devices is a branch
    assert SF.twin_sites(graph, small) == []
    assert SF.twin_sites(graph, {k: v for k, v in groups.items() if k != "DRC"}) == []          # no recovery site, no pair


def test_a_vlan_gateway_the_recovery_site_lacks_is_reported():
    graph, model = _fresh()
    for node in graph.nodes.values():
        if node.hostname.startswith("DRC"):
            node.l3 = [row for row in node.l3 if row["name"] not in ("Vlan911", "agg-edge.911")]
    row = _ids(SF.site_findings(graph, model))["TOPO-047"]
    assert row["severity"] == "low" and "VLAN 911" in row["detail"] and "DRC has not" in row["detail"]
    assert any(d.startswith("HQ-DC") for d in row["devices"]) and row["reference"].startswith("https://csrc.nist.gov")
    graph2, _ = _fresh()
    for node in graph2.nodes.values():
        if node.hostname.startswith("HQ-DC"):
            node.l3 = [row for row in node.l3 if row["name"] not in ("Vlan911", "agg-edge.911")]
    assert _ids(SF.site_findings(graph2, model))["TOPO-047"]["severity"] == "info"            # an extra gateway at the recovery site is only noted


def test_a_site_without_any_gateway_in_its_captures_is_not_judged_on_vlans():
    graph, model = _fresh()
    for node in graph.nodes.values():
        if node.hostname.startswith("DRC"):
            node.l3 = [row for row in node.l3 if row.get("kind") not in ("SVI", "Sub-interface")]
    assert "TOPO-047" not in _ids(SF.site_findings(graph, model))


def test_a_routing_protocol_one_site_lacks_is_reported():
    graph, model = _fresh()
    for node in graph.nodes.values():
        if node.hostname.startswith("DRC"):
            node.l3facts = {**node.l3facts, "neighbors": [n for n in node.l3facts.get("neighbors", []) if n.get("protocol") != "bgp"]}
    row = _ids(SF.site_findings(graph, model))["TOPO-048"]
    assert "protocol: only at HQ-DC: bgp" in row["detail"] and row["reference"].endswith("rfc2328#section-3.1")


def test_an_other_ospf_area_or_vrf_is_reported():
    graph, model = _fresh()
    for node in graph.nodes.values():
        if node.hostname.startswith("DRC-CORE"):
            for port in node.ifparams["ports"].values():
                if isinstance(port.get("ospf"), dict):
                    port["ospf"]["area"] = "0.0.0.5"
            node.l3 = [{**row, "vrf": "PROD"} if row["name"] == "Vlan901" else row for row in node.l3]
    detail = _ids(SF.site_findings(graph, model))["TOPO-048"]["detail"]
    assert "OSPF area" in detail and "0.0.0.5" in detail and "VRF: only at DRC: PROD" in detail


def test_fewer_firewalls_at_the_recovery_site_is_reported():
    graph, model = _fresh()
    graph.nodes["DRC-PADC2"].role_hint = "switch"
    row = _ids(SF.site_findings(graph, model))["TOPO-049"]
    assert row["severity"] == "low" and "firewall: 6 at HQ-DC, 5 at DRC" in row["detail"] and "DRC-PADC2" in row["devices"]


def _interconnect(graph):
    groups = groups_of(graph, auto_mode(graph))
    owner = {k: n for n, ks in groups.items() for k in ks}
    return owner, SF._cables(graph, owner)[("DRC", "HQ-DC")]


def test_an_interconnect_on_one_device_is_reported():
    graph, model = _fresh()
    owner, conns = _interconnect(graph)
    assert {c.a if owner[c.a] == "DRC" else c.b for c in conns} == {"DRC-EDGE1", "DRC-EDGE2"}
    keep = copy.copy(next(c for c in conns if "DRC-EDGE2" not in (c.a, c.b)))
    keep.links = keep.links * 2                                           # two cables, both on DRC-EDGE1
    graph.connections = [c for c in graph.connections if c not in conns] + [keep]
    row = _ids(SF.site_findings(graph, model))["TOPO-050"]
    assert row["severity"] == "medium" and "ends on one device: HQ-DC-EDGE1 at HQ-DC and DRC-EDGE1 at DRC" in row["title"] and row["reference"].endswith("218333-understand-and-configure-nexus-9000-vpc.html")


def test_one_cable_and_no_cable_between_the_sites_are_reported():
    graph, model = _fresh()
    owner, conns = _interconnect(graph)
    first = copy.copy(conns[0])
    first.links = first.links[:1]
    graph.connections = [c for c in graph.connections if c not in conns] + [first]
    row = _ids(SF.site_findings(graph, model))["TOPO-050"]
    assert row["severity"] == "medium" and row["title"].startswith("One cable between")
    graph.connections = [c for c in graph.connections if c is not first]
    row = _ids(SF.site_findings(graph, model))["TOPO-050"]
    assert row["severity"] == "info" and "No cable" in row["title"] and row["reference"].endswith("DCI2_External.pdf")


def test_one_provider_for_both_sites_is_a_medium_finding_and_a_single_provider_a_low_one():
    both = SF._provider_finding("A", "B", {"A": {"x"}, "B": {"x"}})
    assert both["severity"] == "medium" and "one provider only: x" in both["title"] and both["reference"].endswith("rfc4116.html")
    one = SF._provider_finding("A", "B", {"A": {"x", "y"}, "B": {"y"}})
    assert one["severity"] == "low" and "B: y only" in one["detail"]
    assert SF._provider_finding("A", "B", {"A": {"x", "y"}, "B": {"y", "z"}}) is None
    assert SF._provider_finding("A", "B", {"A": {"x"}}) is None                    # a site with no provider in the captures is not judged


def test_the_providers_come_from_the_l3_model_and_are_skipped_without_it():
    graph, model = _fresh()
    owner, _ = _interconnect(graph)
    assert SF._providers(graph, model, owner)["DRC"] == {"telkom", "icon+", "trigatra", "lintasarta"}
    assert all(r["id"] != "TOPO-051" for r in SF.site_findings(graph, None))


def test_the_findings_reach_the_report_of_a_build():
    graph, model = _built()
    assert [r["id"] for r in S.build_findings(graph, model) if r["id"] >= "TOPO-047"] == []


def test_vlan_gateways_are_read_from_svis_and_sub_interfaces_of_every_vendor():
    from features.topology.extract import Device

    node = Device(key="X", hostname="X", captured=True, role_hint="core")
    node.l3 = [{"name": "Vlan10", "kind": "SVI", "ip": "10.0.0.1"}, {"name": "Vlanif20", "kind": "SVI", "ip": "10.0.1.1"}, {"name": "vlan 30", "kind": "SVI", "ip": "10.0.2.1"},
               {"name": "ge-0/0.40", "kind": "Sub-interface", "ip": "10.0.3.1"}, {"name": "agg-edge.911", "kind": "Sub-interface", "ip": "10.0.4.1"},
               {"name": "Vlan50", "kind": "SVI", "ip": "10.0.5.1", "shutdown": True}, {"name": "Vlan60", "kind": "SVI", "ip": "10.0.6.1", "vrf": "management"},
               {"name": "Loopback0", "kind": "Loopback", "ip": "10.9.9.9"}, {"name": "Eth1/1", "kind": "Routed port", "ip": "10.8.8.1"}]
    assert sorted(SF._vlans([node])) == [10, 20, 30, 40, 911]


def test_the_parts_of_one_place_are_one_site_for_the_comparison():
    groups = {"HQ": ["a"], "HQ-1": ["b"], "HQ-2": ["c"], "DR-1": ["d"], "DR-2": ["e"], "KCU": ["f"], "BR-1": ["g"], sites_other(): ["h"]}
    merged = SF.family_groups(groups)
    assert sorted(merged) == sorted(["HQ", "DR", "KCU", "BR-1", sites_other()])             # HQ keeps its remainder, DR-1 + DR-2 are DR, a lone BR-1 is a site of its own
    assert sorted(merged["HQ"]) == ["a", "b", "c"] and sorted(merged["DR"]) == ["d", "e"]
    assert SF.family_groups({"HQ": ["a"], "KCU": ["f"]}) == {"HQ": ["a"], "KCU": ["f"]}


def test_a_recovery_site_cut_into_parts_is_still_the_twin_of_the_main_site_cut_into_parts():
    from tests.test_topology_v05 import _graph_of

    main = [f"HQ-SW{i}" for i in range(1, 7)]
    recovery = [f"DR-SW{i}" for i in range(1, 6)]
    graph = _graph_of(main + recovery, [])
    groups = {"HQ-1": main[:3], "HQ-2": main[3:], "DR-1": recovery[:2], "DR-2": recovery[2:]}
    assert SF.twin_sites(graph, groups) == [("HQ", "DR")]                       # DR-1 and DR-2 hold two or three devices each, together five


def test_a_comparison_says_how_many_devices_it_rests_on():
    graph, model = _fresh()
    for node in graph.nodes.values():
        if node.hostname.startswith("DRC"):
            node.l3 = [row for row in node.l3 if row["name"] not in ("Vlan911", "agg-edge.911")]
    detail = _ids(SF.site_findings(graph, model))["TOPO-047"]["detail"]
    assert "Compared on" in detail and "captured network device(s) at HQ-DC" in detail


def sites_other():
    from features.topology import sites

    return sites.OTHER
