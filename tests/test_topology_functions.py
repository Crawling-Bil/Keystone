"""What a device does in the data center, from the evidence in order: the host-name words, the model family, the cabling, the configuration (features/topology/functions.py).

Found on a real DC and DRC set: the EDGE switch between the WAN routers and the core, the management switch that every tier plugs a management port into, the Catalyst 9500
that serves the campus below the Catalyst 9500 that the WAN routers plug into, and a Huawei CE68 leaf that the model list called a core.  Invented names, ports and addresses.
"""

from __future__ import annotations

import pytest

from features.topology import functions, layout, roles
from features.topology.extract import Device
from features.topology.graph import Connection, Graph, Link
from features.topology.service import devices_table


@pytest.mark.parametrize("name,function", [
    ("SW-EDGE1-DC", "edge"), ("SW-MGMT1-DC", "management"), ("DC-SW-OOB2", "management"), ("SW-TOR6A-DC", "tor"), ("SW-DIST-DC", "distribution"),
    ("SW-AGG2-DC", "aggregation"), ("RTR-INET2-DC", "internet"), ("RTR-PTNR2-DC", "partner"), ("SW-CORE-DC", "core"), ("SW-SPINE1", "core"), ("ASW3", "access"),
    ("SW-LEAF12", "tor"),
    ("TORONTO-SW1", ""), ("BRANCH-SW1", ""), ("SW-EDGEWATER-1", ""), ("MGMTX-1", ""), ("HQ-FLOOR2", "")])
def test_the_words_of_a_host_name_say_the_function_and_a_longer_word_does_not(name, function):
    assert functions.name_function(name)[0] == function


def _graph(spec, links, pairs=()):
    """``spec``: name -> (model, {port: description}); ``links``: (a, port_a, b, port_b).  Nothing here is named by role: the names are N01 ... so only the evidence below counts."""
    nodes = {name: Device(key=name, hostname=name, captured=True, model=model, descriptions=dict(descriptions)) for name, (model, descriptions) in spec.items()}
    conns = [Connection(a, b, [Link(a, pa, b, pb, "confirmed", {"CDP"}, "")]) for a, pa, b, pb in links]
    graph = Graph(nodes=nodes, links=[l for c in conns for l in c.links], connections=conns, hidden_kinds=set())
    for a, b in pairs:
        nodes[a].vpc_domain = nodes[b].vpc_domain = "140"
        graph.vpc_pairs.append((a, b, "140"))
    return graph


def _dc():
    """Two WAN routers, a core, a second Catalyst 9500 below it for the campus, an edge switch, a management switch, a vPC pair and four racks."""
    spec = {"N01": ("ISR4451-X", {}), "N02": ("C8200L-1N-4T", {}), "N03": ("C9500-48Y4C", {}), "N04": ("C9500-24Y4C", {}), "N05": ("C9200L-48T-4X", {}),
            "N06": ("Built-in", {}), "N07": ("N9K-C93180YC-FX", {}), "N08": ("N9K-C93180YC-FX", {}),
            "N10": ("C9200L-24T-4G", {}), "N11": ("C9200L-24T-4G", {}), "N12": ("WS-C2960S-24TS", {}), "N13": ("WS-C2960S-24TS", {}),
            "N20": ("", {}), "N21": ("", {})}                                                       # two campus switches below N04 that nobody captured
    links = [("N01", "Gi0/0/1", "N03", "Twe1/0/1"), ("N03", "Twe1/0/2", "N07", "Eth1/1"), ("N03", "Twe1/0/3", "N08", "Eth1/1"), ("N03", "Twe1/0/4", "N04", "Twe1/0/4"),
             ("N04", "Twe1/0/5", "N20", "Gi1/0/48"), ("N04", "Twe1/0/6", "N21", "Gi1/0/48"),
             ("N05", "Gi1/0/41", "N01", "Gi0/0/2"), ("N05", "Gi1/0/42", "N02", "Gi0/0/2"), ("N05", "Gi1/0/47", "N03", "Twe1/0/47"), ("N05", "Gi1/0/45", "N07", "Eth1/42"),
             ("N07", "Eth1/47", "N08", "Eth1/47")]
    for rack in ("N10", "N11", "N12", "N13"):
        links += [(rack, "Gi1/0/25", "N07", f"Eth1/{rack[-2:]}"), (rack, "Gi1/0/26", "N08", f"Eth1/{rack[-2:]}")]
    for other, port in (("N01", "Gi0/0/3"), ("N02", "Gi0/0/3"), ("N03", "Gi0/0"), ("N05", "Gi0/0"), ("N07", "mgmt0"), ("N08", "mgmt0")):
        links.append(("N06", f"Gi1/0/{len(links)}", other, port))
    graph = _graph(spec, links, pairs=[("N07", "N08")])
    for node in graph.nodes.values():
        if not node.model:
            node.captured, node.caps = False, "Bridge, Router"                                # a switch that its neighbours saw but nobody captured
    graph.nodes["N06"].descriptions = {f"Gi1/0/{i}": f"MGMT-{name}" for i, name in ((11, "N01"), (12, "N02"))}
    roles.classify(graph)
    return graph


def test_a_management_switch_is_found_by_the_management_ports_that_reach_it_and_is_no_tier():
    graph = _dc()
    node = graph.nodes["N06"]
    assert node.function == "management" and "management port" in node.function_why
    assert node.role_hint in ("switch", "access")                                       # not promoted to aggregation because it is cabled to many devices
    assert getattr(node, "hier_depth", None) is None


def test_the_cables_of_a_management_switch_are_not_steps_of_the_hierarchy():
    graph = _dc()
    assert {k: getattr(graph.nodes[k], "hier_depth", None) for k in ("N03", "N07", "N10")} == {"N03": 0, "N07": 1, "N10": 2}


def test_one_device_described_as_management_does_not_make_a_management_switch():
    plain = _graph({"N01": ("C9500-48Y4C", {}), "N02": ("C9300-24T", {}), "N03": ("C9300-24T", {}), "N04": ("C9300-24T", {}), "N05": ("C9300-24T", {}), "N06": ("C9300-24T", {})},
                   [("N01", "Twe1/0/1", n, "Twe1/1/1") for n in ("N02", "N03", "N04", "N05", "N06")])
    plain.nodes["N01"].descriptions = {"Twe1/0/1": "MGMT-N02"}
    roles.classify(plain)
    assert plain.nodes["N01"].function != "management"


def test_an_edge_switch_is_found_by_the_routers_it_joins_to_the_core():
    graph = _dc()
    assert graph.nodes["N05"].function == "edge" and "2 routers" in graph.nodes["N05"].function_why


def test_a_catalyst_9500_below_the_catalyst_9500_of_the_routers_is_a_distribution_switch():
    graph = _dc()
    assert graph.nodes["N03"].role_hint == "core" and graph.nodes["N03"].function == "core"
    assert graph.nodes["N04"].role_hint == "aggregation" and graph.nodes["N04"].function == "distribution"


def test_two_cores_of_a_pair_stay_two_cores():
    spec = {"N01": ("ISR4451-X", {}), "N03": ("C9500-48Y4C", {}), "N04": ("C9500-48Y4C", {}), "N05": ("C9300-24T", {}), "N06": ("C9300-24T", {}), "N07": ("C9300-24T", {})}
    links = [("N01", "Gi0/0/1", "N03", "Twe1/0/1"), ("N03", "Twe1/0/4", "N04", "Twe1/0/4"), ("N03", "Twe1/0/5", "N05", "Eth1"), ("N04", "Twe1/0/5", "N05", "Eth2"),
             ("N03", "Twe1/0/6", "N06", "Eth1"), ("N04", "Twe1/0/6", "N06", "Eth2"), ("N03", "Twe1/0/7", "N07", "Eth1"), ("N04", "Twe1/0/7", "N07", "Eth2")]
    graph = _graph(spec, links)
    roles.classify(graph)
    assert graph.nodes["N03"].function == "core" and graph.nodes["N04"].function == "core"           # N04 shares every neighbour with N03: a second core, not one below it


def test_the_racks_under_one_pair_are_top_of_rack_and_the_pair_is_aggregation():
    graph = _dc()
    assert [graph.nodes[k].function for k in ("N10", "N11", "N12", "N13")] == ["tor"] * 4
    assert "vPC / M-LAG pair" in graph.nodes["N10"].function_why
    assert graph.nodes["N07"].function == "aggregation" and graph.nodes["N08"].function == "aggregation"


def test_a_cloudengine_leaf_is_an_access_switch_by_its_model_not_a_core():
    graph = _graph({"N01": ("CE6881-48S6CQ", {}), "N02": ("CE12804", {})}, [("N01", "10GE1/0/1", "N02", "100GE1/0/1")])
    roles.classify(graph)
    assert graph.nodes["N01"].role_hint == "access" and graph.nodes["N01"].function == "tor"
    assert graph.nodes["N02"].role_hint == "core"


def test_a_catalyst_1100_is_a_router_not_a_switch():
    graph = _graph({"N01": ("C1121-4P", {})}, [])
    roles.classify(graph)
    assert graph.nodes["N01"].role_hint == "router"


def test_every_function_has_its_reason_and_the_device_table_carries_both():
    graph = _dc()
    rows = {r["device"]: r for r in devices_table(graph)}
    assert rows["N06"]["function"] == "management" and rows["N06"]["function_why"]
    assert all(r["function_why"] for r in rows.values() if r["function"])


def test_the_edge_stands_between_the_routers_and_the_core_and_the_management_switch_under_the_tiers_it_touches():
    graph = _dc()
    row = layout._tier_values(graph, list(graph.nodes))
    assert row["N01"] < row["N05"] < row["N03"]                                          # router, edge, core
    assert row["N06"] == row["N07"] + 0.5                                                # cabled across routers, edge, core and aggregation: under the aggregation pair
    assert row["N03"] < row["N07"] < row["N10"]


def test_a_management_switch_cabled_across_two_rows_only_keeps_its_row():
    graph = _dc()
    for conn in list(graph.connections):
        if "N06" in (conn.a, conn.b) and {conn.a, conn.b} - {"N06"} & {"N01", "N02", "N05"}:
            graph.connections.remove(conn)                                               # no cable to the routers or the edge: only core and aggregation (two rows) are left
    row = layout._tier_values(graph, list(graph.nodes))
    assert row["N06"] == 3.0


def test_a_routing_page_without_cables_keeps_its_rows():
    graph = _dc()
    for conn in graph.connections:
        conn.kind = "l3r"
    row = layout._tier_values(graph, list(graph.nodes))
    assert row["N06"] < 4 and row["N05"] >= 1                                            # no edge / management rows where nothing is cabled


def _star(described, plain, described_by="M"):
    """One switch ``M`` cabled to ``described + plain`` other switches; the cables of the first ``described`` ones carry a description that starts with MGMT (on M's port, or on the other end)."""
    others = [f"N{i:02d}" for i in range(1, described + plain + 1)]
    spec = {"M": ("C9200L-48T-4X", {}), **{n: ("C9300-24T", {}) for n in others}}
    links = [("M", f"Gi1/0/{i}", n, "Gi1/0/48") for i, n in enumerate(others, 1)]
    for i, n in enumerate(others[:described], 1):
        target = spec["M"][1] if described_by == "M" else spec[n][1]
        target[f"Gi1/0/{i}" if described_by == "M" else "Gi1/0/48"] = f"MGMT-{n}"
    graph = _graph(spec, links)
    roles.classify(graph)
    return graph


def test_three_cables_described_as_management_are_enough_when_they_are_half_of_the_neighbours():
    assert _star(3, 3).nodes["M"].function == "management"


def test_two_described_cables_are_not_enough():
    assert _star(2, 0).nodes["M"].function != "management"


def test_described_cables_that_are_less_than_half_of_the_neighbours_are_not_enough():
    assert _star(3, 4).nodes["M"].function != "management"


def test_the_description_on_either_end_counts():
    assert _star(4, 0, described_by="M").nodes["M"].function == "management"
    assert _star(4, 0, described_by="other").nodes["M"].function == "management"


def test_a_management_port_at_the_far_end_counts_without_any_description():
    spec = {"M": ("C9200L-48T-4X", {}), **{f"N{i}": ("C9300-24T", {}) for i in range(1, 5)}}
    graph = _graph(spec, [("M", f"Gi1/0/{i}", f"N{i}", "Gi0/0") for i in range(1, 5)])           # Gi0/0 is the management port of a Catalyst switch
    roles.classify(graph)
    assert graph.nodes["M"].function == "management"
    graph = _graph(spec, [("M", f"Gi1/0/{i}", f"N{i}", "Gi1/0/48") for i in range(1, 5)])
    roles.classify(graph)
    assert graph.nodes["M"].function != "management"


def test_the_gi0_0_of_a_router_is_a_data_port():
    spec = {"M": ("C9200L-48T-4X", {}), **{f"R{i}": ("ISR4451-X", {}) for i in range(1, 5)}}
    graph = _graph(spec, [("M", f"Gi1/0/{i}", f"R{i}", "Gi0/0") for i in range(1, 5)])
    roles.classify(graph)
    assert graph.nodes["M"].function != "management"


def _edge(routers, inside):
    spec = {"E": ("C9200L-48T-4X", {}), **{f"R{i}": ("ISR4451-X", {}) for i in range(1, routers + 1)}, **{f"C{i}": ("C9500-24Y4C", {}) for i in range(1, inside + 1)}}
    graph = _graph(spec, [("E", f"Gi1/0/{i}", f"R{i}", "Gi0/0/1") for i in range(1, routers + 1)] + [("E", f"Gi1/0/{20 + i}", f"C{i}", "Twe1/0/1") for i in range(1, inside + 1)])
    roles.classify(graph)
    return graph.nodes["E"]


def test_the_edge_needs_two_routers_and_a_core_or_aggregation_switch():
    assert _edge(2, 1).function == "edge"
    assert _edge(1, 1).function != "edge"                                                 # one router: the core's own uplink
    assert _edge(2, 0).function != "edge"                                                 # no core behind it: an access switch of the router row


def _racks(count, as_pair=True):
    spec = {"C": ("C9500-24Y4C", {}), "A1": ("N9K-C93180YC-FX", {}), "A2": ("N9K-C93180YC-FX", {}), **{f"T{i}": ("C9200L-24T-4G", {}) for i in range(1, count + 1)}}
    links = [("C", "Twe1/0/1", "A1", "Eth1/48"), ("C", "Twe1/0/2", "A2", "Eth1/48"), ("A1", "Eth1/47", "A2", "Eth1/47")] + [(f"T{i}", "Gi1/0/25", "A1", f"Eth1/{i}") for i in range(1, count + 1)] + [(f"T{i}", "Gi1/0/26", "A2", f"Eth1/{i}") for i in range(1, count + 1)]
    graph = _graph(spec, links, pairs=[("A1", "A2")] if as_pair else [])
    roles.classify(graph)
    return graph


def test_the_racks_need_two_other_racks_under_the_same_pair():
    assert [_racks(3).nodes[f"T{i}"].function for i in (1, 2, 3)] == ["tor"] * 3
    assert _racks(2).nodes["T1"].function != "tor"                                       # two switches under a pair: no row of racks


def test_the_uplinks_must_go_to_a_pair():
    assert _racks(3, as_pair=False).nodes["T1"].function != "tor"


def test_a_pair_with_racks_below_is_aggregation_and_without_racks_distribution():
    assert _racks(3).nodes["A1"].function == "aggregation" and "top-of-rack" in _racks(3).nodes["A1"].function_why
    assert _dc().nodes["N04"].function == "distribution"


def _cores(second_pair, router_at_second="none"):
    """C1 has a captured router; C2 has none, or an uncaptured one, or a captured one; S1 and S2 hang only off C2."""
    spec = {"R1": ("ISR4451-X", {}), "C1": ("C9500-48Y4C", {}), "C2": ("C9500-24Y4C", {}), "S1": ("C9300-24T", {}), "S2": ("C9300-24T", {})}
    links = [("R1", "Gi0/0/1", "C1", "Twe1/0/1"), ("C1", "Twe1/0/4", "C2", "Twe1/0/4"), ("C2", "Twe1/0/5", "S1", "Eth1"), ("C2", "Twe1/0/6", "S2", "Eth1")]
    if router_at_second != "none":
        spec["R2"] = ("ISR4451-X", {})
        links.append(("R2", "Gi0/0/1", "C2", "Twe1/0/1"))
    graph = _graph(spec, links, pairs=[("C1", "C2")] if second_pair else [])
    if router_at_second == "uncaptured":
        graph.nodes["R2"].captured, graph.nodes["R2"].caps = False, "Router"
    roles.classify(graph)
    return graph


def test_two_cores_that_are_a_pair_are_not_one_below_the_other_even_with_neighbours_of_their_own():
    assert _cores(second_pair=True).nodes["C2"].role_hint == "core"
    assert _cores(second_pair=False).nodes["C2"].role_hint == "aggregation"             # the same cables without the pair: C2 serves S1 and S2 below C1


def test_a_router_that_was_captured_decides_which_core_is_the_real_one():
    assert _cores(False, "uncaptured").nodes["C2"].role_hint == "aggregation"           # C2 is linked to a router too, but nobody captured it: C1 has the captured router
    assert _cores(False, "captured").nodes["C2"].role_hint == "core"                    # both have a captured router: two cores


def test_one_rack_under_a_switch_that_is_no_vpc_peer_is_not_a_row_of_racks():
    spec = {"C": ("C9500-24Y4C", {}), "A": ("C9300-24T", {}), "T": ("CE6881-48S6CQ", {}), "U": ("CE6881-48S6CQ", {})}
    graph = _graph(spec, [("C", "Twe1/0/1", "A", "Twe1/1/1"), ("A", "Gi1/0/1", "T", "10GE1/0/1")])
    roles.classify(graph)
    assert graph.nodes["T"].function == "tor" and graph.nodes["A"].role_hint == "aggregation" and graph.nodes["A"].function == "distribution"
    graph = _graph(spec, [("C", "Twe1/0/1", "A", "Twe1/1/1"), ("A", "Gi1/0/1", "T", "10GE1/0/1"), ("A", "Gi1/0/2", "U", "10GE1/0/1")])
    roles.classify(graph)
    assert graph.nodes["A"].function == "aggregation"                                    # two racks below it
