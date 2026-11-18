"""A "LINK-<name>" description on a layer-2 port names a device nobody captured: TOPO-058 lists it (it is not drawn).  Invented names.

An aggregation pair whose uplink descriptions say ``LINK-SW-TOR2B`` on a plain trunk names a ToR nobody captured.  Drawing a box for it made the pages of a real data center
set (27 boxes, 60 dashed lines) harder to read, so the engineer gets the list of what to capture next instead.  The rule is narrow: an explicit link word, and either a
device-like name or the same name on two captured devices; the shared name of a pair ('UPLINK1-SW-AGG-DC' on every ToR) is a label, not a device.
"""

from __future__ import annotations

from features.topology import inferred
from features.topology.extract import Device
from features.topology.graph import Connection, Graph


def _graph(spec):
    nodes = {n: Device(key=n, hostname=n, captured=True, descriptions=dict(d)) for n, d in spec.items()}
    return Graph(nodes=nodes, links=[], connections=[], hidden_kinds=set())


def _described(graph):
    facts = inferred.infer_neighbors(graph)
    assert not any(l.state == "inferred" for l in graph.links)          # nothing is drawn
    return sorted((f["name"], tuple(f["devices"])) for f in facts if f["type"] == "described-device")


def test_two_devices_naming_the_same_far_switch_are_listed_once_with_their_ports():
    graph = _graph({"AGG1": {"Eth1/4": "LINK-SW-TOR2B"}, "AGG2": {"Eth1/4": "LINK-SW-TOR2B", "Po112": "LINK-SW-TOR2B"}})
    facts = [f for f in inferred.infer_neighbors(graph) if f["type"] == "described-device"]
    assert len(facts) == 1 and facts[0]["name"] == "SW-TOR2B" and facts[0]["devices"] == ["AGG1", "AGG2"]
    assert [(p["device"], p["port"]) for p in facts[0]["ports"]] == [("AGG1", "Eth1/4"), ("AGG2", "Eth1/4"), ("AGG2", "Po112")]
    assert "SW-TOR2B" not in graph.nodes


def test_one_device_naming_a_name_that_is_not_device_like_lists_nothing():
    assert _described(_graph({"AGG1": {"Eth1/4": "LINK-WAF"}})) == []


def test_a_device_like_name_is_enough_on_its_own():
    assert _described(_graph({"CORE1": {"Eth1/1": "LINK-FW-INT"}})) == [("FW-INT", ("CORE1",))]


def test_a_plain_label_without_a_link_word_lists_nothing():
    assert _described(_graph({"A": {"Eth1/1": "SW-TOR2B"}, "B": {"Eth1/1": "SW-TOR2B"}})) == []


def test_the_side_of_the_far_device_is_not_part_of_its_name():
    graph = _graph({"CORE1": {"Eth1/1": "LINK-FW-PUB1-INSIDE"}, "CORE2": {"Eth1/1": "LINK-FW-PUB1-OUTSIDE"}})
    assert _described(graph) == [("FW-PUB1", ("CORE1", "CORE2"))]


def test_the_name_of_a_pair_is_a_label_not_a_device():
    graph = _graph({"SW-AGG1-DC": {}, "SW-AGG2-DC": {}, "TOR1A": {"Gi1/0/23": "UPLINK-SW-AGG-DC"}, "TOR1B": {"Gi1/0/23": "UPLINK-SW-AGG-DC"}})
    assert _described(graph) == []
    assert inferred._family_alias(graph, "SW-AGG-DC") and not inferred._family_alias(graph, "SW-AGG1-DC")


def test_a_numbered_uplink_of_a_pair_name_is_the_cable_to_the_unit_with_that_number():
    graph = _graph({"SW-AGG1-DC": {}, "SW-AGG2-DC": {}, "TOR1A": {"Gi1/0/23": "UPLINK1-SW-AGG-DC", "Gi1/0/24": "UPLINK2-SW-AGG-DC", "Gi1/0/25": "UPLINK3-SW-AGG-DC"}})
    inferred.infer_neighbors(graph)
    pairs = {(l.a_port, l.b) for l in graph.links if l.state == "inferred" and l.a == "TOR1A"}
    assert pairs == {("Gi1/0/23", "SW-AGG1-DC"), ("Gi1/0/24", "SW-AGG2-DC")}          # uplink 3 names no unit: no cable is made up
    assert inferred._family_member(graph, "UPLINK2-SW-AGG-DC", "TOR1A") == "SW-AGG2-DC" and inferred._family_member(graph, "UPLINK-SW-AGG-DC", "TOR1A") == ""


def test_a_captured_device_is_linked_not_listed():
    graph = _graph({"AGG1": {"Eth1/4": "LINK-SW-TOR2B"}, "SW-TOR2B": {}})
    facts = inferred.infer_neighbors(graph)
    assert [f["type"] for f in facts] == ["inferred-link"]


def test_a_number_after_the_link_word_is_not_part_of_the_name():
    assert inferred.parse_description("UPLINK1-SW-AGG-DC") == ("SW-AGG-DC", "")
    assert inferred.parse_description("UPLINK--SW-AGG-DC") == ("SW-AGG-DC", "")
    assert inferred.parse_description("LINK-SW-TOR2B") == ("SW-TOR2B", "")


def test_corroboration_constant_is_what_gates_the_name():
    assert inferred.CORROBORATION == 2


def test_topo_058_lists_them_as_info_with_the_devices_that_name_them():
    from features.topology import findings
    graph = _graph({"AGG1": {"Eth1/4": "LINK-SW-TOR2B"}, "AGG2": {"Eth1/4": "LINK-SW-TOR2B"}})
    graph.issues += inferred.infer_neighbors(graph)
    rows = [r for r in findings._described_findings(graph)]
    assert len(rows) == 1 and rows[0]["id"] == "TOPO-058" and rows[0]["severity"] == "info"
    assert rows[0]["devices"] == ["AGG1", "AGG2"] and "SW-TOR2B (AGG1 Eth1/4, AGG2 Eth1/4)" in rows[0]["detail"]
    assert findings._described_findings(_graph({"A": {}})) == []
