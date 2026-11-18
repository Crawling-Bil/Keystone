"""The servers of a switch that has switches under it stand in the row under that switch (layout.lift_endpoints).  Invented names and ports.

Servers cabled to an edge, core or aggregation switch were drawn in the last row of the page, so their lines ran down through every row between: across the fan of the
aggregation pair to its top-of-rack switches.  They now stand right under their own switch.  A leaf switch, a router or a firewall keeps the old picture.
"""

from __future__ import annotations

from features.topology import layout, roles
from features.topology.extract import Device, HalfEdge
from features.topology.graph import build
from features.topology.service import build_topology


def _sw(name, neighbours):
    return Device(key=name, hostname=name, captured=True, role_hint="switch",
                  halves=[HalfEdge(local_port=p, remote_name=n, remote_port=rp, protocols={"LLDP"}) for p, n, rp in neighbours])


def _devices(host_parent="LAB-CORE", hosts=3, extra=()):
    core = [("Eth1/1", "LAB-ACC1", "Eth1/48"), ("Eth1/2", "LAB-ACC2", "Eth1/48")]
    acc1 = [("Eth1/48", "LAB-CORE", "Eth1/1")]
    acc2 = [("Eth1/48", "LAB-CORE", "Eth1/2")]
    table = {"LAB-CORE": core, "LAB-ACC1": acc1, "LAB-ACC2": acc2}
    for i in range(hosts):
        table[host_parent].append((f"Eth1/{10 + i}", f"SRV-{i + 1}", "p1"))
    return [_sw(n, h) for n, h in table.items()] + list(extra)


def _values(devices):
    graph = build(devices)
    roles.classify(graph)
    keys = list(graph.nodes)
    value = layout._tier_values(graph, keys)
    return graph, keys, value


def test_servers_of_a_switch_with_switches_under_it_go_to_the_row_under_it():
    graph, keys, value = _values(_devices())
    lifted = layout.lift_endpoints(graph, keys, value)
    assert sorted(lifted) == ["SRV-1", "SRV-2", "SRV-3"]
    assert all(v == value["LAB-CORE"] + 0.5 for v in lifted.values())
    assert value["LAB-CORE"] < value["LAB-ACC1"]


def test_servers_of_a_leaf_switch_stay_where_they_were():
    graph, keys, value = _values(_devices(host_parent="LAB-ACC1"))
    assert layout.lift_endpoints(graph, keys, value) == {}                   # the access switch has no switch under it


def test_a_server_cabled_to_two_switches_is_not_lifted():
    extra = [_sw("LAB-ACC3", [("Eth1/1", "SRV-1", "p2"), ("Eth1/48", "LAB-CORE", "Eth1/3")])]
    devices = _devices(hosts=4, extra=extra)
    devices[0].halves.append(HalfEdge(local_port="Eth1/3", remote_name="LAB-ACC3", remote_port="Eth1/48", protocols={"LLDP"}))
    graph, keys, value = _values(devices)
    assert "SRV-1" not in layout.lift_endpoints(graph, keys, value)
    assert sorted(layout.lift_endpoints(graph, keys, value)) == ["SRV-2", "SRV-3", "SRV-4"]


def test_a_captured_device_and_a_parent_below_the_limit_row_are_not_lifted(monkeypatch):
    graph, keys, value = _values(_devices())
    monkeypatch.setattr(layout, "LIFT_MAX_ROW", value["LAB-CORE"] - 0.5)      # the core now stands below the limit: nothing is lifted
    assert layout.lift_endpoints(graph, keys, value) == {}
    graph, keys, value = _values(_devices())
    graph.nodes["SRV-1"].captured = True
    assert "SRV-1" not in layout.lift_endpoints(graph, keys, value)


def test_a_router_keeps_its_servers_in_the_last_row():
    graph, keys, value = _values(_devices())
    graph.nodes["LAB-CORE"].role_hint = "router"
    assert layout.lift_endpoints(graph, keys, value) == {}


def test_the_page_has_the_servers_between_the_core_and_the_access_switches():
    built = build_topology([], devices=_devices(), group="none", view="physical", collapse_endpoints=False, group_endpoints=True)
    page = built["pages"][0]
    y = {built["graph"].nodes[k].hostname: n.y for k, n in page.nodes.items()}
    assert y["LAB-CORE"] < y["SRV-1"] < y["LAB-ACC1"] and y["SRV-1"] == y["SRV-3"]


def test_switching_the_rule_off_is_visible(monkeypatch):
    monkeypatch.setattr(layout, "LIFT_ENDPOINTS", False)
    built = build_topology([], devices=_devices(), group="none", view="physical", collapse_endpoints=False, group_endpoints=True)
    page = built["pages"][0]
    y = {built["graph"].nodes[k].hostname: n.y for k, n in page.nodes.items()}
    assert y["SRV-1"] > y["LAB-ACC1"]                                         # the old picture: servers in the last row


def test_two_servers_or_one_switch_below_are_too_little_for_a_row(monkeypatch):
    graph, keys, value = _values(_devices(hosts=2))
    assert layout.lift_endpoints(graph, keys, value) == {}                   # two servers: stay in the last row (LIFT_MIN_HOSTS is 3)
    graph, keys, value = _values(_devices(hosts=3))
    assert len(layout.lift_endpoints(graph, keys, value)) == 3
    monkeypatch.setattr(layout, "LIFT_MIN_HOSTS", 4)
    assert layout.lift_endpoints(graph, keys, value) == {}
    monkeypatch.setattr(layout, "LIFT_MIN_HOSTS", 3)
    monkeypatch.setattr(layout, "LIFT_MIN_BELOW", 3)                         # the core has two switches under it: not enough for a limit of three
    assert layout.lift_endpoints(graph, keys, value) == {}
    monkeypatch.setattr(layout, "LIFT_MIN_BELOW", 2)
    assert len(layout.lift_endpoints(graph, keys, value)) == 3


def test_a_parent_deeper_than_the_default_limit_row_keeps_its_servers():
    graph, keys, value = _values(_devices())
    assert layout.LIFT_MAX_ROW == 2.0 and layout.LIFT_MIN_HOSTS == 3 and layout.LIFT_MIN_BELOW == 2
    assert layout.lift_endpoints(graph, keys, value)                       # the core is in a row at or above the limit: lifted
    value["LAB-CORE"] = layout.LIFT_MAX_ROW + 0.5
    assert layout.lift_endpoints(graph, keys, value) == {}
