"""A neighbor name that many separate cables advertise is several hosts, drawn one under each attachment (features/topology/sharedname.py).  Invented names and ports.

A NIC that sends its vendor string as the LLDP system name used to become one box with lines to every rack.  The rules cut only what no real device looks like:
many separate attachments with several on one switch, or a vendor string with two on one switch.  A hub with one cable to each switch, a dual-homed server and a
port-channel with many members are left as they are.
"""

from __future__ import annotations

from features.topology import findings, roles, sharedname
from features.topology.extract import Device, HalfEdge
from features.topology.findings import build_findings
from features.topology.graph import build
from features.topology.service import build_topology


def _switch(name, neighbours, bundles=None):
    """A captured switch: ``neighbours`` is a list of (local port, remote name, remote port)."""
    dev = Device(key=name, hostname=name, captured=True, role_hint="access",
                 halves=[HalfEdge(local_port=p, remote_name=n, remote_port=rp, protocols={"LLDP"}) for p, n, rp in neighbours])
    for po, members in (bundles or {}).items():
        dev.bundles[po] = list(members)
        for m in members:
            dev.bundle_of[m] = po
    return dev


def _graph(devices):
    graph = build(devices)
    roles.classify(graph)
    return graph


def _stubs(graph, name):
    return [n for n in graph.nodes.values() if n.hostname == name.upper() and not n.captured]


def test_ten_cables_of_one_name_on_two_racks_become_ten_end_points_each_under_its_switch():
    a = _switch("RACK-A", [(f"Eth1/{i}", "NIC VENDOR", "p1") for i in range(1, 7)])
    b = _switch("RACK-B", [(f"Eth1/{i}", "NIC VENDOR", "p1") for i in range(1, 5)])
    graph = _graph([a, b])
    assert sharedname.split_shared_names(graph) == 1
    stubs = _stubs(graph, "NIC VENDOR")
    assert len(stubs) == 10 and all(s.split_from == "NIC VENDOR" for s in stubs)
    near = sorted(c.a if c.b.startswith("NIC VENDOR@") else c.b for c in graph.connections if "NIC VENDOR@" in (c.a + c.b))
    assert near == ["RACK-A"] * 6 + ["RACK-B"] * 4
    assert all(len(c.links) == 1 and c.kind == "link" for c in graph.connections if "NIC VENDOR@" in (c.a + c.b))
    assert {l.a for l in graph.links if "NIC VENDOR@" in (l.a + l.b)} | {l.b for l in graph.links if "NIC VENDOR@" in (l.a + l.b)} >= {s.key for s in stubs}
    assert "NIC VENDOR" not in graph.nodes


def test_a_port_channel_is_one_attachment_however_many_members_it_has():
    a = _switch("RACK-A", [(f"Eth1/{i}", "BOND HOST", "p1") for i in range(1, 9)], bundles={"Po1": [f"Eth1/{i}" for i in range(1, 9)]})
    graph = _graph([a])
    assert sharedname.split_shared_names(graph) == 0                      # eight cables, one bundle: one server
    assert len(_stubs(graph, "BOND HOST")) == 1


def test_a_hub_with_one_cable_to_each_switch_is_not_split():
    devices = [_switch(f"ACC{i}", [("Gi0/1", "DIST-UNCAPTURED", "Gi1/0/1")]) for i in range(1, 9)]
    graph = _graph(devices)
    assert sharedname.split_shared_names(graph) == 0                      # eight attachments but never more than one on a switch
    assert len(_stubs(graph, "DIST-UNCAPTURED")) == 1


def test_a_server_with_two_cables_to_two_switches_is_one_server():
    graph = _graph([_switch("RACK-A", [("Eth1/1", "HCI1", "p1")]), _switch("RACK-B", [("Eth1/1", "HCI1", "p2")])])
    assert sharedname.split_shared_names(graph) == 0


def test_a_vendor_string_is_split_from_three_attachments_with_two_on_one_switch_but_not_one_on_each_of_two():
    three = _graph([_switch("RACK-A", [("Eth1/1", "Intel Corporation", "p1"), ("Eth1/2", "Intel Corporation", "p1")]), _switch("RACK-B", [("Eth1/1", "Intel Corporation", "p1")])])
    assert sharedname.split_shared_names(three) == 1 and len(_stubs(three, "Intel Corporation")) == 3
    two = _graph([_switch("RACK-A", [("Eth1/1", "Intel Corporation", "p1")]), _switch("RACK-B", [("Eth1/1", "Intel Corporation", "p1")])])
    assert sharedname.split_shared_names(two) == 0


def test_a_real_name_with_few_attachments_is_never_split():
    graph = _graph([_switch("RACK-A", [(f"Eth1/{i}", "ESX-HOST-01", "vmnic0") for i in range(1, 4)])])
    assert sharedname.split_shared_names(graph) == 0                      # three cables of one name: a multi-NIC host


def test_the_limits_are_the_mutation_check(monkeypatch):
    graph = _graph([_switch("RACK-A", [(f"Eth1/{i}", "NIC VENDOR", "p1") for i in range(1, 6)])])
    assert sharedname.split_shared_names(graph) == 0                      # five: below the limit of six
    monkeypatch.setattr(sharedname, "SPLIT_MIN_UNITS", 5)
    graph = _graph([_switch("RACK-A", [(f"Eth1/{i}", "NIC VENDOR", "p1") for i in range(1, 6)])])
    assert sharedname.split_shared_names(graph) == 1
    monkeypatch.setattr(sharedname, "SPLIT_MIN_ON_ONE_SWITCH", 6)
    graph = _graph([_switch("RACK-A", [(f"Eth1/{i}", "NIC VENDOR", "p1") for i in range(1, 6)])])
    assert sharedname.split_shared_names(graph) == 0                      # more on one switch than there are


def test_topo_045_reports_a_split_name_once_with_the_number_of_end_points():
    a = _switch("RACK-A", [(f"Eth1/{i}", "NIC VENDOR", "p1") for i in range(1, 7)])
    b = _switch("RACK-B", [(f"Eth1/{i}", "NIC VENDOR", "p1") for i in range(1, 5)])
    graph = _graph([a, b])
    sharedname.split_shared_names(graph)
    rows = [f for f in build_findings(graph) if f["id"] == "TOPO-045"]
    assert len(rows) == 1 and rows[0]["devices"] == ["NIC VENDOR"]
    assert "10 separate attachments on 2 switch(es)" in rows[0]["title"] and "10 separate end points" in rows[0]["detail"] and rows[0]["reference"].startswith("https://")


def test_the_whole_build_splits_and_each_end_point_stands_under_its_own_switch():
    a = _switch("RACK-A", [(f"Eth1/{i}", "NIC VENDOR", "p1") for i in range(1, 7)])
    b = _switch("RACK-B", [(f"Eth1/{i}", "NIC VENDOR", "p1") for i in range(1, 5)])
    built = build_topology([], devices=[a, b], group="none", view="physical", collapse_endpoints=False, group_endpoints=True)
    page = built["pages"][0]
    ends = [k for k in page.nodes if k.startswith("NIC VENDOR@")]
    assert len(ends) == 10
    mean_x = lambda switch: sum(page.nodes[k].x for k in ends if f"@{switch}:" in k) / sum(1 for k in ends if f"@{switch}:" in k)
    assert abs(mean_x("RACK-A") - page.nodes["RACK-A"].x) < abs(mean_x("RACK-A") - page.nodes["RACK-B"].x)      # the end points of A stand nearer to A than to B
    assert abs(mean_x("RACK-B") - page.nodes["RACK-B"].x) < abs(mean_x("RACK-B") - page.nodes["RACK-A"].x)
    assert any(f["id"] == "TOPO-045" for f in built["findings"])


def test_every_split_end_point_is_a_host_even_when_the_nic_says_it_bridges():
    a = Device(key="RACK-A", hostname="RACK-A", captured=True, role_hint="access",
               halves=[HalfEdge(local_port=f"Eth1/{i}", remote_name="NIC VENDOR", remote_port="p1", protocols={"LLDP"}, remote_caps="Bridge,Station") for i in range(1, 7)])
    graph = _graph([a])
    assert graph.nodes["NIC VENDOR"].role_hint == "switch"                # six cables of a name the capabilities of which say bridge: not a host role, not a vendor string: left alone
    assert sharedname.split_shared_names(graph) == 0
    renamed = Device(key="RACK-A", hostname="RACK-A", captured=True, role_hint="access",
                     halves=[HalfEdge(local_port=f"Eth1/{i}", remote_name="Broadcom Adv", remote_port="p1", protocols={"LLDP"}, remote_caps="Bridge,Station") for i in range(1, 7)])
    graph = _graph([renamed])
    assert graph.nodes["BROADCOM ADV"].role_hint == "server"                # an adapter vendor string is a server from the first classification (roles.NIC_VENDOR), whatever the capabilities say
    assert sharedname.split_shared_names(graph) == 1                      # a vendor string is no switch name
    roles.classify(graph)                                                 # the second classification (service) must not turn them back into switches
    assert {n.role_hint for n in _stubs(graph, "Broadcom Adv")} == {"server"} and len(_stubs(graph, "Broadcom Adv")) == 6


def test_a_host_name_with_six_cables_spread_one_or_two_per_switch_is_not_split():
    devices = [Device(key=f"ACC{i}", hostname=f"ACC{i}", captured=True, role_hint="access",
                      halves=[HalfEdge(local_port=f"Eth1/{p}", remote_name="SOME SERVER", remote_port="p1", protocols={"LLDP"}) for p in (1, 2)]) for i in range(1, 4)]
    graph = _graph(devices)
    graph.nodes["SOME SERVER"].role_hint = "server"
    assert sharedname.split_shared_names(graph) == 0                       # six attachments, never more than two on a switch: one server on three switches


def test_a_vendor_string_needs_three_attachments_with_two_on_one_switch():
    one_switch = _graph([_switch("RACK-A", [("Eth1/1", "BROADCOM ADV", "p1"), ("Eth1/2", "BROADCOM ADV", "p2")])])
    assert sharedname.split_shared_names(one_switch) == 0                  # two cables to one switch: too few to say
    spread = _graph([_switch(f"RACK-{i}", [("Eth1/1", "BROADCOM ADV", "p1")]) for i in range(1, 4)])
    assert sharedname.split_shared_names(spread) == 0                      # three switches, one cable each: one server may be on all three
    enough = _graph([_switch("RACK-A", [("Eth1/1", "BROADCOM ADV", "p1"), ("Eth1/2", "BROADCOM ADV", "p2")]), _switch("RACK-B", [("Eth1/1", "BROADCOM ADV", "p1")])])
    assert sharedname.split_shared_names(enough) == 1


def test_the_end_points_made_by_a_split_are_hosts_whatever_the_name_was_guessed_to_be():
    graph = _graph([_switch("RACK-A", [(f"Eth1/{i}", "NIC VENDOR", "p1") for i in range(1, 7)])])
    graph.nodes["NIC VENDOR"].role_hint = "server"
    sharedname.split_shared_names(graph)
    twins = _stubs(graph, "NIC VENDOR")
    assert twins and all(t.role_hint == "server" and t.split_from == "NIC VENDOR" for t in twins)
    graph2 = _graph([_switch("RACK-A", [(f"Eth1/{i}", "BROADCOM ADV", "p1") for i in range(1, 7)])])
    graph2.nodes["BROADCOM ADV"].role_hint = "switch"
    sharedname.split_shared_names(graph2)
    assert all(t.role_hint == "server" for t in _stubs(graph2, "BROADCOM ADV"))
