"""Topology Builder v0.7-E: a multi-VDOM FortiGate and a multi-vsys Palo Alto are one firewall node per VDOM / vsys, and a neighbor's cable lands on
the node that owns the remote port.  Synthetic data only (fixtures/firewall/*_synthetic*, a hand-written PAN-OS XML export)."""

from __future__ import annotations

from pathlib import Path

from features.topology import fortidev, graph as graph_module, panosdev
from features.topology.extract import Device, HalfEdge
from features.topology.service import build_topology, read_devices
from tests.test_firewall_scope_filter import PAN_MULTI_VSYS
from tests.topology_samples import iosxe_capture

FIXTURES = Path(__file__).parent / "fixtures"
MULTI = (FIXTURES / "firewall/fortigate_multivdom_synthetic.conf").read_text(encoding="utf-8")
EDGE = (FIXTURES / "firewall/fortigate_vdom_edge_synthetic.conf").read_text(encoding="utf-8")


def _forti(extra_rows: str = "", vdoms: str = "root CORP", mgmt_only_root: bool = False) -> str:
    """A small multi-VDOM FortiGate: port1/port2 in CORP, port3 in DMZ, plus whatever ``extra_rows`` adds to 'config system interface'."""
    root_rows = "" if mgmt_only_root else '    edit "port9"\n        set vdom "root"\n        set ip 10.9.0.1 255.255.255.0\n        set type physical\n    next\n'
    return (f"#config-version=FG100F-7.2.8-FW-build1639-240000:opmode=0:vdom=1:user=admin\nconfig vdom\nedit root\nnext\nedit CORP\nnext\nedit DMZ\nnext\nend\n"
            "config global\nconfig system global\n    set hostname \"FW-SPLIT-01\"\n    set vdom-mode multi-vdom\nend\nconfig system interface\n"
            '    edit "mgmt"\n        set vdom "root"\n        set ip 192.0.2.5 255.255.255.0\n        set type physical\n    next\n' + root_rows +
            '    edit "port1"\n        set vdom "CORP"\n        set ip 10.1.0.1 255.255.255.0\n        set alias "to CORE-SW - Eth1/1"\n        set type physical\n    next\n'
            '    edit "port2"\n        set vdom "CORP"\n        set ip 10.1.1.1 255.255.255.0\n        set type physical\n    next\n'
            '    edit "port3"\n        set vdom "DMZ"\n        set ip 10.3.0.1 255.255.255.0\n        set alias "to CORE-SW - Eth1/3"\n        set type physical\n    next\n'
            + extra_rows + "end\nend\n")


def test_each_vdom_with_data_ports_is_a_node_and_owns_its_ports():
    units = fortidev.units(__import__("features.firewall_analyzer.forti_extract", fromlist=["x"]).extract(__import__("features.firewall_analyzer.forti_tree", fromlist=["x"]).parse_forti(MULTI)), "dc.conf")
    assert [d.hostname for d in units] == ["FW-DC-02 [root]", "FW-DC-02 [CORP]", "FW-DC-02 [GUEST]"]
    assert [sorted(d.unit_ports) for d in units] == [["port1"], ["port2"], ["port3"]]
    assert {d.chassis for d in units} == {"FW-DC-02"} and all(d.role_hint == "firewall" for d in units)
    assert [d.l3facts["vdoms"] for d in units] == [["root"], ["CORP"], ["GUEST"]]


def test_a_management_only_root_vdom_is_not_a_node_but_keeps_the_management_address():
    units = fortidev.read_units(_forti(mgmt_only_root=True), "split.conf")
    assert [d.hostname for d in units] == ["FW-SPLIT-01 [CORP]", "FW-SPLIT-01 [DMZ]"]
    assert "192.0.2.5" in units[0].ips                                   # a management address still names the chassis
    assert all("mgmt" not in d.unit_ports for d in units)


def test_a_single_working_vdom_stays_one_plainly_named_device():
    only = _forti(mgmt_only_root=True).replace('set vdom "DMZ"', 'set vdom "CORP"')
    units = fortidev.read_units(only, "one.conf")
    assert len(units) == 1 and units[0].hostname == "FW-SPLIT-01" and units[0].chassis == ""        # nothing to split: the chassis is the node
    non_vdom = fortidev.read_units((FIXTURES / "firewall/fortigate_synthetic_7.2.conf").read_text(encoding="utf-8"), "plain.conf")
    assert len(non_vdom) == 1 and non_vdom[0].chassis == "" and "[" not in non_vdom[0].hostname


def test_routes_neighbors_and_tunnels_follow_their_vdom():
    units = fortidev.read_units(EDGE, "edge.conf")
    by = {d.unit: d for d in units}
    assert set(by) == {"root", "DMZ-FG"}
    routes = {u: {r["vrf"] for r in d.l3facts["routes"]} for u, d in by.items()}
    assert all(v <= {u} for u, v in routes.items())
    assert all(r["vrf"] == "DMZ-FG" for r in by["DMZ-FG"].l3facts["routes"]) and by["DMZ-FG"].l3facts["routes"]


def _graph(*devices):
    return graph_module.build(list(devices))


def _switch(neighbor_name: str, remote_port: str) -> Device:
    switch = Device(key="", hostname="CORE-SW", captured=True)
    switch.halves.append(HalfEdge(local_port="Eth1/3", remote_name=neighbor_name, remote_port=remote_port, protocols={"LLDP"}))
    return switch


def test_an_lldp_neighbor_naming_the_chassis_lands_on_the_vdom_that_owns_the_port():
    units = fortidev.read_units(_forti(), "split.conf")
    g = _graph(_switch("FW-SPLIT-01", "port3"), *units)
    link = next(l for l in g.links if "CORE-SW" in (l.a, l.b))
    assert {link.a, link.b} == {"CORE-SW", "FW-SPLIT-01 [DMZ]"}
    g = _graph(_switch("fw-split-01.example.net", "port2"), *fortidev.read_units(_forti(), "split.conf"))
    assert {l.b for l in g.links if l.a == "CORE-SW"} == {"FW-SPLIT-01 [CORP]"}


def test_an_unknown_remote_port_falls_back_to_the_first_vdom_node_and_a_vlan_subinterface_follows_its_parent():
    units = fortidev.read_units(_forti(), "split.conf")
    g = _graph(_switch("FW-SPLIT-01", ""), *units)
    assert {l.b for l in g.links if l.a == "CORE-SW"} == {units[0].hostname}
    g = _graph(_switch("FW-SPLIT-01", "port3.100"), *fortidev.read_units(_forti(), "split.conf"))
    assert {l.b for l in g.links if l.a == "CORE-SW"} == {"FW-SPLIT-01 [DMZ]"}


def test_no_stub_node_is_invented_for_the_chassis_name():
    g = _graph(_switch("FW-SPLIT-01", "port3"), *fortidev.read_units(_forti(), "split.conf"))
    assert [k for k, n in g.nodes.items() if not n.captured] == []


def test_an_inter_vdom_link_between_two_vdoms_is_a_cable_between_their_nodes():
    rows = ('    edit "npu0_vlink0"\n        set vdom "CORP"\n        set type physical\n    next\n'
            '    edit "npu0_vlink1"\n        set vdom "DMZ"\n        set type physical\n    next\n')
    units = fortidev.read_units(_forti(extra_rows=rows), "split.conf")
    g = _graph(*units)
    link = next(l for l in g.links if "VDOM-LINK" in l.protocols)
    assert {link.a, link.b} == {"FW-SPLIT-01 [CORP]", "FW-SPLIT-01 [DMZ]"} and link.state == "confirmed"
    assert {link.a_port, link.b_port} == {"npu0_vlink0", "npu0_vlink1"}


def test_an_inter_vdom_link_inside_one_vdom_draws_nothing():
    rows = ('    edit "npu0_vlink0"\n        set vdom "CORP"\n        set type physical\n    next\n'
            '    edit "npu0_vlink1"\n        set vdom "CORP"\n        set type physical\n    next\n')
    assert _graph(*fortidev.read_units(_forti(extra_rows=rows), "split.conf")).links == []


def test_port_descriptions_name_the_chassis_and_the_port_so_the_right_vdom_is_joined_by_inference():
    core = Device(key="", hostname="CORE-SW", captured=True, descriptions={"Eth1/3": "to FW-SPLIT-01 - port3"})
    core.l3 = []
    g = _graph(core, *fortidev.read_units(_forti(), "split.conf"))
    from features.topology import inferred
    inferred.infer_neighbors(g)
    joined = {frozenset((c.a, c.b)) for c in g.connections}
    assert frozenset(("CORE-SW", "FW-SPLIT-01 [DMZ]")) in joined
    ends = {(c.a, l.a_port, c.b, l.b_port) for c in g.connections for l in c.links}
    dmz = next(e for e in ends if "FW-SPLIT-01 [DMZ]" in (e[0], e[2]))
    assert {dmz[1], dmz[3]} == {"Eth1/3", "port3"}                       # the description's port picks the VDOM; the cable keeps both port names
    corp = [e for e in ends if "FW-SPLIT-01 [CORP]" in (e[0], e[2])]      # CORP's own alias ('to CORE-SW - Eth1/1') is a second, separate cable
    assert corp and all("port1" in (e[1], e[3]) and "Eth1/3" not in (e[1], e[3]) for e in corp)


def test_end_to_end_build_draws_one_firewall_node_per_vdom_next_to_the_switch():
    switch = iosxe_capture("CORE-SW", "FOC00000081", "10.96.0.9", cdp=[("FW-SPLIT-01", "192.0.2.5", "FortiGate-100F", "Gi1/0/3", "port3")])
    result = build_topology([("core.txt", switch), ("fw.conf", _forti())], view="physical")
    graph = result["graph"]
    assert {"FW-SPLIT-01 [CORP]", "FW-SPLIT-01 [DMZ]", "CORE-SW"} <= {k for k, n in graph.nodes.items() if n.captured}
    assert any({c.a, c.b} == {"CORE-SW", "FW-SPLIT-01 [DMZ]"} for c in graph.connections)
    assert result["summary"]["captured"] == 4                 # the switch and the three VDOM nodes (root keeps port9)


def test_the_build_survives_when_the_same_chassis_is_uploaded_twice():
    devices, _ = read_devices([("a.conf", _forti()), ("b.conf", _forti() + "\n# again\n")])
    g = _graph(*devices)
    assert len({k for k in g.nodes}) == len(g.nodes)


# --------------------------------------------------------------------------------------------------------------- Palo Alto
def test_a_multi_vsys_palo_alto_is_one_node_per_vsys_with_the_virtual_router_as_vrf():
    units = panosdev.read_units(PAN_MULTI_VSYS, "pa.xml")
    assert [d.hostname for d in units] == ["PA [vsys1]", "PA [vsys2]"]
    assert [sorted(d.unit_ports) for d in units] == [["Eth1/1"], ["Eth1/2"]]
    assert units[0].l3[0]["vrf"] == "vr-a" and units[0].l3facts["routes"][0]["next_hop"] == "10.1.0.254"
    assert all(d.role_hint == "firewall" and d.vendor == "Palo Alto Networks" for d in units)
    assert "Eth1/9" not in units[0].unit_ports | units[1].unit_ports       # an interface no vsys imports belongs to nobody


def test_a_palo_alto_neighbor_cable_lands_on_the_vsys_that_imports_the_port():
    units = panosdev.read_units(PAN_MULTI_VSYS, "pa.xml")
    g = _graph(_switch("PA", "ethernet1/2"), *units)
    assert {l.b for l in g.links if l.a == "CORE-SW"} == {"PA [vsys2]"}


def test_a_single_vsys_or_cli_palo_alto_is_one_device_named_after_the_host():
    cli = (FIXTURES / "firewall/panos_cli_network_synthetic.txt").read_text(encoding="utf-8")
    units = panosdev.read_units(cli, "cli.txt")
    assert len(units) == 1 and units[0].hostname == "LAB-FW01" and units[0].chassis == ""
    assert units[0].model == "PA-520" and units[0].os_version == "PAN-OS 11.1.4"
    assert {r["name"] for r in units[0].l3} >= {"ethernet1/1", "ethernet1/2"} and all(r["kind"] for r in units[0].l3)


def test_the_upload_reads_a_palo_alto_file_instead_of_skipping_it():
    devices, skipped = read_devices([("pa.xml", PAN_MULTI_VSYS)])
    assert skipped == [] and [d.hostname for d in devices] == ["PA [vsys1]", "PA [vsys2]"]
    cli, skipped = read_devices([("cli.txt", (FIXTURES / "firewall/panos_cli_network_synthetic.txt").read_text(encoding="utf-8"))])
    assert skipped == [] and cli[0].hostname == "LAB-FW01"
