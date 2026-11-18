"""Topology v2.7: routed ways round a firewall, the F5 return path, glued Visio lines, SD-WAN control checks, control mapping, change-window pack, renamed devices.

Everything is built from small synthetic networks (names ``FW1``, ``S1``, ``R1``, ``BIGIP-A``); no customer data.

Segmentation between zones: NIST SP 800-41 Rev. 1 https://csrc.nist.gov/pubs/sp/800/41/r1/final
"""

from __future__ import annotations

import pytest

from features.topology import findings, fwzones
from tests.test_topology_v25 import _fw_net

LEGS = [("ethernet1/1.10", "TRUST", 10, "S1", "Gi1/0/1"), ("ethernet1/2.20", "DMZ", 20, "S2", "Gi1/0/1")]


def _svi(name: str, vrf: str = "", shutdown: bool = False) -> dict:
    number = "".join(c for c in name if c.isdigit())
    return {"name": name, "ip": f"10.0.{number}.1", "prefix_len": 24, "vrf": vrf, "kind": "SVI", "shutdown": shutdown, "description": "", "status": "up", "secondary": []}


def _routed(vlan_a=("Vlan10",), vlan_b=("Vlan20",), allowed=None, node="S1"):
    graph = _fw_net(LEGS, allowed=allowed)
    graph.nodes[node].l3 = [_svi(n) for n in vlan_a + vlan_b]
    return graph


# ---- routed bypass -----------------------------------------------------------------------------------------------------------------------------------

def test_a_layer_3_switch_with_an_svi_in_the_vlan_of_each_zone_routes_between_the_zones():
    rows = fwzones.routed_bypasses(_routed())
    assert len(rows) == 1 and rows[0]["kind"] == "svi" and rows[0]["certain"] and rows[0]["via"] == "S1"
    assert {rows[0]["zone_a"], rows[0]["zone_b"]} == {"TRUST", "DMZ"} and "VLAN 10 and VLAN 20" in rows[0]["detail"]
    assert fwzones.bypasses(_routed()) == []                                  # no Layer 2 meeting: the VLANs differ, so the Layer 2 check says nothing


def test_one_svi_alone_does_not_route_between_the_zones():
    assert fwzones.routed_bypasses(_routed(vlan_b=())) == []
    assert fwzones.routed_bypasses(_routed(vlan_a=())) == []


def test_svis_in_different_vrfs_do_not_route_between_the_zones():
    graph = _fw_net(LEGS)
    graph.nodes["S1"].l3 = [_svi("Vlan10", "TRUST"), _svi("Vlan20", "DMZ")]
    assert fwzones.routed_bypasses(graph) == []
    graph.nodes["S1"].l3 = [_svi("Vlan10", "SHARED"), _svi("Vlan20", "SHARED")]
    assert [r["detail"] for r in fwzones.routed_bypasses(graph)] == ["VLAN 10 and VLAN 20 (VRF SHARED)"]


def test_a_shut_down_svi_routes_nothing():
    graph = _fw_net(LEGS)
    graph.nodes["S1"].l3 = [_svi("Vlan10"), _svi("Vlan20", shutdown=True)]
    assert fwzones.routed_bypasses(graph) == []


def test_a_trunk_that_does_not_carry_the_vlan_keeps_the_switch_out_of_the_walk():
    graph = _routed(allowed={("S1", "Gi1/0/48"): "10", ("S2", "Gi1/0/48"): "10"})
    assert fwzones.routed_bypasses(graph) == []                              # VLAN 20 never reaches S1
    assert [r["via"] for r in fwzones.routed_bypasses(_routed(allowed={("S1", "Gi1/0/48"): "10,20", ("S2", "Gi1/0/48"): "10,20"}))] == ["S1"]


def test_the_svi_names_of_huawei_and_aruba_count():
    for name_a, name_b in (("Vlanif10", "Vlanif20"), ("vlan10", "vlan20"), ("Vlan 10", "Vlan 20")):
        graph = _fw_net(LEGS)
        graph.nodes["S1"].l3 = [_svi(name_a), _svi(name_b)]
        assert len(fwzones.routed_bypasses(graph)) == 1, name_a


def test_a_router_cabled_into_both_zones_is_a_possible_way_round():
    graph = _fw_net(LEGS, cables=(), routers=("R1",))
    rows = fwzones.routed_bypasses(graph)
    assert len(rows) == 1 and rows[0]["kind"] == "router" and not rows[0]["certain"] and rows[0]["via"] == "R1"


def test_a_router_reached_through_a_switch_by_tagged_legs_of_both_zones_is_a_possible_way_round():
    graph = _fw_net([LEGS[0], ("ethernet1/2.20", "DMZ", 20, "S1", "Gi1/0/2")], cables=(), routers=("R1",))
    assert [(r["kind"], r["via"]) for r in fwzones.routed_bypasses(graph)] == [("router", "R1")]


def test_untagged_legs_of_unknown_vlan_do_not_reach_a_router_through_a_switch():
    graph = _fw_net([("ethernet1/1", "TRUST", None, "S1", "Gi1/0/1"), ("ethernet1/2", "DMZ", None, "S1", "Gi1/0/2")], cables=(), routers=("R1",))
    assert fwzones.routed_bypasses(graph) == []                              # the walk of an unknown VLAN would reach everything: not evidence


def test_a_router_reached_from_one_zone_only_is_not_a_way_round():
    graph = _fw_net([LEGS[0]], cables=(), routers=("R1",))
    assert fwzones.routed_bypasses(graph) == []


def test_the_untagged_parent_of_vlan_sub_interfaces_is_not_a_zone_of_its_own():
    graph = _fw_net([("ethernet1/1.10", "TRUST", 10, "S1", "Gi1/0/1"), ("ethernet1/1", "carrier", None, "S1", "Gi1/0/1")], cables=(), routers=("R1",), native={("S1", "Gi1/0/1"): 10})
    graph.nodes["FW1"].fw_ifaces[1]["parent"] = ""
    graph.nodes["FW1"].fw_ifaces[0]["parent"] = "ethernet1/1"
    assert fwzones.routed_bypasses(graph) == []


def test_the_findings_say_firm_for_the_svi_and_possible_for_the_router():
    rows = {r["id"]: r for r in findings._bypass_findings(_routed())}
    assert set(rows) == {"TOPO-063"} and rows["TOPO-063"]["severity"] == "high" and "S1" in rows["TOPO-063"]["devices"]
    assert "VRF" in rows["TOPO-063"]["recommendation"] and rows["TOPO-063"]["reference"].startswith("https://")
    rows = {r["id"]: r for r in findings._bypass_findings(_fw_net(LEGS, cables=(), routers=("R1",)))}
    assert set(rows) == {"TOPO-064"} and rows["TOPO-064"]["severity"] == "low"


def test_the_demo_networks_have_no_routed_way_round_a_firewall():
    from features.topology import demo, service
    for name in ("after", "before", "dcdrc", "multisite", "edge"):
        files = [(p.name, p.read_text(encoding="utf-8")) for p in sorted((demo.DEMO_DIR / name).glob("*.txt"))]
        result = service.build_topology(files, view="physical", group="none")
        assert not [f for f in result["findings"] if f["id"] in ("TOPO-063", "TOPO-064")], name


def test_the_bypass_table_lists_the_layer_2_and_the_routed_paths_together():
    both = fwzones.all_bypasses(_routed())
    assert [(r["path"], r["through"], r["certain"]) for r in both] == [("layer 3 switch (SVIs)", "S1", True)]
    l2 = fwzones.all_bypasses(_fw_net([("ethernet1/1.10", "TRUST", 10, "S1", "Gi1/0/1"), ("ethernet1/2.10", "DMZ", 10, "S2", "Gi1/0/1")]))
    assert [(r["path"], r["vlan"]) for r in l2] == [("layer 2 (same VLAN)", 10)]


# ---- F5 return path ---------------------------------------------------------------------------------------------------------------------------------------

def _f5_graph(snat: str = ""):
    """The v2.5 lab BIG-IP; ``snat`` is the source-address-translation type of the one-armed virtual server ('' = none)."""
    import tests.test_topology_v25 as v25
    original = v25.F5_MAP
    block = ("    source-address-translation {\n        type %s\n    }\n" % snat) if snat else ""
    v25.F5_MAP = original.replace("    destination /Common/192.0.2.51:8080\n", "    destination /Common/192.0.2.51:8080\n" + block)
    try:
        return v25._f5_net()
    finally:
        v25.F5_MAP = original


def test_a_one_armed_virtual_server_without_source_nat_is_marked_as_failing():
    from features.topology import f5zones
    table = {(r["virtual_server"], r["member"]): r for r in f5zones.rows(_f5_graph())}
    one = table[("oa_vs", "192.0.2.30:8080")]
    assert one["snat"] == "none" and one["return_path_at_risk"] and "past the BIG-IP" in one["return_path"]
    assert not table[("web_vs", "198.51.100.20:80")]["return_path_at_risk"] and "default gateway must be the BIG-IP" in table[("web_vs", "198.51.100.20:80")]["return_path"]
    assert "route back" in table[("web_vs", "10.77.0.5:80")]["return_path"]


def test_source_nat_on_the_one_armed_virtual_server_clears_the_risk():
    from features.topology import f5zones
    table = {(r["virtual_server"], r["member"]): r for r in f5zones.rows(_f5_graph("automap"))}
    one = table[("oa_vs", "192.0.2.30:8080")]
    assert one["snat"] == "automap" and not one["return_path_at_risk"] and "automap" in one["return_path"]


def test_the_finding_names_the_virtual_server_and_the_fix():
    rows = findings._f5_findings(_f5_graph())
    assert [r["id"] for r in rows] == ["TOPO-065"] and rows[0]["severity"] == "medium" and "oa_vs" in rows[0]["detail"] and "web_vs" not in rows[0]["detail"]
    assert "automap" in rows[0]["recommendation"] and rows[0]["reference"].startswith("https://techdocs.f5.com/")
    assert findings._f5_findings(_f5_graph("automap")) == []


def test_a_network_without_a_bigip_has_no_f5_finding():
    assert findings._f5_findings(_routed()) == []


# ---- glued Visio connectors ---------------------------------------------------------------------------------------------------------------------------------

def _vsdx_page(pages, graph, number=1):
    import io
    import zipfile
    from xml.etree import ElementTree as ET
    from features.topology.vsdx import to_vsdx
    archive = zipfile.ZipFile(io.BytesIO(to_vsdx(pages, graph)))
    return ET.fromstring(archive.read(f"visio/pages/page{number}.xml"))


def _tag(element):
    return element.tag.rsplit("}", 1)[-1]


def test_a_straight_cable_is_a_connector_glued_to_the_boxes_at_both_ends():
    from tests.test_topology_v25 import _run_of
    result = _run_of("after")
    page = result["pages"][0]
    root = _vsdx_page(result["pages"], result["graph"])
    shapes = {e.get("ID"): e for e in root.iter() if _tag(e) == "Shape"}
    connects = [e for e in root.iter() if _tag(e) == "Connect"]
    straight = [i for i, c in enumerate(page.connections) if not page.routes.get(i)]
    assert straight and len(connects) == 2 * len(straight)
    for c in connects:
        assert c.get("FromSheet") in shapes and c.get("ToSheet") in shapes and c.get("ToPart") == "3" and (c.get("FromCell"), c.get("FromPart")) in (("BeginX", "9"), ("EndX", "12"))
    one = next(c for c in connects if c.get("FromCell") == "BeginX")
    cells = {e.get("N"): e for e in shapes[one.get("FromSheet")].iter() if _tag(e) == "Cell"}
    assert cells["ObjType"].get("V") == "2" and cells["BeginX"].get("F") == f"Sheet.{one.get('ToSheet')}!PinX" and cells["BeginY"].get("F") == f"Sheet.{one.get('ToSheet')}!PinY"
    box = {e.get("N"): e for e in shapes[one.get("ToSheet")].iter() if _tag(e) == "Cell"}
    assert abs(float(cells["BeginX"].get("V")) - float(box["PinX"].get("V"))) < 1e-3 and abs(float(cells["BeginY"].get("V")) - float(box["PinY"].get("V"))) < 1e-3


def test_a_cable_with_bends_keeps_its_bends_and_is_not_glued():
    from tests.test_topology_v25 import _run_of
    result = _run_of("after")
    page = result["pages"][0]
    root = _vsdx_page(result["pages"], result["graph"])
    bent = [i for i, c in enumerate(page.connections) if page.routes.get(i)]
    straight = [i for i, c in enumerate(page.connections) if not page.routes.get(i)]
    assert bent, "the demo page must have a bent cable for this test"
    polylines = [e for e in root.iter() if _tag(e) == "Shape" and sum(1 for r in e.iter() if _tag(r) == "Row" and r.get("T") == "LineTo") >= 2 and not any(_tag(c) == "Cell" and c.get("N") == "ObjType" for c in e.iter())
                 and len([r for r in e.iter() if _tag(r) == "Row"]) != 5]
    assert len(polylines) >= len(bent)
    assert len([e for e in root.iter() if _tag(e) == "Connect"]) == 2 * len(straight)


def test_every_shape_id_on_a_visio_page_is_unique_and_the_boxes_lie_over_the_lines():
    from tests.test_topology_v25 import _run_of
    result = _run_of("after")
    root = _vsdx_page(result["pages"], result["graph"])
    ids = [e.get("ID") for e in root.iter() if _tag(e) == "Shape"]
    assert len(ids) == len(set(ids))
    order = [e for e in root.iter() if _tag(e) == "Shape"]
    first_box = next(i for i, e in enumerate(order) if any(_tag(t) == "Text" and t.text in ("L3", "L2", "FW") for t in e.iter()))
    last_line = max(i for i, e in enumerate(order) if any(_tag(c) == "Cell" and c.get("N") == "LineColor" for c in e.iter()) and not any(_tag(t) == "Text" for t in e.iter()))
    assert last_line < first_box                                                                            # the lines are written first: the boxes are drawn over them


# ---- SD-WAN control plane -----------------------------------------------------------------------------------------------------------------------------------

def _edge(name, control=(), omp=(), system_ip="10.0.0.1"):
    from features.topology.extract import Device
    node = Device(key=name, hostname=name, captured=True, role_hint="router")
    node.l3facts = {"control": list(control), "omp_peers": list(omp), "system_ip": system_ip, "site_id": "100"}
    return node


def _ctl(kind, state="up", system_ip="10.250.20.2", colour="mpls"):
    return {"type": kind, "system_ip": system_ip, "site_id": "1", "local_color": colour, "state": state, "uptime": ""}


def _omp(peer="10.250.20.2", state="up", received=10, installed=8):
    return {"peer": peer, "type": "vsmart", "state": state, "received": received, "installed": installed, "sent": 3, "site_id": "1"}


def _net(*nodes):
    from features.topology.graph import Graph
    return Graph(nodes={n.key: n for n in nodes}, links=[], connections=[], hidden_kinds=set())


def _ids(*nodes):
    return {r["id"]: r for r in findings._sdwan_control_findings(_net(*nodes))}


HEALTHY = [_ctl("vsmart", system_ip="10.250.20.2"), _ctl("vsmart", system_ip="10.250.20.3", colour="biz-internet"), _ctl("vmanage", system_ip="10.255.20.1")]


def test_a_healthy_edge_has_no_control_finding():
    assert _ids(_edge("E1", HEALTHY, [_omp(), _omp("10.250.20.3")])) == {}


def test_an_edge_whose_vsmart_connections_are_not_up_is_the_high_finding():
    rows = _ids(_edge("E1", [_ctl("vsmart", "connect"), _ctl("vbond", "up", "10.255.1.7"), _ctl("vmanage")]))
    assert set(rows) == {"TOPO-066"} and rows["TOPO-066"]["severity"] == "high" and "connect" in rows["TOPO-066"]["detail"] and rows["TOPO-066"]["devices"] == ["E1"]


def test_a_controller_that_is_down_while_a_vsmart_is_up_is_the_medium_finding():
    rows = _ids(_edge("E1", [_ctl("vsmart"), _ctl("vsmart", system_ip="10.250.20.3"), _ctl("vmanage", "tear_down", "10.255.20.1")]))
    assert set(rows) == {"TOPO-067"} and "vmanage 10.255.20.1 tear_down" in rows["TOPO-067"]["detail"]


def test_an_omp_session_that_is_up_and_installs_nothing_is_reported_and_a_down_one_is_not():
    rows = _ids(_edge("E1", HEALTHY, [_omp(installed=0), _omp("10.250.20.3", "down", 0, 0)]))
    assert set(rows) == {"TOPO-068"} and "10.250.20.2" in rows["TOPO-068"]["detail"] and "10.250.20.3" not in rows["TOPO-068"]["detail"]


def test_one_vsmart_only_is_a_low_finding():
    rows = _ids(_edge("E1", [_ctl("vsmart"), _ctl("vmanage")]))
    assert set(rows) == {"TOPO-069"} and rows["TOPO-069"]["severity"] == "low"


def test_the_same_system_ip_on_two_edges_is_reported():
    rows = _ids(_edge("E1", HEALTHY, system_ip="10.0.0.9"), _edge("E2", HEALTHY, system_ip="10.0.0.9"), _edge("E3", HEALTHY, system_ip="10.0.0.10"))
    assert set(rows) == {"TOPO-070"} and rows["TOPO-070"]["devices"] == ["E1", "E2"] and "10.0.0.9: E1, E2" in rows["TOPO-070"]["detail"]


def test_a_capture_without_control_tables_gives_no_finding_and_every_row_has_a_reference():
    assert _ids(_edge("E1")) == {}
    every = _ids(_edge("E1", [_ctl("vsmart", "connect")], [_omp(installed=0)]), _edge("E2", [_ctl("vsmart")], system_ip="10.0.0.1"))
    assert all(r["reference"].startswith("https://www.cisco.com/") for r in every.values()) and set(every) >= {"TOPO-066", "TOPO-068", "TOPO-069", "TOPO-070"}


def test_the_reader_carries_the_control_connections_and_omp_peers_of_a_capture():
    from features.topology import l3facts
    text = "\n".join([
        "HOST#show sdwan control connections",
        "PEER    PEER PEER            SITE       DOMAIN PEER                                    PRIV  PEER                                    PUB",
        "TYPE    PROT SYSTEM IP       ID         ID     PRIVATE IP                              PORT  PUBLIC IP                               PORT  ORGANIZATION            LOCAL COLOR     PROXY STATE UPTIME   ID",
        "-----------------------------------------------------------------------------------------------------------------------------------------------------------",
        "vsmart  dtls 10.250.20.2     910000     1      10.255.1.6                              13046 10.255.1.6                              13046 EXAMPLE-SDWAN-FABRIC      private2        No    up     21:00:00:170",
        "vmanage dtls 10.255.20.1     910000     0      10.255.1.5                              13046 10.255.1.5                              13046 EXAMPLE-SDWAN-FABRIC      private2        No    connect",
        "HOST#show sdwan omp peers",
        "TENANT                             DOMAIN    OVERLAY   SITE",
        "ID        PEER             TYPE    ID        ID        ID        STATE    UPTIME           R/I/S",
        "---------------------------------------------------------------------------------------------",
        "0         192.0.2.10       vsmart  1         1         900001    up       1:02:03:04       5/4/3",
        "HOST#",
    ])
    facts = l3facts.read(text, "edge.txt")
    assert [(r["type"], r["state"], r["local_color"]) for r in facts["control"]][0] == ("vsmart", "up", "private2")
    assert facts["omp_peers"] == [{"peer": "192.0.2.10", "type": "vsmart", "state": "up", "received": 5, "installed": 4, "sent": 3, "site_id": "900001"}]


def test_the_demo_networks_raise_none_of_the_new_v27_findings():
    from features.topology import demo, service
    new = {"TOPO-063", "TOPO-064", "TOPO-065", "TOPO-066", "TOPO-067", "TOPO-068", "TOPO-069", "TOPO-070"}
    for name in ("after", "before", "dcdrc", "multisite", "edge"):
        files = [(p.name, p.read_text(encoding="utf-8")) for p in sorted((demo.DEMO_DIR / name).glob("*.txt"))]
        result = service.build_topology(files, view="physical", group="none")
        assert not new & {f["id"] for f in result["findings"]}, name


# ---- control mapping and tracking columns -----------------------------------------------------------------------------------------------------------------

def test_a_zone_bypass_is_evidence_for_pci_nist_iso_cis_and_iec_62443():
    from features.topology import evidence
    for code in ("TOPO-059", "TOPO-060", "TOPO-063", "TOPO-064"):
        controls = {(f, c) for f, c, _ in evidence.controls_for(code)}
        assert (evidence.PCI, "1.4.1") in controls and (evidence.IEC, "SR 5.1") in controls and (evidence.IEC, "SR 5.2") in controls and (evidence.NIST, "SC-7") in controls, code
    assert evidence.IEC == "IEC 62443-3-3:2013" and "teeptrak.com" in evidence.__doc__


def test_the_other_new_findings_are_tagged_and_carry_no_segmentation_control():
    from features.topology import evidence
    for code in ("TOPO-065", "TOPO-066", "TOPO-067", "TOPO-068", "TOPO-069", "TOPO-070"):
        controls = evidence.controls_for(code)
        assert len(controls) >= 2 and not any(f == evidence.IEC for f, _, _ in controls), code


def test_every_control_row_has_the_tracking_columns_and_a_finding_starts_open():
    from features.topology import evidence
    rows = evidence.control_rows([{"id": "TOPO-063", "severity": "high", "title": "routed", "devices": ["S1"]}])
    assert all({"owner", "due_date", "status", "decision_note"} <= set(r) for r in rows)
    assert {r["status"] for r in rows if not r["finding"]} == {""} and {r["status"] for r in rows if r["finding"]} == {"open"}
    assert all(r["owner"] == "" and r["due_date"] == "" and r["decision_note"] == "" for r in rows)       # Keystone never invents an owner or a decision


def test_the_control_page_has_room_for_owner_due_date_and_decision_and_the_iec_section():
    from features.topology import evidence
    page = evidence.control_page(evidence.control_rows([{"id": "TOPO-059", "severity": "high", "title": "t", "devices": ["FW1"]}]), "Net", "2026-11-10", 1)
    assert "<th>Owner</th>" in page and "<th>Due</th>" in page and "accepted risk" in page and "IEC 62443-3-3:2013" in page and page.count("class=\"fill\"") >= 3
    assert page.index("ISO/IEC 27001:2022") < page.index("IEC 62443-3-3:2013")


def test_the_pack_csv_carries_the_tracking_columns(tmp_path):
    import csv
    import io
    from features.topology import demo, routes, service
    files = [(p.name, p.read_text(encoding="utf-8")) for p in sorted((demo.DEMO_DIR / "after").glob("*.txt"))]
    result = service.build_topology(files, view="physical", group="none")
    tables = routes._write_run(tmp_path, result, "Demo", inputs=files)
    reader = csv.DictReader(io.StringIO(tables["pack"]["audit/controls.csv"].decode("utf-8-sig")))
    assert {"owner", "due_date", "status", "decision_note"} <= set(reader.fieldnames)


# ---- comparing two runs: renames, high findings -------------------------------------------------------------------------------------------------------------

def _dev(name, serial, ip="", **fields):
    row = {"device": name, "captured": "yes", "role": "access", "vendor": "Cisco", "model": "C9300", "os_version": "17.9", "management_ip": ip, "serial": serial, "stack_members": "",
           "vpc_domain": "", "vpc_role": ""}
    row.update(fields)
    return row


def _lnk(a, pa, b, pb):
    return {"device_a": a, "port_a": pa, "device_b": b, "port_b": pb, "state": "confirmed", "protocols": "LLDP", "kind": "link", "bundle_a": "", "bundle_b": "", "speed_a": "10G", "speed_b": "10G",
            "rated_a": "10G", "rated_b": "10G", "port_state_a": "up", "port_state_b": "up", "duplex_a": "full", "duplex_b": "full", "subnet": "", "native_vlan": "1", "duplex": ""}


def _runs(old="ACC-OLD", new="ACC-NEW", serial_old="FOC111", serial_new="FOC111", ip_old="10.0.0.5", ip_new="10.0.0.5"):
    before = {"devices": [_dev("CORE1", "S1", "10.0.0.1", role="core"), _dev(old, serial_old, ip_old)], "links": [_lnk("CORE1", "Eth1/1", old, "Te1/1/1")],
              "hosts": [{"mac": "aa:bb", "device": old, "port": "Gi1/0/1", "ip_address": "10.1.1.1", "vlan": "10"}], "behind": [], "findings": []}
    after = {"devices": [_dev("CORE1", "S1", "10.0.0.1", role="core"), _dev(new, serial_new, ip_new)], "links": [_lnk("CORE1", "Eth1/1", new, "Te1/1/1")],
             "hosts": [{"mac": "aa:bb", "device": new, "port": "Gi1/0/1", "ip_address": "10.1.1.1", "vlan": "10"}], "behind": [], "findings": []}
    return before, after


def test_a_device_with_the_same_serial_under_another_name_is_a_rename_and_not_a_removal_and_an_addition():
    from features.topology.diff import compare_runs
    result = compare_runs(*_runs())
    changes = {(r["area"], r["change"]) for r in result["rows"]}
    assert ("Devices", "renamed") in changes and ("Devices", "removed") not in changes and ("Devices", "added") not in changes
    assert not [r for r in result["rows"] if r["area"] in ("Links", "Hosts")]                           # its link and its host follow the new name: no noise
    row = next(r for r in result["rows"] if r["change"] == "renamed")
    assert (row["item"], row["before"], row["after"]) == ("ACC-NEW", "ACC-OLD", "ACC-NEW") and "serial" in row["why"]
    assert result["summary"]["areas"]["Devices"]["renamed"] == 1 and result["summary"]["differences"] == 1 and result["summary"]["verdict"] == "changed"


def test_the_management_address_is_the_evidence_when_the_serial_changed():
    from features.topology.diff import compare_runs
    result = compare_runs(*_runs(serial_new="FOC222"))
    row = next(r for r in result["rows"] if r["change"] == "renamed")
    assert "management address" in row["why"]
    assert any(r["field"] == "serial" for r in result["rows"] if r["change"] == "changed")              # the new serial is still reported as a change of the same device


def test_a_rename_is_not_guessed_when_the_evidence_is_shared_or_missing():
    from features.topology.diff import compare_runs, find_renames
    before, after = _runs(serial_old="", serial_new="", ip_old="", ip_new="")
    assert find_renames(before["devices"], after["devices"]) == {}                                      # nothing in common: removed and added
    before, after = _runs(serial_old="SHARED", serial_new="SHARED", ip_new="10.0.0.99")
    before["devices"].append(_dev("ACC-OTHER", "SHARED", "10.0.0.8"))
    assert find_renames(before["devices"], after["devices"]) == {}                                      # two devices of the first run hold the serial: ambiguous
    before, after = _runs()
    after["devices"].append(_dev("ACC-TWIN", "FOC111", "10.0.0.5"))
    assert find_renames(before["devices"], after["devices"]) == {}                                      # two new devices claim it: ambiguous
    assert {(r["area"], r["change"]) for r in compare_runs(before, after)["rows"] if r["area"] == "Devices"} >= {("Devices", "removed"), ("Devices", "added")}


def test_a_new_high_finding_is_flagged_for_attention_like_a_medium_one():
    from features.topology.diff import compare_runs
    before, after = _runs()
    after["findings"] = [{"id": "TOPO-063", "severity": "high", "title": "routed", "devices": ["CORE1"]}, {"id": "TOPO-061", "severity": "low", "title": "bfd", "devices": ["X"]}]
    rows = {r["item"].split()[0]: r for r in compare_runs(before, after)["rows"] if r["area"] == "Findings"}
    assert rows["TOPO-063"]["impact"] == "attention" and "high" in rows["TOPO-063"]["why"] and rows["TOPO-061"]["impact"] == "info"
    before["findings"] = [{"id": "TOPO-063", "severity": "low", "title": "routed", "devices": ["CORE1"]}]
    after["findings"] = [{"id": "TOPO-063", "severity": "high", "title": "routed", "devices": ["CORE1"]}]
    again = next(r for r in compare_runs(before, after)["rows"] if r["area"] == "Findings")
    assert again["impact"] == "attention"                                                               # low to high is worse


def test_the_drawing_marks_a_renamed_device_with_the_old_name():
    from features.topology import diffmark
    marks = diffmark.collect(*_runs())
    assert marks.devices == {"ACC-NEW": "renamed"} and marks.renamed == {"ACC-NEW": "ACC-OLD"} and marks.gone == [] and marks.links == {} and marks.removed_links == []


# ---- the change-window page and pack -----------------------------------------------------------------------------------------------------------------------

def _tables_of(name):
    from features.topology import demo, service
    files = [(p.name, p.read_text(encoding="utf-8")) for p in sorted((demo.DEMO_DIR / name).glob("*.txt"))]
    result = service.build_topology(files, view="physical", group="none")
    graph = result["graph"]
    return files, {"devices": service.devices_table(graph), "links": service.links_table(graph), "hosts": service.hosts_table(graph), "behind": service.behind_table(graph), "findings": result["findings"]}


def test_a_run_built_against_an_earlier_one_carries_the_change_window():
    from features.topology import demo, service
    files, earlier = _tables_of("before")
    after = [(p.name, p.read_text(encoding="utf-8")) for p in sorted((demo.DEMO_DIR / "after").glob("*.txt"))]
    result = service.build_topology(after, view="physical", group="none", compare_with=earlier, compare_label="the window of 2026-11-01")
    change = result["change_window"]
    assert change["label"] == "the window of 2026-11-01" and change["diff"]["summary"]["differences"] > 0
    assert service.build_topology(after, view="physical", group="none")["change_window"] is None             # without the input there is no page


def test_the_change_window_page_lists_attention_renames_findings_and_an_empty_sign_off():
    from features.topology import changewindow
    from features.topology.diff import compare_runs
    before, after = _runs()
    after["findings"] = [{"id": "TOPO-063", "severity": "high", "title": "routed <b>x</b>", "devices": ["CORE1"]}]
    after["devices"].append(_dev("ACC-NEW2", "FOC999", "10.0.0.77"))
    html = changewindow.page(compare_runs(before, after), "the <i>old</i> run", "Bank <DC>", "2026-11-10 10:00")
    assert "<h2>Needs attention (1)</h2>" in html and "<h2>Renamed devices (1)</h2>" in html and "<h2>New findings (1)</h2>" in html
    assert "ACC-OLD" in html and "ACC-NEW" in html and "PCI DSS v4.0 1.4.1" in html and "IEC 62443-3-3:2013 SR 5.1" in html
    assert "<b>x</b>" not in html and "&lt;b&gt;x&lt;/b&gt;" in html and "the &lt;i&gt;old&lt;/i&gt; run" in html and "Bank &lt;DC&gt;" in html and "<script" not in html.lower()
    for name in changewindow.SIGN_OFF:
        assert f"<td>{name}</td><td></td>" in html


def test_an_identical_comparison_says_so_and_still_has_the_sign_off():
    from features.topology import changewindow
    from features.topology.diff import compare_runs
    before, _ = _runs()
    html = changewindow.page(compare_runs(before, before), "the earlier run")
    assert "No difference between the two runs." in html and "Sign-off" in html and html.count("<p>Nothing.</p>") == 1


def test_the_pack_holds_the_change_window_only_when_a_comparison_was_asked_for(tmp_path):
    import zipfile
    from features.topology import demo, routes, service
    _, earlier = _tables_of("before")
    after = [(p.name, p.read_text(encoding="utf-8")) for p in sorted((demo.DEMO_DIR / "after").glob("*.txt"))]
    plain = service.build_topology(after, view="physical", group="none")
    marked = service.build_topology(after, view="physical", group="none", compare_with=earlier)
    one, two = tmp_path / "one", tmp_path / "two"
    one.mkdir()
    two.mkdir()
    routes._write_run(one, plain, "Demo", inputs=after)
    routes._write_run(two, marked, "Demo", inputs=after)
    names_one = zipfile.ZipFile(one / "keystone-topology-pack.zip").namelist()
    names_two = zipfile.ZipFile(two / "keystone-topology-pack.zip").namelist()
    assert not any("change-window" in n for n in names_one)
    assert any(n.endswith("change-window/change-window.html") for n in names_two) and any(n.endswith("change-window/changes.csv") for n in names_two)
    manifest = zipfile.ZipFile(two / "keystone-topology-pack.zip").read(next(n for n in names_two if n.endswith("MANIFEST.sha256"))).decode()
    assert "change-window/change-window.html" in manifest                                                     # the page is covered by the SHA-256 manifest


# ---- zone-aware L3 over L2 pages, end to end ---------------------------------------------------------------------------------------------------------------

def _across_zone_edges(files, patched=None):
    """(page, extra) pairs of the L3 over L2 pages of ``files`` whose box, with the text lines under it, is half in and half out of a zone box."""
    from features.topology import l3over2, layout, service
    original = l3over2._clear_zone_edges
    if patched is not None:
        l3over2._clear_zone_edges = patched
    try:
        result = service.build_topology(files, view="l3over2", group="auto")
    finally:
        l3over2._clear_zone_edges = original
    found = []
    for page in result["l3_pages"]:
        for key, placed in page.nodes.items():
            box = (placed.x, placed.y, placed.x + layout.NODE_W, placed.y + layout.NODE_H + l3over2.ZONE_CAPTION)
            for _title, _kind, x, y, w, h in page.zones:
                touches = box[0] < x + w and x < box[2] and box[1] < y + h and y < box[3]
                if touches and not (x <= box[0] and box[2] <= x + w and y <= box[1] and box[3] <= y + h):
                    found.append((page.name, key))
    return found


def test_the_l3_pages_of_the_dc_and_drc_demo_keep_every_shared_subnet_off_the_zone_edges():
    """The DC/DRC demo with sites grouped puts a shared subnet across a zone edge unless ``_clear_zone_edges`` moves it: the first assertion shows that the scenario really triggers the rule
    (it fails when the demo stops doing so), the second that the rule clears it."""
    from features.topology import demo
    files = [(p.name, p.read_text(encoding="utf-8")) for p in sorted((demo.DEMO_DIR / "dcdrc").glob("*.txt"))]
    assert len(_across_zone_edges(files, patched=lambda *a, **k: {})) >= 2           # without the rule two subnets (DRC and HQ-DC) stand across an edge
    assert _across_zone_edges(files) == []                                           # with it none does


def test_two_zones_in_the_same_vlan_are_a_layer_2_finding_and_not_a_routed_one_as_well():
    graph = _fw_net([("ethernet1/1.10", "TRUST", 10, "S1", "Gi1/0/1"), ("ethernet1/2.10", "DMZ", 10, "S2", "Gi1/0/1")])
    graph.nodes["S1"].l3 = [_svi("Vlan10")]
    assert len(fwzones.bypasses(graph)) == 1 and fwzones.routed_bypasses(graph) == []                      # one VLAN: one SVI does not route between two zones


def test_two_old_devices_that_point_at_one_new_device_are_not_renamed():
    from features.topology.diff import find_renames
    before = [_dev("A-OLD", "SER-A", "10.0.0.11"), _dev("B-OLD", "SER-B", "10.0.0.12")]
    after = [_dev("NEW", "SER-A", "10.0.0.12")]                                                              # A matches the new device by serial, B by address
    assert find_renames(before, after) == {}
    assert find_renames(before[:1], after) == {"A-OLD": "NEW"}                                               # with one claimant it is a rename
