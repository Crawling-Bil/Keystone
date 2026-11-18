"""Deeper findings about a main site and its recovery site (TOPO-052 to 056) and the parity table, on the invented DC / DR demo with one thing changed in memory at a time."""

from __future__ import annotations

from features.topology import sitefindings as SF
from tests.test_topology_site_findings import _fresh, _ids


def _site(graph, prefix):
    return [n for n in graph.nodes.values() if n.hostname.startswith(prefix)]


def _dci(graph, model):
    ctx = SF._pair_contexts(graph, model)[0]
    return ctx["cables"]


def _rows(graph, model):
    return _ids(SF.site_findings(graph, model))


GATEWAY = {"protocol": "HSRP", "interface": "Vlan10", "group": "10", "virtual_ip": "10.20.10.1", "state": "Standby"}


# ----------------------------------------------------------------------------------------------------------------------- TOPO-052
def test_the_same_gateway_address_at_both_sites_is_reported():
    graph, model = _fresh()
    _site(graph, "HQ-DC-CORE1")[0].l3facts["fhrp"] = [dict(GATEWAY)]
    _site(graph, "DRC-CORE1")[0].l3facts["fhrp"] = [dict(GATEWAY, state="Standby")]
    row = _rows(graph, model)["TOPO-052"]
    assert row["severity"] == "low" and "10.20.10.1" in row["detail"] and sorted(row["devices"]) == ["DRC-CORE1", "HQ-DC-CORE1"]
    assert "isolation" in row["recommendation"] and row["reference"].startswith("https://www.oreilly.com")


def test_both_sites_active_for_the_same_gateway_is_medium():
    graph, model = _fresh()
    _site(graph, "HQ-DC-CORE1")[0].l3facts["fhrp"] = [dict(GATEWAY, state="Active")]
    _site(graph, "DRC-CORE1")[0].l3facts["fhrp"] = [dict(GATEWAY, state="Active")]
    row = _rows(graph, model)["TOPO-052"]
    assert row["severity"] == "medium" and "Active (Master) at both sites" in row["detail"]


def test_different_gateway_addresses_or_one_site_without_any_are_not_reported():
    graph, model = _fresh()
    _site(graph, "HQ-DC-CORE1")[0].l3facts["fhrp"] = [dict(GATEWAY)]
    assert "TOPO-052" not in _rows(graph, model)
    _site(graph, "DRC-CORE1")[0].l3facts["fhrp"] = [dict(GATEWAY, virtual_ip="10.99.10.1")]
    assert "TOPO-052" not in _rows(graph, model)


# ----------------------------------------------------------------------------------------------------------------------- TOPO-053
def _jumbo(graph, value=9216):
    _site(graph, "HQ-DC-ACC1")[0].ifparams = {"global_mtu": False, "ports": {"Eth1/5": {"mtu": value}}}


def test_jumbo_inside_and_1500_on_the_interconnect_is_reported():
    graph, model = _fresh()
    _jumbo(graph)
    row = _rows(graph, model)["TOPO-053"]
    assert row["severity"] == "medium" and "9216" in row["detail"] and "1500 bytes" in row["detail"] and "RFC 7348" in row["recommendation"]
    assert row["reference"] == "https://www.rfc-editor.org/rfc/rfc7348"


def test_a_system_wide_jumbo_setting_counts_as_jumbo_inside():
    graph, model = _fresh()
    _site(graph, "HQ-DC-ACC1")[0].ifparams = {"global_mtu": True, "ports": {}}
    assert "system-wide" in _rows(graph, model)["TOPO-053"]["detail"]


def test_no_jumbo_inside_or_a_jumbo_interconnect_is_not_reported():
    graph, model = _fresh()
    assert "TOPO-053" not in _rows(graph, model)
    _jumbo(graph)
    for near, near_port, far, far_port in _dci(graph, model):
        for node, port in ((near, near_port), (far, far_port)):
            node.ifparams = {"global_mtu": False, "ports": {port: {"mtu": 9216, "ip": True}}}
    assert "TOPO-053" not in _rows(graph, model)


# ----------------------------------------------------------------------------------------------------------------------- TOPO-054
def _trunks(graph, model, allowed_main, allowed_rec):
    for near, near_port, far, far_port in _dci(graph, model):
        near.port_allowed[near_port], far.port_allowed[far_port] = allowed_main, allowed_rec


def test_a_trunk_that_allows_every_vlan_between_the_sites_is_reported():
    graph, model = _fresh()
    _trunks(graph, model, "1-4094", "1-4094")
    row = _rows(graph, model)["TOPO-054"]
    assert row["severity"] == "low" and "4094 VLAN(s)" in row["detail"] and "every VLAN" in row["detail"]


def test_a_stretched_vlan_with_a_gateway_at_both_sites_is_reported_and_one_without_is_not():
    graph, model = _fresh()
    _trunks(graph, model, "911", "911")                                       # the demo has a gateway for VLAN 911 at both sites
    detail = _rows(graph, model)["TOPO-054"]["detail"]
    assert "1 VLAN(s)" in detail and "VLAN 911 has a gateway at both" in detail
    _trunks(graph, model, "3999", "3999")
    assert "TOPO-054" not in _rows(graph, model)                              # stretched, but nobody routes it at both sites


def test_only_the_vlans_allowed_at_both_ends_are_stretched():
    graph, model = _fresh()
    _trunks(graph, model, "911", "100-200")
    assert "TOPO-054" not in _rows(graph, model)


def test_vlan_lists_are_read_as_printed():
    assert SF._vlan_ids("10,21-23") == {10, 21, 22, 23} and len(SF._vlan_ids("1-4094")) == 4094 and len(SF._vlan_ids("all")) == 4094
    assert SF._vlan_ids("none") == set() and SF._vlan_ids("") == set() and SF._vlan_ids("0,4095,50-40,x") == set()


# ----------------------------------------------------------------------------------------------------------------------- TOPO-055
def _layer2(graph, model):
    for near, near_port, far, far_port in _dci(graph, model):
        near.port_modes[near_port], far.port_modes[far_port] = "trunk", "trunk"


def test_the_same_vpc_domain_on_both_sides_of_a_layer_2_interconnect_is_reported():
    graph, model = _fresh()
    assert "TOPO-055" not in _rows(graph, model)                               # the demo's interconnect is routed: the domains never meet
    _layer2(graph, model)
    row = _rows(graph, model)["TOPO-055"]
    assert "vPC domain 10 at both sites" in row["detail"] and row["reference"].startswith("https://community.cisco.com")


def test_a_different_spanning_tree_mode_is_reported_only_over_layer_2():
    graph, model = _fresh()
    for node in _site(graph, "HQ-DC"):
        node.stp_protocol = "rstp"
    for node in _site(graph, "DRC"):
        node.stp_protocol = "mstp"
    assert "TOPO-055" not in _rows(graph, model)
    _layer2(graph, model)
    detail = _rows(graph, model)["TOPO-055"]["detail"]
    assert "spanning tree rstp at HQ-DC, mstp at DRC" in detail


def test_distinct_vpc_domains_over_layer_2_are_fine():
    graph, model = _fresh()
    _layer2(graph, model)
    for node in _site(graph, "DRC"):
        if node.vpc_domain:
            node.vpc_domain = str(int(node.vpc_domain) + 100)
    assert "TOPO-055" not in _rows(graph, model)


# ----------------------------------------------------------------------------------------------------------------------- TOPO-056
def test_firewalls_without_high_availability_at_the_recovery_site_are_reported():
    graph, model = _fresh()
    for name in ("DRC-FGLAN1", "DRC-FGLAN2"):
        _site(graph, name)[0].l3facts["ha"] = ""
    row = _rows(graph, model)["TOPO-056"]
    assert row["severity"] == "medium" and "4 of 6 firewalls at DRC have high availability, 6 of 6 at HQ-DC" in row["detail"]


def test_a_different_ha_mode_is_reported_but_is_not_medium():
    graph, model = _fresh()
    for node in _site(graph, "DRC-FG"):
        node.l3facts["ha"] = "a-a"
    row = _rows(graph, model)["TOPO-056"]
    assert row["severity"] == "low" and "HA mode a-p/active-passive at HQ-DC, a-a/active-passive at DRC" in row["detail"]


def test_a_pair_with_the_same_device_priority_is_reported():
    graph, model = _fresh()
    _site(graph, "DRC-PADC2")[0].l3facts["pan_ha"]["priority"] = 90
    detail = _rows(graph, model)["TOPO-056"]["detail"]
    assert "device priority is the same on both units of DRC-PADC1 and DRC-PADC2" in detail


def test_a_unit_whose_peer_was_not_captured_is_reported():
    from features.topology.extract import Device
    from features.topology.graph import Link

    graph, model = _fresh()
    unit = _site(graph, "DRC-FGLAN1")[0]
    graph.nodes["HAPEER-X"] = Device(key="HAPEER-X", hostname="HA peer of X", captured=False, role_hint="firewall")
    graph.links.append(Link(unit.key, "Eth1/9", "HAPEER-X", "", "inferred", {"HA"}, ""))
    assert "DRC: DRC-FGLAN1 named a peer that was not captured" in _rows(graph, model)["TOPO-056"]["detail"]


# ----------------------------------------------------------------------------------------------------------------------- the parity table
def test_the_parity_table_has_one_row_per_aspect_and_marks_what_only_a_person_can_fill_in():
    graph, model = _fresh()
    rows = SF.parity_rows(graph, model)
    assert {r["pair"] for r in rows} == {"HQ-DC / DRC"}
    assert {"Equipment", "VLANs", "Routing", "Gateways", "Layer 2", "Firewalls", "MTU", "Interconnect", "WAN", "Outside the captures"} <= {r["area"] for r in rows}
    outside = [r for r in rows if r["area"] == "Outside the captures"]
    assert len(outside) == 4 and {r["result"] for r in outside} == {"needs input"} and all(r["main site"] == "" and r["note"] for r in outside)
    assert [r for r in rows if r["aspect"] == "Cables between the sites"][0]["main site"] == "2"
    assert all(set(r) == {"pair", "area", "aspect", "main site", "recovery site", "result", "finding", "control", "note"} for r in rows)


def test_the_symmetric_demo_is_the_same_everywhere_it_can_be_compared():
    graph, model = _fresh()
    rows = SF.parity_rows(graph, model)
    assert not [r for r in rows if r["result"] == "differs" and r["area"] != "Outside the captures"]
    assert {r["finding"] for r in rows} == {""}


def test_a_difference_names_the_finding_that_explains_it():
    graph, model = _fresh()
    for node in _site(graph, "DRC"):
        node.l3 = [row for row in node.l3 if row["name"] not in ("Vlan911", "agg-edge.911")]
    rows = SF.parity_rows(graph, model)
    vlan = [r for r in rows if r["aspect"].startswith("VLAN gateways")][0]
    assert vlan["result"] == "differs" and vlan["finding"] == "TOPO-047" and "only at HQ-DC: 911" in vlan["note"]
    assert [r for r in rows if r["aspect"] == "Routing protocols"][0]["finding"] == ""         # no finding for the aspects that did not differ


def test_the_table_lists_what_the_devices_do_beside_what_they_are():
    graph, model = _fresh()
    node = _site(graph, "HQ-DC-CORE1")[0]
    node.function, node.function_why = "management", "7 of its 8 infrastructure neighbours reach it through a management port"
    for other in _site(graph, "DRC"):
        if getattr(other, "function", "") == "management":
            other.function = ""
    row = [r for r in SF.parity_rows(graph, model) if r["aspect"] == "Function: management switch"][0]
    assert (row["main site"], row["recovery site"], row["result"], row["finding"]) == ("1", "0", "differs", "TOPO-049")
    assert "HQ-DC-CORE1: 7 of its 8" in row["note"]
    found = _rows(graph, model)["TOPO-049"]                                       # the roles are the same at both sites; the missing management switch alone raises the finding
    assert "management switch: 1 at HQ-DC, 0 at DRC" in found["detail"] and found["severity"] == "low"


def test_without_a_recovery_site_there_is_no_table():
    graph, model = _fresh()
    for node in graph.nodes.values():
        node.hostname = node.hostname.replace("DRC-", "HQ-X-")
    graph.__dict__.pop("_sites_cache", None)
    assert SF.parity_rows(graph, model) == []


# ----------------------------------------------------------------------------------------------------------------------- the edges
def test_a_stretched_vlan_that_only_one_site_routes_is_not_reported():
    graph, model = _fresh()
    _trunks(graph, model, "911", "911")
    for node in _site(graph, "DRC"):
        node.l3 = [row for row in node.l3 if row["name"] not in ("Vlan911", "agg-edge.911")]
    assert "TOPO-054" not in _rows(graph, model)


def test_a_trunk_that_one_end_does_not_describe_is_not_a_stretch():
    graph, model = _fresh()
    for near, near_port, far, far_port in _dci(graph, model):
        near.port_allowed[near_port] = "1-4094"
    assert "TOPO-054" not in _rows(graph, model)


def test_a_layer_2_bundle_is_read_through_its_port_channel():
    graph, model = _fresh()
    for near, near_port, far, far_port in _dci(graph, model):
        near.bundle_of[near_port], far.bundle_of[far_port] = "Po99", "Po99"
        near.port_modes["Po99"], far.port_modes["Po99"] = "trunk", "trunk"
    assert "vPC domain 10 at both sites" in _rows(graph, model)["TOPO-055"]["detail"]


def test_a_recovery_site_with_more_high_availability_than_the_main_site_is_not_a_finding():
    graph, model = _fresh()
    for node in _site(graph, "HQ-DC-FGLAN"):
        node.l3facts["ha"] = ""
    assert "TOPO-056" not in _rows(graph, model)


def test_units_with_no_priority_on_either_side_do_not_have_the_same_priority():
    graph, model = _fresh()
    for name in ("DRC-PADC1", "DRC-PADC2"):
        _site(graph, name)[0].l3facts["pan_ha"]["priority"] = None
    assert "TOPO-056" not in _rows(graph, model)


def test_a_site_without_a_firewall_is_not_compared_on_high_availability():
    graph, model = _fresh()
    for node in _site(graph, "DRC"):
        if node.role_hint == "firewall":
            node.role_hint = "router"
    assert "TOPO-056" not in _rows(graph, model)
    assert not [r for r in SF.parity_rows(graph, model) if r["area"] == "Firewalls" and r["result"] == "same"]


def test_the_parity_table_says_so_when_no_cable_was_captured():
    graph, model = _fresh()
    owner = {n.key: n.hostname.startswith("DRC") for n in graph.nodes.values()}
    graph.connections = [c for c in graph.connections if owner.get(c.a) == owner.get(c.b)]
    graph.links = [l for l in graph.links if owner.get(l.a) == owner.get(l.b)]
    row = [r for r in SF.parity_rows(graph, model) if r["aspect"] == "Cables between the sites"][0]
    assert row["result"] == "no cable captured" and row["finding"] == "TOPO-050"


def test_the_parity_table_marks_the_shared_gateway_and_what_a_site_did_not_show():
    graph, model = _fresh()
    _site(graph, "HQ-DC-CORE1")[0].l3facts["fhrp"] = [dict(GATEWAY)]
    _site(graph, "DRC-CORE1")[0].l3facts["fhrp"] = [dict(GATEWAY)]
    rows = SF.parity_rows(graph, model)
    gateway = [r for r in rows if r["aspect"].startswith("HSRP")][0]
    assert gateway["result"] == "same virtual address at both sites" and gateway["finding"] == "TOPO-052" and gateway["note"] == "10.20.10.1"
    for node in _site(graph, "DRC"):
        node.l3, node.l3facts, node.ifparams = [], {}, {}
    rows = SF.parity_rows(graph, model)
    assert [r for r in rows if r["aspect"] == "Routing protocols"][0]["result"] == "not shown at one site"
    assert [r for r in rows if r["aspect"].startswith("VLAN gateways")][0]["result"] == "not shown at one site"


def test_the_symmetric_demo_has_no_notes_on_its_vlan_and_gateway_rows():
    graph, model = _fresh()
    rows = SF.parity_rows(graph, model)
    assert [r["note"] for r in rows if r["aspect"].startswith("VLAN gateways")] == [""]


def test_every_parity_row_names_the_control_it_is_evidence_for():
    graph, model = _fresh()
    rows = SF.parity_rows(graph, model)
    assert rows and all(r["control"] for r in rows)
    by_aspect = {r["aspect"]: r["control"] for r in rows}
    assert "Pasal 37" in by_aspect["Cables between the sites"] and "CP-7" in by_aspect["Cables between the sites"]
    plan = by_aspect["Disaster recovery plan tested within the last 12 months"]
    assert "Pasal 18" in plan and "CP-4" in plan and "A.5.30" in plan
    assert "Pasal 37" in by_aspect["Distance and risk separation between the two sites"]


# ----------------------------------------------------------------------------------------------------------------------- the table in the downloads
def _pack(files):
    import io
    import zipfile
    from app import create_app
    app = create_app()
    app.config["TESTING"] = True
    client = app.test_client()
    data = {"files": [(io.BytesIO(text.encode()), name) for name, text in files], "group": "auto"}
    body = client.post("/topology/api/build", data=data, content_type="multipart/form-data").get_json()
    url = next(d["url"] for d in body["downloads"] if d["name"] == "keystone-topology-pack.zip")
    return body, zipfile.ZipFile(io.BytesIO(client.get(url).data))


def test_the_pack_holds_the_parity_table_as_csv_and_as_a_sheet_when_there_is_a_recovery_site():
    import csv
    import io
    from openpyxl import load_workbook
    from features.topology import demo
    folder = demo.DEMO_DIR / "dcdrc"
    body, archive = _pack([(p.name, p.read_text(encoding="utf-8")) for p in sorted(folder.glob("*.txt"))])
    prefix = "keystone-topology-pack/"
    assert body["ok"] and prefix + "tables/dr-parity.csv" in archive.namelist()
    raw = archive.read(prefix + "tables/dr-parity.csv")
    assert raw.startswith(b"\xef\xbb\xbf")
    rows = list(csv.DictReader(io.StringIO(raw.decode("utf-8-sig"))))
    assert len(rows) > 20 and {"pair", "area", "aspect", "main site", "recovery site", "result", "finding", "control", "note"} == set(rows[0])
    assert any(r["result"] == "needs input" and "Pasal 18" in r["control"] for r in rows)
    sheets = load_workbook(io.BytesIO(archive.read(prefix + "topology.xlsx"))).sheetnames
    assert "DR parity" in sheets and sheets.index("DR parity") < sheets.index("Findings")
    assert "dr-parity.csv" in archive.read(prefix + "README.txt").decode("utf-8")


def test_a_set_without_a_recovery_site_has_no_parity_file_or_sheet():
    import io
    from openpyxl import load_workbook
    from tests.topology_samples import lab_dc
    body, archive = _pack(list(lab_dc().items()))
    prefix = "keystone-topology-pack/"
    assert body["ok"] and prefix + "tables/dr-parity.csv" not in archive.namelist()
    assert "DR parity" not in load_workbook(io.BytesIO(archive.read(prefix + "topology.xlsx"))).sheetnames
