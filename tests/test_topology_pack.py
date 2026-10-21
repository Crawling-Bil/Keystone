"""Topology Builder third round: vPC view, link speed, new findings, run merge, behind-device inventory, documentation pack. Synthetic only."""

from __future__ import annotations

import io
import json
import sys
import zipfile
from pathlib import Path
from xml.etree import ElementTree as ET

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from topology_samples import iosxe_capture, lab_dc, nxos_capture, nxos_mac_table  # noqa: E402

from features.topology import labels  # noqa: E402
from features.topology.findings import build_findings  # noqa: E402
from features.topology.graph import link_speeds  # noqa: E402
from features.topology.service import compress_vlans  # noqa: E402
from features.topology.layout import _tier_values  # noqa: E402
from features.topology.names import speed_from_port, speed_from_transceiver, speed_text  # noqa: E402
from features.topology.report import build_report, bundles_table, make_pack  # noqa: E402
from features.topology.service import behind_table, build_topology, devices_table, hosts_table, links_table, to_json  # noqa: E402
from features.topology.state import StateError, merge, read_state  # noqa: E402


@pytest.fixture(scope="module")
def dc():
    return build_topology(list(lab_dc().items()), group="none")


# ---- speed -------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("name,mbps", [("Te1/1/1", 10000), ("Gi1/0/3", 1000), ("Twe1/0/14", 25000), ("Fo1/0/1", 40000), ("Hu1/0/1", 100000),
                                       ("XGE1/0/45", 10000), ("GE1/0/1", 1000), ("Fa0/1", 100), ("Eth1/1", 0), ("port31", 0), ("Po10", 0)])
def test_speed_from_the_interface_name(name, mbps):
    assert speed_from_port(name) == mbps


@pytest.mark.parametrize("text,mbps", [("10Gbase-SR", 10000), ("SFP+ 10GBASE-SR", 10000), ("SFP-H25GB-SR", 25000), ("QSFP-40G-SR-BD", 40000),
                                       ("1000base-T", 1000), ("10/100/1000BaseTX SFP", 1000), ("SFP-10G-T-X", 10000), ("QSFP-100G-SR4", 100000), ("nonsense", 0)])
def test_speed_from_the_transceiver_type(text, mbps):
    assert speed_from_transceiver(text) == mbps


def test_speed_text():
    assert (speed_text(10000), speed_text(1000), speed_text(100), speed_text(0), speed_text(2500)) == ("10G", "1G", "100M", "", "2500M")


def test_bundle_label_shows_member_count_and_speed(dc):
    graph = dc["graph"]
    conn = next(c for c in graph.connections if c.kind == "peer-link")
    for link in conn.links:
        graph.nodes[link.a].speeds[link.a_port] = 40000
        graph.nodes[link.b].speeds[link.b_port] = 40000
    assert labels.speed_summary(graph, conn) == "40G"
    assert labels.center_text(conn, graph).startswith("vPC peer-link 2x40G")


# ---- vPC view ----------------------------------------------------------------------------------------------------

def test_vpc_pair_becomes_one_frame_and_its_bundle_one_line(dc):
    assert [p.name for p in dc["logical_pages"]] == ["Overview (vPC view)"]
    page = dc["logical_pages"][0]
    assert len(page.pair_boxes) == 1 and next(iter(page.pair_boxes.values())).title == "vPC domain 240"
    merged = [c for c in page.connections if c.kind == "vpc"]
    assert len(merged) == 1 and merged[0].vpc_id == "101" and len(merged[0].links) == 2
    assert {merged[0].a, merged[0].b} & set(page.pair_boxes) and "LAB-ACC1" in (merged[0].a, merged[0].b)
    assert any(c.kind == "peer-link" for c in page.connections)                  # the peer-link stays inside the frame
    physical = dc["pages"][0]
    assert len(physical.connections) > len(page.connections) and not physical.pair_boxes


def test_vpc_line_label(dc):
    graph, page = dc["graph"], dc["logical_pages"][0]
    conn = next(c for c in page.connections if c.kind == "vpc")
    assert labels.center_text(conn, graph).startswith("vPC 101 · 2")
    assert "Po101" in labels.end_texts(conn)[0] or "Po101" in labels.end_texts(conn)[1]


def test_drawio_holds_both_views_and_frames_connect():
    result = build_topology(list(lab_dc().items()))
    root = ET.fromstring(result["drawio"])
    assert [d.get("name") for d in root.findall("diagram")] == ["Overview", "Overview (vPC view)"]
    logical = root.findall("diagram")[1]
    ids = {c.get("id") for c in logical.iter() if c.tag in ("mxCell", "object")}
    frames = [c for c in logical.iter("mxCell") if c.get("id", "").startswith("pb")]
    assert len(frames) == 1 and "vPC domain 240" in frames[0].get("value")
    for obj in logical.iter("object"):
        cell = obj.find("mxCell")
        if cell.get("edge") == "1":
            assert cell.get("source") in ids and cell.get("target") in ids


@pytest.mark.parametrize("view,expected", [("physical", ["Overview"]), ("logical", ["Overview (vPC view)"]), ("both", ["Overview", "Overview (vPC view)"])])
def test_view_option_selects_the_pages_of_the_diagram_file(view, expected):
    root = ET.fromstring(build_topology(list(lab_dc().items()), view=view)["drawio"])
    assert [d.get("name") for d in root.findall("diagram")] == expected


def test_no_vpc_pair_means_no_logical_page():
    files = {"A.txt": iosxe_capture("LAB-A1", "FOC0000A001", "10.1.0.1", cdp=[("LAB-B1", "10.1.0.2", "C9300L", "Gi1/0/1", "Gi1/0/1")])}
    result = build_topology(list(files.items()))
    assert result["logical_pages"] == [] and [s["view"] for s in result["svgs"] if s["view"] != "ip"] == ["physical"]


def test_speed_styling_changes_colours_and_legend():
    state = build_topology(list(lab_dc().items()), line_style="state")
    speed = build_topology(list(lab_dc().items()), line_style="speed")
    assert state["drawio"] != speed["drawio"] and "Speed unknown" in speed["drawio"] and "Confirmed: both ends" in state["drawio"]


def test_svg_of_the_logical_page_has_the_frame(dc):
    svg = next(s["svg"] for s in dc["svgs"] if s["view"] == "logical")
    assert "vPC domain 240" in svg and 'stroke-dasharray="8 5"' in svg


def test_a_device_dragged_between_a_pair_keeps_the_physical_lines():
    from features.topology.logical import logical_page
    from features.topology.layout import Placed
    base = build_topology(list(lab_dc().items()))
    page = base["pages"][0]
    a, b = (base["graph"].vpc_pairs[0][0], base["graph"].vpc_pairs[0][1])
    other = next(k for k in page.nodes if k not in (a, b))
    page.nodes[other] = Placed((page.nodes[a].x + page.nodes[b].x) / 2, page.nodes[a].y, 3)
    assert logical_page(base["graph"], page) is None


def test_management_links_are_hidden_from_the_picture_but_stay_in_the_tables():
    files = lab_dc()
    files["LAB-AGG1.txt"] = nxos_capture(
        "LAB-AGG1", "FDO00000001", "10.99.0.11",
        cdp=[("LAB-ACC1.lab.example(FOC00000001)", "10.99.0.21", "C9300L-48P-4X", "Ethernet1/1", "GigabitEthernet1/0/23"),
             ("LAB-AGG2.lab.example(FDO00000002)", "10.99.0.12", "N9K-C93180YC-FX3", "Ethernet1/47", "Ethernet1/47"),
             ("LAB-AGG2.lab.example(FDO00000002)", "10.99.0.12", "N9K-C93180YC-FX3", "Ethernet1/48", "Ethernet1/48"),
             ("LAB-OOB1", "10.99.9.9", "C1000-48P-4G-L", "mgmt0", "GigabitEthernet1/0/3")],
        port_channels=[(101, ["Eth1/1"]), (240, ["Eth1/47", "Eth1/48"])], vpc=("240", "primary", "240", "10.99.0.12"))
    hidden = build_topology(list(files.items()), hide_mgmt=True)
    shown = build_topology(list(files.items()), hide_mgmt=False)
    assert any(r["kind"] == "mgmt" for r in links_table(hidden["graph"]))
    assert not any(c.kind == "mgmt" for c in hidden["pages"][0].connections)
    assert any(c.kind == "mgmt" for c in shown["pages"][0].connections)


def test_a_switch_hanging_only_off_an_access_pair_is_drawn_below_it():
    files = {"AGG.txt": iosxe_capture("LAB-AGG1", "FOC0000A001", "10.1.0.1", cdp=[("LAB-ACC1", "10.1.0.2", "C9300L", "Gi1/0/1", "Gi1/0/1"), ("LAB-ACC2", "10.1.0.3", "C9300L", "Gi1/0/2", "Gi1/0/1")]),
             "ACC1.txt": iosxe_capture("LAB-ACC1", "FOC0000A002", "10.1.0.2", cdp=[("LAB-AGG1", "10.1.0.1", "C9300L", "Gi1/0/1", "Gi1/0/1"), ("LAB-ACC9", "10.1.0.9", "C9200L", "Gi1/0/5", "Gi1/0/1")]),
             "ACC2.txt": iosxe_capture("LAB-ACC2", "FOC0000A003", "10.1.0.3", cdp=[("LAB-AGG1", "10.1.0.1", "C9300L", "Gi1/0/1", "Gi1/0/2"), ("LAB-ACC9", "10.1.0.9", "C9200L", "Gi1/0/5", "Gi1/0/2")])}
    graph = build_topology(list(files.items()))["graph"]
    tiers = _tier_values(graph, list(graph.nodes))
    assert tiers["LAB-ACC9"] == tiers["LAB-ACC1"] + 0.5 and tiers["LAB-ACC1"] == tiers["LAB-ACC2"]


# ---- findings ----------------------------------------------------------------------------------------------------

def _codes(graph):
    return {f["id"]: f for f in build_findings(graph)}


def test_bundle_member_not_bundled_and_unused_bundle(dc):
    graph = dc["graph"]
    node = graph.nodes["LAB-ACC1"]
    node.member_state.update({"Gi1/0/23": "P", "Gi1/0/24": "s"})
    found = _codes(graph)["TOPO-016"]
    assert found["severity"] == "medium" and "Gi1/0/24 (suspended)" in found["detail"]
    node.member_state.update({"Gi1/0/23": "D", "Gi1/0/24": "D"})
    codes = _codes(graph)
    assert "TOPO-016" not in codes and "LAB-ACC1 Po40" in codes["TOPO-023"]["detail"]


def test_speed_mismatch_across_a_link_and_inside_a_bundle():
    graph = build_topology(list(lab_dc().items()))["graph"]
    link = next(l for l in graph.links if l.a == "LAB-ACC1" or l.b == "LAB-ACC1")
    graph.nodes[link.a].speeds[link.a_port] = 10000
    graph.nodes[link.b].speeds[link.b_port] = 1000
    assert link_speeds(graph, link) == (10000, 1000) or link_speeds(graph, link) == (1000, 10000)
    found = _codes(graph)["TOPO-017"]
    assert found["severity"] == "low" and "10G" in found["detail"] and "1G" in found["detail"]


def test_native_vlan_mismatch_between_two_captured_ends(dc):
    graph = dc["graph"]
    link = next(l for l in graph.links if {l.a, l.b} == {"LAB-ACC1", "LAB-AGG1"})
    graph.nodes[link.a].port_native[link.a_port] = "1"
    graph.nodes[link.b].port_native[link.b_port] = "99"
    found = _codes(graph)["TOPO-018"]
    assert found["severity"] == "medium" and "native 99" in found["detail"]


def test_native_vlan_advertised_by_an_uncaptured_peer_is_compared_with_the_own_trunk():
    graph = build_topology(list(lab_dc().items()))["graph"]
    link = next(l for l in graph.links if "LAB-FW1" in (l.a, l.b))
    own, far = (link.a, link.b) if link.b == "LAB-FW1" else (link.b, link.a)
    own_port = link.a_port if own == link.a else link.b_port
    graph.nodes[own].port_native[own_port] = "1"
    if far == link.b:
        link.seen_native_b = "77"
    else:
        link.seen_native_a = "77"
    assert "native 77" in _codes(graph)["TOPO-018"]["detail"]


def test_vpc_health_and_single_member_peer_link(dc):
    graph = dc["graph"]
    node = graph.nodes["LAB-AGG1"]
    node.vpc_health = {"peer_status": "peer adjacency formed ok", "keepalive_status": "peer is not alive", "consistency_status": "failed", "peer_link_status": "up"}
    found = _codes(graph)["TOPO-019"]
    assert found["severity"] == "medium" and "keep-alive" in found["detail"] and "consistency: failed" in found["detail"]
    node.vpc_health = {}
    node.bundles[node.vpc_peer_link] = node.bundles[node.vpc_peer_link][:1]
    codes = _codes(graph)
    assert "TOPO-019" not in codes and "LAB-AGG1" in codes["TOPO-020"]["detail"] and codes["TOPO-020"]["reference"].startswith("https://community.cisco.com/")


def test_a_configuration_only_capture_has_no_vpc_health_to_judge():
    result = build_topology(list(lab_dc().items()))
    assert not any(f["id"] == "TOPO-019" for f in result["findings"])


# ---- behind devices ----------------------------------------------------------------------------------------------

def test_behind_inventory_counts_virtual_machines_by_mac_prefix():
    files = lab_dc()
    macs = [("32", f"0050.56cc.{n:04x}", "Eth1/40") for n in range(1, 6)] + [("33", "0015.5d00.0001", "Eth1/40"), ("33", "0a00.0000.0001", "Eth1/40")]
    files["LAB-AGG1.txt"] = nxos_capture(
        "LAB-AGG1", "FDO00000001", "10.99.0.11",
        cdp=[("LAB-ACC1.lab.example(FOC00000001)", "10.99.0.21", "C9300L-48P-4X", "Ethernet1/1", "GigabitEthernet1/0/23"),
             ("LAB-AGG2.lab.example(FDO00000002)", "10.99.0.12", "N9K-C93180YC-FX3", "Ethernet1/47", "Ethernet1/47"),
             ("LAB-AGG2.lab.example(FDO00000002)", "10.99.0.12", "N9K-C93180YC-FX3", "Ethernet1/48", "Ethernet1/48")],
        lldp=[("LAB-FW1", "Eth1/40", "port5")], port_channels=[(101, ["Eth1/1"]), (240, ["Eth1/47", "Eth1/48"])],
        vpc=("240", "primary", "240", "10.99.0.12"), extra=nxos_mac_table("LAB-AGG1", macs))
    graph = build_topology(list(files.items()))["graph"]
    rows = behind_table(graph)
    assert len(rows) == 1
    row = rows[0]
    assert (row["behind"], row["switch"], row["port"], row["mac_addresses"], row["vmware"], row["hyper_v"], row["vlans"]) == ("LAB-FW1", "LAB-AGG1", "Eth1/40", 7, 5, 1, "32-33")
    assert {h["kind"] for h in hosts_table(graph)} == {"VMware", "Hyper-V", ""}


def test_vlan_ranges_are_compressed():
    assert compress_vlans(["2", "3", "4", "10", "12", "13"]) == "2-4,10,12-13" and compress_vlans([]) == ""


# ---- merge runs --------------------------------------------------------------------------------------------------

def _saved(result):
    return to_json(result["graph"], result["findings"], result["devices"])


def test_a_second_run_continues_the_first_and_matches_one_run_with_everything():
    files = list(lab_dc().items())
    first = build_topology(files[:2])
    saved = read_state(_saved(first).encode())
    second = build_topology(files[2:], previous=saved)
    full = build_topology(files)
    as_set = lambda r: sorted(tuple(sorted(row.items())) for row in links_table(r["graph"]))
    assert as_set(second) == as_set(full)
    assert second["summary"]["carried"] == 2 and second["summary"]["captured"] == 3
    assert any(f["id"] == "TOPO-022" for f in second["findings"])
    assert {d["capture_run"] for d in devices_table(second["graph"]) if d["captured"] == "yes"} == {"previous run", "this run"}


def test_a_new_capture_replaces_the_saved_device_with_the_same_serial_or_hostname():
    files = list(lab_dc().items())
    saved = read_state(_saved(build_topology(files)).encode())
    result = build_topology(files[:1], previous=saved)
    assert result["replaced"] == ["LAB-AGG1"] and result["summary"]["captured"] == 3 and result["summary"]["carried"] == 2
    kept, replaced = merge(saved, [])
    assert replaced == [] and len(kept) == 3


def test_state_is_valid_json_with_tables_and_a_compact_state_block():
    text = _saved(build_topology(list(lab_dc().items())))
    document = json.loads(text)
    assert {"devices", "links", "hosts", "behind", "findings", "state"} <= set(document)
    assert document["state"]["version"] == 1 and len(document["state"]["devices"]) == 3
    assert "\n" not in json.dumps(document["state"], separators=(",", ":"))


@pytest.mark.parametrize("data", [b"not json", b"[]", b'{"devices": []}', b'{"state": {"version": 99, "devices": []}}', b'{"state": {"version": 1, "devices": [{"x": 1}]}}',
                                  b'{"state": {"version": 1, "devices": "no"}}'])
def test_files_that_are_not_a_saved_run_are_refused_with_a_plain_message(data):
    with pytest.raises(StateError) as error:
        read_state(data)
    assert str(error.value)


def test_a_saved_state_cannot_inject_unknown_fields_or_wrong_types():
    document = json.loads(_saved(build_topology(list(lab_dc().items()))))
    device = document["state"]["devices"][0]
    device["halves"] = [{"local_port": ["x"], "remote_name": 5, "protocols": "no", "evil": "1"}]
    device["serials"] = "FDO1"
    device["speeds"] = {"Eth1/1": "fast"}
    restored = read_state(json.dumps(document).encode())[0]
    assert restored.halves[0].remote_name == "5" and restored.serials == set() and restored.carried


# ---- report and pack ---------------------------------------------------------------------------------------------

def test_report_has_every_section_and_escapes_what_came_from_the_captures():
    result = build_topology(list(lab_dc().items()))
    graph = result["graph"]
    graph.nodes["LAB-ACC1"].hostname = "<img src=x onerror=alert(1)>"
    html = build_report(graph, result["summary"], result["findings"], devices_table(graph), links_table(graph), hosts_table(graph), behind_table(graph), result["svgs"], [])
    assert "<img src=x" not in html and "&lt;img src=x" in html
    for heading in ("1. Diagrams", "2. Findings", "3. Device inventory", "4. Bundles, vPC and peer-links", "5. Hosts behind", "6. Per-device pages", "7. Method and limits", "References"):
        assert heading in html
    assert html.count("class='device'") == 3 and "<svg" in html and "<script" not in html


def test_bundle_table_lists_member_ports_speed_and_vpc_id(dc):
    rows = bundles_table(dc["graph"])
    assert {r["kind"] for r in rows} == {"bundle", "peer-link"} and any(r["vpc_id"] == "101" for r in rows)


def test_pack_is_a_zip_with_fixed_names():
    data = make_pack({"a.txt": "x", "tables/b.csv": b"y"})
    names = zipfile.ZipFile(io.BytesIO(data)).namelist()
    assert names == ["keystone-topology-pack/a.txt", "keystone-topology-pack/tables/b.csv"]


# ---- routes ------------------------------------------------------------------------------------------------------

@pytest.fixture()
def client():
    from app import create_app
    app = create_app()
    app.config["TESTING"] = True
    return app.test_client()


def _post(client, files=None, **fields):
    data = {"files": [(io.BytesIO(t.encode()), n) for n, t in (files or {}).items()], "group": "none", **fields}
    return client.post("/topology/api/build", data=data, content_type="multipart/form-data")


def test_build_returns_both_views_legend_and_new_tables(client):
    body = _post(client, lab_dc()).get_json()
    assert body["ok"] and {p["view"] for p in body["pages"]} == {"physical", "logical"}
    assert body["legend"]["logical"][-2][1].startswith("Frame") or any("Frame" in row[1] for row in body["legend"]["logical"])
    assert isinstance(body["bundles"], list) and isinstance(body["behind"], list)


def test_downloaded_pack_holds_the_report_and_the_exports(client):
    body = _post(client, lab_dc()).get_json()
    url = next(d["url"] for d in body["downloads"] if d["name"] == "keystone-topology-pack.zip")
    archive = zipfile.ZipFile(io.BytesIO(client.get(url).data))
    names = set(archive.namelist())
    prefix = "keystone-topology-pack/"
    assert {prefix + n for n in ("README.txt", "topology-report.html", "topology.drawio", "topology.xlsx", "topology.json", "tables/links.csv", "tables/bundles.csv")} <= names
    assert any(n.startswith(prefix + "diagrams/01-") and n.endswith(".svg") for n in names) and not any(".." in n for n in names)


def test_second_run_from_the_saved_json_through_the_route(client):
    first = _post(client, {k: v for k, v in list(lab_dc().items())[:2]}).get_json()
    saved = client.get(next(d["url"] for d in first["downloads"] if d["name"] == "topology.json")).data
    rest = dict(list(lab_dc().items())[2:])
    data = {"files": [(io.BytesIO(t.encode()), n) for n, t in rest.items()], "group": "none", "previous_state": (io.BytesIO(saved), "topology.json")}
    body = client.post("/topology/api/build", data=data, content_type="multipart/form-data").get_json()
    assert body["ok"] and body["summary"]["captured"] == 3 and body["summary"]["carried"] == 2
    rebuild = client.post("/topology/api/build", data={"group": "none", "previous_state": (io.BytesIO(saved), "topology.json")}, content_type="multipart/form-data")
    assert rebuild.get_json()["ok"] and rebuild.get_json()["summary"]["captured"] == 2 and rebuild.get_json()["summary"]["carried"] == 2


def test_a_wrong_previous_file_and_an_empty_request_are_refused(client):
    bad = client.post("/topology/api/build", data={"previous_state": (io.BytesIO(b"{}"), "x.json")}, content_type="multipart/form-data")
    assert bad.status_code == 400 and "saved state" in bad.get_json()["error"]
    nothing = client.post("/topology/api/build", data={"group": "none"}, content_type="multipart/form-data")
    assert nothing.status_code == 400


def test_view_line_style_and_management_options_reach_the_build(client):
    body = _post(client, lab_dc(), view="physical", line_style="speed", hide_mgmt="0").get_json()
    drawio = client.get(next(d["url"] for d in body["downloads"] if d["name"] == "topology.drawio")).data.decode()
    assert "vPC view" not in drawio and "Speed unknown" in drawio
    junk = _post(client, lab_dc(), view="<script>", line_style="rainbow").get_json()
    assert junk["ok"]


def test_a_diagram_file_with_both_views_is_read_back_as_a_layout():
    from features.topology.layout_io import read_layout
    first = build_topology(list(lab_dc().items()))
    layout = read_layout(first["drawio"].encode())
    assert set(layout) == {"Overview", "Overview (vPC view)"}
    again = build_topology(list(lab_dc().items()), layout=layout)
    assert again["summary"]["layout_kept"] == first["summary"]["captured"] + first["summary"]["seen_only"]
    only_logical = read_layout(build_topology(list(lab_dc().items()), view="logical")["drawio"].encode())
    assert build_topology(list(lab_dc().items()), layout=only_logical)["summary"]["layout_kept"] > 0
