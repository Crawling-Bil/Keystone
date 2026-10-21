"""Topology Builder: name handling, link pairing, bundles, vPC, draw.io output, routes. Synthetic captures only."""

from __future__ import annotations

import io
import re
import sys
from pathlib import Path
from xml.etree import ElementTree as ET

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from topology_samples import iosxe_capture, lab_dc, nxos_capture  # noqa: E402

from features.topology.drawio import to_drawio  # noqa: E402
from features.topology.labels import compress_ports  # noqa: E402
from features.topology.names import canon_port, short_host, split_serial  # noqa: E402
from features.topology.service import build_topology, links_table, to_csv  # noqa: E402


@pytest.fixture(scope="module")
def dc():
    return build_topology(list(lab_dc().items()), group="none")


# ---- names -------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("raw,expected", [
    ("TenGigabitEthernet1/1/1", "Te1/1/1"), ("Te1/1/1", "Te1/1/1"), ("Ethernet1/49", "Eth1/49"), ("Eth1/49", "Eth1/49"),
    ("BR Ethernet1/49", "Eth1/49"), ("TwentyFiveGigE2/0/2", "Twe2/0/2"), ("Port-channel40", "Po40"), ("mgmt0", "mgmt0"),
    ("10GE1/0/47", "XGE1/0/47"), ("BR 10GE1/0/47", "XGE1/0/47"), ("port31", "port31"), ("", ""),
])
def test_port_names_compare_equal_across_commands(raw, expected):
    assert canon_port(raw) == expected


def test_hostname_and_serial_are_split():
    assert split_serial("LAB-AGG1.lab.example(FDO00000001)") == ("LAB-AGG1.lab.example", "FDO00000001")
    assert short_host("lab-agg1.lab.example(FDO00000001)") == "LAB-AGG1"
    assert short_host("10.1.1.1") == "10.1.1.1"


def test_port_runs_are_compressed():
    assert compress_ports(["Eth1/3", "Eth1/1", "Eth1/2", "Eth1/7"]) == "Eth1/1-3, Eth1/7"
    assert compress_ports(["Gi1/0/1", "Gi1/0/2"]) == "Gi1/0/1, Gi1/0/2"


# ---- graph -------------------------------------------------------------------------------------------------------

def test_both_ends_of_a_link_confirm_it(dc):
    rows = {(r["device_a"], r["port_a"], r["device_b"], r["port_b"]): r for r in links_table(dc["graph"])}
    assert rows[("LAB-ACC1", "Gi1/0/23", "LAB-AGG1", "Eth1/1")]["state"] == "confirmed"
    assert rows[("LAB-ACC1", "Gi1/0/24", "LAB-AGG2", "Eth1/1")]["state"] == "confirmed"


def test_uncaptured_neighbor_is_a_single_sided_stub(dc):
    graph = dc["graph"]
    assert graph.nodes["LAB-FW1"].captured is False
    row = next(r for r in links_table(graph) if r["device_b"] == "LAB-FW1" or r["device_a"] == "LAB-FW1")
    assert row["state"] == "single" and row["protocols"] == "LLDP"
    assert graph.nodes["LAB-FW1"].role_hint == "firewall"


def test_identity_uses_serial_number_when_names_differ():
    files = lab_dc()
    files["LAB-ACC1.txt"] = files["LAB-ACC1.txt"].replace("LAB-AGG1.lab.example(FDO00000001)", "RENAMED-HOST(FDO00000001)")
    result = build_topology(list(files.items()))
    assert "RENAMED-HOST" not in result["graph"].nodes          # resolved to the captured LAB-AGG1 by serial
    assert result["summary"]["captured"] == 3


def test_port_channel_members_fold_into_one_line_and_vpc_is_detected(dc):
    graph = dc["graph"]
    bundles = [c for c in graph.connections if c.kind == "bundle"]
    assert len(bundles) == 2 and all(c.multi_chassis and c.vpc_id == "101" for c in bundles)
    assert {(c.a_po, c.b_po) for c in bundles} == {("Po40", "Po101")}
    peer = [c for c in graph.connections if c.kind == "peer-link"]
    assert len(peer) == 1 and len(peer[0].links) == 2
    assert dc["summary"]["vpc_pairs"] == 1


def test_a_port_that_faces_another_device_is_a_conflict():
    files = lab_dc()
    # AGG2 claims that its Eth1/1 faces AGG1 Eth1/1, but AGG1's Eth1/1 faces the access switch.
    files["LAB-AGG2.txt"] = files["LAB-AGG2.txt"].replace(
        "Device ID:LAB-ACC1.lab.example(FOC00000001)\n\nInterface address(es): 1\n    IPv4 Address: 10.99.0.21\nPlatform: cisco C9300L-48P-4X, Capabilities: Switch IGMP\nInterface: Ethernet1/1, Port ID (outgoing port): GigabitEthernet1/0/24",
        "Device ID:LAB-AGG1.lab.example(FDO00000001)\n\nInterface address(es): 1\n    IPv4 Address: 10.99.0.11\nPlatform: cisco N9K-C93180YC-FX3, Capabilities: Switch IGMP\nInterface: Ethernet1/1, Port ID (outgoing port): Ethernet1/1")
    result = build_topology(list(files.items()))
    # two disagreements: AGG2 -> AGG1 (AGG1 says Eth1/1 faces ACC1) and ACC1 -> AGG2 (AGG2 now says Eth1/1 faces AGG1)
    assert result["summary"]["conflicts"] == 2
    assert any(f["id"] == "TOPO-002" for f in result["findings"])


def test_cdp_and_lldp_disagreement_is_reported():
    files = lab_dc()
    # LLDP on AGG1 Eth1/1 names a different device than CDP does on the same port
    files["LAB-AGG1.txt"] = files["LAB-AGG1.txt"].replace("LAB-FW1              Eth1/40", "LAB-OTHER            Eth1/1 ")
    assert "LAB-OTHER" in files["LAB-AGG1.txt"]
    result = build_topology(list(files.items()))
    assert any(f["id"] == "TOPO-011" and "LAB-OTHER" in f["detail"] for f in result["findings"])


def test_same_hostname_with_different_serials_is_kept_apart_and_reported():
    files = lab_dc()
    files["copy.txt"] = files["LAB-ACC1.txt"].replace("FOC00000001", "FOC00000999")
    result = build_topology(list(files.items()))
    assert "LAB-ACC1#2" in result["graph"].nodes
    assert any(f["id"] == "TOPO-003" for f in result["findings"])


def test_uploading_the_same_device_twice_does_not_duplicate_it():
    files = lab_dc()
    files["again.txt"] = files["LAB-ACC1.txt"]
    result = build_topology(list(files.items()))
    assert result["summary"]["captured"] == 3
    assert any(f["id"] == "TOPO-003" and f["severity"] == "low" for f in result["findings"])


def test_capture_without_neighbors_is_reported():
    capture = iosxe_capture("LAB-LONELY", "FOC00000777", "10.99.0.77", cdp=[])
    result = build_topology([("LAB-LONELY.txt", capture)])
    assert any(f["id"] == "TOPO-008" for f in result["findings"])


def test_endpoints_are_collapsed_into_one_node():
    cdp = [(f"LAB-AP-{n}", f"10.99.1.{n}", "AIR-AP2802I-E-K9", f"GigabitEthernet1/0/{n}", "GigabitEthernet0", "Trans-Bridge Source-Route-Bridge IGMP") for n in range(1, 6)]
    capture = iosxe_capture("LAB-ACC9", "FOC00000555", "10.99.0.55", cdp=cdp)
    on = build_topology([("a.txt", capture)], collapse_endpoints=True)
    off = build_topology([("a.txt", capture)], collapse_endpoints=False)
    assert len(on["graph"].nodes) == 2 and len(off["graph"].nodes) == 6
    assert len(links_table(on["graph"])) == 5                      # every port still listed in links.csv


def test_unreadable_file_is_skipped_not_fatal():
    result = build_topology([("empty.txt", "   "), *lab_dc().items()])
    assert result["skipped"] == [{"file": "empty.txt", "reason": "The file is empty."}]
    assert result["summary"]["captured"] == 3


def _huawei(host: str, local: str, peer: str, remote: str, octet: int) -> str:
    return (f"<{host}>display version\nHuawei Versatile Routing Platform Software\nVRP (R) software, Version 5.170 (S5735 V200R021C10SPC600)\n"
            f"HUAWEI S5735-L48T4X-A1 Routing Switch uptime is 10 days\n<{host}>display lldp neighbor brief\n"
            f"Local Intf       Neighbor Dev             Neighbor Intf             Exptime(s)\n{local:<16} {peer:<24} {remote:<25} 95\n"
            f"<{host}>display current-configuration\n#\nsysname {host}\n#\ninterface Vlanif1\n ip address 10.88.0.{octet} 255.255.255.0\n#\nreturn\n<{host}>")


def test_huawei_lldp_links_are_paired_and_os_version_is_text():
    files = [("a.txt", _huawei("LAB-HW-ACC1", "XGE0/0/1", "LAB-HW-AGG1", "XGE0/0/5", 11)),
             ("b.txt", _huawei("LAB-HW-AGG1", "XGE0/0/5", "LAB-HW-ACC1", "XGE0/0/1", 12))]
    result = build_topology(files)
    assert result["summary"]["confirmed"] == 1 and result["summary"]["captured"] == 2
    assert all(isinstance(n.os_version, str) and "{" not in n.os_version for n in result["graph"].nodes.values())


# ---- draw.io -----------------------------------------------------------------------------------------------------

def test_drawio_file_is_well_formed_and_connected(dc):
    root = ET.fromstring(dc["drawio"])
    assert root.tag == "mxfile" and root.find("diagram") is not None
    for diagram in root.findall("diagram"):          # draw.io numbers cells per page, so every page has its own cells 0 and 1
        ids = [el.get("id") for el in diagram.iter() if el.get("id") and el.tag in ("mxCell", "object")]
        assert len(ids) == len(set(ids)), "cell ids must be unique inside a page"
    physical = root.find("diagram")                   # the second page is the logical (vPC) view of the same estate
    cells = {c.get("id"): c for c in physical.iter("mxCell")}
    assert "0" in cells and cells["1"].get("parent") == "0"
    vertices = {el.get("id") for el in physical.iter("object") if el.find("mxCell").get("vertex") == "1"}
    edges = [el for el in physical.iter("object") if el.find("mxCell").get("edge") == "1"]
    assert len(vertices) == 4 and len(edges) == 4
    for edge in edges:
        cell = edge.find("mxCell")
        assert cell.get("source") in vertices and cell.get("target") in vertices
    labels = " ".join(el.get("label", "") for el in root.iter("object"))
    assert "LAB-AGG1" in labels and "N9K-C93180YC-FX3" in labels and "10.99.0.11" in labels


def test_drawio_styles_match_the_reference_diagrams(dc):
    text = dc["drawio"]
    for token in ("shape=mxgraph.cisco19.rect", "prIcon=l3_switch", "prIcon=l2_switch", "prIcon=firewall",
                  "endArrow=none", "strokeColor=#0070c0", "strokeColor=#ED7D31", 'fontColor=' if False else "labelBackgroundColor=#ffffff"):
        assert token in text, token


def test_groups_become_containers_and_extra_pages():
    files = {"LAB-A1.txt": iosxe_capture("SITE1-SW1", "FOC0000A001", "10.1.0.1", cdp=[("SITE2-SW1", "10.2.0.1", "C9300L-48P-4X", "Gi1/0/1", "Gi1/0/1")]),
             "LAB-B1.txt": iosxe_capture("SITE2-SW1", "FOC0000B001", "10.2.0.1", cdp=[("SITE1-SW1", "10.1.0.1", "C9300L-48P-4X", "Gi1/0/1", "Gi1/0/1")])}
    result = build_topology(list(files.items()), group="prefix1")
    assert [p.name for p in result["pages"]] == ["Overview", "SITE1", "SITE2"]
    root = ET.fromstring(result["drawio"])
    assert [d.get("name") for d in root.findall("diagram")] == ["Overview", "SITE1", "SITE2"]
    assert result["summary"]["confirmed"] == 1


def test_special_characters_in_names_cannot_break_the_files():
    host = 'LAB-<b>&"X'
    capture = iosxe_capture("LAB-OK", "FOC00000321", "10.99.0.32", cdp=[(host, "10.99.0.33", "C9300L-48P-4X", "Gi1/0/1", "Gi1/0/2")])
    result = build_topology([("x.txt", capture)])
    ET.fromstring(result["drawio"])                                 # still parses
    assert "<b>&\"X" not in result["svgs"][0]["svg"]


def test_csv_cells_cannot_run_as_spreadsheet_formulas():
    text = to_csv([{"device": "=cmd|' /C calc'!A0", "note": "+1+1", "ok": "-5"}])
    assert "'=cmd" in text and "'+1+1" in text and ",-5" in text


# ---- routes ------------------------------------------------------------------------------------------------------

@pytest.fixture()
def client():
    from app import create_app
    app = create_app()
    app.config["TESTING"] = True
    return app.test_client()


def _upload(files: dict[str, str]) -> dict:
    return {"files": [(io.BytesIO(text.encode()), name) for name, text in files.items()], "group": "none"}


def test_topology_page_opens_and_is_in_the_registry(client):
    response = client.get("/topology")
    assert response.status_code == 200 and b"Topology Builder" in response.data
    assert b'href="/topology"' in client.get("/").data


def test_build_returns_results_and_downloads(client):
    response = client.post("/topology/api/build", data=_upload(lab_dc()), content_type="multipart/form-data")
    body = response.get_json()
    assert response.status_code == 200 and body["ok"] and body["summary"]["captured"] == 3
    assert body["pages"][0]["svg"].startswith("<svg")
    names = {d["name"] for d in body["downloads"]}
    assert names == {"topology.drawio", "topology.xlsx", "links.csv", "devices.csv", "hosts.csv", "behind.csv", "bundles.csv", "findings.csv",
                     "topology.json", "topology-report.html", "keystone-topology-pack.zip", "run-settings.txt"}
    for download in body["downloads"]:
        fetched = client.get(download["url"])
        assert fetched.status_code == 200 and fetched.data
    ET.fromstring(client.get(f"/topology/api/export/{body['export_id']}/topology.drawio").data)


def test_build_rejects_missing_and_unreadable_input(client):
    assert client.post("/topology/api/build", data={}, content_type="multipart/form-data").status_code == 400
    response = client.post("/topology/api/build", data=_upload({"x.txt": "hello"}), content_type="multipart/form-data")
    assert response.status_code == 400 and not response.get_json()["ok"]


@pytest.mark.parametrize("export_id,name", [("0" * 32, "topology.drawio"), ("../" * 3 + "etc", "topology.drawio"), ("a" * 32, "app.py")])
def test_export_route_refuses_unknown_or_unsafe_names(client, export_id, name):
    assert client.get(f"/topology/api/export/{export_id}/{name}").status_code == 404


def test_sensible_defaults_for_unknown_grouping(client):
    data = _upload(lab_dc())
    data["group"] = "not-a-mode"
    assert client.post("/topology/api/build", data=data, content_type="multipart/form-data").get_json()["ok"]
