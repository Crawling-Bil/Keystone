"""Sizing Tool: classify, the readers, the rollup arithmetic, the overrides, the routes and the Excel workbook.

Everything runs on the invented campus set shipped with the tool (``features/sizing_tool/demo/campus``) and on short synthetic strings; no customer capture is used.
"""

from __future__ import annotations

import io

import pytest
from openpyxl import load_workbook

from app import create_app
from features.sizing_tool import demo, licence_extra
from features.sizing_tool.classify import classify, role_of, site_of, tier_of
from features.sizing_tool.common import new_asset
from features.sizing_tool.rollup import build
from features.sizing_tool.routes import apply_overrides
from features.sizing_tool.service import read_texts

CAMPUS = {name: data.decode("utf-8") for name, data in demo.read_set("campus")}


@pytest.fixture(scope="module")
def assets():
    found, skipped = read_texts(list(CAMPUS.items()))
    assert skipped == []
    return {a["hostname"].split(".")[0]: a for a in found}, found


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setenv("NES_DISABLE_AUTH", "1")
    app = create_app()
    app.testing = True
    return app.test_client()


# ------------------------------------------------------------------------------------------------------------------------------- classify

@pytest.mark.parametrize("name, analyzer, brand", [
    ("CMP-CORE1.txt", "switch", "Cisco"), ("CMP-ACC1.txt", "switch", "Cisco"), ("CMP-HWSW1.txt", "switch", "Huawei"), ("CMP-AOSCX1.txt", "switch", "Aruba"),
    ("CMP-RTR1.txt", "router", "Cisco"), ("CMP-PAFW1.txt", "firewall", "Palo Alto"), ("CMP-FGFW1.txt", "firewall", "Fortinet"), ("CMP-LB1.txt", "lb", "F5"),
    ("CMP-WLC1.txt", "wireless", "Cisco"), ("CMP-WLC2.txt", "wireless", "Huawei"),
])
def test_every_campus_capture_goes_to_its_analyzer(name, analyzer, brand):
    found = classify(CAMPUS[name])
    assert (found["analyzer"], found["brand"]) == (analyzer, brand)


def test_nexus_show_command_capture_goes_to_the_switch_reader():
    text = "SW# show version\nCisco Nexus Operating System (NX-OS) Software\n  NXOS: version 10.3(5)\n  cisco Nexus9000 N9K-C93180YC-FX3 Chassis\n"
    assert classify(text) == {"analyzer": "switch", "brand": "Cisco", "label": "Cisco Nexus switch (show commands)"}


@pytest.mark.parametrize("set_id", ["topology:before", "topology:after", "topology:edge", "topology:multisite", "topology:dcdrc"])
def test_every_topology_demo_capture_is_read(set_id):
    found, skipped = read_texts([(n, d.decode()) for n, d in demo.read_set(set_id)])
    assert skipped == [] and found


def test_unknown_text_is_not_classified():
    assert classify("hello world\nnothing network here")["analyzer"] == ""


def test_role_tier_site_rules():
    assert role_of("X-FW1", "PA-3220", "") == "firewall"
    assert role_of("X-LB1", "BIG-IP i5800", "") == "loadbalancer"
    assert tier_of("core", "switch") == "Core"
    assert tier_of("access", "switch") == "Access"
    assert site_of("JKT-CORE1") == "JKT"
    assert site_of("JKT-DC-ACC2") == "JKT-DC"


# ------------------------------------------------------------------------------------------------------------------------------- readers

def test_campus_set_reads_fifteen_records(assets):
    by_name, found = assets
    assert len(found) == 15
    assert {a["device_type"] for a in found} == {"switch", "router", "firewall", "load_balancer", "wlc", "access_point"}
    assert len({a["id"] for a in found}) == 15


def test_cisco_core_components_and_licences(assets):
    core = assets[0]["CMP-CORE1"]
    assert core["vendor"] == "Cisco" and core["model"].startswith("C9404R")
    categories = {c["category"] for c in core["components"]}
    assert {"Chassis", "Module", "Power supply"} <= categories
    assert any(l["name"].lower().endswith("dna advantage") for l in core["licences"])
    assert core["capacity"]["Physical ports"] > 0


def test_stack_is_one_record_with_members(assets):
    acc = assets[0]["CMP-ACC1"]
    assert acc["ha"].startswith("Stack of 2")
    assert acc["capacity"]["Stack members"] == 2
    assert "(Active)" in acc["serial"] and "(Standby)" in acc["serial"]


def test_huawei_and_aruba_switch(assets):
    hw, aruba = assets[0]["CMP-HWSW1"], assets[0]["CMP-AOSCX1"]
    assert hw["vendor"] == "Huawei" and hw["licences"]
    assert aruba["vendor"] == "Aruba" and aruba["serial"] == "SG24520CX1"
    assert any("Aruba Central" in n for n in aruba["notes"])             # Aruba licences are not in a switch capture: the note says where they are


def test_router_reads_licences_and_routing(assets):
    rtr = assets[0]["CMP-RTR1"]
    assert rtr["device_type"] == "router" and rtr["licences"]
    assert any("package" in l["name"] for l in rtr["licences"])


def test_palo_alto_config_plus_runtime_in_one_file(assets):
    fw = assets[0]["CMP-PAFW1"]
    assert (fw["model"], fw["serial"]) == ("PA-3220", "007254000141")
    assert fw["os"] == "PAN-OS 10.2.9-h1" and fw["ha"] == "HA active-passive"
    assert fw["capacity"]["Firewall policies"] == 4 and fw["capacity"]["NAT rules / VIPs"] == 2 and fw["capacity"]["Zones"] == 4
    names = [l["name"] for l in fw["licences"]]
    assert "Threat Prevention" in names and "PAN-DB URL Filtering" in names and "GlobalProtect Gateway" in names
    assert next(l for l in fw["licences"] if l["name"] == "Threat Prevention")["expires"] == "2027-01-12"
    assert "SYNTHETIC" not in repr(fw) and "REDACTED" not in repr(fw)


def test_palo_alto_runtime_only_capture_still_reads_licences():
    runtime = CAMPUS["CMP-PAFW1.txt"]
    head = runtime[:runtime.index("admin@CMP-PAFW1> show config running")]
    tail = runtime[runtime.index("admin@CMP-PAFW1> request license info"):]
    found, skipped = read_texts([("pa.txt", head + tail)])
    assert skipped == [] and found[0]["model"] == "PA-3220" and len(found[0]["licences"]) == 6


def test_fortigate_reads_policies_vips_and_ha(assets):
    fg = assets[0]["CMP-FGFW1"]
    assert fg["model"] == "FortiGate-100F" and fg["serial"] == "FG100FTK20000141" and fg["ha"] == "HA active-passive (a-p)"
    assert fg["capacity"]["Firewall policies"] == 5 and fg["capacity"]["NAT rules / VIPs"] == 2 and fg["capacity"]["VPN tunnels"] == 1
    assert fg["licences"][0]["name"] == "FortiGate licence" and fg["licences"][0]["state"] == "Valid"
    assert "SYNTHETIC" not in repr(fg)


def test_f5_licence_bundle_subscriptions_and_no_registration_key(assets):
    lb = assets[0]["CMP-LB1"]
    assert lb["model"] == "BIG-IP i5800" and lb["ha"] == "HA cluster of 2" and lb["os"] == "TMOS 15.1.8"
    names = {l["name"]: l for l in lb["licences"]}
    assert "Best Bundle, i5800" in names and names["IP Intelligence, 1Yr"]["expires"] == "2026-12-06"
    assert "AAAAA-BBBBB" not in repr(lb)
    assert lb["capacity"]["Virtual servers"] == 3 and lb["capacity"]["Pools"] == 2
    assert {"ASM module", "LTM module"} <= set(names)


def test_wireless_controllers_and_access_points_by_model(assets):
    _, found = assets
    wlc1 = next(a for a in found if a["hostname"] == "CMP-WLC1" and a["device_type"] == "wlc")
    assert wlc1["model"] == "C9800-L-F-K9" and wlc1["capacity"]["Access points (configured)"] == 24 and wlc1["capacity"]["Licensed AP capacity"] == 250
    aps = {a["model"]: a for a in found if a["device_type"] == "access_point" and a["vendor"] == "Cisco"}
    assert {m: a["capacity"]["Access points"] for m, a in aps.items()} == {"C9120AXI-F": 12, "C9130AXI-E": 8, "C9105AXW-E": 4}
    wlc2 = next(a for a in found if a["hostname"] == "CMP-WLC2" and a["device_type"] == "wlc")
    assert wlc2["vendor"] == "Huawei" and wlc2["capacity"]["Licensed AP capacity"] == 32 and wlc2["capacity"]["Access points (configured)"] == 12
    assert sum(a["capacity"]["Access points"] for a in found if a["vendor"] == "Huawei" and a["device_type"] == "access_point") == 12


def test_the_same_capture_twice_is_merged_not_counted_twice():
    found, _ = read_texts([("a.txt", CAMPUS["CMP-CORE1.txt"]), ("b.txt", CAMPUS["CMP-CORE1.txt"])])
    assert len(found) == 2 and found[1]["duplicate_of"] == found[0]["id"] and found[0]["merged_from"] == ["a.txt", "b.txt"]
    assert any("Same device" in n for n in found[1]["notes"]) and not any("counted twice" in n for n in found[0]["notes"] + found[1]["notes"])


def test_two_devices_with_one_hostname_and_different_serials_are_both_counted_and_flagged():
    other = CAMPUS["CMP-CORE1.txt"].replace("FXS2412Q0A1", "FXS2412Q0ZZ")
    found, _ = read_texts([("a.txt", CAMPUS["CMP-CORE1.txt"]), ("b.txt", other)])
    assert len(found) == 2 and not any(a["duplicate_of"] for a in found) and any("same hostname" in n for n in found[1]["notes"])


def test_unreadable_or_empty_capture_is_reported_not_fatal():
    found, skipped = read_texts([("empty.txt", "  \n"), ("junk.txt", "lorem ipsum"), ("ok.txt", CAMPUS["CMP-LB1.txt"])])
    assert len(found) == 1
    assert {s["file"] for s in skipped} == {"empty.txt", "junk.txt"}


# ------------------------------------------------------------------------------------------------------------------------------- licence readers

HUAWEI_LICENSE = """<SW1>display license
License state: Normal
Active license file: SW1.dat
Product name: S5735
Item name                 Control value  Description
----------------------------------------------------------------------
WLAN-AC-AP-LIC           32             Number of manageable APs
<SW1>
"""


def test_huawei_licence_block():
    items = licence_extra.huawei_licences(HUAWEI_LICENSE)
    assert items[0]["state"] == "Normal" and "S5735" in items[0]["name"]
    assert items[1]["name"] == "WLAN-AC-AP-LIC" and "value 32" in items[1]["detail"]
    assert licence_extra.huawei_licences("<SW1>display version\nVRP\n") == []


def test_pan_licence_marks_expired_and_perpetual():
    text = ("admin@FW> request license info\n\nLicense entry:\nFeature: Base\nExpires: Never\nExpired?: no\n\n"
            "License entry:\nFeature: Threat Prevention\nExpires: January 1, 2020\nExpired?: yes\n\nadmin@FW> exit\n")
    items = licence_extra.pan_licences(text)
    assert [(i["name"], i["state"]) for i in items] == [("Base", "active"), ("Threat Prevention", "expired")]
    assert items[0]["detail"] == "perpetual" and items[0]["expires"] == ""


def test_f5_licence_ignores_text_without_the_command():
    assert licence_extra.f5_licences("[admin@lb:Active:Standalone] ~ # tmsh show sys version\nSys::Version\n") == []


# ------------------------------------------------------------------------------------------------------------------------------- rollup

def _asset(**kw):
    base = dict(hostname="X-SW1", vendor="Cisco", device_type="switch", role="access", model="M1", capacity={"Physical ports": 28, "Ports 10G": 7, "VLANs": 18, "PoE power (W)": 152.5})
    base.update(kw)
    return new_asset(**base)


def test_growth_rounds_up_only_what_adds_up():
    a = _asset()
    a["id"] = "d1"
    rows = {r["label"]: r for g in build([a], 25)["groups"] for r in g["sizing"]}
    assert rows["Physical ports"]["today"] == 28 and rows["Physical ports"]["target"] == 35
    assert rows["Ports 10G"]["target"] == 9                                    # 8.75 rounds up
    assert rows["VLANs"]["target"] == rows["VLANs"]["today"] == 18             # a VLAN count is not a capacity that grows
    assert rows["PoE power (W)"]["target"] == 190.6
    assert build([a], 0)["groups"][0]["sizing"][0]["target"] == 28


def test_rollup_adds_up_across_devices_and_lists_gaps():
    one, two = _asset(hostname="X-SW1"), _asset(hostname="X-SW2", capacity={"Physical ports": 12})
    one["id"], two["id"] = "d1", "d2"
    one["components"].append({"category": "Transceiver", "part": "SFP-10G-SR", "description": "10GBASE-SR", "qty": 3})
    two["components"].append({"category": "Transceiver", "part": "SFP-10G-SR", "description": "10GBASE-SR", "qty": 2})
    out = build([one, two], 10)
    ports = next(r for r in out["groups"][0]["sizing"] if r["label"] == "Physical ports")
    assert ports["today"] == 40 and ports["largest_single_device"] == 28
    bom = next(b for b in out["bom"] if b["part"] == "SFP-10G-SR")
    assert (bom["qty"], bom["devices"]) == (5, 2)
    assert out["summary"]["devices"] == 2 and out["sites"][0]["site"] == "X"


def test_campus_rollup_summary(assets):
    out = build(assets[1], 25)
    s = out["summary"]
    assert s["devices"] == 15 and s["access_points"] == 36
    assert s["by_type"] == {"Access point": 5, "Firewall": 2, "Load balancer": 1, "Router": 1, "Switch": 4, "Wireless controller": 2}
    assert set(s["by_vendor"]) == {"Aruba", "Cisco", "F5", "Fortinet", "Huawei", "Palo Alto"}
    assert out["links"] and all(l["url"].startswith("https://") for l in out["links"])
    assert {g["type"] for g in out["groups"]} == {"switch", "router", "firewall", "load_balancer", "wlc", "access_point"}
    assert all(g["inputs"] for g in out["groups"])


# ------------------------------------------------------------------------------------------------------------------------------- overrides

def test_overrides_exclude_retype_and_resite():
    a, b, c = (_asset(hostname=f"X-SW{i}") for i in (1, 2, 3))
    a["id"], b["id"], c["id"] = "d1", "d2", "d3"
    out = apply_overrides([a, b, c], {"d1": {"exclude": True}, "d2": {"device_type": "router", "site": "  HQ  "}, "d3": {"device_type": "toaster", "site": 5}})
    assert [x["id"] for x in out] == ["d2", "d3"]
    assert out[0]["device_type"] == "router" and out[0]["site"] == "HQ"
    assert out[1]["device_type"] == "switch" and out[1]["site"] == "X"          # a type outside the six and a non-string site are ignored
    assert a["device_type"] == "switch" and b["device_type"] == "switch"       # the stored run is never changed


# ------------------------------------------------------------------------------------------------------------------------------- routes

def test_page_opens_and_is_in_the_registry(client):
    page = client.get("/sizing-tool")
    assert page.status_code == 200 and b"Sizing Tool" in page.data
    assert "sizing" in client.get("/api/health").get_json()["modules"]


def test_demo_lists_topology_sets_and_the_campus(client):
    sets = {s["id"]: s for s in client.get("/sizing-tool/api/demo").get_json()["sets"]}
    assert {"topology:before", "topology:after", "topology:edge", "topology:multisite", "topology:dcdrc", "campus"} <= set(sets)
    assert len(sets["campus"]["files"]) == 10 and sets["campus"]["origin"] == "Sizing Tool"


def test_analyze_demo_then_rollup_with_overrides_then_export(client):
    first = client.post("/sizing-tool/api/analyze", data={"demo": "campus", "growth": "25", "name": "Refresh test"}).get_json()
    assert first["ok"] and len(first["assets"]) == 15 and first["skipped"] == []
    run_id = first["run_id"]
    drop = [a["id"] for a in first["assets"] if a["hostname"] == "CMP-CORE1"]
    second = client.post("/sizing-tool/api/rollup", json={"run_id": run_id, "growth": 50, "overrides": {drop[0]: {"exclude": True}}}).get_json()
    assert second["ok"] and len(second["assets"]) == 14 and second["rollup"]["growth"] == 50
    xlsx = client.post("/sizing-tool/api/export", json={"run_id": run_id, "growth": 25, "overrides": {}})
    assert xlsx.status_code == 200 and "keystone-Refresh-test.xlsx" in xlsx.headers["Content-Disposition"]
    book = load_workbook(io.BytesIO(xlsx.data))
    assert {"Summary", "Devices", "Sizing by type", "Models", "Bill of materials", "Licences", "Features in use", "Sites", "Gaps in the captures", "Inputs and links"} <= set(book.sheetnames)
    assert book["Devices"].max_row == 16


def test_topology_demo_sets_read_too(client):
    answer = client.post("/sizing-tool/api/analyze", data={"demo": "topology:edge"}).get_json()
    assert answer["ok"] and {a["device_type"] for a in answer["assets"]} >= {"switch", "firewall", "load_balancer"}


def test_analyze_uploads_a_file(client):
    answer = client.post("/sizing-tool/api/analyze", data={"files": (io.BytesIO(CAMPUS["CMP-PAFW1.txt"].encode()), "pa.txt")}, content_type="multipart/form-data").get_json()
    assert answer["ok"] and answer["assets"][0]["model"] == "PA-3220"


def test_analyze_errors(client):
    assert client.post("/sizing-tool/api/analyze", data={}).status_code == 400
    assert client.post("/sizing-tool/api/analyze", data={"demo": "nope"}).status_code == 400
    junk = client.post("/sizing-tool/api/analyze", data={"files": (io.BytesIO(b"lorem ipsum"), "x.txt")}, content_type="multipart/form-data")
    assert junk.status_code == 400 and junk.get_json()["skipped"][0]["file"] == "x.txt"


@pytest.mark.parametrize("run_id", ["", "../../etc/passwd", "z" * 32, "0" * 32])
def test_rollup_and_export_refuse_bad_run_ids(client, run_id):
    assert client.post("/sizing-tool/api/rollup", json={"run_id": run_id}).status_code == 404
    assert client.post("/sizing-tool/api/export", json={"run_id": run_id}).status_code == 404


def test_a_folder_that_is_not_a_run_id_is_never_opened(client):
    from features.sizing_tool import routes
    folder = routes.EXPORT_DIR / "not-a-run-id"
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "run.json").write_text('{"name": "x", "assets": [], "skipped": []}', encoding="utf-8")
    try:
        assert client.post("/sizing-tool/api/rollup", json={"run_id": "not-a-run-id"}).status_code == 404
    finally:
        (folder / "run.json").unlink()
        folder.rmdir()


def test_growth_is_clamped(client):
    big = client.post("/sizing-tool/api/analyze", data={"demo": "topology:edge", "growth": "99999"}).get_json()
    assert big["rollup"]["growth"] == 500
    bad = client.post("/sizing-tool/api/analyze", data={"demo": "topology:edge", "growth": "abc"}).get_json()
    assert bad["rollup"]["growth"] == 25


def test_links_route_gives_https_vendor_documentation(client):
    links = client.get("/sizing-tool/api/links").get_json()["links"]
    assert links and all(l["url"].startswith("https://") for l in links)
    assert {"Cisco", "Huawei", "Aruba", "Palo Alto", "Fortinet", "F5"} <= {l["vendor"] for l in links}


# ------------------------------------------------------------------------------------------------------------------------------- Excel safety

def test_workbook_neutralises_formula_text(client):
    from features.sizing_tool.excel import to_xlsx
    a = _asset(hostname="=HYPERLINK(\"http://example.test\")", model="+SUM(A1)")
    a["id"] = "d1"
    a["licences"].append({"name": "@cmd", "state": "-1+1", "expires": "", "detail": ""})
    book = load_workbook(io.BytesIO(to_xlsx([a], build([a], 25), "t")))
    for sheet in book:
        for row in sheet.iter_rows():
            for cell in row:
                assert not (isinstance(cell.value, str) and cell.value[:1] in ("=", "+", "@") and cell.data_type == "f"), (sheet.title, cell.coordinate)
