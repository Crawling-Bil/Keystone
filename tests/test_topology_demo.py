"""The demo captures behind the Topology Builder's "Load demo data" buttons: both sets are served, build cleanly and tell the story they promise.

The files are invented (documentation domain, 10.20.0.0/24); the tests also make sure nothing else can slip into them.
"""

from __future__ import annotations

import io
import re

import pytest

from features.topology import demo, routes


@pytest.fixture()
def client(tmp_path, monkeypatch):
    from app import create_app
    monkeypatch.setattr(routes, "EXPORT_DIR", tmp_path)
    app = create_app()
    app.config["TESTING"] = True
    return app.test_client()


def _files(client, set_id: str) -> list[tuple[io.BytesIO, str]]:
    sets = {s["id"]: s for s in client.get("/topology/api/demo").get_json()["sets"]}
    return [(io.BytesIO(client.get(f"/topology/api/demo/{set_id}/{f['name']}").data), f["name"]) for f in sets[set_id]["files"]]


def _build(client, set_id: str, name: str) -> dict:
    body = client.post("/topology/api/build", data={"files": _files(client, set_id), "group": "none", "name": name}, content_type="multipart/form-data").get_json()
    assert body["ok"], body
    return body


def test_the_page_has_the_demo_row_and_its_script(client):
    page = client.get("/topology").get_data(as_text=True)
    assert 'data-role="demo"' in page and "topology-demo.js" in page


def test_all_sets_are_listed_with_their_files(client):
    sets = {s["id"]: s for s in client.get("/topology/api/demo").get_json()["sets"]}
    assert set(sets) == {"before", "after", "edge", "multisite"} and len(sets["multisite"]["files"]) == 44 and sets["multisite"]["group"] == "auto"
    assert [f["name"] for f in sets["edge"]["files"]] == ["DC1-CORE1.txt", "DC1-CORE2.txt", "DC1-FW1.txt", "DC1-LB1.txt"]
    assert [f["name"] for f in sets["before"]["files"]] == ["DC1-ACC1.txt", "DC1-ACC2.txt", "DC1-ACC3.txt", "DC1-ACC4.txt", "DC1-CORE1.txt", "DC1-CORE2.txt"]
    assert len(sets["after"]["files"]) == 7 and "DC1-ACC5.txt" in [f["name"] for f in sets["after"]["files"]]
    assert all(f["size"] > 500 for s in sets.values() for f in s["files"])


def test_only_listed_files_can_be_fetched(client):
    assert client.get("/topology/api/demo/before/DC1-CORE1.txt").status_code == 200
    for path in ("/topology/api/demo/before/DC1-ACC5.txt", "/topology/api/demo/nope/DC1-CORE1.txt", "/topology/api/demo/before/..%2Fdemo.py",
                 "/topology/api/demo/%2E%2E/demo.py", "/topology/api/demo/before/DC1-CORE1.txt/x", "/topology/api/demo/before/.."):
        assert client.get(path).status_code in (404, 308, 400), path
    assert demo.read_file("before", "../../demo.py") is None and demo.read_file("before", "../demo.py") is None and demo.read_file("../", "demo.py") is None and demo.read_file(None, None) is None


def test_the_first_set_builds_a_clean_vpc_data_center(client):
    body = _build(client, "before", "Demo before")
    summary = body["summary"]
    assert summary["captured"] == 6 and summary["seen_only"] == 1 and summary["vpc_pairs"] == 1
    assert summary["conflicts"] == 0 and summary["skipped"] == 0 and summary["links"] == 12


def test_the_second_set_differs_by_exactly_the_planned_changes(client):
    before, after = _build(client, "before", "Demo before"), _build(client, "after", "Demo after")
    diff = client.post("/topology/api/diff", data={"before_id": before["export_id"], "after_id": after["export_id"]}).get_json()
    rows = {(r["area"], r["change"], r["item"], r["field"]) for r in diff["rows"]}
    assert ("Devices", "added", "DC1-ACC5", "") in rows
    assert ("Devices", "changed", "DC1-ACC2", "management_ip") in rows
    assert ("Links", "removed", "DC1-ACC3 Gi1/0/48 - DC1-CORE2 Eth1/3", "") in rows
    assert any(r["area"] == "Findings" and r["change"] == "added" and r["item"].startswith("TOPO-035") for r in diff["rows"])      # the pulled uplink leaves ACC3 single-homed
    assert diff["summary"]["differences"] == 7 and diff["summary"]["attention"] == 3


def test_the_third_set_draws_a_firewall_and_an_f5_on_the_core_pair(client):
    body = _build(client, "edge", "Demo edge")
    summary = body["summary"]
    assert summary["captured"] == 4 and summary["seen_only"] == 0 and summary["vpc_pairs"] == 1 and summary["conflicts"] == 0 and summary["skipped"] == 0
    assert summary["links"] == 6 and summary["connections"] == 5
    roles = {d["device"]: (d["vendor"], d["role"]) for d in body["devices"]}
    assert roles["DC1-FW1"] == ("Fortinet", "firewall") and roles["DC1-LB1"] == ("F5", "loadbalancer")
    links = {(l["device_a"], l["port_a"], l["device_b"], l["port_b"]) for l in body["links"]}
    assert ("DC1-CORE1", "Eth1/10", "DC1-FW1", "port1") in links and ("DC1-CORE2", "Eth1/11", "DC1-LB1", "1.2") in links
    assert {f["id"] for f in body["findings"]} == {"TOPO-001", "TOPO-008"} and {f["severity"] for f in body["findings"]} == {"info"}      # nothing to fix: the set is for looking at the drawing
    assert "F5 map · DC1-LB1" in [p["name"] for p in body["pages"]]


def test_the_demo_files_hold_only_invented_values():
    for path in sorted(demo.DEMO_DIR.glob("*/*.txt")):
        if path.parent.name == "multisite":
            continue                                       # has its own, wider check below
        text = path.read_text(encoding="utf-8")
        assert set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)) <= {f"10.20.{m}.{n}" for m in (0, 10, 20, 30, 200) for n in range(0, 256)} | {"255.255.255.0", "255.255.255.252", "255.255.255.255", "0.0.0.0", "15.1.8.2"}, path.name
        for host in set(re.findall(r"\b([A-Za-z][\w-]*)\.dc1\.example\.test", text)):
            assert host.startswith("DC1-"), path.name
        assert not re.search(r"password|secret|snmp-server community|enable ", text, re.I), path.name


def test_the_multisite_files_hold_only_invented_values():
    import ipaddress
    allowed = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.31.100.0/22", "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "198.18.0.0/15", "198.19.10.0/24", "169.254.0.0/16")]
    masks = {"255.255.255.0", "255.255.255.252", "255.255.255.248", "255.255.255.192", "255.255.255.255", "255.255.0.0", "255.0.0.0", "0.0.0.0", "0.0.0.255", "0.0.0.63", "0.0.0.7",
             "255.255.255.128", "255.255.255.254", "255.255.255.240", "255.255.255.224", "255.255.255.0"}
    files = sorted((demo.DEMO_DIR / "multisite").glob("*.txt"))
    assert len(files) == 44
    for path in files:
        text = path.read_text(encoding="utf-8")
        for found in set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)):
            assert found in masks or any(ipaddress.ip_address(found) in net for net in allowed), (path.name, found)
        assert not re.search(r"password|secret|cipher|snmp-(?:server|agent) community|\bkey\b", text, re.I), path.name
        for host in set(re.findall(r"\b([A-Za-z][\w-]*)\.demo\.example\.test", text)):
            assert re.match(r"(HQ|JKT|SBY|YOG|MKS|MED|BAL)-", host), (path.name, host)


def test_the_fourth_set_is_a_head_quarter_with_six_branches(client):
    sets = {s["id"]: s for s in client.get("/topology/api/demo").get_json()["sets"]}
    names = [f["name"] for f in sets["multisite"]["files"]]
    assert sum(n.startswith("HQ-") for n in names) == 20
    assert all(sum(n.startswith(f"{code}-") for n in names) == 4 for code in ("JKT", "SBY", "YOG", "MKS", "MED", "BAL"))
    files = _files(client, "multisite")
    body = client.post("/topology/api/build", data={"files": files, "group": "auto", "name": "Demo multisite"}, content_type="multipart/form-data").get_json()
    assert body["ok"], body
    summary = body["summary"]
    assert summary["captured"] == 44 and summary["skipped"] == 0 and summary["conflicts"] == 0 and summary["vpc_pairs"] == 4
    assert summary["confirmed"] == 64 and summary["connections"] and summary["hosts"] >= 60
    vendors = {d["vendor"] for d in body["devices"] if d["device"] in set(n[:-4] for n in names)}
    assert {"Cisco", "Fortinet", "Palo Alto Networks", "Aruba", "Huawei"} <= vendors
    pages = [p["name"] for p in body["pages"]]
    assert {"Overview", "HQ", "JKT", "SBY", "YOG", "MKS", "MED", "BAL"} <= set(pages)
    assert {f["id"] for f in body["findings"]} <= {"TOPO-008", "TOPO-027", "TOPO-043"} and not any(f["severity"] in ("medium", "high") for f in body["findings"])
    assert len(body["l3_links"]) == 53 and all(l["state"] == "working" for l in body["l3_links"]) and body["l3_unresolved"] == []
    clouds = {l["device_b"] for l in body["l3_links"] if "provider" in l["kind"].lower()}
    assert {"MPLS · Telkom", "MPLS · Lintasarta", "MPLS · Icon+", "MPLS · Trigatra"} <= clouds


# ---- the baseline banner: the newest pinned run is compared with every new build ---------------------------------------------------------------

def _pin(client, run_id: str) -> None:
    assert client.post(f"/topology/api/history/{run_id}/pin", json={"pinned": True}).get_json()["ok"]


def test_without_a_pinned_run_there_is_no_baseline(client):
    built = _build(client, "before", "Today")
    assert client.get(f"/topology/api/baseline/{built['export_id']}").get_json() == {"ok": True, "baseline": None}
    later = _build(client, "after", "Later")                            # an older run that is not pinned is never the baseline
    assert client.get(f"/topology/api/baseline/{later['export_id']}").get_json() == {"ok": True, "baseline": None}
    assert not any(r["baseline"] for r in client.get("/topology/api/history").get_json()["runs"])


def test_a_new_build_is_compared_with_the_pinned_baseline(client):
    before = _build(client, "before", "Today")
    _pin(client, before["export_id"])
    after = _build(client, "after", "Changed")
    answer = client.get(f"/topology/api/baseline/{after['export_id']}").get_json()
    assert answer["ok"] and answer["baseline"]["id"] == before["export_id"] and answer["baseline"]["name"] == "Today"
    assert answer["differences"] == 7 and answer["attention"] == 3
    same = _build(client, "before", "Again")
    assert client.get(f"/topology/api/baseline/{same['export_id']}").get_json()["differences"] == 0


def test_the_newest_pinned_run_is_the_baseline_and_a_run_is_never_its_own(client):
    import os
    first, second = _build(client, "before", "First"), _build(client, "after", "Second")
    os.utime(routes.EXPORT_DIR / first["export_id"], (1, 1))            # the folder time does not decide which is newest: the build time does
    _pin(client, first["export_id"]); _pin(client, second["export_id"])
    runs = {r["id"]: r for r in client.get("/topology/api/history").get_json()["runs"]}
    assert [r["baseline"] for r in sorted(runs.values(), key=lambda r: r["built_seconds"], reverse=True)].count(True) == 1
    newest = max(runs.values(), key=lambda r: (r["built_seconds"], r["id"]))
    assert newest["baseline"] is True
    assert client.get(f"/topology/api/baseline/{newest['id']}").get_json()["baseline"]["id"] != newest["id"]


def test_the_baseline_endpoint_checks_the_id(client):
    assert client.get("/topology/api/baseline/not-an-id").status_code == 404
    assert client.get(f"/topology/api/baseline/{'0' * 32}").get_json() == {"ok": True, "baseline": None}


def test_the_page_has_the_banner_and_its_script(client):
    page = client.get("/topology").get_data(as_text=True)
    assert 'data-role="baseline"' in page and "topology-baseline.js" in page
