"""Sizing Tool: router logical interfaces, the one-page summary, the candidate library and the side-by-side comparison.  Invented data only."""

from __future__ import annotations

import io
import json

import pytest

from app import create_app
from features.sizing_tool import candidates, summary
from features.sizing_tool.service import read_texts

ROUTER = """RTR1#show version
Cisco IOS XE Software, Version 17.06.03
cisco ISR4331/K9 (1RU) processor
Processor board ID FDO12345678

RTR1#show ip interface brief
Interface              IP-Address      OK? Method Status                Protocol
GigabitEthernet0/0/0   10.0.0.1        YES manual up                    up
GigabitEthernet0/0/1   unassigned      YES unset  administratively down down
Loopback0              10.255.0.1      YES manual up                    up
Loopback1              10.255.1.1      YES manual up                    up
Tunnel10               172.16.0.1      YES manual up                    up
Port-channel1          unassigned      YES unset  up                    up
Vlan10                 10.10.0.1       YES manual up                    up
"""


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setenv("NES_DISABLE_AUTH", "1")
    app = create_app()
    app.testing = True
    return app.test_client()


def _run(client):
    return client.post("/sizing-tool/api/analyze", data={"demo": "campus", "name": "Test <b>x</b>"}).get_json()["run_id"]


# ----------------------------------------------------------------------------------------------------------------------- router logical interfaces

def test_router_loopbacks_tunnels_port_channels_and_svis_are_counted_from_the_interface_brief():
    found, _ = read_texts([("r.txt", ROUTER)])
    cap = found[0]["capacity"]
    assert cap["Physical interfaces"] == 2 and cap["Logical interfaces (loopback, tunnel, BDI)"] == 5
    assert (cap["Logical: loopbacks"], cap["Logical: tunnels"], cap["Logical: port-channels"], cap["Logical: SVIs"]) == (2, 1, 1, 1)


# ----------------------------------------------------------------------------------------------------------------------- summary

def test_the_summary_is_one_self_contained_page_with_the_name_escaped(client):
    response = client.post("/sizing-tool/api/summary", json={"run_id": _run(client), "growth": 25})
    html = response.data.decode()
    assert response.status_code == 200 and "keystone-Test-b-x-b-summary.html" in response.headers["Content-Disposition"]
    assert "<script" not in html and "http://" not in html and "https://" not in html
    assert "Test &lt;b&gt;x&lt;/b&gt;" in html and "<b>x</b>" not in html
    assert "What was found" in html and "What needs a decision" in html and "What is still needed" in html


def test_the_summary_refuses_a_bad_run_id(client):
    assert client.post("/sizing-tool/api/summary", json={"run_id": "../x"}).status_code == 404


# ----------------------------------------------------------------------------------------------------------------------- library

def test_library_round_trips_and_drops_what_is_not_valid():
    lib = [{"name": "Model A", "vendor": "X", "device_type": "firewall", "capacity": {"Firewall policies": 5000, "VPN tunnels": 0}},
           {"name": "", "capacity": {"VPN tunnels": 5}}, {"name": "No capacity", "capacity": {}}, {"name": "Model A", "device_type": "firewall", "capacity": {"VPN tunnels": 9}},
           {"name": "Bad number", "capacity": {"x": "nine"}}, "text", {"name": "Odd type", "device_type": "toaster", "capacity": {"Ports 1G": 24}}]
    clean = candidates.clean_library(lib)
    assert [c["name"] for c in clean] == ["Model A", "Odd type"] and clean[0]["capacity"] == {"Firewall policies": 5000.0} and clean[1]["device_type"] == ""
    assert candidates.loads(candidates.dumps(clean)) == clean


@pytest.mark.parametrize("data, sentence", [(b"not json", "not valid JSON"), (b'{"format": "other"}', "not a Keystone candidate library"),
                                            (json.dumps({"format": candidates.FORMAT, "version": 99, "candidates": []}).encode(), "newer version"), (b"\xff\xfe\x00", "not text")])
def test_a_file_that_is_not_a_library_is_refused_in_one_sentence(data, sentence):
    with pytest.raises(candidates.LibraryError, match=sentence):
        candidates.loads(data)


def test_library_routes_export_and_import(client):
    lib = [{"name": "Model A", "device_type": "switch", "capacity": {"Ports 1G": 48}}]
    out = client.post("/sizing-tool/api/candidates/export", json={"library": lib})
    assert out.status_code == 200 and "keystone-candidates.json" in out.headers["Content-Disposition"]
    back = client.post("/sizing-tool/api/candidates/import", data={"file": (io.BytesIO(out.data), "lib.json")}, content_type="multipart/form-data").get_json()
    assert back["ok"] and back["library"][0]["name"] == "Model A"
    bad = client.post("/sizing-tool/api/candidates/import", data={"file": (io.BytesIO(b"{}"), "lib.json")}, content_type="multipart/form-data")
    assert bad.status_code == 400 and "not a Keystone candidate library" in bad.get_json()["error"]
    assert client.post("/sizing-tool/api/candidates/import", data={}).status_code == 400


# ----------------------------------------------------------------------------------------------------------------------- compare two candidates

def test_two_candidates_are_compared_on_units_and_fullness(client):
    run_id = _run(client)
    first = client.post("/sizing-tool/api/rollup", json={"run_id": run_id, "options": {"growth": 0}}).get_json()
    plan = next(p for p in first["rollup"]["plan"] if p["device_type"] == "switch")
    label = next(r["label"] for r in plan["rows"] if r["scales"] and r["label"].startswith("Ports "))
    big, small = {"name": "Big", "capacity": {label: 1000}}, {"name": "Small", "capacity": {label: 5}}
    answer = client.post("/sizing-tool/api/candidates/compare", json={"run_id": run_id, "options": {"growth": 0}, "group": plan["key"], "candidates": [big, small]}).get_json()
    cmp = answer["comparison"]
    assert answer["ok"] and cmp["a"]["units"] == 1 and cmp["b"]["units"] > 1 and cmp["fewer_units"] == "Big" and cmp["names"] == ["Big", "Small"]
    row = next(r for r in cmp["rows"] if r["label"] == label)
    assert row["a"]["used_pct"] is not None and row["b"]["used_pct"] is not None and row["a"]["used_pct"] < row["b"]["used_pct"]


@pytest.mark.parametrize("body", [{"group": "switch", "candidates": [{"name": "A", "capacity": {"x": 1}}]}, {"group": "", "candidates": [{"name": "A", "capacity": {"x": 1}}, {"name": "B", "capacity": {"x": 1}}]},
                                  {"group": "switch", "candidates": [{"name": "A", "capacity": {}}, {"name": "B", "capacity": {"x": 1}}]}])
def test_compare_asks_for_a_group_and_two_valid_candidates(client, body):
    assert client.post("/sizing-tool/api/candidates/compare", json={"run_id": _run(client), **body}).status_code == 400


def test_compare_names_a_group_that_is_not_in_the_run(client):
    two = [{"name": "A", "capacity": {"Ports 1G": 10}}, {"name": "B", "capacity": {"Ports 1G": 20}}]
    assert client.post("/sizing-tool/api/candidates/compare", json={"run_id": _run(client), "group": "firewall|nope", "candidates": two}).status_code == 404
