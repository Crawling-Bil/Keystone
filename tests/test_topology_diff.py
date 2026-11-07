"""Compare two topology runs: what was added, removed, re-cabled or changed, and what needs attention. Synthetic data only."""

from __future__ import annotations

import io
import json
import sys
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from features.topology.diff import DiffError, compare_runs, load_run, parse_speed  # noqa: E402


def device(name, **fields):
    return {"device": name, "captured": "yes", "role": "switch", "vendor": "cisco", "model": "N9K-C93180YC-EX", "os_version": "9.3(5)",
            "management_ip": "10.0.0.1", "serial": "SN1", "stack_members": "", "vpc_domain": "", "vpc_role": "", **fields}


def link(a, pa, b, pb, **fields):
    return {"device_a": a, "port_a": pa, "device_b": b, "port_b": pb, "state": "confirmed", "protocols": "CDP/LLDP", "bundle_a": "", "bundle_b": "",
            "kind": "link", "vpc_id": "", "speed_a": "10G", "speed_b": "10G", "rated_a": "10G", "rated_b": "10G", "port_state_a": "up", "port_state_b": "up",
            "duplex_a": "full", "duplex_b": "full", "subnet": "", "native_vlan": "1", "duplex": "", "note": "", **fields}


def run(devices=(), links=(), hosts=(), findings=(), behind=()):
    return {"devices": list(devices), "links": list(links), "hosts": list(hosts), "findings": list(findings), "behind": list(behind)}


def rows_of(result, area=None, change=None):
    return [r for r in result["rows"] if (area is None or r["area"] == area) and (change is None or r["change"] == change)]


BASE_LINKS = [link("AGG1", "Eth1/1", "ACC1", "Te1/1/1"), link("AGG1", "Eth1/2", "ACC2", "Te1/1/1")]
BASE = run([device("AGG1"), device("ACC1", role="access"), device("ACC2", role="access")], BASE_LINKS)


# ---- the same run -------------------------------------------------------------------------------------------------

def test_a_run_compared_with_itself_has_no_difference():
    result = compare_runs(BASE, BASE)
    assert result["rows"] == [] and result["summary"]["verdict"] == "identical"
    assert result["summary"]["differences"] == 0 and result["summary"]["areas"]["Links"]["same"] == 2


# ---- devices ------------------------------------------------------------------------------------------------------

def test_added_and_removed_devices():
    after = run([device("AGG1"), device("ACC1", role="access"), device("ACC3", role="access", model="C9300-48P")], BASE_LINKS[:1])
    result = compare_runs(BASE, after)
    assert [r["item"] for r in rows_of(result, "Devices", "added")] == ["ACC3"]
    removed = rows_of(result, "Devices", "removed")
    assert [r["item"] for r in removed] == ["ACC2"] and removed[0]["impact"] == "attention"
    assert rows_of(result, "Devices", "added")[0]["impact"] == "info"


def test_a_changed_field_is_reported_with_both_values():
    after = run([device("AGG1", os_version="10.2(3)"), device("ACC1", role="access"), device("ACC2", role="access")], BASE_LINKS)
    row = rows_of(compare_runs(BASE, after), "Devices", "changed")[0]
    assert (row["item"], row["field"], row["before"], row["after"], row["impact"]) == ("AGG1", "os_version", "9.3(5)", "10.2(3)", "info")


def test_a_new_management_address_and_a_vpc_role_change_need_attention():
    before = run([device("AGG1", vpc_domain="10", vpc_role="primary")])
    after = run([device("AGG1", management_ip="10.9.9.9", vpc_domain="10", vpc_role="secondary")])
    changed = {r["field"]: r for r in rows_of(compare_runs(before, after), "Devices", "changed")}
    assert changed["management_ip"]["impact"] == "attention" and changed["vpc_role"]["impact"] == "attention"


def test_a_value_the_first_run_did_not_know_is_only_information():
    before = run([device("AGG1", management_ip="")])
    after = run([device("AGG1", management_ip="10.0.0.1")])
    row = rows_of(compare_runs(before, after), "Devices", "changed")[0]
    assert row["impact"] == "info"


def test_a_device_that_is_no_longer_captured_needs_attention_and_one_that_is_now_captured_does_not():
    seen = device("ACC1", captured="no (seen by neighbors)")
    lost = rows_of(compare_runs(run([device("ACC1")]), run([seen])), "Devices", "changed")[0]
    gained = rows_of(compare_runs(run([seen]), run([device("ACC1")])), "Devices", "changed")[0]
    assert (lost["field"], lost["impact"]) == ("captured", "attention") and gained["impact"] == "info"


def test_lost_capture_commands_are_listed():
    before = run([device("AGG1", has_mac="yes", has_lldp="yes")])
    after = run([device("AGG1", has_mac="no", has_lldp="yes")])
    row = rows_of(compare_runs(before, after), "Devices", "changed")[0]
    assert row["field"] == "captured commands" and row["before"] == "-mac" and "missing" in row["why"]


def test_captured_in_both_is_counted():
    after = run([device("AGG1"), device("ACC1", captured="no (seen by neighbors)")])
    assert compare_runs(BASE, after)["summary"]["captured_in_both"] == 1


# ---- links --------------------------------------------------------------------------------------------------------

def test_the_order_of_the_two_ends_does_not_matter_and_speed_follows_its_end():
    flipped = run(BASE["devices"], [link("ACC1", "Te1/1/1", "AGG1", "Eth1/1"), BASE_LINKS[1]])
    assert compare_runs(BASE, flipped)["rows"] == []
    flipped_slow = run(BASE["devices"], [link("ACC1", "Te1/1/1", "AGG1", "Eth1/1", speed_a="1G", speed_b="10G"), BASE_LINKS[1]])
    rows = rows_of(compare_runs(BASE, flipped_slow), "Links", "changed")
    assert len(rows) == 1 and rows[0]["field"].startswith("speed at ACC1 Te1/1/1") and (rows[0]["before"], rows[0]["after"]) == ("10G", "1G")


def test_a_link_that_slows_down_needs_attention_and_one_that_speeds_up_does_not():
    slow = run(BASE["devices"], [link("AGG1", "Eth1/1", "ACC1", "Te1/1/1", speed_a="1G", speed_b="1G"), BASE_LINKS[1]])
    fast_before = run(BASE["devices"], [link("AGG1", "Eth1/1", "ACC1", "Te1/1/1", speed_a="1G", speed_b="1G"), BASE_LINKS[1]])
    down = rows_of(compare_runs(BASE, slow), "Links", "changed")
    up = rows_of(compare_runs(fast_before, BASE), "Links", "changed")
    assert down and all(r["impact"] == "attention" for r in down) and "dropped" in down[0]["why"]
    assert up and all(r["impact"] == "info" for r in up)


def test_duplex_native_vlan_and_bundle_changes_need_attention():
    after = run(BASE["devices"], [link("AGG1", "Eth1/1", "ACC1", "Te1/1/1", duplex_a="half", native_vlan="99", bundle_a="Po1", bundle_b="Po1"), BASE_LINKS[1]])
    result = compare_runs(BASE, after)
    by_field = {r["field"]: r for r in rows_of(result, "Links", "changed")}
    assert by_field["native_vlan"]["impact"] == "attention"
    assert by_field["duplex at AGG1 Eth1/1"]["impact"] == "attention"
    assert by_field["bundle at AGG1 Eth1/1"]["impact"] == "info"       # a bundle that appears where there was none is a better capture, not a loss


def test_a_port_that_leaves_its_bundle_needs_attention():
    before = run(BASE["devices"], [link("AGG1", "Eth1/1", "ACC1", "Te1/1/1", bundle_a="Po1"), BASE_LINKS[1]])
    row = rows_of(compare_runs(before, BASE), "Links", "changed")[0]
    assert row["impact"] == "attention" and "port-channel" in row["why"]


def test_a_port_that_goes_down_needs_attention():
    after = run(BASE["devices"], [link("AGG1", "Eth1/1", "ACC1", "Te1/1/1", port_state_b="down"), BASE_LINKS[1]])
    row = rows_of(compare_runs(BASE, after), "Links", "changed")[0]
    assert row["impact"] == "attention" and row["field"] == "port state at ACC1 Te1/1/1"


def test_a_link_seen_from_fewer_ends_needs_attention_and_one_confirmed_later_does_not():
    single = run(BASE["devices"], [link("AGG1", "Eth1/1", "ACC1", "Te1/1/1", state="single"), BASE_LINKS[1]])
    worse = rows_of(compare_runs(BASE, single), "Links", "changed")[0]
    better = rows_of(compare_runs(single, BASE), "Links", "changed")[0]
    assert (worse["field"], worse["before"], worse["after"], worse["impact"]) == ("state", "confirmed", "single", "attention")
    assert (better["before"], better["after"], better["impact"]) == ("single", "confirmed", "info")
    conflict = run(BASE["devices"], [link("AGG1", "Eth1/1", "ACC1", "Te1/1/1", state="conflict"), BASE_LINKS[1]])
    assert rows_of(compare_runs(single, conflict), "Links", "changed")[0]["impact"] == "attention"


def test_a_finding_that_keeps_its_id_while_its_devices_change_is_one_row():
    result = compare_runs(run(findings=[finding("TOPO-004", "info", "A", "B", title="2 devices not captured")]),
                          run(findings=[finding("TOPO-004", "info", "B", title="1 device not captured")]))
    rows = rows_of(result, "Findings")
    assert len(rows) == 1 and rows[0]["change"] == "changed" and (rows[0]["before"], rows[0]["after"]) == ("A, B", "B")
    assert result["summary"]["areas"]["Findings"]["changed"] == 1 and result["summary"]["areas"]["Findings"]["added"] == 0


def test_added_and_removed_links():
    after = run(BASE["devices"], [BASE_LINKS[0], link("AGG1", "Eth1/3", "ACC3", "Te1/1/2")])
    result = compare_runs(BASE, after)
    assert [r["item"] for r in rows_of(result, "Links", "removed")] == ["ACC2 Te1/1/1 - AGG1 Eth1/2"]          # the ends are written in alphabetical order, whichever way the run had them
    assert rows_of(result, "Links", "removed")[0]["impact"] == "attention"
    assert [r["item"] for r in rows_of(result, "Links", "added")] == ["ACC3 Te1/1/2 - AGG1 Eth1/3"]


def test_a_cable_moved_to_another_port_of_the_same_device_is_one_row():
    after = run(BASE["devices"], [BASE_LINKS[0], link("AGG1", "Eth1/2", "ACC2", "Te1/1/9")])
    result = compare_runs(BASE, after)
    moved = rows_of(result, "Links", "moved")
    assert len(moved) == 1 and moved[0]["impact"] == "attention" and "Te1/1/9" in moved[0]["after"] and "Te1/1/1" in moved[0]["before"]
    assert not rows_of(result, "Links", "added") and not rows_of(result, "Links", "removed")


def test_a_link_between_the_same_two_devices_on_other_ports_at_both_ends_is_moved():
    after = run(BASE["devices"], [BASE_LINKS[0], link("AGG1", "Eth1/20", "ACC2", "Te1/1/9")])
    assert len(rows_of(compare_runs(BASE, after), "Links", "moved")) == 1


def test_two_unrelated_changes_are_not_called_a_move():
    after = run(BASE["devices"], [link("AGG1", "Eth1/9", "ACC3", "Te1/1/1"), link("AGG2", "Eth1/9", "ACC1", "Te1/1/1")])
    result = compare_runs(BASE, after)
    assert not rows_of(result, "Links", "moved")
    assert len(rows_of(result, "Links", "removed")) == 2 and len(rows_of(result, "Links", "added")) == 2


def test_parallel_links_in_one_bundle_are_matched_one_by_one():
    parallel = [link("AGG1", "Eth1/1", "ACC1", "Te1/1/1", bundle_a="Po1", bundle_b="Po1"), link("AGG1", "Eth1/2", "ACC1", "Te1/1/2", bundle_a="Po1", bundle_b="Po1")]
    before = run(BASE["devices"], parallel)
    after = run(BASE["devices"], parallel[:1])
    result = compare_runs(before, after)
    assert [r["item"] for r in rows_of(result, "Links", "removed")] == ["ACC1 Te1/1/2 - AGG1 Eth1/2"]


# ---- findings, hosts, behind --------------------------------------------------------------------------------------

def finding(code, severity, *devices, title="t"):
    return {"id": code, "severity": severity, "title": title, "detail": "", "devices": list(devices), "recommendation": "", "reference": ""}


def test_new_and_resolved_findings():
    before = run(findings=[finding("TOPO-001", "info", "A"), finding("TOPO-002", "medium", "B")])
    after = run(findings=[finding("TOPO-001", "info", "A"), finding("TOPO-030", "medium", "C"), finding("TOPO-031", "low", "D")])
    result = compare_runs(before, after)
    added = {r["item"].split()[0]: r for r in rows_of(result, "Findings", "added")}
    assert added["TOPO-030"]["impact"] == "attention" and added["TOPO-031"]["impact"] == "info"
    assert [r["item"].split()[0] for r in rows_of(result, "Findings", "resolved")] == ["TOPO-002"]
    assert result["summary"]["areas"]["Findings"]["same"] == 1


def test_a_finding_that_becomes_worse_needs_attention():
    result = compare_runs(run(findings=[finding("TOPO-001", "info", "A")]), run(findings=[finding("TOPO-001", "medium", "A")]))
    row = rows_of(result, "Findings", "changed")[0]
    assert (row["before"], row["after"], row["impact"]) == ("info", "medium", "attention")


def test_a_finding_id_that_does_not_pair_one_to_one_is_reported_as_new_and_resolved():
    result = compare_runs(run(findings=[finding("TOPO-001", "info", "A")]), run(findings=[finding("TOPO-001", "info", "B"), finding("TOPO-001", "info", "C")]))
    assert len(rows_of(result, "Findings", "added")) == 2 and len(rows_of(result, "Findings", "resolved")) == 1


def host(mac, device_name, port, ip="", vlan="10"):
    return {"mac": mac, "ip_address": ip, "vlan": vlan, "device": device_name, "port": port, "behind": "", "kind": "", "note": ""}


def test_hosts_that_move_appear_disappear_or_change_address():
    before = run(hosts=[host("aaaa.bbbb.0001", "ACC1", "Gi1/0/1", "10.0.10.5"), host("aaaa.bbbb.0002", "ACC1", "Gi1/0/2"), host("aaaa.bbbb.0003", "ACC1", "Gi1/0/3", "10.0.10.7")])
    after = run(hosts=[host("AAAA.BBBB.0001", "ACC2", "Gi1/0/9", "10.0.10.5"), host("aaaa.bbbb.0003", "ACC1", "Gi1/0/3", "10.0.10.99"), host("aaaa.bbbb.0004", "ACC1", "Gi1/0/4")])
    result = compare_runs(before, after)
    assert [r["item"] for r in rows_of(result, "Hosts", "moved")] == ["aaaa.bbbb.0001"]
    assert [r["item"] for r in rows_of(result, "Hosts", "removed")] == ["aaaa.bbbb.0002"]
    assert [r["item"] for r in rows_of(result, "Hosts", "added")] == ["aaaa.bbbb.0004"]
    changed = rows_of(result, "Hosts", "changed")
    assert len(changed) == 1 and (changed[0]["field"], changed[0]["before"], changed[0]["after"]) == ("ip address", "10.0.10.7", "10.0.10.99")
    assert all(r["impact"] == "info" for r in rows_of(result, "Hosts"))


def test_an_address_learned_for_the_first_time_is_not_a_change():
    result = compare_runs(run(hosts=[host("aaaa.bbbb.0001", "ACC1", "Gi1/0/1")]), run(hosts=[host("aaaa.bbbb.0001", "ACC1", "Gi1/0/1", "10.0.10.5")]))
    assert result["rows"] == []


def test_behind_device_counts():
    def row(macs, vlans="10"):
        return {"behind": "UCS-FI-A", "switch": "AGG1", "port": "Po5", "mac_addresses": macs, "vlans": vlans}
    result = compare_runs(run(behind=[row(40)]), run(behind=[row(55, "10,20")]))
    assert [(r["field"], r["before"], r["after"]) for r in rows_of(result, "Behind devices", "changed")] == [("mac addresses", "40", "55"), ("vlans", "10", "10,20")]
    assert rows_of(compare_runs(run(behind=[row(40)]), run()), "Behind devices", "removed")


# ---- the whole result ---------------------------------------------------------------------------------------------

def test_rows_are_ordered_by_area_and_attention_first():
    after = run([device("AGG1", os_version="10.2(3)"), device("ACC1", role="access")], [BASE_LINKS[0]])
    rows = compare_runs(BASE, after)["rows"]
    areas = [r["area"] for r in rows]
    assert areas == sorted(areas, key=["Devices", "Links", "Findings", "Hosts", "Behind devices"].index)
    devices = [r for r in rows if r["area"] == "Devices"]
    assert devices[0]["impact"] == "attention" and devices[-1]["impact"] == "info"


def test_summary_counts_and_verdict():
    after = run([device("AGG1", os_version="10.2(3)"), device("ACC1", role="access"), device("ACC2", role="access")], BASE_LINKS)
    summary = compare_runs(BASE, after)["summary"]
    assert summary["verdict"] == "changed" and summary["attention"] == 0 and summary["differences"] == 1
    assert summary["before"]["devices"] == 3 and summary["after"]["links"] == 2
    attention = compare_runs(BASE, run(BASE["devices"], BASE_LINKS[:1]))["summary"]
    assert attention["verdict"] == "attention" and attention["attention"] == 1


def test_a_very_long_area_is_cut_and_says_so(monkeypatch):
    from features.topology import diff
    monkeypatch.setattr(diff, "MAX_ROWS_PER_AREA", 5)
    after = run(hosts=[host(f"aaaa.bbbb.{n:04x}", "ACC1", "Gi1/0/1") for n in range(9)])
    result = compare_runs(run(), after)
    assert len(rows_of(result, "Hosts")) == 5 and result["summary"]["truncated"] == {"Hosts": 4}
    assert result["summary"]["areas"]["Hosts"]["added"] == 9


def test_parse_speed():
    assert [parse_speed(t) for t in ("10G", "1G", "100M", "2500M", "25 Gbps", "", "fast", None)] == [10000, 1000, 100, 2500, 25000, 0, 0, 0]


# ---- reading a file -----------------------------------------------------------------------------------------------

def test_load_run_reads_json_and_a_pack_zip():
    data = json.dumps(BASE).encode()
    assert load_run(data)["devices"][0]["device"] == "AGG1"
    assert load_run(b"\xef\xbb\xbf" + data)["links"]                       # with a byte order mark
    pack = io.BytesIO()
    with zipfile.ZipFile(pack, "w") as z:
        z.writestr("README.txt", "x")
        z.writestr("topology.json", data)
    assert len(load_run(pack.getvalue())["devices"]) == 3


@pytest.mark.parametrize("data,words", [(b"not json", "readable JSON"), (b"[1, 2]", "devices and links"), (b'{"devices": 1, "links": []}', "devices and links"),
                                        (b"PK\x03\x04junk", "ZIP")])
def test_load_run_refuses_what_is_not_a_run(data, words):
    with pytest.raises(DiffError) as error:
        load_run(data)
    assert words in str(error.value)


def test_a_zip_without_topology_json_is_refused():
    pack = io.BytesIO()
    with zipfile.ZipFile(pack, "w") as z:
        z.writestr("README.txt", "x")
    with pytest.raises(DiffError, match="no topology.json"):
        load_run(pack.getvalue())


def test_the_anonymized_copy_inside_a_pack_is_not_taken_for_the_run():
    pack = io.BytesIO()
    with zipfile.ZipFile(pack, "w") as z:
        z.writestr("_anonymized/topology.json", json.dumps(run([device("ANON")], [])))
    with pytest.raises(DiffError):
        load_run(pack.getvalue())


def test_rows_that_are_not_objects_are_skipped():
    run_data = load_run(json.dumps({"devices": [device("A"), 5, "x"], "links": [None], "hosts": "none"}).encode())
    assert len(run_data["devices"]) == 1 and run_data["links"] == [] and run_data["hosts"] == []


# ---- real runs and the route --------------------------------------------------------------------------------------

def _real_run(files, **extra):
    from features.topology.service import build_topology, to_json
    result = build_topology(list(files), group="none", **extra)
    return to_json(result["graph"], result["findings"], result["devices"], result["settings"]).encode()


def test_two_real_builds_of_the_synthetic_data_center_differ_where_the_captures_differ():
    from topology_samples import lab_dc
    captures = lab_dc()
    full = _real_run(captures.items())
    partial = _real_run([(n, t) for n, t in captures.items() if n != "LAB-ACC1.txt"])
    result = compare_runs(load_run(partial), load_run(full))
    assert result["summary"]["verdict"] != "identical"
    assert any(r["area"] == "Devices" and r["item"].startswith("LAB-ACC1") for r in result["rows"])
    assert compare_runs(load_run(full), load_run(full))["summary"]["verdict"] == "identical"
    reverse = compare_runs(load_run(full), load_run(partial))
    assert reverse["summary"]["areas"]["Devices"]["changed"] + reverse["summary"]["areas"]["Devices"]["removed"] >= 1


@pytest.fixture()
def client(tmp_path, monkeypatch):
    from app import create_app
    from features.topology import routes
    monkeypatch.setattr(routes, "EXPORT_DIR", tmp_path)
    app = create_app()
    app.config.update(TESTING=True)
    return app.test_client()


def test_the_route_compares_two_uploads_and_returns_a_csv(client):
    before = json.dumps(BASE).encode()
    after = json.dumps(run([device("AGG1"), device("ACC1", role="access")], BASE_LINKS[:1])).encode()
    body = client.post("/topology/api/diff", data={"before": (io.BytesIO(before), "a.json"), "after": (io.BytesIO(after), "b.json")},
                       content_type="multipart/form-data").get_json()
    assert body["ok"] and body["summary"]["verdict"] == "attention"
    assert body["csv"].splitlines()[0] == "area,change,impact,item,field,before,after,why"
    assert "ACC2" in body["csv"]


def test_the_route_compares_kept_runs_and_lists_them(client, tmp_path):
    for number, document in ((1, BASE), (2, run(BASE["devices"], BASE_LINKS[:1]))):
        folder = tmp_path / f"{number:032x}"
        folder.mkdir()
        (folder / "topology.json").write_text(json.dumps(document), encoding="utf-8")
        (folder / "_name.txt").write_text(f"run-{number}", encoding="utf-8")
    runs = client.get("/topology/api/runs").get_json()["runs"]
    assert {r["id"] for r in runs} == {f"{1:032x}", f"{2:032x}"} and {r["name"] for r in runs} == {"run-1", "run-2"}
    assert all(r["devices"] == 3 for r in runs)
    body = client.post("/topology/api/diff", data={"before_id": f"{1:032x}", "after_id": f"{2:032x}"}).get_json()
    assert body["ok"] and [r["item"] for r in body["rows"] if r["change"] == "removed" and r["area"] == "Links"] == ["ACC2 Te1/1/1 - AGG1 Eth1/2"]


@pytest.mark.parametrize("data,status,words", [
    ({}, 400, "Choose the before run"),
    ({"before_id": "../etc", "after_id": "x"}, 400, "Unknown run"),
    ({"before_id": "0" * 32, "after_id": "1" * 32}, 400, "removed"),
])
def test_the_route_explains_a_missing_or_unknown_run(client, data, status, words):
    response = client.post("/topology/api/diff", data=data)
    assert response.status_code == status and words in response.get_json()["error"]


def test_the_route_names_the_side_that_is_not_a_run(client):
    good = json.dumps(BASE).encode()
    response = client.post("/topology/api/diff", data={"before": (io.BytesIO(good), "a.json"), "after": (io.BytesIO(b"nope"), "b.txt")},
                           content_type="multipart/form-data")
    assert response.status_code == 400 and response.get_json()["error"].startswith("The after run:")


def test_the_page_offers_the_comparison(client):
    page = client.get("/topology").get_data(as_text=True)
    assert 'data-role="diff-form"' in page and "topology-diff.js" in page
