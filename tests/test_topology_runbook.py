"""Cutover runbook (features/topology/runbook.py).  Synthetic runs only: hand-written tables in the shape of topology.json."""

from __future__ import annotations

import datetime
import io
import json
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from features.topology import runbook  # noqa: E402
from features.topology.diff import load_run  # noqa: E402
from features.topology.runbook import FAMILIES, RunbookError, build_runbook, family_of  # noqa: E402


def dev(name, role="access", **fields):
    return {"device": name, "captured": "yes", "role": role, "vendor": "Cisco", "model": "C9300-48P", "os_version": "17.9", "management_ip": "10.0.0." + str(abs(hash(name)) % 200 + 1),
            "serial": "SN" + name, "stack_members": "", "vpc_domain": "", "vpc_role": "", **fields}


def link(a, pa, b, pb, **fields):
    return {"device_a": a, "port_a": pa, "device_b": b, "port_b": pb, "state": "confirmed", "protocols": "CDP/LLDP", "bundle_a": "", "bundle_b": "", "kind": "link", "vpc_id": "",
            "speed_a": "10G", "speed_b": "10G", "rated_a": "10G", "rated_b": "10G", "port_state_a": "up", "port_state_b": "up", "duplex_a": "full", "duplex_b": "full",
            "subnet": "", "native_vlan": "1", "duplex": "", "note": "", **fields}


def run(devices, links, hosts=(), findings=()):
    return {"devices": list(devices), "links": list(links), "hosts": list(hosts), "findings": list(findings), "behind": []}


def campus(dual_homed=False, vpc=True):
    """FW1 over two cores; ACC1 on both cores; ACC2 on CORE1 only (unless dual_homed)."""
    devices = [dev("FW1", "router", vendor="Fortinet", model="FortiGate 100F"),
               dev("CORE1", "core", model="N9K-C93180YC-FX", vpc_domain="10" if vpc else "", vpc_role="primary" if vpc else ""),
               dev("CORE2", "core", model="N9K-C93180YC-FX", vpc_domain="10" if vpc else "", vpc_role="secondary" if vpc else ""),
               dev("ACC1"), dev("ACC2")]
    links = [link("FW1", "port1", "CORE1", "Eth1/1"), link("FW1", "port2", "CORE2", "Eth1/1"),
             link("CORE1", "Eth1/10", "ACC1", "Gi1/0/48"), link("CORE2", "Eth1/10", "ACC1", "Gi1/0/47"),
             link("CORE1", "Eth1/11", "ACC2", "Gi1/0/48")]
    if dual_homed:
        links.append(link("CORE2", "Eth1/11", "ACC2", "Gi1/0/47"))
    return run(devices, links)


def plan(result, name):
    return next(d for d in result["devices"] if d["device"] == name)


# ---- impact ---------------------------------------------------------------------------------------------------------------------------------

def test_a_single_homed_switch_is_lost_when_its_only_upstream_goes():
    result = build_runbook(campus())
    assert plan(result, "CORE1")["outage"] is True
    assert "ACC2" in plan(result, "CORE1")["impact_text"] and "ACC1" not in plan(result, "CORE1")["impact_text"]
    assert plan(result, "CORE2")["outage"] is False


def test_with_a_second_path_nothing_is_lost():
    result = build_runbook(campus(dual_homed=True))
    assert [d["device"] for d in result["devices"] if d["outage"]] == ["FW1"]            # the only top device: everything below loses it
    assert result["summary"]["outage"] == 1 and result["summary"]["rolling"] == 4


def test_the_outage_text_names_the_top_device_that_can_no_longer_be_reached():
    assert "No remaining path to FW1" in plan(build_runbook(campus()), "CORE1")["impact_text"]


def test_the_only_top_level_device_takes_everything_with_it():
    result = build_runbook(campus())
    text = plan(result, "FW1")["impact_text"]
    assert "No other top-level device" in text and "CORE1" in text


def test_devices_that_were_already_cut_off_are_not_counted():
    data = campus()
    data["devices"].append(dev("LONELY"))
    data["links"].append(link("LONELY", "Gi1/0/1", "GHOST", "Gi0/1"))      # GHOST is not in the devices table and has no path to a root
    assert "LONELY" not in plan(build_runbook(data), "CORE1")["impact_text"]


def test_management_links_do_not_count_as_paths():
    data = campus()
    data["links"].append(link("ACC2", "mgmt0", "CORE2", "mgmt0", kind="mgmt"))          # a management cable is not a data path: ACC2 still depends on CORE1
    assert plan(build_runbook(data), "CORE1")["outage"] is True
    data["links"][-1]["kind"] = "link"
    assert plan(build_runbook(data), "CORE1")["outage"] is False


def test_end_host_macs_behind_the_lost_switches_are_counted():
    data = campus()
    data["hosts"] = [{"device": "ACC2", "port": f"Gi1/0/{i}", "mac": f"0000.0000.00{i:02d}"} for i in range(1, 6)] + [{"device": "ACC1", "port": "Gi1/0/1", "mac": "0000.0000.0099"}]
    assert "About 5 end-host MAC address(es)" in plan(build_runbook(data), "CORE1")["impact_text"]


def test_access_points_are_counted_by_kind_not_listed_one_by_one():
    data = campus()
    data["devices"] += [dev(f"AP{i}", "ap", captured="no") for i in range(1, 4)]
    data["links"] += [link("ACC2", f"Gi1/0/{i}", f"AP{i}", "eth0") for i in range(1, 4)]
    assert "3 aps" in plan(build_runbook(data), "CORE1")["impact_text"]


# ---- order ----------------------------------------------------------------------------------------------------------------------------------

def test_the_order_runs_from_the_edge_to_the_core():
    names = [d["device"] for d in build_runbook(campus())["devices"]]
    assert names.index("ACC1") < names.index("CORE1") and names.index("ACC2") < names.index("CORE2") and names[-1] == "FW1"


def test_the_secondary_vpc_peer_goes_before_the_primary_when_the_impact_is_equal():
    names = [d["device"] for d in build_runbook(campus(dual_homed=True))["devices"]]
    assert names.index("CORE2") < names.index("CORE1")


def test_less_impact_goes_first_within_a_tier():
    names = [d["device"] for d in build_runbook(campus())["devices"]]
    assert names.index("CORE2") < names.index("CORE1")           # CORE2 loses nobody, CORE1 loses ACC2


def test_less_impact_beats_the_secondary_rule():
    data = campus()
    data["devices"][1]["vpc_role"], data["devices"][2]["vpc_role"] = "secondary", "primary"        # CORE1 is secondary but loses ACC2; CORE2 is primary and loses nobody
    names = [d["device"] for d in build_runbook(data)["devices"]]
    assert names.index("CORE2") < names.index("CORE1")


def test_the_sequence_numbers_follow_the_order():
    assert [d["seq"] for d in build_runbook(campus())["devices"]] == [1, 2, 3, 4, 5]


# ---- vPC and stack --------------------------------------------------------------------------------------------------------------------------

def test_vpc_peers_get_a_partner_check_and_a_gate():
    result = build_runbook(campus(dual_homed=True))
    steps = [s for s in result["steps"] if s["device"] == "CORE1"]
    assert any(s["step"] == "Check the partner CORE2 is healthy" and s["command"] == "show vpc" for s in steps)
    assert any(s["step"] == "Gate: start CORE2 only now" for s in steps)
    assert plan(result, "CORE1")["partner"] == "CORE2" and plan(result, "CORE2")["partner"] == "CORE1"


def test_devices_without_a_pair_have_no_gate():
    result = build_runbook(campus(dual_homed=True, vpc=False))
    assert not any("Gate" in s["step"] or "partner" in s["step"] for s in result["steps"])


def test_a_stack_is_flagged_as_one_unit():
    data = campus()
    data["devices"][3]["stack_members"] = "3"
    assert "A stack of 3 members" in build_runbook(data)["html"]


def test_a_device_without_management_address_says_to_use_the_console():
    data = campus()
    data["devices"][3]["management_ip"] = ""
    assert "No management address in the capture. Use the console." in build_runbook(data)["html"]


# ---- platforms and commands -----------------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("vendor,model,extra,expected", [
    ("Cisco", "C9300-48P", {}, "iosxe"), ("Cisco", "N9K-C93180YC-FX", {}, "nxos"), ("Cisco", "Nexus 5548", {}, "nxos"), ("Cisco", "C9500-24Q", {"vpc_domain": "3"}, "nxos"),
    ("Huawei", "S5735-L48T4S-A1", {}, "huawei"), ("Aruba", "6300M 48G", {}, "aoscx"), ("Aruba", "8325-48Y8C", {}, "aoscx"), ("Aruba", "2930F-48G", {}, "arubaos"),
    ("HPE", "2540-48G", {}, "arubaos"), ("Fortinet", "FortiGate 100F", {}, "fortigate"), ("Palo Alto Networks", "PA-3220", {}, "paloalto"),
    ("F5", "BIG-IP i5800", {}, "f5"), ("Juniper", "EX4300", {}, "generic"), ("", "", {}, "generic"),
])
def test_the_platform_picks_its_command_list(vendor, model, extra, expected):
    assert family_of({"vendor": vendor, "model": model, "role": "switch", **extra}) == expected


def test_each_platform_gets_its_own_commands_in_the_baseline_and_the_check():
    data = run([dev("HW1", vendor="Huawei", model="S5735"), dev("NX1", "core", model="N9K-C9336C-FX2"), dev("SW1")], [link("HW1", "XGE0/0/1", "NX1", "Eth1/1"), link("SW1", "Gi1/0/1", "NX1", "Eth1/2")])
    steps = build_runbook(data)["steps"]
    assert "display eth-trunk" in next(s for s in steps if s["device"] == "HW1" and s["step"] == "Take the baseline")["command"]
    assert "show vpc" in next(s for s in steps if s["device"] == "NX1" and s["step"] == "Take the baseline")["command"]
    assert "show etherchannel summary" in next(s for s in steps if s["device"] == "SW1" and s["step"] == "Take the baseline")["command"]
    after = [s for s in steps if s["device"] == "HW1" and s["phase"] == "After"][0]
    assert after["command"] == next(s for s in steps if s["device"] == "HW1" and s["step"] == "Take the baseline")["command"]


def test_no_built_in_command_changes_a_device():
    forbidden = re.compile(r"^(configure|conf\b|write|reload|copy|erase|delete|format|system-view|commit|save|reboot|shutdown|no\s|undo\s|set\s|clear)", re.I)
    for key, family in FAMILIES.items():
        for command in family["commands"]:
            assert not forbidden.match(command.replace("tmsh ", "")), (key, command)


def test_a_platform_without_a_command_list_says_so_instead_of_printing_nothing():
    data = run([dev("X1", vendor="Juniper", model="EX4300")], [])
    step = next(s for s in build_runbook(data)["steps"] if s["step"] == "Take the baseline")
    assert step["command"] == "" and "equivalents" in step["detail"]


# ---- steps ----------------------------------------------------------------------------------------------------------------------------------

def test_the_port_map_is_in_natural_port_order_and_each_cable_is_a_step():
    data = run([dev("SW1"), dev("SW2", "core"), dev("SW3", "core")],
               [link("SW1", "Gi1/0/10", "SW2", "Eth1/1"), link("SW1", "Gi1/0/2", "SW3", "Eth1/2"), link("SW1", "Gi1/0/1", "SW2", "Eth1/3")])
    steps = [s["step"] for s in build_runbook(data)["steps"] if s["device"] == "SW1" and s["step"].startswith("Patch")]
    assert steps == ["Patch Gi1/0/1 to SW2 Eth1/3", "Patch Gi1/0/2 to SW3 Eth1/2", "Patch Gi1/0/10 to SW2 Eth1/1"]


def test_a_long_port_map_is_cut_and_says_where_the_rest_is():
    data = run([dev("SW1"), dev("SW2", "core")], [link("SW1", f"Gi1/0/{i}", "SW2", f"Eth1/{i}") for i in range(1, 251)])
    result = build_runbook(data)
    patches = [s for s in result["steps"] if s["device"] == "SW1" and s["step"].startswith("Patch")]
    assert len(patches) == runbook.MAX_PORT_ROWS + 1 and patches[-1]["step"] == "Patch the remaining 50 port(s)"
    assert "200 of 250 ports shown" in result["html"]


def test_links_seen_from_one_end_get_a_confirm_cabling_step():
    data = campus()
    data["links"][4]["state"] = "single"
    steps = [s for s in build_runbook(data)["steps"] if s["step"].startswith("Confirm the cabling")]
    assert {s["device"] for s in steps} == {"CORE1", "ACC2"} and "(single)" in steps[0]["detail"]
    assert not [s for s in build_runbook(campus())["steps"] if s["step"].startswith("Confirm the cabling")]


def test_open_high_and_medium_findings_are_listed_for_their_devices_only():
    data = campus()
    data["findings"] = [{"id": "TOPO-001", "severity": "high", "title": "Link disagrees", "devices": ["ACC1", "CORE1"]},
                        {"id": "TOPO-002", "severity": "medium", "title": "Native VLAN differs", "devices": "ACC1, ACC2"},
                        {"id": "TOPO-009", "severity": "low", "title": "Minor", "devices": ["ACC1"]}, {"id": "TOPO-010", "severity": "info", "title": "Info", "devices": ["ACC1"]}]
    steps = {(s["device"]): s for s in build_runbook(data)["steps"] if s["step"] == "Read the open findings for this device"}
    assert set(steps) == {"ACC1", "CORE1", "ACC2"}
    assert "TOPO-001" in steps["ACC1"]["detail"] and "TOPO-002" in steps["ACC1"]["detail"] and "TOPO-009" not in steps["ACC1"]["detail"] and "TOPO-010" not in steps["ACC1"]["detail"]


def test_the_change_type_decides_the_middle_steps():
    for change, present, absent in (("replace", "Take the old unit out", "Load the new software image"), ("upgrade", "Load the new software image", "Take the old unit out"),
                                    ("config", "Apply the configuration change", "Take the old unit out")):
        names = {s["step"] for s in build_runbook(campus(), change=change)["steps"]}
        assert present in names and absent not in names


def test_rollback_steps_follow_the_change_type():
    def rollback(change):
        return [s["step"] for s in build_runbook(campus(), change=change)["steps"] if s["device"] == "ACC1" and s["phase"] == "Rollback"]
    assert any("Re-patch every cable" in s for s in rollback("replace"))
    assert any("previous image" in s for s in rollback("upgrade"))
    assert any("Restore the configuration backup" in s for s in rollback("config"))


def test_unknown_change_type_is_refused():
    with pytest.raises(RunbookError, match="Unknown change type"):
        build_runbook(campus(), change="demolish")


def test_the_plan_always_ends_with_the_compare_and_baseline_checks():
    steps = [s["step"] for s in build_runbook(campus())["steps"] if s["device"] == "ALL"]
    assert "Compare the two runs" in steps and "Check the new configurations against the baseline" in steps
    assert steps[0] == "Approve the change and name the people"


def test_new_hardware_preparation_is_only_for_a_replacement():
    assert "Prepare the new units" in {s["step"] for s in build_runbook(campus(), change="replace")["steps"]}
    assert "Prepare the new units" not in {s["step"] for s in build_runbook(campus(), change="upgrade")["steps"]}


# ---- scope ----------------------------------------------------------------------------------------------------------------------------------

def test_only_the_named_devices_are_planned_but_all_stay_in_the_impact_calculation():
    result = build_runbook(campus(), only=["core1", "acc1"])
    assert [d["device"] for d in result["devices"]] == ["ACC1", "CORE1"]
    assert "ACC2" in plan(result, "CORE1")["impact_text"]


def test_an_unknown_name_is_refused_with_the_names_that_exist():
    with pytest.raises(RunbookError) as err:
        build_runbook(campus(), only=["NOPE"])
    assert "NOPE" in str(err.value) and "ACC1" in str(err.value)


def test_a_device_that_was_not_captured_cannot_be_planned_and_is_listed_as_not_in_the_plan():
    data = campus()
    data["devices"].append(dev("GHOST", "switch", captured="no"))
    data["links"].append(link("GHOST", "Gi0/1", "ACC1", "Gi1/0/1"))
    result = build_runbook(data)
    assert "GHOST" not in [d["device"] for d in result["devices"]] and result["summary"]["not_captured"] == 1
    assert "Not in the plan" in result["html"] and "GHOST" in result["html"]
    with pytest.raises(RunbookError):
        build_runbook(data, only=["GHOST"])


def test_a_run_without_captured_devices_has_nothing_to_plan():
    with pytest.raises(RunbookError, match="no captured device"):
        build_runbook(run([dev("X", captured="no")], []))


# ---- output ---------------------------------------------------------------------------------------------------------------------------------

def test_html_is_escaped_and_has_no_script():
    data = campus()
    data["devices"][3]["device"] = "ACC<script>alert(1)</script>"
    data["links"][2]["device_b"] = "ACC<script>alert(1)</script>"
    html = build_runbook(data, title="<img src=x onerror=alert(1)>", window='"><b>', reference="&")["html"]
    assert "<script" not in html.lower() and "<img" not in html and "&lt;script&gt;" in html and "&lt;img src=x" in html


def test_html_has_the_sections_the_reader_needs():
    html = build_runbook(campus(), title="Lab", window="Sat 22:00", reference="CHG1")["html"]
    for text in ("1. Order of work", "2. Before the window", "3. Device procedures", "3.1 ACC1", "3.5 FW1", "4. After the window", "5. Sign-off", "6. References", "Port map", "Rollback", "window Sat 22:00", "change record CHG1"):
        assert text in html
    assert html.count("class='device'") == 5


def test_references_are_only_the_ones_for_platforms_in_the_plan():
    html = build_runbook(campus())["html"]
    assert "218333-understand-and-configure-nexus-9000-vpc" in html and "EDOC1100333463" not in html


def test_the_csv_rows_are_a_tracking_sheet():
    result = build_runbook(campus())
    steps = result["steps"]
    assert [s["seq"] for s in steps] == [str(i) for i in range(1, len(steps) + 1)]
    assert all(s["done"] == "" and s["by"] == "" and s["time"] == "" for s in steps)
    assert not any("\n" in s["command"] for s in steps) and result["summary"]["steps"] == len(steps)
    assert {s["phase"] for s in steps} == {"Preparation", "Before", "Change", "After", "Rollback", "Verification"}


def test_summary_counts():
    summary = build_runbook(campus())["summary"]
    assert summary["devices"] == 5 and summary["outage"] == 2 and summary["rolling"] == 3 and summary["roots"] == ["FW1"]


# ---- the route and the page -------------------------------------------------------------------------------------------------------------------

@pytest.fixture()
def client():
    from app import create_app
    app = create_app()
    app.config["TESTING"] = True
    return app.test_client()


def upload(data):
    return (io.BytesIO(json.dumps(data).encode()), "topology.json")


def test_the_route_writes_a_runbook_from_an_uploaded_run(client):
    body = client.post("/topology/api/runbook", data={"source": upload(campus()), "title": "Lab", "change": "upgrade", "devices": "ACC1\nCORE1"}, content_type="multipart/form-data").get_json()
    assert body["ok"] and body["summary"]["devices"] == 2 and body["summary"]["change"] == "upgrade"
    assert body["html"].startswith("<!doctype html>") and body["csv"].splitlines()[0].startswith("seq,device_order,device,phase,step")


def test_the_route_reads_a_run_kept_on_this_computer(client, tmp_path, monkeypatch):
    from features.topology import routes
    run_id = "a" * 32
    folder = tmp_path / run_id
    folder.mkdir()
    (folder / "topology.json").write_text(json.dumps(campus()), encoding="utf-8")
    monkeypatch.setattr(routes, "EXPORT_DIR", tmp_path)
    body = client.post("/topology/api/runbook", data={"source_id": run_id}, content_type="multipart/form-data").get_json()
    assert body["ok"] and body["summary"]["devices"] == 5


@pytest.mark.parametrize("data,message", [
    ({}, "Choose the source run"),
    ({"source_id": "../../etc"}, "Unknown run"),
    ({"source_id": "b" * 32}, "removed"),
    ({"change": "demolish"}, "Unknown change type"),
    ({"devices": "NOPE"}, "Not a captured device"),
])
def test_the_route_refuses_what_it_cannot_plan(client, data, message):
    if "source_id" not in data:
        data = {**data, "source": upload(campus())} if data else data
    response = client.post("/topology/api/runbook", data=data, content_type="multipart/form-data")
    assert response.status_code == 400 and message in response.get_json()["error"]


def test_the_route_refuses_a_file_that_is_not_a_run(client):
    response = client.post("/topology/api/runbook", data={"source": (io.BytesIO(b"not json"), "x.json")}, content_type="multipart/form-data")
    assert response.status_code == 400 and "not readable JSON" in response.get_json()["error"]


def test_a_real_build_gives_a_runbook(client):
    from topology_samples import lab_dc
    from features.topology.ingest import to_captures
    from features.topology.service import build_topology, to_json
    result = build_topology(to_captures([(n, t.encode()) for n, t in lab_dc().items()], 100), name="x", created=datetime.datetime.now())
    text = to_json(result["graph"], result["findings"], result["devices"], result["settings"])
    body = client.post("/topology/api/runbook", data={"source": (io.BytesIO(text.encode()), "topology.json")}, content_type="multipart/form-data").get_json()
    assert body["ok"] and body["summary"]["devices"] == 3
    assert load_run(text.encode())["devices"]


def test_the_page_has_the_panel_and_its_script(client):
    page = client.get("/topology").get_data(as_text=True)
    assert 'data-role="runbook"' in page and "topology-runbook.js" in page and 'data-role="rb-form"' in page
    js = (Path(__file__).resolve().parent.parent / "static" / "js" / "topology-runbook.js").read_text(encoding="utf-8")
    assert "/api/runbook" in js and "source_id" in js and 'append("source"' in js
