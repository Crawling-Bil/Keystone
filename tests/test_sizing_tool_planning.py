"""Sizing Tool 1.1: CSV imports, replacement plan, expiry, duplicates and logical units, compare, evidence, the project file, the capture pack and the new routes.

Every capture and CSV in this file is invented (documentation-style names and serials); no customer data is used.
"""

from __future__ import annotations

import io
import json
import pathlib
from datetime import date

import pytest

from app import create_app
from features.sizing_tool import capture_pack, demo
from features.sizing_tool import imports as csv_imports
from features.sizing_tool import plan, project
from features.sizing_tool.common import iso_date, new_asset
from features.sizing_tool.evidence import confidence_summary, evidence
from features.sizing_tool.service import read_texts

ROOT = pathlib.Path(__file__).resolve().parents[1]


def make(hostname="JKT-SW1", dtype="switch", model="C9300-48P", serial="FCW0000A1B2", **kw):
    kw.setdefault("vendor", "Cisco")
    asset = new_asset(hostname=hostname, device_type=dtype, model=model, serial=serial, **kw)
    asset.setdefault("id", "")
    return asset


def fleet(*assets):
    for n, asset in enumerate(assets, 1):
        asset["id"] = f"d{n}"
    plan.mark_duplicates_and_units(list(assets))
    return list(assets)


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setenv("NES_DISABLE_AUTH", "1")
    app = create_app()
    app.testing = True
    return app.test_client()


# ----------------------------------------------------------------------------------------------------------------------------------- dates

@pytest.mark.parametrize("raw, want", [
    ("Dec 06 2026", "2026-12-06"), ("December 06, 2026", "2026-12-06"), ("2026-12-06", "2026-12-06"), ("06-Dec-2026", "2026-12-06"), ("2026/12/06", "2026-12-06"),
    ("20261206", "2026-12-06"), ("06/12/2026", "2026-12-06"), ("12/25/2026", "2026-12-25"), ("25/12/2026", "2026-12-25"), ("2026-12-06T10:30:00Z", "2026-12-06"),
    ("Sun Dec 06 2026", "2026-12-06"), ("", ""), ("never", ""), ("perpetual", ""), ("not a date", ""), ("31/02/2026", ""), ("1850-01-01", ""),
])
def test_iso_date_reads_every_format_the_vendors_print(raw, want):
    assert iso_date(raw) == want


def test_iso_date_us_order_when_asked():
    assert iso_date("06/12/2026", day_first=False) == "2026-06-12"


# --------------------------------------------------------------------------------------------------------------------------------- imports

def test_csv_reader_handles_bom_semicolons_tabs_and_quotes():
    header, rows = csv_imports.read_csv("﻿Hostname;Site\r\n\"JKT-SW1\";\"Jakarta, HQ\"\r\n")
    assert header == ["Hostname", "Site"] and rows[0]["Site"] == "Jakarta, HQ"
    header, rows = csv_imports.read_csv("Hostname\tSite\nA\tB\n")
    assert rows == [{"Hostname": "A", "Site": "B"}]


def test_csv_reader_refuses_too_many_rows_and_empty_input():
    with pytest.raises(ValueError):
        csv_imports.read_csv("")
    big = "Hostname,Site\n" + "a,b\n" * (csv_imports.MAX_ROWS + 5)
    with pytest.raises(ValueError):
        csv_imports.read_csv(big)


def test_site_map_matches_by_hostname_and_serial_and_reports_the_rest():
    assets = fleet(make("JKT-SW1", serial="FCW0000A1B2"), make("SBY-SW1", serial="FCW0000C3D4"))
    found, report = csv_imports.import_site_map("Device Name,Location,Building,Level\nJKT-SW1.corp.example,HQ,Tower A,3\nFCW0000C3D4,Branch,,\nGHOST-1,X,,\n", assets)
    assert found["d1"] == {"site": "HQ", "building": "Tower A", "floor": "3"}
    assert found["d2"]["site"] == "Branch"
    assert report["matched"] == 2 and report["rows"] == 3 and report["unmatched"] == 1 and "ghost-1" in report["unmatched_examples"][0].lower()
    assert report["columns"]["site"] == "Location"


def test_site_map_needs_a_site_column_and_a_key():
    assets = fleet(make())
    with pytest.raises(ValueError):
        csv_imports.import_site_map("Hostname,Colour\nJKT-SW1,red\n", assets)
    with pytest.raises(ValueError):
        csv_imports.import_site_map("Site,Floor\nHQ,3\n", assets)


def test_peaks_import_reads_units_from_the_header():
    assets = fleet(make("JKT-FW1", "firewall", "PA-3220", "0123456789"))
    found, report = csv_imports.import_peaks("Hostname,Peak throughput (Gbps),Concurrent sessions,CPU %\nJKT-FW1,2.5,\"120,000\",63\n", assets)
    peaks = found["d1"]
    assert peaks["Peak throughput (Mbit/s)"]["value"] == 2500 and peaks["Peak throughput (Mbit/s)"]["unit"] == "Mbit/s"
    assert peaks["Peak concurrent sessions"]["value"] == 120000
    assert peaks["Peak CPU (%)"]["unit"] == "%" and peaks["Peak CPU (%)"]["source"] == "csv"
    assert report["matched"] == 1


@pytest.mark.parametrize("header, row, dialect", [
    ("Serial Number,Subscription Name,Start Date,End Date,Quantity,Status", "FCW0000A1B2,Network Advantage,01/01/2024,31/12/2026,1,Active", "cisco"),
    ("Serial,Contract,Expiration Date", "FCW0000A1B2,FortiCare Premium,2026-12-31", "forti"),
    ("Device Serial,License Type,Expiry", "FCW0000A1B2,Foundation,Dec 31 2026", "aruba"),
    ("Serial #,Subscription,Expires", "FCW0000A1B2,Threat Prevention,2026/12/31", "palo"),
])
def test_entitlement_import_finds_columns_in_each_portal_export(header, row, dialect):
    assets = fleet(make())
    found, report = csv_imports.import_entitlements(f"{header}\n{row}\n", assets)
    entry = found["d1"][0]
    assert entry["expires"] == "2026-12-31" and entry["source"] == "csv", dialect
    assert report["matched"] == 1 and "licence" in report["columns"] and "end" in report["columns"]


def test_entitlement_import_counts_ambiguous_dates_and_refuses_without_a_licence_column():
    assets = fleet(make())
    _, report = csv_imports.import_entitlements("Serial,Subscription,End Date\nFCW0000A1B2,Advantage,06/12/2026\n", assets)
    assert report["ambiguous_dates"] == 1
    with pytest.raises(ValueError):
        csv_imports.import_entitlements("Serial,End Date\nFCW0000A1B2,2026-01-01\n", assets)


def test_lifecycle_import_matches_model_or_a_part_number_and_keeps_no_dates_of_its_own():
    asset = make(model="C9300-48P")
    asset["components"] = [{"category": "Chassis", "part": "C9300-48P", "description": "", "qty": 1}]
    assets = fleet(asset, make("X-RTR1", "router", "ISR4331", "FDO0000ZZZ1"))
    found, report = csv_imports.import_lifecycle("Product ID,End of Sale,End of Support,Replacement\nC9300-48P,2027-01-31,Jan 31 2032,C9300X-48HX\nNOT-HERE,2020-01-01,2021-01-01,\n", assets)
    assert found["d1"]["end_of_support"] == "2032-01-31" and found["d1"]["replacement"] == "C9300X-48HX"
    assert "d2" not in found and report["unmatched"] == 1


def test_lifecycle_import_needs_model_and_a_date_column():
    with pytest.raises(ValueError):
        csv_imports.import_lifecycle("Foo,Bar\n1,2\n", fleet(make()))


def test_formulas_in_imported_cells_stay_text_in_the_workbook(client):
    from features.sizing_tool.excel import to_xlsx
    asset = make()
    asset["licences"] = [{"name": "=HYPERLINK(\"http://x\")", "state": "", "expires": "", "detail": "", "source": "csv"}]
    asset["id"] = "d1"
    from features.sizing_tool.rollup import build
    data = to_xlsx([asset], {**build([asset], 25), "plan": [], "expiry": plan.expiry([asset]), "licence_models": [], "units": plan.logical_units([asset]), "confidence": {}, "peaks": {"rows": [], "missing_total": 0}, "lifecycle": []}, "t")
    from openpyxl import load_workbook
    for sheet in load_workbook(io.BytesIO(data)):
        for row in sheet.iter_rows():
            for cell in row:
                assert not (isinstance(cell.value, str) and cell.value.startswith("=")) or cell.data_type != "f"


# ------------------------------------------------------------------------------------------------------------------------ enrich and expiry

def test_enrich_never_changes_the_stored_assets_and_manual_peaks_win_over_csv():
    assets = fleet(make("JKT-FW1", "firewall", "PA-3220", "0123456789"))
    imports = {"site_map": {"d1": {"site": "HQ", "building": "B1", "floor": "2"}},
               "peaks": {"d1": {"Peak sessions": {"value": 10, "unit": "sessions", "source": "csv", "window": ""}}},
               "entitlements": {"d1": [{"name": "Threat Prevention", "state": "active", "expires": "2026-12-31", "detail": "", "source": "csv"}]}}
    out = plan.enrich(assets, imports, {"manual_peaks": {"d1": {"Peak sessions": 99}}})
    assert out[0]["site"] == "HQ" and out[0]["floor"] == "2" and out[0]["peaks"]["Peak sessions"]["source"] == "manual" and out[0]["peaks"]["Peak sessions"]["value"] == 99
    assert out[0]["licences"][0]["source"] == "csv"
    assert assets[0]["peaks"] == {} and assets[0]["licences"] == [] and assets[0]["floor"] == ""


def test_expiry_states_timeline_and_undated():
    asset = make()
    asset["licences"] = [{"name": "A", "expires": "2026-01-01"}, {"name": "B", "expires": "Mar 10 2027"}, {"name": "C", "expires": "2030-01-01"}, {"name": "D", "expires": ""}]
    out = plan.expiry([asset], months=6, today=date(2026, 11, 15))
    states = {i["licence"]: i["state"] for i in out["items"]}
    assert states == {"A": "expired", "B": "soon", "C": "later"}
    assert out["expired"] == 1 and out["soon"] == 1 and out["dated"] == 3 and out["undated"] == 1 and out["beyond_timeline"] == 1
    assert len(out["timeline"]) == 24 and out["timeline"][0]["month"] == "2026-11"
    assert [t["count"] for t in out["timeline"] if t["month"] == "2027-03"] == [1]
    assert out["items"][0]["licence"] == "A" and out["items"][0]["days_left"] < 0


def test_expiry_months_are_clamped():
    assert plan.expiry([], months=9999, today=date(2026, 1, 1))["months"] == 60
    assert plan.expiry([], months=0, today=date(2026, 1, 1))["months"] == 12 or plan.expiry([], months=0, today=date(2026, 1, 1))["months"] >= 1


# ----------------------------------------------------------------------------------------------------------------------- duplicates and units

def test_same_serial_is_counted_once_and_can_be_kept_by_the_architect():
    a, b = make("JKT-SW1", serial="FCW0000A1B2"), make("JKT-SW1-copy", serial="fcw0000a1b2")
    out = fleet(a, b)
    assert out[1]["duplicate_of"] == "d1" and not out[0]["duplicate_of"]
    assert any("Same device" in n for n in out[1]["notes"])
    from features.sizing_tool.routes import apply_overrides
    assert [x["id"] for x in apply_overrides(out, {})] == ["d1"]
    assert [x["id"] for x in apply_overrides(out, {"d2": {"keep_duplicate": True}})] == ["d1", "d2"]


def test_a_config_only_capture_and_a_show_only_capture_of_one_device_are_merged():
    """The configuration names the VLANs and the licences, the show commands carry the serial, the live ports and the optics: the architect gets one device with both."""
    config = make("JKT-SW1", serial="", capacity={"VLANs": 40, "Physical ports": 48}, source="config.txt", features=[{"group": "Layer 2", "name": "VLANs", "count": 40}])
    show = make("jkt-sw1", serial="FCW0000A1B2", capacity={"Physical ports": 48, "Ports in use (link up)": 31, "Transceivers": 4}, in_use={"Ports 1G": 31}, source="show.txt",
                components=[{"category": "Transceiver", "part": "SFP-10G-SR", "description": "10GBASE-SR", "qty": 4}],
                licences=[{"name": "Network Advantage", "state": "IN USE", "expires": "2027-03-01", "detail": ""}])
    out = fleet(config, show)
    keep, dropped = (out[0], out[1]) if not out[0]["duplicate_of"] else (out[1], out[0])
    assert dropped["duplicate_of"] == keep["id"]
    assert keep["serial"] == "FCW0000A1B2" and keep["capacity"]["VLANs"] == 40 and keep["capacity"]["Ports in use (link up)"] == 31 and keep["capacity"]["Transceivers"] == 4
    assert keep["in_use"] == {"Ports 1G": 31} and keep["licences"][0]["name"] == "Network Advantage"
    assert any(c["part"] == "SFP-10G-SR" for c in keep["components"]) and any(f["name"] == "VLANs" for f in keep["features"])
    assert sorted(keep["merged_from"]) == ["config.txt", "show.txt"]
    assert any("merged into one" in n for n in keep["notes"])


def test_merging_again_changes_nothing():
    a, b = make("JKT-SW1", serial="FCW0000A1B2", capacity={"VLANs": 40}, source="a.txt"), make("JKT-SW1", serial="FCW0000A1B2", capacity={"Transceivers": 4}, source="b.txt")
    out = fleet(a, b)
    before = ({k: v for k, v in out[0].items() if k != "notes"}, len(out[0]["notes"]))
    plan.mark_duplicates_and_units(out)
    assert ({k: v for k, v in out[0].items() if k != "notes"}, len(out[0]["notes"])) == before


def test_two_devices_with_one_name_but_two_serials_are_not_merged():
    out = fleet(make("JKT-SW1", serial="FCW0000A1B2"), make("JKT-SW1", serial="FCW0000C3D4"))
    assert not any(a["duplicate_of"] for a in out)


def test_two_boxes_of_one_vpc_design_are_one_logical_unit_but_unrelated_ones_are_not():
    one, two = make("DC-CORE-1", serial="FOC1111AAAA", ha="vPC pair"), make("DC-CORE-2", serial="FOC2222BBBB", ha="vPC pair")
    lone = make("DC-CORE-9", model="N9K-C9336C", serial="FOC3333CCCC", ha="Standalone")
    out = fleet(one, two, lone)
    assert out[0]["logical_unit"] == out[1]["logical_unit"] != out[2]["logical_unit"]
    units = plan.logical_units(out)
    assert units["count"] == 2 and units["pairs"] == 1 and units["kinds"]["redundant pair (two devices captured)"] == 1


def test_a_pair_needs_the_same_model_and_an_ha_mode():
    a, b = make("DC-A-1", model="X1", serial="FOC1111AAAA", ha="vPC pair"), make("DC-A-2", model="X2", serial="FOC2222BBBB", ha="vPC pair")
    c, d = make("DC-B-1", model="X1", serial="FOC3333CCCC"), make("DC-B-2", model="X1", serial="FOC4444DDDD")
    out = fleet(a, b, c, d)
    assert plan.logical_units(out)["count"] == 4


def test_stack_serials_are_all_indexed():
    stack = make("ACC-STK", serial="1 (Active): FOC1234ABCD; 2 (Standby): FOC5678EFGH")
    assert plan.parse_serials(stack) == ["FOC1234ABCD", "FOC5678EFGH"]


# ------------------------------------------------------------------------------------------------------------------------- replacement plan

def access(host, ports, in_use, poe=0):
    a = make(host, role="access", serial=f"FOC{abs(hash(host)) % 10**7:07d}")
    a["capacity"] = {"Physical ports": ports, "Ports in use (link up)": in_use, "PoE power (W)": poe}
    return a


def test_plan_units_follow_target_over_usable_and_the_highest_quantity_decides():
    assets = fleet(access("A-1", 48, 40, 400), access("A-2", 48, 30, 300))
    out = plan.replacement_plan(assets, {"spare_pct": 20, "redundancy": "none", "profiles": {"switch|Access": {"Ports in use (link up)": 48, "PoE power (W)": 740}}}, 25)
    row = {r["label"]: r for r in out[0]["rows"]}
    assert row["Ports in use (link up)"]["today"] == 70 and row["Ports in use (link up)"]["target"] == 88          # ceil(70 * 1.25)
    assert row["Ports in use (link up)"]["units_needed"] == 3                                                       # 88 / (48 * .8) = 2.29
    assert row["PoE power (W)"]["units_needed"] == 2                                                                # 875 / 592 = 1.48
    assert out[0]["units_needed"] == 3 and out[0]["final_units"] == 3 and out[0]["limited_by"] == "Ports in use (link up)"


@pytest.mark.parametrize("mode, want", [("none", 3), ("n+1", 4), ("2n", 6)])
def test_plan_redundancy(mode, want):
    assets = fleet(access("A-1", 48, 40), access("A-2", 48, 30))
    out = plan.replacement_plan(assets, {"spare_pct": 20, "redundancy": mode, "profiles": {"switch|Access": {"Ports in use (link up)": 48}}}, 25)
    assert out[0]["final_units"] == want


def test_plan_without_a_profile_invents_nothing_and_bad_values_are_ignored():
    assets = fleet(access("A-1", 48, 40))
    out = plan.replacement_plan(assets, {"profiles": {"switch|Access": {"Ports in use (link up)": "abc", "PoE power (W)": -5, "Physical ports": 0}}}, 25)
    assert out[0]["final_units"] is None and out[0]["units_needed"] is None and not out[0]["has_profile"]
    assert all(r["per_unit"] is None for r in out[0]["rows"])
    out = plan.replacement_plan(assets, {"redundancy": "bogus", "spare_pct": 9999, "profiles": {"switch|Access": {"Ports in use (link up)": 100}}}, 0)
    assert out[0]["final_units"] == 4                                                                                # 40 in use / (100 x (1 - 90 % spare cap)); redundancy falls back to none


def test_plan_basis_switch_uses_physical_ports():
    asset = access("A-1", 48, 10)
    asset["capacity"]["Ports 1G"] = 48
    asset["in_use"] = {"Ports 1G": 10}
    assets = fleet(asset)
    today = lambda basis: {r["label"]: r["today"] for r in plan.replacement_plan(assets, {"ports_basis": basis}, 0)[0]["rows"]}["Ports 1G"]
    assert today("in_use") == 10 and today("physical") == 48


def test_access_points_are_counted_by_quantity_not_as_boxes():
    ap = make("WLC-AP", "access_point", "C9120AXI")
    ap["capacity"] = {"Access points": 36}
    out = plan.replacement_plan(fleet(ap), {}, 25)
    assert out[0]["units_today"] == 36 and out[0]["final_units"] is None


def test_licence_models_name_the_vendor_model_without_inventing_dates():
    notes = plan.licence_models(fleet(make(), make("FW1", "firewall", "PA-440", "0123456789", vendor="Palo Alto")))
    assert notes and all({"vendor", "note", "title", "url"} <= set(n) for n in notes)
    assert all(n["url"].startswith("https://") for n in notes if n["url"])


# ------------------------------------------------------------------------------------------------------------------------------- compare

def test_compare_finds_added_removed_changed_and_moved_quantities():
    old1, old2 = access("A-1", 48, 30), access("A-2", 24, 10)
    new1, new3 = access("A-1", 48, 40), access("A-3", 48, 5)
    new1["serial"], new1["id"] = old1["serial"], "d1"
    new1["os"] = "17.9.4"
    fleet(old1, old2)
    fleet(new1, new3)
    new1["serial"] = old1["serial"]
    new1["serials"] = old1["serials"]
    out = plan.compare([old1, old2], [new1, new3])
    assert [d["hostname"] for d in out["added"]] == ["A-3"] and [d["hostname"] for d in out["removed"]] == ["A-2"]
    fields = {d["field"] for c in out["changed"] for d in c["diffs"]}
    assert {"Software", "Ports in use (link up)"} <= fields
    assert any(t["label"].endswith("Physical ports") and t["delta"] == 24 for t in out["totals"])


def test_compare_of_a_run_with_itself_is_empty():
    assets = fleet(access("A-1", 48, 30), access("A-2", 24, 10))
    out = plan.compare(assets, assets)
    assert not out["added"] and not out["removed"] and not out["changed"] and out["unchanged"] == 2 and out["totals"] == []


# ------------------------------------------------------------------------------------------------------------------------------ evidence

def test_evidence_says_where_a_number_comes_from_and_downgrades_missing_commands():
    asset = access("A-1", 48, 30)
    asset["notes"] = ["No show power-over-ethernet brief in the capture: the PoE budget is unknown."]
    asset["peaks"] = {"Peak sessions": {"value": 5, "unit": "sessions", "source": "manual", "window": ""}}
    rows = {r["label"]: r for r in evidence(asset)}
    assert rows["Physical ports"]["confidence"] == "high" and rows["Ports in use (link up)"]["confidence"] == "medium"
    assert rows["PoE power (W)"]["confidence"] == "low"
    assert rows["Peak sessions"]["confidence"] == "entered" and rows["Peak sessions"]["from"] == "entered by you"
    assert sum(confidence_summary([asset]).values()) == len(rows)
    assert "notes" in asset and asset["notes"] == ["No show power-over-ethernet brief in the capture: the PoE budget is unknown."]       # evidence is not stored


# --------------------------------------------------------------------------------------------------------------------------- project file

def test_project_round_trip_keeps_the_run_and_the_options():
    assets = fleet(access("A-1", 48, 30), make("JKT-FW1", "firewall", "PA-3220", "0123456789"))
    options = {"growth": 40, "spare_pct": 15, "redundancy": "n+1", "ports_basis": "physical", "profiles": {"switch|Access": {"Physical ports": 48}},
               "manual_peaks": {"d2": {"Peak sessions": 100}}, "overrides": {"d1": {"site": "HQ", "exclude": True}}}
    text = project.dumps("Q4 refresh", assets, [{"file": "x", "reason": "y"}], ["campus"], {"site_map": {"d1": {"site": "HQ"}}}, options)
    back = project.loads(text.encode("utf-8"))
    assert back["name"] == "Q4 refresh" and [a["hostname"] for a in back["assets"]] == ["A-1", "JKT-FW1"]
    assert back["options"]["growth"] == 40 and back["options"]["redundancy"] == "n+1" and back["options"]["profiles"] == options["profiles"]
    assert back["options"]["overrides"]["d1"] == {"site": "HQ", "exclude": True} and back["imports"]["site_map"] == {"d1": {"site": "HQ"}}


@pytest.mark.parametrize("payload", [b"not json", b"[]", b'{"format": "other"}', json.dumps({"format": project.FORMAT, "version": 99, "assets": []}).encode(),
                                     json.dumps({"format": project.FORMAT, "version": 1, "assets": []}).encode(),
                                     json.dumps({"format": project.FORMAT, "version": 1, "assets": [{"device_type": "toaster"}]}).encode(), b"\xff\xfe\x00"])
def test_project_refuses_what_it_cannot_trust(payload):
    with pytest.raises(ValueError):
        project.loads(payload)


def test_project_file_with_hostile_content_is_cleaned():
    evil = {"format": project.FORMAT, "version": 1, "name": "n" * 500,
            "assets": [{"id": "../../x", "device_type": "switch", "hostname": "<script>x</script>", "capacity": {"Physical ports": "lots", "VLANs": 5, "x": True},
                        "components": "no", "licences": [{"name": "L", "expires": 5}], "peaks": {"p": {"value": "big"}}, "tier": "access", "evil": "__proto__"},
                       {"id": "../../x", "device_type": "router", "hostname": "R"}],
            "imports": {"site_map": {"nope": {"site": "x"}, "../../x": {"site": "ok"}}, "peaks": "bad"},
            "options": {"growth": 1e9, "redundancy": "root", "profiles": {"switch|Access": {"x": "y", "ok": 5}}, "overrides": {"d": {"device_type": "x" * 100, "evil": 1}}}}
    back = project.loads(json.dumps(evil).encode())
    assert len(back["name"]) <= 60 and len({a["id"] for a in back["assets"]}) == 2
    first = back["assets"][0]
    assert first["capacity"] == {"VLANs": 5} and first["components"] == [] and first["peaks"] == {} and "evil" not in first
    assert back["options"]["growth"] == 500 and "redundancy" not in back["options"] and back["options"]["profiles"] == {"switch|Access": {"ok": 5}}
    assert set(back["options"]["overrides"]["d"]) == {"device_type"} and len(back["options"]["overrides"]["d"]["device_type"]) <= 40
    assert back["imports"]["peaks"] == {} and "nope" not in back["imports"]["site_map"]


# ----------------------------------------------------------------------------------------------------------------------- capture pack

def test_every_pack_command_is_still_in_the_collect_script_it_comes_from():
    for pack in capture_pack.PACKS:
        script = ROOT / "static" / "collect-scripts" / pack["source"]
        assert script.is_file(), pack["id"]
        text = script.read_text(encoding="utf-8", errors="replace").lower()
        for command, _ in pack["commands"]:
            if command in capture_pack.DOCUMENTED_ONLY:
                continue
            assert command.lower() in text, f"{pack['id']}: {command} is not in {pack['source']}"


def test_every_pack_has_https_documentation_and_a_reason_for_each_command():
    for pack in capture_pack.packs_for():
        assert pack["docs"] and all(d["url"].startswith("https://") for d in pack["docs"])
        assert pack["commands"] and all(c["why"] for c in pack["commands"])
    assert {p["vendor"] for p in capture_pack.packs_for()} >= {"Cisco", "Huawei", "Aruba", "Palo Alto", "Fortinet", "F5"}
    assert [p["id"] for p in capture_pack.packs_for(["F5"])] == ["f5-bigip"]
    text = capture_pack.as_text(["f5-bigip"])
    assert "tmsh show sys performance all-stats" in text and "Cisco Nexus" not in text


def test_capture_pack_routes(client):
    answer = client.get("/sizing-tool/api/capture-packs").get_json()
    assert answer["ok"] and len(answer["packs"]) == len(capture_pack.PACKS)
    download = client.get("/sizing-tool/api/capture-pack.txt")
    assert download.status_code == 200 and "attachment" in download.headers["Content-Disposition"] and b"show inventory" in download.data


# ---------------------------------------------------------------------------------------------------------------------------------- routes

CAMPUS = demo.read_set("campus")


def start(client, names=("CMP-PAFW1.txt", "CMP-CORE1.txt")):
    files = [(io.BytesIO(data), name) for name, data in CAMPUS if name in names]
    return client.post("/sizing-tool/api/analyze", data={"files": files, "name": "Test run"}, content_type="multipart/form-data").get_json()


def test_analyze_answer_carries_the_new_blocks(client):
    answer = start(client)
    assert answer["ok"] and {"plan", "expiry", "licence_models", "units", "confidence", "peaks", "lifecycle"} <= set(answer["rollup"])
    assert answer["all_assets"] and answer["evidence"] and "peak_fields" in answer and len(answer["assets"]) <= len(answer["all_assets"])
    assert answer["options"]["growth"] == 25


def test_import_routes_site_map_then_clear(client):
    answer = start(client)
    run = answer["run_id"]
    host = answer["assets"][0]["hostname"]
    csv = f"Hostname,Site,Building,Floor\n{host},Surabaya,Tower B,7\n".encode()
    out = client.post("/sizing-tool/api/import", data={"run_id": run, "kind": "site_map", "file": (io.BytesIO(csv), "map.csv")}, content_type="multipart/form-data").get_json()
    assert out["ok"] and out["report"]["matched"] == 1
    assert {a["site"] for a in out["assets"] if a["hostname"] == host} == {"Surabaya"} and any(a["floor"] == "7" for a in out["all_assets"])
    assert out["imports_report"]["site_map"]["matched"] == 1
    cleared = client.post("/sizing-tool/api/import/clear", json={"run_id": run, "kind": "site_map"}).get_json()
    assert cleared["ok"] and "site_map" not in cleared["imports_report"] and not any(a["floor"] == "7" for a in cleared["all_assets"])


def test_import_route_refuses_bad_input(client):
    run = start(client)["run_id"]
    post = lambda **kw: client.post("/sizing-tool/api/import", data=kw, content_type="multipart/form-data")
    assert post(run_id=run, kind="nonsense", file=(io.BytesIO(b"a,b\n1,2\n"), "x.csv")).status_code == 400
    assert post(run_id=run, kind="site_map").status_code == 400
    assert post(run_id=run, kind="site_map", file=(io.BytesIO(b"Colour,Shape\nred,round\n"), "x.csv")).status_code == 400
    assert post(run_id="0" * 32, kind="site_map", file=(io.BytesIO(b"Hostname,Site\na,b\n"), "x.csv")).status_code == 404


def test_entitlement_import_feeds_the_expiry_view(client):
    answer = start(client)
    run, host = answer["run_id"], answer["assets"][0]["hostname"]
    csv = f"Hostname,Subscription,End Date\n{host},Test subscription,2099-01-01\n".encode()
    out = client.post("/sizing-tool/api/import", data={"run_id": run, "kind": "entitlements", "file": (io.BytesIO(csv), "e.csv")}, content_type="multipart/form-data").get_json()
    assert any(i["licence"] == "Test subscription" and i["state"] == "later" and i["source"] == "csv" for i in out["rollup"]["expiry"]["items"])


def test_rollup_with_profiles_and_typed_peaks(client):
    answer = start(client)
    run = answer["run_id"]
    fw = next(a for a in answer["assets"] if a["device_type"] == "firewall")
    options = {"growth": 10, "spare_pct": 10, "redundancy": "n+1", "profiles": {"firewall": {"Firewall policies": 100}}, "manual_peaks": {fw["id"]: {"Peak throughput (Mbit/s)": 1500}}}
    out = client.post("/sizing-tool/api/rollup", json={"run_id": run, "options": options}).get_json()
    plan_fw = next(p for p in out["rollup"]["plan"] if p["device_type"] == "firewall")
    assert plan_fw["final_units"] and plan_fw["final_units"] >= 2                                                       # n+1 always adds a unit
    assert any(r["label"] == "Peak throughput (Mbit/s)" for r in out["rollup"]["peaks"]["rows"])
    assert out["options"]["redundancy"] == "n+1" and out["rollup"]["growth"] == 10


def test_add_route_numbers_on_and_flags_a_second_capture_of_the_same_device(client):
    answer = start(client, ("CMP-PAFW1.txt",))
    run = answer["run_id"]
    again = lambda: [(io.BytesIO(data), "second.txt") for name, data in CAMPUS if name == "CMP-PAFW1.txt"] + [(io.BytesIO(data), "core.txt") for name, data in CAMPUS if name == "CMP-CORE1.txt"]
    out = client.post("/sizing-tool/api/add", data={"run_id": run, "files": again()}, content_type="multipart/form-data").get_json()
    assert out["ok"] and len(out["all_assets"]) == 3 and out["added"] == 2
    assert len({a["id"] for a in out["all_assets"]}) == 3
    assert sum(1 for a in out["all_assets"] if a["duplicate_of"]) == 1 and len(out["assets"]) == 2
    assert client.post("/sizing-tool/api/add", data={"run_id": run}, content_type="multipart/form-data").status_code == 400
    assert client.post("/sizing-tool/api/add", data={"run_id": "0" * 32, "files": again()}, content_type="multipart/form-data").status_code == 404


def test_project_save_open_and_compare(client):
    answer = start(client)
    run = answer["run_id"]
    saved = client.post("/sizing-tool/api/project/save", json={"run_id": run, "options": {"growth": 33, "redundancy": "2n"}})
    assert saved.status_code == 200 and ".sizing.json" in saved.headers["Content-Disposition"]
    opened = client.post("/sizing-tool/api/project/open", data={"file": (io.BytesIO(saved.data), "p.sizing.json")}, content_type="multipart/form-data").get_json()
    assert opened["ok"] and opened["run_id"] != run and opened["options"]["growth"] == 33 and opened["options"]["redundancy"] == "2n"
    assert [a["hostname"] for a in opened["all_assets"]] == [a["hostname"] for a in answer["all_assets"]]
    same = client.post("/sizing-tool/api/compare", data={"run_id": opened["run_id"], "other_run_id": run}, content_type="multipart/form-data").get_json()
    assert same["ok"] and not same["added"] and not same["removed"] and not same["changed"]
    by_file = client.post("/sizing-tool/api/compare", data={"run_id": run, "project": (io.BytesIO(saved.data), "p.sizing.json")}, content_type="multipart/form-data").get_json()
    assert by_file["ok"] and by_file["unchanged"] == len(answer["assets"])
    assert client.post("/sizing-tool/api/compare", data={"run_id": run, "other_run_id": run}, content_type="multipart/form-data").status_code == 400
    assert client.post("/sizing-tool/api/project/open", data={"file": (io.BytesIO(b"{}"), "x.json")}, content_type="multipart/form-data").status_code == 400
    assert client.post("/sizing-tool/api/project/open", data={}, content_type="multipart/form-data").status_code == 400


def test_runs_listing_and_the_bom_csv(client):
    run = start(client)["run_id"]
    runs = client.get("/sizing-tool/api/runs").get_json()["runs"]
    assert any(r["run_id"] == run and r["name"] == "Test run" for r in runs)
    bom = client.post("/sizing-tool/api/export-bom", json={"run_id": run, "options": {"growth": 20}})
    assert bom.status_code == 200 and bom.headers["Content-Type"].startswith("text/csv") and bom.data.startswith(b"\xef\xbb\xbf")
    lines = bom.data.decode("utf-8-sig").splitlines()
    assert len(lines) > 1 and "Part number" in lines[0]
    assert client.post("/sizing-tool/api/export-bom", json={"run_id": "0" * 32}).status_code == 404


def test_new_routes_refuse_bad_run_ids(client):
    for path in ("import/clear", "project/save", "export-bom"):
        assert client.post(f"/sizing-tool/api/{path}", json={"run_id": "../x"}).status_code == 404


# ----------------------------------------------------------------------------------------------------------------------- readers and classify

AOS_S = """ACC-AOS-1# show system

  System Name        : ACC-AOS-1
  Software revision  : WC.16.11.0012
  Serial Number      : SG9ZZ12345

ACC-AOS-1# show interfaces brief

  Port   Type      | Alert   Enabled Status Mode Mode Ctrl Limit
  ------ --------- + ------- ------- ------ ---- ---- ----- -----
  1      100/1000T | No      Yes     Up     1000FDx MDI off  0
  2      100/1000T | No      Yes     Down   1000FDx MDI off  0
  25     10GbE-SFP+| No      Yes     Up     10GigFD NA off  0
"""

NEXUS = """SW1# show version
Cisco Nexus Operating System (NX-OS) Software
  NXOS: version 10.3(5)
  cisco Nexus9000 N9K-C93180YC-FX3 Chassis
  Device name: DC-LEAF-1
  Processor Board ID FDO11112222
SW1# show interface status
Port          Name               Status    Vlan      Duplex  Speed   Type
Eth1/1        --                 connected 1         full    10G     10Gbase-SR
Eth1/2        --                 notconnect 1        full    auto    10Gbase-SR
Eth1/49       --                 connected trunk     full    100G    QSFP-100G-SR4
Eth1/50       --                 connected trunk     full    40G     QSFP-4x10G-AOC
"""

ROUTER_NO_TABLE = """RTR-1# show version
Cisco IOS XE Software, Version 17.09.04a
cisco ISR4331/K9 (1RU) processor with 1234567K/6147K bytes of memory.
Processor board ID FDO99998888
RTR-1# show ip interface brief
Interface              IP-Address      OK? Method Status                Protocol
GigabitEthernet0/0/0   192.0.2.1       YES manual up                    up
GigabitEthernet0/0/1   unassigned      YES unset  administratively down down
"""


def test_aos_s_capture_is_read_with_speeds_and_link_state():
    found, skipped = read_texts([("aos.txt", AOS_S)])
    assert skipped == [] and len(found) == 1
    asset = found[0]
    assert (asset["vendor"], asset["device_type"], asset["hostname"], asset["serial"]) == ("Aruba", "switch", "ACC-AOS-1", "SG9ZZ12345")
    assert asset["capacity"]["Physical ports"] == 3 and asset["capacity"]["Ports in use (link up)"] == 2
    assert asset["capacity"]["Ports 1G"] == 2 and asset["capacity"]["Ports 10G"] == 1 and asset["in_use"] == {"Ports 1G": 1, "Ports 10G": 1}
    assert any("Aruba Central" in n for n in asset["notes"])                                                           # the subscription is not in a switch capture: said, not guessed


def test_nexus_speeds_come_from_the_status_type_column_and_a_breakout_stays_unresolved():
    asset = read_texts([("nx.txt", NEXUS)])[0][0]
    cap = asset["capacity"]
    assert cap["Ports 10G"] == 2 and cap["Ports 100G"] == 1 and cap["Ports (speed not in name)"] == 1                     # 4x10G breakout names no single speed
    assert any("Port speed is not in the port names" in n for n in asset["notes"])
    assert evidence(asset)[0]["confidence"] in ("high", "medium", "low")


@pytest.mark.parametrize("name, bucket", [("QSFP-100G-SR4", "100G"), ("QSFP-H40G-CU", "40G"), ("SFP-25G-SR", "25G"), ("SFP-H10GB-CU", "10G"), ("10Gbase-SR", "10G"), ("1000base-T", "1G"),
                                          ("QSFP-4x10G-AOC", None), ("--", None), ("", None)])
def test_type_column_to_speed_bucket(name, bucket):
    from features.sizing_tool.readers import _type_bucket
    assert _type_bucket(name) == bucket


def test_router_capture_without_a_routing_table_is_read_not_crashed():
    found, skipped = read_texts([("r.txt", ROUTER_NO_TABLE)])
    assert skipped == [] and found[0]["device_type"] == "router" and found[0]["capacity"]["Routes"] == 0
    assert found[0]["capacity"]["Physical interfaces"] == 2


def test_f5_peaks_are_the_maximum_column_in_the_right_unit():
    from features.sizing_tool.readers import _lb_peaks
    asset = make("LB1", "load_balancer", "BIG-IP i5800", "f5-aaaa-bbbb", vendor="F5")
    result = {"sections": [{"id": "performance_live", "rows": [
        {"group": "Throughput", "metric": "Service", "current": "1G", "average": "2G", "maximum": "4.2G", "since": "Mon Oct 12"},
        {"group": "System CPU Usage", "metric": "Utilization", "maximum": "71"},
        {"group": "Active Connections", "metric": "Connections", "maximum": "250K"}]}]}
    _lb_peaks(asset, result)
    assert asset["peaks"]["Peak throughput (Mbit/s)"]["value"] == pytest.approx(4200.0)
    assert asset["peaks"]["Peak CPU (%)"]["value"] == 71 and asset["peaks"]["Peak concurrent connections"]["value"] == 250000
    assert asset["peaks"]["Peak CPU (%)"]["source"] == "capture" and "since" in asset["peaks"]["Peak throughput (Mbit/s)"]["window"]


def test_classify_sends_aos_s_and_show_only_ios_to_the_right_reader():
    from features.sizing_tool.classify import classify
    assert classify(AOS_S)["analyzer"] == "aos_s"
    assert classify(NEXUS)["analyzer"] == "switch" and classify(ROUTER_NO_TABLE)["analyzer"] == "router"


def test_cisco_wlc_power_supplies_come_into_the_bill_of_materials():
    text = dict((n, d.decode()) for n, d in CAMPUS)["CMP-WLC1.txt"]
    wlc = read_texts([("w.txt", text)])[0][0]
    parts = {(c["category"], c["part"]) for c in wlc["components"]}
    assert ("Chassis", wlc["model"]) in parts and ("Power supply", "PWR-C1-350WAC-P") in parts
    assert sum(1 for c in wlc["components"] if c["category"] == "Chassis") == 1                                            # the chassis is not counted twice
