"""Sizing Tool: features in use -> the licence tier the replacement needs, and the renewal windows.  Invented assets only."""

from __future__ import annotations

from datetime import date

from features.sizing_tool import tiers
from features.sizing_tool.common import new_asset


def box(vendor, dtype="switch", model="X", **kw):
    asset = new_asset(hostname=kw.pop("hostname", "TEST-1"), vendor=vendor, device_type=dtype, model=model, serial="S123456789")
    asset.update(kw)
    return asset


def feats(*pairs, group="Layer 3"):
    return [{"group": group, "name": name, "count": count} for name, count in pairs]


def test_a_catalyst_9000_keeps_the_licence_level_it_runs_today():
    asset = box("Cisco", model="C9300-48P", licences=[{"name": "C9300 Network Advantage", "state": "IN USE", "expires": "", "detail": ""},
                                                       {"name": "C9300 DNA Essentials", "state": "NOT IN USE", "expires": "", "detail": ""}])
    out = tiers.hints(asset)
    assert [h["needs"] for h in out if h["feature"] == "Licence in use"] == ["At least C9300 Network Advantage on the replacement"]


def test_stackwise_virtual_needs_advantage_and_says_which_page_states_it():
    out = tiers.hints(box("Cisco", model="C9500-24Y4C", ha="StackWise Virtual (domain 1)"))
    hint = next(h for h in out if h["feature"] == "StackWise Virtual")
    assert "Network Advantage" in hint["needs"] and hint["certainty"] == "stated" and hint["url"].startswith("https://www.cisco.com/")


def test_routing_features_are_marked_to_confirm_in_feature_navigator_not_asserted():
    out = tiers.hints(box("Cisco", model="C9300-48P", features=feats(("OSPF", 1), ("VRFs", 2))))
    hint = next(h for h in out if h["feature"] == "Routing / overlay features")
    assert hint["certainty"] == "confirm" and hint["url"] == "https://cfnng.cisco.com/" and "OSPF" in hint["evidence"]


def test_a_non_catalyst_9000_cisco_switch_gets_no_hint():
    assert tiers.hints(box("Cisco", model="WS-C3850-24P", ha="StackWise Virtual (domain 1)")) == []


def test_palo_alto_rules_with_profiles_and_decryption_point_at_their_subscriptions():
    out = tiers.hints(box("Palo Alto", "firewall", inspection={"policies": 5, "threat": 2, "application": 1, "decrypt": 1}))
    assert {h["feature"] for h in out} == {"Security profiles on rules", "URL / application rules", "Decryption"}
    decrypt = next(h for h in out if h["feature"] == "Decryption")
    assert "Decryption Mirroring" in decrypt["needs"] and decrypt["certainty"] == "stated"


def test_fortigate_threat_profiles_name_the_bundles_and_large_vdom_counts_are_flagged():
    out = tiers.hints(box("Fortinet", "firewall", inspection={"policies": 4, "threat": 3, "application": 0, "decrypt": 0}, capacity={"VDOMs / vsys": 12}))
    assert any("NGFW Service Bundle" in h["needs"] for h in out) and any(h["feature"] == "Virtual domains" and h["certainty"] == "confirm" for h in out)


def test_f5_modules_and_a_pair_each_need_their_own_licence():
    asset = box("F5", "load_balancer", features=feats(("ASM (provisioned)", 1), ("LTM (provisioned)", 1), group="Provisioned modules"), ha="HA cluster of 2")
    out = tiers.hints(asset)
    assert any(h["feature"] == "Provisioned modules" and "ASM" in h["evidence"] for h in out) and any(h["feature"] == "Device group" for h in out)


def test_aruba_switch_and_ap_hints_name_foundation_and_advanced():
    sw = tiers.hints(box("Aruba"))[0]
    ap = tiers.hints(box("Aruba", "access_point"))[0]
    assert "Foundation" in sw["needs"] and "NetConductor" in sw["why"] and "Air Slice" in ap["why"]


def test_huawei_controller_needs_an_ap_licence_for_the_managed_count_and_a_new_esn_file():
    out = tiers.hints(box("Huawei", "wlc", capacity={"Access points": 262}))
    assert any("262" in h["needs"] for h in out) and any(h["feature"] == "Licence file" for h in out)
    out = tiers.hints(box("Huawei", "wlc", capacity={"Access points (configured)": 262, "Access points joined": 241}))     # the labels the Huawei AC reader prints
    assert any("262" in h["needs"] for h in out)


def test_devices_with_the_same_hint_are_one_row():
    rows = tiers.licence_tiers([box("Aruba", hostname=f"SW{n}") for n in range(40)])
    assert len(rows) == 1 and rows[0]["count"] == 40 and len(rows[0]["devices"]) == 40


def test_an_asset_that_breaks_a_rule_gives_no_hints_instead_of_failing():
    assert tiers.hints({"vendor": "Palo Alto", "device_type": "firewall", "inspection": "broken"}) == []


def test_licences_ending_close_together_are_one_renewal_window_with_the_latest_date():
    def lic(day):
        return {"name": "L", "state": "x", "expires": day, "detail": ""}
    assets = [box("Cisco", hostname="A", licences=[lic("2027-01-10")]), box("Cisco", hostname="B", licences=[lic("2027-03-01")]), box("Cisco", hostname="C", licences=[lic("2027-12-01")]),
              box("Cisco", hostname="D", licences=[lic("2026-06-01")])]
    windows = tiers.coterm(assets, today=date(2026, 11, 16))
    assert [(w["from"], w["coterm"], w["expired"], w["licences"]) for w in windows] == [("2026-06-01", "2026-06-01", True, 1), ("2027-01-10", "2027-03-01", False, 2), ("2027-12-01", "2027-12-01", False, 1)]


def test_the_run_answer_and_the_workbook_carry_tiers_and_windows(monkeypatch):
    import io
    from openpyxl import load_workbook
    from app import create_app
    monkeypatch.setenv("NES_DISABLE_AUTH", "1")
    app = create_app()
    app.testing = True
    client = app.test_client()
    answer = client.post("/sizing-tool/api/analyze", data={"demo": "campus"}).get_json()
    assert answer["ok"] and answer["rollup"]["tiers"] and answer["rollup"]["coterm"]
    resp = client.post("/sizing-tool/api/export", json={"run_id": answer["run_id"], "growth": 25, "overrides": {}})
    wb = load_workbook(io.BytesIO(resp.data))
    assert "Licence tiers" in wb.sheetnames and "Renewal windows" in wb.sheetnames and wb["Licence tiers"].max_row > 1
