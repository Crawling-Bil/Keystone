"""Huawei radio planning: per-AP and AP-group radio settings, and the
source-to-target comparison used by Config Delta. Synthetic data only."""
from __future__ import annotations

from features.wireless_center import radio_planning as rp

SOURCE = """#
wlan
 ap-group name WAREHOUSE
  radio 0
   vap-profile CORP wlan 1
   eirp 18
   calibrate auto-txpower-select disable
  radio 2
   radio disable
 ap-group name OFFICE
  radio 1
   vap-profile CORP wlan 1
   work-mode monitor
 ap-id 0 type-id 139 ap-mac aaaa-bbbb-0001 ap-sn SN0001
  ap-name WH-AP-01
  ap-group WAREHOUSE
  radio 0
   eirp 127
   calibrate auto-txpower-select disable
  radio 1
   eirp 20
 ap-id 1 type-id 139 ap-mac aaaa-bbbb-0002 ap-sn SN0002
  ap-name WH-AP-02
  ap-group WAREHOUSE
 ap-id 2 type-id 139 ap-mac aaaa-bbbb-0003 ap-sn SN0003
  ap-name OF-AP-01
  ap-group OFFICE
  radio 1
   channel 20mhz 36
   calibrate auto-channel-select disable
 radio-5g-profile name HD
  rrm-profile HD
#
"""

TARGET = SOURCE.replace(" ap-id 0 type-id 139 ap-mac aaaa-bbbb-0001", " ap-id 7 type-id 139 ap-mac aaaa-bbbb-0001") \
    .replace("   eirp 127\n   calibrate auto-txpower-select disable\n  radio 1\n   eirp 20\n", "   eirp 15\n") \
    .replace("   channel 20mhz 36\n", "   channel 20mhz 36\n   calibrate auto-txpower-select enable\n")


def _row(plan, ap, radio):
    return next(r for r in plan["rows"] if r["ap"] == ap and r["radio"] == radio)


def test_plan_resolves_ap_over_group():
    plan = rp.plan(SOURCE)
    one = _row(plan, "WH-AP-01", "0")
    assert (one["power_mode"], one["eirp"], one["eirp_source"]) == ("Fixed", "127", "AP")
    assert "maximum power" in one["note"]
    inherited = _row(plan, "WH-AP-02", "0")
    assert (inherited["eirp"], inherited["eirp_source"], inherited["set_on"]) == ("18", "AP Group", "AP Group")
    ignored = _row(plan, "WH-AP-01", "1")
    assert ignored["power_mode"] == "Auto" and "ignored" in ignored["note"]
    assert _row(plan, "WH-AP-02", "2")["status"] == "Disabled"
    office = _row(plan, "OF-AP-01", "1")
    assert (office["channel"], office["channel_mode"], office["work_mode"]) == ("20mhz 36", "Fixed", "monitor")
    assert plan["summary"]["fixed_channel"] == 1 and plan["summary"]["aps_total"] == 3
    titles = " | ".join(f["title"] for f in plan["findings"])
    for expected in ("EIRP that does not apply", "EIRP above 30 dBm", "monitor mode", "radio disabled"):
        assert expected in titles
    assert any(p["name"] == "HD" for p in plan["profiles"])


def test_compare_matches_by_mac_and_writes_target_ids():
    result = rp.compare(SOURCE, TARGET)
    rows = {(r["ap"], r["radio"]): r for r in result["rows"]}
    assert rows[("WH-AP-01", "0")]["status"] == "Different"
    assert rows[("WH-AP-01", "1")]["status"] == "Missing on Target"
    assert rows[("WH-AP-01", "0")]["target_ap_id"] == "7"
    assert ("OF-AP-01", "1") not in rows             # only an explicit default differs
    script = result["commands"]
    assert " ap-id 7\n  radio 0\n   calibrate auto-txpower-select disable\n   eirp 127" in script
    assert " ap-id 7\n  radio 1\n   eirp 20" in script
    assert script.startswith("# Radio planning") and "\nwlan\n" in script


def test_same_config_has_no_difference():
    assert rp.compare(SOURCE, SOURCE)["rows"] == []
